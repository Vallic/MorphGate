//! Port forwarding over a dedicated [`Connection`]: local (`ssh -L`), remote (`ssh -R`) and
//! dynamic SOCKS5 (`ssh -D`).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::{Connection, Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum Forward {
    /// Listen on this machine; each connection is opened to `target` *from the server*.
    Local {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    /// The server listens; each connection comes back and is opened to `target` *from this machine*.
    Remote {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    /// SOCKS5 proxy on this machine; every destination is reached from the server.
    Dynamic { bind_host: String, bind_port: u16 },
}

/// A running forward. Owns its SSH connection; [`stop`](Self::stop) closes both.
pub struct Tunnel {
    conn: Arc<Connection>,
    task: JoinHandle<()>,
    forward: Forward,
    port: u16,
    active: Arc<AtomicUsize>,
}

impl Tunnel {
    pub async fn start(conn: Connection, forward: Forward) -> Result<Self> {
        let conn = Arc::new(conn);
        let active = Arc::new(AtomicUsize::new(0));
        let (task, port) = match &forward {
            Forward::Local {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => {
                let (listener, port) = bind(bind_host, *bind_port).await?;
                let target = (target_host.clone(), *target_port);
                let task = accept_loop(
                    listener,
                    conn.clone(),
                    active.clone(),
                    move |conn, sock, peer| pipe_local(conn, sock, peer, target.clone()),
                );
                (task, port)
            }
            Forward::Dynamic {
                bind_host,
                bind_port,
            } => {
                let (listener, port) = bind(bind_host, *bind_port).await?;
                let task = accept_loop(listener, conn.clone(), active.clone(), pipe_socks);
                (task, port)
            }
            Forward::Remote {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => {
                let (tx, rx) = mpsc::unbounded_channel();
                *conn.forwarded.lock().expect("not poisoned") = Some(tx);
                let allocated = conn
                    .handle
                    .tcpip_forward(bind_host.clone(), u32::from(*bind_port))
                    .await
                    .map_err(|e| Error::Bind {
                        addr: format!("{bind_host}:{bind_port} on the server"),
                        source: io::Error::other(e.to_string()),
                    })?;
                let port = if *bind_port == 0 {
                    u16::try_from(allocated).unwrap_or(0)
                } else {
                    *bind_port
                };
                let task = remote_loop(rx, active.clone(), (target_host.clone(), *target_port));
                (task, port)
            }
        };
        Ok(Self {
            conn,
            task,
            forward,
            port,
            active,
        })
    }

    pub fn forward(&self) -> &Forward {
        &self.forward
    }

    /// The port actually listening (useful when 0 was requested). For remote forwards this is
    /// the port on the server.
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn is_alive(&self) -> bool {
        !self.task.is_finished() && !self.conn.is_closed()
    }

    pub async fn stop(self) {
        self.task.abort();
        if let Forward::Remote { bind_host, .. } = &self.forward {
            let _ = self
                .conn
                .handle
                .cancel_tcpip_forward(bind_host.clone(), u32::from(self.port))
                .await;
        }
        let _ = self.conn.close().await;
    }
}

async fn bind(host: &str, port: u16) -> Result<(TcpListener, u16)> {
    let err = |source| Error::Bind {
        addr: format!("{host}:{port}"),
        source,
    };
    let listener = TcpListener::bind((host, port)).await.map_err(err)?;
    let bound = listener.local_addr().map_err(err)?.port();
    Ok((listener, bound))
}

/// Counts a connection as active for as long as it lives.
struct Active(Arc<AtomicUsize>);

impl Active {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn accept_loop<F, Fut>(
    listener: TcpListener,
    conn: Arc<Connection>,
    active: Arc<AtomicUsize>,
    handle: F,
) -> JoinHandle<()>
where
    F: Fn(Arc<Connection>, TcpStream, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let Ok((sock, peer)) = listener.accept().await else {
                continue;
            };
            if conn.is_closed() {
                return;
            }
            let _ = sock.set_nodelay(true);
            let guard = Active::new(&active);
            let work = handle(conn.clone(), sock, peer);
            tokio::spawn(async move {
                work.await;
                drop(guard);
            });
        }
    })
}

fn remote_loop(
    mut rx: mpsc::UnboundedReceiver<russh::Channel<russh::client::Msg>>,
    active: Arc<AtomicUsize>,
    target: (String, u16),
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(channel) = rx.recv().await {
            let guard = Active::new(&active);
            let (host, port) = target.clone();
            tokio::spawn(async move {
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(mut sock) => {
                        let _ = sock.set_nodelay(true);
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
                    }
                    Err(e) => {
                        tracing::debug!(%e, "remote forward: local target unreachable");
                        let _ = channel.close().await;
                    }
                }
                drop(guard);
            });
        }
    })
}

async fn pipe_local(
    conn: Arc<Connection>,
    mut sock: TcpStream,
    peer: SocketAddr,
    target: (String, u16),
) {
    match conn.direct_tcpip(&target.0, target.1, Some(peer)).await {
        Ok(mut stream) => {
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
        }
        Err(e) => tracing::debug!(%e, "local forward: open failed"),
    }
}

async fn pipe_socks(conn: Arc<Connection>, mut sock: TcpStream, peer: SocketAddr) {
    let Ok((host, port)) = socks5_accept(&mut sock).await else {
        return;
    };
    match conn.direct_tcpip(&host, port, Some(peer)).await {
        Ok(mut stream) => {
            if socks5_reply(&mut sock, REPLY_OK).await.is_ok() {
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
            }
        }
        Err(_) => {
            let _ = socks5_reply(&mut sock, REPLY_REFUSED).await;
        }
    }
}

// ------------------------------------------------------------------ SOCKS5 (RFC 1928), CONNECT only

const REPLY_OK: u8 = 0x00;
const REPLY_REFUSED: u8 = 0x05;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

fn protocol(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Negotiates "no authentication" and reads a CONNECT request; returns the destination.
async fn socks5_accept<S: AsyncRead + AsyncWrite + Unpin>(
    sock: &mut S,
) -> io::Result<(String, u16)> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(protocol("not a SOCKS5 client"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[5, 0xFF]).await?;
        return Err(protocol("client requires authentication"));
    }
    sock.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(protocol("bad SOCKS5 request"));
    }
    if req[1] != 1 {
        socks5_reply(sock, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(protocol("only CONNECT is supported"));
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let len = sock.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            sock.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| protocol("domain name is not UTF-8"))?
        }
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            socks5_reply(sock, REPLY_ADDRESS_NOT_SUPPORTED).await?;
            return Err(protocol("unknown address type"));
        }
    };
    let port = sock.read_u16().await?;
    Ok((host, port))
}

async fn socks5_reply<S: AsyncWrite + Unpin>(sock: &mut S, code: u8) -> io::Result<()> {
    sock.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn handshake(request: &[u8]) -> (io::Result<(String, u16)>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(request).await.unwrap();
        let result = socks5_accept(&mut server).await;
        drop(server);
        let mut replies = Vec::new();
        client.read_to_end(&mut replies).await.unwrap();
        (result, replies)
    }

    #[tokio::test]
    async fn socks5_connect_requests() {
        let (r, replies) = handshake(&[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 7, 0x1F, 0x90]).await;
        assert_eq!(r.unwrap(), ("10.0.0.7".into(), 8080));
        assert_eq!(replies, [5, 0]);

        let mut domain = vec![5, 2, 2, 0, 5, 1, 0, 3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            handshake(&domain).await.0.unwrap(),
            ("example.com".into(), 443)
        );

        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&22u16.to_be_bytes());
        assert_eq!(handshake(&v6).await.0.unwrap(), ("::1".into(), 22));
    }

    #[tokio::test]
    async fn socks5_rejections() {
        // Only username/password offered: no acceptable method.
        let (r, replies) = handshake(&[5, 1, 2]).await;
        assert!(r.is_err());
        assert_eq!(replies, [5, 0xFF]);

        // BIND is not supported.
        let (r, replies) = handshake(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]).await;
        assert!(r.is_err());
        assert_eq!(&replies[2..4], [5, REPLY_COMMAND_NOT_SUPPORTED]);

        // SOCKS4 client.
        assert!(handshake(&[4, 1, 0, 80]).await.0.is_err());
    }
}
