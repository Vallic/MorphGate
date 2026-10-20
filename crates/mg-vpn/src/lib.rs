//! In-app VPNs for MorphGate: WireGuard, OpenVPN and openconnect (Cisco AnyConnect,
//! GlobalProtect, Fortinet, Pulse/Ivanti, …).
//!
//! Every [`Tunnel`] runs inside the app with its own TCP/IP stack (smoltcp), and
//! [`Tunnel::connect`] returns an ordinary async byte stream to a host behind the VPN. Nothing
//! touches the operating system's network configuration: no TUN device, no routes, no root, and
//! tunnels to different clients can use overlapping subnets at the same time.

mod net;
mod netstack;
pub mod openconnect;
pub mod openvpn;
pub mod wireguard;

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

pub use net::IpNet;
use netstack::{Cmd, LinkState, StackConfig, StackIo};

/// A byte stream through a tunnel (to `host:port` on the VPN side).
pub type VpnStream = tokio::io::DuplexStream;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("{0}")]
    Config(String),
    #[error("cannot resolve the VPN server {0}")]
    Resolve(String),
    /// The server didn't answer, or the handshake failed.
    #[error("{0}")]
    Connect(String),
    /// The server rejected the credentials.
    #[error("{0}")]
    Auth(String),
    #[error("cancelled")]
    Cancelled,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What a running tunnel looks like from the inside.
#[derive(Clone, Debug, Default)]
pub struct TunnelInfo {
    /// Where the tunnel goes, for display (`vpn.example.com:1194/udp`).
    pub server: String,
    /// This device's addresses inside the VPN.
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    /// Networks the server says are reachable through it.
    pub routes: Vec<IpNet>,
    pub mtu: u16,
    /// An openconnect server certificate the user accepted during this connect, to be pinned
    /// (`pin-sha256:…`).
    pub accepted_server_cert: Option<String>,
}

/// One thing the user is asked to type.
#[derive(Clone, Debug)]
pub struct PromptField {
    pub label: String,
    /// Hide what is typed (passwords, one-time codes).
    pub secret: bool,
    /// Pre-filled value.
    pub value: String,
}

/// Interactive input during a connect: passwords that aren't saved, one-time codes, and
/// untrusted server certificates.
pub trait Prompter: Send + Sync {
    /// `None` = cancelled. Otherwise one answer per field.
    fn ask(
        &self,
        title: String,
        message: String,
        fields: Vec<PromptField>,
    ) -> BoxFuture<'_, Option<Vec<String>>>;

    /// The VPN server's certificate isn't trusted by the system. `true` = trust (and pin) it.
    fn trust_certificate(
        &self,
        host: String,
        reason: String,
        fingerprint: String,
    ) -> BoxFuture<'_, bool>;

    /// The server wants the user to sign in on a web page (SAML, OpenID Connect, …): open
    /// `url` in the browser and tell the user to finish there. The connect keeps waiting for
    /// the server meanwhile, and drops this future when it no longer needs it (signed in, or
    /// given up). The future completes only if the user cancels; the default can't show a
    /// browser, so it cancels at once.
    fn web_sign_in(&self, title: String, url: String) -> BoxFuture<'_, ()> {
        let _ = (title, url);
        Box::pin(async {})
    }
}

/// For connects that must not block on a person: every question is answered "no".
pub struct NoPrompt;

impl Prompter for NoPrompt {
    fn ask(&self, _: String, _: String, _: Vec<PromptField>) -> BoxFuture<'_, Option<Vec<String>>> {
        Box::pin(async { None })
    }

    fn trust_certificate(&self, _: String, _: String, _: String) -> BoxFuture<'_, bool> {
        Box::pin(async { false })
    }
}

/// A web sign-in the user may still cancel, while a connect waits for its server.
pub(crate) struct WebSignIn<'a>(Option<BoxFuture<'a, ()>>);

impl<'a> WebSignIn<'a> {
    pub fn none() -> Self {
        Self(None)
    }

    /// Opens `url` (replacing a page opened earlier in the same connect).
    pub fn open(&mut self, prompter: &'a dyn Prompter, title: &str, url: String) {
        self.0 = Some(prompter.web_sign_in(title.to_owned(), url));
    }

    /// Completes when the user cancels the sign-in; pending forever when there is none.
    pub async fn cancelled(&mut self) {
        match &mut self.0 {
            Some(f) => f.await,
            None => std::future::pending().await,
        }
    }
}

/// A running VPN with its private TCP/IP stack.
pub struct Tunnel {
    cmds: mpsc::UnboundedSender<Cmd>,
    stack: JoinHandle<()>,
    link: Arc<LinkState>,
    stop: Arc<watch::Sender<bool>>,
    info: TunnelInfo,
}

impl Tunnel {
    /// Starts the TCP/IP stack on top of a link that is up. The link task keeps running until
    /// the stack ends (last stream closed after the tunnel was dropped), or [`Tunnel::shutdown`].
    pub(crate) fn spawn(
        info: TunnelInfo,
        cfg: StackConfig,
        io: StackIo,
        link: Arc<LinkState>,
        stop: watch::Sender<bool>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let stop = Arc::new(stop);
        let driver = netstack::Driver::new(cfg, io, rx, tx.downgrade(), link.clone());
        let keep_link = stop.clone();
        let stack = tokio::spawn(async move {
            driver.await;
            // The link stops once nobody can use the stack any more.
            drop(keep_link);
        });
        Self {
            cmds: tx,
            stack,
            link,
            stop,
            info,
        }
    }

    /// Opens a TCP connection to `host:port` inside the VPN. Hostnames resolve through the VPN's
    /// DNS servers (with its search domains), falling back to the system resolver.
    pub async fn connect(&self, host: &str, port: u16) -> io::Result<VpnStream> {
        let (reply, rx) = oneshot::channel();
        self.cmds
            .send(Cmd::Connect {
                host: host.to_owned(),
                port,
                reply,
            })
            .map_err(|_| self.gone())?;
        rx.await.map_err(|_| self.gone())?
    }

    fn gone(&self) -> io::Error {
        let msg = match self.link.error() {
            Some(e) => format!("the VPN connection has stopped: {e}"),
            None => "the VPN connection has stopped".into(),
        };
        io::Error::new(io::ErrorKind::BrokenPipe, msg)
    }

    pub fn is_alive(&self) -> bool {
        !self.stack.is_finished()
    }

    pub fn info(&self) -> &TunnelInfo {
        &self.info
    }

    /// Why the link went down, if it did.
    pub fn error(&self) -> Option<String> {
        self.link.error()
    }

    /// Stops now, cutting every stream (and logging out where the protocol has a logout).
    /// Dropping the tunnel instead lets open streams finish and then stops.
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
        self.stack.abort();
    }

    #[cfg(test)]
    pub(crate) async fn listen(&self, port: u16) -> mpsc::UnboundedReceiver<VpnStream> {
        let (accepted, rx) = mpsc::unbounded_channel();
        self.cmds.send(Cmd::Listen { port, accepted }).unwrap();
        rx
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    pub fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    }

    /// Serves an echo service on `port` of the tunnel's stack.
    pub async fn echo_on(tunnel: &Tunnel, port: u16) {
        let mut accepted = tunnel.listen(port).await;
        tokio::spawn(async move {
            while let Some(s) = accepted.recv().await {
                tokio::spawn(echo(s));
            }
        });
    }

    pub async fn echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut s: S) {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = s.shutdown().await;
    }

    /// Runs `echo {tag}-$((6*7))` in a real SSH session (mg-ssh) dialed through `tunnel`, and
    /// returns the terminal output.
    pub async fn ssh_echo(
        tunnel: Arc<Tunnel>,
        host: &str,
        port: u16,
        user: &str,
        key: &str,
        tag: &str,
    ) -> String {
        struct Via(Arc<Tunnel>);
        impl mg_ssh::Dialer for Via {
            fn dial<'a>(
                &'a self,
                host: &'a str,
                port: u16,
            ) -> BoxFuture<'a, io::Result<mg_ssh::BoxedStream>> {
                Box::pin(async move {
                    Ok(Box::new(self.0.connect(host, port).await?) as mg_ssh::BoxedStream)
                })
            }
            fn describe(&self) -> String {
                "test VPN".into()
            }
        }
        struct Trust;
        impl mg_ssh::HostKeyPrompt for Trust {
            fn confirm(&self, _: mg_ssh::HostKeyInfo) -> BoxFuture<'static, bool> {
                Box::pin(async { true })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let opts = mg_ssh::ConnectOptions {
            host: host.into(),
            port,
            user: user.into(),
            auth: mg_ssh::Auth::KeyFile {
                path: key.into(),
                passphrase: None,
            },
            term: "xterm".into(),
            size: mg_ssh::TermSize { cols: 80, rows: 24 },
            connect_timeout: Duration::from_secs(10),
            jumps: vec![],
            via_command: None,
            dialer: Some(Arc::new(Via(tunnel))),
            forward_agent: None,
        };
        let kh = Arc::new(mg_ssh::KnownHosts::new(dir.path().join("known_hosts")));
        let (session, mut events) = mg_ssh::Session::connect(opts, kh, Arc::new(Trust))
            .await
            .unwrap();
        session
            .write(format!("echo {tag}-$((6*7))\nexit\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(ev) = events.recv().await {
                match ev {
                    mg_ssh::SessionEvent::Output(b) => out.extend(b),
                    mg_ssh::SessionEvent::Closed => break,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Round trip a message, then push `bulk` bytes both ways at once and compare.
    pub async fn exercise<S>(s: S, bulk: usize)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(s);
        wr.write_all(b"SSH-2.0-hello\r\n").await.unwrap();
        let mut hello = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut hello))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&hello, b"SSH-2.0-hello\r\n");
        let data: Vec<u8> = (0..bulk as u32).map(|i| (i * 31 % 251) as u8).collect();
        let expected = data.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&data).await.unwrap();
            wr.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(60), rd.read_to_end(&mut got))
            .await
            .expect("transfer stalled")
            .unwrap();
        writer.await.unwrap();
        assert_eq!(got.len(), expected.len());
        assert!(got == expected, "data corrupted in transit");
    }
}
