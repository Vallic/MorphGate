//! The TCP/IP stack every tunnel runs: smoltcp over a virtual IP device whose packets come from
//! and go to a VPN link task, with in-process duplex pipes as the app-facing streams.

mod device;

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, Sleep};

use crate::IpNet;
use device::VirtualDevice;

/// Per-socket buffers; the receive buffer is the advertised window.
const TCP_BUF: usize = 128 * 1024;
const PIPE: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// After both sides closed, how long queued data and our FIN may take to be acknowledged.
const LINGER: Duration = Duration::from_secs(30);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(12);
/// Packets queued between the stack and a link, each way. Overflow drops, like a NIC queue;
/// TCP inside the tunnel retransmits.
pub(crate) const LINK_QUEUE: usize = 1024;
/// Bounded work per poll so one busy tunnel can't starve the runtime.
const MAX_ROUNDS: usize = 64;
const MAX_PACKETS_PER_ROUND: usize = 256;

type Reply = oneshot::Sender<io::Result<DuplexStream>>;

/// The link's ends: packets it decrypted go `to_stack`; packets to encrypt come `from_stack`.
pub(crate) struct LinkIo {
    pub to_stack: mpsc::Sender<Vec<u8>>,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
}

pub(crate) struct StackIo {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
}

pub(crate) fn link_pair() -> (LinkIo, StackIo) {
    let (to_stack, rx) = mpsc::channel(LINK_QUEUE);
    let (tx, from_stack) = mpsc::channel(LINK_QUEUE);
    (
        LinkIo {
            to_stack,
            from_stack,
        },
        StackIo { rx, tx },
    )
}

/// Link status, shared between the link task, the stack and the [`crate::Tunnel`].
#[derive(Default)]
pub(crate) struct LinkState {
    pub up: AtomicBool,
    error: std::sync::Mutex<Option<String>>,
}

impl LinkState {
    /// Records why the link went down (the first reason wins).
    pub fn fail(&self, msg: impl Into<String>) {
        let mut e = self.error.lock().unwrap_or_else(|p| p.into_inner());
        if e.is_none() {
            *e = Some(msg.into());
        }
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }
}

pub(crate) struct StackConfig {
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub mtu: u16,
    /// Destinations the link can carry at all (WireGuard `AllowedIPs`); `None` = anything.
    pub allowed: Option<Vec<IpNet>>,
    /// Routes the server announced; used to explain timeouts.
    pub routes: Vec<IpNet>,
}

pub(crate) enum Cmd {
    Connect {
        host: String,
        port: u16,
        reply: Reply,
    },
    ConnectIp {
        ip: IpAddr,
        port: u16,
        reply: Reply,
    },
    #[cfg(test)]
    Listen {
        port: u16,
        accepted: mpsc::UnboundedSender<DuplexStream>,
    },
}

struct Conn {
    handle: SocketHandle,
    ip: Option<IpAddr>,
    /// Our end of the pipe; the caller holds the other end as its stream.
    far: DuplexStream,
    /// Handed to the caller once the TCP handshake completes.
    near: Option<DuplexStream>,
    reply: Option<Reply>,
    deadline: Instant,
    app_eof: bool,
    eof_sent: bool,
    /// Set once both sides closed: give up on an unacknowledged tail after this.
    linger: Option<Instant>,
    done: bool,
}

struct Lookup {
    host: String,
    /// Names still to try (search domains), in order.
    names: VecDeque<String>,
    query: dns::QueryHandle,
    port: u16,
    reply: Reply,
    deadline: Instant,
}

#[cfg(test)]
struct Listener {
    port: u16,
    /// smoltcp accepts one connection per listening socket: keep a small backlog.
    handles: Vec<SocketHandle>,
    accepted: mpsc::UnboundedSender<DuplexStream>,
}

pub(crate) struct Driver {
    io: StackIo,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    dns: Option<SocketHandle>,
    conns: Vec<Conn>,
    lookups: Vec<Lookup>,
    #[cfg(test)]
    listeners: Vec<Listener>,
    cmds: mpsc::UnboundedReceiver<Cmd>,
    /// For system-resolver lookups, which finish on another task.
    cmd_back: mpsc::WeakUnboundedSender<Cmd>,
    link: Arc<LinkState>,
    cfg: StackConfig,
    has_v4: bool,
    has_v6: bool,
    next_port: u16,
    epoch: std::time::Instant,
    wake: Pin<Box<Sleep>>,
    closed: bool,
    link_down: bool,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system RNG");
    b
}

/// Without congestion control smoltcp sends its whole window at once, which overflows UDP
/// buffers and stalls in retransmit backoff.
fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUF]),
        tcp::SocketBuffer::new(vec![0; TCP_BUF]),
    );
    sock.set_nagle_enabled(false);
    sock.set_congestion_control(tcp::CongestionControl::Cubic);
    sock
}

fn err(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

impl Driver {
    pub fn new(
        cfg: StackConfig,
        io: StackIo,
        cmds: mpsc::UnboundedReceiver<Cmd>,
        cmd_back: mpsc::WeakUnboundedSender<Cmd>,
        link: Arc<LinkState>,
    ) -> Self {
        let mut device = VirtualDevice::new(cfg.mtu);
        let epoch = std::time::Instant::now();
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = u64::from_le_bytes(random::<8>());
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::from_micros(0));
        let (mut has_v4, mut has_v6) = (false, false);
        iface.update_ip_addrs(|addrs| {
            for net in &cfg.addresses {
                let _ = addrs.push(IpCidr::new(IpAddress::from(net.addr), net.prefix));
            }
        });
        // Everything not on-link goes to the peer: the tunnel is the only route.
        for net in &cfg.addresses {
            match net.addr {
                IpAddr::V4(a) if !has_v4 => {
                    has_v4 = true;
                    let _ = iface.routes_mut().add_default_ipv4_route(a);
                }
                IpAddr::V6(a) if !has_v6 => {
                    has_v6 = true;
                    let _ = iface.routes_mut().add_default_ipv6_route(a);
                }
                _ => {}
            }
        }
        let mut sockets = SocketSet::new(vec![]);
        let dns = (!cfg.dns.is_empty()).then(|| {
            let servers: Vec<IpAddress> = cfg.dns.iter().map(|ip| IpAddress::from(*ip)).collect();
            let slots: Vec<Option<dns::DnsQuery>> = (0..8).map(|_| None).collect();
            sockets.add(dns::Socket::new(&servers, slots))
        });
        Self {
            io,
            iface,
            device,
            sockets,
            dns,
            conns: Vec::new(),
            lookups: Vec::new(),
            #[cfg(test)]
            listeners: Vec::new(),
            cmds,
            cmd_back,
            link,
            cfg,
            has_v4,
            has_v6,
            next_port: 49_152 + u16::from_le_bytes(random::<2>()) % 16_000,
            epoch,
            wake: Box::pin(tokio::time::sleep(Duration::ZERO)),
            closed: false,
            link_down: false,
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    fn ephemeral_port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 65_000 {
            49_152
        } else {
            self.next_port + 1
        };
        self.next_port
    }

    fn down_reason(&self) -> String {
        match self.link.error() {
            Some(e) => format!("the VPN connection was lost: {e}"),
            None => "the VPN connection was lost".into(),
        }
    }

    // -------------------------------------------------------------- commands

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Connect { host, port, reply } => {
                let host = host.trim().trim_end_matches('.').to_owned();
                if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
                    return self.open(ip, port, reply);
                }
                if self.dns.is_none() {
                    return self.system_lookup(host, port, reply);
                }
                let names = self.candidates(&host);
                self.start_lookup(host, names, port, reply, Instant::now() + LOOKUP_TIMEOUT);
            }
            Cmd::ConnectIp { ip, port, reply } => self.open(ip, port, reply),
            #[cfg(test)]
            Cmd::Listen { port, accepted } => {
                let handles = (0..8).map(|_| self.listen_socket(port)).collect();
                self.listeners.push(Listener {
                    port,
                    handles,
                    accepted,
                });
            }
        }
    }

    /// Single-label names try the VPN's search domains first (like `ndots:1`).
    fn candidates(&self, host: &str) -> VecDeque<String> {
        let mut names = VecDeque::new();
        if !host.contains('.') {
            for d in &self.cfg.search_domains {
                names.push_back(format!("{host}.{}", d.trim_matches('.')));
            }
        }
        names.push_back(host.to_owned());
        names
    }

    fn start_lookup(
        &mut self,
        host: String,
        mut names: VecDeque<String>,
        port: u16,
        reply: Reply,
        deadline: Instant,
    ) {
        let Some(h) = self.dns else {
            return self.system_lookup(host, port, reply);
        };
        let qtype = if self.has_v4 {
            DnsQueryType::A
        } else {
            DnsQueryType::Aaaa
        };
        while let Some(name) = names.pop_front() {
            match self.sockets.get_mut::<dns::Socket>(h).start_query(
                self.iface.context(),
                &name,
                qtype,
            ) {
                Ok(query) => {
                    self.lookups.push(Lookup {
                        host,
                        names,
                        query,
                        port,
                        reply,
                        deadline,
                    });
                    return;
                }
                Err(e) => tracing::debug!(%name, ?e, "vpn dns query"),
            }
        }
        self.system_lookup(host, port, reply);
    }

    /// The system resolver: for profiles without DNS, and as a fallback when the VPN's DNS
    /// doesn't know the name.
    fn system_lookup(&mut self, host: String, port: u16, reply: Reply) {
        let back = self.cmd_back.clone();
        let via_vpn = self.dns.is_some();
        tokio::spawn(async move {
            let result = tokio::net::lookup_host((host.as_str(), port))
                .await
                .ok()
                .and_then(|mut a| a.next());
            match (result, back.upgrade()) {
                (Some(addr), Some(tx)) => {
                    let _ = tx.send(Cmd::ConnectIp {
                        ip: addr.ip(),
                        port,
                        reply,
                    });
                }
                (None, _) => {
                    let msg = if via_vpn {
                        format!("cannot resolve {host} (neither the VPN's DNS nor the system's)")
                    } else {
                        format!("cannot resolve {host}; the VPN profile has no DNS server")
                    };
                    let _ = reply.send(Err(err(io::ErrorKind::NotFound, msg)));
                }
                (Some(_), None) => {}
            }
        });
    }

    fn open(&mut self, ip: IpAddr, port: u16, reply: Reply) {
        if self.link_down {
            let _ = reply.send(Err(err(io::ErrorKind::BrokenPipe, self.down_reason())));
            return;
        }
        if let Some(allowed) = &self.cfg.allowed
            && !allowed.iter().any(|n| n.contains(ip))
        {
            let _ = reply.send(Err(err(
                io::ErrorKind::PermissionDenied,
                format!("{ip} is outside this VPN's AllowedIPs"),
            )));
            return;
        }
        if (ip.is_ipv4() && !self.has_v4) || (ip.is_ipv6() && !self.has_v6) {
            let _ = reply.send(Err(err(
                io::ErrorKind::Unsupported,
                format!("the VPN gave this device no address for {ip}'s IP version"),
            )));
            return;
        }
        let mut sock = new_tcp_socket();
        sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(25)));
        let local = self.ephemeral_port();
        if let Err(e) = sock.connect(self.iface.context(), (IpAddress::from(ip), port), local) {
            let _ = reply.send(Err(err(
                io::ErrorKind::InvalidInput,
                format!("cannot connect to {ip}:{port}: {e:?}"),
            )));
            return;
        }
        let handle = self.sockets.add(sock);
        let (near, far) = tokio::io::duplex(PIPE);
        self.conns.push(Conn {
            handle,
            ip: Some(ip),
            far,
            near: Some(near),
            reply: Some(reply),
            deadline: Instant::now() + CONNECT_TIMEOUT,
            app_eof: false,
            eof_sent: false,
            linger: None,
            done: false,
        });
    }

    fn timeout_message(&self, ip: Option<IpAddr>) -> String {
        if !self.link.is_up() {
            return "connection timed out: the VPN link is not up".into();
        }
        let mut msg =
            String::from("connection through the VPN timed out (host down or port filtered?)");
        if let Some(ip) = ip
            && !self.cfg.routes.is_empty()
            && !self.cfg.routes.iter().any(|r| r.contains(ip))
        {
            let routes: Vec<String> = self.cfg.routes.iter().map(ToString::to_string).collect();
            msg.push_str(&format!(
                "; {ip} is not in the networks the VPN announced ({})",
                routes.join(", ")
            ));
        }
        msg
    }

    #[cfg(test)]
    fn listen_socket(&mut self, port: u16) -> SocketHandle {
        let mut sock = new_tcp_socket();
        sock.listen(port).expect("listen");
        self.sockets.add(sock)
    }

    #[cfg(test)]
    fn poll_listeners(&mut self) -> bool {
        let mut any = false;
        for i in 0..self.listeners.len() {
            for j in 0..self.listeners[i].handles.len() {
                let handle = self.listeners[i].handles[j];
                let state = self.sockets.get::<tcp::Socket>(handle).state();
                if matches!(state, tcp::State::Established | tcp::State::CloseWait) {
                    let (near, far) = tokio::io::duplex(PIPE);
                    self.conns.push(Conn {
                        handle,
                        ip: None,
                        far,
                        near: None,
                        reply: None,
                        deadline: Instant::now(),
                        app_eof: false,
                        eof_sent: false,
                        linger: None,
                        done: false,
                    });
                    let _ = self.listeners[i].accepted.send(near);
                    let port = self.listeners[i].port;
                    self.listeners[i].handles[j] = self.listen_socket(port);
                    any = true;
                }
            }
        }
        any
    }

    // -------------------------------------------------------------- link side

    fn poll_link(&mut self, cx: &mut Context<'_>) -> bool {
        let mut any = false;
        for _ in 0..MAX_PACKETS_PER_ROUND {
            match self.io.rx.poll_recv(cx) {
                Poll::Ready(Some(packet)) => {
                    self.device.rx.push_back(packet);
                    any = true;
                }
                Poll::Ready(None) => {
                    self.link_down = true;
                    break;
                }
                Poll::Pending => break,
            }
        }
        any
    }

    fn flush_tx(&mut self) -> bool {
        let mut any = false;
        while let Some(packet) = self.device.tx.pop_front() {
            any = true;
            match self.io.tx.try_send(packet) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.link_down = true;
                    self.device.tx.clear();
                    break;
                }
            }
        }
        any
    }

    /// The link is gone: fail what's pending. Dropping the driver then closes every pipe, which
    /// the app sees as EOF.
    fn fail_all(&mut self) {
        let reason = self.down_reason();
        for c in &mut self.conns {
            if let Some(reply) = c.reply.take() {
                let _ = reply.send(Err(err(io::ErrorKind::BrokenPipe, reason.clone())));
            }
        }
        for l in self.lookups.drain(..) {
            let _ = l
                .reply
                .send(Err(err(io::ErrorKind::BrokenPipe, reason.clone())));
        }
        while let Ok(cmd) = self.cmds.try_recv() {
            #[allow(irrefutable_let_patterns)] // `Listen` exists in tests only
            if let Cmd::Connect { reply, .. } | Cmd::ConnectIp { reply, .. } = cmd {
                let _ = reply.send(Err(err(io::ErrorKind::BrokenPipe, reason.clone())));
            }
        }
        tracing::debug!(%reason, "vpn stack stopping");
    }

    // -------------------------------------------------------------- application side

    fn pump_app_to_sockets(&mut self, cx: &mut Context<'_>) -> bool {
        let mut any = false;
        for conn in self
            .conns
            .iter_mut()
            .filter(|c| c.reply.is_none() && !c.done)
        {
            let sock = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            while !conn.app_eof && sock.can_send() {
                let room = sock.send_capacity() - sock.send_queue();
                if room == 0 {
                    break;
                }
                let mut chunk = [0u8; 16 * 1024];
                let n = room.min(chunk.len());
                let mut rb = ReadBuf::new(&mut chunk[..n]);
                match Pin::new(&mut conn.far).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                        conn.app_eof = true;
                        sock.close();
                        any = true;
                    }
                    Poll::Ready(Ok(())) => {
                        let _ = sock.send_slice(rb.filled());
                        any = true;
                    }
                    Poll::Ready(Err(_)) => {
                        sock.abort();
                        conn.done = true;
                        any = true;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }
        any
    }

    fn pump_sockets_to_app(&mut self, cx: &mut Context<'_>) -> bool {
        let mut any = false;
        let now = Instant::now();
        let mut timed_out = Vec::new();
        for (i, conn) in self.conns.iter_mut().enumerate().filter(|(_, c)| !c.done) {
            let sock = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            if let Some(reply) = conn.reply.take() {
                match sock.state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        let _ = reply.send(Ok(conn
                            .near
                            .take()
                            .expect("near end present until established")));
                        any = true;
                    }
                    tcp::State::Closed | tcp::State::TimeWait => {
                        let _ = reply.send(Err(err(
                            io::ErrorKind::ConnectionRefused,
                            "connection refused (through VPN)",
                        )));
                        conn.done = true;
                        any = true;
                        continue;
                    }
                    _ if now >= conn.deadline => {
                        sock.abort();
                        conn.reply = Some(reply);
                        timed_out.push(i);
                        any = true;
                        continue;
                    }
                    _ => {
                        conn.reply = Some(reply);
                        continue;
                    }
                }
            }
            while sock.can_recv() {
                let r = sock.recv(|data| match Pin::new(&mut conn.far).poll_write(cx, data) {
                    Poll::Ready(Ok(n)) => (n, Ok(n)),
                    Poll::Ready(Err(e)) => (0, Err(e)),
                    Poll::Pending => (0, Ok(0)),
                });
                match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(_)) => any = true,
                    _ => {
                        sock.abort();
                        conn.done = true;
                        break;
                    }
                }
            }
            if conn.done {
                continue;
            }
            // Peer finished sending and we delivered everything: EOF to the caller.
            let established_once =
                !matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived);
            if !conn.eof_sent
                && established_once
                && !sock.may_recv()
                && !sock.can_recv()
                && Pin::new(&mut conn.far).poll_shutdown(cx).is_ready()
            {
                conn.eof_sent = true;
                any = true;
            }
            // Only drop the socket once everything we sent, FIN included, was acknowledged:
            // a socket removed early answers the peer's next segment with a reset, and the
            // tail of the stream is lost.
            let finished = matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait);
            if conn.eof_sent && finished {
                conn.done = true;
            } else if conn.eof_sent && conn.app_eof {
                let until = *conn.linger.get_or_insert(now + LINGER);
                if now >= until {
                    sock.abort();
                    conn.done = true;
                }
            }
        }
        for i in timed_out {
            let msg = self.timeout_message(self.conns[i].ip);
            if let Some(reply) = self.conns[i].reply.take() {
                let _ = reply.send(Err(err(io::ErrorKind::TimedOut, msg)));
            }
            self.conns[i].done = true;
        }
        let sockets = &mut self.sockets;
        self.conns.retain(|c| {
            if c.done {
                sockets.remove(c.handle);
            }
            !c.done
        });
        any
    }

    fn poll_lookups(&mut self) -> bool {
        let Some(h) = self.dns else { return false };
        let mut any = false;
        let mut i = 0;
        while i < self.lookups.len() {
            let result = self
                .sockets
                .get_mut::<dns::Socket>(h)
                .get_query_result(self.lookups[i].query);
            match result {
                Ok(addrs) if !addrs.is_empty() => {
                    let l = self.lookups.swap_remove(i);
                    self.open(IpAddr::from(addrs[0]), l.port, l.reply);
                    any = true;
                }
                Err(dns::GetQueryResultError::Pending)
                    if Instant::now() < self.lookups[i].deadline =>
                {
                    i += 1
                }
                Err(dns::GetQueryResultError::Pending) => {
                    let l = self.lookups.swap_remove(i);
                    self.sockets.get_mut::<dns::Socket>(h).cancel_query(l.query);
                    self.system_lookup(l.host, l.port, l.reply);
                    any = true;
                }
                // No such name (or no address): next search domain, then the system resolver.
                _ => {
                    let l = self.lookups.swap_remove(i);
                    if l.names.is_empty() || Instant::now() >= l.deadline {
                        self.system_lookup(l.host, l.port, l.reply);
                    } else {
                        self.start_lookup(l.host, l.names, l.port, l.reply, l.deadline);
                    }
                    any = true;
                }
            }
        }
        any
    }
}

impl Future for Driver {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let mut rounds = 0;
        loop {
            let mut progress = false;
            loop {
                match this.cmds.poll_recv(cx) {
                    Poll::Ready(Some(cmd)) => {
                        progress = true;
                        this.handle(cmd);
                    }
                    Poll::Ready(None) => this.closed = true,
                    Poll::Pending => break,
                }
                if this.closed {
                    break;
                }
            }
            if this.closed && this.conns.is_empty() {
                return Poll::Ready(());
            }
            progress |= this.poll_link(cx);
            progress |= this.pump_app_to_sockets(cx);
            let now = this.now();
            if this.iface.poll(now, &mut this.device, &mut this.sockets)
                == PollResult::SocketStateChanged
            {
                progress = true;
            }
            progress |= this.flush_tx();
            if this.link_down {
                this.fail_all();
                return Poll::Ready(());
            }
            progress |= this.pump_sockets_to_app(cx);
            progress |= this.poll_lookups();
            #[cfg(test)]
            {
                progress |= this.poll_listeners();
            }
            rounds += 1;
            if !progress {
                break;
            }
            if rounds >= MAX_ROUNDS {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        // Connect deadlines and lookups are checked on a coarse tick; smoltcp says when it needs
        // the next poll.
        let mut at = Instant::now() + Duration::from_millis(500);
        if let Some(d) = this.iface.poll_delay(this.now(), &this.sockets) {
            at = at.min(Instant::now() + Duration::from_micros(d.total_micros()));
        }
        this.wake.as_mut().reset(at);
        if this.wake.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}
