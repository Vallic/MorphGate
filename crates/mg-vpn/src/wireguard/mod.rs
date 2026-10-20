//! WireGuard (boringtun) as a tunnel link: UDP to the peers, IP packets to the stack.
//!
//! A profile may have several `[Peer]`s behind one UDP socket. Each peer has its own
//! handshake, session and timers (one boringtun [`Tunn`] per peer, persistent keepalives
//! included). Outgoing packets go to the peer whose AllowedIPs match the destination most
//! specifically (cryptokey routing); a decrypted packet is only accepted when its source
//! address routes back to the peer that sent it.

mod config;

use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use config::RouteTable;
pub use config::{WgConfig, WgPeer, public_key};

use crate::netstack::{LinkIo, LinkState, StackConfig, link_pair};
use crate::{Tunnel, TunnelInfo, VpnError};

const WG_TICK: Duration = Duration::from_millis(250);
const MAX_DATAGRAM: usize = 65_536;
/// Handshake messages a second before the interface answers with cookies (boringtun's
/// default per peer).
const HANDSHAKE_RATE_LIMIT: u64 = 10;
/// Once one peer has answered, how long a connect waits for the others before going ahead.
const OTHERS_GRACE: Duration = Duration::from_secs(2);

/// Which peers have completed a handshake, for [`start`] to wait on.
struct PeerStatus(Vec<AtomicBool>);

impl PeerStatus {
    fn new(n: usize) -> Self {
        Self((0..n).map(|_| AtomicBool::new(false)).collect())
    }

    fn is_up(&self, peer: usize) -> bool {
        self.0[peer].load(Ordering::Relaxed)
    }

    fn set_up(&self, peer: usize) {
        self.0[peer].store(true, Ordering::Relaxed);
    }
}

async fn resolve(endpoint: &str) -> Result<SocketAddr, VpnError> {
    tokio::net::lookup_host(endpoint)
        .await
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| VpnError::Resolve(endpoint.to_owned()))
}

/// Starts the tunnel and waits for the handshakes, so a wrong key or unreachable endpoint
/// fails here with a clear error rather than as a mysterious connect timeout. With several
/// peers, one answering is enough: the others get [`OTHERS_GRACE`] to follow, then keep
/// trying in the background.
pub async fn start(cfg: WgConfig) -> Result<Tunnel, VpnError> {
    let mut endpoints = Vec::with_capacity(cfg.peers.len());
    for peer in &cfg.peers {
        endpoints.push(match &peer.endpoint {
            Some(e) => Some(resolve(e).await?),
            None => None,
        });
    }
    let bind: SocketAddr = if endpoints.iter().flatten().all(SocketAddr::is_ipv4) {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("literal");
    let timeout = cfg.handshake_timeout;
    let (tunnel, status) = spawn(cfg, endpoints.clone(), bind)?;
    let wanted: Vec<(usize, SocketAddr)> = endpoints
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e.map(|e| (i, e)))
        .collect();
    let started = Instant::now();
    let mut first_up = None;
    loop {
        let up = wanted.iter().filter(|(i, _)| status.is_up(*i)).count();
        if up == wanted.len() {
            break;
        }
        if up > 0 && first_up.get_or_insert_with(Instant::now).elapsed() >= OTHERS_GRACE {
            break;
        }
        if started.elapsed() >= timeout {
            if up > 0 {
                break;
            }
            tunnel.shutdown();
            let to = match &wanted[..] {
                [(_, one)] => one.to_string(),
                all => format!(
                    "any peer ({})",
                    all.iter()
                        .map(|(_, e)| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            return Err(VpnError::Connect(format!(
                "no WireGuard handshake with {to}; check the endpoint, the keys, and that UDP \
                 isn't blocked"
            )));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for (i, e) in wanted.iter().filter(|(i, _)| !status.is_up(*i)) {
        tracing::warn!(peer = i + 1, endpoint = %e, "no WireGuard handshake with this peer yet");
    }
    Ok(tunnel)
}

/// An IPv4 address as a dual-stack IPv6 socket wants it.
fn for_socket(addr: SocketAddr, v6_socket: bool) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) if v6_socket => {
            SocketAddr::V6(SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0))
        }
        a => a,
    }
}

/// Binds the UDP socket and starts link + stack. Peers without an endpoint wait for the peer
/// to call (the in-process test server).
fn spawn(
    cfg: WgConfig,
    endpoints: Vec<Option<SocketAddr>>,
    bind: SocketAddr,
) -> Result<(Tunnel, Arc<PeerStatus>), VpnError> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(bind),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let v6 = bind.is_ipv6();
    if v6 {
        // Peers may be IPv4 and IPv6 at once.
        let _ = sock.set_only_v6(false);
    }
    // Bursts of encrypted segments; the OS may cap these, which is fine.
    let _ = sock.set_recv_buffer_size(4 << 20);
    let _ = sock.set_send_buffer_size(4 << 20);
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into())?;
    let send: std::net::UdpSocket = sock.into();
    let local = send.local_addr()?;
    let udp = UdpSocket::from_std(send.try_clone()?)?;

    let (io, stack_io) = link_pair();
    let state = Arc::new(LinkState::default());
    let status = Arc::new(PeerStatus::new(cfg.peers.len()));
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(run(
        Link {
            peers: Peers::new(&cfg, &endpoints, v6),
            udp,
            send,
        },
        io,
        state.clone(),
        status.clone(),
        stop_rx,
    ));
    let known: Vec<String> = endpoints
        .iter()
        .flatten()
        .map(ToString::to_string)
        .collect();
    let allowed = cfg.allowed_ips();
    let info = TunnelInfo {
        server: if known.is_empty() {
            local.to_string()
        } else {
            known.join(", ")
        },
        addresses: cfg.addresses.clone(),
        dns: cfg.dns.clone(),
        search_domains: vec![],
        routes: allowed.clone(),
        mtu: cfg.mtu,
        accepted_server_cert: None,
    };
    let stack = StackConfig {
        addresses: cfg.addresses.clone(),
        dns: cfg.dns.clone(),
        search_domains: vec![],
        mtu: cfg.mtu,
        allowed: Some(allowed),
        routes: vec![],
    };
    Ok((Tunnel::spawn(info, stack, stack_io, state, stop_tx), status))
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("system RNG");
    b
}

struct Peer {
    tunn: Tunn,
    /// Our 24-bit index for this peer's sessions.
    index: u32,
    public_key: [u8; 32],
    /// Where its packets go; follows the peer when it roams.
    endpoint: Option<SocketAddr>,
}

/// Every peer's WireGuard state and the table that picks between them. Network I/O stays
/// outside: what to send goes to a `send(datagram, to)` callback, decrypted packets to
/// `deliver`.
struct Peers {
    peers: Vec<Peer>,
    routes: RouteTable,
    secret: x25519::StaticSecret,
    public: x25519::PublicKey,
    /// Checks handshake MACs (cheap, needs our public key) and answers floods with cookies;
    /// one for the whole interface, as in boringtun's own device.
    limiter: Arc<RateLimiter>,
    limiter_reset: Instant,
}

impl Peers {
    fn new(cfg: &WgConfig, endpoints: &[Option<SocketAddr>], v6_socket: bool) -> Self {
        let secret = x25519::StaticSecret::from(cfg.private_key);
        let public = x25519::PublicKey::from(&secret);
        let limiter = Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT));
        // Session indices carry the peer's number in their top 24 bits; that is how replies
        // and data packets find their peer.
        let base = u32::from_le_bytes(random::<4>()) >> 8;
        let peers = cfg
            .peers
            .iter()
            .zip(endpoints)
            .enumerate()
            .map(|(i, (p, endpoint))| {
                let index = base.wrapping_add(i as u32) & 0x00ff_ffff;
                Peer {
                    tunn: Tunn::new(
                        secret.clone(),
                        x25519::PublicKey::from(p.public_key),
                        p.preshared_key,
                        p.keepalive,
                        index,
                        Some(limiter.clone()),
                    ),
                    index,
                    public_key: p.public_key,
                    endpoint: endpoint.map(|e| for_socket(e, v6_socket)),
                }
            })
            .collect();
        Self {
            peers,
            routes: RouteTable::new(cfg),
            secret,
            public,
            limiter,
            limiter_reset: Instant::now(),
        }
    }

    /// Starts a handshake with every peer we know the address of.
    fn initiate(&mut self, buf: &mut [u8], send: &mut impl FnMut(&[u8], SocketAddr)) {
        for peer in &mut self.peers {
            if let Some(to) = peer.endpoint
                && let TunnResult::WriteToNetwork(p) =
                    peer.tunn.format_handshake_initiation(buf, false)
            {
                send(p, to);
            }
        }
    }

    /// Which peer a (MAC-checked) message is from. A handshake initiation names its sender's
    /// static key (encrypted to ours); every other message carries the index we gave that peer.
    fn peer_of(&self, packet: &Packet) -> Option<usize> {
        let index = match packet {
            Packet::HandshakeInit(p) => {
                let half = parse_handshake_anon(&self.secret, &self.public, p).ok()?;
                return self
                    .peers
                    .iter()
                    .position(|peer| peer.public_key == half.peer_static_public);
            }
            Packet::HandshakeResponse(p) => p.receiver_idx,
            Packet::PacketCookieReply(p) => p.receiver_idx,
            Packet::PacketData(p) => p.receiver_idx,
        };
        self.peers.iter().position(|peer| peer.index == index >> 8)
    }

    /// A datagram from the network. Returns the peer it authenticated as, if it did.
    fn on_datagram(
        &mut self,
        datagram: &[u8],
        from: SocketAddr,
        buf: &mut [u8],
        send: &mut impl FnMut(&[u8], SocketAddr),
        deliver: &mut impl FnMut(&[u8]),
    ) -> Option<usize> {
        // Handshake MACs first: finding the peer of an initiation costs a Diffie-Hellman.
        let packet = match self.limiter.verify_packet(Some(from.ip()), datagram, buf) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                send(cookie, from);
                return None;
            }
            Err(_) => return None,
        };
        let Some(i) = self.peer_of(&packet) else {
            tracing::trace!(%from, "wireguard packet for no known peer");
            return None;
        };
        let peer = &mut self.peers[i];
        let src = match peer.tunn.decapsulate(Some(from.ip()), datagram, buf) {
            TunnResult::WriteToNetwork(packet) => {
                send(packet, from);
                while let TunnResult::WriteToNetwork(p) = peer.tunn.decapsulate(None, &[], buf) {
                    send(p, from);
                }
                None
            }
            TunnResult::WriteToTunnelV4(packet, src) => Some((packet, IpAddr::V4(src))),
            TunnResult::WriteToTunnelV6(packet, src) => Some((packet, IpAddr::V6(src))),
            TunnResult::Done => None,
            TunnResult::Err(e) => {
                tracing::trace!(?e, peer = i + 1, "wireguard decapsulate");
                return None;
            }
        };
        if let Some((packet, src)) = src {
            // Cryptokey routing: the source must be one of this peer's addresses.
            if self.routes.lookup(src) == Some(i) {
                deliver(packet);
            } else {
                tracing::trace!(%src, peer = i + 1, "dropping a packet from outside the peer's AllowedIPs");
            }
        }
        // WireGuard roaming: follow the peer to its latest address.
        peer.endpoint = Some(from);
        Some(i)
    }

    /// An IP packet from the stack, to the peer its destination routes to.
    fn on_outgoing(
        &mut self,
        packet: &[u8],
        buf: &mut [u8],
        send: &mut impl FnMut(&[u8], SocketAddr),
    ) {
        // The stack only sends to AllowedIPs, so every packet has a peer.
        let Some(i) = Tunn::dst_address(packet).and_then(|ip| self.routes.lookup(ip)) else {
            return;
        };
        let peer = &mut self.peers[i];
        match peer.tunn.encapsulate(packet, buf) {
            TunnResult::WriteToNetwork(out) => {
                if let Some(to) = peer.endpoint {
                    send(out, to);
                }
            }
            TunnResult::Err(e) => tracing::trace!(?e, peer = i + 1, "wireguard encapsulate"),
            _ => {}
        }
    }

    /// Handshake retries, rekeying and keepalives, for each peer on its own schedule.
    fn on_tick(&mut self, buf: &mut [u8], send: &mut impl FnMut(&[u8], SocketAddr)) {
        if self.limiter_reset.elapsed() >= Duration::from_secs(1) {
            self.limiter.reset_count();
            self.limiter_reset = Instant::now();
        }
        for (i, peer) in self.peers.iter_mut().enumerate() {
            match peer.tunn.update_timers(buf) {
                TunnResult::WriteToNetwork(p) => {
                    if let Some(to) = peer.endpoint {
                        send(p, to);
                    }
                }
                TunnResult::Err(e) => tracing::trace!(?e, peer = i + 1, "wireguard timers"),
                _ => {}
            }
        }
    }

    /// Whether peer `i` has a session.
    fn has_session(&self, i: usize) -> bool {
        self.peers[i].tunn.stats().0.is_some()
    }
}

struct Link {
    peers: Peers,
    udp: UdpSocket,
    /// Same socket (dup'd fd) for sending: tokio's `try_send_to` refuses until it has seen
    /// write readiness, which would silently drop the first handshake.
    send: std::net::UdpSocket,
}

async fn run(
    mut link: Link,
    mut io: LinkIo,
    state: Arc<LinkState>,
    status: Arc<PeerStatus>,
    mut stop: watch::Receiver<bool>,
) {
    let mut rx_buf = vec![0u8; MAX_DATAGRAM];
    let mut tx_buf = vec![0u8; MAX_DATAGRAM];
    let sock = &link.send;
    // Non-blocking; a full buffer drops the datagram, and TCP inside the tunnel retransmits.
    let mut send = |packet: &[u8], to: SocketAddr| {
        if let Err(e) = sock.send_to(packet, to) {
            tracing::trace!(%e, "udp send");
        }
    };
    let to_stack = io.to_stack.clone();
    let mut deliver = |packet: &[u8]| {
        let _ = to_stack.try_send(packet.to_vec());
    };
    link.peers.initiate(&mut tx_buf, &mut send);
    let mut tick = tokio::time::interval(WG_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = stop.changed() => if r.is_err() || *stop.borrow() { break },
            r = link.udp.recv_from(&mut rx_buf) => {
                let Ok((n, from)) = r else { continue };
                let valid = link.peers.on_datagram(&rx_buf[..n], from, &mut tx_buf, &mut send, &mut deliver);
                if let Some(i) = valid
                    && !status.is_up(i)
                    && link.peers.has_session(i)
                {
                    status.set_up(i);
                    state.up.store(true, Ordering::Relaxed);
                }
            }
            packet = io.from_stack.recv() => {
                let Some(packet) = packet else { break };
                link.peers.on_outgoing(&packet, &mut tx_buf, &mut send);
            }
            _ = tick.tick() => link.peers.on_tick(&mut tx_buf, &mut send),
        }
    }
    state.up.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use std::io;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::IpNet;
    use crate::testutil::{echo_on, exercise, init_tracing};

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut sk = [0u8; 32];
        getrandom::fill(&mut sk).unwrap();
        let pk = STANDARD
            .decode(public_key(&sk))
            .unwrap()
            .try_into()
            .unwrap();
        (sk, pk)
    }

    fn peer(pk: [u8; 32], endpoint: Option<&str>, allowed: &[&str]) -> WgPeer {
        WgPeer {
            public_key: pk,
            preshared_key: None,
            endpoint: endpoint.map(Into::into),
            allowed_ips: allowed.iter().map(|a| IpNet::parse(a).unwrap()).collect(),
            keepalive: None,
        }
    }

    fn with_peers(sk: [u8; 32], addr: &str, peers: Vec<WgPeer>) -> WgConfig {
        WgConfig {
            private_key: sk,
            addresses: vec![IpNet::parse(addr).unwrap()],
            dns: vec![],
            mtu: 1420,
            peers,
            handshake_timeout: Duration::from_secs(5),
        }
    }

    fn cfg(sk: [u8; 32], addr: &str, pk: [u8; 32], endpoint: &str, allowed: &[&str]) -> WgConfig {
        with_peers(sk, addr, vec![peer(pk, Some(endpoint), allowed)])
    }

    /// An in-process WireGuard "server" peer at `addr` with an echo service on :22, accepting
    /// the client's 10.77.0.2.
    async fn echo_peer_at(client_pk: [u8; 32], addr: &str) -> ([u8; 32], Tunnel) {
        let (sk, pk) = keypair();
        let (server, _) = spawn(
            with_peers(sk, addr, vec![peer(client_pk, None, &["10.77.0.2/32"])]),
            vec![None],
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        echo_on(&server, 22).await;
        (pk, server)
    }

    async fn echo_peer(client_pk: [u8; 32]) -> ([u8; 32], Tunnel) {
        echo_peer_at(client_pk, "10.77.0.1/24").await
    }

    async fn client() -> (Tunnel, Tunnel) {
        init_tracing();
        let (sk, pk) = keypair();
        let (server_pk, server) = echo_peer(pk).await;
        let tunnel = start(cfg(
            sk,
            "10.77.0.2/32",
            server_pk,
            &server.info().server,
            &["10.77.0.0/24"],
        ))
        .await
        .expect("handshake");
        (tunnel, server)
    }

    async fn round_trip(tunnel: &Tunnel, ip: &str, msg: &[u8]) {
        let mut s = tokio::time::timeout(Duration::from_secs(5), tunnel.connect(ip, 22))
            .await
            .unwrap_or_else(|_| panic!("connect to {ip} timed out"))
            .unwrap_or_else(|e| panic!("connect to {ip}: {e}"));
        s.write_all(msg).await.unwrap();
        let mut back = vec![0u8; msg.len()];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(back, msg);
    }

    #[tokio::test]
    async fn tcp_echo_through_the_tunnel() {
        let (tunnel, _server) = client().await;
        round_trip(&tunnel, "10.77.0.1", b"SSH-2.0-hello\r\n").await;
    }

    #[tokio::test]
    async fn bulk_transfer_with_flow_control() {
        let (tunnel, _server) = client().await;
        let s = tunnel.connect("10.77.0.1", 22).await.unwrap();
        exercise(s, 2 * 1024 * 1024).await;
    }

    #[tokio::test]
    async fn several_streams_at_once() {
        let (tunnel, _server) = client().await;
        let mut tasks = Vec::new();
        let tunnel = Arc::new(tunnel);
        for i in 0..5u8 {
            let t = tunnel.clone();
            tasks.push(tokio::spawn(async move {
                let mut s = t.connect("10.77.0.1", 22).await.unwrap();
                let msg = vec![i; 1000];
                s.write_all(&msg).await.unwrap();
                let mut back = vec![0; 1000];
                s.read_exact(&mut back).await.unwrap();
                assert_eq!(back, msg);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    #[tokio::test]
    async fn closed_port_and_allowed_ips() {
        let (tunnel, _server) = client().await;
        let e = tunnel.connect("10.77.0.1", 2222).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "{e}");
        let e = tunnel.connect("192.168.1.1", 22).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
    }

    #[tokio::test]
    async fn shutdown_cuts_streams_and_fails_new_connects() {
        let (tunnel, _server) = client().await;
        let mut s = tunnel.connect("10.77.0.1", 22).await.unwrap();
        tunnel.shutdown();
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("stream not cut");
        assert!(matches!(r, Ok(0) | Err(_)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!tunnel.is_alive());
        assert!(tunnel.connect("10.77.0.1", 22).await.is_err());
    }

    #[tokio::test]
    async fn wrong_key_fails_at_handshake() {
        let (sk, pk) = keypair();
        let (_, server) = echo_peer(pk).await;
        let (_, wrong_server_pk) = keypair();
        let mut c = cfg(
            sk,
            "10.77.0.2/32",
            wrong_server_pk,
            &server.info().server,
            &["10.77.0.0/24"],
        );
        c.handshake_timeout = Duration::from_millis(800);
        match start(c).await {
            Err(VpnError::Connect(m)) => assert!(m.contains("no WireGuard handshake"), "{m}"),
            other => panic!("{:?}", other.map(|_| ())),
        }
    }

    /// Two gateways, each with its own network: traffic goes to the right one, both ways.
    #[tokio::test]
    async fn two_peers_each_with_its_own_network() {
        init_tracing();
        let (sk, pk) = keypair();
        let (a_pk, a) = echo_peer_at(pk, "10.77.0.1/24").await;
        let (b_pk, b) = echo_peer_at(pk, "10.88.0.1/24").await;
        let tunnel = start(with_peers(
            sk,
            "10.77.0.2/32",
            vec![
                peer(a_pk, Some(&a.info().server), &["10.77.0.0/24"]),
                peer(b_pk, Some(&b.info().server), &["10.88.0.0/24"]),
            ],
        ))
        .await
        .expect("handshakes");
        assert!(
            tunnel.info().server.contains(", "),
            "{}",
            tunnel.info().server
        );
        assert_eq!(tunnel.info().routes.len(), 2);
        round_trip(&tunnel, "10.77.0.1", b"to a").await;
        round_trip(&tunnel, "10.88.0.1", b"to b").await;
        let s = tunnel.connect("10.88.0.1", 22).await.unwrap();
        exercise(s, 512 * 1024).await;
    }

    /// A /16 inside another peer's /8 goes to the peer with the /16; the rest of the /8 to
    /// the other one. Each gateway only owns its own address, so a wrong pick times out.
    #[tokio::test]
    async fn the_most_specific_allowed_ips_win() {
        init_tracing();
        let (sk, pk) = keypair();
        let (wide_pk, wide) = echo_peer_at(pk, "10.6.0.1/32").await;
        let (narrow_pk, narrow) = echo_peer_at(pk, "10.5.0.1/32").await;
        let tunnel = start(with_peers(
            sk,
            "10.77.0.2/32",
            vec![
                peer(wide_pk, Some(&wide.info().server), &["10.0.0.0/8"]),
                peer(narrow_pk, Some(&narrow.info().server), &["10.5.0.0/16"]),
            ],
        ))
        .await
        .unwrap();
        round_trip(&tunnel, "10.5.0.1", b"narrow").await;
        round_trip(&tunnel, "10.6.0.1", b"wide").await;
    }

    /// A gateway that never answers doesn't keep the others from working.
    #[tokio::test]
    async fn a_silent_peer_does_not_block_the_others() {
        init_tracing();
        let (sk, pk) = keypair();
        let (a_pk, a) = echo_peer_at(pk, "10.77.0.1/24").await;
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (silent_pk, _) = keypair();
        let started = Instant::now();
        let tunnel = start(with_peers(
            sk,
            "10.77.0.2/32",
            vec![
                peer(
                    silent_pk,
                    Some(&silent.local_addr().unwrap().to_string()),
                    &["10.99.0.0/24"],
                ),
                peer(a_pk, Some(&a.info().server), &["10.77.0.0/24"]),
            ],
        ))
        .await
        .expect("one peer is enough");
        assert!(started.elapsed() < Duration::from_secs(4));
        round_trip(&tunnel, "10.77.0.1", b"still works").await;
    }

    /// Connections the other way round: a gateway (10.88.0.1) dials the client.
    #[tokio::test]
    async fn a_gateway_can_dial_in() {
        init_tracing();
        let (sk, pk) = keypair();
        let (gw_pk, gw) = echo_peer_at(pk, "10.88.0.1/24").await;
        let tunnel = start(with_peers(
            sk,
            "10.77.0.2/32",
            vec![
                peer(keypair().1, None, &["10.99.0.0/24"]),
                peer(gw_pk, Some(&gw.info().server), &["10.88.0.0/24"]),
            ],
        ))
        .await
        .unwrap();
        echo_on(&tunnel, 22).await;
        let s = tokio::time::timeout(Duration::from_secs(5), gw.connect("10.77.0.2", 22))
            .await
            .expect("dial timed out")
            .expect("dial");
        exercise(s, 16 * 1024).await;
    }

    /// A minimal IPv4/UDP packet.
    fn ipv4_packet(src: &str, dst: &str) -> Vec<u8> {
        let (src, dst): (std::net::Ipv4Addr, std::net::Ipv4Addr) =
            (src.parse().unwrap(), dst.parse().unwrap());
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    /// Cryptokey routing on the way in: a peer may only send from its own AllowedIPs, not from
    /// another peer's addresses or anywhere else.
    #[test]
    fn packets_from_outside_a_peers_allowed_ips_are_dropped() {
        let (client_sk, client_pk) = keypair();
        let (gw_sk, gw_pk) = keypair();
        let gw_addr: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let other_addr: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        let cfg = with_peers(
            client_sk,
            "10.77.0.2/32",
            vec![
                peer(keypair().1, Some("192.0.2.2:51820"), &["10.99.0.0/24"]),
                peer(gw_pk, Some("192.0.2.1:51820"), &["10.88.0.0/24"]),
            ],
        );
        let mut client = Peers::new(&cfg, &[Some(other_addr), Some(gw_addr)], false);
        let mut gw = Tunn::new(
            x25519::StaticSecret::from(gw_sk),
            x25519::PublicKey::from(client_pk),
            None,
            None,
            7,
            None,
        );
        let (mut buf, mut gw_buf) = (vec![0u8; 2048], vec![0u8; 2048]);

        // Handshake: the client's initiation, the gateway's response, the client's keepalive.
        let mut sent = Vec::new();
        client.initiate(&mut buf, &mut |p, to| sent.push((p.to_vec(), to)));
        assert_eq!(sent.len(), 2, "one initiation per peer");
        let init = sent
            .iter()
            .find(|(_, to)| *to == gw_addr)
            .unwrap()
            .0
            .clone();
        let TunnResult::WriteToNetwork(response) = gw.decapsulate(None, &init, &mut gw_buf) else {
            panic!("no handshake response")
        };
        let response = response.to_vec();
        let mut sent = Vec::new();
        let from = client.on_datagram(
            &response,
            gw_addr,
            &mut buf,
            &mut |p, to| sent.push((p.to_vec(), to)),
            &mut |_| {},
        );
        assert_eq!(from, Some(1));
        assert!(client.has_session(1) && !client.has_session(0));
        for (keepalive, to) in &sent {
            assert_eq!(*to, gw_addr);
            gw.decapsulate(None, keepalive, &mut gw_buf);
        }

        for (src, accepted) in [
            ("10.88.0.1", true),
            ("10.99.0.1", false),
            ("10.77.0.9", false),
        ] {
            let TunnResult::WriteToNetwork(data) =
                gw.encapsulate(&ipv4_packet(src, "10.77.0.2"), &mut gw_buf)
            else {
                panic!("gateway has no session")
            };
            let data = data.to_vec();
            let mut got = Vec::new();
            let from = client.on_datagram(&data, gw_addr, &mut buf, &mut |_, _| {}, &mut |p| {
                got.push(p.to_vec())
            });
            assert_eq!(from, Some(1), "authenticated as the gateway");
            assert_eq!(got.len(), usize::from(accepted), "packet from {src}");
        }

        // Replies go to the gateway that owns the destination.
        let mut sent = Vec::new();
        client.on_outgoing(
            &ipv4_packet("10.77.0.2", "10.88.0.1"),
            &mut buf,
            &mut |p, to| sent.push((p.to_vec(), to)),
        );
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, gw_addr);
        assert!(matches!(
            gw.decapsulate(None, &sent[0].0, &mut gw_buf),
            TunnResult::WriteToTunnelV4(..)
        ));
    }

    /// A handshake initiation without a valid MAC (it needs our public key) goes nowhere.
    #[test]
    fn forged_handshakes_are_dropped() {
        let (sk, _) = keypair();
        let gw: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let cfg = with_peers(
            sk,
            "10.77.0.2/32",
            vec![peer(keypair().1, Some("192.0.2.1:51820"), &["10.0.0.0/8"])],
        );
        let mut peers = Peers::new(&cfg, &[Some(gw)], false);
        let mut forged = vec![0u8; 148];
        forged[0] = 1;
        let mut replies = 0;
        let from = peers.on_datagram(
            &forged,
            "198.51.100.7:4444".parse().unwrap(),
            &mut [0u8; 2048],
            &mut |_, _| replies += 1,
            &mut |_| panic!("delivered"),
        );
        assert_eq!((from, replies), (None, 0));
    }

    #[test]
    fn ipv4_peers_on_a_dual_stack_socket() {
        let v4: SocketAddr = "192.0.2.7:51820".parse().unwrap();
        assert_eq!(for_socket(v4, false), v4);
        assert_eq!(for_socket(v4, true).to_string(), "[::ffff:192.0.2.7]:51820");
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(for_socket(v6, true), v6);
    }

    /// The real thing end to end: an `mg-ssh` session whose TCP runs through this WireGuard
    /// tunnel. The in-process peer acts as an exit node forwarding 10.77.0.1:22 to `MG_TEST_SSH`.
    #[tokio::test]
    #[ignore = "needs MG_TEST_SSH and MG_TEST_KEY (see crates/mg-ssh/tests/live.rs)"]
    async fn ssh_session_over_wireguard() {
        let (Ok(target), Ok(key)) = (std::env::var("MG_TEST_SSH"), std::env::var("MG_TEST_KEY"))
        else {
            return;
        };
        let user = std::env::var("MG_TEST_USER").unwrap_or_else(|_| "mg".into());

        // Exit node: the peer accepts on 10.77.0.1:22 and relays to the real sshd.
        let (sk, pk) = keypair();
        let (server_sk, server_pk) = keypair();
        let (server, _) = spawn(
            with_peers(
                server_sk,
                "10.77.0.1/24",
                vec![peer(pk, None, &["10.77.0.2/32"])],
            ),
            vec![None],
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut accepted = server.listen(22).await;
        tokio::spawn(async move {
            while let Some(mut inside) = accepted.recv().await {
                let target = target.clone();
                tokio::spawn(async move {
                    let mut outside = tokio::net::TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut inside, &mut outside).await;
                });
            }
        });
        let tunnel = Arc::new(
            start(cfg(
                sk,
                "10.77.0.2/32",
                server_pk,
                &server.info().server,
                &["10.77.0.0/24"],
            ))
            .await
            .unwrap(),
        );
        let out =
            crate::testutil::ssh_echo(tunnel, "10.77.0.1", 22, &user, &key, "over-wireguard").await;
        assert!(out.contains("over-wireguard-42"), "output was: {out}");
    }
}
