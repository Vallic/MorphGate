//! One OpenVPN session: reset handshake, TLS over the reliability layer, key method 2, push,
//! then the data channel with keepalives and server-initiated renegotiation.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::ClientConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::config::{Cipher, Compress, Config, Proto, Remote};
use super::data::DataChannel;
use super::keys::{self, ClientRandom, ServerRandom};
use super::push::Pushed;
use super::reliable::Reliable;
use super::wire::{self, Control, SessionId, Wrap};
use super::{compress, tls};
use crate::netstack::{LinkIo, LinkState};

const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
const OCC_MAGIC: [u8; 16] = [
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
];
const OCC_EXIT: u8 = 6;
/// TLS bytes per control packet; keeps packets under OpenVPN's default `tls-mtu` (1250).
const CONTROL_CHUNK: usize = 1100;
const PUSH_RETRY: Duration = Duration::from_secs(5);
/// How long the previous key keeps decrypting after a renegotiation (`tran-window`).
const TRANSITION: Duration = Duration::from_secs(60);
const DEFAULT_PING: Duration = Duration::from_secs(10);

/// The longest a server may keep a sign-in pending (OpenVPN caps it at half the default
/// renegotiation interval).
const MAX_PENDING: Duration = Duration::from_secs(1800);

pub struct Params {
    pub cfg: Arc<Config>,
    pub tls: Arc<rustls::ClientConfig>,
    pub remote: Remote,
    /// `None` when the profile doesn't use `auth-user-pass`.
    pub credentials: Option<(String, Zeroizing<String>)>,
    /// What the user has to act on while the session waits.
    pub notices: mpsc::UnboundedSender<Notice>,
}

/// Something for the user while the session is being set up.
#[derive(Debug, PartialEq, Eq)]
pub enum Notice {
    /// Sign in on this web page (`WEB_AUTH` / `OPEN_URL`); the server says when it's done.
    WebSignIn(String),
}

#[derive(Debug)]
pub enum Failure {
    /// No answer or network trouble: try the next server.
    Unreachable(String),
    /// The server rejected the credentials.
    AuthFailed(String),
    /// Dynamic challenge (`CRV1`): ask the user, then reconnect with the answer.
    Challenge {
        state_id: String,
        username: String,
        text: String,
        echo: bool,
    },
    /// TLS, protocol or configuration trouble: stop.
    Fatal(String),
}

pub struct Ready {
    pub pushed: Pushed,
    pub cipher: Cipher,
    pub server: SocketAddr,
}

// ------------------------------------------------------------------------------- transport

enum Sender {
    Udp(Arc<UdpSocket>),
    Tcp(mpsc::Sender<Vec<u8>>),
}

impl Sender {
    async fn send(&self, packet: Vec<u8>, droppable: bool) {
        match self {
            Sender::Udp(s) => {
                if let Err(e) = s.send(&packet).await {
                    tracing::trace!(%e, "openvpn udp send");
                }
            }
            Sender::Tcp(tx) if droppable => {
                let _ = tx.try_send(packet);
            }
            Sender::Tcp(tx) => {
                let _ = tx.send(packet).await;
            }
        }
    }
}

async fn connect(
    remote: &Remote,
    timeout: Duration,
) -> Result<(Sender, mpsc::Receiver<Vec<u8>>, SocketAddr), String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((remote.host.as_str(), remote.port))
        .await
        .map_err(|e| format!("cannot resolve {}: {e}", remote.host))?
        .collect();
    let first = *addrs
        .first()
        .ok_or_else(|| format!("cannot resolve {}", remote.host))?;
    let (tx, rx) = mpsc::channel(1024);
    match remote.proto {
        Proto::Udp => {
            let bind: SocketAddr = if first.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .expect("literal");
            let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
            sock.connect(first).await.map_err(|e| e.to_string())?;
            let sock = Arc::new(sock);
            let reader = sock.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                loop {
                    tokio::select! {
                        r = reader.recv(&mut buf) => match r {
                            Ok(n) => {
                                if tx.try_send(buf[..n].to_vec()).is_err() && tx.is_closed() {
                                    break;
                                }
                            }
                            // ICMP errors (port unreachable) surface here; keep listening.
                            Err(e) => {
                                tracing::trace!(%e, "openvpn udp recv");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        },
                        _ = tx.closed() => break,
                    }
                }
            });
            Ok((Sender::Udp(sock), rx, first))
        }
        Proto::Tcp => {
            let mut last = String::new();
            for addr in addrs {
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_nodelay(true);
                        let (mut rd, mut wr) = stream.into_split();
                        tokio::spawn(async move {
                            loop {
                                let mut len = [0u8; 2];
                                if rd.read_exact(&mut len).await.is_err() {
                                    break;
                                }
                                let mut p = vec![0u8; usize::from(u16::from_be_bytes(len))];
                                if rd.read_exact(&mut p).await.is_err() || tx.send(p).await.is_err()
                                {
                                    break;
                                }
                            }
                        });
                        let (wtx, mut wrx) = mpsc::channel::<Vec<u8>>(256);
                        tokio::spawn(async move {
                            while let Some(p) = wrx.recv().await {
                                let mut framed = Vec::with_capacity(p.len() + 2);
                                framed.extend_from_slice(&(p.len() as u16).to_be_bytes());
                                framed.extend_from_slice(&p);
                                if wr.write_all(&framed).await.is_err() {
                                    break;
                                }
                            }
                            let _ = wr.shutdown().await;
                        });
                        return Ok((Sender::Tcp(wtx), rx, addr));
                    }
                    Ok(Err(e)) => last = format!("{addr}: {e}"),
                    Err(_) => last = format!("{addr}: connection timed out"),
                }
            }
            Err(last)
        }
    }
}

// ------------------------------------------------------------------------------- key states

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Our reset is out; waiting for the server's.
    Reset,
    /// TLS handshake and key exchange.
    Tls,
    /// Data keys installed.
    Active,
}

struct KeyState {
    key_id: u8,
    rel: Reliable,
    tls: ClientConnection,
    random: ClientRandom,
    phase: Phase,
    sent_keys: bool,
    server_random: Option<ServerRandom>,
    plaintext: Vec<u8>,
    data: Option<DataChannel>,
    started: Instant,
    retire_at: Option<Instant>,
}

impl KeyState {
    fn new(key_id: u8, reset_opcode: u8, p: &Params, rto: Duration) -> Result<Self, String> {
        let tls = ClientConnection::new(p.tls.clone(), tls::server_name())
            .map_err(|e| format!("TLS setup: {e}"))?;
        let mut rel = Reliable::new(rto);
        rel.queue(reset_opcode, Vec::new());
        Ok(Self {
            key_id,
            rel,
            tls,
            random: ClientRandom::generate(),
            phase: Phase::Reset,
            sent_keys: false,
            server_random: None,
            plaintext: Vec::new(),
            data: None,
            started: Instant::now(),
            retire_at: None,
        })
    }
}

// ------------------------------------------------------------------------------- session

enum Event {
    Ready,
    Failed(Failure),
    /// The link went down after it was up.
    Down(String),
}

struct Session {
    p: Params,
    rto: Duration,
    wrap: Wrap,
    local_sid: SessionId,
    remote_sid: Option<SessionId>,
    keys: Vec<KeyState>,
    primary: Option<u8>,
    pushed: Pushed,
    push_done: bool,
    push_sent_at: Option<Instant>,
    cipher: Option<Cipher>,
    compress: Compress,
    peer_id: Option<u32>,
    auth_token: Option<Zeroizing<String>>,
    auth_token_user: Option<String>,
    ping: Duration,
    ping_restart: Option<Duration>,
    started: Instant,
    /// The server deferred the sign-in (`AUTH_PENDING`) until this.
    pending_until: Option<Instant>,
    /// The page the server asked the user to sign in on, once asked.
    web_sign_in: Option<String>,
    last_recv: Instant,
    last_send: Instant,
    /// Wire packets to send: (packet, droppable).
    out: Vec<(Vec<u8>, bool)>,
    to_stack: Vec<Vec<u8>>,
    event: Option<Event>,
}

fn options_string(cfg: &Config, proto: Proto) -> String {
    let cipher = cfg.fallback_cipher.unwrap_or(cfg.data_ciphers[0]);
    let auth = if cipher.is_aead() {
        "[null-digest]".to_owned()
    } else {
        format!("{:?}", cfg.auth).to_ascii_uppercase()
    };
    let mut s = format!(
        "V4,dev-type tun,link-mtu 1549,tun-mtu {},proto {},cipher {},auth {auth},keysize {},key-method 2,tls-client",
        cfg.tun_mtu,
        if proto == Proto::Udp {
            "UDPv4"
        } else {
            "TCPv4_CLIENT"
        },
        cipher.name(),
        cipher.key_len() * 8,
    );
    if matches!(cfg.compress, Compress::Lzo | Compress::LzoStub) {
        s.push_str(",comp-lzo");
    }
    s
}

fn peer_info(cfg: &Config) -> String {
    let plat = if cfg!(target_os = "macos") {
        "mac"
    } else if cfg!(windows) {
        "win"
    } else {
        "linux"
    };
    // Bit 1: P_DATA_V2 (peer-id), bit 3: tls-ekm key derivation, bit 4: AUTH_PENDING with a
    // timeout.
    let proto = 2 | 16 | if cfg.ekm { 8 } else { 0 };
    let ciphers: Vec<&str> = cfg.data_ciphers.iter().map(|c| c.name()).collect();
    // IV_SSO: the web sign-in kinds we can hand to a browser.
    format!(
        "IV_VER=2.6.12\nIV_PLAT={plat}\nIV_PROTO={proto}\nIV_NCP=2\nIV_CIPHERS={}\nIV_TCPNL=1\n\
         IV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_SSO=webauth,openurl\n\
         IV_GUI_VER=MorphGate_{}\n",
        ciphers.join(":"),
        env!("CARGO_PKG_VERSION"),
    )
}

impl Session {
    fn new(p: Params) -> Result<Self, String> {
        let rto = match p.remote.proto {
            Proto::Udp => Duration::from_secs(2),
            Proto::Tcp => Duration::from_secs(10),
        };
        let mut local_sid = [0u8; 8];
        getrandom::fill(&mut local_sid).expect("system RNG");
        let wrap = Wrap::client(p.cfg.tls_wrap.as_ref(), p.cfg.auth);
        let reset = if wrap.is_v2() {
            wire::CONTROL_HARD_RESET_CLIENT_V3
        } else {
            wire::CONTROL_HARD_RESET_CLIENT_V2
        };
        let first = KeyState::new(0, reset, &p, rto)?;
        let now = Instant::now();
        Ok(Self {
            wrap,
            compress: p.cfg.compress,
            rto,
            local_sid,
            remote_sid: None,
            keys: vec![first],
            primary: None,
            pushed: Pushed::default(),
            push_done: false,
            push_sent_at: None,
            cipher: None,
            peer_id: None,
            auth_token: None,
            auth_token_user: None,
            ping: DEFAULT_PING,
            ping_restart: None,
            started: now,
            pending_until: None,
            web_sign_in: None,
            last_recv: now,
            last_send: now,
            out: Vec::new(),
            to_stack: Vec::new(),
            event: None,
            p,
        })
    }

    fn ready(&self) -> bool {
        self.primary.is_some()
    }

    fn fail(&mut self, f: Failure) {
        if self.event.is_none() {
            self.event = Some(if self.ready() {
                Event::Down(match f {
                    Failure::Unreachable(m)
                    | Failure::AuthFailed(m)
                    | Failure::Fatal(m)
                    | Failure::Challenge { text: m, .. } => m,
                })
            } else {
                Event::Failed(f)
            });
        }
    }

    fn key_index(&self, key_id: u8) -> Option<usize> {
        self.keys.iter().position(|k| k.key_id == key_id)
    }

    // --------------------------------------------------------------------- incoming

    fn on_packet(&mut self, packet: &[u8]) {
        let Some(&first) = packet.first() else { return };
        let op = wire::opcode(first);
        if op == wire::DATA_V1 || op == wire::DATA_V2 {
            self.on_data(op, wire::key_id(first), packet);
        } else if wire::is_control(op) {
            match self.wrap.decode(packet) {
                Some(c) => self.on_control(c),
                None => tracing::debug!(op, "dropping control packet that failed authentication"),
            }
        }
    }

    fn on_control(&mut self, c: Control) {
        match self.remote_sid {
            None if c.opcode == wire::CONTROL_HARD_RESET_SERVER_V2 => {
                self.remote_sid = Some(c.session_id);
                self.wrap.reset_replay();
            }
            None => return,
            Some(sid) if sid != c.session_id => return,
            Some(_) => {}
        }
        if c.acked_session.is_some_and(|s| s != self.local_sid) {
            return;
        }
        self.last_recv = Instant::now();
        let i = match self.key_index(c.key_id) {
            Some(i) => i,
            None if c.opcode == wire::CONTROL_SOFT_RESET_V1 && self.ready() => {
                // The server renegotiates: a fresh TLS session under the new key id.
                match KeyState::new(c.key_id, wire::CONTROL_SOFT_RESET_V1, &self.p, self.rto) {
                    Ok(ks) => {
                        tracing::debug!(key_id = c.key_id, "openvpn renegotiation");
                        self.keys.push(ks);
                        self.keys.len() - 1
                    }
                    Err(e) => return self.fail(Failure::Fatal(e)),
                }
            }
            None => return,
        };
        self.keys[i].rel.acked(&c.acks);
        let Some(id) = c.msg_id else { return };
        for (op, payload) in self.keys[i].rel.received(id, c.opcode, c.payload) {
            match op {
                wire::CONTROL_HARD_RESET_SERVER_V2 | wire::CONTROL_SOFT_RESET_V1 => {
                    if self.keys[i].phase == Phase::Reset {
                        // The server is there: start TLS (our ClientHello is waiting).
                        self.keys[i].phase = Phase::Tls;
                        if op == wire::CONTROL_HARD_RESET_SERVER_V2
                            && self.wrap.is_v2()
                            && wire::wants_wkc_again(&payload)
                        {
                            // The server kept no state: our next packet (it acks the reset)
                            // carries the wrapped key again.
                            tracing::debug!("openvpn server asks for the tls-crypt-v2 key again");
                            self.keys[i].rel.queue(wire::CONTROL_WKC_V1, Vec::new());
                        }
                        self.flush_tls(i);
                    }
                }
                wire::CONTROL_V1 => self.on_tls(i, &payload),
                _ => {}
            }
            if self.event.is_some() {
                return;
            }
        }
    }

    fn on_tls(&mut self, i: usize, payload: &[u8]) {
        let ks = &mut self.keys[i];
        if let Err(e) = ks.tls.read_tls(&mut &payload[..]) {
            return self.fail(Failure::Fatal(format!("TLS: {e}")));
        }
        if let Err(e) = ks.tls.process_new_packets() {
            // Flush the alert so the server logs why.
            self.flush_tls(i);
            return self.fail(Failure::Fatal(tls_error(&e)));
        }
        let ks = &mut self.keys[i];
        if !ks.tls.is_handshaking() && !ks.sent_keys {
            ks.sent_keys = true;
            let creds = self.p.credentials.as_ref().map(|(u, pw)| {
                // After the first login a pushed auth-token replaces the password.
                match &self.auth_token {
                    Some(t) => (
                        self.auth_token_user.clone().unwrap_or_else(|| u.clone()),
                        Zeroizing::new(t.to_string()),
                    ),
                    None => (u.clone(), pw.clone()),
                }
            });
            let msg = keys::client_message(
                &ks.random,
                &options_string(&self.p.cfg, self.p.remote.proto),
                creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
                &peer_info(&self.p.cfg),
            );
            if let Err(e) = ks.tls.writer().write_all(&msg) {
                return self.fail(Failure::Fatal(format!("TLS: {e}")));
            }
        }
        let mut buf = [0u8; 4096];
        loop {
            match self.keys[i].tls.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.keys[i].plaintext.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        self.flush_tls(i);
        self.on_plaintext(i);
    }

    fn flush_tls(&mut self, i: usize) {
        let ks = &mut self.keys[i];
        let mut bytes = Vec::new();
        while ks.tls.wants_write() {
            if ks.tls.write_tls(&mut bytes).is_err() {
                break;
            }
        }
        for chunk in bytes.chunks(CONTROL_CHUNK) {
            ks.rel.queue(wire::CONTROL_V1, chunk.to_vec());
        }
    }

    fn on_plaintext(&mut self, i: usize) {
        if self.keys[i].server_random.is_none() {
            match keys::parse_server_message(&self.keys[i].plaintext) {
                None => return,
                Some(Err(e)) => return self.fail(Failure::Fatal(e.into())),
                Some(Ok((r, used))) => {
                    self.keys[i].server_random = Some(r);
                    self.keys[i].plaintext.drain(..used);
                    if self.ready() {
                        // Renegotiation: same cipher, new keys.
                        self.install_keys(i);
                    } else {
                        self.send_push_request(i);
                    }
                }
            }
        }
        while let Some(end) = self.keys[i].plaintext.iter().position(|b| *b == 0) {
            let msg: Vec<u8> = self.keys[i].plaintext.drain(..=end).collect();
            let text = String::from_utf8_lossy(&msg[..end]).into_owned();
            self.on_message(&text);
            if self.event.is_some() {
                return;
            }
        }
    }

    fn send_push_request(&mut self, i: usize) {
        let ks = &mut self.keys[i];
        if ks.tls.writer().write_all(b"PUSH_REQUEST\0").is_ok() {
            self.push_sent_at = Some(Instant::now());
            self.flush_tls(i);
        }
    }

    fn on_message(&mut self, text: &str) {
        tracing::debug!(msg = %text.split(',').next().unwrap_or(""), "openvpn control message");
        if text.starts_with("PUSH_REPLY") {
            if self.push_done {
                // After a renegotiation the server may hand out a fresh auth-token.
                let mut later = Pushed::default();
                later.add(text);
                if let Some(t) = later.auth_token {
                    self.auth_token = Some(Zeroizing::new(t));
                }
                return;
            }
            if !self.pushed.add(text) {
                self.push_done = true;
                self.on_pushed();
            }
        } else if let Some(rest) = text.strip_prefix("AUTH_FAILED") {
            let reason = rest.trim_start_matches(',').trim();
            if let Some(ch) = reason.strip_prefix("CRV1:") {
                // CRV1:<flags>:<state id>:<base64 username>:<challenge text>
                let parts: Vec<&str> = ch.splitn(4, ':').collect();
                if let [flags, state_id, user, text] = parts[..] {
                    let username = STANDARD
                        .decode(user)
                        .ok()
                        .and_then(|u| String::from_utf8(u).ok())
                        .unwrap_or_default();
                    return self.fail(Failure::Challenge {
                        state_id: state_id.to_owned(),
                        username,
                        text: text.to_owned(),
                        echo: flags.split(',').any(|f| f == "E"),
                    });
                }
            }
            let msg = if reason.is_empty() {
                "the OpenVPN server rejected the sign-in (wrong username or password?)".to_owned()
            } else {
                format!("the OpenVPN server rejected the sign-in: {reason}")
            };
            self.fail(Failure::AuthFailed(msg));
        } else if let Some(keywords) = text.strip_prefix("AUTH_PENDING") {
            self.on_auth_pending(keywords);
        } else if let Some(url) = web_sign_in_url(text) {
            self.on_web_sign_in(url);
        } else if text.starts_with("RESTART") || text.starts_with("HALT") {
            let reason = text.split_once(',').map(|(_, r)| r).unwrap_or("");
            self.fail(Failure::Fatal(if reason.is_empty() {
                "the OpenVPN server ended the session".into()
            } else {
                format!("the OpenVPN server ended the session: {reason}")
            }));
        } else if text.starts_with("EXIT") {
            self.fail(Failure::Unreachable(
                "the OpenVPN server is shutting down".into(),
            ));
        } else if let Some(info) = text.strip_prefix("INFO,") {
            tracing::info!(%info, "openvpn server info");
        }
    }

    /// Deferred authentication (a web sign-in, a push notification to approve, …): wait as long
    /// as the server says (`AUTH_PENDING,timeout 300`), or the handshake window.
    fn on_auth_pending(&mut self, keywords: &str) {
        let hand_window = self.p.cfg.hand_window;
        let timeout = keywords
            .split(',')
            .find_map(|k| k.trim().strip_prefix("timeout "))
            .and_then(|t| t.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let wait = timeout
            .unwrap_or(hand_window)
            .min(MAX_PENDING.max(hand_window));
        tracing::info!(wait_s = wait.as_secs(), "openvpn sign-in pending");
        self.pending_until = Some(Instant::now() + wait);
    }

    /// The server wants the user on a web page; the session keeps waiting for its verdict.
    fn on_web_sign_in(&mut self, url: &str) {
        let url = url.trim();
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return self.fail(Failure::Fatal(format!(
                "the server wants a web sign-in at \"{url}\", which is not a web page"
            )));
        }
        if self.web_sign_in.as_deref() == Some(url) {
            return;
        }
        tracing::info!("openvpn server asks for a web sign-in");
        if self.pending_until.is_none() {
            // Servers say AUTH_PENDING first; one that didn't gets the handshake window.
            self.pending_until = Some(Instant::now() + self.p.cfg.hand_window);
        }
        self.web_sign_in = Some(url.to_owned());
        let _ = self.p.notices.send(Notice::WebSignIn(url.to_owned()));
    }

    fn on_pushed(&mut self) {
        let cfg = self.p.cfg.clone();
        let cipher = match (&self.pushed.cipher, &self.pushed.cipher_name) {
            (Some(c), _) => *c,
            (None, Some(name)) => {
                return self.fail(Failure::Fatal(format!(
                    "the server chose the data cipher {name}, which MorphGate doesn't support"
                )));
            }
            (None, None) => match cfg.fallback_cipher {
                Some(c) => c,
                None => {
                    return self.fail(Failure::Fatal(
                        "the server didn't negotiate a data cipher; add `data-ciphers-fallback` \
                         (e.g. AES-256-CBC) to the profile"
                            .into(),
                    ));
                }
            },
        };
        if self.pushed.addresses().is_empty() {
            return self.fail(Failure::Fatal(
                "the server assigned no address to this client (no ifconfig in its push)".into(),
            ));
        }
        self.cipher = Some(cipher);
        self.compress = self.pushed.compress.unwrap_or(cfg.compress);
        self.peer_id = self.pushed.peer_id;
        self.auth_token = self.pushed.auth_token.clone().map(Zeroizing::new);
        self.auth_token_user = self
            .pushed
            .auth_token_user
            .as_deref()
            .and_then(|u| STANDARD.decode(u).ok())
            .and_then(|u| String::from_utf8(u).ok());
        self.ping = self
            .pushed
            .ping
            .or(cfg.ping)
            .filter(|p| *p > 0)
            .map_or(DEFAULT_PING, |p| Duration::from_secs(u64::from(p)));
        self.ping_restart = self
            .pushed
            .ping_restart
            .or(cfg.ping_restart)
            .filter(|p| *p > 0)
            .map(|p| Duration::from_secs(u64::from(p)));
        if let Some(i) = self.key_index(0) {
            self.install_keys(i);
        }
        if self.ready() {
            self.event = Some(Event::Ready);
        }
    }

    fn install_keys(&mut self, i: usize) {
        let Some(cipher) = self.cipher else { return };
        let ks = &mut self.keys[i];
        let Some(server) = ks.server_random else {
            return;
        };
        let material = if self.pushed.ekm {
            let mut m = Zeroizing::new([0u8; 256]);
            match ks
                .tls
                .export_keying_material(&mut *m, keys::EKM_LABEL, None)
            {
                Ok(_) => m,
                Err(e) => return self.fail(Failure::Fatal(format!("key export: {e}"))),
            }
        } else {
            let Some(remote) = self.remote_sid else {
                return;
            };
            keys::prf_material(&ks.random, &server, &self.local_sid, &remote)
        };
        ks.data = Some(DataChannel::new(cipher, self.p.cfg.auth, &material));
        ks.phase = Phase::Active;
        let new_id = ks.key_id;
        if let Some(old) = self.primary.and_then(|k| self.key_index(k)) {
            self.keys[old].retire_at = Some(Instant::now() + TRANSITION);
        }
        self.primary = Some(new_id);
    }

    fn on_data(&mut self, op: u8, key_id: u8, packet: &[u8]) {
        let Some(i) = self.key_index(key_id) else {
            return;
        };
        let header_len = if op == wire::DATA_V2 { 4 } else { 1 };
        let Some(data) = self.keys[i].data.as_mut() else {
            return;
        };
        let Some(plain) = data.decrypt(packet, header_len) else {
            tracing::trace!("dropping data packet that failed authentication");
            return;
        };
        self.last_recv = Instant::now();
        let Some(ip) = compress::unframe(self.compress, plain) else {
            tracing::debug!("dropping data packet with unknown compression framing");
            return;
        };
        if ip == PING {
            return;
        }
        if ip.len() == 17 && ip[..16] == OCC_MAGIC {
            if ip[16] == OCC_EXIT {
                self.fail(Failure::Unreachable(
                    "the OpenVPN server is shutting down".into(),
                ));
            }
            return;
        }
        self.to_stack.push(ip);
    }

    // --------------------------------------------------------------------- outgoing

    fn send_data(&mut self, payload: Vec<u8>, droppable: bool) {
        let Some(i) = self.primary.and_then(|k| self.key_index(k)) else {
            return;
        };
        let key_id = self.keys[i].key_id;
        let framed = compress::frame(self.compress, payload);
        let header: Vec<u8> = match self.peer_id {
            Some(pid) => {
                let id = pid.to_be_bytes();
                vec![wire::header(wire::DATA_V2, key_id), id[1], id[2], id[3]]
            }
            None => vec![wire::header(wire::DATA_V1, key_id)],
        };
        let Some(data) = self.keys[i].data.as_mut() else {
            return;
        };
        match data.encrypt(&header, &framed) {
            Some(p) => {
                self.out.push((p, droppable));
                self.last_send = Instant::now();
            }
            None => self.fail(Failure::Fatal("data channel packet ids exhausted".into())),
        }
    }

    /// Puts due control packets (new, retransmitted, and bare acks) into `out`.
    fn pump(&mut self, now: Instant) {
        for i in 0..self.keys.len() {
            let key_id = self.keys[i].key_id;
            let due = self.keys[i].rel.due(now);
            for (id, opcode, payload) in due {
                let acks = self.keys[i].rel.take_acks(4);
                let c = Control {
                    opcode,
                    key_id,
                    session_id: self.local_sid,
                    acked_session: (!acks.is_empty()).then(|| self.remote_sid.unwrap_or_default()),
                    acks,
                    msg_id: Some(id),
                    payload,
                };
                let p = self.wrap.encode(&c);
                self.out.push((p, false));
            }
            while self.keys[i].rel.has_acks() {
                let acks = self.keys[i].rel.take_acks(8);
                let c = Control {
                    opcode: wire::ACK_V1,
                    key_id,
                    session_id: self.local_sid,
                    acked_session: self.remote_sid,
                    acks,
                    msg_id: None,
                    payload: Vec::new(),
                };
                let p = self.wrap.encode(&c);
                self.out.push((p, false));
            }
        }
    }

    fn on_timer(&mut self, now: Instant) {
        let cfg = self.p.cfg.clone();
        if !self.ready() {
            if self.remote_sid.is_none() && now >= self.started + cfg.server_poll_timeout {
                return self.fail(Failure::Unreachable(format!(
                    "no answer from {} (wrong address or port, UDP blocked, or a tls-auth / \
                     tls-crypt key mismatch)",
                    self.p.remote
                )));
            }
            if now >= self.pending_until.unwrap_or(self.started + cfg.hand_window) {
                let tls_done = self.keys.first().is_some_and(|k| !k.tls.is_handshaking());
                return self.fail(if self.web_sign_in.is_some() {
                    Failure::AuthFailed("the sign-in in the browser wasn't finished in time".into())
                } else if self.pending_until.is_some() {
                    Failure::AuthFailed(
                        "the server's sign-in check didn't finish in time (AUTH_PENDING)".into(),
                    )
                } else if tls_done {
                    Failure::AuthFailed(
                        "the server never confirmed the sign-in (no PUSH_REPLY)".into(),
                    )
                } else {
                    Failure::Fatal("TLS handshake with the OpenVPN server timed out".into())
                });
            }
            if let (Some(at), Some(i)) = (self.push_sent_at, self.key_index(0))
                && !self.push_done
                && now >= at + PUSH_RETRY
            {
                self.send_push_request(i);
            }
            return;
        }
        // Renegotiations that never finish take the session down with them.
        if self
            .keys
            .iter()
            .any(|k| k.phase != Phase::Active && now >= k.started + cfg.hand_window)
        {
            return self.fail(Failure::Fatal(
                "key renegotiation with the server failed".into(),
            ));
        }
        self.keys.retain(|k| k.retire_at.is_none_or(|t| now < t));
        if let Some(restart) = self.ping_restart
            && now >= self.last_recv + restart
        {
            return self.fail(Failure::Unreachable(format!(
                "no traffic from the OpenVPN server for {}s",
                restart.as_secs()
            )));
        }
        if now >= self.last_send + self.ping {
            self.send_data(PING.to_vec(), false);
        }
    }

    fn next_wake(&self) -> Instant {
        let now = Instant::now();
        let mut at = now + Duration::from_secs(1);
        for k in &self.keys {
            if let Some(d) = k.rel.next_deadline() {
                at = at.min(d);
            }
        }
        if self.ready() {
            at = at.min(self.last_send + self.ping);
        }
        at.max(now + Duration::from_millis(5))
    }

    /// Tells the server we're leaving (UDP only; TCP sees the connection close).
    fn goodbye(&mut self) {
        if self.ready() && self.p.remote.proto == Proto::Udp {
            let mut occ = OCC_MAGIC.to_vec();
            occ.push(OCC_EXIT);
            self.send_data(occ, false);
        }
    }
}

/// The page of a web sign-in request: `INFO_PRE,WEB_AUTH:<flags>:<url>` (flags such as
/// `proxy` or `hidden`, often none), `INFO_PRE,OPEN_URL:<url>`, and the same without
/// `INFO_PRE,` or as `INFO,`.
fn web_sign_in_url(text: &str) -> Option<&str> {
    let rest = text
        .strip_prefix("INFO_PRE,")
        .or_else(|| text.strip_prefix("INFO,"))
        .unwrap_or(text);
    match rest.strip_prefix("WEB_AUTH:") {
        Some(flags_and_url) => flags_and_url.split_once(':').map(|(_, url)| url),
        None => rest.strip_prefix("OPEN_URL:"),
    }
}

fn tls_error(e: &rustls::Error) -> String {
    use rustls::{AlertDescription, CertificateError, Error};
    match e {
        // Same-named CAs (Easy-RSA defaults) surface as a bad signature rather than unknown.
        Error::InvalidCertificate(
            CertificateError::UnknownIssuer | CertificateError::BadSignature,
        ) => "the server's certificate isn't signed by the profile's CA".into(),
        Error::InvalidCertificate(CertificateError::Expired) => {
            "the server's certificate has expired".into()
        }
        Error::InvalidCertificate(c) => format!("the server's certificate was rejected: {c:?}"),
        Error::General(m) => m.clone(),
        Error::AlertReceived(AlertDescription::HandshakeFailure) => {
            "TLS handshake failure (the server may require a client certificate, or only offer \
             cipher suites MorphGate doesn't support)"
                .into()
        }
        Error::AlertReceived(a) => format!("the server aborted TLS: {a:?}"),
        e => format!("TLS: {e}"),
    }
}

/// Runs one session to `p.remote`. Reports on `ready` once the tunnel is usable (or why not),
/// then carries data until stopped, the stack goes away, or the server drops us.
pub async fn run(
    p: Params,
    mut io: LinkIo,
    state: Arc<LinkState>,
    mut stop: watch::Receiver<bool>,
    ready: oneshot::Sender<Result<Ready, Failure>>,
) {
    let (sender, mut rx, server) = match connect(&p.remote, p.cfg.server_poll_timeout).await {
        Ok(t) => t,
        Err(e) => {
            let _ = ready.send(Err(Failure::Unreachable(e)));
            return;
        }
    };
    let mut s = match Session::new(p) {
        Ok(s) => s,
        Err(e) => {
            let _ = ready.send(Err(Failure::Fatal(e)));
            return;
        }
    };
    let mut ready = Some(ready);
    let mut stopping = false;
    loop {
        let wake = s.next_wake();
        tokio::select! {
            r = stop.changed() => {
                if r.is_err() || *stop.borrow() {
                    stopping = true;
                }
            }
            packet = rx.recv() => match packet {
                Some(packet) => s.on_packet(&packet),
                None => s.fail(Failure::Unreachable("the server closed the connection".into())),
            },
            packet = io.from_stack.recv(), if s.ready() => match packet {
                Some(packet) => s.send_data(packet, true),
                None => stopping = true,
            },
            _ = tokio::time::sleep_until(wake) => s.on_timer(Instant::now()),
        }
        if stopping {
            s.goodbye();
        }
        s.pump(Instant::now());
        for (packet, droppable) in s.out.drain(..) {
            sender.send(packet, droppable).await;
        }
        for packet in s.to_stack.drain(..) {
            let _ = io.to_stack.try_send(packet);
        }
        if stopping {
            break;
        }
        match s.event.take() {
            Some(Event::Ready) => {
                state.up.store(true, Ordering::Relaxed);
                if let Some(r) = ready.take() {
                    let _ = r.send(Ok(Ready {
                        pushed: s.pushed.clone(),
                        cipher: s.cipher.expect("cipher set when ready"),
                        server,
                    }));
                }
            }
            Some(Event::Failed(f)) => {
                if let Some(r) = ready.take() {
                    let _ = r.send(Err(f));
                }
                break;
            }
            Some(Event::Down(reason)) => {
                tracing::info!(%reason, "openvpn link down");
                state.fail(reason);
                break;
            }
            None => {}
        }
    }
    state.up.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session whose server has answered its reset, as far as the timers are concerned.
    fn session(extra: &str) -> (Session, mpsc::UnboundedReceiver<Notice>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(vec![]).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca.self_signed(&key).unwrap().pem();
        let cfg = Config::parse(&format!(
            "client\nremote 127.0.0.1 1194\nhand-window 30\n{extra}\n<ca>\n{ca}</ca>\n"
        ))
        .unwrap();
        let tls = tls::client_config(&cfg, None).unwrap();
        let (notices, rx) = mpsc::unbounded_channel();
        let remote = cfg.remotes[0].clone();
        let mut s = Session::new(Params {
            cfg: Arc::new(cfg),
            tls,
            remote,
            credentials: None,
            notices,
        })
        .unwrap();
        s.remote_sid = Some([7; 8]);
        (s, rx)
    }

    fn failure(s: &Session) -> Option<String> {
        match &s.event {
            Some(Event::Failed(Failure::AuthFailed(m) | Failure::Fatal(m))) => Some(m.clone()),
            _ => None,
        }
    }

    #[test]
    fn web_sign_in_requests_in_every_spelling() {
        let url = |t| web_sign_in_url(t);
        assert_eq!(
            url("INFO_PRE,WEB_AUTH::https://idp.example/sso?a=1&b=2"),
            Some("https://idp.example/sso?a=1&b=2")
        );
        assert_eq!(
            url("INFO_PRE,WEB_AUTH:proxy,hidden:https://idp.example/x"),
            Some("https://idp.example/x")
        );
        assert_eq!(
            url("INFO_PRE,OPEN_URL:https://x.example/"),
            Some("https://x.example/")
        );
        assert_eq!(
            url("OPEN_URL:https://x.example/"),
            Some("https://x.example/")
        );
        assert_eq!(
            url("INFO,WEB_AUTH::http://x.example/"),
            Some("http://x.example/")
        );
        assert_eq!(url("INFO,the server says hello"), None);
        assert_eq!(url("INFO_PRE,CR_TEXT:E,R:Enter the code"), None);
    }

    #[tokio::test]
    async fn a_web_sign_in_waits_as_long_as_the_server_says() {
        let (mut s, mut notices) = session("");
        s.on_message("AUTH_PENDING,timeout 120");
        let until = s.pending_until.expect("pending");
        assert!(until >= Instant::now() + Duration::from_secs(115));
        s.on_message("INFO_PRE,WEB_AUTH::https://idp.example/sso?state=abc");
        assert_eq!(
            notices.try_recv().unwrap(),
            Notice::WebSignIn("https://idp.example/sso?state=abc".into())
        );
        // Servers repeat themselves; the page opens once.
        s.on_message("INFO_PRE,WEB_AUTH::https://idp.example/sso?state=abc");
        assert!(notices.try_recv().is_err());

        // Past the profile's 30 s hand-window, still within the server's 120 s: waiting.
        s.on_timer(Instant::now() + Duration::from_secs(90));
        assert!(s.event.is_none());
        s.on_timer(until + Duration::from_secs(1));
        let m = failure(&s).expect("timed out");
        assert!(m.contains("browser"), "{m}");
    }

    #[tokio::test]
    async fn auth_pending_without_a_timeout_or_with_a_huge_one() {
        let (mut s, _) = session("");
        let before = Instant::now();
        s.on_message("AUTH_PENDING");
        let until = s.pending_until.unwrap();
        assert!(
            until >= before + Duration::from_secs(30) && until < before + Duration::from_secs(31)
        );
        s.on_message("AUTH_PENDING,timeout 999999,other keyword");
        assert!(s.pending_until.unwrap() <= Instant::now() + MAX_PENDING);
        s.on_timer(Instant::now() + MAX_PENDING + Duration::from_secs(1));
        let m = failure(&s).unwrap();
        assert!(m.contains("AUTH_PENDING"), "{m}");
    }

    #[tokio::test]
    async fn only_web_pages_are_opened() {
        let (mut s, mut notices) = session("");
        s.on_message("INFO_PRE,WEB_AUTH::file:///etc/passwd");
        assert!(notices.try_recv().is_err());
        assert!(failure(&s).unwrap().contains("not a web page"));
    }

    #[tokio::test]
    async fn the_client_says_which_sign_ins_it_can_do() {
        let (s, _) = session("");
        let info = peer_info(&s.p.cfg);
        assert!(info.contains("IV_SSO=webauth,openurl\n"), "{info}");
        // DATA_V2, tls-ekm, and AUTH_PENDING keywords.
        assert!(info.contains("IV_PROTO=26\n"), "{info}");
    }
}
