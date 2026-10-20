//! Running openconnect (Unix): its prompts, the tun-script helper, and the packet socket.

use std::collections::BTreeMap;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{UnixDatagram, UnixListener, UnixStream};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::OcConfig;
use crate::netstack::{LinkIo, LinkState, StackConfig, link_pair};
use crate::{IpNet, PromptField, Prompter, Tunnel, TunnelInfo, VpnError, WebSignIn};

pub(super) const ENV_SOCKET: &str = "MG_OC_SOCKET";
pub(super) const ENV_TOKEN: &str = "MG_OC_TOKEN";
/// Set when the helper runs as openconnect's external browser: the page to open.
const ENV_URL: &str = "MG_OC_URL";
/// A partial line on stderr followed by this much silence is a prompt waiting for input.
const QUIET: Duration = Duration::from_millis(250);
/// How long openconnect may take to connect, not counting time spent answering prompts.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(90);
/// How long a sign-in in the browser may take.
const WEB_SIGN_IN_TIMEOUT: Duration = Duration::from_secs(600);
const CERT_PROMPT: &str = "Enter 'yes' to accept";
const RECENT: usize = 40;

// ------------------------------------------------------------------------------- helper side

fn env(name: &str) -> io::Result<String> {
    std::env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("{name} is not set")))
}

/// Settings openconnect exports to its script that describe the tunnel.
fn wanted(key: &str) -> bool {
    key.starts_with("INTERNAL_IP4_")
        || key.starts_with("INTERNAL_IP6_")
        || (key.starts_with("CISCO_") && key != "CISCO_BANNER")
        || matches!(key, "VPNGATEWAY" | "TUNDEV" | "IDLE_TIMEOUT")
}

/// Entry point when MorphGate's binary runs as openconnect's `--script-tun` script: hands the
/// packet socket (`VPNFD`) and the tunnel settings to the app, then waits until the app is done.
/// Run as openconnect's external browser instead (`MG_OC_URL` set, see [`browser_script`]), it
/// hands the sign-in page to the app, which opens it and tells the user.
pub fn tun_helper_main() -> ! {
    let (what, result) = match std::env::var(ENV_URL) {
        Ok(url) => ("browser", open_url(&url)),
        Err(_) => ("tun", helper()),
    };
    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("MorphGate {what} helper: {e}");
            1
        }
    };
    std::process::exit(code)
}

/// Our token, then `KEY=value` entries, NUL-separated, with a length in front.
fn message<'a>(token: String, entries: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<u8> {
    let mut msg = token.into_bytes();
    msg.push(0);
    for (k, v) in entries {
        msg.extend_from_slice(format!("{k}={v}").as_bytes());
        msg.push(0);
    }
    let mut framed = (msg.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&msg);
    framed
}

fn open_url(url: &str) -> io::Result<()> {
    let framed = message(env(ENV_TOKEN)?, [(ENV_URL, url)].into_iter());
    std::os::unix::net::UnixStream::connect(env(ENV_SOCKET)?)?.write_all(&framed)
}

fn helper() -> io::Result<()> {
    let fd: i32 = env("VPNFD")?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "VPNFD is not a number"))?;
    let socket = env(ENV_SOCKET)?;
    let token = env(ENV_TOKEN)?;
    // SAFETY: openconnect starts us with VPNFD open and doesn't use our copy; from here on this
    // process owns it, and nothing else in it refers to that descriptor.
    let vpnfd = unsafe { OwnedFd::from_raw_fd(fd) };

    let settings: Vec<(String, String)> = std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .filter(|(k, _)| wanted(k))
        .collect();
    let framed = message(
        token,
        settings.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    );

    let stream = std::os::unix::net::UnixStream::connect(socket)?;
    let fds = [vpnfd.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut cmsg = SendAncillaryBuffer::new(&mut space);
    cmsg.push(SendAncillaryMessage::ScmRights(&fds));
    let sent = sendmsg(
        &stream,
        &[IoSlice::new(&framed)],
        &mut cmsg,
        SendFlags::empty(),
    )?;
    (&stream).write_all(&framed[sent..])?;
    drop(vpnfd);
    // Stay around until the app closes its end (the tunnel stopped).
    let mut b = [0u8; 1];
    let _ = (&stream).read(&mut b);
    Ok(())
}

// ------------------------------------------------------------------------------- app side

pub(super) struct PrivateDir(pub(super) PathBuf);

impl PrivateDir {
    pub(super) fn new() -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).map_err(|e| io::Error::other(e.to_string()))?;
        let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("mg-oc-{name}"));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// openconnect starts its `--external-browser` as `program URL`, by path and without a shell
/// (`posix_spawn`). This script, in the private directory, runs the helper with the page in
/// `MG_OC_URL`; the socket and token come along in openconnect's environment.
pub(super) fn browser_script(dir: &Path, helper: &[String]) -> io::Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join("browser");
    let helper: Vec<String> = helper.iter().map(|a| shell_quote(a)).collect();
    let script = format!(
        "#!/bin/sh\n{ENV_URL}=\"$1\"\nexport {ENV_URL}\nexec {}\n",
        helper.join(" ")
    );
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)?
        .write_all(script.as_bytes())?;
    Ok(path)
}

/// Whether this openconnect has `--external-browser` (9.0 and later); asked once per program.
pub(super) async fn has_external_browser(program: &Path) -> bool {
    static KNOWN: std::sync::Mutex<BTreeMap<PathBuf, bool>> =
        std::sync::Mutex::new(BTreeMap::new());
    if let Some(known) = KNOWN.lock().ok().and_then(|k| k.get(program).copied()) {
        return known;
    }
    let help = Command::new(program)
        .arg("--help")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .await;
    let has = help.is_ok_and(|o| {
        let text = [o.stdout, o.stderr].concat();
        String::from_utf8_lossy(&text).contains("--external-browser")
    });
    if let Ok(mut k) = KNOWN.lock() {
        k.insert(program.to_owned(), has);
    }
    has
}

/// Everything the app passes openconnect.
pub(super) struct Invocation<'a> {
    pub cfg: &'a OcConfig,
    pub program: &'a Path,
    pub socket: &'a Path,
    pub token: &'a str,
    /// The external-browser script, when this openconnect can use one.
    pub browser: Option<&'a Path>,
}

impl Invocation<'_> {
    pub(super) fn command(&self) -> Command {
        let cfg = self.cfg;
        let mut cmd = Command::new(self.program);
        cmd.arg(format!("--protocol={}", cfg.protocol));
        if let Some(u) = cfg.username.as_deref().filter(|u| !u.is_empty()) {
            cmd.arg(format!("--user={u}"));
        }
        if let Some(g) = cfg.authgroup.as_deref().filter(|g| !g.is_empty()) {
            cmd.arg(format!("--authgroup={g}"));
        }
        if let Some(pin) = cfg.server_cert.as_deref().filter(|p| !p.is_empty()) {
            cmd.arg(format!("--servercert={pin}"));
        }
        if cfg.password.as_ref().is_some_and(|p| !p.is_empty()) {
            cmd.arg("--passwd-on-stdin");
        }
        if let Some(browser) = self.browser {
            // Single sign-on (SAML) in the user's browser, where the server offers it.
            cmd.arg(format!("--external-browser={}", browser.display()));
        }
        let script: Vec<String> = cfg.helper.iter().map(|a| shell_quote(a)).collect();
        cmd.arg("--script-tun")
            .arg(format!("--script={}", script.join(" ")))
            .arg("--")
            .arg(cfg.server.trim())
            .env(ENV_SOCKET, self.socket)
            .env(ENV_TOKEN, self.token)
            // English output: prompts and messages are recognised by their text.
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env_remove("LANGUAGE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    }
}

enum Output {
    Line { stderr: bool, text: String },
    Prompt(String),
}

fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(
    mut r: R,
    stderr: bool,
    tx: mpsc::UnboundedSender<Output>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut partial: Vec<u8> = Vec::new();
        loop {
            let read = if stderr && !partial.is_empty() {
                match tokio::time::timeout(QUIET, r.read(&mut buf)).await {
                    Ok(r) => r,
                    Err(_) => {
                        let text = String::from_utf8_lossy(&partial).into_owned();
                        partial.clear();
                        if tx.send(Output::Prompt(text)).is_err() {
                            return;
                        }
                        continue;
                    }
                }
            } else {
                r.read(&mut buf).await
            };
            match read {
                Ok(0) | Err(_) => {
                    if !partial.is_empty() {
                        let text = String::from_utf8_lossy(&partial).trim_end().to_owned();
                        let _ = tx.send(Output::Line { stderr, text });
                    }
                    return;
                }
                Ok(n) => {
                    partial.extend_from_slice(&buf[..n]);
                    while let Some(pos) = partial.iter().position(|b| *b == b'\n') {
                        let line: Vec<u8> = partial.drain(..=pos).collect();
                        let text = String::from_utf8_lossy(&line).trim_end().to_owned();
                        if !text.is_empty() && tx.send(Output::Line { stderr, text }).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });
}

/// What openconnect has said: recent lines, and the details of a certificate it doubts.
#[derive(Default)]
struct Log {
    lines: Vec<(bool, String)>,
    since_prompt: Vec<String>,
    fingerprint: Option<String>,
    reason: String,
    host: String,
}

impl Log {
    fn line(&mut self, stderr: bool, text: String) {
        tracing::debug!(target: "openconnect", "{text}");
        if let Some(fp) = text.trim().strip_prefix("--servercert ") {
            self.fingerprint = Some(fp.trim().to_owned());
        }
        if let Some(r) = text.strip_prefix("Reason: ") {
            self.reason = r.trim().to_owned();
        }
        if let Some(rest) = text.strip_prefix("Certificate from VPN server \"")
            && let Some((host, _)) = rest.split_once('"')
        {
            self.host = host.to_owned();
        }
        if stderr {
            self.since_prompt.push(text.clone());
        }
        self.lines.push((stderr, text));
        if self.lines.len() > RECENT {
            self.lines.remove(0);
        }
    }

    /// Why openconnect gave up, in its own words.
    fn failure(&self, status: Option<ExitStatus>) -> VpnError {
        let errors: Vec<&str> = self
            .lines
            .iter()
            .filter(|(e, t)| *e && !t.starts_with("    --servercert") && !t.starts_with("To trust"))
            .map(|(_, t)| t.as_str())
            .collect();
        let tail: Vec<&str> = if errors.is_empty() {
            self.lines
                .iter()
                .rev()
                .take(2)
                .rev()
                .map(|(_, t)| t.as_str())
                .collect()
        } else {
            errors.iter().rev().take(3).rev().copied().collect()
        };
        let msg = if tail.is_empty() {
            format!(
                "openconnect exited ({})",
                status.map_or("killed".into(), |s| s.to_string())
            )
        } else {
            format!("openconnect: {}", tail.join(" "))
        };
        let lower = msg.to_lowercase();
        if lower.contains("login failed") || lower.contains("authentication failed") {
            VpnError::Auth(msg)
        } else {
            VpnError::Connect(msg)
        }
    }
}

/// Answers one openconnect prompt through the user. `None` = the user cancelled.
async fn answer(
    prompt: &str,
    log: &mut Log,
    prompter: &dyn Prompter,
    title: &str,
    accepted_cert: &mut Option<String>,
) -> Option<String> {
    let message = log.since_prompt.split_off(0);
    if prompt.contains(CERT_PROMPT) {
        let fp = log.fingerprint.clone().unwrap_or_default();
        let trusted = prompter
            .trust_certificate(log.host.clone(), log.reason.clone(), fp.clone())
            .await;
        if !trusted {
            return None;
        }
        *accepted_cert = Some(fp);
        return Some("yes".into());
    }
    let label = prompt.trim().trim_end_matches(':').trim().to_owned();
    let lower = label.to_lowercase();
    let plain = ["user", "login", "email", "name", "group", "realm", "domain"]
        .iter()
        .any(|w| lower.contains(w));
    let mut message: Vec<String> = message
        .into_iter()
        .filter(|l| !l.starts_with("POST ") && !l.starts_with("Connected to"))
        .collect();
    let message = message.split_off(message.len().saturating_sub(3));
    prompter
        .ask(
            title.to_owned(),
            message.join("\n"),
            vec![PromptField {
                label,
                secret: !plain,
                value: String::new(),
            }],
        )
        .await
        .and_then(|a| a.into_iter().next())
}

pub(super) struct Setup {
    fd: OwnedFd,
    env: BTreeMap<String, String>,
    /// Kept open while the tunnel runs; closing it lets the helper exit.
    conn: UnixStream,
}

/// What a helper has to say.
pub(super) enum Received {
    /// The tun script: the tunnel is up.
    Setup(Setup),
    /// The external browser: the user must sign in on this page.
    OpenUrl(String),
}

/// Reads a helper's message: the packet socket (as `SCM_RIGHTS`) and the settings, or a page
/// to open.
pub(super) async fn receive(stream: UnixStream, token: &str) -> io::Result<Received> {
    let mut buf = vec![0u8; 64 * 1024];
    let (n, fd) = loop {
        stream.readable().await?;
        let r = stream.try_io(Interest::READABLE, || {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut cmsg = RecvAncillaryBuffer::new(&mut space);
            let got = recvmsg(
                &stream,
                &mut [IoSliceMut::new(&mut buf)],
                &mut cmsg,
                RecvFlags::empty(),
            )?;
            let mut fd = None;
            for m in cmsg.drain() {
                if let RecvAncillaryMessage::ScmRights(fds) = m {
                    for f in fds {
                        fd.get_or_insert(f);
                    }
                }
            }
            Ok((got.bytes, fd))
        });
        match r {
            Ok(x) => break x,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    };
    if let Some(fd) = &fd {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)?;
    }
    if n < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short message"));
    }
    let len = u32::from_be_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
    if len > buf.len() - 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut stream = stream;
    let mut have = n;
    while have < 4 + len {
        let m = stream.read(&mut buf[have..4 + len]).await?;
        if m == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        have += m;
    }
    let mut parts = buf[4..4 + len].split(|b| *b == 0);
    if parts.next() != Some(token.as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong token",
        ));
    }
    let mut env: BTreeMap<String, String> = parts
        .filter_map(|kv| {
            let kv = String::from_utf8_lossy(kv);
            kv.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect();
    if let (None, Some(url)) = (&fd, env.remove(ENV_URL)) {
        return Ok(Received::OpenUrl(url));
    }
    let fd = fd.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no socket received"))?;
    Ok(Received::Setup(Setup {
        fd,
        env,
        conn: stream,
    }))
}

struct Settings {
    addresses: Vec<IpNet>,
    dns: Vec<IpAddr>,
    domains: Vec<String>,
    routes: Vec<IpNet>,
    mtu: u16,
    gateway: Option<String>,
}

fn settings(env: &BTreeMap<String, String>) -> Result<Settings, VpnError> {
    let get = |k: &str| env.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let mut addresses = Vec::new();
    if let Some(a) = get("INTERNAL_IP4_ADDRESS").and_then(|a| a.parse::<Ipv4Addr>().ok()) {
        let prefix = get("INTERNAL_IP4_NETMASKLEN")
            .and_then(|p| p.parse().ok())
            .or_else(|| {
                get("INTERNAL_IP4_NETMASK")
                    .and_then(|m| m.parse().ok())
                    .and_then(|m| IpNet::from_netmask(a, m))
                    .map(|n| n.prefix)
            })
            .unwrap_or(32);
        addresses.push(IpNet::new(IpAddr::V4(a), prefix));
    }
    if let Some(n) = get("INTERNAL_IP6_NETMASK")
        .filter(|n| n.contains('/'))
        .and_then(|n| IpNet::parse(n).ok())
        .or_else(|| get("INTERNAL_IP6_ADDRESS").and_then(|a| IpNet::parse(a).ok()))
    {
        addresses.push(n);
    }
    if addresses.is_empty() {
        return Err(VpnError::Connect(
            "openconnect connected, but the server assigned no address".into(),
        ));
    }
    let dns = ["INTERNAL_IP4_DNS", "INTERNAL_IP6_DNS"]
        .iter()
        .filter_map(|k| get(k))
        .flat_map(str::split_whitespace)
        .filter_map(|d| d.parse().ok())
        .collect();
    let domains = get("CISCO_DEF_DOMAIN")
        .map(|d| {
            d.split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .map(Into::into)
                .collect()
        })
        .unwrap_or_default();
    let mut routes = Vec::new();
    for prefix in ["CISCO_SPLIT_INC", "CISCO_IPV6_SPLIT_INC"] {
        let n: usize = get(prefix).and_then(|c| c.parse().ok()).unwrap_or(0);
        for i in 0..n.min(10_000) {
            let Some(addr) =
                get(&format!("{prefix}_{i}_ADDR")).and_then(|a| a.parse::<IpAddr>().ok())
            else {
                continue;
            };
            let len = get(&format!("{prefix}_{i}_MASKLEN")).and_then(|l| l.parse().ok());
            let net = match (addr, len) {
                (_, Some(len)) => Some(IpNet::new(addr, len)),
                (IpAddr::V4(a), None) => get(&format!("{prefix}_{i}_MASK"))
                    .and_then(|m| m.parse().ok())
                    .and_then(|m| IpNet::from_netmask(a, m)),
                (IpAddr::V6(_), None) => None,
            };
            routes.extend(net);
        }
    }
    if routes.is_empty() {
        // No split-include: everything goes through the VPN.
        routes.push(IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        routes.push(IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
    }
    let mtu = get("INTERNAL_IP4_MTU")
        .or(get("INTERNAL_IP6_MTU"))
        .and_then(|m| m.parse::<u16>().ok())
        .unwrap_or(1300)
        .clamp(576, 9000);
    Ok(Settings {
        addresses,
        dns,
        domains,
        routes,
        mtu,
        gateway: get("VPNGATEWAY").map(Into::into),
    })
}

pub(super) async fn start(
    cfg: OcConfig,
    prompter: &dyn Prompter,
    label: &str,
) -> Result<Tunnel, VpnError> {
    let program = cfg
        .program
        .clone()
        .or_else(super::find_openconnect)
        .ok_or_else(|| VpnError::Config(super::install_hint().into()))?;
    if cfg.helper.is_empty() {
        return Err(VpnError::Config("no tun helper configured".into()));
    }
    let dir = PrivateDir::new()?;
    let sock_path = dir.0.join("s");
    let listener = UnixListener::bind(&sock_path)?;
    let mut token = [0u8; 16];
    getrandom::fill(&mut token).map_err(|e| io::Error::other(e.to_string()))?;
    let token: String = token.iter().map(|b| format!("{b:02x}")).collect();

    let browser = if has_external_browser(&program).await {
        Some(browser_script(&dir.0, &cfg.helper)?)
    } else {
        None
    };
    let mut child = Invocation {
        cfg: &cfg,
        program: &program,
        socket: &sock_path,
        token: &token,
        browser: browser.as_deref(),
    }
    .command()
    .spawn()
    .map_err(|e| VpnError::Config(format!("cannot run {}: {e}", program.display())))?;
    let password = cfg.password.as_ref().filter(|p| !p.is_empty());
    let mut stdin = child.stdin.take().expect("piped");
    let (out_tx, mut out) = mpsc::unbounded_channel();
    spawn_reader(child.stdout.take().expect("piped"), false, out_tx.clone());
    spawn_reader(child.stderr.take().expect("piped"), true, out_tx);
    if let Some(pw) = &password {
        let line = zeroize::Zeroizing::new(format!("{}\n", pw.as_str()));
        stdin.write_all(line.as_bytes()).await?;
    }

    let title = format!("Sign in to {label}");
    let mut log = Log::default();
    let mut accepted_cert = None;
    let mut out_open = true;
    let mut deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut web = WebSignIn::none();
    let setup = loop {
        tokio::select! {
            conn = listener.accept() => {
                let (stream, _) = conn?;
                match receive(stream, &token).await {
                    Ok(Received::Setup(s)) => break s,
                    Ok(Received::OpenUrl(url)) => {
                        tracing::info!(target: "openconnect", "web sign-in requested");
                        web.open(prompter, &title, url);
                        deadline = Instant::now() + WEB_SIGN_IN_TIMEOUT;
                    }
                    Err(e) => tracing::warn!(%e, "openconnect helper"),
                }
            }
            () = web.cancelled() => {
                terminate(&mut child).await;
                return Err(VpnError::Cancelled);
            }
            ev = out.recv(), if out_open => match ev {
                Some(Output::Line { stderr, text }) => log.line(stderr, text),
                Some(Output::Prompt(text)) => {
                    tracing::debug!(target: "openconnect", prompt = %text);
                    match answer(&text, &mut log, prompter, &title, &mut accepted_cert).await {
                        Some(reply) => {
                            let line = zeroize::Zeroizing::new(format!("{reply}\n"));
                            stdin.write_all(line.as_bytes()).await?;
                            deadline = Instant::now() + CONNECT_TIMEOUT;
                        }
                        None => {
                            terminate(&mut child).await;
                            return Err(if text.contains(CERT_PROMPT) {
                                VpnError::Connect(format!(
                                    "the VPN server's certificate is not trusted ({})",
                                    log.reason
                                ))
                            } else {
                                VpnError::Cancelled
                            });
                        }
                    }
                }
                None => out_open = false,
            },
            status = child.wait() => {
                // Let the readers deliver the last words.
                tokio::time::sleep(Duration::from_millis(50)).await;
                while let Ok(ev) = out.try_recv() {
                    if let Output::Line { stderr, text } = ev {
                        log.line(stderr, text);
                    }
                }
                return Err(log.failure(status.ok()));
            }
            _ = tokio::time::sleep_until(deadline) => {
                terminate(&mut child).await;
                return Err(VpnError::Connect(format!(
                    "openconnect didn't connect within {}s{}",
                    CONNECT_TIMEOUT.as_secs(),
                    log.lines.last().map(|(_, t)| format!(" (last message: {t})")).unwrap_or_default()
                )));
            }
        }
    };
    // Connected: a sign-in page still on screen goes away.
    drop(web);
    drop(listener);
    drop(dir);

    let s = match settings(&setup.env) {
        Ok(s) => s,
        Err(e) => {
            terminate(&mut child).await;
            return Err(e);
        }
    };
    let std_sock = std::os::unix::net::UnixDatagram::from(setup.fd);
    std_sock.set_nonblocking(true)?;
    let sock = Arc::new(UnixDatagram::from_std(std_sock)?);
    tracing::info!(
        server = %cfg.server,
        address = %s.addresses[0],
        "openconnect connected"
    );

    let (io, stack_io) = link_pair();
    let state = Arc::new(LinkState::default());
    state.up.store(true, Ordering::Relaxed);
    let (stop_tx, stop_rx) = watch::channel(false);
    let info = TunnelInfo {
        server: match &s.gateway {
            Some(g) => format!("{} ({g})", cfg.server),
            None => cfg.server.clone(),
        },
        addresses: s.addresses.clone(),
        dns: s.dns.clone(),
        search_domains: s.domains.clone(),
        routes: s.routes.clone(),
        mtu: s.mtu,
        accepted_server_cert: accepted_cert,
    };
    let stack = StackConfig {
        addresses: s.addresses,
        dns: s.dns,
        search_domains: s.domains,
        mtu: s.mtu,
        allowed: None,
        routes: s.routes,
    };
    tokio::spawn(run_link(
        Running {
            child,
            _stdin: stdin,
            out,
            out_open,
            _conn: setup.conn,
            sock,
            log,
        },
        io,
        state.clone(),
        stop_rx,
    ));
    Ok(Tunnel::spawn(info, stack, stack_io, state, stop_tx))
}

/// SIGTERM lets openconnect log out of the VPN session; kill it if it takes too long.
async fn terminate(child: &mut Child) {
    if let Some(pid) = child
        .id()
        .and_then(|p| rustix::process::Pid::from_raw(p as i32))
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        if tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = child.kill().await;
}

struct Running {
    child: Child,
    _stdin: ChildStdin,
    out: mpsc::UnboundedReceiver<Output>,
    out_open: bool,
    _conn: UnixStream,
    sock: Arc<UnixDatagram>,
    log: Log,
}

async fn run_link(
    mut r: Running,
    mut io: LinkIo,
    state: Arc<LinkState>,
    mut stop: watch::Receiver<bool>,
) {
    let reader = {
        let sock = r.sock.clone();
        let tx = io.to_stack.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok(n) = sock.recv(&mut buf).await {
                let _ = tx.try_send(buf[..n].to_vec());
            }
        })
    };
    let ended = loop {
        tokio::select! {
            changed = stop.changed() => if changed.is_err() || *stop.borrow() { break None },
            packet = io.from_stack.recv() => match packet {
                Some(p) => { let _ = r.sock.send(&p).await; }
                None => break None,
            },
            status = r.child.wait() => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                while let Ok(ev) = r.out.try_recv() {
                    if let Output::Line { stderr, text } = ev {
                        r.log.line(stderr, text);
                    }
                }
                break Some(r.log.failure(status.ok()).to_string());
            }
            ev = r.out.recv(), if r.out_open => match ev {
                Some(Output::Line { stderr, text }) => r.log.line(stderr, text),
                Some(Output::Prompt(p)) => {
                    tracing::warn!(target: "openconnect", prompt = %p, "unexpected prompt while connected");
                }
                None => r.out_open = false,
            },
        }
    };
    match ended {
        Some(reason) => {
            tracing::info!(%reason, "openconnect link down");
            state.fail(reason);
        }
        None => terminate(&mut r.child).await,
    }
    state.up.store(false, Ordering::Relaxed);
    reader.abort();
}

#[cfg(test)]
pub(super) fn parse_settings_for_test(env: &[(&str, &str)]) -> Result<TunnelInfo, VpnError> {
    let env = env
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect();
    let s = settings(&env)?;
    Ok(TunnelInfo {
        addresses: s.addresses,
        dns: s.dns,
        search_domains: s.domains,
        routes: s.routes,
        mtu: s.mtu,
        ..Default::default()
    })
}
