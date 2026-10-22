//! End-to-end tests against a real sshd. Skipped unless `MG_TEST_SSH` is set.
//!
//! Any OpenSSH server with TCP forwarding enabled works, e.g. a throwaway user-level one:
//!
//! ```sh
//! d=$(mktemp -d); ssh-keygen -q -t ed25519 -N '' -f $d/host; ssh-keygen -q -t ed25519 -N '' -f $d/key
//! cp $d/key.pub $d/authorized_keys
//! printf '%s\n' "Port 2222" "ListenAddress 127.0.0.1" "HostKey $d/host" "PidFile $d/pid" \
//!   "AuthorizedKeysFile $d/authorized_keys" "PasswordAuthentication no" "UsePAM no" \
//!   "Subsystem sftp internal-sftp" > $d/cfg
//! /usr/sbin/sshd -f $d/cfg
//! MG_TEST_SSH=127.0.0.1:2222 MG_TEST_USER=$USER MG_TEST_KEY=$d/key \
//!   cargo test -p mg-ssh --test live -- --include-ignored --test-threads=1
//! ```
//!
//! CI (`.github/workflows/ci.yml`) also sets `MG_TEST_PASSWORD` for a PAM password user.
//!
//! Without `MG_TEST_PASSWORD` the tests authenticate with `MG_TEST_KEY` instead and the
//! password-specific test is skipped, so a key-only user-level sshd is enough.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mg_ssh::{
    Auth, ConnectOptions, Connection, Error, Forward, Hop, HostAuthority, HostKeyInfo,
    HostKeyPrompt, KnownHosts, ProxyCommand, Session, SessionEvent, TermSize, Tunnel,
};
use zeroize::Zeroizing;

struct Env {
    host: String,
    port: u16,
    user: String,
    password: String,
    key: Option<String>,
}

fn env() -> Option<Env> {
    let target = std::env::var("MG_TEST_SSH").ok()?;
    let (host, port) = target.rsplit_once(':').expect("MG_TEST_SSH=host:port");
    Some(Env {
        host: host.into(),
        port: port.parse().unwrap(),
        user: std::env::var("MG_TEST_USER").unwrap_or_else(|_| "mg".into()),
        password: std::env::var("MG_TEST_PASSWORD").unwrap_or_default(),
        key: std::env::var("MG_TEST_KEY").ok(),
    })
}

#[derive(Default)]
struct CountingPrompt {
    calls: AtomicUsize,
    accept: bool,
}

impl HostKeyPrompt for CountingPrompt {
    fn confirm(&self, info: HostKeyInfo) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        assert!(info.fingerprint.starts_with("SHA256:"));
        self.calls.fetch_add(1, Ordering::SeqCst);
        let accept = self.accept;
        Box::pin(async move { accept })
    }
}

fn opts(env: &Env, auth: Auth) -> ConnectOptions {
    ConnectOptions {
        host: env.host.clone(),
        port: env.port,
        user: env.user.clone(),
        auth,
        term: "xterm-256color".into(),
        size: TermSize {
            cols: 120,
            rows: 30,
        },
        connect_timeout: Duration::from_secs(10),
        jumps: vec![],
        via_command: None,
        listed_keys: None,
        dialer: None,
        forward_agent: None,
    }
}

fn password(env: &Env) -> Auth {
    Auth::Password(Zeroizing::new(env.password.clone()))
}

/// Password when the server is set up for it, otherwise the test key.
fn auth(env: &Env) -> Auth {
    match (&env.key, env.password.is_empty()) {
        (Some(key), true) => Auth::KeyFile {
            path: key.into(),
            passphrase: None,
        },
        _ => password(env),
    }
}

/// Runs a command in the interactive shell and returns everything printed until the session closes.
async fn run(
    session: Session,
    mut events: tokio::sync::mpsc::Receiver<SessionEvent>,
    cmd: &str,
) -> (String, Option<u32>) {
    session
        .write(format!("{cmd}\nexit 7\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut status = None;
    let collect = async {
        while let Some(ev) = events.recv().await {
            match ev {
                SessionEvent::Output(b) => out.extend(b),
                SessionEvent::Exit { status: s } => status = Some(s),
                SessionEvent::Closed => break,
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), collect)
        .await
        .expect("session did not close");
    (String::from_utf8_lossy(&out).into_owned(), status)
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn shell_resize_exit_and_tofu() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });

    let (s, ev) = Session::connect(opts(&env, auth(&env)), kh.clone(), prompt.clone())
        .await
        .unwrap();
    s.resize(TermSize {
        cols: 100,
        rows: 40,
    })
    .await
    .unwrap();
    let (out, status) = run(s, ev, "echo mg-$((40+2)); stty size").await;
    assert!(out.contains("mg-42"), "output was: {out}");
    assert!(
        out.contains("40 100"),
        "resize not applied, output was: {out}"
    );
    assert_eq!(status, Some(7));
    assert_eq!(prompt.calls.load(Ordering::SeqCst), 1);

    // Second connection: key is now pinned, no prompt.
    let (s, ev) = Session::connect(opts(&env, auth(&env)), kh, prompt.clone())
        .await
        .unwrap();
    run(s, ev, "true").await;
    assert_eq!(prompt.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn rejected_host_key_is_not_learned() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: false,
        ..Default::default()
    });
    let err = Session::connect(opts(&env, auth(&env)), kh, prompt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::HostKeyRejected(_)), "{err}");
    assert!(!dir.path().join("known_hosts").exists());
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn changed_host_key_fails_closed() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let entry = if env.port == 22 {
        env.host.clone()
    } else {
        format!("[{}]:{}", env.host, env.port)
    };
    std::fs::write(
        &path,
        format!("{entry} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRbMaf7RI+oSkPOCPrFjPoMWJEIu96Drte4Q3r9OQYR\n"),
    )
    .unwrap();
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let err = Session::connect(
        opts(&env, auth(&env)),
        Arc::new(KnownHosts::new(path)),
        prompt.clone(),
    )
    .await
    .err()
    .unwrap();
    let Error::HostKeyChanged(info) = &err else {
        panic!("{err}")
    };
    // The pinned key is reported too, so the app can show both fingerprints.
    assert_eq!(
        info.pinned.as_ref().map(|p| p.1.as_str()),
        Some("SHA256:cS8T+87q/3OOXl3+m1vOyYgIbZg5M0XGFpdH+32DQwg")
    );
    assert_eq!(
        prompt.calls.load(Ordering::SeqCst),
        0,
        "a changed key must never be offered for acceptance"
    );
}

/// Host keys a feed lists for a host decide instead of known_hosts: the server's key connects
/// without asking (over a stale pin, too) and isn't written down; another one is refused.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn listed_host_keys_decide() {
    let Some(env) = env() else { return };
    // The server's key, learned the usual way.
    let dir = tempfile::tempdir().unwrap();
    let learned = dir.path().join("learned");
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let (s, ev) = Session::connect(
        opts(&env, auth(&env)),
        Arc::new(KnownHosts::new(&learned)),
        prompt,
    )
    .await
    .unwrap();
    run(s, ev, "true").await;
    let line = std::fs::read_to_string(&learned).unwrap();
    let key: String = line
        .split_whitespace()
        .skip(1)
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let listed = |key: &str| {
        let mut o = opts(&env, auth(&env));
        o.listed_keys = Some(mg_ssh::ListedKeys {
            keys: vec![key.to_owned()],
            from: "Ops".into(),
        });
        o
    };

    let fresh = dir.path().join("fresh");
    let never = Arc::new(CountingPrompt::default());
    let (s, ev) = Session::connect(
        listed(&key),
        Arc::new(KnownHosts::new(&fresh)),
        never.clone(),
    )
    .await
    .unwrap();
    run(s, ev, "true").await;
    assert!(!fresh.exists(), "a listed key isn't written down");

    let stale = dir.path().join("stale");
    let entry = if env.port == 22 {
        env.host.clone()
    } else {
        format!("[{}]:{}", env.host, env.port)
    };
    let other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRbMaf7RI+oSkPOCPrFjPoMWJEIu96Drte4Q3r9OQYR";
    std::fs::write(&stale, format!("{entry} {other}\n")).unwrap();
    let (s, ev) = Session::connect(
        listed(&key),
        Arc::new(KnownHosts::new(&stale)),
        never.clone(),
    )
    .await
    .unwrap();
    run(s, ev, "true").await;

    let err = Session::connect(
        listed(other),
        Arc::new(KnownHosts::new(&fresh)),
        never.clone(),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(&err, Error::HostKeyNotListed { from, .. } if from == "Ops"),
        "{err}"
    );
    assert_eq!(never.calls.load(Ordering::SeqCst), 0, "nothing asked");
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn wrong_password_fails() {
    let Some(env) = env() else { return };
    if env.password.is_empty() {
        eprintln!("skipped: MG_TEST_PASSWORD not set");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let auth = Auth::Password(Zeroizing::new("definitely-wrong".into()));
    let err = Session::connect(opts(&env, auth), kh, prompt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::AuthFailed), "{err}");
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH and MG_TEST_KEY"]
async fn key_file_auth() {
    let Some(env) = env() else { return };
    let Some(key) = env.key.clone() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let auth = Auth::KeyFile {
        path: key.into(),
        passphrase: None,
    };
    let (s, ev) = Session::connect(opts(&env, auth), kh, prompt)
        .await
        .unwrap();
    let (out, _) = run(s, ev, "whoami").await;
    assert!(out.contains(&env.user), "output was: {out}");

    // Same key held in memory, as saved hosts use it.
    let pem = std::fs::read_to_string(env.key.as_ref().unwrap()).unwrap();
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts2")));
    let auth = Auth::Key {
        private_key: Zeroizing::new(pem),
        passphrase: None,
        certificate: None,
    };
    let (s, ev) = Session::connect(opts(&env, auth), kh, prompt)
        .await
        .unwrap();
    let (out, _) = run(s, ev, "echo in-memory-ok").await;
    assert!(out.contains("in-memory-ok"), "output was: {out}");
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn unreachable_port_reports_connect_error() {
    let Some(_) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt::default());
    let env = Env {
        host: "127.0.0.1".into(),
        port: 1,
        user: "x".into(),
        password: String::new(),
        key: None,
    };
    let err = Session::connect(opts(&env, auth(&env)), kh, prompt)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::Connect { .. }), "{err}");
}

fn hop(env: &Env) -> Hop {
    Hop {
        host: env.host.clone(),
        port: env.port,
        user: env.user.clone(),
        auth: auth(env),
        via_command: None,
        listed_keys: None,
    }
}

/// A jump host that refuses nothing but runs a command whose stdio carries the next hop, as
/// `ProxyCommand ssh jump-host nc %h %p` does: bash's `/dev/tcp` instead of nc, which not every
/// server has.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn jump_through_a_command() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let mut o = opts(&env, auth(&env));
    o.jumps = vec![hop(&env)];
    // A relay to %h:%p, as `nc %h %p` (tests/relay.py: the sshd runs on this machine). The jump
    // host runs it as the test's SSH user, who may not be able to read this checkout (CI's
    // throwaway user can't enter the runner's home): a world-readable copy in the temp folder.
    let relay = std::env::temp_dir().join(format!("mg-relay-{}.py", std::process::id()));
    std::fs::write(&relay, include_str!("relay.py")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&relay, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    o.via_command = Some(format!("exec python3 -I '{}' %h %p", relay.display()));
    let connected = Session::connect(o, kh, prompt).await;
    let _ = std::fs::remove_file(&relay);
    let (s, ev) = connected.unwrap();
    let (out, _) = run(s, ev, "echo via-command-ok").await;
    assert!(out.contains("via-command-ok"), "output was: {out}");
}

/// The server's host certificate, signed by a CA trusted for it (`MG_TEST_HOST_CA`, the CA's
/// public key; the sshd has `HostCertificate`): no prompt, nothing pinned. Signed by a CA that
/// isn't the one trusted for the host: refused.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH and MG_TEST_HOST_CA"]
async fn a_host_certificate_from_a_trusted_ca() {
    let Some(env) = env() else { return };
    let Ok(ca) = std::env::var("MG_TEST_HOST_CA") else {
        return;
    };
    let ca = std::fs::read_to_string(ca).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    kh.set_authorities(vec![HostAuthority {
        patterns: vec![env.host.clone()],
        key: russh::keys::PublicKey::from_openssh(ca.trim()).unwrap(),
        from: "test".into(),
    }]);
    let prompt = Arc::new(CountingPrompt::default());
    let (s, ev) = Session::connect(opts(&env, auth(&env)), kh.clone(), prompt.clone())
        .await
        .unwrap();
    let (out, _) = run(s, ev, "echo certified-ok").await;
    assert!(out.contains("certified-ok"), "output was: {out}");
    assert_eq!(prompt.calls.load(Ordering::SeqCst), 0, "no prompt");
    assert_eq!(kh.pinned(&env.host, env.port), None, "nothing pinned");

    // Another CA trusted for the host: its certificate doesn't hold up.
    let (_, other) = mg_ssh::keys::generate_ed25519("other-ca").unwrap();
    kh.set_authorities(vec![HostAuthority {
        patterns: vec![env.host.clone()],
        key: russh::keys::PublicKey::from_openssh(&other.public_key).unwrap(),
        from: "test".into(),
    }]);
    let Err(e) = Session::connect(opts(&env, auth(&env)), kh, prompt.clone()).await else {
        panic!("connected with a certificate from a CA not trusted for the host");
    };
    assert!(matches!(e, Error::HostCertificate { .. }), "error was: {e}");
    assert_eq!(prompt.calls.load(Ordering::SeqCst), 0);
}

/// The first hop through a command on this machine (OpenSSH's `ProxyCommand`): the relay.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn through_a_proxy_command() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let mut o = opts(&env, auth(&env));
    o.dialer = Some(Arc::new(ProxyCommand::new(
        format!(
            "exec python3 -I '{}/tests/relay.py' %h %p",
            env!("CARGO_MANIFEST_DIR")
        ),
        env.user.clone(),
    )));
    let (s, ev) = Session::connect(o, kh, prompt).await.unwrap();
    let (out, _) = run(s, ev, "echo via-proxy-ok").await;
    assert!(out.contains("via-proxy-ok"), "output was: {out}");
}

/// A proxy command that fails, as `aws ssm start-session` without its plugin: what it said is
/// the error.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn a_proxy_command_that_fails_says_why() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let mut o = opts(&env, auth(&env));
    o.dialer = Some(Arc::new(ProxyCommand::new(
        "echo 'SessionManagerPlugin is not found.' >&2; exit 255",
        env.user.clone(),
    )));
    let Err(e) = Session::connect(o, kh, prompt).await else {
        panic!("connected through a command that failed");
    };
    let e = e.to_string();
    assert!(
        e.contains("SessionManagerPlugin is not found."),
        "error was: {e}"
    );
}

/// A jump command that refuses, as Vallic Cloud's `jump` does for a machine it doesn't know:
/// what it wrote to stderr is the error.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn a_jump_command_that_refuses_says_why() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });
    let mut o = opts(&env, auth(&env));
    o.jumps = vec![hop(&env)];
    o.via_command = Some(
        "echo 'vallic: no machine called \"web-9\" here; this environment has: web-1, web-2' >&2; exit 255"
            .into(),
    );
    let Err(e) = Session::connect(o, kh, prompt).await else {
        panic!("connected through a command that refused");
    };
    let e = e.to_string();
    assert!(
        e.contains("vallic: no machine called \"web-9\" here; this environment has: web-1, web-2"),
        "error was: {e}"
    );
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn jump_host_tunnel() {
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    let prompt = Arc::new(CountingPrompt {
        accept: true,
        ..Default::default()
    });

    // Target reached through the same server acting as a jump host (direct-tcpip to itself).
    let mut o = opts(&env, auth(&env));
    o.jumps = vec![hop(&env)];
    let (s, ev) = Session::connect(o, kh.clone(), prompt.clone())
        .await
        .unwrap();
    let (out, _) = run(s, ev, "echo via-jump-ok").await;
    assert!(out.contains("via-jump-ok"), "output was: {out}");
    assert_eq!(
        prompt.calls.load(Ordering::SeqCst),
        1,
        "same host:port, pinned once"
    );

    // Two jumps deep.
    let mut o = opts(&env, auth(&env));
    o.jumps = vec![hop(&env), hop(&env)];
    let (s, ev) = Session::connect(o, kh.clone(), prompt.clone())
        .await
        .unwrap();
    let (out, _) = run(s, ev, "echo two-jumps-ok").await;
    assert!(out.contains("two-jumps-ok"), "output was: {out}");

    // Target port closed behind the jump host.
    let mut o = opts(&env, auth(&env));
    o.port = 1;
    o.jumps = vec![hop(&env)];
    let err = Session::connect(o, kh.clone(), prompt.clone())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::Unreachable { .. }), "{err}");

    // Jump host refuses our credentials: error says which hop failed.
    let mut o = opts(&env, auth(&env));
    o.jumps = vec![Hop {
        auth: Auth::Password(Zeroizing::new("wrong".into())),
        ..hop(&env)
    }];
    let err = Session::connect(o, kh, prompt).await.err().unwrap();
    assert!(
        matches!(&err, Error::Jump { source, .. } if matches!(**source, Error::AuthFailed)),
        "{err}"
    );
}

fn trusting() -> (Arc<KnownHosts>, Arc<CountingPrompt>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let kh = Arc::new(KnownHosts::new(dir.path().join("known_hosts")));
    (
        kh,
        Arc::new(CountingPrompt {
            accept: true,
            ..Default::default()
        }),
        dir,
    )
}

async fn open(env: &Env, kh: &Arc<KnownHosts>, prompt: &Arc<CountingPrompt>) -> Connection {
    Connection::open(
        hop(env),
        vec![],
        None,
        Duration::from_secs(10),
        kh.clone(),
        prompt.clone(),
    )
    .await
    .unwrap()
}

async fn read_line<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    use tokio::io::AsyncReadExt;
    let mut line = Vec::new();
    let read = async {
        let mut b = [0u8; 1];
        while s.read_exact(&mut b).await.is_ok() {
            line.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("timed out reading");
    String::from_utf8_lossy(&line).into_owned()
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn local_forward() {
    let Some(env) = env() else { return };
    let (kh, prompt, _dir) = trusting();
    let forward = Forward::Local {
        bind_host: "127.0.0.1".into(),
        bind_port: 0,
        target_host: "127.0.0.1".into(),
        target_port: env.port,
    };
    let tunnel = Tunnel::start(open(&env, &kh, &prompt).await, forward)
        .await
        .unwrap();
    let port = tunnel.port();
    assert_ne!(port, 0);

    // The server's own sshd, reached from the server side: we should read its banner.
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    assert!(read_line(&mut s).await.starts_with("SSH-2.0-"));
    assert_eq!(tunnel.active_connections(), 1);
    assert!(tunnel.is_alive());
    drop(s);

    tunnel.stop().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "listener must close on stop"
    );
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn dynamic_socks_forward() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(env) = env() else { return };
    let (kh, prompt, _dir) = trusting();
    let forward = Forward::Dynamic {
        bind_host: "127.0.0.1".into(),
        bind_port: 0,
    };
    let tunnel = Tunnel::start(open(&env, &kh, &prompt).await, forward)
        .await
        .unwrap();

    let socks = |dest: Vec<u8>| {
        let port = tunnel.port();
        async move {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            s.write_all(&[5, 1, 0]).await.unwrap();
            let mut hello = [0u8; 2];
            s.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 0]);
            s.write_all(&[&[5u8, 1, 0][..], &dest].concat())
                .await
                .unwrap();
            let mut reply = [0u8; 10];
            s.read_exact(&mut reply).await.unwrap();
            (reply[1], s)
        }
    };
    let p = env.port.to_be_bytes();

    let (code, mut s) = socks([&[1u8, 127, 0, 0, 1][..], &p].concat()).await;
    assert_eq!(code, 0);
    assert!(read_line(&mut s).await.starts_with("SSH-2.0-"));

    let (code, mut s) = socks([&[3u8, 9][..], b"localhost", &p].concat()).await;
    assert_eq!(code, 0);
    assert!(read_line(&mut s).await.starts_with("SSH-2.0-"));

    let (code, _) = socks([&[1u8, 127, 0, 0, 1][..], &1u16.to_be_bytes()].concat()).await;
    assert_eq!(
        code, 5,
        "closed port behind the tunnel reports 'connection refused'"
    );
    tunnel.stop().await;
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn remote_forward() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(env) = env() else { return };
    let (kh, prompt, _dir) = trusting();

    // Echo server on this machine: the forward's target.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n @ 1..) = c.read(&mut buf).await {
                    if c.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let forward = Forward::Remote {
        bind_host: "127.0.0.1".into(),
        bind_port: 0,
        target_host: "127.0.0.1".into(),
        target_port: echo_port,
    };
    let tunnel = Tunnel::start(open(&env, &kh, &prompt).await, forward)
        .await
        .unwrap();
    assert_ne!(
        tunnel.port(),
        0,
        "server allocates a port when 0 is requested"
    );

    // Something on the server connects to the forwarded port; it must reach our echo server.
    let other = open(&env, &kh, &prompt).await;
    let mut s = other
        .direct_tcpip("127.0.0.1", tunnel.port(), None)
        .await
        .unwrap();
    s.write_all(b"ping through -R\n").await.unwrap();
    assert_eq!(read_line(&mut s).await, "ping through -R\n");
    tunnel.stop().await;
    other.close().await.unwrap();
}

/// Stands in for a VPN: dials over plain TCP but proves the first hop went through the dialer.
struct CountingDialer(AtomicUsize);

impl mg_ssh::Dialer for CountingDialer {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<mg_ssh::BoxedStream>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let s = tokio::net::TcpStream::connect((host, port)).await?;
            Ok(Box::new(s) as mg_ssh::BoxedStream)
        })
    }
    fn describe(&self) -> String {
        "test dialer".into()
    }
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn first_hop_uses_the_dialer() {
    let Some(env) = env() else { return };
    let (kh, prompt, _dir) = trusting();
    let dialer = Arc::new(CountingDialer(AtomicUsize::new(0)));

    let mut o = opts(&env, auth(&env));
    o.jumps = vec![hop(&env)];
    o.dialer = Some(dialer.clone());
    let (s, ev) = Session::connect(o, kh.clone(), prompt.clone())
        .await
        .unwrap();
    let (out, _) = run(s, ev, "echo dialed-ok").await;
    assert!(out.contains("dialed-ok"), "output was: {out}");
    assert_eq!(
        dialer.0.load(Ordering::SeqCst),
        1,
        "only the first hop is dialed; the target goes through the jump"
    );

    let mut o = opts(&env, auth(&env));
    o.port = 1;
    o.dialer = Some(dialer);
    let err = Session::connect(o, kh, prompt).await.err().unwrap();
    assert!(
        matches!(&err, Error::Connect { addr, .. } if addr.contains("via test dialer")),
        "{err}"
    );
}

// ------------------------------------------------------------------ SFTP

fn tree(root: &std::path::Path) -> Vec<u8> {
    let mut x = 0x9e37_79b9u32;
    let big: Vec<u8> = (0..3 * 1024 * 1024 + 17)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    std::fs::create_dir_all(root.join("sub/empty")).unwrap();
    std::fs::write(root.join("a.txt"), b"hello sftp\n").unwrap();
    std::fs::write(root.join("sub/b.bin"), &big).unwrap();
    std::fs::write(root.join("run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("loop")).unwrap();
    }
    big
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn sftp_browse_transfer_and_manage() {
    use mg_ssh::Sftp;
    use mg_ssh::sftp::{EntryKind, TransferOptions, join};

    let Some(env) = env() else { return };
    let (kh, prompt, _dir) = trusting();
    let sftp = Sftp::open(Arc::new(open(&env, &kh, &prompt).await))
        .await
        .unwrap();
    let home = sftp.home().await.unwrap();
    assert!(home.starts_with('/'), "{home}");
    let base = join(&home, &format!("mg-sftp-test-{}", std::process::id()));
    let _ = sftp.remove(&base).await;
    sftp.mkdir(&base).await.unwrap();

    let local = tempfile::tempdir().unwrap();
    let src = local.path().join("project");
    let big = tree(&src);

    // Upload a directory tree.
    let mut last = None;
    let opts = TransferOptions::default();
    let up = sftp
        .upload(std::slice::from_ref(&src), &base, &opts, |p| {
            last = Some(p.clone())
        })
        .await
        .unwrap();
    let last = last.unwrap();
    assert_eq!(last.bytes_done, last.bytes_total);
    assert_eq!((up.files, last.files_total), (3, 3));
    assert_eq!(up.skipped, vec!["project/loop".to_string()]);
    let remote = join(&base, "project");
    let names: Vec<String> = sftp
        .list(&remote)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["sub", "a.txt", "run.sh"]);
    let sub = sftp.list(&join(&remote, "sub")).await.unwrap();
    assert_eq!(sub[0].name, "empty");
    assert_eq!(sub[0].kind, EntryKind::Dir);
    assert_eq!(sub[1].size, big.len() as u64);
    #[cfg(unix)]
    assert_eq!(
        sftp.stat(&join(&remote, "run.sh")).await.unwrap().mode,
        Some(0o755)
    );

    // Never overwrites unless asked.
    let again = sftp
        .upload(std::slice::from_ref(&src), &base, &opts, |_| {})
        .await;
    assert!(
        matches!(again, Err(Error::Exists(ref n)) if n == "project"),
        "{again:?}"
    );
    let replace = TransferOptions {
        overwrite: true,
        ..Default::default()
    };
    sftp.upload(std::slice::from_ref(&src), &base, &replace, |_| {})
        .await
        .unwrap();

    // Download it back and compare byte for byte.
    let back = tempfile::tempdir().unwrap();
    let down = sftp
        .download(std::slice::from_ref(&remote), back.path(), &opts, |_| {})
        .await
        .unwrap();
    assert_eq!(down.files, 3);
    let got = back.path().join("project");
    assert_eq!(std::fs::read(got.join("sub/b.bin")).unwrap(), big);
    assert_eq!(std::fs::read(got.join("a.txt")).unwrap(), b"hello sftp\n");
    assert!(got.join("sub/empty").is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(got.join("run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
    assert!(matches!(
        sftp.download(std::slice::from_ref(&remote), back.path(), &opts, |_| {})
            .await,
        Err(Error::Exists(_))
    ));

    // Manage: rename (refusing to clobber), chmod, delete a tree.
    let a = join(&remote, "a.txt");
    let renamed = join(&remote, "renamed.txt");
    assert!(matches!(
        sftp.rename(&a, &join(&remote, "run.sh")).await,
        Err(Error::Exists(_))
    ));
    sftp.rename(&a, &renamed).await.unwrap();
    sftp.chmod(&renamed, 0o600).await.unwrap();
    assert_eq!(sftp.stat(&renamed).await.unwrap().mode, Some(0o600));
    assert!(sftp.list(&join(&base, "nope")).await.is_err());

    // Cancelling removes the partial file.
    let huge = local.path().join("huge.bin");
    std::fs::write(&huge, vec![7u8; 40 * 1024 * 1024]).unwrap();
    let cancel = TransferOptions::default();
    let flag = cancel.cancel.clone();
    let r = sftp
        .upload(std::slice::from_ref(&huge), &base, &cancel, |p| {
            if p.bytes_done > 1024 * 1024 {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        })
        .await;
    assert!(matches!(r, Err(Error::Cancelled)), "{r:?}");
    assert!(!sftp.exists(&join(&base, "huge.bin")).await.unwrap());

    // And a full-size round trip, to catch pipelining bugs.
    let started = std::time::Instant::now();
    sftp.upload(std::slice::from_ref(&huge), &base, &opts, |_| {})
        .await
        .unwrap();
    let huge_back = back.path().join("huge-back");
    std::fs::create_dir(&huge_back).unwrap();
    sftp.download(&[join(&base, "huge.bin")], &huge_back, &opts, |_| {})
        .await
        .unwrap();
    let data = std::fs::read(huge_back.join("huge.bin")).unwrap();
    assert!(data.len() == 40 * 1024 * 1024 && data.iter().all(|b| *b == 7));
    eprintln!("40 MiB up + down in {:?}", started.elapsed());

    sftp.remove(&base).await.unwrap();
    assert!(!sftp.exists(&base).await.unwrap());
}

#[tokio::test]
#[ignore = "needs MG_TEST_SSH"]
async fn authorized_keys_are_replaced_atomically() {
    use mg_ssh::authorized_keys::{self, add, public_key, remove};
    let Some(env) = env() else { return };
    let (kh, prompt, _dir) = trusting();
    let sftp = mg_ssh::Sftp::open(Arc::new(open(&env, &kh, &prompt).await))
        .await
        .unwrap();
    // A scratch directory in the test user's home, never the real ~/.ssh. Everything goes
    // through SFTP: the test user needn't be the one running the test.
    let base = mg_ssh::sftp::join(&sftp.home().await.unwrap(), ".mg-test-authorized-keys");
    if sftp.exists(&base).await.unwrap() {
        sftp.remove(&base).await.unwrap();
    }
    sftp.mkdir(&base).await.unwrap();
    let dir = mg_ssh::sftp::join(&base, "ssh");
    let p = &mg_ssh::sftp::join(&dir, "authorized_keys");
    let mode = async |p: &str| sftp.stat(p).await.unwrap().mode.unwrap() & 0o777;
    let (_, a) = mg_ssh::keys::generate_ed25519("a").unwrap();
    let (_, b) = mg_ssh::keys::generate_ed25519("b").unwrap();

    // No file yet: it's created, in a private directory.
    assert_eq!(authorized_keys::read(&sftp, p).await.unwrap(), "");
    let one = add("", &a.public_key).unwrap();
    authorized_keys::write(&sftp, p, &one).await.unwrap();
    assert_eq!(authorized_keys::read(&sftp, p).await.unwrap(), one);
    assert_eq!((mode(p).await, mode(&dir).await), (0o600, 0o700));

    // Replacing keeps the file's permissions and leaves no temporary file behind.
    sftp.chmod(p, 0o640).await.unwrap();
    let two = add(&one, &b.public_key).unwrap();
    authorized_keys::write(&sftp, p, &two).await.unwrap();
    assert_eq!(authorized_keys::read(&sftp, p).await.unwrap(), two);
    assert_eq!(mode(p).await, 0o640);
    let (without_a, n) = remove(&two, &[public_key(&a.public_key).unwrap()]);
    assert_eq!(n, 1);
    authorized_keys::write(&sftp, p, &without_a).await.unwrap();
    assert_eq!(
        authorized_keys::read(&sftp, p).await.unwrap(),
        format!("{}\n", b.public_key)
    );
    let left: Vec<_> = sftp
        .list(&dir)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != "." && n != "..")
        .collect();
    assert_eq!(left, ["authorized_keys"]);

    sftp.remove(&base).await.unwrap();
}

/// A real `ssh-agent` holding the test key: signing in through it, with one key picked, and
/// forwarding it so `ssh-add -l` on the server sees that key.
#[tokio::test]
#[ignore = "needs MG_TEST_SSH and MG_TEST_KEY"]
async fn agent_sign_in_and_forwarding() {
    let Some(env) = env() else { return };
    let Some(key) = env.key.clone() else { return };
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("agent.sock");
    /// Stops the agent however the test ends.
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _agent = Stop(
        std::process::Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("ssh-agent"),
    );
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let added = std::process::Command::new("ssh-add")
        .arg(&key)
        .env("SSH_AUTH_SOCK", &sock)
        .status()
        .unwrap();
    assert!(added.success());
    let fingerprint = mg_ssh::keys::inspect(&std::fs::read_to_string(&key).unwrap(), None)
        .unwrap()
        .fingerprint;
    let source = mg_ssh::AgentSource::Path(sock.clone());
    let with = |fp: &str| Auth::Agent {
        source: source.clone(),
        fingerprint: Some(fp.to_owned()),
    };
    let (kh, prompt, _kh_dir) = trusting();

    // Signed in with the agent's key; the server can't reach an agent nobody forwarded.
    let (s, ev) = Session::connect(opts(&env, with(&fingerprint)), kh.clone(), prompt.clone())
        .await
        .unwrap();
    let (out, _) = run(s, ev, "ssh-add -l; echo agent-exit=$?").await;
    assert!(!out.contains(&fingerprint), "{out}");
    assert!(out.contains("agent-exit=2"), "no agent there: {out}");

    // Forwarded: `ssh-add -l` lists our key.
    let mut forwarding = opts(&env, with(&fingerprint));
    forwarding.forward_agent = Some(source.clone());
    let (s, ev) = Session::connect(forwarding, kh.clone(), prompt.clone())
        .await
        .unwrap();
    let (out, _) = run(s, ev, "ssh-add -l; echo agent-exit=$?").await;
    assert!(out.contains(&fingerprint), "{out}");
    assert!(out.contains("agent-exit=0"), "{out}");

    // A key the agent doesn't hold: said so, nothing else offered.
    let other = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let err = Session::connect(opts(&env, with(other)), kh, prompt)
        .await
        .err()
        .expect("no such key in the agent");
    assert!(err.to_string().contains("doesn't hold the key"), "{err}");
}
