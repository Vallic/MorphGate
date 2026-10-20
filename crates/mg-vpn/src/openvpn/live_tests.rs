//! Against a real `openvpn` 2.6 server, which needs root to create its TUN device. Run inside a
//! throwaway user + network namespace (no real root, nothing touches the host network):
//!
//! ```sh
//! cargo test -p mg-vpn --no-run
//! unshare -Urn sh -c 'ip link set lo up && MG_OVPN_LIVE=1 cargo test --offline -p mg-vpn openvpn::live -- --ignored'
//! ```
//!
//! Each test starts its own server on 127.0.0.1 with its own subnet (10.8.N.0/24); an echo
//! service listens on all addresses of the namespace, so `10.8.N.1` reaches it through the
//! server's TUN device. The client is the in-app one: nothing on the client side is a TUN.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use super::config::tests::STATIC_KEY;
use super::*;
use crate::testutil::{echo, exercise, init_tracing};
use crate::{BoxFuture, PromptField, Prompter, Tunnel, VpnError};

fn live() -> bool {
    std::env::var_os("MG_OVPN_LIVE").is_some()
}

struct Pki {
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(vec![]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "MorphGate test CA");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(ca, ca_key);
    let leaf = |cn: &str, eku: ExtendedKeyUsagePurpose| {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![eku];
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        (
            p.signed_by(&key, &issuer).unwrap().pem(),
            key.serialize_pem(),
        )
    };
    let (server_cert, server_key) = leaf("server", ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) = leaf("client", ExtendedKeyUsagePurpose::ClientAuth);
    Pki {
        ca: ca_pem,
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(11_940);

struct Server {
    _child: Child,
    /// The server's working directory (config, keys, scripts).
    dir: tempfile::TempDir,
    port: u16,
    pki: Pki,
}

const CHECK_SH: &str = r#"#!/bin/sh
# auth-user-pass-verify via-file: line 1 user, line 2 password.
u=$(sed -n 1p "$1"); p=$(sed -n 2p "$1")
[ "$u" = alice ] || exit 1
[ "$p" = s3cret ] && exit 0
case "$p" in
  SCRV1:*)
    pw=$(echo "$p" | cut -d: -f2 | base64 -d); otp=$(echo "$p" | cut -d: -f3 | base64 -d)
    [ "$pw" = s3cret ] && [ "$otp" = 123456 ] && exit 0 ;;
esac
exit 1
"#;

/// Starts `openvpn` as a server on 127.0.0.1 with subnet 10.8.`net`.0/24 and waits until it is
/// ready. `extra` is appended to the server config.
async fn server(net: u8, tcp: bool, extra: &str) -> Server {
    let pki = pki();
    let dir = tempfile::tempdir().unwrap();
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    let w = |name: &str, body: &str| std::fs::write(dir.path().join(name), body).unwrap();
    w("ca.pem", &pki.ca);
    w("server.pem", &pki.server_cert);
    w("server.key", &pki.server_key);
    w("ta.key", STATIC_KEY);
    for (script, body) in [("check.sh", CHECK_SH), ("web-auth.sh", WEB_AUTH_SH)] {
        w(script, body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join(script),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    }
    let conf = format!(
        "port {port}\nproto {}\nlocal 127.0.0.1\ndev tun\nserver 10.8.{net}.0 255.255.255.0\n\
         ca ca.pem\ncert server.pem\nkey server.key\ndh none\nverb 3\nscript-security 2\n{extra}\n",
        if tcp { "tcp4-server" } else { "udp4" },
    );
    w("server.conf", &conf);
    let mut child = Command::new("openvpn")
        .arg("--config")
        .arg("server.conf")
        .current_dir(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("openvpn is installed");
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut log = String::new();
    let up = tokio::time::timeout(Duration::from_secs(15), async {
        while let Ok(Some(line)) = lines.next_line().await {
            log.push_str(&line);
            log.push('\n');
            if line.contains("Initialization Sequence Completed") {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(up, Ok(true)),
        "openvpn server didn't start:\n{log}"
    );
    // Keep draining the log (and show it with RUST_LOG=debug).
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(target: "openvpn-server", "{line}");
        }
    });
    Server {
        _child: child,
        dir,
        port,
        pki,
    }
}

/// Echo service on every address of the namespace, so `10.8.N.1:port` works through TUN.
async fn echo_service() -> u16 {
    let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(echo(s));
        }
    });
    port
}

fn client_profile(s: &Server, proto: &str, extra: &str, with_cert: bool) -> String {
    let mut p = format!(
        "client\ndev tun\nproto {proto}\nremote 127.0.0.1 {}\nnobind\nremote-cert-tls server\n\
         verify-x509-name server name\n<ca>\n{}</ca>\n{extra}\n",
        s.port, s.pki.ca
    );
    if with_cert {
        p.push_str(&format!(
            "<cert>\n{}</cert>\n<key>\n{}</key>\n",
            s.pki.client_cert, s.pki.client_key
        ));
    }
    p
}

struct Answers(Vec<String>);

impl Prompter for Answers {
    fn ask(&self, _: String, _: String, f: Vec<PromptField>) -> BoxFuture<'_, Option<Vec<String>>> {
        let n = f.len();
        let a: Vec<String> = self.0.iter().take(n).cloned().collect();
        Box::pin(async move { Some(a) })
    }
    fn trust_certificate(&self, _: String, _: String, _: String) -> BoxFuture<'_, bool> {
        Box::pin(async { false })
    }
}

fn alice() -> Option<Credentials> {
    Some(Credentials {
        username: "alice".into(),
        password: Zeroizing::new("s3cret".into()),
    })
}

async fn connect(profile: &str, creds: Option<Credentials>) -> Result<Tunnel, VpnError> {
    let cfg = Config::parse(profile).unwrap();
    start(cfg, creds, &Answers(vec![]), "test").await
}

async fn check(tunnel: &Tunnel, net: u8, port: u16, bulk: usize) {
    let s = tunnel
        .connect(&format!("10.8.{net}.1"), port)
        .await
        .expect("connect through the tunnel");
    exercise(s, bulk).await;
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn udp_tls_auth_certificate() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(1, false, "topology subnet\ntls-auth ta.key 0\npush \"dhcp-option DNS 10.8.1.1\"\npush \"dhcp-option DOMAIN corp.test\"").await;
    let echo = echo_service().await;
    let t = connect(
        &client_profile(
            &s,
            "udp",
            &format!("key-direction 1\n<tls-auth>\n{STATIC_KEY}</tls-auth>"),
            true,
        ),
        None,
    )
    .await
    .unwrap();
    let info = t.info();
    assert_eq!(info.addresses[0].to_string(), "10.8.1.2/24");
    assert_eq!(
        info.dns,
        vec!["10.8.1.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(info.search_domains, vec!["corp.test".to_string()]);
    check(&t, 1, echo, 2 * 1024 * 1024).await;
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn tcp_tls_crypt_password_chacha() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(
        2,
        true,
        "topology subnet\ntls-crypt ta.key\ndata-ciphers CHACHA20-POLY1305\nverify-client-cert none\n\
         username-as-common-name\nauth-user-pass-verify check.sh via-file",
    )
    .await;
    let echo = echo_service().await;
    let profile = client_profile(
        &s,
        "tcp",
        &format!(
            "auth-user-pass\ndata-ciphers CHACHA20-POLY1305\n<tls-crypt>\n{STATIC_KEY}</tls-crypt>"
        ),
        false,
    );
    let t = connect(&profile, alice()).await.unwrap();
    check(&t, 2, echo, 1024 * 1024).await;

    let wrong = Some(Credentials {
        username: "alice".into(),
        password: Zeroizing::new("nope".into()),
    });
    match connect(&profile, wrong).await {
        Err(VpnError::Auth(m)) => assert!(m.contains("rejected"), "{m}"),
        other => panic!("expected an auth failure, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn static_challenge_is_sent_as_scrv1() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(
        3,
        false,
        "topology subnet\nverify-client-cert none\nusername-as-common-name\nauth-user-pass-verify check.sh via-file",
    )
    .await;
    let echo = echo_service().await;
    let profile = client_profile(
        &s,
        "udp",
        "auth-user-pass\nstatic-challenge \"Enter PIN\" 1",
        false,
    );
    let cfg = Config::parse(&profile).unwrap();
    // Saved password, typed one-time code.
    let t = start(cfg, alice(), &Answers(vec!["123456".into()]), "test")
        .await
        .unwrap();
    check(&t, 3, echo, 64 * 1024).await;
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn cbc_cipher_with_legacy_prf_keys() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(
        4,
        false,
        "topology subnet\ndata-ciphers AES-256-CBC\nauth SHA256",
    )
    .await;
    let echo = echo_service().await;
    let mut cfg = Config::parse(&client_profile(
        &s,
        "udp",
        "data-ciphers AES-256-CBC\nauth SHA256",
        true,
    ))
    .unwrap();
    // Don't offer tls-ekm: the server falls back to OpenVPN's PRF.
    cfg.ekm = false;
    let t = start(cfg, None, &Answers(vec![]), "test").await.unwrap();
    check(&t, 4, echo, 1024 * 1024).await;
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn lzo_compressed_server_net30() {
    if !live() {
        return;
    }
    init_tracing();
    // The net30 topology (by name: OpenVPN 2.7 makes subnet the default) and a server that really
    // compresses what it sends.
    let s = server(
        5,
        false,
        "topology net30\ncomp-lzo yes\nallow-compression yes",
    )
    .await;
    let echo = echo_service().await;
    let t = connect(&client_profile(&s, "udp", "comp-lzo yes", true), None)
        .await
        .unwrap();
    assert_eq!(t.info().addresses[0].prefix, 32);
    // Highly compressible data, so packets from the server arrive LZO-compressed.
    let mut stream = t.connect("10.8.5.1", echo).await.unwrap();
    let data = vec![b'z'; 200_000];
    let (mut rd, mut wr) = tokio::io::split(&mut stream);
    let (_, got) = tokio::join!(
        async {
            wr.write_all(&data).await.unwrap();
        },
        async {
            let mut got = vec![0u8; data.len()];
            tokio::time::timeout(Duration::from_secs(20), rd.read_exact(&mut got))
                .await
                .expect("stalled")
                .unwrap();
            got
        }
    );
    assert!(got == data);
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn renegotiation_with_auth_token_and_keepalive() {
    if !live() {
        return;
    }
    init_tracing();
    // The server renegotiates every 3 s and drops clients silent for 4 s.
    let s = server(
        6,
        false,
        "topology subnet\nreneg-sec 3\nkeepalive 1 4\nhand-window 10\nauth-gen-token 600 20\n\
         auth-user-pass-verify check.sh via-file",
    )
    .await;
    let echo = echo_service().await;
    let t = Arc::new(
        connect(&client_profile(&s, "udp", "auth-user-pass", true), alice())
            .await
            .unwrap(),
    );
    let mut stream = t.connect("10.8.6.1", echo).await.unwrap();
    // Keep a conversation going across several renegotiations.
    for i in 0..40u32 {
        let msg = format!("message {i}\n");
        stream.write_all(msg.as_bytes()).await.unwrap();
        let mut back = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
            .await
            .unwrap_or_else(|_| panic!("stalled at message {i}"))
            .unwrap();
        assert_eq!(back, msg.as_bytes());
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // Idle longer than the server's ping-restart: our keepalives must hold the session.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(t.is_alive(), "{:?}", t.error());
    check(&t, 6, echo, 256 * 1024).await;
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn wrong_ca_is_refused() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(7, false, "topology subnet").await;
    let other = pki();
    let profile = client_profile(&s, "udp", "", true).replace(&s.pki.ca, &other.ca);
    match connect(&profile, None).await {
        Err(VpnError::Connect(m)) => assert!(m.contains("CA"), "{m}"),
        other => panic!("expected a certificate error, got {:?}", other.map(|_| ())),
    }
}

/// Runs the local `openvpn` to make keys in `dir`.
fn openvpn_genkey(dir: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("openvpn")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .status()
        .expect("openvpn is installed");
    assert!(status.success(), "openvpn {args:?}");
}

/// A tls-crypt-v2 server key and a client key made from it, by the real `openvpn`.
fn tls_crypt_v2_keys(dir: &std::path::Path, name: &str) -> (std::path::PathBuf, String) {
    let server = format!("{name}-server.key");
    let client = format!("{name}-client.key");
    openvpn_genkey(dir, &["--genkey", "tls-crypt-v2-server", &server]);
    openvpn_genkey(
        dir,
        &[
            "--tls-crypt-v2",
            &server,
            "--genkey",
            "tls-crypt-v2-client",
            &client,
        ],
    );
    (
        dir.join(server),
        std::fs::read_to_string(dir.join(client)).unwrap(),
    )
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn tls_crypt_v2_client_key() {
    if !live() {
        return;
    }
    init_tracing();
    let keys = tempfile::tempdir().unwrap();
    let (server_key, client_key) = tls_crypt_v2_keys(keys.path(), "ours");
    // `force-cookie`: the server keeps no state before the three-way handshake, so the client
    // must send its wrapped key a second time (P_CONTROL_WKC_V1).
    let s = server(
        9,
        false,
        &format!(
            "topology subnet\ntls-crypt-v2 {} force-cookie",
            server_key.display()
        ),
    )
    .await;
    let echo = echo_service().await;
    let profile = |key: &str| {
        client_profile(
            &s,
            "udp",
            &format!("server-poll-timeout 3\n<tls-crypt-v2>\n{key}</tls-crypt-v2>"),
            true,
        )
    };
    let t = connect(&profile(&client_key), None).await.unwrap();
    check(&t, 9, echo, 1024 * 1024).await;
    drop(t);

    // A client key made for another server: its packets don't authenticate, so the server
    // doesn't answer at all.
    let (_, stranger) = tls_crypt_v2_keys(keys.path(), "theirs");
    match connect(&profile(&stranger), None).await {
        Err(VpnError::Connect(m)) => assert!(m.contains("no answer"), "{m}"),
        other => panic!("expected no answer, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn tls_crypt_v2_over_tcp_with_renegotiation() {
    if !live() {
        return;
    }
    init_tracing();
    let keys = tempfile::tempdir().unwrap();
    let (server_key, client_key) = tls_crypt_v2_keys(keys.path(), "tcp");
    let s = server(
        10,
        true,
        &format!(
            "topology subnet\ntls-crypt-v2 {}\nreneg-sec 2\nhand-window 10",
            server_key.display()
        ),
    )
    .await;
    let echo = echo_service().await;
    let t = connect(
        &client_profile(
            &s,
            "tcp",
            &format!("<tls-crypt-v2>\n{client_key}</tls-crypt-v2>"),
            true,
        ),
        None,
    )
    .await
    .unwrap();
    let mut stream = t.connect("10.8.10.1", echo).await.unwrap();
    // Keep talking across a few renegotiations, which also run under the client's key.
    for i in 0..24u32 {
        let msg = format!("message {i}\n");
        stream.write_all(msg.as_bytes()).await.unwrap();
        let mut back = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
            .await
            .unwrap_or_else(|_| panic!("stalled at message {i}"))
            .unwrap();
        assert_eq!(back, msg.as_bytes());
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    check(&t, 10, echo, 256 * 1024).await;
}

/// Runs the local `openssl` in `dir`: the PKI comes from rcgen, but bundles and encrypted keys
/// should be the ones people actually get.
fn openssl(dir: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl is installed");
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn pkcs12_bundle_and_encrypted_key() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(11, false, "topology subnet").await;
    let echo = echo_service().await;
    let dir = tempfile::tempdir().unwrap();
    let w = |name: &str, body: &str| std::fs::write(dir.path().join(name), body).unwrap();
    w("ca.crt", &s.pki.ca);
    w("client.crt", &s.pki.client_cert);
    w("client.key", &s.pki.client_key);
    let pass = "pass:correct horse";
    openssl(
        dir.path(),
        &[
            "pkcs12",
            "-export",
            "-inkey",
            "client.key",
            "-in",
            "client.crt",
            "-certfile",
            "ca.crt",
            "-passout",
            pass,
            "-out",
            "client.p12",
        ],
    );
    let bundle = std::fs::read(dir.path().join("client.p12")).unwrap();

    // No <ca>: the bundle's CA vouches for the server, as with OpenVPN.
    let profile = format!(
        "client\ndev tun\nproto udp\nremote 127.0.0.1 {}\nnobind\nremote-cert-tls server\n\
         verify-x509-name server name\n<pkcs12>\n{}\n</pkcs12>\n",
        s.port,
        base64::engine::general_purpose::STANDARD.encode(&bundle)
    );
    let typed = Answers(vec!["correct horse".into()]);
    let t = start(Config::parse(&profile).unwrap(), None, &typed, "test")
        .await
        .unwrap();
    check(&t, 11, echo, 256 * 1024).await;
    drop(t);

    // The same key as an encrypted PKCS#8 file next to its certificate.
    openssl(
        dir.path(),
        &[
            "pkcs8",
            "-topk8",
            "-v2",
            "aes-256-cbc",
            "-in",
            "client.key",
            "-passout",
            pass,
            "-out",
            "client-enc.pem",
        ],
    );
    let encrypted = std::fs::read_to_string(dir.path().join("client-enc.pem")).unwrap();
    let profile = format!(
        "{}<cert>\n{}</cert>\n<key>\n{encrypted}</key>\n",
        client_profile(&s, "udp", "", false),
        s.pki.client_cert
    );
    let t = start(Config::parse(&profile).unwrap(), None, &typed, "test")
        .await
        .unwrap();
    check(&t, 11, echo, 256 * 1024).await;
    drop(t);

    // A wrong password three times over: refused before anything goes on the wire.
    let wrong = Answers(vec!["nope".into()]);
    match start(Config::parse(&profile).unwrap(), None, &wrong, "test").await {
        Err(VpnError::Auth(m)) => assert!(m.contains("wrong passphrase"), "{m}"),
        other => panic!("expected a passphrase error, got {:?}", other.map(|_| ())),
    }
}

/// Deferred authentication the way an SSO plugin does it (OpenVPN 2.6 scripts may defer): ask
/// the client to sign in on a web page, then approve once the test has "visited" it (the file
/// `visited-<client port>` appears), or refuse after 20 s.
const WEB_AUTH_SH: &str = r#"#!/bin/sh
printf '30\nwebauth\nWEB_AUTH::http://127.0.0.1:9/sso?visit=visited-%s\n' "$untrusted_port" > "$auth_pending_file"
(
  i=0
  while [ ! -f "visited-$untrusted_port" ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done
  if [ -f "visited-$untrusted_port" ]; then echo 1 > "$auth_control_file"; else echo 0 > "$auth_control_file"; fi
) > /dev/null 2>&1 &
exit 2
"#;

/// A user who signs in on whatever page opens (the test page says which file to create), and
/// never cancels.
struct Browser {
    dir: std::path::PathBuf,
    pages: std::sync::Mutex<Vec<String>>,
}

impl Prompter for Browser {
    fn ask(&self, _: String, _: String, _: Vec<PromptField>) -> BoxFuture<'_, Option<Vec<String>>> {
        Box::pin(async { None })
    }
    fn trust_certificate(&self, _: String, _: String, _: String) -> BoxFuture<'_, bool> {
        Box::pin(async { false })
    }
    fn web_sign_in(&self, _: String, url: String) -> BoxFuture<'_, ()> {
        let visit = url.split_once("?visit=").expect("the test page").1;
        std::fs::write(self.dir.join(visit), "").unwrap();
        self.pages.lock().unwrap().push(url);
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
#[ignore = "needs a network namespace with root: see the module docs"]
async fn web_sign_in_with_deferred_auth() {
    if !live() {
        return;
    }
    init_tracing();
    let s = server(
        12,
        false,
        "topology subnet\nverify-client-cert none\nusername-as-common-name\n\
         auth-user-pass-verify web-auth.sh via-file",
    )
    .await;
    let echo = echo_service().await;
    let profile = client_profile(&s, "udp", "auth-user-pass", false);

    // Someone who can't open a browser cancels: the connect stops at once.
    let started = std::time::Instant::now();
    match start(
        Config::parse(&profile).unwrap(),
        alice(),
        &Answers(vec![]),
        "test",
    )
    .await
    {
        Err(VpnError::Cancelled) => {}
        other => panic!("expected a cancel, got {:?}", other.map(|_| ())),
    }
    assert!(started.elapsed() < Duration::from_secs(10));

    // The page opens, the user signs in there, and the server lets the tunnel up.
    let browser = Browser {
        dir: s.dir.path().to_owned(),
        pages: Default::default(),
    };
    let t = start(Config::parse(&profile).unwrap(), alice(), &browser, "test")
        .await
        .unwrap();
    let pages = browser.pages.lock().unwrap().clone();
    assert_eq!(pages.len(), 1, "{pages:?}");
    assert!(pages[0].starts_with("http://127.0.0.1:9/sso?visit=visited-"));
    check(&t, 12, echo, 256 * 1024).await;
}

/// A real `mg-ssh` session through OpenVPN. The sshd lives outside the namespace, so
/// `MG_TEST_SSH` may be `unix:/path` (a socket on the shared filesystem relaying to it).
#[tokio::test]
#[ignore = "needs a network namespace with root, MG_TEST_SSH and MG_TEST_KEY"]
async fn ssh_session_over_openvpn() {
    let (Ok(target), Ok(key)) = (std::env::var("MG_TEST_SSH"), std::env::var("MG_TEST_KEY")) else {
        return;
    };
    if !live() {
        return;
    }
    init_tracing();
    let user = std::env::var("MG_TEST_USER").unwrap_or_else(|_| "mg".into());
    let s = server(8, false, "topology subnet").await;
    // Relay connections reaching the namespace to the sshd.
    let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut inside, _)) = l.accept().await {
            let target = target.clone();
            tokio::spawn(async move {
                if let Some(path) = target.strip_prefix("unix:") {
                    let mut out = tokio::net::UnixStream::connect(path).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut inside, &mut out).await;
                } else {
                    let mut out = tokio::net::TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut inside, &mut out).await;
                }
            });
        }
    });
    let t = connect(&client_profile(&s, "udp", "", true), None)
        .await
        .unwrap();
    let out =
        crate::testutil::ssh_echo(Arc::new(t), "10.8.8.1", port, &user, &key, "over-openvpn").await;
    assert!(out.contains("over-openvpn-42"), "output was: {out}");
}

/// Runs without a server: the errors people see when the address or port is wrong.
#[tokio::test]
async fn unreachable_servers_fail_fast_with_a_reason() {
    let p = pki();
    let udp = format!(
        "client\nremote 127.0.0.1 9\nserver-poll-timeout 2\n<ca>\n{}</ca>\n",
        p.ca
    );
    let started = std::time::Instant::now();
    match connect(&udp, None).await {
        Err(VpnError::Connect(m)) => assert!(m.contains("no answer"), "{m}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    let tcp = udp.replace("remote 127.0.0.1 9", "remote 127.0.0.1 9 tcp");
    match connect(&tcp, None).await {
        Err(VpnError::Connect(m)) => {
            assert!(m.contains("refused") || m.contains("127.0.0.1"), "{m}")
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
}
