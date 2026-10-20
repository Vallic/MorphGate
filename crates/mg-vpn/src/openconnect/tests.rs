//! The real `openconnect` program against a small in-process AnyConnect server (XML
//! aggregate auth, CSTP over TLS). The server's side of the tunnel is another in-app stack
//! with an echo service at 10.9.0.1:7, so nothing here needs root or touches the network.
//!
//! openconnect runs this very test binary as its tun script: [`tun_helper_entry`] turns into
//! the helper when openconnect starts it with `VPNFD` set.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Digest as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use super::*;
use crate::netstack::{LinkState, StackConfig, link_pair};
use crate::testutil::{echo_on, exercise, init_tracing};
use crate::{BoxFuture, IpNet, PromptField, Prompter, Tunnel, TunnelInfo, VpnError};

/// Not a real test: openconnect runs the test binary with this filter as its tun script (and
/// as its external browser).
#[test]
#[ignore = "entry point for openconnect's --script-tun, see the module docs"]
fn tun_helper_entry() {
    if std::env::var_os("VPNFD").is_some() || std::env::var_os("MG_OC_URL").is_some() {
        tun_helper_main();
    }
}

/// `MG_OC_HELPER=/path/to/morphgate-desktop` checks the app binary's helper mode instead.
fn helper_command() -> Vec<String> {
    if let Ok(app) = std::env::var("MG_OC_HELPER") {
        return vec![app, "--mg-oc-tun".into()];
    }
    vec![
        std::env::current_exe().unwrap().display().to_string(),
        "openconnect::tests::tun_helper_entry".into(),
        "--exact".into(),
        "--ignored".into(),
        "--quiet".into(),
        "--test-threads=1".into(),
    ]
}

#[derive(Default)]
struct Seen {
    disconnected: bool,
    logins: usize,
}

struct FakeServer {
    port: u16,
    pin: String,
    seen: Arc<Mutex<Seen>>,
}

/// The far end of the VPN: an in-app stack at 10.9.0.1 with an echo service on port 7, and
/// port 22 relayed to `MG_TEST_SSH` when that is set.
async fn far_end() -> (Tunnel, crate::netstack::LinkIo) {
    let (link, stack_io) = link_pair();
    let state = Arc::new(LinkState::default());
    state.up.store(true, std::sync::atomic::Ordering::Relaxed);
    let (stop, _) = watch::channel(false);
    let stack = Tunnel::spawn(
        TunnelInfo::default(),
        StackConfig {
            addresses: vec![IpNet::parse("10.9.0.1/24").unwrap()],
            dns: vec![],
            search_domains: vec![],
            mtu: 1300,
            allowed: None,
            routes: vec![],
        },
        stack_io,
        state,
        stop,
    );
    echo_on(&stack, 7).await;
    if let Ok(target) = std::env::var("MG_TEST_SSH") {
        let mut accepted = stack.listen(22).await;
        tokio::spawn(async move {
            while let Some(mut inside) = accepted.recv().await {
                let target = target.clone();
                tokio::spawn(async move {
                    let mut outside = tokio::net::TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut inside, &mut outside).await;
                });
            }
        });
    }
    (stack, link)
}

const TOKEN: &str = "0123456789ABCDEF";

/// How the fake server signs people in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Login {
    Password,
    PasswordThenCode,
    /// SAML in an external browser (AnyConnect "sso-v2", browser mode `external`).
    Sso,
}

/// What the identity provider hands back through the browser (alphanumeric, as Cisco's are).
const SSO_TOKEN: &str = "SsoToken4711";
/// openconnect listens here for the browser's redirect (Cisco's fixed port).
const SSO_PORT: u16 = 29786;

/// The SSO login form. Its sign-in page carries, in `done=`, where the identity provider would
/// redirect the browser at the end: openconnect's listener, with the token encrypted to the
/// client's STRAP DH key.
fn sso_form(strap_dh_pubkey: &str) -> String {
    let done = format!(
        "http://[::1]:{SSO_PORT}/api/sso/{}",
        sso_token_for(strap_dh_pubkey).expect("a P-256 STRAP DH key")
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="main">
<title>Login</title>
<message>Please complete the authentication process in the browser.</message>
<sso-v2-login>https://idp.example/saml/login?done={done}</sso-v2-login>
<sso-v2-login-final>https://idp.example/saml/final</sso-v2-login-final>
<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>acSamlv2Error</sso-v2-error-cookie-name>
<sso-v2-browser-mode>external</sso-v2-browser-mode>
<form method="post" action="/auth">
<input type="sso" name="sso-token"></input>
</form></auth>
</config-auth>"#
    )
}

/// The token for openconnect's HPKE-style envelope (its hpke.c): ECDH on P-256 with the
/// client's `X-AnyConnect-STRAP-DH-Pubkey`, HKDF-SHA256 ("AC_ECIES") to an AES-256-GCM key,
/// a 12-byte tag; TLVs 1 = our public key (SPKI), 2 = tag, 3 = ciphertext, 4 = IV. Base64,
/// percent-encoded for the URL path.
fn sso_token_for(strap_dh_pubkey: &str) -> Option<String> {
    use aws_lc_rs::{aead, agreement, hkdf, rand};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    /// DER of a P-256 SubjectPublicKeyInfo, up to the uncompressed point.
    const SPKI_P256: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    let der = STANDARD.decode(strap_dh_pubkey.trim()).ok()?;
    let theirs = der.get(der.len().checked_sub(65)?..)?;
    let ours =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rand::SystemRandom::new())
            .ok()?;
    let mut spki = SPKI_P256.to_vec();
    spki.extend_from_slice(ours.compute_public_key().ok()?.as_ref());
    let secret: [u8; 32] = agreement::agree_ephemeral(
        ours,
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, theirs),
        (),
        |s| s.try_into().map_err(|_| ()),
    )
    .ok()?;
    let mut key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
        .extract(&secret)
        .expand(&[b"AC_ECIES"], Len(32))
        .ok()?
        .fill(&mut key)
        .ok()?;
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).ok()?;
    let mut sealed = SSO_TOKEN.as_bytes().to_vec();
    let tag = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).ok()?)
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::empty(),
            &mut sealed,
        )
        .ok()?;
    let mut blob = vec![0, 1];
    for (kind, value) in [
        (1u16, &spki[..]),
        // A truncated GCM tag is the full tag's first bytes.
        (2, &tag.as_ref()[..12]),
        (3, &sealed[..]),
        (4, &iv[..]),
    ] {
        blob.extend_from_slice(&kind.to_be_bytes());
        blob.extend_from_slice(&(value.len() as u16).to_be_bytes());
        blob.extend_from_slice(value);
    }
    Some(
        STANDARD
            .encode(blob)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D"),
    )
}

/// Someone at the browser: finishes the identity provider's part by following its redirect
/// back to openconnect, or cancels.
#[derive(Default)]
struct SsoUser {
    cancel: bool,
    pages: Mutex<Vec<String>>,
}

impl Prompter for SsoUser {
    fn ask(&self, _: String, _: String, _: Vec<PromptField>) -> BoxFuture<'_, Option<Vec<String>>> {
        Box::pin(async { None })
    }

    fn trust_certificate(&self, _: String, _: String, _: String) -> BoxFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn web_sign_in(&self, _: String, url: String) -> BoxFuture<'_, ()> {
        self.pages.lock().unwrap().push(url.clone());
        if self.cancel {
            return Box::pin(async {});
        }
        Box::pin(async move {
            let path = url
                .split_once(&format!("[::1]:{SSO_PORT}"))
                .expect("the redirect back to openconnect")
                .1
                .to_owned();
            let mut s = tokio::net::TcpStream::connect(("::1", SSO_PORT))
                .await
                .expect("openconnect listens for the browser");
            s.write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost:{SSO_PORT}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut reply = String::new();
            let _ = s.read_to_string(&mut reply).await;
            assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
            // Signed in; the connect drops this once the tunnel is up.
            std::future::pending::<()>().await
        })
    }
}

fn auth_form(error: Option<&str>, otp: bool) -> String {
    let error = error
        .map(|e| format!("<error id=\"88\" param1=\"\" param2=\"\">{e}</error>"))
        .unwrap_or_default();
    let (id, message, fields) = if otp {
        (
            "otp",
            "Enter the code from your authenticator app.",
            r#"<input type="password" name="secondary_password" label="Verification code:"></input>"#,
        )
    } else {
        (
            "main",
            "Please enter your username and password.",
            r#"<input type="text" name="username" label="Username:"></input><input type="password" name="password" label="Password:"></input>"#,
        )
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="{id}">
<message>{message}</message>
{error}
<form method="post" action="/auth">
{fields}
</form></auth>
</config-auth>"#
    )
}

fn complete() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-id>1</session-id>
<session-token>{TOKEN}</session-token>
<auth id="success"><message id="0" param1="" param2=""></message></auth>
</config-auth>"#
    )
}

fn tag<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))? + start;
    Some(&body[start..end])
}

async fn read_request<S: AsyncRead + Unpin>(
    s: &mut S,
) -> Option<(String, String, HashMap<String, String>, String)> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.ok()? == 0 {
            return None;
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: HashMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .get("content-length")
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.ok()?;
    Some((
        method,
        path,
        headers,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, body: &str, cookie: bool) {
    let cookie = if cookie {
        format!("Set-Cookie: webvpn={TOKEN}; Secure\r\n")
    } else {
        String::new()
    };
    let msg = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nX-Transcend-Version: 1\r\n{cookie}\r\n{body}",
        body.len()
    );
    let _ = s.write_all(msg.as_bytes()).await;
}

/// CSTP: `STF\x01`, length, type, 0, payload.
async fn cstp<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    s: S,
    mut io: crate::netstack::LinkIo,
    seen: Arc<Mutex<Seen>>,
) {
    let (mut rd, mut wr) = tokio::io::split(s);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    let frame = |kind: u8, payload: &[u8]| {
        let mut f = b"STF\x01".to_vec();
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.push(kind);
        f.push(0);
        f.extend_from_slice(payload);
        f
    };
    let out_tx = tx.clone();
    let pump = tokio::spawn(async move {
        while let Some(p) = io.from_stack.recv().await {
            if out_tx.send(frame(0, &p)).is_err() {
                break;
            }
        }
    });
    loop {
        let mut h = [0u8; 8];
        if rd.read_exact(&mut h).await.is_err() || &h[..4] != b"STF\x01" {
            break;
        }
        let mut payload = vec![0u8; usize::from(u16::from_be_bytes([h[4], h[5]]))];
        if rd.read_exact(&mut payload).await.is_err() {
            break;
        }
        match h[6] {
            0 => {
                let _ = io.to_stack.try_send(payload);
            }
            3 => {
                let _ = tx.send(frame(4, &payload));
            }
            5 | 9 => {
                seen.lock().unwrap().disconnected = true;
                break;
            }
            _ => {}
        }
    }
    pump.abort();
    writer.abort();
}

impl FakeServer {
    async fn start(login: Login) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pin = format!(
            "pin-sha256:{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                sha2::Sha256::digest(rcgen::PublicKeyData::subject_public_key_info(&key))
            )
        );
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let seen = Arc::new(Mutex::new(Seen::default()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut password_ok = false;
                    while let Some((method, _path, headers, body)) = read_request(&mut s).await {
                        if method == "CONNECT" {
                            let ok = headers.get("cookie").is_some_and(|c| c.contains(TOKEN));
                            if !ok {
                                let _ = s
                                    .write_all(
                                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                                    )
                                    .await;
                                return;
                            }
                            let _ = s
                                .write_all(
                                    b"HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\n\
                                      X-CSTP-Address: 10.9.0.2\r\nX-CSTP-Netmask: 255.255.255.0\r\n\
                                      X-CSTP-DNS: 10.9.0.1\r\nX-CSTP-Default-Domain: corp.test\r\n\
                                      X-CSTP-Split-Include: 10.9.0.0/255.255.255.0\r\n\
                                      X-CSTP-MTU: 1300\r\nX-CSTP-Base-MTU: 1500\r\nX-CSTP-DPD: 30\r\n\
                                      X-CSTP-Keepalive: 20\r\nX-CSTP-Idle-Timeout: none\r\n\
                                      X-CSTP-Session-Timeout: none\r\nX-CSTP-Rekey-Method: none\r\n\r\n",
                                )
                                .await;
                            let (_stack, io) = far_end().await;
                            return cstp(s, io, seen).await;
                        }
                        if !body.contains("auth-reply") {
                            let form = match (login, headers.get("x-anyconnect-strap-dh-pubkey")) {
                                (Login::Sso, Some(key)) => sso_form(key),
                                (Login::Sso, None) => {
                                    auth_form(Some("This openconnect can't do SSO."), false)
                                }
                                _ => auth_form(None, false),
                            };
                            respond(&mut s, &form, false).await;
                            continue;
                        }
                        if let Some(token) = tag(&body, "sso-token") {
                            if token == SSO_TOKEN {
                                seen.lock().unwrap().logins += 1;
                                respond(&mut s, &complete(), true).await;
                            } else {
                                respond(&mut s, &auth_form(Some("SSO failed."), false), false)
                                    .await;
                            }
                            continue;
                        }
                        if let Some(code) = tag(&body, "secondary_password") {
                            if password_ok && code == "123456" {
                                seen.lock().unwrap().logins += 1;
                                respond(&mut s, &complete(), true).await;
                            } else {
                                respond(&mut s, &auth_form(Some("Wrong code."), true), false).await;
                            }
                            continue;
                        }
                        let good = tag(&body, "username") == Some("alice")
                            && tag(&body, "password") == Some("s3cret");
                        if !good {
                            respond(&mut s, &auth_form(Some("Login failed."), false), false).await;
                        } else if login == Login::PasswordThenCode {
                            password_ok = true;
                            respond(&mut s, &auth_form(None, true), false).await;
                        } else {
                            seen.lock().unwrap().logins += 1;
                            respond(&mut s, &complete(), true).await;
                        }
                    }
                });
            }
        });
        Self { port, pin, seen }
    }

    fn config(&self, password: Option<&str>, pin: bool) -> OcConfig {
        OcConfig {
            server: format!("https://127.0.0.1:{}/", self.port),
            protocol: "anyconnect".into(),
            username: Some("alice".into()),
            password: password.map(|p| zeroize::Zeroizing::new(p.into())),
            authgroup: None,
            server_cert: pin.then(|| self.pin.clone()),
            helper: helper_command(),
            program: None,
        }
    }
}

/// Answers prompts by label; records what was asked.
#[derive(Default)]
struct Script {
    answers: Vec<(&'static str, &'static str)>,
    trust: bool,
    asked: Mutex<Vec<String>>,
    cert: Mutex<Option<String>>,
}

impl Prompter for Script {
    fn ask(
        &self,
        _: String,
        message: String,
        fields: Vec<PromptField>,
    ) -> BoxFuture<'_, Option<Vec<String>>> {
        let label = fields[0].label.clone();
        self.asked
            .lock()
            .unwrap()
            .push(format!("{label} [{message}]"));
        let a = self
            .answers
            .iter()
            .find(|(k, _)| label.contains(k))
            .map(|(_, v)| vec![(*v).to_owned()]);
        Box::pin(async move { a })
    }

    fn trust_certificate(&self, _: String, _: String, fp: String) -> BoxFuture<'_, bool> {
        *self.cert.lock().unwrap() = Some(fp);
        let t = self.trust;
        Box::pin(async move { t })
    }
}

fn available() -> bool {
    let ok = find_openconnect().is_some();
    if !ok {
        eprintln!("openconnect is not installed; skipping");
    }
    ok
}

#[tokio::test(flavor = "multi_thread")]
async fn connects_with_pinned_certificate_and_saved_password() {
    if !available() {
        return;
    }
    init_tracing();
    let server = FakeServer::start(Login::Password).await;
    let t = start(
        server.config(Some("s3cret"), true),
        &Script::default(),
        "test",
    )
    .await
    .unwrap();
    let info = t.info();
    assert_eq!(info.addresses[0].to_string(), "10.9.0.2/24");
    assert_eq!(
        info.dns,
        vec!["10.9.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(info.search_domains, vec!["corp.test".to_string()]);
    assert_eq!(info.routes[0].to_string(), "10.9.0.0/24");
    assert!(info.accepted_server_cert.is_none());
    let s = t.connect("10.9.0.1", 7).await.unwrap();
    exercise(s, 1024 * 1024).await;

    // Stopping logs out: openconnect sends the server a disconnect.
    t.shutdown();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while !server.seen.lock().unwrap().disconnected {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no disconnect from openconnect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn asks_for_trust_password_and_one_time_code() {
    if !available() {
        return;
    }
    init_tracing();
    let server = FakeServer::start(Login::PasswordThenCode).await;
    let script = Script {
        answers: vec![("Password", "s3cret"), ("Verification code", "123456")],
        trust: true,
        ..Default::default()
    };
    let t = start(server.config(None, false), &script, "test")
        .await
        .unwrap();
    assert_eq!(
        t.info().accepted_server_cert.as_deref(),
        Some(server.pin.as_str())
    );
    assert_eq!(
        script.cert.lock().unwrap().as_deref(),
        Some(server.pin.as_str())
    );
    let asked = script.asked.lock().unwrap().clone();
    assert!(asked.iter().any(|a| a.starts_with("Password")), "{asked:?}");
    assert!(
        asked
            .iter()
            .any(|a| a.starts_with("Verification code") && a.contains("authenticator")),
        "{asked:?}"
    );
    exercise(t.connect("10.9.0.1", 7).await.unwrap(), 64 * 1024).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_saved_password_asks_again_and_cancel_stops() {
    if !available() {
        return;
    }
    init_tracing();
    let server = FakeServer::start(Login::Password).await;
    let script = Script {
        answers: vec![("Password", "s3cret")],
        ..Default::default()
    };
    let t = start(server.config(Some("wrong"), true), &script, "test")
        .await
        .unwrap();
    let asked = script.asked.lock().unwrap().clone();
    assert!(asked[0].contains("Login failed"), "{asked:?}");
    drop(t);

    // Nobody answers: the connect is cancelled and openconnect is stopped.
    let r = start(
        server.config(Some("wrong"), true),
        &Script::default(),
        "test",
    )
    .await;
    assert!(matches!(r, Err(VpnError::Cancelled)), "{:?}", r.map(|_| ()));

    // An untrusted certificate the user rejects.
    let r = start(
        server.config(Some("s3cret"), false),
        &Script::default(),
        "test",
    )
    .await;
    match r {
        Err(VpnError::Connect(m)) => assert!(m.contains("not trusted"), "{m}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn unreachable_server_reports_openconnects_reason() {
    if !available() {
        return;
    }
    let cfg = OcConfig {
        server: "https://127.0.0.1:9/".into(),
        protocol: "anyconnect".into(),
        username: None,
        password: None,
        authgroup: None,
        server_cert: None,
        helper: helper_command(),
        program: None,
    };
    match start(cfg, &Script::default(), "test").await {
        Err(VpnError::Connect(m)) => assert!(m.starts_with("openconnect:"), "{m}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

/// A real `mg-ssh` session through openconnect (see crates/mg-ssh/tests/live.rs for the sshd).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs MG_TEST_SSH and MG_TEST_KEY"]
async fn ssh_session_over_openconnect() {
    let (Ok(_), Ok(key)) = (std::env::var("MG_TEST_SSH"), std::env::var("MG_TEST_KEY")) else {
        return;
    };
    if !available() {
        return;
    }
    let user = std::env::var("MG_TEST_USER").unwrap_or_else(|_| "mg".into());
    let server = FakeServer::start(Login::Password).await;
    let t = start(
        server.config(Some("s3cret"), true),
        &Script::default(),
        "test",
    )
    .await
    .unwrap();
    let out =
        crate::testutil::ssh_echo(Arc::new(t), "10.9.0.1", 22, &user, &key, "over-openconnect")
            .await;
    assert!(out.contains("over-openconnect-42"), "output was: {out}");
}

/// SAML through the real openconnect: it starts our browser script, the page reaches the
/// user, the identity provider's redirect brings the token back, and the tunnel comes up.
/// Cancelling in the browser stops openconnect instead. (Needs an openconnect with
/// `--external-browser`, built with HPKE support, and port 29786 free.)
#[tokio::test(flavor = "multi_thread")]
async fn sso_in_the_browser_with_the_real_openconnect() {
    if !available() {
        return;
    }
    let program = find_openconnect().unwrap();
    if !helper::has_external_browser(&program).await {
        eprintln!("this openconnect has no --external-browser; skipping");
        return;
    }
    init_tracing();
    let server = FakeServer::start(Login::Sso).await;

    let user = SsoUser::default();
    let t = start(server.config(None, true), &user, "test")
        .await
        .unwrap();
    let pages = user.pages.lock().unwrap().clone();
    assert_eq!(pages.len(), 1, "{pages:?}");
    assert!(pages[0].starts_with("https://idp.example/saml/login?done="));
    assert_eq!(server.seen.lock().unwrap().logins, 1);
    exercise(t.connect("10.9.0.1", 7).await.unwrap(), 64 * 1024).await;
    t.shutdown();
    drop(t);

    let quitter = SsoUser {
        cancel: true,
        ..Default::default()
    };
    let r = start(server.config(None, true), &quitter, "test").await;
    assert!(matches!(r, Err(VpnError::Cancelled)), "{:?}", r.map(|_| ()));
    assert_eq!(quitter.pages.lock().unwrap().len(), 1);
    assert_eq!(server.seen.lock().unwrap().logins, 1);
}

/// openconnect runs `--external-browser` as `program URL` with its environment; the script
/// hands the page to the app through the helper.
#[tokio::test]
async fn the_browser_script_hands_the_sign_in_page_to_the_app() {
    let dir = helper::PrivateDir::new().unwrap();
    let socket = dir.0.join("s");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let script = helper::browser_script(&dir.0, &helper_command()).unwrap();
    let page = "https://idp.example/saml?SAMLRequest=a%2Bb&RelayState='x y'";
    let mut browser = tokio::process::Command::new(&script)
        .arg(page)
        .env(helper::ENV_SOCKET, &socket)
        .env(helper::ENV_TOKEN, "t0k3n")
        .spawn()
        .unwrap();
    let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the helper never called")
        .unwrap();
    match helper::receive(stream, "t0k3n").await.unwrap() {
        helper::Received::OpenUrl(url) => assert_eq!(url, page),
        helper::Received::Setup(_) => panic!("a tun setup from the browser script"),
    }
    assert!(browser.wait().await.unwrap().success());

    // Someone else's message (wrong token) is refused.
    let mut stranger = tokio::process::Command::new(&script)
        .arg(page)
        .env(helper::ENV_SOCKET, &socket)
        .env(helper::ENV_TOKEN, "guess")
        .spawn()
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    assert!(helper::receive(stream, "t0k3n").await.is_err());
    let _ = stranger.wait().await;
}

#[test]
fn openconnect_gets_the_browser_script_and_the_tun_helper() {
    let cfg = OcConfig {
        server: " https://vpn.example.com/eng ".into(),
        protocol: "anyconnect".into(),
        username: Some("alice".into()),
        password: Some(zeroize::Zeroizing::new("pw".into())),
        authgroup: Some("Engineering".into()),
        server_cert: Some("pin-sha256:abc=".into()),
        helper: vec!["/opt/Morph Gate/morphgate".into(), "--mg-oc-tun".into()],
        program: None,
    };
    let invocation = |browser| helper::Invocation {
        cfg: &cfg,
        program: std::path::Path::new("/usr/sbin/openconnect"),
        socket: std::path::Path::new("/tmp/mg-oc-1/s"),
        token: "t",
        browser,
    };
    let args = |cmd: tokio::process::Command| -> Vec<String> {
        cmd.as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    };
    let with = args(invocation(Some(std::path::Path::new("/tmp/mg-oc-1/browser"))).command());
    assert_eq!(
        with,
        vec![
            "--protocol=anyconnect",
            "--user=alice",
            "--authgroup=Engineering",
            "--servercert=pin-sha256:abc=",
            "--passwd-on-stdin",
            "--external-browser=/tmp/mg-oc-1/browser",
            "--script-tun",
            "--script='/opt/Morph Gate/morphgate' '--mg-oc-tun'",
            "--",
            "https://vpn.example.com/eng",
        ]
    );
    // An openconnect older than 9 doesn't know the option: it isn't passed.
    let without = args(invocation(None).command());
    assert!(!without.iter().any(|a| a.starts_with("--external-browser")));
    assert_eq!(without.len(), with.len() - 1);
}

#[tokio::test]
async fn the_installed_openconnect_is_asked_whether_it_can_use_a_browser() {
    let Some(program) = find_openconnect() else {
        return;
    };
    let help = std::process::Command::new(&program)
        .arg("--help")
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&[help.stdout, help.stderr].concat())
        .contains("--external-browser");
    assert_eq!(helper::has_external_browser(&program).await, expected);
}

#[test]
fn split_include_and_full_tunnel_settings() {
    let info = helper::parse_settings_for_test(&[
        ("INTERNAL_IP4_ADDRESS", "10.1.2.3"),
        ("INTERNAL_IP4_NETMASK", "255.255.0.0"),
        ("INTERNAL_IP4_DNS", "10.1.0.1 10.1.0.2"),
        ("INTERNAL_IP6_NETMASK", "fd00::5/64"),
        ("INTERNAL_IP4_MTU", "1380"),
        ("CISCO_DEF_DOMAIN", "corp.example lab.example"),
        ("CISCO_SPLIT_INC", "2"),
        ("CISCO_SPLIT_INC_0_ADDR", "10.0.0.0"),
        ("CISCO_SPLIT_INC_0_MASK", "255.0.0.0"),
        ("CISCO_SPLIT_INC_0_MASKLEN", "8"),
        ("CISCO_SPLIT_INC_1_ADDR", "192.168.7.0"),
        ("CISCO_SPLIT_INC_1_MASK", "255.255.255.0"),
    ])
    .unwrap();
    let addrs: Vec<String> = info.addresses.iter().map(ToString::to_string).collect();
    assert_eq!(addrs, vec!["10.1.2.3/16", "fd00::5/64"]);
    assert_eq!(info.dns.len(), 2);
    assert_eq!(info.search_domains, vec!["corp.example", "lab.example"]);
    let routes: Vec<String> = info.routes.iter().map(ToString::to_string).collect();
    assert_eq!(routes, vec!["10.0.0.0/8", "192.168.7.0/24"]);
    assert_eq!(info.mtu, 1380);

    let full = helper::parse_settings_for_test(&[("INTERNAL_IP4_ADDRESS", "10.1.2.3")]).unwrap();
    assert_eq!(full.routes[0].to_string(), "0.0.0.0/0");
    assert_eq!(full.addresses[0].prefix, 32);
    assert!(helper::parse_settings_for_test(&[]).is_err());
}
