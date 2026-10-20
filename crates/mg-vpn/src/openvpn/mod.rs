//! OpenVPN client, in-app: the TLS control channel (rustls) over UDP or TCP, the data channel
//! (AES-GCM, ChaCha20-Poly1305, or AES-CBC + HMAC), and the shared TCP/IP stack on top. No TUN
//! device and no root, like every MorphGate tunnel.
//!
//! Speaks to OpenVPN 2.4+ servers (and OpenVPN Access Server, pfSense, OPNsense, …): tls-auth,
//! tls-crypt, tls-crypt-v2 (client-specific keys), client certificates, username/password with
//! static and dynamic challenges, auth-token, cipher negotiation, compression framing,
//! server-initiated renegotiation.

mod compress;
mod config;
mod data;
mod keyfile;
mod keys;
mod lzo;
mod push;
mod reliable;
mod replay;
mod session;
mod tls;
mod wire;

#[cfg(test)]
mod live_tests;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::{mpsc, oneshot, watch};
use zeroize::Zeroizing;

pub use config::{
    Cipher, Compress, Config, Digest, NameType, Proto, Remote, StaticChallenge, TlsCryptV2Key,
    TlsWrap, inline_files, inline_files_with,
};

use crate::netstack::{LinkState, StackConfig, link_pair};
use crate::{PromptField, Prompter, Tunnel, TunnelInfo, VpnError, WebSignIn};
use keyfile::KeyError;
use session::{Failure, Notice, Params};

/// MTU of the in-app stack: small enough that encrypted packets fit a 1500-byte path.
const STACK_MTU: u16 = 1400;
/// Passphrases typed for a protected client key before giving up.
const MAX_PASSPHRASE_TRIES: usize = 3;
/// Dynamic challenges answered in a row before giving up.
const MAX_CHALLENGES: usize = 3;

/// Username and password for `auth-user-pass` profiles (saved in the vault, or typed).
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

fn field(label: &str, secret: bool, value: &str) -> PromptField {
    PromptField {
        label: label.into(),
        secret,
        value: value.into(),
    }
}

/// Fills in what the profile and the vault don't have by asking, and applies a static
/// challenge (`SCRV1`).
async fn credentials(
    cfg: &Config,
    saved: Option<Credentials>,
    prompter: &dyn Prompter,
    title: &str,
) -> Result<Option<(String, Zeroizing<String>)>, VpnError> {
    if !cfg.auth_user_pass {
        return Ok(None);
    }
    let mut username = saved
        .as_ref()
        .map(|c| c.username.clone())
        .filter(|u| !u.is_empty())
        .or_else(|| cfg.username.clone())
        .unwrap_or_default();
    let mut password = saved
        .map(|c| c.password)
        .filter(|p| !p.is_empty())
        .or_else(|| cfg.password.clone());
    let challenge = cfg.static_challenge.as_ref();
    if username.is_empty() || password.is_none() || challenge.is_some() {
        let mut fields = Vec::new();
        if username.is_empty() || password.is_none() {
            fields.push(field("Username", false, &username));
            fields.push(field("Password", true, ""));
        }
        if let Some(ch) = challenge {
            fields.push(field(&ch.text, !ch.echo, ""));
        }
        let answers = prompter
            .ask(title.into(), String::new(), fields)
            .await
            .ok_or(VpnError::Cancelled)?;
        let mut answers = answers.into_iter();
        if username.is_empty() || password.is_none() {
            username = answers.next().unwrap_or_default();
            password = Some(Zeroizing::new(answers.next().unwrap_or_default()));
        }
        if let Some(ch) = challenge {
            let response = Zeroizing::new(answers.next().unwrap_or_default());
            let pw = password.take().unwrap_or_default();
            password = Some(Zeroizing::new(if ch.concat {
                format!("{}{}", *pw, *response)
            } else {
                format!(
                    "SCRV1:{}:{}",
                    STANDARD.encode(pw.as_bytes()),
                    STANDARD.encode(response.as_bytes())
                )
            }));
        }
    }
    Ok(Some((username, password.unwrap_or_default())))
}

/// What a passphrase unlocks.
#[derive(Clone)]
enum Locked {
    Key(Zeroizing<String>),
    Bundle(Zeroizing<Vec<u8>>),
}

impl Locked {
    /// Tries one passphrase, off the async runtime (key derivation is deliberately slow).
    async fn open(&self, cfg: &Config, passphrase: &str) -> Result<tls::Identity, KeyError> {
        let locked = self.clone();
        let passphrase = Zeroizing::new(passphrase.to_owned());
        let opened = tokio::task::spawn_blocking(move || match &locked {
            Locked::Key(pem) => keyfile::decrypt(pem, &passphrase).map(Ok),
            Locked::Bundle(der) => keyfile::open_pkcs12(der, &passphrase).map(Err),
        })
        .await
        .map_err(|e| KeyError::Unusable(format!("opening the client key failed: {e}")))??;
        match opened {
            Ok(key) => {
                tls::identity_with_key(cfg, key).map_err(|e| KeyError::Unusable(e.to_string()))
            }
            Err(bundle) => Ok(tls::Identity {
                chain: bundle.chain,
                key: bundle.key,
                authorities: bundle.authorities,
            }),
        }
    }
}

/// The client certificate and key, unlocked with the profile's `<askpass>`, with no password
/// (bundles exported without one), or with a passphrase the user types.
async fn identity(
    cfg: &Config,
    prompter: &dyn Prompter,
    title: &str,
) -> Result<Option<tls::Identity>, VpnError> {
    let (locked, what, label) = match (&cfg.pkcs12, &cfg.key) {
        (Some(der), _) => (
            Locked::Bundle(der.clone()),
            "certificate bundle (PKCS#12) is protected by a password",
            "Bundle password",
        ),
        (None, Some(pem)) if cfg.needs_passphrase() => (
            Locked::Key(pem.clone()),
            "private key is protected by a passphrase",
            "Key passphrase",
        ),
        _ => return tls::plain_identity(cfg),
    };
    let mut untyped: Vec<Zeroizing<String>> = cfg.askpass.iter().cloned().collect();
    if untyped.is_empty() && matches!(locked, Locked::Bundle(_)) {
        untyped.push(Zeroizing::new(String::new()));
    }
    for passphrase in &untyped {
        match locked.open(cfg, passphrase).await {
            Ok(id) => return Ok(Some(id)),
            Err(KeyError::WrongPassphrase) => {}
            Err(KeyError::Unusable(m)) => return Err(VpnError::Config(m)),
        }
    }
    let mut message = if cfg.askpass.is_some() {
        format!("The passphrase in the profile (askpass) doesn't work: its {what}.")
    } else {
        format!("The profile's {what}.")
    };
    for _ in 0..MAX_PASSPHRASE_TRIES {
        let answer = prompter
            .ask(title.into(), message, vec![field(label, true, "")])
            .await
            .ok_or(VpnError::Cancelled)?;
        let passphrase = Zeroizing::new(answer.into_iter().next().unwrap_or_default());
        match locked.open(cfg, &passphrase).await {
            Ok(id) => return Ok(Some(id)),
            Err(KeyError::WrongPassphrase) => message = "That didn't work; try again.".into(),
            Err(KeyError::Unusable(m)) => return Err(VpnError::Config(m)),
        }
    }
    Err(VpnError::Auth(format!(
        "wrong passphrase for the client {}",
        match locked {
            Locked::Key(_) => "key",
            Locked::Bundle(_) => "certificate bundle (PKCS#12)",
        }
    )))
}

/// Connects (trying the profile's servers in order) and returns the running tunnel.
pub async fn start(
    cfg: Config,
    saved: Option<Credentials>,
    prompter: &dyn Prompter,
    label: &str,
) -> Result<Tunnel, VpnError> {
    let title = format!("Sign in to {label}");
    let identity = identity(&cfg, prompter, &title).await?;
    let tls = tls::client_config(&cfg, identity.as_ref())?;
    drop(identity);
    let cfg = Arc::new(cfg);
    let mut creds = credentials(&cfg, saved, prompter, &title).await?;
    let mut remotes = cfg.remotes.clone();
    if cfg.remote_random && remotes.len() > 1 {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).expect("system RNG");
        let n = remotes.len();
        remotes.rotate_left(usize::from(r[0]) % n);
    }
    let mut errors = Vec::new();
    let mut challenges = 0;
    let mut i = 0;
    while i < remotes.len() {
        let remote = remotes[i].clone();
        let (io, stack_io) = link_pair();
        let state = Arc::new(LinkState::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let (ready_tx, mut ready_rx) = oneshot::channel();
        let (notices_tx, mut notices) = mpsc::unbounded_channel();
        tokio::spawn(session::run(
            Params {
                cfg: cfg.clone(),
                tls: tls.clone(),
                remote: remote.clone(),
                credentials: creds.clone(),
                notices: notices_tx,
            },
            io,
            state.clone(),
            stop_rx,
            ready_tx,
        ));
        // Until the session is up (or not): relay what the server wants the user to do.
        let mut web = WebSignIn::none();
        let outcome = loop {
            tokio::select! {
                r = &mut ready_rx => break r.unwrap_or_else(|_| {
                    Err(Failure::Fatal("the OpenVPN session ended unexpectedly".into()))
                }),
                Some(Notice::WebSignIn(url)) = notices.recv() => web.open(prompter, &title, url),
                () = web.cancelled() => {
                    let _ = stop_tx.send(true);
                    return Err(VpnError::Cancelled);
                }
            }
        };
        // Signed in (or failed): the browser prompt goes away.
        drop(web);
        match outcome {
            Ok(ready) => {
                let pushed = &ready.pushed;
                let mut dns = pushed.dns.clone();
                dns.extend(cfg.dns.iter().copied());
                let mut domains = pushed.domains.clone();
                domains.extend(cfg.domains.iter().cloned());
                let mut routes = if cfg.route_nopull {
                    pushed.addresses()
                } else {
                    pushed.networks()
                };
                routes.extend(cfg.routes.iter().copied());
                let addresses = pushed.addresses();
                tracing::info!(
                    server = %remote, cipher = ready.cipher.name(),
                    address = %addresses.first().map(ToString::to_string).unwrap_or_default(),
                    "openvpn connected"
                );
                let info = TunnelInfo {
                    server: format!("{remote} ({})", ready.server),
                    addresses: addresses.clone(),
                    dns: dns.clone(),
                    search_domains: domains.clone(),
                    routes: routes.clone(),
                    mtu: STACK_MTU,
                    accepted_server_cert: None,
                };
                let stack = StackConfig {
                    addresses,
                    dns,
                    search_domains: domains,
                    mtu: pushed.tun_mtu.unwrap_or(cfg.tun_mtu).min(STACK_MTU),
                    allowed: None,
                    routes,
                };
                return Ok(Tunnel::spawn(info, stack, stack_io, state, stop_tx));
            }
            Err(Failure::Unreachable(e)) => {
                errors.push(e);
                i += 1;
            }
            Err(Failure::AuthFailed(e)) => return Err(VpnError::Auth(e)),
            Err(Failure::Fatal(e)) => return Err(VpnError::Connect(e)),
            Err(Failure::Challenge {
                state_id,
                username,
                text,
                echo,
            }) => {
                challenges += 1;
                if challenges > MAX_CHALLENGES {
                    return Err(VpnError::Auth("too many sign-in challenges".into()));
                }
                let answer = prompter
                    .ask(title.clone(), text.clone(), vec![field(&text, !echo, "")])
                    .await
                    .ok_or(VpnError::Cancelled)?;
                let response = answer.into_iter().next().unwrap_or_default();
                creds = Some((
                    username,
                    Zeroizing::new(format!("CRV1::{state_id}::{response}")),
                ));
                // Same server again, with the answer.
            }
        }
    }
    Err(VpnError::Connect(match errors.len() {
        0 => "the profile has no servers".into(),
        1 => errors.remove(0),
        _ => format!("no OpenVPN server answered: {}", errors.join("; ")),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::keyfile::tests::{
        CA, CLIENT_CERT, LEGACY_AES128, P12, P12_NO_PASSWORD, PASSPHRASE, PKCS8_AES256,
    };
    use super::*;
    use crate::BoxFuture;

    /// Answers prompts from a list, in order, and records what it was asked.
    #[derive(Default)]
    struct Typed {
        answers: Mutex<Vec<&'static str>>,
        asked: Mutex<Vec<(String, String)>>,
    }

    impl Typed {
        fn new(answers: &[&'static str]) -> Self {
            let mut answers = answers.to_vec();
            answers.reverse();
            Self {
                answers: Mutex::new(answers),
                ..Default::default()
            }
        }

        fn asked(&self) -> Vec<(String, String)> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Prompter for Typed {
        fn ask(
            &self,
            _: String,
            message: String,
            f: Vec<PromptField>,
        ) -> BoxFuture<'_, Option<Vec<String>>> {
            self.asked
                .lock()
                .unwrap()
                .push((f[0].label.clone(), message));
            assert!(f[0].secret, "passphrases are typed hidden");
            let a = self
                .answers
                .lock()
                .unwrap()
                .pop()
                .map(|a| vec![a.to_owned()]);
            Box::pin(async move { a })
        }

        fn trust_certificate(&self, _: String, _: String, _: String) -> BoxFuture<'_, bool> {
            Box::pin(async { false })
        }
    }

    fn with_key(key: &str, extra: &str) -> Config {
        Config::parse(&format!(
            "client\nremote x\n<ca>\n{CA}</ca>\n<cert>\n{CLIENT_CERT}</cert>\n<key>\n{key}</key>\n{extra}"
        ))
        .unwrap()
    }

    fn with_bundle(der: &[u8], extra: &str) -> Config {
        Config::parse(&format!(
            "client\nremote x\n<pkcs12>\n{}\n</pkcs12>\n{extra}",
            STANDARD.encode(der)
        ))
        .unwrap()
    }

    /// Unlocks, then checks the result makes a TLS client.
    async fn unlock(cfg: &Config, p: &Typed) -> Result<Option<tls::Identity>, VpnError> {
        let id = identity(cfg, p, "Sign in to test").await?;
        tls::client_config(cfg, id.as_ref())?;
        Ok(id)
    }

    #[tokio::test]
    async fn an_encrypted_key_asks_for_its_passphrase_until_it_fits() {
        for key in [PKCS8_AES256, LEGACY_AES128] {
            let p = Typed::new(&["nope", PASSPHRASE]);
            let id = unlock(&with_key(key, ""), &p).await.unwrap().unwrap();
            assert_eq!(id.chain.len(), 1);
            let asked = p.asked();
            assert_eq!(asked.len(), 2);
            assert_eq!(asked[0].0, "Key passphrase");
            assert!(
                asked[0].1.contains("protected by a passphrase"),
                "{asked:?}"
            );
            assert!(asked[1].1.contains("try again"), "{asked:?}");
        }
    }

    #[tokio::test]
    async fn askpass_unlocks_without_asking_and_a_wrong_one_asks() {
        let p = Typed::new(&[]);
        let cfg = with_key(
            PKCS8_AES256,
            &format!("<askpass>\n{PASSPHRASE}\n</askpass>\n"),
        );
        assert!(unlock(&cfg, &p).await.unwrap().is_some());
        assert!(p.asked().is_empty());

        let p = Typed::new(&[PASSPHRASE]);
        let cfg = with_key(PKCS8_AES256, "<askpass>\nstale\n</askpass>\n");
        assert!(unlock(&cfg, &p).await.unwrap().is_some());
        assert!(p.asked()[0].1.contains("askpass"), "{:?}", p.asked());
    }

    #[tokio::test]
    async fn bundles_bring_the_ca_and_open_without_a_password_when_they_have_none() {
        let p = Typed::new(&[]);
        let id = unlock(&with_bundle(P12_NO_PASSWORD, ""), &p)
            .await
            .unwrap()
            .unwrap();
        assert!(p.asked().is_empty(), "no password, no question");
        assert_eq!(id.authorities.len(), 1, "the CA comes from the bundle");

        let p = Typed::new(&[PASSPHRASE]);
        let id = unlock(&with_bundle(P12, ""), &p).await.unwrap().unwrap();
        assert_eq!(p.asked()[0].0, "Bundle password");
        assert!(p.asked()[0].1.contains("PKCS#12"));
        assert_eq!(id.chain.len(), 1);
    }

    #[tokio::test]
    async fn cancelling_or_three_wrong_passphrases_stop_the_connect() {
        let cfg = with_key(PKCS8_AES256, "");
        assert!(matches!(
            unlock(&cfg, &Typed::new(&[])).await,
            Err(VpnError::Cancelled)
        ));
        let p = Typed::new(&["a", "b", "c", PASSPHRASE]);
        match unlock(&cfg, &p).await {
            Err(VpnError::Auth(m)) => assert!(m.contains("wrong passphrase for the client key")),
            other => panic!("{:?}", other.map(|_| ())),
        }
        assert_eq!(p.asked().len(), MAX_PASSPHRASE_TRIES);
    }

    #[tokio::test]
    async fn plain_profiles_need_no_passphrase() {
        let p = Typed::new(&[]);
        let plain = Config::parse(&format!(
            "client\nremote x\n<ca>\n{CA}</ca>\nauth-user-pass\n"
        ))
        .unwrap();
        assert!(unlock(&plain, &p).await.unwrap().is_none());
        assert!(p.asked().is_empty());
    }
}
