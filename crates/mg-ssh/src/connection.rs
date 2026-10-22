//! An authenticated SSH transport (possibly through jump hosts), shared by interactive
//! sessions and port-forwarding tunnels.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::agent::AgentIdentity;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelStream, Disconnect};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::command_stream::command_stream;
use crate::proxy_command::expand;
use crate::{AgentKey, AgentSource, Error, HostKeyCheck, HostKeyInfo, KnownHosts, Result};

pub enum Auth {
    /// Tries `password`, then falls back to keyboard-interactive (common with PAM).
    Password(Zeroizing<String>),
    KeyFile {
        path: PathBuf,
        passphrase: Option<Zeroizing<String>>,
    },
    /// A private key held in memory (from the vault), OpenSSH or PEM encoded, and maybe an
    /// OpenSSH certificate for it, presented first.
    Key {
        private_key: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
        certificate: Option<String>,
    },
    /// The keys of the agent at `source`; only the one with `fingerprint` (`SHA256:…`) when set,
    /// as OpenSSH's `IdentitiesOnly` (a server allows a few attempts only).
    Agent {
        source: AgentSource,
        fingerprint: Option<String>,
    },
}

/// One SSH server on the way to the target.
pub struct Hop {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    /// How the hop before carries this one: a command it runs, whose stdin and stdout carry
    /// this hop's SSH (OpenSSH's `ProxyCommand ssh jump-host <command>`), instead of a forwarded
    /// TCP connection. `%h`, `%p` and `%r` are this hop's host, port and user. For bastions that
    /// refuse forwarding but hand a session on (`nc %h %p`, Vallic's `<env> jump <machine>`).
    pub via_command: Option<String>,
    /// The host keys whoever described this host lists for it (a feed): the server must
    /// present one of them, and is trusted without asking.
    pub listed_keys: Option<ListedKeys>,
}

/// Host keys a server is known to have, from where its host came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListedKeys {
    /// OpenSSH public keys, `ssh-ed25519 AAAA…`.
    pub keys: Vec<String>,
    /// Who lists them, for messages (the feed's name).
    pub from: String,
}

/// [`ListedKeys`], read: `None` when none of them is a key (then the host is asked about as
/// any other).
fn listed(keys: Option<ListedKeys>) -> Option<(Vec<PublicKey>, String)> {
    let l = keys?;
    let parsed: Vec<PublicKey> = l
        .keys
        .iter()
        .filter_map(|k| PublicKey::from_openssh(k.trim()).ok())
        .collect();
    (!parsed.is_empty()).then_some((parsed, l.from))
}

/// Asks the user whether to trust a host key seen for the first time.
pub trait HostKeyPrompt: Send + Sync + 'static {
    fn confirm(&self, info: HostKeyInfo) -> Pin<Box<dyn Future<Output = bool> + Send>>;

    /// A security key (FIDO2) is about to sign in to `host`: ask for a touch. `None` once it
    /// has signed (or not).
    fn security_key(&self, _host: &str, _key: Option<&AgentKey>) {}
}

/// Any byte stream the SSH transport can run over.
pub trait AsyncStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

pub type BoxedStream = Box<dyn AsyncStream>;

/// Opens the first hop's TCP connection some other way than the OS network stack, e.g. inside
/// a per-host VPN tunnel. Jump hosts after the first hop go through SSH as usual.
pub trait Dialer: Send + Sync + 'static {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<BoxedStream>> + Send + 'a>>;
    /// For error messages, e.g. `VPN "Client A"`.
    fn describe(&self) -> String;

    /// Why the last stream it gave ended before SSH got going, where it can say (a proxy
    /// command's stderr).
    fn failure(&self) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        Box::pin(async { None })
    }
}

enum Via<'a> {
    Os,
    Dialer(&'a dyn Dialer),
    Jump(&'a client::Handle<Verifier>),
}

/// Server-initiated `forwarded-tcpip` channels for an active remote forward.
pub(crate) type ForwardSlot = Arc<Mutex<Option<mpsc::UnboundedSender<Channel<Msg>>>>>;
/// The agent the target's server may use (agent forwarding); `None` refuses its channels.
pub(crate) type AgentSlot = Arc<Mutex<Option<AgentSource>>>;

/// What only the target hop has: where remote-forward channels go, and the agent it may use.
struct TargetSlots {
    forwarded: ForwardSlot,
    agent: AgentSlot,
}

pub struct Connection {
    pub(crate) handle: client::Handle<Verifier>,
    /// Jump connections, nearest first; dropping them would tear down the tunnel.
    jumps: Vec<client::Handle<Verifier>>,
    pub(crate) forwarded: ForwardSlot,
    agent: AgentSlot,
    /// Kept alive for the connection's lifetime (e.g. the VPN the first hop runs through).
    _dialer: Option<Arc<dyn Dialer>>,
}

impl Connection {
    /// Connects to `target` through `jumps` (nearest first), verifying every host key and
    /// authenticating at every hop. `timeout` applies per hop and pauses during host-key prompts.
    /// `dialer`, if set, opens the first hop's TCP connection (e.g. through a VPN).
    pub async fn open(
        target: Hop,
        jumps: Vec<Hop>,
        dialer: Option<Arc<dyn Dialer>>,
        timeout: Duration,
        known_hosts: Arc<KnownHosts>,
        prompt: Arc<dyn HostKeyPrompt>,
    ) -> Result<Self> {
        let mut handles: Vec<client::Handle<Verifier>> = Vec::with_capacity(jumps.len());
        for hop in jumps {
            let name = format!("{}:{}", hop.host, hop.port);
            let via = match (handles.last(), dialer.as_deref()) {
                (Some(prev), _) => Via::Jump(prev),
                (None, Some(d)) => Via::Dialer(d),
                (None, None) => Via::Os,
            };
            let handle = connect_hop(hop, via, &known_hosts, &prompt, timeout, None)
                .await
                .map_err(|e| Error::Jump {
                    host: name,
                    source: Box::new(e),
                })?;
            handles.push(handle);
        }
        let forwarded: ForwardSlot = Arc::default();
        let agent: AgentSlot = Arc::default();
        let via = match (handles.last(), dialer.as_deref()) {
            (Some(prev), _) => Via::Jump(prev),
            (None, Some(d)) => Via::Dialer(d),
            (None, None) => Via::Os,
        };
        let handle = connect_hop(
            target,
            via,
            &known_hosts,
            &prompt,
            timeout,
            Some(TargetSlots {
                forwarded: forwarded.clone(),
                agent: agent.clone(),
            }),
        )
        .await?;
        Ok(Self {
            handle,
            jumps: handles,
            forwarded,
            agent,
            _dialer: dialer,
        })
    }

    /// Lets the server use the agent at `source` (agent forwarding, which a session then asks
    /// for). Until then the server's agent channels are refused.
    pub fn allow_agent_forwarding(&self, source: AgentSource) {
        *self.agent.lock().expect("not poisoned") = Some(source);
    }

    /// A TCP stream to `host:port` as seen from the server (`direct-tcpip`).
    pub async fn direct_tcpip(
        &self,
        host: &str,
        port: u16,
        originator: Option<SocketAddr>,
    ) -> Result<ChannelStream<Msg>> {
        let (orig_ip, orig_port) = originator.map_or(("127.0.0.1".to_owned(), 0), |a| {
            (a.ip().to_string(), a.port())
        });
        let channel = self
            .handle
            .channel_open_direct_tcpip(host, u32::from(port), orig_ip, u32::from(orig_port))
            .await
            .map_err(|e| Error::Unreachable {
                addr: format!("{host}:{port}"),
                reason: e.to_string(),
            })?;
        Ok(channel.into_stream())
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed() || self.jumps.iter().any(|j| j.is_closed())
    }

    pub async fn close(&self) -> Result<()> {
        let result = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        for jump in self.jumps.iter().rev() {
            let _ = jump.disconnect(Disconnect::ByApplication, "", "en").await;
        }
        Ok(result?)
    }
}

/// The host key algorithms whose certificates are asked for where a host CA is trusted.
const HOST_CERTIFICATES: &[russh::keys::Algorithm] = &[
    russh::keys::Algorithm::Ed25519,
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP256,
    },
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP384,
    },
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP521,
    },
    russh::keys::Algorithm::Rsa {
        hash: Some(russh::keys::HashAlg::Sha512),
    },
    russh::keys::Algorithm::Rsa {
        hash: Some(russh::keys::HashAlg::Sha256),
    },
];

/// A hop's SSH settings. `host_certificates`: a host CA is trusted for it, so its certificate is
/// asked for (else only plain host keys, which are pinned).
fn client_config(host_certificates: bool) -> Arc<client::Config> {
    let mut preferred = russh::Preferred::default();
    if host_certificates {
        preferred.host_key_certificates = HOST_CERTIFICATES.into();
    }
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        preferred,
        ..Default::default()
    })
}

/// Connects (directly, or through `via` with a direct-tcpip tunnel), verifies the host key and
/// authenticates.
async fn connect_hop(
    hop: Hop,
    via: Via<'_>,
    known_hosts: &Arc<KnownHosts>,
    prompt: &Arc<dyn HostKeyPrompt>,
    timeout: Duration,
    target: Option<TargetSlots>,
) -> Result<client::Handle<Verifier>> {
    let (forwarded, agent) = match target {
        Some(t) => (Some(t.forwarded), Some(t.agent)),
        None => (None, None),
    };
    let addr = format!("{}:{}", hop.host, hop.port);
    let rejected = Arc::new(Mutex::new(None));
    let prompting = Arc::new(AtomicBool::new(false));
    let verifier = Verifier {
        host: hop.host.clone(),
        port: hop.port,
        listed: listed(hop.listed_keys.clone()),
        known_hosts: known_hosts.clone(),
        prompt: prompt.clone(),
        rejected: rejected.clone(),
        prompting: prompting.clone(),
        forwarded,
        agent,
    };
    let config = client_config(!known_hosts.authorities_for(&hop.host, hop.port).is_empty());
    let via_command = match hop.via_command.as_deref() {
        Some(c) => Some(expand(c, &hop.host, hop.port, &hop.user).map_err(|reason| {
            Error::Unreachable {
                addr: addr.clone(),
                reason,
            }
        })?),
        None => None,
    };
    let (dial, host, port) = (addr.clone(), hop.host.clone(), hop.port);
    let connecting = async move {
        match via {
            Via::Os => client::connect(config, dial.as_str(), verifier).await,
            Via::Dialer(dialer) => {
                let stream = dialer
                    .dial(&host, port)
                    .await
                    .map_err(|source| Error::Connect {
                        addr: format!("{dial} via {}", dialer.describe()),
                        source,
                    })?;
                match client::connect_stream(config, stream, verifier).await {
                    Ok(handle) => Ok(handle),
                    Err(e) => match dialer.failure().await {
                        Some(said) => Err(Error::Unreachable {
                            addr: format!("{dial} via {}", dialer.describe()),
                            reason: said,
                        }),
                        None => Err(e),
                    },
                }
            }
            Via::Jump(jump) => {
                let unreachable = |reason: String| Error::Unreachable {
                    addr: dial.clone(),
                    reason,
                };
                match &via_command {
                    // A session running the command, without a terminal: its stdio is the stream.
                    // Where the connection through it fails, what the command wrote to stderr
                    // says why ("no machine called …").
                    Some(command) => {
                        let channel = jump
                            .channel_open_session()
                            .await
                            .map_err(|e| unreachable(e.to_string()))?;
                        channel
                            .exec(false, command.as_bytes())
                            .await
                            .map_err(|e| unreachable(format!("{command}: {e}")))?;
                        let (stream, stderr) = command_stream(channel);
                        match client::connect_stream(config, stream, verifier).await {
                            Ok(handle) => Ok(handle),
                            Err(e) => match stderr.text().await {
                                said if said.is_empty() => Err(e),
                                said => Err(unreachable(format!("{command}: {said}"))),
                            },
                        }
                    }
                    None => {
                        let channel = jump
                            .channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0)
                            .await
                            .map_err(|e| unreachable(e.to_string()))?;
                        client::connect_stream(config, channel.into_stream(), verifier).await
                    }
                }
            }
        }
    };
    tokio::pin!(connecting);

    // The timeout restarts while the user is looking at the host-key prompt.
    let outcome = loop {
        match tokio::time::timeout(timeout, &mut connecting).await {
            Ok(result) => break result,
            Err(_) if prompting.load(Ordering::SeqCst) => continue,
            Err(_) => return Err(Error::Timeout(addr)),
        }
    };
    let mut handle = match outcome {
        Ok(h) => h,
        Err(e) => {
            if let Some(why) = rejected.lock().expect("not poisoned").take() {
                return Err(why);
            }
            return Err(match e {
                Error::Ssh(russh::Error::IO(source)) => connect_failed(addr, source),
                other => other,
            });
        }
    };
    if !authenticate(&mut handle, &hop.host, &hop.user, hop.auth, prompt).await? {
        return Err(Error::AuthFailed);
    }
    Ok(handle)
}

/// A direct connection that failed. macOS 15 and later ask before an app connects to devices on
/// the local network, and answer "no route to host" while it isn't allowed (the first attempt
/// fails while the question is up): say where that's allowed.
fn connect_failed(addr: String, source: std::io::Error) -> Error {
    if cfg!(target_os = "macos") && source.kind() == std::io::ErrorKind::HostUnreachable {
        return Error::Unreachable {
            addr,
            reason: format!(
                "{source}. If it's on your local network, macOS may be asking whether MorphGate \
                 can reach devices there: allow it in System Settings → Privacy & Security → \
                 Local Network, then connect again"
            ),
        };
    }
    Error::Connect { addr, source }
}

async fn authenticate(
    handle: &mut client::Handle<Verifier>,
    host: &str,
    user: &str,
    auth: Auth,
    prompt: &Arc<dyn HostKeyPrompt>,
) -> Result<bool> {
    match auth {
        Auth::Password(password) => {
            if handle
                .authenticate_password(user, password.as_str())
                .await?
                .success()
            {
                return Ok(true);
            }
            keyboard_interactive(handle, user, &password).await
        }
        Auth::KeyFile { path, passphrase } => {
            let key =
                russh::keys::load_secret_key(&path, passphrase.as_deref().map(String::as_str))
                    .map_err(|e| match e {
                        russh::keys::Error::KeyIsEncrypted => Error::KeyNeedsPassphrase,
                        other => Error::Key(format!("{}: {other}", path.display())),
                    })?;
            publickey(handle, user, key).await
        }
        Auth::Key {
            private_key,
            passphrase,
            certificate,
        } => {
            let key = crate::keys::decode(&private_key, passphrase.as_deref().map(String::as_str))?;
            // The certificate first, then the key alone (as ssh does): a server may take either.
            let cert = certificate
                .as_deref()
                .and_then(|c| russh::keys::Certificate::from_openssh(c.trim()).ok());
            if let Some(cert) = cert
                && handle
                    .authenticate_openssh_cert(user, Arc::new(key.clone()), cert)
                    .await?
                    .success()
            {
                return Ok(true);
            }
            publickey(handle, user, key).await
        }
        Auth::Agent {
            source,
            fingerprint,
        } => agent(handle, host, user, &source, fingerprint.as_deref(), prompt).await,
    }
}

async fn publickey(
    handle: &mut client::Handle<Verifier>,
    user: &str,
    key: russh::keys::PrivateKey,
) -> Result<bool> {
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
    Ok(handle.authenticate_publickey(user, key).await?.success())
}

async fn keyboard_interactive(
    handle: &mut client::Handle<Verifier>,
    user: &str,
    password: &str,
) -> Result<bool> {
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await?;
    // Answer hidden prompts with the password; bail out on anything unexpected.
    for _ in 0..4 {
        resp = match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                if prompts.iter().any(|p| p.echo) {
                    return Ok(false);
                }
                let answers = prompts.iter().map(|_| password.to_owned()).collect();
                handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?
            }
        };
    }
    Ok(false)
}

async fn agent(
    handle: &mut client::Handle<Verifier>,
    host: &str,
    user: &str,
    source: &AgentSource,
    fingerprint: Option<&str>,
    prompt: &Arc<dyn HostKeyPrompt>,
) -> Result<bool> {
    let mut client = crate::agent::client(source).await?;
    let mut ids: Vec<_> = client
        .request_identities()
        .await
        .map_err(|e| Error::Agent(e.to_string()))?
        .into_iter()
        .filter(|id| fingerprint.is_none_or(|f| crate::agent::key_of(id).fingerprint == f))
        .collect();
    // Certificates first (`step ssh login`, `tsh login` add one beside its key): a server that
    // only trusts its CA takes no key alone.
    ids.sort_by_key(|id| !matches!(id, AgentIdentity::Certificate { .. }));
    if ids.is_empty() {
        return Err(Error::Agent(match fingerprint {
            Some(f) => {
                format!("the agent doesn't hold the key {f} (unlock it, or add it to the agent)")
            }
            None => "the agent holds no keys".into(),
        }));
    }
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    for id in ids {
        let key = crate::agent::key_of(&id);
        if key.security_key {
            prompt.security_key(host, Some(&key));
        }
        let signed = match &id {
            AgentIdentity::Certificate { certificate, .. } => {
                handle
                    .authenticate_certificate_with(user, certificate.clone(), hash, &mut client)
                    .await
            }
            _ => {
                handle
                    .authenticate_publickey_with(
                        user,
                        id.public_key().into_owned(),
                        hash,
                        &mut client,
                    )
                    .await
            }
        };
        if key.security_key {
            prompt.security_key(host, None);
        }
        if signed.map_err(|e| Error::Agent(e.to_string()))?.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) struct Verifier {
    host: String,
    port: u16,
    /// The keys listed for this host, and by whom: they decide instead of known_hosts.
    listed: Option<(Vec<PublicKey>, String)>,
    known_hosts: Arc<KnownHosts>,
    prompt: Arc<dyn HostKeyPrompt>,
    /// Why the key was refused, surfaced after `connect` fails.
    rejected: Arc<Mutex<Option<Error>>>,
    /// Set while the user decides on an unknown key, so the connect timeout waits.
    prompting: Arc<AtomicBool>,
    /// Only on the target hop: where accepted remote-forward channels go.
    forwarded: Option<ForwardSlot>,
    /// Only on the target hop: the agent it may forward.
    agent: Option<AgentSlot>,
}

impl Verifier {
    fn reject(&self, err: Error) -> bool {
        *self.rejected.lock().expect("not poisoned") = Some(err);
        false
    }
}

impl client::Handler for Verifier {
    type Error = Error;

    async fn check_server_key(&mut self, server_key: &PublicKeyOrCertificate) -> Result<bool> {
        // A host certificate from a CA trusted for this host: no pinning. Certificates are only
        // asked for where a CA is (see `client_config`); one that doesn't hold up is refused,
        // as OpenSSH does.
        if let PublicKeyOrCertificate::Certificate(cert) = server_key {
            // Revoked: the certificate's key, or the CA that signed it.
            for revoked in [cert.public_key(), cert.signature_key()] {
                if let Some(from) = self.known_hosts.revoked(&self.host, self.port, revoked) {
                    return Ok(self.reject(Error::HostKeyRevoked {
                        host: self.host.clone(),
                        port: self.port,
                        fingerprint: revoked.fingerprint(HashAlg::Sha256).to_string(),
                        from,
                    }));
                }
            }
            let authorities = self.known_hosts.authorities_for(&self.host, self.port);
            if !authorities.is_empty() {
                return Ok(
                    match crate::known_hosts::certified(cert, &self.host, &authorities) {
                        Ok(()) => true,
                        Err(why) => self.reject(Error::HostCertificate {
                            host: self.host.clone(),
                            port: self.port,
                            why,
                        }),
                    },
                );
            }
        }
        // A plain key (or a certificate nobody vouches for here): pinned on first use.
        let key: PublicKey = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => {
                PublicKey::new(cert.public_key().clone(), "")
            }
        };
        let mut info = HostKeyInfo::new(&self.host, self.port, &key);
        // Listed for the host (its feed): one of those, or refused. A revoked key still isn't.
        if let Some((keys, from)) = &self.listed {
            if let Some(revoked) = self
                .known_hosts
                .revoked(&self.host, self.port, key.key_data())
            {
                return Ok(self.reject(Error::HostKeyRevoked {
                    host: self.host.clone(),
                    port: self.port,
                    fingerprint: info.fingerprint.clone(),
                    from: revoked,
                }));
            }
            if keys.iter().any(|k| k.key_data() == key.key_data()) {
                return Ok(true);
            }
            return Ok(self.reject(Error::HostKeyNotListed {
                host: self.host.clone(),
                port: self.port,
                fingerprint: info.fingerprint.clone(),
                from: from.clone(),
            }));
        }
        match self.known_hosts.check(&self.host, self.port, &key)? {
            HostKeyCheck::Trusted => Ok(true),
            HostKeyCheck::Revoked { from } => Ok(self.reject(Error::HostKeyRevoked {
                host: self.host.clone(),
                port: self.port,
                fingerprint: info.fingerprint.clone(),
                from,
            })),
            HostKeyCheck::Changed { path, line } => {
                info.pinned = self
                    .known_hosts
                    .recorded(&self.host, self.port, &path, line);
                info.changed_in = Some((path, line));
                Ok(self.reject(Error::HostKeyChanged(Box::new(info))))
            }
            HostKeyCheck::Unknown => {
                self.prompting.store(true, Ordering::SeqCst);
                let accepted = self.prompt.confirm(info.clone()).await;
                self.prompting.store(false, Ordering::SeqCst);
                if accepted {
                    self.known_hosts.learn(&self.host, self.port, &key)?;
                    Ok(true)
                } else {
                    Ok(self.reject(Error::HostKeyRejected(Box::new(info))))
                }
            }
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<()> {
        let sender = self
            .forwarded
            .as_ref()
            .and_then(|slot| slot.lock().expect("not poisoned").clone());
        match sender {
            Some(tx) => {
                reply.accept().await;
                let _ = tx.send(channel);
            }
            // No remote forward requested: dropping the reply rejects the channel.
            None => drop(reply),
        }
        Ok(())
    }

    /// The server opens a channel to our agent: only with agent forwarding asked for, and
    /// then to the agent chosen for it. A server can't use an agent nobody forwarded.
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<()> {
        let source = self
            .agent
            .as_ref()
            .and_then(|slot| slot.lock().expect("not poisoned").clone());
        let Some(source) = source else {
            drop(reply);
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            match crate::agent::stream(&source).await {
                Ok(mut agent) => {
                    let mut channel = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut channel, &mut agent).await;
                }
                Err(e) => tracing::warn!("agent forwarding: {e}"),
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_route_on_macos_points_at_local_network_access() {
        let e = connect_failed(
            "192.168.1.5:22".into(),
            std::io::Error::from(std::io::ErrorKind::HostUnreachable),
        );
        assert_eq!(
            e.to_string().contains("Privacy & Security → Local Network"),
            cfg!(target_os = "macos"),
            "{e}"
        );
        let refused = connect_failed(
            "192.168.1.5:22".into(),
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
        );
        assert!(matches!(refused, Error::Connect { .. }));
    }
}
