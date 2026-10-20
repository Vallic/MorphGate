//! Per-host VPNs, all running inside the app (mg-vpn): WireGuard and OpenVPN natively,
//! openconnect (AnyConnect, GlobalProtect, …) through the openconnect program in script-tun
//! mode. Starting one changes nothing on the system, and different clients' VPNs can be up at
//! the same time.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use mg_ssh::{BoxedStream, Dialer};
use mg_store::{Item, ItemData, VpnKind, VpnProfile};
use mg_vpn::openconnect::{OcConfig, PROTOCOLS};
use mg_vpn::openvpn::Credentials;
use mg_vpn::wireguard::WgConfig;
use mg_vpn::{BoxFuture, PromptField, Prompter, Tunnel, VpnError};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::ssh::VpnRef;
use crate::util::expand_home;
use crate::vault::VaultState;

/// When MorphGate's binary is started with this argument it acts as openconnect's tun script.
pub const OC_HELPER_ARG: &str = "--mg-oc-tun";
const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

type Answers = Option<Vec<String>>;

/// Running tunnels, shared by every session and port forward using the same profile. Only weak
/// references live here: a tunnel stops once its last connection is gone.
#[derive(Default)]
pub struct VpnManager {
    tunnels: Mutex<HashMap<String, Weak<Tunnel>>>,
    /// One connect at a time per profile (it may be waiting on a password prompt); others wait
    /// for it and share the tunnel.
    starting: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    prompts: Arc<Mutex<HashMap<u64, oneshot::Sender<Answers>>>>,
    next_prompt: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

struct VpnDialer {
    tunnel: Arc<Tunnel>,
    label: String,
}

impl Dialer for VpnDialer {
    fn dial<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<BoxedStream>> + Send + 'a>> {
        Box::pin(async move { Ok(Box::new(self.tunnel.connect(host, port).await?) as BoxedStream) })
    }

    fn describe(&self) -> String {
        format!("VPN \"{}\"", self.label)
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldView {
    label: String,
    secret: bool,
    value: String,
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum PromptEvent {
    #[serde(rename_all = "camelCase")]
    Fields {
        prompt_id: u64,
        vpn: String,
        title: String,
        message: String,
        fields: Vec<FieldView>,
    },
    #[serde(rename_all = "camelCase")]
    Certificate {
        prompt_id: u64,
        vpn: String,
        host: String,
        reason: String,
        fingerprint: String,
    },
    /// Sign in on a web page (opened in the browser); answering it means "cancel".
    #[serde(rename_all = "camelCase")]
    Browser {
        prompt_id: u64,
        vpn: String,
        title: String,
        url: String,
        /// Why the browser didn't open by itself, if it didn't.
        error: Option<String>,
    },
}

/// Asks the UI (`vpn-prompt` event) and waits for `vpn_prompt_answer`.
struct UiPrompter<'a> {
    app: AppHandle,
    label: String,
    prompts: Arc<Mutex<HashMap<u64, oneshot::Sender<Answers>>>>,
    next: &'a AtomicU64,
}

/// A prompt on screen. If the connect stops waiting before anyone answers (the server finished
/// a web sign-in, the connect failed, the wait timed out), it is taken off the screen
/// (`vpn-prompt-closed`).
struct OnScreen<'a> {
    app: &'a AppHandle,
    prompts: &'a Mutex<HashMap<u64, oneshot::Sender<Answers>>>,
    id: u64,
}

impl Drop for OnScreen<'_> {
    fn drop(&mut self) {
        // Answers take the entry out first; still there means nobody answered.
        if lock(self.prompts).remove(&self.id).is_some() {
            let _ = self.app.emit("vpn-prompt-closed", self.id);
        }
    }
}

impl UiPrompter<'_> {
    /// Shows a prompt and waits for its answer, up to `timeout` (`None`: as long as the caller
    /// waits).
    async fn request(
        &self,
        event: impl FnOnce(u64) -> PromptEvent,
        timeout: Option<Duration>,
    ) -> Answers {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.prompts).insert(id, tx);
        let _on_screen = OnScreen {
            app: &self.app,
            prompts: &self.prompts,
            id,
        };
        if self.app.emit("vpn-prompt", event(id)).is_err() {
            return None;
        }
        match timeout {
            Some(t) => tokio::time::timeout(t, rx)
                .await
                .ok()
                .and_then(Result::ok)
                .flatten(),
            None => rx.await.ok().flatten(),
        }
    }
}

impl Prompter for UiPrompter<'_> {
    fn ask(
        &self,
        title: String,
        message: String,
        fields: Vec<PromptField>,
    ) -> BoxFuture<'_, Answers> {
        Box::pin(self.request(
            move |prompt_id| {
                PromptEvent::Fields {
                    prompt_id,
                    vpn: self.label.clone(),
                    title,
                    message,
                    fields: fields
                        .into_iter()
                        .map(|f| FieldView {
                            label: f.label,
                            secret: f.secret,
                            value: f.value,
                        })
                        .collect(),
                }
            },
            Some(PROMPT_TIMEOUT),
        ))
    }

    fn trust_certificate(
        &self,
        host: String,
        reason: String,
        fingerprint: String,
    ) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            self.request(
                move |prompt_id| PromptEvent::Certificate {
                    prompt_id,
                    vpn: self.label.clone(),
                    host,
                    reason,
                    fingerprint,
                },
                Some(PROMPT_TIMEOUT),
            )
            .await
            .is_some()
        })
    }

    fn web_sign_in(&self, title: String, url: String) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let error = crate::util::open_in_browser(&self.app, &url).err();
            // No timeout of our own: the server says how long a sign-in may take, and the
            // connect drops this (closing the dialog) once it stops waiting.
            self.request(
                move |prompt_id| PromptEvent::Browser {
                    prompt_id,
                    vpn: self.label.clone(),
                    title,
                    url,
                    error,
                },
                None,
            )
            .await;
        })
    }
}

fn helper_command() -> Result<Vec<String>, VpnError> {
    let exe = std::env::current_exe()?;
    Ok(vec![exe.display().to_string(), OC_HELPER_ARG.into()])
}

fn opt(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Into::into)
}

async fn start(kind: &VpnKind, label: &str, prompter: &dyn Prompter) -> Result<Tunnel, VpnError> {
    match kind {
        VpnKind::Wireguard { config } => mg_vpn::wireguard::start(WgConfig::parse(config)?).await,
        VpnKind::Openvpn {
            config,
            username,
            password,
        } => {
            let cfg = mg_vpn::openvpn::Config::parse(config)?;
            let saved = (username.is_some() || password.is_some()).then(|| Credentials {
                username: username.clone().unwrap_or_default(),
                password: Zeroizing::new(password.clone().unwrap_or_default()),
            });
            mg_vpn::openvpn::start(cfg, saved, prompter, label).await
        }
        VpnKind::Openconnect {
            server,
            protocol,
            username,
            password,
            authgroup,
            server_cert,
        } => {
            let cfg = OcConfig {
                server: server.clone(),
                protocol: protocol.clone(),
                username: opt(username),
                password: opt(password).map(Zeroizing::new),
                authgroup: opt(authgroup),
                server_cert: opt(server_cert),
                helper: helper_command()?,
                program: None,
            };
            mg_vpn::openconnect::start(cfg, prompter, label).await
        }
    }
}

/// Remembers an openconnect server certificate the user chose to trust.
fn pin_certificate(vault: &VaultState, id: &str, pin: &str) -> Result<(), String> {
    let mut v = vault.guard()?;
    let item = v.item(id).map_err(|e| e.to_string())?;
    if let ItemData::Vpn(mut p) = item.data
        && let VpnKind::Openconnect { server_cert, .. } = &mut p.vpn
    {
        *server_cert = Some(pin.to_owned());
        v.upsert(Some(id), ItemData::Vpn(p))
            .map_err(|e| e.to_string())?;
        drop(v);
        vault.changed();
    }
    Ok(())
}

impl VpnManager {
    fn running(&self, id: &str) -> Option<Arc<Tunnel>> {
        lock(&self.tunnels)
            .get(id)
            .and_then(Weak::upgrade)
            .filter(|t| t.is_alive())
    }

    async fn tunnel(
        &self,
        app: &AppHandle,
        vault: &VaultState,
        vpn: &VpnRef,
    ) -> Result<Arc<Tunnel>, String> {
        if let Some(t) = self.running(&vpn.id) {
            return Ok(t);
        }
        let gate = lock(&self.starting)
            .entry(vpn.id.clone())
            .or_default()
            .clone();
        let _one_at_a_time = gate.lock().await;
        if let Some(t) = self.running(&vpn.id) {
            return Ok(t);
        }
        let prompter = UiPrompter {
            app: app.clone(),
            label: vpn.label.clone(),
            prompts: self.prompts.clone(),
            next: &self.next_prompt,
        };
        let tunnel = start(&vpn.kind, &vpn.label, &prompter)
            .await
            .map_err(|e| format!("VPN \"{}\": {e}", vpn.label))?;
        if let Some(pin) = &tunnel.info().accepted_server_cert
            && let Err(e) = pin_certificate(vault, &vpn.id, pin)
        {
            tracing::warn!(%e, "could not save the VPN server certificate");
        }
        let tunnel = Arc::new(tunnel);
        lock(&self.tunnels).insert(vpn.id.clone(), Arc::downgrade(&tunnel));
        Ok(tunnel)
    }

    pub(crate) async fn dialer(
        &self,
        app: &AppHandle,
        vault: &VaultState,
        vpn: VpnRef,
    ) -> Result<Arc<dyn Dialer>, String> {
        let tunnel = self.tunnel(app, vault, &vpn).await?;
        Ok(Arc::new(VpnDialer {
            tunnel,
            label: vpn.label,
        }))
    }

    /// New connections start a fresh tunnel (after an edit); existing ones keep theirs.
    fn forget(&self, id: &str) {
        lock(&self.tunnels).remove(id);
    }

    /// Lock: cut every tunnel now.
    pub(crate) async fn shutdown_all(&self) {
        let tunnels: Vec<_> = lock(&self.tunnels).drain().collect();
        for (_, t) in tunnels {
            if let Some(t) = t.upgrade() {
                t.shutdown();
            }
        }
        for (_, waiting) in lock(&self.prompts).drain() {
            let _ = waiting.send(None);
        }
    }
}

#[derive(Serialize)]
pub struct Fact {
    label: &'static str,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnView {
    id: String,
    vault_id: String,
    label: String,
    kind: &'static str,
    /// Where it connects to, for lists.
    server: String,
    /// Read-only details for the panel.
    facts: Vec<Fact>,
    /// WireGuard: this device's public key, which the VPN admin needs to add the peer.
    public_key: Option<String>,
    username: Option<String>,
    has_password: bool,
    protocol: Option<String>,
    authgroup: Option<String>,
    server_cert: Option<String>,
    active: bool,
    /// While connected: this device's address(es) inside the VPN.
    address: Option<String>,
    /// Set if the profile can't be used as stored (or openconnect is missing).
    problem: Option<String>,
    updated_at: i64,
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn fact(label: &'static str, value: impl Into<String>) -> Fact {
    Fact {
        label,
        value: value.into(),
    }
}

fn view(
    id: String,
    vault_id: String,
    updated_at: i64,
    p: &VpnProfile,
    running: Option<&Tunnel>,
) -> VpnView {
    let mut v = VpnView {
        id,
        vault_id,
        label: p.label.clone(),
        kind: "wireguard",
        server: String::new(),
        facts: vec![],
        public_key: None,
        username: None,
        has_password: false,
        protocol: None,
        authgroup: None,
        server_cert: None,
        active: running.is_some(),
        address: running.map(|t| join(&t.info().addresses)),
        problem: None,
        updated_at,
    };
    match &p.vpn {
        VpnKind::Wireguard { config } => match WgConfig::parse(config) {
            Ok(c) => {
                let endpoints = c.endpoints();
                v.server = endpoints
                    .first()
                    .map(|e| (*e).to_owned())
                    .unwrap_or_default();
                v.public_key = Some(mg_vpn::wireguard::public_key(&c.private_key));
                v.facts = vec![
                    fact(
                        if endpoints.len() > 1 {
                            "Endpoints"
                        } else {
                            "Endpoint"
                        },
                        endpoints.join(", "),
                    ),
                    fact("Address", join(&c.addresses)),
                    fact("Routes", join(&c.allowed_ips())),
                ];
                if c.peers.len() > 1 {
                    v.facts.push(fact("Peers", c.peers.len().to_string()));
                }
                if !c.dns.is_empty() {
                    v.facts.push(fact("DNS", join(&c.dns)));
                }
            }
            Err(e) => v.problem = Some(e.to_string()),
        },
        VpnKind::Openvpn {
            config,
            username,
            password,
        } => {
            v.kind = "openvpn";
            v.username = username.clone();
            v.has_password = password.is_some();
            match mg_vpn::openvpn::Config::parse(config) {
                Ok(c) => {
                    v.server = c
                        .remotes
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_default();
                    v.facts = vec![
                        fact(
                            if c.remotes.len() > 1 {
                                "Servers"
                            } else {
                                "Server"
                            },
                            join(&c.remotes),
                        ),
                        fact("Sign-in", c.auth_summary()),
                        fact(
                            "Ciphers",
                            c.data_ciphers
                                .iter()
                                .map(|c| c.name())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                    ];
                    if let Some(w) = &c.tls_wrap {
                        v.facts.push(fact("Control channel", w.name()));
                    }
                    if c.pkcs12.is_some() {
                        v.facts.push(fact("Certificate", "PKCS#12 bundle"));
                    }
                    if c.needs_passphrase() {
                        v.facts.push(fact(
                            "Key passphrase",
                            match (&c.askpass, &c.pkcs12) {
                                (Some(_), _) => "in the profile (askpass)",
                                (None, Some(_)) => "asked when connecting, if the bundle has one",
                                (None, None) => "asked when connecting",
                            },
                        ));
                    }
                    if let Some(ch) = &c.static_challenge {
                        v.facts.push(fact("One-time code", ch.text.clone()));
                    }
                }
                Err(e) => v.problem = Some(e.to_string()),
            }
        }
        VpnKind::Openconnect {
            server,
            protocol,
            username,
            password,
            authgroup,
            server_cert,
        } => {
            v.kind = "openconnect";
            v.server = server.clone();
            v.username = username.clone();
            v.has_password = password.is_some();
            v.protocol = Some(protocol.clone());
            v.authgroup = authgroup.clone();
            v.server_cert = server_cert.clone();
            let name = PROTOCOLS
                .iter()
                .find(|(p, _)| p == protocol)
                .map_or(protocol.as_str(), |(_, n)| n);
            v.facts = vec![fact("Server", server.clone()), fact("Protocol", name)];
            if let Some(g) = authgroup {
                v.facts.push(fact("Group", g.clone()));
            }
            v.facts.push(fact(
                "Certificate",
                match server_cert {
                    Some(pin) => format!("pinned ({pin})"),
                    None => "trusted by the system".into(),
                },
            ));
            if let Some(why) = mg_vpn::openconnect::unavailable() {
                v.problem = Some(why.into());
            }
        }
    }
    if let Some(t) = running {
        let info = t.info();
        if !info.routes.is_empty() {
            v.facts.push(fact("Networks", join(&info.routes)));
        }
        if !info.dns.is_empty() {
            v.facts.push(fact("VPN DNS", join(&info.dns)));
        }
    }
    v
}

#[tauri::command]
pub async fn vpns_list(
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
) -> Result<Vec<VpnView>, String> {
    let profiles: Vec<(String, String, i64, VpnProfile)> = vault
        .guard()?
        .items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::Vpn(p) => Some((i.id, i.vault_id, i.updated_at, p)),
            _ => None,
        })
        .collect();
    let mut out: Vec<VpnView> = profiles
        .into_iter()
        .map(|(id, vault_id, updated_at, p)| {
            let running = vpns.running(&id);
            view(id, vault_id, updated_at, &p, running.as_deref())
        })
        .collect();
    out.sort_by_key(|v| v.label.to_lowercase());
    Ok(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnInput {
    id: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    kind: String,
    label: String,
    /// Pasted WireGuard config or `.ovpn` profile. When editing, empty keeps the stored one.
    config: Option<String>,
    /// Or a path to the file (an `.ovpn`'s referenced files are embedded).
    config_path: Option<String>,
    /// With a picked `.ovpn` (as `config`): the files it refers to, picked along with it.
    #[serde(default)]
    config_files: Vec<PickedFile>,
    server: Option<String>,
    protocol: Option<String>,
    authgroup: Option<String>,
    username: Option<String>,
    /// `None` keeps the saved password, `""` removes it.
    password: Option<String>,
    #[serde(default)]
    forget_server_cert: bool,
}

/// A file picked in the page: its name and its bytes, base64.
#[derive(Deserialize)]
pub struct PickedFile {
    name: String,
    data: String,
}

fn read_file(path: &str) -> Result<(String, std::path::PathBuf), String> {
    let path = expand_home(path.trim());
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((text, path))
}

fn host_of(server: &str) -> &str {
    let s = server
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    s.split(['/', ':']).next().unwrap_or(s)
}

fn build(input: &VpnInput, existing: Option<VpnKind>) -> Result<(String, VpnKind), String> {
    let pasted = opt(&input.config);
    let path = opt(&input.config_path);
    let password = |old: Option<String>| match &input.password {
        None => old,
        Some(p) if p.is_empty() => None,
        Some(p) => Some(p.clone()),
    };
    let label = input.label.trim();
    match input.kind.as_str() {
        "wireguard" => {
            let config = match (pasted, path, existing) {
                (Some(text), _, _) => text,
                (None, Some(p), _) => read_file(&p)?.0,
                (None, None, Some(VpnKind::Wireguard { config })) => config,
                _ => return Err("Paste a WireGuard configuration or choose a .conf file.".into()),
            };
            let parsed = WgConfig::parse(&config).map_err(|e| e.to_string())?;
            let label = match label {
                "" => format!(
                    "WireGuard {}",
                    host_of(parsed.endpoints().first().copied().unwrap_or_default())
                ),
                l => l.to_owned(),
            };
            Ok((label, VpnKind::Wireguard { config }))
        }
        "openvpn" => {
            let old_password = match &existing {
                Some(VpnKind::Openvpn { password, .. }) => password.clone(),
                _ => None,
            };
            let config = match (pasted, path, existing) {
                // Files the profile refers to come from those picked along with it, by name.
                (Some(text), _, _) => {
                    let picked: HashMap<&str, &str> = input
                        .config_files
                        .iter()
                        .map(|f| (f.name.as_str(), f.data.as_str()))
                        .collect();
                    mg_vpn::openvpn::inline_files_with(&text, |file| {
                        let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
                        let data = picked.get(name).ok_or_else(|| {
                            if picked.is_empty() {
                                format!("the profile refers to {name}: choose the .ovpn file and {name} together, or paste a profile with it inline")
                            } else {
                                format!("the profile refers to {name}: choose it along with the profile")
                            }
                        })?;
                        base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            data.trim(),
                        )
                        .map_err(|_| format!("{name} couldn't be read"))
                    })
                    .map_err(|e| e.to_string())?
                }
                (None, Some(p), _) => {
                    let (text, path) = read_file(&p)?;
                    let dir = path.parent().unwrap_or(std::path::Path::new("."));
                    mg_vpn::openvpn::inline_files(&text, dir).map_err(|e| e.to_string())?
                }
                (None, None, Some(VpnKind::Openvpn { config, .. })) => config,
                _ => return Err("Paste an .ovpn profile or choose the .ovpn file.".into()),
            };
            let parsed = mg_vpn::openvpn::Config::parse(&config).map_err(|e| e.to_string())?;
            let label = match label {
                "" => format!("OpenVPN {}", parsed.remotes[0].host),
                l => l.to_owned(),
            };
            Ok((
                label,
                VpnKind::Openvpn {
                    config,
                    username: opt(&input.username),
                    password: password(old_password),
                },
            ))
        }
        "openconnect" => {
            let server = opt(&input.server).ok_or("Enter the VPN server's address.")?;
            let protocol = opt(&input.protocol).unwrap_or_else(|| "anyconnect".into());
            if !PROTOCOLS.iter().any(|(p, _)| *p == protocol) {
                return Err(format!("unknown openconnect protocol \"{protocol}\""));
            }
            let (old_password, old_cert) = match existing {
                Some(VpnKind::Openconnect {
                    server: old_server,
                    password,
                    server_cert,
                    ..
                }) => (
                    password,
                    // A pin belongs to the server it was accepted for.
                    server_cert.filter(|_| old_server == server && !input.forget_server_cert),
                ),
                _ => (None, None),
            };
            let label = match label {
                "" => host_of(&server).to_owned(),
                l => l.to_owned(),
            };
            Ok((
                label,
                VpnKind::Openconnect {
                    server,
                    protocol,
                    username: opt(&input.username),
                    password: password(old_password),
                    authgroup: opt(&input.authgroup),
                    server_cert: old_cert,
                },
            ))
        }
        other => Err(format!("unknown VPN type \"{other}\"")),
    }
}

fn kind_name(k: &VpnKind) -> &'static str {
    match k {
        VpnKind::Wireguard { .. } => "wireguard",
        VpnKind::Openvpn { .. } => "openvpn",
        VpnKind::Openconnect { .. } => "openconnect",
    }
}

#[tauri::command]
pub async fn vpn_save(
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
    input: VpnInput,
) -> Result<VpnView, String> {
    let existing = match &input.id {
        Some(id) => match vault.guard()?.item(id).map_err(|e| e.to_string())?.data {
            ItemData::Vpn(p) => Some(p.vpn),
            _ => return Err("not a VPN profile".into()),
        },
        None => None,
    };
    if let Some(old) = &existing
        && kind_name(old) != input.kind
    {
        return Err("A VPN's type can't change; create a new VPN instead.".into());
    }
    let (label, vpn) = build(&input, existing)?;
    let Item {
        id,
        vault_id,
        updated_at,
        data,
    } = crate::vault::save(
        &mut *vault.guard()?,
        input.id.as_deref(),
        input.vault_id.as_deref(),
        ItemData::Vpn(VpnProfile { label, vpn }),
    )
    .map_err(|e| e.to_string())?;
    vault.changed();
    vpns.forget(&id);
    match data {
        ItemData::Vpn(p) => Ok(view(id, vault_id, updated_at, &p, None)),
        _ => unreachable!("upsert returns the data it was given"),
    }
}

#[tauri::command]
pub async fn vpn_delete(
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
    id: String,
) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(|e| e.to_string())?;
    vault.changed();
    vpns.forget(&id);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnTest {
    server: String,
    address: String,
    millis: u64,
}

/// Connects (handshake, sign-in, address assigned) to prove the profile works. The tunnel is
/// kept for hosts that use it; it stops when nothing does.
#[tauri::command]
pub async fn vpn_test(
    app: AppHandle,
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
    id: String,
) -> Result<VpnTest, String> {
    let vpn = match vault.guard()?.item(&id).map_err(|e| e.to_string())?.data {
        ItemData::Vpn(VpnProfile { label, vpn }) => VpnRef {
            id: id.clone(),
            label,
            kind: vpn,
        },
        _ => return Err("not a VPN profile".into()),
    };
    let started = Instant::now();
    let tunnel = vpns.tunnel(&app, &vault, &vpn).await?;
    Ok(VpnTest {
        server: tunnel.info().server.clone(),
        address: join(&tunnel.info().addresses),
        millis: started.elapsed().as_millis() as u64,
    })
}

#[tauri::command]
pub async fn vpn_prompt_answer(
    vpns: State<'_, VpnManager>,
    prompt_id: u64,
    answers: Option<Vec<String>>,
) -> Result<(), String> {
    if let Some(tx) = lock(&vpns.prompts).remove(&prompt_id) {
        let _ = tx.send(answers);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: &str) -> VpnInput {
        VpnInput {
            id: None,
            vault_id: None,
            kind: kind.into(),
            label: String::new(),
            config: None,
            config_path: None,
            config_files: Vec::new(),
            server: None,
            protocol: None,
            authgroup: None,
            username: None,
            password: None,
            forget_server_cert: false,
        }
    }

    #[test]
    fn openconnect_profiles_keep_pins_and_passwords_sensibly() {
        let mut i = input("openconnect");
        i.server = Some("https://vpn.example.com/eng".into());
        i.username = Some(" alice ".into());
        i.password = Some("pw".into());
        let (label, kind) = build(&i, None).unwrap();
        assert_eq!(label, "vpn.example.com");
        let VpnKind::Openconnect {
            protocol,
            username,
            password,
            server_cert,
            ..
        } = &kind
        else {
            panic!()
        };
        assert_eq!(
            (protocol.as_str(), username.as_deref()),
            ("anyconnect", Some("alice"))
        );
        assert_eq!(password.as_deref(), Some("pw"));
        assert!(server_cert.is_none());

        // Pinned later; an edit without a password keeps both.
        let pinned = match kind {
            VpnKind::Openconnect {
                server,
                protocol,
                username,
                password,
                authgroup,
                ..
            } => VpnKind::Openconnect {
                server,
                protocol,
                username,
                password,
                authgroup,
                server_cert: Some("pin-sha256:x".into()),
            },
            _ => unreachable!(),
        };
        i.password = None;
        let (_, kept) = build(&i, Some(pinned.clone())).unwrap();
        assert!(matches!(
            &kept,
            VpnKind::Openconnect {
                password: Some(_),
                server_cert: Some(_),
                ..
            }
        ));
        // Another server: the pin goes. An empty password clears it.
        i.server = Some("other.example.com".into());
        i.password = Some(String::new());
        let (_, moved) = build(&i, Some(pinned)).unwrap();
        assert!(matches!(
            &moved,
            VpnKind::Openconnect {
                password: None,
                server_cert: None,
                ..
            }
        ));

        i.protocol = Some("pptp".into());
        assert!(build(&i, None).is_err());
    }

    #[test]
    fn openvpn_from_a_file_embeds_what_it_references() {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        std::fs::write(
            dir.path().join("ca.crt"),
            params.self_signed(&key).unwrap().pem(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("client.ovpn"),
            "client\nremote vpn.example.com 1194\nca ca.crt\nauth-user-pass\n",
        )
        .unwrap();
        let mut i = input("openvpn");
        i.config_path = Some(dir.path().join("client.ovpn").display().to_string());
        i.username = Some("alice".into());
        let (label, kind) = build(&i, None).unwrap();
        assert_eq!(label, "OpenVPN vpn.example.com");
        let VpnKind::Openvpn {
            config,
            username,
            password,
        } = &kind
        else {
            panic!()
        };
        assert!(config.contains("<ca>"));
        assert_eq!(username.as_deref(), Some("alice"));
        assert!(password.is_none());

        // Pasted text that points at files explains what to do instead.
        let mut p = input("openvpn");
        p.config = Some("client\nremote x\nca ca.crt\n".into());
        assert!(
            build(&p, None)
                .unwrap_err()
                .contains("refers to ca.crt: choose the .ovpn file and ca.crt together")
        );

        // Picked along with the profile, by name (wherever the profile says it is).
        let ca = std::fs::read(dir.path().join("ca.crt")).unwrap();
        let mut picked = input("openvpn");
        picked.config = Some("client\nremote vpn.example.com 1194\nca keys/ca.crt\n".into());
        picked.config_files = vec![PickedFile {
            name: "ca.crt".into(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ca),
        }];
        let (_, VpnKind::Openvpn { config, .. }) = build(&picked, None).unwrap() else {
            panic!()
        };
        assert!(config.contains("<ca>\n-----BEGIN CERTIFICATE-----"));
        picked.config_files[0].name = "other.crt".into();
        assert!(
            build(&picked, None)
                .unwrap_err()
                .contains("refers to ca.crt: choose it along with the profile")
        );
    }
}
