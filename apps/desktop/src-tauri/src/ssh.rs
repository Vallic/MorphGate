use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mg_ssh::{
    Auth, ConnectOptions, Hop, HostKeyInfo, HostKeyPrompt, KnownHosts, Session, SessionEvent,
    TermSize, Tunnel,
};
use mg_store::{Host, HostAuth, Item, ItemData, LocalVault, SshKey, VpnKind, VpnProfile};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{Mutex, oneshot};
use zeroize::Zeroizing;

use crate::session_log::{Recorder, SharedRecorder};
use crate::vault::VaultState;

const HOSTKEY_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

pub struct SshState {
    sessions: Mutex<HashMap<u64, Arc<Session>>>,
    prompts: Arc<Mutex<HashMap<u64, oneshot::Sender<bool>>>>,
    pub(crate) known_hosts: Arc<KnownHosts>,
    next_id: AtomicU64,
    /// Running port forwards, keyed by their vault item id.
    pub(crate) tunnels: Mutex<HashMap<String, Tunnel>>,
    /// Sessions being recorded (hosts with `record_sessions`), by session id.
    recorders: Mutex<HashMap<u64, SharedRecorder>>,
}

impl SshState {
    pub fn new(data_dir: PathBuf) -> Self {
        let mut kh = KnownHosts::new(data_dir.join("known_hosts"));
        if let Some(openssh) = KnownHosts::openssh_default() {
            kh = kh.with_read_only(openssh);
        }
        Self {
            sessions: Mutex::default(),
            prompts: Arc::default(),
            known_hosts: Arc::new(kh),
            next_id: AtomicU64::new(1),
            tunnels: Mutex::default(),
            recorders: Mutex::default(),
        }
    }

    fn id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Host-key prompt that asks the UI (`hostkey-prompt` event).
    pub(crate) fn prompt(&self, app: AppHandle) -> Arc<dyn HostKeyPrompt> {
        Arc::new(UiPrompt {
            app,
            prompts: self.prompts.clone(),
            prompt_id: self.id(),
        })
    }

    pub(crate) async fn stop_all_tunnels(&self) {
        let tunnels: Vec<Tunnel> = self.tunnels.lock().await.drain().map(|(_, t)| t).collect();
        for t in tunnels {
            t.stop().await;
        }
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum AuthRequest {
    Password {
        password: String,
    },
    /// A key the person chose or pasted (OpenSSH, PEM or PuTTY), for this connection only.
    Key {
        private_key: String,
        passphrase: Option<String>,
    },
    Agent,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum Target {
    /// Quick connect: everything comes from the form.
    Adhoc {
        host: String,
        port: u16,
        user: String,
        auth: AuthRequest,
    },
    /// A vault host; `password` is only needed when none is saved. `tmux` names the tab's
    /// session on the server, for hosts that keep theirs.
    Saved {
        host_id: String,
        password: Option<String>,
        #[serde(default)]
        tmux: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequest {
    target: Target,
    size: TermSize,
}

/// The VPN the first hop is dialed through.
pub(crate) struct VpnRef {
    pub id: String,
    pub label: String,
    pub kind: VpnKind,
}

pub(crate) struct Resolved {
    pub target: Hop,
    pub jumps: Vec<Hop>,
    pub vpn: Option<VpnRef>,
    /// The first hop's proxy command, allowed on this device (see proxy.rs).
    pub proxy: Option<mg_ssh::ProxyCommand>,
}

/// The first hop's connection: through its proxy command, its VPN (a host has one or neither),
/// or the network (`None`).
pub(crate) async fn first_hop(
    app: &AppHandle,
    vault: &VaultState,
    vpns: &crate::vpn::VpnManager,
    vpn: Option<VpnRef>,
    proxy: Option<mg_ssh::ProxyCommand>,
) -> Result<Option<Arc<dyn mg_ssh::Dialer>>, String> {
    if let Some(proxy) = proxy {
        return Ok(Some(Arc::new(proxy)));
    }
    match vpn {
        Some(v) => Ok(Some(vpns.dialer(app, vault, v).await?)),
        None => Ok(None),
    }
}

/// Turns a connect request into the target, its jump hosts (nearest first) and the VPN the
/// first hop needs, reading secrets from the vault for saved hosts.
pub(crate) fn resolve(target: Target, vault: &VaultState) -> Result<Resolved, String> {
    match target {
        Target::Adhoc {
            host,
            port,
            user,
            auth,
        } => {
            let auth = match auth {
                AuthRequest::Password { password } => Auth::Password(Zeroizing::new(password)),
                AuthRequest::Key {
                    private_key,
                    passphrase,
                } => Auth::Key {
                    private_key: Zeroizing::new(private_key),
                    passphrase: passphrase.filter(|p| !p.is_empty()).map(Zeroizing::new),
                    certificate: None,
                },
                AuthRequest::Agent => Auth::Agent {
                    source: mg_ssh::AgentSource::System,
                    fingerprint: None,
                },
            };
            Ok(Resolved {
                target: Hop {
                    host,
                    port,
                    user,
                    auth,
                    via_command: None,
                    listed_keys: None,
                },
                jumps: Vec::new(),
                vpn: None,
                proxy: None,
            })
        }
        Target::Saved {
            host_id, password, ..
        } => {
            let v = vault.guard()?;
            let (jumps, target) = v.route(&host_id).map_err(|e| e.to_string())?;
            let first = jumps.first().unwrap_or(&target);
            let vpn = match &first.data {
                ItemData::Host(Host {
                    vpn_ref: Some(id), ..
                }) => match v.item(id).map_err(|e| e.to_string())?.data {
                    ItemData::Vpn(VpnProfile { label, vpn }) => Some(VpnRef {
                        id: id.clone(),
                        label,
                        kind: vpn,
                    }),
                    _ => return Err("the host's VPN profile is missing from the vault".into()),
                },
                _ => None,
            };
            // Reached through its cloud: the command is built here (cloud.rs), not taken from the
            // vault, so it needs no allowing.
            let cloud = match &first.data {
                ItemData::Host(Host {
                    source: Some(source),
                    label,
                    ..
                }) if source.reach.is_some() => {
                    if cfg!(mobile) {
                        return Err(format!(
                            "\"{label}\" connects through its cloud's CLI on the computer: connect to it from the desktop app"
                        ));
                    }
                    crate::cloud::reach_command(&v, source)
                        .map_err(|e| format!("\"{label}\": {e}"))?
                }
                _ => None,
            };
            let proxy = match &first.data {
                _ if cloud.is_some() => cloud,
                ItemData::Host(Host {
                    proxy_command: Some(command),
                    label,
                    ..
                }) => {
                    if cfg!(mobile) {
                        return Err(format!(
                            "\"{label}\" connects through a command run on the computer: connect to it from the desktop app"
                        ));
                    }
                    if !crate::proxy::allowed(&v, command) {
                        return Err(format!(
                            "\"{label}\" connects by running a command on this computer, which this device hasn't allowed: {command}. Open the host to allow it."
                        ));
                    }
                    Some(command.clone())
                }
                _ => None,
            };
            let jumps = jumps
                .into_iter()
                .map(|item| saved_hop(&v, item, None, true))
                .collect::<Result<Vec<_>, _>>()?;
            let target = saved_hop(&v, target, password, false)?;
            let proxy = proxy.map(|command| {
                mg_ssh::ProxyCommand::new(command, jumps.first().unwrap_or(&target).user.clone())
            });
            Ok(Resolved {
                target,
                jumps,
                vpn,
                proxy,
            })
        }
    }
}

/// `prompted` is a password typed for this connection only; jump hosts need theirs saved.
fn saved_hop(
    v: &LocalVault,
    item: Item,
    prompted: Option<String>,
    is_jump: bool,
) -> Result<Hop, String> {
    let ItemData::Host(host) = item.data else {
        return Err("not a host".into());
    };
    let auth = match host.auth {
        HostAuth::Password { password: saved } => {
            match prompted.filter(|p| !p.is_empty()).or(saved) {
                Some(p) => Auth::Password(Zeroizing::new(p)),
                None if is_jump => {
                    return Err(format!(
                        "jump host \"{}\" has no saved password; save one or switch it to a key",
                        host.label
                    ));
                }
                None => return Err("password required".into()),
            }
        }
        HostAuth::Key { key_ref } => match v.item(&key_ref).map_err(|e| e.to_string())?.data {
            ItemData::SshKey(SshKey {
                private_key,
                passphrase,
                certificate,
                ..
            }) => Auth::Key {
                private_key: Zeroizing::new(private_key),
                passphrase: passphrase.map(Zeroizing::new),
                certificate,
            },
            _ => {
                return Err(format!(
                    "the SSH key of \"{}\" is missing from the vault",
                    host.label
                ));
            }
        },
        HostAuth::Agent { agent, path, key } => Auth::Agent {
            source: crate::agents::source(agent.as_deref(), path.as_deref())
                .map_err(|e| format!("{}: {e}", host.label))?,
            fingerprint: key,
        },
    };
    // The host keys its feed lists: they decide, instead of what this device pinned.
    let listed_keys = host
        .source
        .as_ref()
        .filter(|s| !s.host_keys.is_empty())
        .map(|s| mg_ssh::ListedKeys {
            keys: s.host_keys.clone(),
            from: match v.item(&s.source_ref).map(|i| i.data) {
                Ok(ItemData::CloudSource(c)) => c.label,
                _ => "its feed".into(),
            },
        });
    Ok(Hop {
        host: host.hostname,
        port: host.port,
        user: host.user,
        auth,
        via_command: host.jump_command,
        listed_keys,
    })
}

/// Lifecycle events on the status channel; terminal bytes go on the raw output channel.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum StatusEvent {
    Exit {
        status: u32,
    },
    Closed,
    /// The session is recorded into this `session_log` item.
    #[serde(rename_all = "camelCase")]
    Recording {
        log_id: String,
    },
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyPromptEvent {
    prompt_id: u64,
    #[serde(flatten)]
    info: HostKeyInfo,
}

/// Emits `hostkey-prompt` to the UI and waits for `hostkey_answer`.
struct UiPrompt {
    app: AppHandle,
    prompts: Arc<Mutex<HashMap<u64, oneshot::Sender<bool>>>>,
    prompt_id: u64,
}

impl HostKeyPrompt for UiPrompt {
    fn confirm(&self, info: HostKeyInfo) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let (app, prompts, prompt_id) = (self.app.clone(), self.prompts.clone(), self.prompt_id);
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            prompts.lock().await.insert(prompt_id, tx);
            if app
                .emit("hostkey-prompt", HostKeyPromptEvent { prompt_id, info })
                .is_err()
            {
                prompts.lock().await.remove(&prompt_id);
                return false;
            }
            let accepted = matches!(
                tokio::time::timeout(HOSTKEY_PROMPT_TIMEOUT, rx).await,
                Ok(Ok(true))
            );
            prompts.lock().await.remove(&prompt_id);
            accepted
        })
    }

    fn security_key(&self, host: &str, key: Option<&mg_ssh::AgentKey>) {
        let _ = self.app.emit(
            "security-key",
            SecurityKeyEvent {
                host: host.to_owned(),
                key: key.cloned(),
            },
        );
    }
}

/// A security key waits for a touch to sign in to `host`; `key: None` once it's done.
#[derive(Clone, Serialize)]
struct SecurityKeyEvent {
    host: String,
    key: Option<mg_ssh::AgentKey>,
}

/// What the UI shows when a host answers with a different key than the one pinned.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangedKey {
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
    pinned_algorithm: Option<String>,
    pinned_fingerprint: Option<String>,
    /// The known_hosts file and line holding the pinned key.
    file: Option<String>,
    line: Option<usize>,
}

/// A failed connection's message. A changed host key (also behind a jump host) is first sent to
/// the UI as `hostkey-changed`, so it can show the pinned and the presented key side by side.
pub(crate) fn connect_error(app: &AppHandle, e: mg_ssh::Error) -> String {
    let mut cause = &e;
    while let mg_ssh::Error::Jump { source, .. } = cause {
        cause = source;
    }
    if let mg_ssh::Error::HostKeyChanged(info) = cause {
        let (pinned_algorithm, pinned_fingerprint) = info.pinned.clone().unzip();
        let (file, line) = info.changed_in.clone().unzip();
        let _ = app.emit(
            "hostkey-changed",
            ChangedKey {
                host: info.host.clone(),
                port: info.port,
                algorithm: info.algorithm.clone(),
                fingerprint: info.fingerprint.clone(),
                pinned_algorithm,
                pinned_fingerprint,
                file: file.map(|f| crate::util::tilde(&f)),
                line,
            },
        );
    }
    e.to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnedKey {
    algorithm: String,
    fingerprint: String,
}

/// The host key `host:port` is pinned to (known_hosts), once it has connected.
#[tauri::command]
pub fn host_pinned_key(state: State<'_, SshState>, host: String, port: u16) -> Option<PinnedKey> {
    state
        .known_hosts
        .pinned(host.trim(), port)
        .map(|(algorithm, fingerprint)| PinnedKey {
            algorithm,
            fingerprint,
        })
}

/// Attaches to the tab's tmux session (`morphgate`, `morphgate-2`, …), creating it when
/// missing; without tmux on the server, a login shell. Written for any login shell (sh, bash,
/// zsh, fish, tcsh).
fn tmux_command(name: Option<&str>) -> String {
    let name = name
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 64
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .unwrap_or("morphgate");
    format!("tmux new-session -A -s {name} || exec $SHELL -l")
}

#[tauri::command]
pub async fn ssh_connect(
    app: AppHandle,
    state: State<'_, SshState>,
    vault: State<'_, VaultState>,
    vpns: State<'_, crate::vpn::VpnManager>,
    request: ConnectRequest,
    on_output: Channel<InvokeResponseBody>,
    on_status: Channel<StatusEvent>,
) -> Result<u64, String> {
    let saved_host = match &request.target {
        Target::Saved { host_id, .. } => Some(host_id.clone()),
        Target::Adhoc { .. } => None,
    };
    // What the session runs: the host's login command, or for hosts that keep their session a
    // tmux session on the server; some get the agent forwarded (not where the host's cloud
    // forwards nothing, as Vallic Cloud's SSH).
    let (keep, forward_agent) = match &request.target {
        Target::Saved { host_id, tmux, .. } => {
            let route = vault.guard()?.route(host_id).map_err(|e| e.to_string())?;
            match route.1.data {
                ItemData::Host(h) => (
                    h.login_command
                        .or_else(|| h.keep_session.then(|| tmux_command(tmux.as_deref()))),
                    h.forward_agent && !h.source.as_ref().is_some_and(|s| s.no_forwarding),
                ),
                _ => (None, false),
            }
        }
        Target::Adhoc { .. } => (None, false),
    };
    crate::renew::before_connect(&vault, &request.target).await?;
    let Resolved {
        target,
        jumps,
        vpn,
        proxy,
    } = resolve(request.target, &vault)?;
    let dialer = first_hop(&app, &vault, &vpns, vpn, proxy).await?;
    // The agent the host signs in with, or the system's.
    let forward_agent = forward_agent.then(|| match &target.auth {
        Auth::Agent { source, .. } => source.clone(),
        _ => mg_ssh::AgentSource::System,
    });
    let opts = ConnectOptions {
        forward_agent,
        host: target.host.trim().to_owned(),
        port: target.port,
        user: target.user.trim().to_owned(),
        auth: target.auth,
        jumps,
        via_command: target.via_command,
        listed_keys: target.listed_keys,
        dialer,
        term: "xterm-256color".into(),
        size: request.size,
        connect_timeout: Duration::from_secs(15),
    };
    let prompt = state.prompt(app.clone());
    crate::host_cas::trust(&vault, &state.known_hosts);

    let opened = match &keep {
        Some(command) => {
            Session::connect_running(opts, command, state.known_hosts.clone(), prompt).await
        }
        None => Session::connect(opts, state.known_hosts.clone(), prompt).await,
    };
    let (session, mut events) = opened.map_err(|e| connect_error(&app, e))?;

    let id = state.id();
    state.sessions.lock().await.insert(id, Arc::new(session));
    let recorder = saved_host
        .and_then(|h| Recorder::start(&app, &h, request.size.cols, request.size.rows))
        .map(|r| Arc::new(std::sync::Mutex::new(r)));
    if let Some(r) = &recorder {
        state.recorders.lock().await.insert(id, r.clone());
        if let Ok(r) = r.lock() {
            let _ = on_status.send(StatusEvent::Recording {
                log_id: r.item_id().to_owned(),
            });
        }
    }

    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            let sent = match event {
                SessionEvent::Output(bytes) => {
                    if let Some(Ok(mut r)) = recorder.as_ref().map(|r| r.lock()) {
                        r.output(&bytes);
                    }
                    on_output.send(InvokeResponseBody::Raw(bytes))
                }
                SessionEvent::Exit { status } => on_status.send(StatusEvent::Exit { status }),
                SessionEvent::Closed => break,
            };
            if sent.is_err() {
                break;
            }
        }
        if let Some(r) = recorder {
            if let Ok(mut r) = r.lock() {
                r.finish();
            }
            app_handle
                .state::<SshState>()
                .recorders
                .lock()
                .await
                .remove(&id);
        }
        let _ = on_status.send(StatusEvent::Closed);
    });

    Ok(id)
}

async fn session(state: &SshState, id: u64) -> Result<Arc<Session>, String> {
    state
        .sessions
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| "session is closed".into())
}

#[tauri::command]
pub async fn ssh_write(state: State<'_, SshState>, id: u64, data: String) -> Result<(), String> {
    session(&state, id)
        .await?
        .write(data.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_resize(state: State<'_, SshState>, id: u64, size: TermSize) -> Result<(), String> {
    if let Some(r) = state.recorders.lock().await.get(&id)
        && let Ok(mut r) = r.lock()
    {
        r.resize(size.cols, size.rows);
    }
    session(&state, id)
        .await?
        .resize(size)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_disconnect(state: State<'_, SshState>, id: u64) -> Result<(), String> {
    let removed = state.sessions.lock().await.remove(&id);
    if let Some(session) = removed {
        session.close().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn hostkey_answer(
    state: State<'_, SshState>,
    prompt_id: u64,
    accept: bool,
) -> Result<(), String> {
    if let Some(tx) = state.prompts.lock().await.remove(&prompt_id) {
        let _ = tx.send(accept);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host whose proxy command came with the vault doesn't connect until this device allows
    /// the command; once allowed, the first hop is the command.
    #[test]
    fn a_proxy_command_runs_once_this_device_allows_it() {
        let dir = tempfile::tempdir().unwrap();
        let state = VaultState::open(
            &dir.path().join("vault.sqlite3"),
            Arc::new(tokio::sync::Notify::new()),
        )
        .unwrap();
        let id = {
            let mut g = state.guard().unwrap();
            let v = std::mem::replace(&mut *g, LocalVault::open_in_memory().unwrap());
            *g = v.with_kdf_cost(
                mg_vault::KdfParams::MIN_M_KIB,
                mg_vault::KdfParams::MIN_T,
                1,
            );
            g.create("correct horse battery").unwrap();
            let host = Host {
                label: "private-box".into(),
                hostname: "i-0abc123".into(),
                port: 22,
                user: "ec2-user".into(),
                auth: HostAuth::Password {
                    password: Some("pw".into()),
                },
                jump_ref: None,
                vpn_ref: None,
                theme_ref: None,
                record_sessions: false,
                tags: vec![],
                notes: String::new(),
                group_ref: None,
                identity_ref: None,
                keep_session: false,
                forward_agent: false,
                login_command: None,
                jump_command: None,
                proxy_command: Some("aws ssm start-session --target %h".into()),
                source: None,
            };
            // As a sync brings it: saved without going through the editor.
            g.upsert(None, ItemData::Host(host)).unwrap().id
        };
        let target = || Target::Saved {
            host_id: id.clone(),
            password: None,
            tmux: None,
        };
        let Err(e) = resolve(target(), &state) else {
            panic!("connected through a command this device hasn't allowed");
        };
        assert!(
            e.contains("hasn't allowed: aws ssm start-session --target %h"),
            "{e}"
        );
        crate::proxy::allow(&state.guard().unwrap(), "aws ssm start-session --target %h").unwrap();
        let resolved = resolve(target(), &state).unwrap();
        assert!(resolved.proxy.is_some());
    }

    #[test]
    fn tmux_sessions_are_named_safely() {
        assert_eq!(
            tmux_command(None),
            "tmux new-session -A -s morphgate || exec $SHELL -l"
        );
        assert_eq!(
            tmux_command(Some("morphgate-2")),
            "tmux new-session -A -s morphgate-2 || exec $SHELL -l"
        );
        assert_eq!(
            tmux_command(Some("x; rm -rf ~")),
            "tmux new-session -A -s morphgate || exec $SHELL -l"
        );
    }
    use serde_json::json;

    #[test]
    fn connect_request_shapes_match_the_frontend() {
        let saved: ConnectRequest = serde_json::from_value(json!({
            "target": { "kind": "saved", "hostId": "H1", "password": "pw" },
            "size": { "cols": 80, "rows": 24 }
        }))
        .unwrap();
        assert!(matches!(saved.target, Target::Saved { ref host_id, .. } if host_id == "H1"));

        let adhoc: ConnectRequest = serde_json::from_value(json!({
            "target": { "kind": "adhoc", "host": "h", "port": 22, "user": "u",
                        "auth": { "kind": "key", "privateKey": "-----BEGIN…", "passphrase": null } },
            "size": { "cols": 80, "rows": 24 }
        }))
        .unwrap();
        assert!(matches!(
            adhoc.target,
            Target::Adhoc {
                auth: AuthRequest::Key { .. },
                ..
            }
        ));
    }
}
