//! Tauri commands for the local vault. Secrets (passwords, private keys) flow *into* Rust only;
//! the views sent back to the webview never contain them.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use mg_store::{Host, HostAuth, Item, ItemData, LocalVault, Snippet, SshKey, Status};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::util::expand_home;

pub struct VaultState(pub(crate) Arc<Mutex<LocalVault>>, Arc<Notify>);

/// Why the vault file didn't open (then there's no [`VaultState`]): the window says so.
pub struct Unopened(pub String);

impl VaultState {
    /// `changed` is notified after every local edit (and unlock) so sync can run soon.
    pub fn open(path: &Path, changed: Arc<Notify>) -> mg_store::Result<Self> {
        Ok(Self(Arc::new(Mutex::new(LocalVault::open(path)?)), changed))
    }

    pub fn changed(&self) {
        self.1.notify_one();
    }

    pub fn guard(&self) -> Result<MutexGuard<'_, LocalVault>, String> {
        self.0
            .lock()
            .map_err(|_| "vault state is poisoned; restart MorphGate".to_owned())
    }

    /// Argon2id takes ~1 s by design; keep it off the async runtime.
    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut LocalVault) -> mg_store::Result<T> + Send + 'static,
    ) -> Result<T, String> {
        let inner = self.0.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let mut vault = inner
                .lock()
                .map_err(|_| "vault state is poisoned; restart MorphGate".to_owned())?;
            f(&mut vault).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

fn err(e: mg_store::Error) -> String {
    e.to_string()
}

/// Saves into the item's own vault, or a new item into `vault_id` (default: personal).
pub(crate) fn save(
    v: &mut LocalVault,
    id: Option<&str>,
    vault_id: Option<&str>,
    data: ItemData,
) -> mg_store::Result<Item> {
    match (id, vault_id) {
        (None, Some(vault)) => v.upsert_in(vault, None, data),
        _ => v.upsert(id, data),
    }
}

// ---------------------------------------------------------------- lock / unlock

#[tauri::command]
pub fn vault_status(app: tauri::AppHandle) -> Result<Status, String> {
    use tauri::Manager;
    match app.try_state::<VaultState>() {
        Some(vault) => vault.guard()?.status().map_err(err),
        None => Err(app
            .try_state::<Unopened>()
            .map_or_else(|| "the vault didn't open".to_owned(), |u| u.0.clone())),
    }
}

/// Returns the recovery code; the UI shows it once and never stores it.
#[tauri::command]
pub async fn vault_create(
    vault: State<'_, VaultState>,
    password: String,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    crate::password::check(&password)?;
    vault
        .blocking(move |v| Ok(v.create(&password)?.to_code().to_string()))
        .await
}

#[tauri::command]
pub async fn vault_unlock(vault: State<'_, VaultState>, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    vault.blocking(move |v| v.unlock(&password)).await?;
    vault.changed();
    Ok(())
}

/// Forgets the keys and stops every tunnel (terminal tabs close in the UI).
#[tauri::command]
pub async fn vault_lock(
    vault: State<'_, VaultState>,
    ssh: State<'_, crate::ssh::SshState>,
    vpns: State<'_, crate::vpn::VpnManager>,
    sftp: State<'_, crate::sftp::SftpState>,
) -> Result<(), String> {
    ssh.stop_all_tunnels().await;
    sftp.close_all().await;
    vpns.shutdown_all().await;
    vault.guard()?.lock();
    Ok(())
}

/// Why this device's data was erased, for the first-run screen (`device-erased`).
#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Erased {
    /// `signedOut`: its sync account signed it out from elsewhere; `disconnected`: its user chose
    /// to clear it when disconnecting it.
    reason: &'static str,
    /// The sync account it was in.
    email: Option<String>,
}

/// Forgets everything this device keeps: open tunnels, file browsers and VPNs close, the OS
/// keychain entry (or Android's biometric key) goes, the vault is emptied, and the window goes
/// back to first run with the reason. Callers may hold the sync state's `running` lock.
pub(crate) async fn erase_device(
    app: &tauri::AppHandle,
    reason: &'static str,
) -> Result<(), String> {
    use tauri::{Emitter, Manager};
    app.state::<crate::ssh::SshState>().stop_all_tunnels().await;
    app.state::<crate::sftp::SftpState>().close_all().await;
    app.state::<crate::vpn::VpnManager>().shutdown_all().await;
    #[cfg(target_os = "android")]
    let _ = crate::biometric::forget(app).await;
    let inner = app.state::<VaultState>().0.clone();
    let email = tauri::async_runtime::spawn_blocking(move || -> Result<Option<String>, String> {
        let mut v = inner
            .lock()
            .map_err(|_| "vault state is poisoned".to_owned())?;
        let email = v.sync_info().ok().flatten().map(|i| i.config.email);
        #[cfg(not(target_os = "android"))]
        if let Ok(Some(id)) = v.device_unlock_id() {
            let _ = crate::keychain::delete(&id);
        }
        v.erase().map_err(|e| e.to_string())?;
        Ok(email)
    })
    .await
    .map_err(|e| e.to_string())??;
    app.state::<crate::sync::SyncState>().forget().await;
    let _ = app.emit("device-erased", Erased { reason, email });
    Ok(())
}

/// Lost password. With sync on, the new password is set on the server first (every other
/// device is signed out and asks for it), and this device is signed back in.
#[tauri::command]
pub async fn vault_recover(
    app: tauri::AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, crate::sync::SyncState>,
    recovery_code: String,
    new_password: String,
) -> Result<(), String> {
    let (code, password) = (Zeroizing::new(recovery_code), Zeroizing::new(new_password));
    crate::password::check(&password)?;
    let Some((client, cfg)) = crate::sync::fresh_client(&vault)? else {
        return vault.blocking(move |v| v.recover(&code, &password)).await;
    };
    {
        let _single = sync.running.lock().await;
        mg_store::account::recover(
            &vault.0,
            client.clone(),
            &cfg.email,
            code,
            password,
            crate::sync::device_info(cfg.device_id, cfg.device_public_key),
        )
        .await
        .map_err(|e| e.to_string())?;
        crate::sync::set_client(&sync, client).await;
    }
    vault.changed();
    crate::sync::emit_status(&app, false);
    Ok(())
}

/// With sync on, the server takes the new password first and the other devices are signed out
/// until they sign in with it.
#[tauri::command]
pub async fn vault_change_password(
    app: tauri::AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, crate::sync::SyncState>,
    current: String,
    new_password: String,
) -> Result<(), String> {
    let (current, new_password) = (Zeroizing::new(current), Zeroizing::new(new_password));
    crate::password::check(&new_password)?;
    let _single = sync.running.lock().await;
    match crate::sync::session(&sync, &vault).await? {
        Some(client) => {
            mg_store::account::change_password(&vault.0, client, current, new_password)
                .await
                .map_err(|e| e.to_string())?;
            crate::sync::emit_status(&app, false);
            Ok(())
        }
        None => {
            vault
                .blocking(move |v| v.change_password(&current, &new_password))
                .await
        }
    }
}

/// Replaces the recovery code (the old one stops working; on the sync server too). Returns the
/// new one, which the UI shows once.
#[tauri::command]
pub async fn vault_new_recovery_code(
    vault: State<'_, VaultState>,
    sync: State<'_, crate::sync::SyncState>,
    password: String,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let _single = sync.running.lock().await;
    let rk = match crate::sync::session(&sync, &vault).await? {
        Some(client) => mg_store::account::new_recovery_key(&vault.0, client, password)
            .await
            .map_err(|e| e.to_string())?,
        None => {
            vault
                .blocking(move |v| {
                    let (_, creds) = v.prepare_new_recovery_key(&password)?;
                    v.apply_credentials(creds)?
                        .ok_or_else(|| mg_store::Error::Corrupt("no recovery key was made".into()))
                })
                .await?
        }
    };
    Ok(rk.to_code().to_string())
}

// ---------------------------------------------------------------- hosts

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum AuthView {
    Password {
        saved: bool,
    },
    Key {
        key_id: String,
    },
    /// `agent`: `None` for the system's; `path` for `custom`; `key`: the one key offered.
    Agent {
        agent: Option<String>,
        path: Option<String>,
        key: Option<String>,
    },
}

impl From<HostAuth> for AuthView {
    fn from(auth: HostAuth) -> Self {
        match auth {
            HostAuth::Password { password } => AuthView::Password {
                saved: password.is_some(),
            },
            HostAuth::Key { key_ref } => AuthView::Key { key_id: key_ref },
            HostAuth::Agent { agent, path, key } => AuthView::Agent { agent, path, key },
        }
    }
}

/// A host as it connects: `user`, `auth`, the jump host, VPN, theme and session keeping come
/// from its identity and group where it leaves them empty. `own` is what the host itself says
/// (what the editor edits).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostView {
    id: String,
    vault_id: String,
    label: String,
    hostname: String,
    port: u16,
    user: String,
    auth: AuthView,
    jump_id: Option<String>,
    vpn_id: Option<String>,
    /// The terminal theme for this host (an item id or `builtin:…`); `None` = the device's.
    theme_id: Option<String>,
    /// Attach to a tmux session on the server.
    keep_session: bool,
    record_sessions: bool,
    /// Forward the SSH agent to it.
    forward_agent: bool,
    /// Run at login, with a terminal, instead of the shell.
    login_command: Option<String>,
    /// How its jump host carries it: a command the jump host runs.
    jump_command: Option<String>,
    /// A command run on this device whose stdio is the connection (OpenSSH's `ProxyCommand`).
    proxy_command: Option<String>,
    /// This device runs `proxy_command` (see proxy.rs).
    proxy_allowed: bool,
    /// The cloud source that keeps it, if one does.
    source: Option<HostSourceView>,
    group_id: Option<String>,
    identity_id: Option<String>,
    tags: Vec<String>,
    notes: String,
    updated_at: i64,
    own: HostOwn,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSourceView {
    source_id: String,
    /// `vallic`, `aws`, `gcp` or `azure` (empty if the source is gone).
    provider: String,
    /// The provider no longer lists it.
    gone: bool,
    no_sftp: bool,
    no_forwarding: bool,
    /// Its state where it isn't running (`stopped`).
    state: Option<String>,
    /// Reached through its cloud: `aws-ssm`, `aws-eice` or `gcp-iap`.
    via: Option<String>,
    /// The feed that lists its host keys (which decide instead of a pinned key), if one does.
    listed_by: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostOwn {
    user: String,
    auth: AuthView,
    jump_id: Option<String>,
    vpn_id: Option<String>,
    theme_id: Option<String>,
    keep_session: bool,
}

impl HostView {
    /// `effective` is the host with its identity and group applied (the same host when it
    /// can't be resolved).
    fn new(id: String, vault_id: String, updated_at: i64, h: Host, effective: Host) -> Self {
        Self {
            id,
            vault_id,
            label: h.label,
            hostname: h.hostname,
            port: h.port,
            user: effective.user,
            auth: effective.auth.into(),
            jump_id: effective.jump_ref,
            vpn_id: effective.vpn_ref,
            theme_id: effective.theme_ref,
            keep_session: effective.keep_session,
            record_sessions: h.record_sessions,
            forward_agent: h.forward_agent,
            login_command: h.login_command,
            jump_command: h.jump_command,
            proxy_command: h.proxy_command,
            proxy_allowed: false,
            source: h.source.map(|s| HostSourceView {
                source_id: s.source_ref,
                provider: String::new(),
                gone: s.gone,
                no_sftp: s.no_sftp,
                no_forwarding: s.no_forwarding,
                state: s.state,
                via: s.reach.map(|r| r.kind),
                listed_by: (!s.host_keys.is_empty()).then(String::new),
            }),
            group_id: h.group_ref,
            identity_id: h.identity_ref,
            tags: h.tags,
            notes: h.notes,
            updated_at,
            own: HostOwn {
                user: h.user,
                auth: h.auth.into(),
                jump_id: h.jump_ref,
                vpn_id: h.vpn_ref,
                theme_id: h.theme_ref,
                keep_session: h.keep_session,
            },
        }
    }

    pub(crate) fn of(v: &LocalVault, item: Item) -> Option<Self> {
        let effective = v.effective_host(&item).ok();
        let ItemData::Host(h) = item.data else {
            return None;
        };
        let effective = effective.unwrap_or_else(|| h.clone());
        let proxy_allowed = h
            .proxy_command
            .as_deref()
            .is_some_and(|c| crate::proxy::allowed(v, c));
        let mut view = Self::new(item.id, item.vault_id, item.updated_at, h, effective);
        view.proxy_allowed = proxy_allowed;
        if let Some(s) = view.source.as_mut()
            && let Ok(Item {
                data: ItemData::CloudSource(c),
                ..
            }) = v.item(&s.source_id)
        {
            s.provider = c.provider;
            if let Some(by) = s.listed_by.as_mut() {
                *by = c.label;
            }
        }
        Some(view)
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum AuthInput {
    /// `None` keeps the saved password, `""` forgets it, anything else replaces it.
    Password {
        password: Option<String>,
    },
    Key {
        key_id: String,
    },
    /// See [`AuthView::Agent`]; empty strings are `None`.
    Agent {
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        key: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInput {
    id: Option<String>,
    /// For a new host: the vault to create it in (default: the personal vault).
    #[serde(default)]
    vault_id: Option<String>,
    label: String,
    hostname: String,
    port: u16,
    user: String,
    auth: AuthInput,
    #[serde(default)]
    jump_id: Option<String>,
    #[serde(default)]
    vpn_id: Option<String>,
    #[serde(default)]
    theme_id: Option<String>,
    #[serde(default)]
    record_sessions: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    identity_id: Option<String>,
    #[serde(default)]
    keep_session: bool,
    #[serde(default)]
    forward_agent: bool,
    #[serde(default)]
    login_command: Option<String>,
    #[serde(default)]
    jump_command: Option<String>,
    #[serde(default)]
    proxy_command: Option<String>,
}

/// `None` keeps the saved password, `""` forgets it.
fn auth_from(input: AuthInput, previous_password: Option<String>) -> HostAuth {
    match input {
        AuthInput::Password { password: None } => HostAuth::Password {
            password: previous_password,
        },
        AuthInput::Password { password: Some(p) } => HostAuth::Password {
            password: Some(p).filter(|p| !p.is_empty()),
        },
        AuthInput::Key { key_id } => HostAuth::Key { key_ref: key_id },
        AuthInput::Agent { agent, path, key } => {
            let filled =
                |s: Option<String>| s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
            let agent = filled(agent).filter(|a| a != "system");
            HostAuth::Agent {
                // A path only means something for a custom agent.
                path: filled(path).filter(|_| agent.as_deref() == Some("custom")),
                agent,
                key: filled(key),
            }
        }
    }
}

#[tauri::command]
pub fn hosts_list(vault: State<'_, VaultState>) -> Result<Vec<HostView>, String> {
    let v = vault.guard()?;
    let mut hosts: Vec<HostView> = v
        .items()
        .map_err(err)?
        .into_iter()
        .filter(|i| matches!(i.data, ItemData::Host(_)))
        .filter_map(|i| HostView::of(&v, i))
        .collect();
    hosts.sort_by_key(|h| h.label.to_lowercase());
    Ok(hosts)
}

#[tauri::command]
pub fn host_save(vault: State<'_, VaultState>, input: HostInput) -> Result<HostView, String> {
    let mut v = vault.guard()?;
    let previous = match &input.id {
        Some(id) => match v.item(id).map_err(err)?.data {
            ItemData::Host(h) => Some(h),
            _ => None,
        },
        None => None,
    };
    let previous_password = match &previous {
        Some(Host {
            auth: HostAuth::Password { password },
            ..
        }) => password.clone(),
        _ => None,
    };
    // A proxy command typed here (new, or changed) is allowed on this device; one that came
    // with the vault and is saved unchanged isn't (see proxy.rs).
    let previous_proxy = previous.as_ref().and_then(|h| h.proxy_command.clone());
    let proxy_command = input
        .proxy_command
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty());
    // A host a cloud source keeps stays kept: the editor changes what's the person's.
    let source = previous.and_then(|h| h.source);
    let auth = auth_from(input.auth, previous_password);
    let hostname = input.hostname.trim().to_owned();
    let label = match input.label.trim() {
        "" => hostname.clone(),
        l => l.to_owned(),
    };
    let host = Host {
        label,
        hostname,
        port: input.port,
        user: input.user.trim().to_owned(),
        auth,
        jump_ref: input.jump_id.filter(|j| !j.is_empty()),
        vpn_ref: input.vpn_id.filter(|j| !j.is_empty()),
        theme_ref: input.theme_id.filter(|t| !t.is_empty()),
        record_sessions: input.record_sessions,
        tags: input
            .tags
            .into_iter()
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect(),
        notes: input.notes,
        group_ref: input.group_id.filter(|g| !g.is_empty()),
        identity_ref: input.identity_id.filter(|i| !i.is_empty()),
        keep_session: input.keep_session,
        forward_agent: input.forward_agent,
        login_command: input
            .login_command
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty()),
        jump_command: input
            .jump_command
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty()),
        proxy_command: proxy_command.clone(),
        source,
    };
    let item = save(
        &mut v,
        input.id.as_deref(),
        input.vault_id.as_deref(),
        ItemData::Host(host),
    )
    .map_err(err)?;
    if let Some(command) = proxy_command.filter(|c| previous_proxy.as_ref() != Some(c)) {
        crate::proxy::allow(&v, &command)?;
    }
    let view = HostView::of(&v, item).ok_or("not a host")?;
    drop(v);
    vault.changed();
    Ok(view)
}

// ---------------------------------------------------------------- identities

/// Credentials several hosts share.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityView {
    id: String,
    vault_id: String,
    label: String,
    user: String,
    auth: AuthView,
    updated_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInput {
    id: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    label: String,
    user: String,
    auth: AuthInput,
}

fn identity_view(item: Item) -> Option<IdentityView> {
    let ItemData::Identity(i) = item.data else {
        return None;
    };
    Some(IdentityView {
        id: item.id,
        vault_id: item.vault_id,
        label: i.label,
        user: i.user,
        auth: i.auth.into(),
        updated_at: item.updated_at,
    })
}

#[tauri::command]
pub fn identities_list(vault: State<'_, VaultState>) -> Result<Vec<IdentityView>, String> {
    let mut out: Vec<IdentityView> = vault
        .guard()?
        .items()
        .map_err(err)?
        .into_iter()
        .filter_map(identity_view)
        .collect();
    out.sort_by_key(|i| i.label.to_lowercase());
    Ok(out)
}

#[tauri::command]
pub fn identity_save(
    vault: State<'_, VaultState>,
    input: IdentityInput,
) -> Result<IdentityView, String> {
    let mut v = vault.guard()?;
    let previous_password = match &input.id {
        Some(id) => match v.item(id).map_err(err)?.data {
            ItemData::Identity(mg_store::Identity {
                auth: HostAuth::Password { password },
                ..
            }) => password,
            _ => None,
        },
        None => None,
    };
    let identity = mg_store::Identity {
        label: input.label.trim().to_owned(),
        user: input.user.trim().to_owned(),
        auth: auth_from(input.auth, previous_password),
    };
    let item = save(
        &mut v,
        input.id.as_deref(),
        input.vault_id.as_deref(),
        ItemData::Identity(identity),
    )
    .map_err(err)?;
    drop(v);
    vault.changed();
    identity_view(item).ok_or_else(|| "not an identity".into())
}

#[tauri::command]
pub fn identity_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(err)?;
    vault.changed();
    Ok(())
}

// ---------------------------------------------------------------- host groups

/// Hosts that belong together, and the defaults they share.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    name: String,
    #[serde(default)]
    identity_id: Option<String>,
    #[serde(default)]
    jump_id: Option<String>,
    #[serde(default)]
    vpn_id: Option<String>,
    #[serde(default)]
    theme_id: Option<String>,
    #[serde(default)]
    keep_session: bool,
}

fn group_view(item: Item) -> Option<GroupView> {
    let ItemData::HostGroup(g) = item.data else {
        return None;
    };
    Some(GroupView {
        id: Some(item.id),
        vault_id: Some(item.vault_id),
        name: g.name,
        identity_id: g.identity_ref,
        jump_id: g.jump_ref,
        vpn_id: g.vpn_ref,
        theme_id: g.theme_ref,
        keep_session: g.keep_session,
    })
}

#[tauri::command]
pub fn groups_list(vault: State<'_, VaultState>) -> Result<Vec<GroupView>, String> {
    let mut out: Vec<GroupView> = vault
        .guard()?
        .items()
        .map_err(err)?
        .into_iter()
        .filter_map(group_view)
        .collect();
    out.sort_by_key(|g| g.name.to_lowercase());
    Ok(out)
}

#[tauri::command]
pub fn group_save(vault: State<'_, VaultState>, input: GroupView) -> Result<GroupView, String> {
    let some = |s: Option<String>| s.filter(|s| !s.is_empty());
    let group = mg_store::HostGroup {
        name: input.name.trim().to_owned(),
        identity_ref: some(input.identity_id),
        jump_ref: some(input.jump_id),
        vpn_ref: some(input.vpn_id),
        theme_ref: some(input.theme_id),
        keep_session: input.keep_session,
    };
    let mut v = vault.guard()?;
    let item = save(
        &mut v,
        input.id.as_deref(),
        input.vault_id.as_deref(),
        ItemData::HostGroup(group),
    )
    .map_err(err)?;
    drop(v);
    vault.changed();
    group_view(item).ok_or_else(|| "not a group".into())
}

/// Its hosts stay, keeping what they took from it.
#[tauri::command]
pub fn group_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(err)?;
    vault.changed();
    Ok(())
}

#[tauri::command]
pub fn host_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(err)?;
    vault.changed();
    Ok(())
}

// ---------------------------------------------------------------- SSH keys

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    id: String,
    vault_id: String,
    label: String,
    algorithm: String,
    fingerprint: String,
    public_key: String,
    /// The stored PEM is itself passphrase-protected (passphrase saved alongside).
    encrypted: bool,
    /// Its OpenSSH certificate, presented when signing in.
    certificate: Option<mg_ssh::keys::CertInfo>,
    /// A certificate is stored but can't be read (or isn't for this key).
    certificate_error: Option<String>,
    /// How its certificate is renewed (renew.rs).
    renew: Option<mg_store::CertRenewal>,
    /// This device runs the renewal command (typed here, or allowed).
    renew_allowed: bool,
    updated_at: i64,
}

impl KeyView {
    pub(crate) fn new(
        v: &LocalVault,
        id: String,
        vault_id: String,
        updated_at: i64,
        k: SshKey,
    ) -> Self {
        let renew_allowed = k
            .renew
            .as_ref()
            .is_some_and(|r| crate::proxy::allowed(v, &r.command));
        let (certificate, certificate_error) = match &k.certificate {
            None => (None, None),
            Some(c) => match mg_ssh::keys::certificate(c, &k.public_key) {
                Ok(info) => (Some(info), None),
                Err(e) => (None, Some(e.to_string())),
            },
        };
        Self {
            id,
            vault_id,
            label: k.label,
            algorithm: k.algorithm,
            fingerprint: k.fingerprint,
            public_key: k.public_key,
            encrypted: k.passphrase.is_some(),
            certificate,
            certificate_error,
            renew: k.renew,
            renew_allowed,
            updated_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum KeySource {
    Text { text: String },
    File { path: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyImport {
    label: String,
    #[serde(default)]
    vault_id: Option<String>,
    source: KeySource,
    passphrase: Option<String>,
}

fn save_key(v: &mut LocalVault, key: SshKey, vault_id: Option<&str>) -> Result<KeyView, String> {
    let Item {
        id,
        vault_id,
        updated_at,
        data,
    } = save(v, None, vault_id, ItemData::SshKey(key)).map_err(err)?;
    match data {
        ItemData::SshKey(k) => Ok(KeyView::new(v, id, vault_id, updated_at, k)),
        _ => unreachable!("upsert returns the data it was given"),
    }
}

#[tauri::command]
pub fn keys_list(vault: State<'_, VaultState>) -> Result<Vec<KeyView>, String> {
    let v = vault.guard()?;
    let mut keys: Vec<KeyView> = v
        .items()
        .map_err(err)?
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::SshKey(k) => Some(KeyView::new(&v, i.id, i.vault_id, i.updated_at, k)),
            _ => None,
        })
        .collect();
    keys.sort_by_key(|k| k.label.to_lowercase());
    Ok(keys)
}

#[tauri::command]
pub fn key_generate(
    vault: State<'_, VaultState>,
    label: String,
    vault_id: Option<String>,
) -> Result<KeyView, String> {
    let label = match label.trim() {
        "" => "MorphGate key".to_owned(),
        l => l.to_owned(),
    };
    let (pem, info) = mg_ssh::keys::generate_ed25519(&label).map_err(|e| e.to_string())?;
    let key = SshKey {
        label,
        private_key: pem.to_string(),
        passphrase: None,
        public_key: info.public_key,
        algorithm: info.algorithm,
        fingerprint: info.fingerprint,
        certificate: None,
        renew: None,
    };
    let view = {
        let mut v = vault.guard()?;
        save_key(&mut v, key, vault_id.as_deref())?
    };
    vault.changed();
    Ok(view)
}

#[tauri::command]
pub fn key_import(vault: State<'_, VaultState>, input: KeyImport) -> Result<KeyView, String> {
    let (pem, default_label) = match input.source {
        KeySource::Text { text } => (Zeroizing::new(text), "Imported key".to_owned()),
        KeySource::File { path } => {
            let path = expand_home(path.trim());
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (Zeroizing::new(text), name)
        }
    };
    let passphrase = input
        .passphrase
        .filter(|p| !p.is_empty())
        .map(Zeroizing::new);
    // A PuTTY key comes in as an OpenSSH one.
    let (pem, info) = mg_ssh::keys::for_vault(&pem, passphrase.as_deref().map(String::as_str))
        .map_err(|e| e.to_string())?;
    let label = match input.label.trim() {
        "" => default_label,
        l => l.to_owned(),
    };
    let key = SshKey {
        label,
        private_key: pem.to_string(),
        // Only kept when the PEM actually needs it.
        passphrase: if info.encrypted {
            passphrase.map(|p| p.to_string())
        } else {
            None
        },
        public_key: info.public_key,
        algorithm: info.algorithm,
        fingerprint: info.fingerprint,
        certificate: None,
        renew: None,
    };
    let view = {
        let mut v = vault.guard()?;
        save_key(&mut v, key, input.vault_id.as_deref())?
    };
    vault.changed();
    Ok(view)
}

/// Gives a key an OpenSSH certificate (a `…-cert.pub` file, or its text), replacing the one it
/// has, or removes it (`source` none). Only a user certificate for this key is taken.
#[tauri::command]
pub fn key_certificate(
    vault: State<'_, VaultState>,
    id: String,
    source: Option<KeySource>,
) -> Result<KeyView, String> {
    let text = match source {
        None => None,
        Some(KeySource::Text { text }) => Some(text),
        Some(KeySource::File { path }) => {
            let path = expand_home(path.trim());
            Some(std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?)
        }
    };
    let view = {
        let mut v = vault.guard()?;
        let item = v.item(&id).map_err(err)?;
        let ItemData::SshKey(mut key) = item.data else {
            return Err("not an SSH key".into());
        };
        key.certificate = match text {
            None => None,
            Some(t) => Some(
                mg_ssh::keys::certificate(&t, &key.public_key)
                    .map_err(|e| e.to_string())?
                    .certificate,
            ),
        };
        let Item {
            id,
            vault_id,
            updated_at,
            data,
        } = save(&mut v, Some(&id), None, ItemData::SshKey(key)).map_err(err)?;
        match data {
            ItemData::SshKey(k) => KeyView::new(&v, id, vault_id, updated_at, k),
            _ => unreachable!("saved as a key"),
        }
    };
    vault.changed();
    Ok(view)
}

#[tauri::command]
pub fn key_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(err)?;
    vault.changed();
    Ok(())
}

// ---------------------------------------------------------------- snippets

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetView {
    id: String,
    vault_id: String,
    name: String,
    body: String,
    tags: Vec<String>,
    updated_at: i64,
    /// The feed that keeps it (it's read-only here), if one does.
    source: Option<SnippetSourceView>,
    /// Its feed changed the body since this device last pasted or ran it: ask first.
    changed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetSourceView {
    source_id: String,
    /// The feed's name.
    label: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetInput {
    id: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    name: String,
    body: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Where this device keeps the hash of the body it last sent of a feed's snippet (not synced).
fn sent_setting(id: &str) -> String {
    format!("snippet-sent:{id}")
}

fn body_hash(body: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn snippet_view(
    v: &LocalVault,
    id: String,
    vault_id: String,
    updated_at: i64,
    s: Snippet,
) -> SnippetView {
    let source = s.source.as_ref().map(|src| SnippetSourceView {
        source_id: src.source_ref.clone(),
        label: match v.item(&src.source_ref).map(|i| i.data) {
            Ok(ItemData::CloudSource(c)) => c.label,
            _ => "its feed".into(),
        },
    });
    let changed = source.is_some()
        && v.setting(&sent_setting(&id))
            .ok()
            .flatten()
            .is_some_and(|sent| sent != body_hash(&s.body));
    SnippetView {
        id,
        vault_id,
        name: s.name,
        body: s.body,
        tags: s.tags,
        updated_at,
        source,
        changed,
    }
}

/// A feed's snippet can't be changed here: "make a copy" instead.
fn from_feed(v: &LocalVault, id: &str) -> Result<(), String> {
    match v.item(id).map(|i| i.data) {
        Ok(ItemData::Snippet(Snippet {
            source: Some(src),
            name,
            ..
        })) => {
            let feed = match v.item(&src.source_ref).map(|i| i.data) {
                Ok(ItemData::CloudSource(c)) => c.label,
                _ => "its feed".into(),
            };
            Err(format!(
                "\"{name}\" comes from {feed}: it changes there, or make a copy to change it here"
            ))
        }
        _ => Ok(()),
    }
}

#[tauri::command]
pub fn snippets_list(vault: State<'_, VaultState>) -> Result<Vec<SnippetView>, String> {
    let v = vault.guard()?;
    let mut snippets: Vec<SnippetView> = v
        .items()
        .map_err(err)?
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::Snippet(s) => Some(snippet_view(&v, i.id, i.vault_id, i.updated_at, s)),
            _ => None,
        })
        .collect();
    snippets.sort_by_key(|s| s.name.to_lowercase());
    Ok(snippets)
}

#[tauri::command]
pub fn snippet_save(
    vault: State<'_, VaultState>,
    input: SnippetInput,
) -> Result<SnippetView, String> {
    let snippet = Snippet {
        name: input.name.trim().to_owned(),
        body: input.body,
        tags: input
            .tags
            .into_iter()
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect(),
        source: None,
    };
    let mut v = vault.guard()?;
    if let Some(id) = &input.id {
        from_feed(&v, id)?;
    }
    let Item {
        id,
        vault_id,
        updated_at,
        data,
    } = save(
        &mut v,
        input.id.as_deref(),
        input.vault_id.as_deref(),
        ItemData::Snippet(snippet),
    )
    .map_err(err)?;
    let view = match data {
        ItemData::Snippet(s) => snippet_view(&v, id, vault_id, updated_at, s),
        _ => unreachable!("upsert returns the data it was given"),
    };
    drop(v);
    vault.changed();
    Ok(view)
}

#[tauri::command]
pub fn snippet_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    {
        let mut v = vault.guard()?;
        from_feed(&v, &id)?;
        v.delete(&id).map_err(err)?;
    }
    vault.changed();
    Ok(())
}

/// This device pasted or ran a feed's snippet: what it sent is what it'll compare the next
/// change with.
#[tauri::command]
pub fn snippet_sent(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    let v = vault.guard()?;
    let ItemData::Snippet(s) = v.item(&id).map_err(err)?.data else {
        return Err("not a snippet".into());
    };
    if s.source.is_some() {
        v.set_setting(&sent_setting(&id), Some(&body_hash(&s.body)))
            .map_err(err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Pins the JSON shapes `src/api.ts` sends and expects.
    #[test]
    fn ipc_shapes_match_the_frontend() {
        let input: HostInput = serde_json::from_value(json!({
            "id": null, "label": "", "hostname": "db1", "port": 22, "user": "root",
            "auth": { "kind": "key", "keyId": "K1" }, "tags": ["prod"], "notes": ""
        }))
        .unwrap();
        assert!(matches!(input.auth, AuthInput::Key { ref key_id } if key_id == "K1"));
        let keep: AuthInput =
            serde_json::from_value(json!({ "kind": "password", "password": null })).unwrap();
        assert!(matches!(keep, AuthInput::Password { password: None }));

        let host = Host {
            label: "db".into(),
            hostname: "db1".into(),
            port: 22,
            user: "root".into(),
            auth: HostAuth::Password {
                password: Some("secret".into()),
            },
            jump_ref: Some("J1".into()),
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
            proxy_command: None,
            source: None,
        };
        let view = HostView::new("H1".into(), "V1".into(), 5, host.clone(), host);
        let v = serde_json::to_value(&view).unwrap();
        assert_eq!(v["auth"], json!({ "kind": "password", "saved": true }));
        assert_eq!(v["updatedAt"], 5);
        assert_eq!(v["jumpId"], "J1");
        assert!(
            !v.to_string().contains("secret"),
            "views must never carry secrets"
        );

        let import: KeyImport = serde_json::from_value(json!({
            "label": "", "source": { "kind": "file", "path": "~/.ssh/id_ed25519" }, "passphrase": null
        }))
        .unwrap();
        assert!(matches!(import.source, KeySource::File { .. }));
    }
}

/// Saves a readable copy of the vault (`morphgate-vault-export/1` JSON) in the downloads folder,
/// after the master password; returns where. Secrets and team vaults only when asked for.
#[tauri::command]
pub async fn vault_export(
    app: tauri::AppHandle,
    vault: State<'_, VaultState>,
    password: String,
    secrets: bool,
    team_vaults: bool,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let inner = vault.0.clone();
    let data = tauri::async_runtime::spawn_blocking(move || {
        let v = inner
            .lock()
            .map_err(|_| "vault state is poisoned".to_owned())?;
        v.verify_password(&password).map_err(|e| e.to_string())?;
        v.export_plaintext(mg_store::export::ExportOptions {
            secrets,
            team_vaults,
        })
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    let day = data["exported_at"].as_str().and_then(|t| t.get(..10));
    let path = crate::util::download_path(
        &app,
        &format!("morphgate-vault-{}", day.unwrap_or("export")),
        "json",
    )?;
    let text = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    write_private(&path, text.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::saved(&path))
}

/// Writes a file only its owner can read (where the system has such permissions).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)
}
