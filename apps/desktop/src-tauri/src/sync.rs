//! Vault sync: enable / sign in / disconnect commands and the background loop.

use std::sync::Arc;
use std::time::Duration;

use mg_store::account;
use mg_store::sync::{Hold, SyncConfig, SyncError, sync_once, sync_once_with};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{LocalVault, Status};
use mg_sync::{B64, DeviceInfo, SyncClient};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{Mutex, Notify};
use zeroize::Zeroizing;

use crate::vault::VaultState;

/// While someone is using the app; while nobody is (no input for 5 minutes, or the window hidden),
/// `AWAY`. Coming back syncs at once.
const INTERVAL: Duration = Duration::from_secs(60);
const AWAY: Duration = Duration::from_secs(300);
const DEBOUNCE: Duration = Duration::from_millis(1500);

pub struct SyncState {
    client: Mutex<Option<Arc<SyncClient>>>,
    /// Single flight: one sync or account change at a time (two requests refreshing the same
    /// token at once would look like token theft to the server).
    pub(crate) running: Mutex<()>,
    pub(crate) poke: Arc<Notify>,
    /// Organizations whose vaults wait on this device, and why (as of the last round).
    held: std::sync::Mutex<Vec<(String, Hold)>>,
    /// Other devices waiting for this account's approval, per organization (last round).
    approvals_waiting: std::sync::Mutex<Vec<(String, usize)>>,
    /// Organizations that want this account's SSH keys published (last round).
    member_keys_due: std::sync::Mutex<Vec<String>>,
    /// Someone is using the app (the window shown, input in the last 5 minutes).
    present: std::sync::atomic::AtomicBool,
    /// What the last round fetched, for the account (server, account id) it was fetched as.
    round_cache: std::sync::Mutex<Option<((String, String), mg_store::sharing::RoundCache)>>,
    /// A sync round is running: what "Syncing…" shows. Not `running` held: account and Teams
    /// calls hold that too, and a status read during one stayed "Syncing…" until the next
    /// round's event, up to a minute later.
    in_round: std::sync::atomic::AtomicBool,
    /// The device this run told the server what it is now (name, platform, version), once.
    device_told: std::sync::Mutex<Option<String>>,
}

/// Marks a round as running for as long as it lives (every way out of `run` clears it).
struct InRound<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> InRound<'a> {
    fn new(flag: &'a std::sync::atomic::AtomicBool) -> Self {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        Self(flag)
    }
}

impl Drop for InRound<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl SyncState {
    /// Drops the session and what the last rounds learnt (the device was erased).
    pub(crate) async fn forget(&self) {
        *self.client.lock().await = None;
        if let Ok(mut c) = self.round_cache.lock() {
            *c = None;
        }
        if let Ok(mut v) = self.held.lock() {
            v.clear();
        }
        if let Ok(mut v) = self.approvals_waiting.lock() {
            v.clear();
        }
        if let Ok(mut v) = self.member_keys_due.lock() {
            v.clear();
        }
    }
}

/// What sign-in commands return when the account needs an authenticator code: the UI asks for
/// one and calls again with it.
const TOTP_REQUIRED: &str = "totp_required";

fn sign_in_error(e: account::AccountError) -> String {
    match e {
        account::AccountError::TotpRequired => TOTP_REQUIRED.into(),
        other => other.to_string(),
    }
}

const SIGNED_OUT: &str = "Signed out of sync. If the master password was changed on another device, sign in again with the new one.";

impl SyncState {
    pub fn new(poke: Arc<Notify>) -> Self {
        Self {
            client: Mutex::default(),
            running: Mutex::default(),
            poke,
            present: std::sync::atomic::AtomicBool::new(true),
            round_cache: std::sync::Mutex::default(),
            held: std::sync::Mutex::default(),
            approvals_waiting: std::sync::Mutex::default(),
            member_keys_due: std::sync::Mutex::default(),
            in_round: std::sync::atomic::AtomicBool::new(false),
            device_told: std::sync::Mutex::default(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusView {
    enabled: bool,
    server: Option<String>,
    email: Option<String>,
    last_sync_at: Option<i64>,
    last_error: Option<String>,
    syncing: bool,
    /// Sync is on but the server ended this device's session: sign in again.
    signed_out: bool,
    /// Organizations whose vaults wait for this account to turn on two-step verification.
    totp_required: Vec<SsoNeed>,
    /// Organizations whose vaults wait for this device to sign in at their identity provider.
    sso_required: Vec<SsoNeed>,
    /// Organizations whose vaults wait for this device to be approved (or that denied it).
    approval_required: Vec<ApprovalNeed>,
    /// Devices waiting for this account's approval.
    approvals_waiting: Vec<ApprovalsWaiting>,
    /// Organizations that want this account to publish its SSH keys.
    member_keys_due: Vec<SsoNeed>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalNeed {
    org_id: String,
    org_name: String,
    denied: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalsWaiting {
    org_id: String,
    org_name: String,
    count: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoNeed {
    org_id: String,
    org_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    name: String,
    version: String,
    registration_open: bool,
    billing: bool,
    /// New accounts confirm their address with a mailed code.
    email_verification: bool,
    totp: bool,
    /// The terms new accounts accept, when the server asks.
    terms: Option<TermsView>,
}

/// The terms of use and privacy policy a server asks accounts to accept.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TermsView {
    version: String,
    terms_url: String,
    privacy_url: String,
}

impl From<mg_sync::Terms> for TermsView {
    fn from(t: mg_sync::Terms) -> Self {
        TermsView {
            version: t.version,
            terms_url: t.terms_url,
            privacy_url: t.privacy_url,
        }
    }
}

/// This device's name, as the account's devices and session logs show it: a computer's host
/// name; a phone's maker and model ("Google Pixel 8"); on iOS "iPhone" or "iPad", all an app
/// may know there.
pub(crate) fn device_name() -> String {
    system_name()
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| match std::env::consts::OS {
            "android" => "Android device".into(),
            "ios" => "iPhone".into(),
            _ => "MorphGate desktop".into(),
        })
}

#[cfg(windows)]
fn system_name() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
fn system_name() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most `buf.len()` bytes into `buf`.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    // macOS adds ".local", its name on the local network.
    Some(
        String::from_utf8_lossy(&buf[..end])
            .trim_end_matches(".local")
            .to_owned(),
    )
}

#[cfg(target_os = "android")]
fn system_name() -> Option<String> {
    let property = |key: &str| {
        let key = std::ffi::CString::new(key).ok()?;
        let mut value = [0u8; 92]; // PROP_VALUE_MAX
        // SAFETY: `key` is NUL-terminated; the property's value is at most PROP_VALUE_MAX bytes.
        let len = unsafe { libc::__system_property_get(key.as_ptr(), value.as_mut_ptr().cast()) };
        let value = String::from_utf8_lossy(&value[..len.max(0) as usize])
            .trim()
            .to_owned();
        (!value.is_empty()).then_some(value)
    };
    let model = property("ro.product.model")?;
    let maker = property("ro.product.manufacturer").unwrap_or_default();
    // "Pixel 8" from "Google": "Google Pixel 8"; a model that starts with its maker stays as it is.
    Some(
        if maker.is_empty() || model.to_lowercase().starts_with(&maker.to_lowercase()) {
            model
        } else {
            let mut maker = maker.chars();
            let first = maker
                .next()
                .map(|c| c.to_uppercase().collect::<String>())
                .unwrap_or_default();
            format!("{first}{} {model}", maker.as_str())
        },
    )
}

#[cfg(target_os = "ios")]
fn system_name() -> Option<String> {
    // "iPhone17,1" or "iPad16,3"; the simulator names the model it plays instead of the Mac's.
    let model = std::env::var("SIMULATOR_MODEL_IDENTIFIER")
        .ok()
        .or_else(|| {
            let key = std::ffi::CString::new("hw.machine").ok()?;
            let mut value = [0u8; 64];
            let mut len = value.len();
            // SAFETY: sysctlbyname writes at most `len` bytes into `value` and sets `len`.
            let r = unsafe {
                libc::sysctlbyname(
                    key.as_ptr(),
                    value.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            (r == 0).then(|| {
                String::from_utf8_lossy(&value[..len])
                    .trim_end_matches('\0')
                    .to_owned()
            })
        })?;
    Some(
        if model.starts_with("iPad") {
            "iPad"
        } else {
            "iPhone"
        }
        .into(),
    )
}

pub(crate) fn device_info(device_id: String, public_key: [u8; 32]) -> DeviceInfo {
    let name = device_name();
    // The spec's platforms; anything else (a BSD) is closest to Linux.
    let platform = match std::env::consts::OS {
        os @ ("macos" | "windows" | "android" | "ios") => os,
        _ => "linux",
    };
    DeviceInfo {
        id: device_id,
        name: name.chars().take(100).collect(),
        platform: platform.into(),
        client_version: Some(env!("CARGO_PKG_VERSION").into()),
        public_key: B64(public_key.to_vec()),
    }
}

/// A device key is not used for signing yet; a valid Ed25519 public key keeps the door open.
fn new_device() -> (String, [u8; 32]) {
    let key = mg_vault::AccountKeys::generate()
        .map(|k| k.public().sign)
        .unwrap_or([0; 32]);
    (ulid::Ulid::generate().to_string(), key)
}

fn status(vault: &VaultState, sync: &SyncState, syncing: bool) -> SyncStatusView {
    let names = vault
        .guard()
        .ok()
        .and_then(|v| v.orgs().ok())
        .unwrap_or_default();
    let name = |id: &str| {
        names
            .iter()
            .find(|o| o.id == id)
            .map_or_else(|| "Your organization".into(), |o| o.name.clone())
    };
    let held = sync.held.lock().map(|h| h.clone()).unwrap_or_default();
    let totp_required = held
        .iter()
        .filter(|(_, why)| *why == Hold::Totp)
        .map(|(id, _)| SsoNeed {
            org_id: id.clone(),
            org_name: name(id),
        })
        .collect();
    let sso_required = held
        .iter()
        .filter(|(_, why)| *why == Hold::Sso)
        .map(|(id, _)| SsoNeed {
            org_id: id.clone(),
            org_name: name(id),
        })
        .collect();
    let approval_required = held
        .iter()
        .filter(|(_, why)| matches!(why, Hold::Approval | Hold::Denied))
        .map(|(id, why)| ApprovalNeed {
            org_id: id.clone(),
            org_name: name(id),
            denied: *why == Hold::Denied,
        })
        .collect();
    let approvals_waiting = sync
        .approvals_waiting
        .lock()
        .map(|w| {
            w.iter()
                .map(|(id, count)| ApprovalsWaiting {
                    org_id: id.clone(),
                    org_name: name(id),
                    count: *count,
                })
                .collect()
        })
        .unwrap_or_default();
    let (info, has_token) = vault
        .guard()
        .ok()
        .map(|v| {
            (
                v.sync_info().ok().flatten(),
                v.has_sync_token().unwrap_or(false),
            )
        })
        .unwrap_or_default();
    let member_keys_due = sync
        .member_keys_due
        .lock()
        .map(|due| {
            due.iter()
                .map(|id| SsoNeed {
                    org_id: id.clone(),
                    org_name: name(id),
                })
                .collect()
        })
        .unwrap_or_default();
    SyncStatusView {
        signed_out: info.is_some() && !has_token,
        enabled: info.is_some(),
        server: info.as_ref().map(|i| i.config.server_url.clone()),
        email: info.as_ref().map(|i| i.config.email.clone()),
        last_sync_at: info.as_ref().and_then(|i| i.last_sync_at),
        last_error: info.and_then(|i| i.last_error),
        syncing,
        totp_required,
        sso_required,
        approval_required,
        approvals_waiting,
        member_keys_due,
    }
}

pub(crate) fn emit_status(app: &AppHandle, syncing: bool) {
    let _ = app.emit(
        "sync-status",
        status(
            &app.state::<VaultState>(),
            &app.state::<SyncState>(),
            syncing,
        ),
    );
}

/// What kept shared vaults from syncing, as the Sync panel says it: each vault by its name (not
/// its id), once; a team vault without a plan as the team page says it (the member can't fix it
/// in their own account).
fn vault_problems(v: &mg_store::LocalVault, r: &mg_store::sync::SyncReport) -> String {
    let vaults = v.vaults().unwrap_or_default();
    let orgs: std::collections::HashMap<String, String> = v
        .orgs()
        .map(|o| o.into_iter().map(|o| (o.id, o.name)).collect())
        .unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    for (id, e) in &r.vault_errors {
        let info = vaults.iter().find(|x| &x.id == id);
        let org = info
            .and_then(|x| x.org_id.as_ref())
            .and_then(|o| orgs.get(o));
        let line = match (info, org) {
            (_, Some(org)) if r.plan_refused.contains(id) => {
                format!("{org} has no plan: its vaults can be read, not changed, until it has one")
            }
            (Some(x), Some(org)) => {
                format!("{org} / {}: {e}", x.name.as_deref().unwrap_or("vault"))
            }
            (Some(x), None) if x.personal => format!("Your vault: {e}"),
            _ => format!("vault {id}: {e}"),
        };
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines.join("; ")
}

/// Runs one sync if the vault is unlocked and sync is enabled. Never panics; errors are recorded.
pub async fn run(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<SyncState>();
    let vault = app.state::<VaultState>();
    let waiting = std::time::Instant::now();
    let _single = state.running.lock().await;
    tracing::debug!(
        waited_ms = waiting.elapsed().as_millis() as u64,
        "sync round: lock taken"
    );
    let _in_round = InRound::new(&state.in_round);

    let (info, token) = {
        let v = vault.guard()?;
        if v.status().map_err(|e| e.to_string())? != Status::Unlocked {
            return Ok(());
        }
        let Some(info) = v.sync_info().map_err(|e| e.to_string())? else {
            return Ok(());
        };
        (info, v.sync_token().map_err(|e| e.to_string())?)
    };

    let client = {
        let mut slot = state.client.lock().await;
        match slot
            .as_ref()
            .filter(|c| c.origin() == info.config.server_url.trim_end_matches('/'))
        {
            Some(c) => c.clone(),
            None => {
                // Signed out: nothing to do until the user signs in again.
                let Some(t) = token else { return Ok(()) };
                let c =
                    Arc::new(SyncClient::new(&info.config.server_url).map_err(|e| e.to_string())?);
                c.resume(t.to_string());
                *slot = Some(c.clone());
                c
            }
        }
    };

    emit_status(app, true);
    // Shared vaults first (organizations, verified keys, access changes), then every vault's items.
    let account = (
        info.config.server_url.clone(),
        info.config.account_id.clone(),
    );
    let mut cache = match state.round_cache.lock().ok().and_then(|mut c| c.take()) {
        Some((of, cache)) if of == account => cache,
        _ => mg_store::sharing::RoundCache::default(),
    };
    let shared = mg_store::sharing::refresh_with(&vault.0, &client, &mut cache).await;
    if let Ok(mut slot) = state.round_cache.lock() {
        *slot = Some((account, cache));
    }
    let result = match &shared {
        Err(mg_store::account::AccountError::SignedOut) => Err(SyncError::Unauthorized),
        Err(mg_store::account::AccountError::DeviceRevoked) => Err(SyncError::DeviceRevoked),
        Err(mg_store::account::AccountError::AccountDeleted) => Err(SyncError::AccountDeleted),
        // A vault the list says this device has up to date isn't pulled.
        Ok(r) => sync_once_with(&vault.0, &HttpRemote(&client), &r.heads).await,
        Err(_) => sync_once(&vault.0, &HttpRemote(&client)).await,
    };
    let shared_problem = match &shared {
        Ok(r) if !r.errors.is_empty() => Some(format!("Shared vaults: {}", r.errors.join("; "))),
        Err(
            mg_store::account::AccountError::SignedOut
            | mg_store::account::AccountError::DeviceRevoked
            | mg_store::account::AccountError::AccountDeleted,
        )
        | Ok(_) => None,
        Err(e) => Some(format!("Shared vaults: {e}")),
    };
    let shared_changed = matches!(&shared, Ok(r) if r.changed);
    // Removed from an organization (or it was deleted): its vaults just left; say so once.
    if let Ok(r) = &shared
        && !r.orgs_gone.is_empty()
    {
        let _ = app.emit("orgs-gone", &r.orgs_gone);
    }

    let error = {
        let v = vault.guard()?;
        if let Some(rotated) = client.take_rotated_refresh() {
            let _ = v.set_sync_token(&rotated);
        }
        let error = match &result {
            Ok(r) if !r.vault_errors.is_empty() => Some(vault_problems(&v, r)),
            Ok(_) => shared_problem,
            Err(SyncError::Unauthorized) => {
                let _ = v.clear_sync_token();
                Some(SIGNED_OUT.to_owned())
            }
            Err(e) => Some(e.to_string()),
        };
        let _ = v.record_sync(error.as_deref());
        error
    };
    if matches!(result, Err(SyncError::Unauthorized)) {
        *state.client.lock().await = None;
    }
    // What this device is now (an app update; a phone that signed in when it said "Linux"),
    // which it otherwise only says when it signs in: once a run. A server without it (404, 405)
    // is left alone.
    let device_id = &info.config.device_id;
    if result.is_ok()
        && state
            .device_told
            .lock()
            .is_ok_and(|t| t.as_ref() != Some(device_id))
    {
        let d = device_info(device_id.clone(), info.config.device_public_key);
        let update = mg_sync::DeviceUpdate {
            name: d.name,
            platform: d.platform,
            client_version: d.client_version,
        };
        match client.update_device(device_id, &update).await {
            Ok(())
            | Err(mg_sync::Error::Api {
                status: 404 | 405, ..
            }) => {
                if let Ok(mut told) = state.device_told.lock() {
                    *told = Some(device_id.clone());
                }
            }
            Err(e) => tracing::debug!(%e, "device update"),
        }
    }
    // Signed out by its account (another device, the account page): it forgets everything.
    if matches!(result, Err(SyncError::DeviceRevoked)) {
        crate::vault::erase_device(app, "signedOut").await?;
        return Ok(());
    }
    // The account was deleted elsewhere: sync goes off as when disconnecting and keeping a copy
    // (the personal vault stays, now the only copy; team vaults go), and the window says why.
    if matches!(result, Err(SyncError::AccountDeleted)) {
        let email = info.config.email.clone();
        vault.guard()?.disable_sync().map_err(|e| e.to_string())?;
        state.forget().await;
        let _ = app.emit("account-deleted", email);
        let _ = app.emit("vault-changed", ());
        emit_status(app, false);
        return Ok(());
    }
    // What this round's vaults wait on: a sign-in, an approval (they stay; they sync once
    // that's settled). The organization's own answer comes first.
    if let Ok(mut held) = state.held.lock() {
        let mut orgs: Vec<(String, Hold)> = match &shared {
            Ok(r) => r.held.clone(),
            Err(_) => held.clone(),
        };
        if let Ok(r) = &result {
            for (org, why) in &r.held {
                if !orgs.iter().any(|(o, _)| o == org) {
                    orgs.push((org.clone(), *why));
                }
            }
        }
        orgs.sort();
        *held = orgs;
    }
    if let (Ok(r), Ok(mut waiting)) = (&shared, state.approvals_waiting.lock()) {
        *waiting = r.approvals_waiting.clone();
    }
    if let (Ok(r), Ok(mut due)) = (&shared, state.member_keys_due.lock()) {
        *due = r.member_keys_due.clone();
    }
    if shared_changed || result.as_ref().is_ok_and(|r| r.changed_locally()) {
        let _ = app.emit("vault-changed", ());
    }
    // Recordings uploaded or refused: the logs list shows where each stands.
    if result
        .as_ref()
        .is_ok_and(|r| r.blobs_uploaded > 0 || !r.blob_errors.is_empty())
    {
        let _ = app.emit("session-logs-changed", ());
    }
    emit_status(app, false);
    tracing::debug!(
        ms = waiting.elapsed().as_millis() as u64,
        ?error,
        "sync round: done"
    );
    error.map_or(Ok(()), Err)
}

/// Syncs every minute while the app is used (every 5 while it isn't), and shortly after local
/// edits or coming back to it.
pub fn spawn_loop(app: AppHandle) {
    let poke = app.state::<SyncState>().poke.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let present = app
                .state::<SyncState>()
                .present
                .load(std::sync::atomic::Ordering::Relaxed);
            let wait = if present { INTERVAL } else { AWAY };
            let poked = tokio::time::timeout(wait, poke.notified()).await.is_ok();
            tracing::debug!(poked, "sync loop: woke");
            tokio::time::sleep(DEBOUNCE).await;
            if let Err(e) = run(&app).await {
                tracing::debug!(%e, "sync failed");
            }
        }
    });
}

/// Whether someone is using the app (the window shown, input in the last 5 minutes); coming back
/// syncs at once.
#[tauri::command]
pub fn sync_presence(state: State<'_, SyncState>, present: bool) {
    let was = state
        .present
        .swap(present, std::sync::atomic::Ordering::Relaxed);
    if present && !was {
        state.poke.notify_one();
    }
}

/// This device's signed-in session, for account changes. Callers hold `running`.
pub(crate) async fn session(
    state: &SyncState,
    vault: &VaultState,
) -> Result<Option<Arc<SyncClient>>, String> {
    let (info, token) = {
        let v = vault.guard()?;
        let Some(info) = v.sync_info().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        (info, v.sync_token().map_err(|e| e.to_string())?)
    };
    let mut slot = state.client.lock().await;
    if let Some(c) = slot
        .as_ref()
        .filter(|c| c.origin() == info.config.server_url.trim_end_matches('/'))
    {
        return Ok(Some(c.clone()));
    }
    let Some(token) = token else {
        return Err(account::AccountError::SignedOut.to_string());
    };
    let c = Arc::new(SyncClient::new(&info.config.server_url).map_err(|e| e.to_string())?);
    c.resume(token.to_string());
    *slot = Some(c.clone());
    Ok(Some(c))
}

/// A fresh client for this device's server (sign-in, recovery), and the device it signs in as.
pub(crate) fn fresh_client(
    vault: &VaultState,
) -> Result<Option<(Arc<SyncClient>, SyncConfig)>, String> {
    let Some(info) = vault.guard()?.sync_info().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let c = SyncClient::new(&info.config.server_url).map_err(|e| e.to_string())?;
    Ok(Some((Arc::new(c), info.config)))
}

pub(crate) async fn set_client(state: &SyncState, client: Arc<SyncClient>) {
    *state.client.lock().await = Some(client);
}

async fn blocking<T: Send + 'static>(
    vault: &VaultState,
    f: impl FnOnce(&mut LocalVault) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let inner = vault.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut v = inner
            .lock()
            .map_err(|_| "vault state is poisoned".to_owned())?;
        f(&mut v)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ------------------------------------------------------------------ commands

#[tauri::command]
pub fn sync_status(vault: State<'_, VaultState>, state: State<'_, SyncState>) -> SyncStatusView {
    status(
        &vault,
        &state,
        state.in_round.load(std::sync::atomic::Ordering::Relaxed),
    )
}

#[tauri::command]
pub async fn sync_check(server: String) -> Result<ServerView, String> {
    let caps = SyncClient::new(&server)
        .map_err(|e| e.to_string())?
        .capabilities()
        .await
        .map_err(|e| e.to_string())?;
    let (name, version) = caps.server.map(|s| (s.name, s.version)).unwrap_or_default();
    Ok(ServerView {
        name,
        version,
        registration_open: caps.features.registration_open,
        billing: caps.features.billing.is_some(),
        email_verification: caps.features.email_verification,
        totp: caps.features.totp,
        terms: caps.features.terms.map(TermsView::from),
    })
}

/// Servers with email verification: mails the code that [`sync_enable`] then needs.
#[tauri::command]
pub async fn sync_start_registration(server: String, email: String) -> Result<(), String> {
    SyncClient::new(&server)
        .map_err(|e| e.to_string())?
        .start_registration(email.trim())
        .await
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableResult {
    /// Set when the vault had no stored recovery proof and got a new recovery key: show it once.
    recovery_code: Option<String>,
}

/// The sign-up form.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUp {
    server: String,
    email: String,
    password: String,
    /// On servers that verify addresses: the mailed code.
    email_code: Option<String>,
    /// The version of the server's terms the person accepted.
    accepted_terms: Option<String>,
}

/// Creates an account on the server from this device's existing vault and uploads everything.
#[tauri::command]
pub async fn sync_enable(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    signup: SignUp,
) -> Result<EnableResult, String> {
    let SignUp {
        server,
        email,
        password,
        email_code,
        accepted_terms,
    } = signup;
    let password = Zeroizing::new(password);
    let email = email.trim().to_owned();
    // Until this client is the device's, no sync round may start: it would sign in with the
    // stored token too, and the second use of a refresh token signs the device out.
    let single = state.running.lock().await;
    let client = Arc::new(SyncClient::new(&server).map_err(|e| e.to_string())?);
    let caps = client.capabilities().await.map_err(|e| e.to_string())?;
    if !caps.features.registration_open {
        return Err("This server does not accept new accounts.".into());
    }
    let (export, rotated) = blocking(&vault, move |v| {
        v.export_for_registration(&password)
            .map_err(|e| e.to_string())
    })
    .await?;
    let (device_id, device_key) = new_device();
    let mut req = register_request(
        &export,
        &email,
        device_info(device_id.clone(), device_key),
        email_code.map(|c| c.trim().to_owned()),
    );
    req.accepted_terms = accepted_terms;
    let session = client
        .register(&req)
        .await
        .map_err(|e| match e {
            mg_sync::Error::Api { status: 409, .. } => {
                "This email already has an account on that server: choose \"I have an account\" to sign in to it.".into()
            }
            mg_sync::Error::Api { code, .. } if code == "email_code_required" => {
                "This server needs the code it mails to that address.".into()
            }
            mg_sync::Error::Api { code, .. } if code == "invalid_code" => {
                "That code is wrong or has expired. Send a new one.".into()
            }
            mg_sync::Error::Api { code, .. } if code == "terms_not_accepted" => {
                "Accept the terms of use and the privacy policy first.".into()
            }
            other => other.to_string(),
        })?;
    client
        .create_vault(&create_vault_request(&export.vault))
        .await
        .map_err(|e| e.to_string())?;
    {
        let mut v = vault.guard()?;
        v.enable_sync(&SyncConfig {
            server_url: client.origin().to_owned(),
            email,
            account_id: session.account_id,
            device_id,
            device_public_key: device_key,
        })
        .map_err(|e| e.to_string())?;
        v.set_sync_token(&session.tokens.refresh_token)
            .map_err(|e| e.to_string())?;
        client.take_rotated_refresh();
    }
    *state.client.lock().await = Some(client);
    drop(single);
    let _ = run(&app).await;
    Ok(EnableResult {
        recovery_code: rotated.map(|rk| rk.to_code().to_string()),
    })
}

/// First run on a new device: joins an existing account instead of creating a local vault.
#[tauri::command]
pub async fn sync_sign_in(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    server: String,
    email: String,
    password: String,
    totp: Option<String>,
) -> Result<(), String> {
    {
        // No sync round until the client is in place (see `sync_enable`).
        let _single = state.running.lock().await;
        let client = fresh_device(&vault, &server).await?;
        let (device_id, device_key) = new_device();
        account::sign_in(
            &vault.0,
            client.clone(),
            email.trim(),
            Zeroizing::new(password),
            device_info(device_id, device_key),
            totp.map(|c| c.trim().to_owned()),
        )
        .await
        .map_err(sign_in_error)?;
        set_client(&state, client).await;
    }
    run(&app).await
}

/// A device with a vault of its own (never synced) signs in to an existing account: what the
/// vault holds goes into the account's, and the device opens with the account's master password
/// from now on. Unlocking with the system keychain carries over, with the account's keys.
/// Returns how many items it brought.
#[tauri::command]
pub async fn sync_join(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    server: String,
    email: String,
    password: String,
    totp: Option<String>,
) -> Result<usize, String> {
    // No sync round until the client is in place (see `sync_enable`).
    let single = state.running.lock().await;
    let keychain = vault
        .guard()?
        .device_unlock_id()
        .map_err(|e| e.to_string())?;
    let client = Arc::new(SyncClient::new(&server).map_err(|e| e.to_string())?);
    client.capabilities().await.map_err(|e| e.to_string())?;
    let (device_id, device_key) = new_device();
    let count = account::join(
        &vault.0,
        client.clone(),
        email.trim(),
        Zeroizing::new(password),
        device_info(device_id, device_key),
        totp.map(|c| c.trim().to_owned()),
    )
    .await
    .map_err(sign_in_error)?;
    // Android's fingerprint unlock needs a check to be set up again: it goes off.
    #[cfg(target_os = "android")]
    if keychain.is_some() {
        let _ = crate::device::biometric_off(&app, &vault).await;
    }
    #[cfg(not(target_os = "android"))]
    if let Some(old) = keychain {
        let mut v = vault.guard()?;
        let _ = crate::keychain::delete(&old);
        if let Ok((id, key)) = v.enable_device_unlock()
            && crate::keychain::store(&id, &key).is_err()
        {
            let _ = v.disable_device_unlock();
        }
    }
    set_client(&state, client).await;
    drop(single);
    run(&app).await?;
    Ok(count)
}

/// First run on a new device, master password forgotten: sets a new one with the recovery code,
/// then joins the account with it.
#[tauri::command]
pub async fn sync_recover_sign_in(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    server: String,
    email: String,
    recovery_code: String,
    new_password: String,
) -> Result<(), String> {
    {
        // No sync round until the client is in place (see `sync_enable`).
        let _single = state.running.lock().await;
        let client = fresh_device(&vault, &server).await?;
        let (device_id, device_key) = new_device();
        account::recover_and_sign_in(
            &vault.0,
            client.clone(),
            email.trim(),
            Zeroizing::new(recovery_code),
            Zeroizing::new(new_password),
            device_info(device_id, device_key),
        )
        .await
        .map_err(|e| e.to_string())?;
        set_client(&state, client).await;
    }
    run(&app).await
}

async fn fresh_device(vault: &VaultState, server: &str) -> Result<Arc<SyncClient>, String> {
    if vault.guard()?.status().map_err(|e| e.to_string())? != Status::Uninitialized {
        return Err("This device already has a vault.".into());
    }
    let client = Arc::new(SyncClient::new(server).map_err(|e| e.to_string())?);
    client.capabilities().await.map_err(|e| e.to_string())?;
    Ok(client)
}

/// After the server signed this device out (password changed elsewhere, or the device was
/// signed out from another one): signs in again. With a new password the vault here re-wraps
/// its keys and unlocks with that password from now on.
#[tauri::command]
pub async fn sync_sign_in_again(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    password: String,
    totp: Option<String>,
) -> Result<(), String> {
    {
        let _single = state.running.lock().await;
        let (client, cfg) = fresh_client(&vault)?.ok_or("Sync is not enabled.")?;
        account::sign_in_again(
            &vault.0,
            client.clone(),
            &cfg.email,
            Zeroizing::new(password),
            device_info(cfg.device_id, cfg.device_public_key),
            totp.map(|c| c.trim().to_owned()),
        )
        .await
        .map_err(sign_in_error)?;
        set_client(&state, client).await;
    }
    run(&app).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    id: String,
    name: String,
    platform: String,
    created_at: String,
    last_seen_at: Option<String>,
    current: bool,
}

#[tauri::command]
pub async fn sync_devices(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
) -> Result<Vec<DeviceView>, String> {
    let _single = state.running.lock().await;
    let client = session(&state, &vault)
        .await?
        .ok_or("Sync is not enabled.")?;
    let devices = client.devices().await.map_err(|e| e.to_string());
    if let Some(t) = client.take_rotated_refresh() {
        vault
            .guard()?
            .set_sync_token(&t)
            .map_err(|e| e.to_string())?;
    }
    Ok(devices?
        .into_iter()
        .map(|d| DeviceView {
            id: d.info.id,
            name: d.info.name,
            platform: d.info.platform,
            created_at: d.created_at,
            last_seen_at: d.last_seen_at,
            current: d.current,
        })
        .collect())
}

/// Signs another device out of sync. What is already on it stays there.
#[tauri::command]
pub async fn sync_revoke_device(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    id: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = session(&state, &vault)
        .await?
        .ok_or("Sync is not enabled.")?;
    let result = client.revoke_device(&id).await.map_err(|e| e.to_string());
    if let Some(t) = client.take_rotated_refresh() {
        vault
            .guard()?
            .set_sync_token(&t)
            .map_err(|e| e.to_string())?;
    }
    result
}

#[tauri::command]
pub async fn sync_now(app: AppHandle) -> Result<(), String> {
    tracing::debug!("sync now: asked");
    run(&app).await
}

/// Signs this device out and stops syncing; local data stays.
#[tauri::command]
pub async fn sync_disable(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    remove: bool,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    if let Some(client) = state.client.lock().await.take() {
        let _ = client.logout().await;
    }
    // Cleared: back to first run (the account keeps everything that synced).
    if remove {
        return crate::vault::erase_device(&app, "disconnected").await;
    }
    // Kept: the personal vault stays here, unsynced; team vaults go.
    vault.guard()?.disable_sync().map_err(|e| e.to_string())?;
    emit_status(&app, false);
    Ok(())
}

// ------------------------------------------------------------------ account

/// This device's session; callers hold `running`.
async fn signed_in(state: &SyncState, vault: &VaultState) -> Result<Arc<SyncClient>, String> {
    session(state, vault)
        .await?
        .ok_or_else(|| "Sync is not enabled.".to_owned())
}

/// Keeps a refresh token the client rotated while talking to the server.
fn keep_token(vault: &VaultState, client: &SyncClient) -> Result<(), String> {
    match client.take_rotated_refresh() {
        Some(t) => vault.guard()?.set_sync_token(&t).map_err(|e| e.to_string()),
        None => Ok(()),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanView {
    plan: String,
    /// `trialing`, `active`, `grace`, `lapsed` or `canceled`.
    status: Option<String>,
    expires_at: Option<String>,
    grace_ends_at: Option<String>,
    /// Set when a team seat covered it: the team (its grace runs from when the seat ended).
    seat_team: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    email: String,
    /// `None` when the server doesn't verify addresses.
    email_verified: Option<bool>,
    totp_enabled: bool,
    /// The server offers two-step verification.
    totp: bool,
    /// The server can move the account to another address.
    email_change: bool,
    /// The server has an account portal ("Manage account").
    portal: bool,
    plan: Option<PlanView>,
    /// The server's terms, when this account hasn't accepted their current version.
    terms_to_accept: Option<TermsView>,
}

/// The sync account as the server sees it, and what the server offers for it.
#[tauri::command]
pub async fn sync_account(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
) -> Result<AccountView, String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    let account = client.account().await;
    keep_token(&vault, &client)?;
    let account = account.map_err(|e| e.to_string())?;
    let caps = client.capabilities().await.map_err(|e| e.to_string())?;
    // Moved to another address from another device: sign in with that one from now on.
    let moved = {
        let v = vault.guard()?;
        let moved = v
            .sync_info()
            .ok()
            .flatten()
            .is_some_and(|i| i.config.email != account.email);
        if moved {
            v.set_sync_email(&account.email)
                .map_err(|e| e.to_string())?;
        }
        moved
    };
    if moved {
        emit_status(&app, false);
    }
    Ok(AccountView {
        email: account.email,
        email_verified: account.email_verified,
        totp_enabled: account.totp_enabled,
        totp: caps.features.totp,
        email_change: caps.features.email_verification,
        portal: caps
            .features
            .billing
            .as_ref()
            .is_some_and(|b| b.web_session),
        plan: account.entitlement.map(|e| PlanView {
            plan: e.plan,
            status: e.status,
            expires_at: e.expires_at,
            grace_ends_at: e.grace_ends_at,
            seat_team: (e.source.as_deref() == Some("team_seat"))
                .then_some(e.team)
                .flatten(),
        }),
        terms_to_accept: caps
            .features
            .terms
            .filter(|t| {
                account
                    .terms
                    .as_ref()
                    .is_none_or(|a| a.version != t.version)
            })
            .map(TermsView::from),
    })
}

/// Accepts the server's current terms (they changed since the account accepted them).
#[tauri::command]
pub async fn sync_accept_terms(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    version: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    let result = client.accept_terms(&version).await;
    keep_token(&vault, &client)?;
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupView {
    /// Base32, to type into an authenticator app.
    secret: String,
    uri: String,
    /// The `otpauth://` URI as an SVG QR code, dark on white so it scans in either theme.
    qr_svg: String,
}

fn qr_svg(text: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build())
}

/// Starts two-step verification (master password required): a secret to scan.
#[tauri::command]
pub async fn sync_totp_start(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    password: String,
) -> Result<TotpSetupView, String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    let setup = account::start_totp(&vault.0, client, Zeroizing::new(password))
        .await
        .map_err(|e| e.to_string())?;
    Ok(TotpSetupView {
        qr_svg: qr_svg(&setup.uri)?,
        secret: setup.secret,
        uri: setup.uri,
    })
}

/// Turns two-step verification on with a code from the scanned secret.
#[tauri::command]
pub async fn sync_totp_enable(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    code: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    account::enable_totp(&vault.0, client, code)
        .await
        .map_err(|e| e.to_string())?;
    // Teams that require it open their vaults: the next round brings them.
    state.poke.notify_one();
    Ok(())
}

/// Turns two-step verification off (master password and a current code).
#[tauri::command]
pub async fn sync_totp_disable(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    password: String,
    code: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    account::disable_totp(&vault.0, client, Zeroizing::new(password), code)
        .await
        .map_err(|e| e.to_string())?;
    // Teams that require it hold their vaults back from now on: the next round says so.
    state.poke.notify_one();
    Ok(())
}

/// Mails a code to the address the account should move to.
#[tauri::command]
pub async fn sync_email_start(
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    new_email: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    account::start_email_change(&vault.0, client, new_email)
        .await
        .map_err(|e| match e {
            account::AccountError::Server(m) if m.contains("account_exists") => {
                "That address already has an account on this server.".into()
            }
            other => other.to_string(),
        })
}

/// Moves the account to the new address with the mailed code (master password required).
#[tauri::command]
pub async fn sync_email_change(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    password: String,
    new_email: String,
    code: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    account::change_email(&vault.0, client, Zeroizing::new(password), new_email, code)
        .await
        .map_err(|e| e.to_string())?;
    emit_status(&app, false);
    Ok(())
}

/// Deletes the sync account (the master password proves it); this device keeps its vault, with
/// sync off, as after [`sync_disable`].
#[tauri::command]
pub async fn sync_delete_account(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    password: String,
) -> Result<(), String> {
    let _single = state.running.lock().await;
    let client = signed_in(&state, &vault).await?;
    account::delete_account(&vault.0, client, Zeroizing::new(password))
        .await
        .map_err(|e| e.to_string())?;
    state.client.lock().await.take();
    vault.changed();
    emit_status(&app, false);
    Ok(())
}

/// Saves what the server keeps about the account (not the vault: that's end-to-end encrypted)
/// as JSON in the downloads folder; returns the file's path.
#[tauri::command]
pub async fn sync_export_account(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
) -> Result<String, String> {
    let data = {
        let _single = state.running.lock().await;
        let client = signed_in(&state, &vault).await?;
        let data = client.account_export().await;
        keep_token(&vault, &client)?;
        data.map_err(|e| match e {
            mg_sync::Error::Api { status: 404, .. } => {
                "this sync server doesn't offer a data export".to_string()
            }
            e => e.to_string(),
        })?
    };
    let day = data["generated_at"].as_str().and_then(|t| t.get(..10));
    let path = crate::util::download_path(
        &app,
        &format!("morphgate-account-{}", day.unwrap_or("export")),
        "json",
    )?;
    let text = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::saved(&path))
}

/// Opens the server's account portal in the browser, already signed in (single-use link), on
/// `next` (an account page such as `/account/team/<org>/billing`) or the account page.
#[tauri::command]
pub async fn sync_open_portal(
    app: AppHandle,
    vault: State<'_, VaultState>,
    state: State<'_, SyncState>,
    next: Option<String>,
) -> Result<(), String> {
    let link = {
        let _single = state.running.lock().await;
        let client = signed_in(&state, &vault).await?;
        let link = client.web_session(next.as_deref()).await;
        keep_token(&vault, &client)?;
        link.map_err(|e| e.to_string())?
    };
    crate::util::open_in_browser(&app, &link.url)
}
