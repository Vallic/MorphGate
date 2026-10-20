//! This device's unlock options: the OS keychain instead of typing the master password,
//! optionally only after Touch ID / Windows Hello / polkit confirms the user is there, and
//! locking after a period of inactivity. On Android, a fingerprint or face instead: the device
//! key is sealed by a Keystore key that only a biometric check releases (see `biometric`), so the
//! check is always part of it. On iPhones and iPads too: iOS releases the device key only after
//! Face ID, Touch ID or the passcode (see `keychain`). Nothing here syncs.

#[cfg(not(target_os = "android"))]
use std::sync::Mutex;

use mg_presence::{Kind, Parent, Status};
use mg_store::LocalVault;
use mg_vault::DeviceKey;
use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

#[cfg(not(target_os = "android"))]
use crate::keychain;
use crate::vault::VaultState;

const AUTO_LOCK: &str = "auto_lock_minutes";
/// Minutes without use before the vault locks, until the device chooses (`0` there: never).
const AUTO_LOCK_DEFAULT: u32 = 15;
/// "1": keychain unlock first asks the OS to verify the user.
const REQUIRE_PRESENCE: &str = "unlock_requires_presence";
/// "0": don't look for updates by itself (default: look at launch and twice a day).
const UPDATE_CHECK: &str = "update_check";

/// Shown by macOS as "MorphGate is trying to …", by Windows as a sentence.
#[cfg(not(target_os = "android"))]
const UNLOCK_REASON: &str = "unlock your vault";
const CONFIRM_REASON: &str = "confirm it's you";

/// The error a cancelled OS prompt turns into; the UI shows nothing for it.
pub(crate) const CANCELLED: &str = "cancelled";

/// Android: the device key sealed by the biometric Keystore key (base64).
#[cfg(target_os = "android")]
const SEALED_UNLOCK: &str = "android_unlock_sealed";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceView {
    /// "touchId", "faceId", "windowsHello", "system", "passcode" (iOS), or "biometric" (Android:
    /// a fingerprint or face).
    kind: &'static str,
    /// "ready", "setup" (Linux: the polkit action must be installed) or "unavailable".
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl From<mg_presence::Availability> for PresenceView {
    fn from(a: mg_presence::Availability) -> Self {
        let kind = match a.kind {
            Kind::TouchId => "touchId",
            Kind::FaceId => "faceId",
            Kind::WindowsHello => "windowsHello",
            Kind::System => "system",
            Kind::Passcode => "passcode",
        };
        let (status, detail) = match a.status {
            Status::Ready => ("ready", None),
            Status::NeedsSetup => ("setup", None),
            Status::Unavailable(why) => ("unavailable", Some(why)),
        };
        PresenceView {
            kind,
            status,
            detail,
        }
    }
}

fn presence_error(e: mg_presence::Error) -> String {
    match e {
        mg_presence::Error::Cancelled => CANCELLED.into(),
        other => other.to_string(),
    }
}

/// The native window the OS prompt belongs to (Windows only).
fn parent(window: &tauri::Window) -> Parent {
    #[cfg(windows)]
    return Parent(window.hwnd().ok().map(|h| h.0 as isize));
    #[cfg(not(windows))]
    {
        let _ = window;
        Parent::default()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStatus {
    /// A system keychain can be used here.
    keychain_available: bool,
    /// The vault unlocks from the keychain on this device.
    keychain_enabled: bool,
    /// 0 = never.
    auto_lock_minutes: u32,
    /// What verifying the user means here, and whether it works.
    presence: PresenceView,
    /// Keychain unlock asks the OS to verify the user first.
    presence_required: bool,
    /// Look for updates at launch and twice a day.
    auto_update_check: bool,
}

/// Readable while locked: the unlock screen needs it.
#[tauri::command]
pub async fn device_status(
    app: AppHandle,
    vault: State<'_, VaultState>,
) -> Result<DeviceStatus, String> {
    let (enabled, minutes, required, update_check) = {
        let v = vault.guard()?;
        (
            v.device_unlock_id().map_err(|e| e.to_string())?.is_some(),
            auto_lock_minutes(v.setting(AUTO_LOCK).map_err(|e| e.to_string())?.as_deref()),
            presence_required(&v)?,
            v.setting(UPDATE_CHECK)
                .map_err(|e| e.to_string())?
                .as_deref()
                != Some("0"),
        )
    };
    #[cfg(target_os = "android")]
    let (available, presence, required) = {
        // The check is part of the key here: always on.
        let _ = required;
        let s = crate::biometric::status(&app).await;
        let presence = PresenceView {
            kind: "biometric",
            status: if s.available { "ready" } else { "unavailable" },
            detail: s.reason,
        };
        (s.available, presence, true)
    };
    #[cfg(not(target_os = "android"))]
    let (available, presence) = {
        let _ = &app;
        let (available, presence) = tauri::async_runtime::spawn_blocking(|| {
            (keychain::available(), mg_presence::availability())
        })
        .await
        .map_err(|e| e.to_string())?;
        (available, PresenceView::from(presence))
    };
    Ok(DeviceStatus {
        keychain_available: available,
        keychain_enabled: enabled,
        auto_lock_minutes: minutes,
        presence,
        presence_required: required,
        auto_update_check: update_check,
    })
}

/// Always on iOS: there the keychain unlock is "unlock with Face ID", which iOS enforces.
fn presence_required(v: &LocalVault) -> Result<bool, String> {
    if cfg!(target_os = "ios") {
        return Ok(true);
    }
    Ok(v.setting(REQUIRE_PRESENCE)
        .map_err(|e| e.to_string())?
        .is_some_and(|s| s == "1"))
}

/// Makes keychain unlock ask the OS to verify the user first (after a successful check, so a
/// broken setup can't lock anyone out of the quick path), or stops asking.
#[tauri::command]
pub async fn presence_require(
    window: tauri::Window,
    vault: State<'_, VaultState>,
    enabled: bool,
) -> Result<(), String> {
    {
        let v = vault.guard()?;
        if v.status().map_err(|e| e.to_string())? != mg_store::Status::Unlocked {
            return Err("Unlock the vault first.".into());
        }
        if enabled && v.device_unlock_id().map_err(|e| e.to_string())?.is_none() {
            return Err("Turn on unlocking with the system keychain first.".into());
        }
    }
    if enabled {
        let parent = parent(&window);
        tauri::async_runtime::spawn_blocking(move || mg_presence::verify(CONFIRM_REASON, parent))
            .await
            .map_err(|e| e.to_string())?
            .map_err(presence_error)?;
    }
    vault
        .guard()?
        .set_setting(REQUIRE_PRESENCE, enabled.then_some("1"))
        .map_err(|e| e.to_string())
}

/// Linux: installs MorphGate's polkit action (polkit asks for an administrator password).
#[tauri::command]
pub async fn presence_setup() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(mg_presence::setup)
        .await
        .map_err(|e| e.to_string())?
        .map_err(presence_error)
}

/// Turns on unlocking from the system keychain. Asks for the master password first: this adds
/// a way into the vault.
#[tauri::command]
pub async fn keychain_enable(
    app: AppHandle,
    vault: State<'_, VaultState>,
    password: String,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    #[cfg(target_os = "android")]
    let done = enable_biometric(&app, &vault, password).await;
    #[cfg(not(target_os = "android"))]
    let done = {
        let _ = app;
        enable_keychain(&vault, password).await?;
        #[cfg(target_os = "ios")]
        confirm_keychain(&vault).await?;
        Ok(())
    };
    done
}

/// iOS: reads back the key just stored, so iOS asks for Face ID now. Where that doesn't work, the
/// unlock is turned off again rather than left to fail every time.
#[cfg(target_os = "ios")]
async fn confirm_keychain(vault: &VaultState) -> Result<(), String> {
    let id = vault
        .guard()?
        .device_unlock_id()
        .map_err(|e| e.to_string())?
        .ok_or("Unlocking with the system keychain is off.")?;
    let read = tauri::async_runtime::spawn_blocking(move || keychain::load(&id))
        .await
        .map_err(|e| e.to_string())?;
    match read {
        Ok(Some(_)) => Ok(()),
        other => {
            let _ = disable_keychain(vault).await;
            Err(other
                .err()
                .unwrap_or_else(|| "the keychain didn't keep the key".into()))
        }
    }
}

#[cfg(not(target_os = "android"))]
async fn enable_keychain(vault: &VaultState, password: Zeroizing<String>) -> Result<(), String> {
    let inner = vault.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut v = inner
            .lock()
            .map_err(|_| "vault state is poisoned".to_owned())?;
        v.verify_password(&password).map_err(|e| e.to_string())?;
        let old = v.device_unlock_id().map_err(|e| e.to_string())?;
        let (id, key) = v.enable_device_unlock().map_err(|e| e.to_string())?;
        if let Err(e) = keychain::store(&id, &key) {
            let _ = v.disable_device_unlock();
            return Err(e);
        }
        if let Some(old) = old.filter(|o| *o != id) {
            let _ = keychain::delete(&old);
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn keychain_disable(app: AppHandle, vault: State<'_, VaultState>) -> Result<(), String> {
    #[cfg(target_os = "android")]
    let done = biometric_off(&app, &vault).await;
    #[cfg(not(target_os = "android"))]
    let done = {
        let _ = app;
        disable_keychain(&vault).await
    };
    done
}

#[cfg(not(target_os = "android"))]
async fn disable_keychain(vault: &VaultState) -> Result<(), String> {
    let inner = vault.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut v = inner
            .lock()
            .map_err(|_| "vault state is poisoned".to_owned())?;
        if let Some(id) = v.device_unlock_id().map_err(|e| e.to_string())? {
            // Off here even if the keychain can't be reached; its entry is useless without the
            // wrapped keys in the vault.
            let _ = keychain::delete(&id);
        }
        v.disable_device_unlock().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Unlocks with the device key from the system keychain, after the OS verifies the user if this
/// device asks for that.
#[tauri::command]
pub async fn vault_unlock_keychain(
    app: AppHandle,
    window: tauri::Window,
    vault: State<'_, VaultState>,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = window;
        unlock_biometric(&app, &vault).await?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        let inner = vault.0.clone();
        let parent = parent(&window);
        tauri::async_runtime::spawn_blocking(move || {
            unlock_from_keychain(
                &inner,
                // iOS asks by itself when the key is read.
                || {
                    if cfg!(target_os = "ios") {
                        Ok(())
                    } else {
                        mg_presence::verify(UNLOCK_REASON, parent)
                    }
                },
                keychain::load,
            )
        })
        .await
        .map_err(|e| e.to_string())??;
    }
    vault.changed();
    Ok(())
}

/// The keychain unlock, with the OS check and the keychain passed in (tests replace both).
#[cfg(not(target_os = "android"))]
fn unlock_from_keychain(
    vault: &Mutex<LocalVault>,
    verify: impl FnOnce() -> Result<(), mg_presence::Error>,
    load: impl FnOnce(&str) -> Result<Option<DeviceKey>, String>,
) -> Result<(), String> {
    let poisoned = |_| "vault state is poisoned".to_owned();
    let (id, required) = {
        let v = vault.lock().map_err(poisoned)?;
        let id = v
            .device_unlock_id()
            .map_err(|e| e.to_string())?
            .ok_or("Unlocking with the system keychain is off.")?;
        (id, presence_required(&v)?)
    };
    // Not holding the vault while the OS dialog is up (the check, or iOS's own while the key is
    // read): that can take as long as the user likes.
    if required {
        verify().map_err(presence_error)?;
    }
    let key = load(&id)?;
    let mut v = vault.lock().map_err(poisoned)?;
    match key {
        Some(key) => v.unlock_with_device_key(&key).map_err(|e| e.to_string()),
        None => {
            let _ = v.disable_device_unlock();
            Err(
                "The key is no longer in the system keychain, so keychain unlock was turned \
                 off. Unlock with the master password."
                    .into(),
            )
        }
    }
}

/// Android: a new device key, sealed after a fingerprint or face check. Asks for the master
/// password first, as on desktops: this adds a way into the vault.
#[cfg(target_os = "android")]
async fn enable_biometric(
    app: &AppHandle,
    vault: &VaultState,
    password: Zeroizing<String>,
) -> Result<(), String> {
    let inner = vault.0.clone();
    let key = tauri::async_runtime::spawn_blocking(move || {
        let mut v = inner
            .lock()
            .map_err(|_| "vault state is poisoned".to_owned())?;
        v.verify_password(&password).map_err(|e| e.to_string())?;
        let (_, key) = v.enable_device_unlock().map_err(|e| e.to_string())?;
        Ok::<_, String>(key)
    })
    .await
    .map_err(|e| e.to_string())??;
    match crate::biometric::seal(app, key.as_bytes(), "Turn on unlocking MorphGate with it").await {
        Ok(sealed) => {
            use base64::Engine;
            let sealed = base64::engine::general_purpose::STANDARD.encode(sealed);
            vault
                .guard()?
                .set_setting(SEALED_UNLOCK, Some(&sealed))
                .map_err(|e| e.to_string())
        }
        Err(e) => {
            let _ = vault.guard()?.disable_device_unlock();
            Err(e)
        }
    }
}

/// Android: fingerprint unlock off (the Keystore key goes too). Also used when the account's
/// keys changed under it (joining an account).
#[cfg(target_os = "android")]
pub(crate) async fn biometric_off(app: &AppHandle, vault: &VaultState) -> Result<(), String> {
    let _ = crate::biometric::forget(app).await;
    let mut v = vault.guard()?;
    v.set_setting(SEALED_UNLOCK, None)
        .map_err(|e| e.to_string())?;
    v.disable_device_unlock().map_err(|e| e.to_string())
}

/// Android: opens the sealed device key with a fingerprint or face, then the vault with it.
#[cfg(target_os = "android")]
async fn unlock_biometric(app: &AppHandle, vault: &VaultState) -> Result<(), String> {
    use base64::Engine;
    let sealed = {
        let v = vault.guard()?;
        v.device_unlock_id()
            .map_err(|e| e.to_string())?
            .ok_or("Unlocking with a fingerprint or face is off.")?;
        v.setting(SEALED_UNLOCK)
            .map_err(|e| e.to_string())?
            .ok_or("Unlocking with a fingerprint or face is off.")?
    };
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(sealed)
        .map_err(|e| e.to_string())?;
    let secret = match crate::biometric::open(app, &sealed, "Use your fingerprint or face").await {
        Ok(secret) => secret,
        Err(e) => {
            // New fingerprints or faces, or a key the phone dropped: it can't come back.
            if e.lost {
                let _ = biometric_off(app, vault).await;
            }
            return Err(e.message);
        }
    };
    let bytes: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| "the stored key is damaged".to_owned())?;
    vault
        .guard()?
        .unlock_with_device_key(&DeviceKey::from_bytes(bytes))
        .map_err(|e| e.to_string())
}

/// The device's choice, else the default. Before the default, "never" was the setting's absence:
/// those devices lock after the default now.
fn auto_lock_minutes(setting: Option<&str>) -> u32 {
    setting
        .and_then(|m| m.parse().ok())
        .unwrap_or(AUTO_LOCK_DEFAULT)
}

/// `0`: never. Kept as a value, so "never" stays apart from not having chosen.
#[tauri::command]
pub fn set_auto_lock(vault: State<'_, VaultState>, minutes: u32) -> Result<(), String> {
    vault
        .guard()?
        .set_setting(AUTO_LOCK, Some(&minutes.min(24 * 60).to_string()))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_auto_update_check(vault: State<'_, VaultState>, enabled: bool) -> Result<(), String> {
    vault
        .guard()?
        .set_setting(UPDATE_CHECK, (!enabled).then_some("0"))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use mg_vault::KdfParams;

    use super::*;

    /// A locked vault that has keychain unlock on; returns it with its device key.
    fn locked_vault(require_presence: bool) -> (Mutex<LocalVault>, DeviceKey) {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        let (_, key) = v.enable_device_unlock().unwrap();
        v.set_setting(REQUIRE_PRESENCE, require_presence.then_some("1"))
            .unwrap();
        v.lock();
        (Mutex::new(v), key)
    }

    fn status(v: &Mutex<LocalVault>) -> mg_store::Status {
        v.lock().unwrap().status().unwrap()
    }

    #[test]
    fn keychain_unlock_waits_for_the_os_check() {
        let (vault, key) = locked_vault(true);
        let read = Cell::new(false);
        let load = |_: &str| {
            read.set(true);
            Ok(Some(DeviceKey::from_bytes(*key.as_bytes())))
        };

        // Cancelled or failed: the keychain isn't even read.
        let r = unlock_from_keychain(&vault, || Err(mg_presence::Error::Cancelled), load);
        assert_eq!(r, Err(CANCELLED.to_owned()));
        let r = unlock_from_keychain(
            &vault,
            || Err(mg_presence::Error::Failed("authentication failed".into())),
            load,
        );
        assert_eq!(r, Err("authentication failed".to_owned()));
        assert!(!read.get());
        assert_eq!(status(&vault), mg_store::Status::Locked);

        unlock_from_keychain(&vault, || Ok(()), load).unwrap();
        assert!(read.get());
        assert_eq!(status(&vault), mg_store::Status::Unlocked);
    }

    #[test]
    fn without_the_setting_there_is_no_prompt() {
        let (vault, key) = locked_vault(false);
        unlock_from_keychain(
            &vault,
            || panic!("must not ask the OS"),
            |_| Ok(Some(DeviceKey::from_bytes(*key.as_bytes()))),
        )
        .unwrap();
        assert_eq!(status(&vault), mg_store::Status::Unlocked);
    }

    #[test]
    fn auto_lock_is_15_minutes_until_chosen() {
        assert_eq!(auto_lock_minutes(None), 15);
        assert_eq!(auto_lock_minutes(Some("0")), 0);
        assert_eq!(auto_lock_minutes(Some("60")), 60);
        assert_eq!(auto_lock_minutes(Some("soon")), 15);
    }

    #[test]
    fn presence_views_match_the_frontend() {
        let v = |kind, status| {
            serde_json::to_value(PresenceView::from(mg_presence::Availability {
                kind,
                status,
            }))
            .unwrap()
        };
        assert_eq!(
            v(Kind::TouchId, Status::Ready),
            serde_json::json!({ "kind": "touchId", "status": "ready" })
        );
        assert_eq!(
            v(Kind::System, Status::NeedsSetup),
            serde_json::json!({ "kind": "system", "status": "setup" })
        );
        assert_eq!(
            v(Kind::FaceId, Status::Ready),
            serde_json::json!({ "kind": "faceId", "status": "ready" })
        );
        assert_eq!(
            v(Kind::Passcode, Status::Ready),
            serde_json::json!({ "kind": "passcode", "status": "ready" })
        );
        assert_eq!(
            v(Kind::WindowsHello, Status::Unavailable("no PIN".into())),
            serde_json::json!({ "kind": "windowsHello", "status": "unavailable", "detail": "no PIN" })
        );
    }
}
