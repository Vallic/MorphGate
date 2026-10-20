//! Android: unlocking with a fingerprint or face. The device key that unwraps the vault's account
//! keys (as the system keychain holds it on desktops) is sealed with a key in Android's Keystore
//! that Android only lets the app use right after a strong biometric check
//! (`gen/android/app/src/main/java/com/morphgate/app/BiometricKeyPlugin.kt`). The sealed bytes are
//! kept in the vault's device settings; without the check they are useless.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tauri::plugin::mobile::PluginInvokeError;
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{AppHandle, Manager, Wry};
use zeroize::Zeroizing;

struct BiometricKey(PluginHandle<Wry>);

pub fn init() -> TauriPlugin<Wry> {
    Builder::new("biometric-key")
        .setup(|app, api| {
            let handle = api.register_android_plugin("com.morphgate.app", "BiometricKeyPlugin")?;
            app.manage(BiometricKey(handle));
            Ok(())
        })
        .build()
}

#[derive(Deserialize)]
pub struct Status {
    pub available: bool,
    /// Why not, for the user.
    pub reason: Option<String>,
}

#[derive(Serialize)]
struct Prompt<'a> {
    title: &'a str,
    subtitle: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed: Option<String>,
}

#[derive(Deserialize)]
struct Sealed {
    sealed: String,
}

#[derive(Deserialize)]
struct Opened {
    secret: String,
}

fn plugin(app: &AppHandle) -> Result<&PluginHandle<Wry>, String> {
    app.try_state::<BiometricKey>()
        .map(|s| &s.inner().0)
        .ok_or_else(|| "fingerprint unlock isn't set up in this build".to_owned())
}

/// What the device commands show: a cancelled prompt is "cancelled" (the UI shows nothing), new
/// fingerprints or faces get an explanation.
fn describe(e: PluginInvokeError) -> String {
    match e {
        PluginInvokeError::InvokeRejected(r) => match r.code.as_deref() {
            Some("CANCELLED") => crate::device::CANCELLED.into(),
            Some("INVALIDATED") => "The fingerprints or faces on this phone changed, so unlocking with them stopped working: \
                 unlock with the master password, then turn it on again in Security."
                .into(),
            _ => r.message.unwrap_or_else(|| "the fingerprint check failed".into()),
        },
        other => other.to_string(),
    }
}

pub async fn status(app: &AppHandle) -> Status {
    let unavailable = |reason: String| Status {
        available: false,
        reason: Some(reason),
    };
    match plugin(app) {
        Ok(p) => p
            .run_mobile_plugin_async::<Status>("status", ())
            .await
            .unwrap_or_else(|e| unavailable(describe(e))),
        Err(e) => unavailable(e),
    }
}

/// Seals `secret` after a fingerprint or face check (a new Keystore key each time).
pub async fn seal(app: &AppHandle, secret: &[u8], subtitle: &str) -> Result<Vec<u8>, String> {
    let out: Sealed = plugin(app)?
        .run_mobile_plugin_async(
            "seal",
            Prompt {
                title: "Unlock with fingerprint or face",
                subtitle,
                secret: Some(STANDARD.encode(secret)),
                sealed: None,
            },
        )
        .await
        .map_err(describe)?;
    STANDARD.decode(out.sealed).map_err(|e| e.to_string())
}

/// Why [`open`] failed.
pub struct OpenError {
    /// The Keystore key can't come back (new fingerprints or faces, or the phone dropped it).
    pub lost: bool,
    pub message: String,
}

/// Opens what [`seal`] returned, after a fingerprint or face check.
pub async fn open(
    app: &AppHandle,
    sealed: &[u8],
    subtitle: &str,
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let failed = |message: String| OpenError {
        lost: false,
        message,
    };
    let out: Opened = plugin(app)
        .map_err(failed)?
        .run_mobile_plugin_async(
            "open",
            Prompt {
                title: "Unlock MorphGate",
                subtitle,
                secret: None,
                sealed: Some(STANDARD.encode(sealed)),
            },
        )
        .await
        .map_err(|e| {
            let lost = matches!(&e, PluginInvokeError::InvokeRejected(r)
                if matches!(r.code.as_deref(), Some("INVALIDATED" | "GONE")));
            OpenError {
                lost,
                message: describe(e),
            }
        })?;
    let secret = Zeroizing::new(out.secret);
    STANDARD
        .decode(secret.as_bytes())
        .map(Zeroizing::new)
        .map_err(|e| failed(e.to_string()))
}

/// Deletes the Keystore key.
pub async fn forget(app: &AppHandle) -> Result<(), String> {
    plugin(app)?
        .run_mobile_plugin_async::<serde_json::Value>("forget", ())
        .await
        .map(|_| ())
        .map_err(describe)
}
