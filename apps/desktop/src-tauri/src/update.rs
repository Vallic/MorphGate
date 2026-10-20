//! Updates from MorphGate's release feed (GitHub Releases). Every update is signed with
//! MorphGate's update key; the plugin checks it against the public key built into the app
//! (`plugins.updater.pubkey`) before anything is installed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::utils::config::BundleType;
use tauri::{AppHandle, State};
use tauri_plugin_updater::Update;
#[cfg(desktop)]
use tauri_plugin_updater::UpdaterExt;

/// Another feed, for trying the update path against a local server. Updates from it must still
/// carry MorphGate's signature.
#[cfg(desktop)]
const ENDPOINT_ENV: &str = "MORPHGATE_UPDATE_ENDPOINT";

/// The update found by the last check, kept for `update_install`.
#[derive(Default)]
pub struct UpdateState(Mutex<Option<Update>>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    version: String,
    /// How this copy was installed: "appimage", "deb", "rpm", "app", "msi" or "nsis". Absent for
    /// a development build, which can't update itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<&'static str>,
}

fn package_name(bundle: BundleType) -> &'static str {
    match bundle {
        BundleType::AppImage => "appimage",
        BundleType::Deb => "deb",
        BundleType::Rpm => "rpm",
        BundleType::App => "app",
        BundleType::Dmg => "dmg",
        BundleType::Msi => "msi",
        BundleType::Nsis => "nsis",
    }
}

#[tauri::command]
pub fn about(app: AppHandle) -> About {
    About {
        version: app.package_info().version.to_string(),
        package: tauri::utils::platform::bundle_type().map(package_name),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    /// RFC 3339, as published.
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<String>,
}

/// Phones update through their app store.
#[cfg(mobile)]
fn updater(_: &AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    Err("On phones, MorphGate updates through the app store.".into())
}

#[cfg(desktop)]
fn updater(app: &AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    let mut builder = app.updater_builder();
    if let Some(url) = std::env::var(ENDPOINT_ENV).ok().filter(|u| !u.is_empty()) {
        let url = url.parse().map_err(|e| format!("{ENDPOINT_ENV}: {e}"))?;
        builder = builder.endpoints(vec![url]).map_err(|e| e.to_string())?;
    }
    builder.build().map_err(|e| e.to_string())
}

/// The newer release, if there is one.
#[tauri::command]
pub async fn update_check(
    app: AppHandle,
    state: State<'_, UpdateState>,
) -> Result<Option<UpdateInfo>, String> {
    let update = updater(&app)?
        .check()
        .await
        .map_err(|e| format!("Couldn't check for updates: {e}"))?;
    let info = update.as_ref().map(|u| UpdateInfo {
        version: u.version.clone(),
        notes: u.body.clone().filter(|b| !b.trim().is_empty()),
        date: u.raw_json["pub_date"].as_str().map(str::to_owned),
    });
    *state.0.lock().map_err(|_| "update state is poisoned")? = update;
    Ok(info)
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Progress {
    Downloading { downloaded: u64, total: Option<u64> },
    Installing,
}

/// Downloads, verifies and installs the update found by the last check, then restarts
/// (sessions, tunnels and VPNs close on the way out).
#[tauri::command]
pub async fn update_install(
    app: AppHandle,
    state: State<'_, UpdateState>,
    on_progress: Channel<Progress>,
) -> Result<(), String> {
    let update = state
        .0
        .lock()
        .map_err(|_| "update state is poisoned")?
        .take()
        .ok_or("Check for updates first.")?;
    let mut downloaded = 0u64;
    let mut last = Instant::now() - Duration::from_secs(1);
    let installed = update
        .download_and_install(
            |chunk, total| {
                downloaded += chunk as u64;
                // A few updates a second are plenty for a progress bar.
                if last.elapsed() >= Duration::from_millis(100) || Some(downloaded) == total {
                    last = Instant::now();
                    let _ = on_progress.send(Progress::Downloading { downloaded, total });
                }
            },
            || {
                let _ = on_progress.send(Progress::Installing);
            },
        )
        .await;
    if let Err(e) = installed {
        // Keep it, so "Install" can be tried again without another check.
        if let Ok(mut slot) = state.0.lock() {
            slot.get_or_insert(update);
        }
        return Err(format!("The update couldn't be installed: {e}"));
    }
    app.restart()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes_match_the_frontend() {
        assert_eq!(
            serde_json::to_value(Progress::Downloading {
                downloaded: 5,
                total: Some(9)
            })
            .unwrap(),
            json!({ "kind": "downloading", "downloaded": 5, "total": 9 })
        );
        assert_eq!(
            serde_json::to_value(Progress::Installing).unwrap(),
            json!({ "kind": "installing" })
        );
        assert_eq!(package_name(BundleType::AppImage), "appimage");
        let about = About {
            version: "1.2.3".into(),
            package: None,
        };
        assert_eq!(
            serde_json::to_value(about).unwrap(),
            json!({ "version": "1.2.3" })
        );
    }
}
