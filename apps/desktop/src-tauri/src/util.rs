use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager};
use tauri_plugin_opener::OpenerExt;

/// `~/x` → `$HOME/x`; anything else unchanged.
pub fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

/// `$HOME/x` → `~/x`, for showing a path; anything else unchanged.
pub fn tilde(path: &Path) -> String {
    match std::env::home_dir().and_then(|home| path.strip_prefix(home).ok().map(Path::to_owned)) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// A new file in the downloads folder (the home folder without one): `stem.ext`, or
/// `stem-2.ext` and so on when that's taken. `stem` is made safe for a file name. On iOS, the
/// app's Documents folder, which the Files app shows as MorphGate's (`UIFileSharingEnabled`).
pub fn download_path(app: &AppHandle, stem: &str, ext: &str) -> Result<PathBuf, String> {
    #[cfg(target_os = "ios")]
    let dir = app.path().document_dir().map_err(|e| e.to_string())?;
    #[cfg(not(target_os = "ios"))]
    let dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().home_dir())
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let stem: String = stem
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut path = dir.join(format!("{stem}.{ext}"));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = dir.join(format!("{stem}-{n}.{ext}"));
    }
    Ok(path)
}

/// A file [`download_path`] made, as the user finds it: `~/Downloads/x.json`, or on iOS
/// `x.json in Files › MorphGate`. Follows "Saved".
pub fn saved(path: &Path) -> String {
    #[cfg(target_os = "ios")]
    if let Some(name) = path.file_name() {
        return format!("{} in Files › MorphGate", name.to_string_lossy());
    }
    tilde(path)
}

/// Opens a web page in the browser (`MORPHGATE_BROWSER` names another program to open it with,
/// as the e2e tests do).
pub fn open_in_browser(app: &AppHandle, url: &str) -> Result<(), String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("only web pages open in the browser".into());
    }
    match std::env::var("MORPHGATE_BROWSER")
        .ok()
        .filter(|b| !b.is_empty())
    {
        Some(browser) => {
            let mut child = std::process::Command::new(browser)
                .arg(url)
                .spawn()
                .map_err(|e| format!("cannot open {url}: {e}"))?;
            std::thread::spawn(move || child.wait());
            Ok(())
        }
        None => app
            .opener()
            .open_url(url, None::<&str>)
            .map_err(|e| format!("cannot open {url}: {e}")),
    }
}

/// A link the app shows (an upgrade page, a sign-in page that didn't open by itself).
#[tauri::command]
pub fn open_link(app: AppHandle, url: String) -> Result<(), String> {
    open_in_browser(&app, &url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_undoes_expand_home() {
        let p = expand_home("~/.local/share/known_hosts");
        assert_eq!(tilde(&p), "~/.local/share/known_hosts");
        assert_eq!(
            tilde(Path::new("/etc/ssh/ssh_known_hosts")),
            "/etc/ssh/ssh_known_hosts"
        );
    }
}
