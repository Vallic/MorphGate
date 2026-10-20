//! Renewing a key's short-lived certificate: a command run on this device, given the key's public
//! key, that prints the new certificate (or leaves it in a file). Before a connection whose keys'
//! certificates are missing or run out within five minutes, and on demand.
//! The command comes with the vault, so it runs only where this device allowed it (proxy.rs keeps
//! that list, by the command's text).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mg_store::{CertRenewal, HostAuth, ItemData, LocalVault, SshKey};
use serde::Deserialize;
use tauri::State;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::ssh::Target;
use crate::util::expand_home;
use crate::vault::{KeyView, VaultState, save};

/// A certificate that runs out within this many seconds is renewed before connecting.
const SOON: u64 = 300;

/// A renewal may sign in through the browser first (step-ca, Vault with OIDC).
const TIMEOUT: Duration = Duration::from_secs(180);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// When the key's certificate runs out (unix seconds): `None` for none (or one that isn't for it).
fn expires(key: &SshKey) -> Option<u64> {
    let text = key.certificate.as_deref()?;
    mg_ssh::keys::certificate(text, &key.public_key)
        .ok()
        .map(|c| c.valid_before)
}

/// Runs `command` through this system's shell.
fn shell(command: &str) -> Command {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = Command::new("cmd");
        c.raw_arg("/D /S /C \"").raw_arg(command).raw_arg("\"");
        c.creation_flags(CREATE_NO_WINDOW);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    }
}

/// `path` as one word for the shell.
fn quoted(path: &Path) -> String {
    let p = path.display().to_string();
    if cfg!(windows) {
        format!("\"{p}\"")
    } else {
        format!("'{}'", p.replace('\'', "'\\''"))
    }
}

/// `%k` (the public key's file) and `%%` in the command.
fn expand(command: &str, key_file: &Path) -> String {
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('%', Some('k')) => {
                chars.next();
                out.push_str(&quoted(key_file));
            }
            ('%', Some('%')) => {
                chars.next();
                out.push('%');
            }
            _ => out.push(c),
        }
    }
    out
}

/// A folder of its own for the public key file, removed when done.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the renewal and returns what it gave: the certificate it printed, the one `ssh-keygen -s`
/// left beside the key file, or the one in `file`.
async fn run(renewal: &CertRenewal, public_key: &str) -> Result<String, String> {
    let dir = std::env::temp_dir().join(format!("morphgate-renew-{}", ulid::Ulid::generate()));
    std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let scratch = Scratch(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o700));
    }
    let key_file = scratch.0.join("key.pub");
    std::fs::write(&key_file, format!("{}\n", public_key.trim()))
        .map_err(|e| format!("{}: {e}", key_file.display()))?;
    let mut child = shell(&expand(&renewal.command, &key_file))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin
            .write_all(format!("{}\n", public_key.trim()).as_bytes())
            .await;
    }
    let output = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("it took longer than {} s", TIMEOUT.as_secs()))?
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let said = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if said.is_empty() {
            format!("it failed ({})", output.status)
        } else {
            said
        });
    }
    let printed = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = printed
        .lines()
        .map(str::trim)
        .find(|l| l.contains("-cert-v01@openssh.com"))
    {
        return Ok(line.to_owned());
    }
    let beside = scratch.0.join("key-cert.pub");
    if let Ok(text) = std::fs::read_to_string(&beside) {
        return Ok(text);
    }
    match &renewal.file {
        Some(file) => {
            let path = expand_home(file.trim());
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
        }
        None => Err("it gave no certificate: print it, or say which file it's left in".into()),
    }
}

/// Renews the certificate of key `key_id` when it's due (or `force`). `Ok(false)`: nothing to do.
pub(crate) async fn renew(vault: &VaultState, key_id: &str, force: bool) -> Result<bool, String> {
    let (key, allowed) = {
        let v = vault.guard()?;
        let ItemData::SshKey(key) = v.item(key_id).map_err(|e| e.to_string())?.data else {
            return Err("not an SSH key".into());
        };
        let allowed = key
            .renew
            .as_ref()
            .is_some_and(|r| crate::proxy::allowed(&v, &r.command));
        (key, allowed)
    };
    let Some(renewal) = key.renew.clone() else {
        return Ok(false);
    };
    if !force && expires(&key).is_some_and(|until| until > now() + SOON) {
        return Ok(false);
    }
    if cfg!(mobile) {
        return Err(
            "renewing it runs a command on the computer: renew it from the desktop app".into(),
        );
    }
    if !allowed {
        return Err(format!(
            "this device hasn't allowed its renewal command: {}. Open the key to allow it.",
            renewal.command
        ));
    }
    let text = run(&renewal, &key.public_key).await?;
    let cert = mg_ssh::keys::certificate(&text, &key.public_key)
        .map_err(|e| format!("the certificate it gave: {e}"))?;
    {
        let mut v = vault.guard()?;
        let ItemData::SshKey(mut current) = v.item(key_id).map_err(|e| e.to_string())?.data else {
            return Err("not an SSH key".into());
        };
        current.certificate = Some(cert.certificate);
        save(&mut v, Some(key_id), None, ItemData::SshKey(current)).map_err(|e| e.to_string())?;
    }
    vault.changed();
    Ok(true)
}

/// The keys a connection to `host_id` signs in with, along its route, by id and name.
fn route_keys(v: &LocalVault, host_id: &str) -> Result<Vec<(String, String)>, String> {
    let (jumps, target) = v.route(host_id).map_err(|e| e.to_string())?;
    let mut out: Vec<(String, String)> = Vec::new();
    for item in jumps.iter().chain(std::iter::once(&target)) {
        let Ok(host) = v.effective_host(item) else {
            continue;
        };
        if let HostAuth::Key { key_ref } = host.auth
            && !out.iter().any(|(id, _)| id == &key_ref)
            && let Ok(mg_store::Item {
                data: ItemData::SshKey(k),
                ..
            }) = v.item(&key_ref)
            && k.renew.is_some()
        {
            out.push((key_ref, k.label));
        }
    }
    Ok(out)
}

/// Before connecting: renews the certificates of the keys on the way that are due. One that can't
/// be renewed but still works for now is used as it is.
pub(crate) async fn before_connect(vault: &VaultState, target: &Target) -> Result<(), String> {
    let Target::Saved { host_id, .. } = target else {
        return Ok(());
    };
    let keys = route_keys(&*vault.guard()?, host_id)?;
    for (key_id, label) in keys {
        if let Err(e) = renew(vault, &key_id, false).await {
            let usable = {
                let v = vault.guard()?;
                matches!(v.item(&key_id).map(|i| i.data), Ok(ItemData::SshKey(k)) if expires(&k).is_some_and(|until| until > now()))
            };
            if !usable {
                return Err(format!("renewing the certificate of key \"{label}\": {e}"));
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenewalInput {
    command: String,
    #[serde(default)]
    file: Option<String>,
}

fn view(v: &LocalVault, key_id: &str) -> Result<KeyView, String> {
    let item = v.item(key_id).map_err(|e| e.to_string())?;
    match item.data {
        ItemData::SshKey(k) => Ok(KeyView::new(v, item.id, item.vault_id, item.updated_at, k)),
        _ => Err("not an SSH key".into()),
    }
}

/// How a key's certificate is renewed (`None`: it isn't). A command typed here is allowed on
/// this device.
#[tauri::command]
pub fn key_renewal(
    vault: State<'_, VaultState>,
    id: String,
    renewal: Option<RenewalInput>,
) -> Result<KeyView, String> {
    let renewal = renewal
        .map(|r| CertRenewal {
            command: r.command.trim().to_owned(),
            file: r
                .file
                .map(|f| f.trim().to_owned())
                .filter(|f| !f.is_empty()),
        })
        .filter(|r| !r.command.is_empty());
    let out = {
        let mut v = vault.guard()?;
        let ItemData::SshKey(mut key) = v.item(&id).map_err(|e| e.to_string())?.data else {
            return Err("not an SSH key".into());
        };
        let before = key.renew.as_ref().map(|r| r.command.clone());
        if let Some(r) = renewal
            .as_ref()
            .filter(|r| before.as_ref() != Some(&r.command))
        {
            crate::proxy::allow(&v, &r.command)?;
        }
        key.renew = renewal;
        save(&mut v, Some(&id), None, ItemData::SshKey(key)).map_err(|e| e.to_string())?;
        view(&v, &id)?
    };
    vault.changed();
    Ok(out)
}

/// Lets this device run the key's renewal command (one that came with the vault).
#[tauri::command]
pub fn key_allow_renewal(vault: State<'_, VaultState>, id: String) -> Result<KeyView, String> {
    let v = vault.guard()?;
    let ItemData::SshKey(key) = v.item(&id).map_err(|e| e.to_string())?.data else {
        return Err("not an SSH key".into());
    };
    let command = key.renew.ok_or("the key has no renewal command")?.command;
    crate::proxy::allow(&v, &command)?;
    view(&v, &id)
}

/// Renews the key's certificate now.
#[tauri::command]
pub async fn key_renew(vault: State<'_, VaultState>, id: String) -> Result<KeyView, String> {
    renew(&vault, &id, true).await?;
    view(&*vault.guard()?, &id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_file_goes_where_k_is() {
        let path = Path::new("/tmp/renew/key.pub");
        assert_eq!(
            expand("vault write ssh/sign/deploy public_key=@%k 100%%", path),
            if cfg!(windows) {
                "vault write ssh/sign/deploy public_key=@\"/tmp/renew/key.pub\" 100%".to_owned()
            } else {
                "vault write ssh/sign/deploy public_key=@'/tmp/renew/key.pub' 100%".to_owned()
            }
        );
    }

    /// A host's key without a certificate, renewed by `ssh-keygen -s` before connecting: refused
    /// until this device allows the command; once renewed, not again while it's good.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_due_certificate_is_renewed_before_connecting() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca");
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ca)
            .status();
        if !made.is_ok_and(|s| s.success()) {
            return;
        }
        let state = VaultState::open(
            &dir.path().join("vault.sqlite3"),
            std::sync::Arc::new(tokio::sync::Notify::new()),
        )
        .unwrap();
        let command = format!(
            "ssh-keygen -q -s '{}' -I renewed -n deploy -V -5m:+1h %k",
            ca.display()
        );
        let (key_id, host_id) = {
            let mut g = state.guard().unwrap();
            let v = std::mem::replace(&mut *g, LocalVault::open_in_memory().unwrap());
            *g = v.with_kdf_cost(
                mg_vault::KdfParams::MIN_M_KIB,
                mg_vault::KdfParams::MIN_T,
                1,
            );
            g.create("correct horse battery").unwrap();
            let (pem, info) = mg_ssh::keys::generate_ed25519("deploy").unwrap();
            let key = g
                .upsert(
                    None,
                    ItemData::SshKey(SshKey {
                        label: "deploy".into(),
                        private_key: pem.to_string(),
                        passphrase: None,
                        public_key: info.public_key,
                        algorithm: info.algorithm,
                        fingerprint: info.fingerprint,
                        certificate: None,
                        renew: Some(CertRenewal {
                            command: command.clone(),
                            file: None,
                        }),
                    }),
                )
                .unwrap()
                .id;
            let host = g
                .upsert(
                    None,
                    ItemData::Host(mg_store::Host {
                        label: "web".into(),
                        hostname: "web.example".into(),
                        port: 22,
                        user: "deploy".into(),
                        auth: HostAuth::Key {
                            key_ref: key.clone(),
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
                        proxy_command: None,
                        source: None,
                    }),
                )
                .unwrap()
                .id;
            (key, host)
        };
        let target = || Target::Saved {
            host_id: host_id.clone(),
            password: None,
            tmux: None,
        };
        let e = before_connect(&state, &target()).await.unwrap_err();
        assert!(e.contains("hasn't allowed its renewal command"), "{e}");
        crate::proxy::allow(&state.guard().unwrap(), &command).unwrap();
        before_connect(&state, &target()).await.unwrap();
        let key = |state: &VaultState| match state.guard().unwrap().item(&key_id).unwrap() {
            mg_store::Item {
                data: ItemData::SshKey(k),
                updated_at,
                ..
            } => (k, updated_at),
            _ => unreachable!(),
        };
        let (renewed, at) = key(&state);
        let cert =
            mg_ssh::keys::certificate(renewed.certificate.as_deref().unwrap(), &renewed.public_key)
                .unwrap();
        assert_eq!(cert.key_id, "renewed");
        // Good for an hour: not renewed again.
        before_connect(&state, &target()).await.unwrap();
        assert_eq!(key(&state).1, at);
    }

    /// `ssh-keygen -s` signs the key file and leaves the certificate beside it; a command that
    /// prints it works too; one that fails says why.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_certificate_from_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ca)
            .status();
        if !status.is_ok_and(|s| s.success()) {
            return; // no ssh-keygen here
        }
        let (_, info) = mg_ssh::keys::generate_ed25519("me").unwrap();
        let signed = run(
            &CertRenewal {
                command: format!(
                    "ssh-keygen -q -s '{}' -I renewed -n deploy -V -5m:+1h %k",
                    ca.display()
                ),
                file: None,
            },
            &info.public_key,
        )
        .await
        .unwrap();
        let cert = mg_ssh::keys::certificate(&signed, &info.public_key).unwrap();
        assert_eq!(cert.key_id, "renewed");
        assert_eq!(cert.principals, ["deploy"]);

        let printed = run(
            &CertRenewal {
                command: format!("cat '{}'", dir.path().join("none").display()),
                file: None,
            },
            &info.public_key,
        )
        .await
        .unwrap_err();
        assert!(printed.contains("No such file"), "{printed}");

        let silent = run(
            &CertRenewal {
                command: "true".into(),
                file: None,
            },
            &info.public_key,
        )
        .await
        .unwrap_err();
        assert!(silent.contains("gave no certificate"), "{silent}");
    }
}
