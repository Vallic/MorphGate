//! Offboarding someone from an organization: what they could read, finding and removing their
//! SSH keys on the organization's hosts, and replacing a shared SSH key everywhere it's
//! installed. Removing the member and rotating vault keys are the Teams commands.

use std::time::Duration;

use mg_ssh::authorized_keys::{self, KeyData, PATH};
use mg_ssh::{Auth, Connection, Sftp};
use mg_store::{Access, HostAuth, ItemData, SshKey};
use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::orgs::with_client;
use crate::ssh::{SshState, Target, resolve};
use crate::sync::SyncState;
use crate::vault::VaultState;
use crate::vpn::VpnManager;

const CONNECT: Duration = Duration::from_secs(15);

/// One vault the member could open, and what's in it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReachView {
    vault_id: String,
    name: String,
    access: Access,
    hosts: usize,
    keys: usize,
    vpns: usize,
    other: usize,
    /// The member key directory (public keys only).
    directory: bool,
}

/// A secret the member could read, to change after they leave.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretView {
    /// `password` (a host's saved password), `key` (a shared SSH key), `vpn`, or `feed` (a
    /// feed's token, to rotate where the feed is published).
    kind: &'static str,
    item_id: String,
    label: String,
    vault_name: String,
    /// Keys: the hosts that log in with it.
    used_by: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    vaults: Vec<ReachView>,
    secrets: Vec<SecretView>,
    /// Their published SSH keys (fingerprints), the ones a host scan looks for.
    keys: Vec<String>,
}

/// What a member can open in the organization (their vault access, from the server) and what
/// that exposes (from this device's copy). Owners and admins only.
#[tauri::command]
pub async fn offboard_summary(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
) -> Result<Summary, String> {
    let vaults: Vec<_> = vault
        .guard()?
        .vaults()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|v| v.org_id.as_deref() == Some(org_id.as_str()))
        .collect();
    let ids: Vec<String> = vaults.iter().map(|v| v.id.clone()).collect();
    let access = with_client(&sync, &vault, async |c| {
        let mut out = Vec::new();
        for id in &ids {
            let members = c.vault_members(id).await?;
            out.push(
                members
                    .into_iter()
                    .find(|m| m.account_id == account_id)
                    .map(|m| m.permission),
            );
        }
        Ok(out)
    })
    .await?;

    let v = vault.guard()?;
    let items = v.items().map_err(|e| e.to_string())?;
    let mut reach = Vec::new();
    let mut secrets = Vec::new();
    for (info, permission) in vaults.iter().zip(access) {
        let Some(permission) = permission else {
            continue;
        };
        let name = info.name.clone().unwrap_or_else(|| "Shared vault".into());
        let mut r = ReachView {
            vault_id: info.id.clone(),
            name: name.clone(),
            access: match permission {
                mg_sync::Permission::Read => Access::Read,
                mg_sync::Permission::Write => Access::Write,
                mg_sync::Permission::Manage => Access::Manage,
            },
            hosts: 0,
            keys: 0,
            vpns: 0,
            other: 0,
            directory: info.directory,
        };
        for item in items.iter().filter(|i| i.vault_id == info.id) {
            match &item.data {
                ItemData::Host(h) => {
                    r.hosts += 1;
                    if matches!(&h.auth, HostAuth::Password { password: Some(_) }) {
                        secrets.push(SecretView {
                            kind: "password",
                            item_id: item.id.clone(),
                            label: h.label.clone(),
                            vault_name: name.clone(),
                            used_by: Vec::new(),
                        });
                    }
                }
                // Shared credentials: a saved password is a secret like a host's.
                ItemData::Identity(i) => {
                    r.other += 1;
                    if matches!(&i.auth, HostAuth::Password { password: Some(_) }) {
                        secrets.push(SecretView {
                            kind: "password",
                            item_id: item.id.clone(),
                            label: i.label.clone(),
                            vault_name: name.clone(),
                            used_by: Vec::new(),
                        });
                    }
                }
                ItemData::SshKey(k) => {
                    r.keys += 1;
                    secrets.push(SecretView {
                        kind: "key",
                        item_id: item.id.clone(),
                        label: k.label.clone(),
                        vault_name: name.clone(),
                        used_by: hosts_using(&v, &items, &item.id),
                    });
                }
                ItemData::Vpn(p) => {
                    r.vpns += 1;
                    secrets.push(SecretView {
                        kind: "vpn",
                        item_id: item.id.clone(),
                        label: p.label.clone(),
                        vault_name: name.clone(),
                        used_by: Vec::new(),
                    });
                }
                ItemData::CloudSource(c) if c.token.is_some() => {
                    r.other += 1;
                    secrets.push(SecretView {
                        kind: "feed",
                        item_id: item.id.clone(),
                        label: c.label.clone(),
                        vault_name: name.clone(),
                        used_by: Vec::new(),
                    });
                }
                ItemData::MemberKey(_) => {}
                _ => r.other += 1,
            }
        }
        reach.push(r);
    }
    let keys = v
        .member_keys(&org_id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|k| k.account_id == account_id && k.verified)
        .map(|k| mg_ssh::keys::public_fingerprint(&k.public_key).unwrap_or(k.public_key))
        .collect();
    Ok(Summary {
        vaults: reach,
        secrets,
        keys,
    })
}

/// Hosts that sign in with the key, themselves or through an identity or group.
fn hosts_using(v: &mg_store::LocalVault, items: &[mg_store::Item], key_id: &str) -> Vec<String> {
    items
        .iter()
        .filter(|i| matches!(i.data, ItemData::Host(_)))
        .filter_map(|i| v.effective_host(i).ok())
        .filter(|h| matches!(&h.auth, HostAuth::Key { key_ref } if key_ref == key_id))
        .map(|h| h.label)
        .collect()
}

/// A host checked for, or cleaned of, someone's keys.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    host_id: String,
    label: String,
    /// Lines found (scan) or removed (clean); `None` when the host couldn't be checked.
    keys: Option<usize>,
    problem: Option<String>,
}

/// The cloud that decides who signs in to a host, where that isn't the host's `authorized_keys`:
/// one whose SSH opens a shell in the customer's container, not on a machine (Vallic Cloud's: no
/// SFTP, nothing to edit), and lets people in by their account there.
fn account_cloud(v: &mg_store::LocalVault, h: &mg_store::Host) -> Option<String> {
    let source = h.source.as_ref().filter(|s| s.no_sftp)?;
    Some(match v.item(&source.source_ref).map(|i| i.data) {
        Ok(ItemData::CloudSource(c)) => c.label,
        _ => "its cloud".to_owned(),
    })
}

/// The organization's hosts (in vaults this device can open, the directory aside), with why a
/// host's keys can't be looked at, where they can't.
fn org_hosts(
    vault: &VaultState,
    org: &str,
) -> Result<Vec<(String, String, Option<String>)>, String> {
    let v = vault.guard()?;
    let vaults: Vec<String> = v
        .vaults()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|x| x.org_id.as_deref() == Some(org) && !x.directory)
        .map(|x| x.id)
        .collect();
    let mut hosts: Vec<(String, String, Option<String>)> = v
        .items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|i| vaults.contains(&i.vault_id))
        .filter_map(|i| match i.data {
            ItemData::Host(h) => {
                let skip = account_cloud(&v, &h).map(|cloud| {
                    format!(
                        "skipped: {cloud} lets people in by their account there, not by \
                         authorized_keys; remove their access there"
                    )
                });
                Some((i.id, h.label, skip))
            }
            _ => None,
        })
        .collect();
    hosts.sort_by_key(|h| h.1.to_lowercase());
    Ok(hosts)
}

/// The member's published, verified keys.
fn member_keys(vault: &VaultState, org: &str, account: &str) -> Result<Vec<KeyData>, String> {
    Ok(vault
        .guard()?
        .member_keys(org)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|k| k.account_id == account && k.verified)
        .filter_map(|k| authorized_keys::public_key(&k.public_key))
        .collect())
}

/// SFTP to a saved host with its saved credentials, or `with_key` instead of its own auth.
async fn sftp(
    app: &AppHandle,
    ssh: &SshState,
    vault: &VaultState,
    vpns: &VpnManager,
    host_id: &str,
    with_key: Option<&str>,
) -> Result<Sftp, String> {
    let crate::ssh::Resolved {
        mut target,
        jumps,
        vpn,
        proxy,
    } = resolve(
        Target::Saved {
            host_id: host_id.to_owned(),
            password: None,
            tmux: None,
        },
        vault,
    )
    .map_err(|e| {
        if e == "password required" {
            "asks for a password every time (save one to include it)".to_owned()
        } else {
            e
        }
    })?;
    if let Some(pem) = with_key {
        target.auth = Auth::Key {
            private_key: Zeroizing::new(pem.to_owned()),
            passphrase: None,
            certificate: None,
        };
    }
    let dialer = crate::ssh::first_hop(app, vault, vpns, vpn, proxy).await?;
    crate::host_cas::trust(vault, &ssh.known_hosts);
    let conn = Connection::open(
        target,
        jumps,
        dialer,
        CONNECT,
        ssh.known_hosts.clone(),
        ssh.prompt(app.clone()),
    )
    .await
    .map_err(|e| crate::ssh::connect_error(app, e))?;
    Sftp::open(std::sync::Arc::new(conn))
        .await
        .map_err(|e| e.to_string())
}

/// Removes `remove` and adds `add` in one host's `authorized_keys`; returns how many lines
/// went. Checks the result by reading it back.
async fn edit_keys(sftp: &Sftp, remove: &[KeyData], add: Option<&str>) -> Result<usize, String> {
    let before = authorized_keys::read(sftp, PATH)
        .await
        .map_err(|e| e.to_string())?;
    let (mut after, removed) = authorized_keys::remove(&before, remove);
    if let Some(line) = add
        && let Some(with) = authorized_keys::add(&after, line)
    {
        after = with;
    }
    if after != before {
        authorized_keys::write(sftp, PATH, &after)
            .await
            .map_err(|e| e.to_string())?;
        let check = authorized_keys::read(sftp, PATH)
            .await
            .map_err(|e| e.to_string())?;
        if check != after {
            return Err("the file changed while it was being edited; check it by hand".into());
        }
    }
    Ok(removed)
}

/// Looks for the member's published keys in `~/.ssh/authorized_keys` on every organization host.
#[tauri::command]
pub async fn offboard_scan(
    app: AppHandle,
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
    org_id: String,
    account_id: String,
) -> Result<Vec<HostResult>, String> {
    let keys = member_keys(&vault, &org_id, &account_id)?;
    let mut out = Vec::new();
    for (host_id, label, skip) in org_hosts(&vault, &org_id)? {
        if let Some(why) = skip {
            out.push(HostResult {
                host_id,
                label,
                keys: None,
                problem: Some(why),
            });
            continue;
        }
        let found = async {
            let sftp = sftp(&app, &ssh, &vault, &vpns, &host_id, None).await?;
            let text = authorized_keys::read(&sftp, PATH)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(authorized_keys::find(&text, &keys).len())
        }
        .await;
        out.push(HostResult {
            host_id,
            label,
            keys: found.as_ref().ok().copied(),
            problem: found.err(),
        });
    }
    Ok(out)
}

/// Removes the member's published keys from the given hosts' `authorized_keys`.
#[tauri::command]
pub async fn offboard_clean(
    app: AppHandle,
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
    org_id: String,
    account_id: String,
    host_ids: Vec<String>,
) -> Result<Vec<HostResult>, String> {
    let keys = member_keys(&vault, &org_id, &account_id)?;
    if keys.is_empty() {
        return Err("they published no SSH keys to look for".into());
    }
    let mut out = Vec::new();
    for (host_id, label, skip) in org_hosts(&vault, &org_id)?
        .into_iter()
        .filter(|(id, ..)| host_ids.contains(id))
    {
        if let Some(why) = skip {
            out.push(HostResult {
                host_id,
                label,
                keys: None,
                problem: Some(why),
            });
            continue;
        }
        let removed = async {
            let sftp = sftp(&app, &ssh, &vault, &vpns, &host_id, None).await?;
            edit_keys(&sftp, &keys, None).await
        }
        .await;
        out.push(HostResult {
            host_id,
            label,
            keys: removed.as_ref().ok().copied(),
            problem: removed.err(),
        });
    }
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyReplaced {
    /// The new key's fingerprint.
    fingerprint: String,
    hosts: Vec<HostResult>,
    /// Hosts that still accept the old key (removing it failed); worth fixing by hand.
    old_key_left: Vec<String>,
}

/// Replaces an SSH key in the vault with a new one on every host that logs in with it: the new
/// key is installed and tried on each host first (with the old one still there), only then does
/// the vault switch to it, and then the old key is removed from those hosts. If installing or
/// trying fails anywhere, the new key is taken off again and nothing changes.
#[tauri::command]
pub async fn key_replace(
    app: AppHandle,
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    vpns: State<'_, VpnManager>,
    key_id: String,
) -> Result<KeyReplaced, String> {
    let (old, vault_id, hosts) = {
        let v = vault.guard()?;
        let item = v.item(&key_id).map_err(|e| e.to_string())?;
        let ItemData::SshKey(old) = item.data else {
            return Err("not an SSH key".into());
        };
        let items = v.items().map_err(|e| e.to_string())?;
        let using: Vec<(String, mg_store::Host)> = items
            .iter()
            .filter(|i| i.vault_id == item.vault_id && matches!(i.data, ItemData::Host(_)))
            .filter_map(|i| Some((i.id.clone(), v.effective_host(i).ok()?)))
            .filter(|(_, h)| matches!(&h.auth, HostAuth::Key { key_ref } if *key_ref == key_id))
            .collect();
        // Hosts that take keys from the person's cloud account can't be given the new key here,
        // and would lose their way in once the vault switched.
        if let Some((_, h)) = using.iter().find(|(_, h)| account_cloud(&v, h).is_some()) {
            let cloud = account_cloud(&v, h).unwrap_or_default();
            return Err(format!(
                "\"{}\" signs in to {} on {cloud}, which takes keys from your account there, not \
                 from the host: give its hosts another key first (Clouds), then replace this one",
                old.label, h.label
            ));
        }
        let hosts: Vec<(String, String)> = using.into_iter().map(|(id, h)| (id, h.label)).collect();
        (old, item.vault_id, hosts)
    };
    if vault
        .guard()?
        .vaults()
        .map_err(|e| e.to_string())?
        .iter()
        .any(|v| v.id == vault_id && v.access == Access::Read)
    {
        return Err("you can view this vault but not change it".into());
    }
    let old_key = authorized_keys::public_key(&old.public_key)
        .ok_or("the stored key has no readable public key")?;
    let (pem, info) = mg_ssh::keys::generate_ed25519(&old.label).map_err(|e| e.to_string())?;
    let new_key = authorized_keys::public_key(&info.public_key).ok_or("generated key")?;

    // 1. Install the new key next to the old one, and log in with it.
    let mut results = Vec::new();
    let mut installed = Vec::new();
    let mut failed = false;
    for (host_id, label) in &hosts {
        let step = async {
            let s = sftp(&app, &ssh, &vault, &vpns, host_id, None).await?;
            edit_keys(&s, &[], Some(&info.public_key)).await?;
            installed.push(host_id.clone());
            sftp(&app, &ssh, &vault, &vpns, host_id, Some(&pem))
                .await
                .map_err(|e| format!("the new key was installed but doesn't log in: {e}"))?;
            Ok::<_, String>(())
        }
        .await;
        failed |= step.is_err();
        results.push(HostResult {
            host_id: host_id.clone(),
            label: label.clone(),
            keys: step.is_ok().then_some(1),
            problem: step.err(),
        });
    }
    if failed {
        // Take the new key off again; the vault still has the old one.
        for host_id in &installed {
            if let Ok(s) = sftp(&app, &ssh, &vault, &vpns, host_id, None).await {
                let _ = edit_keys(&s, std::slice::from_ref(&new_key), None).await;
            }
        }
        let problems: Vec<String> = results
            .iter()
            .filter_map(|r| r.problem.as_ref().map(|p| format!("{}: {p}", r.label)))
            .collect();
        return Err(format!(
            "nothing was changed; the new key couldn't be set up on every host. {}",
            problems.join("; ")
        ));
    }

    // 2. The vault switches to the new key (same item, so every host keeps pointing at it).
    {
        let mut v = vault.guard()?;
        v.upsert(
            Some(&key_id),
            ItemData::SshKey(SshKey {
                label: old.label.clone(),
                private_key: pem.to_string(),
                passphrase: None,
                public_key: info.public_key.clone(),
                algorithm: info.algorithm.clone(),
                fingerprint: info.fingerprint.clone(),
                // A certificate certifies the old key: the new one has none until it's issued
                // (by its renewal, where it has one).
                certificate: None,
                renew: old.renew.clone(),
            }),
        )
        .map_err(|e| e.to_string())?;
    }
    vault.changed();

    // 3. The old key comes off every host (logging in with the new one).
    let mut old_key_left = Vec::new();
    for r in &mut results {
        let step = async {
            let s = sftp(&app, &ssh, &vault, &vpns, &r.host_id, None).await?;
            edit_keys(&s, std::slice::from_ref(&old_key), None).await
        }
        .await;
        if let Err(e) = step {
            old_key_left.push(r.label.clone());
            r.problem = Some(format!("the old key is still accepted here: {e}"));
        }
    }
    Ok(KeyReplaced {
        fingerprint: info.fingerprint,
        hosts: results,
        old_key_left,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_store::{CloudSource, LocalVault};
    use serde_json::json;

    #[test]
    fn hosts_that_take_keys_from_a_cloud_account_are_named_with_it() {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            mg_vault::KdfParams::MIN_M_KIB,
            mg_vault::KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        let source = v
            .upsert(
                None,
                ItemData::CloudSource(CloudSource {
                    label: "Vallic Cloud".into(),
                    provider: "vallic".into(),
                    ..Default::default()
                }),
            )
            .unwrap();
        let host = |source: serde_json::Value| -> mg_store::Host {
            let mut h = json!({ "label": "shop · prod", "hostname": "h.example", "port": 22,
                                "user": "u", "auth": { "kind": "agent" } });
            if !source.is_null() {
                h["source"] = source;
            }
            serde_json::from_value(h).unwrap()
        };
        let vallic = host(json!({ "source_ref": source.id, "external_id": "env:1",
                                  "no_sftp": true, "no_forwarding": true }));
        assert_eq!(account_cloud(&v, &vallic).as_deref(), Some("Vallic Cloud"));
        // AWS hosts are ordinary sshd servers: their authorized_keys can be edited.
        let aws =
            host(json!({ "source_ref": source.id, "external_id": "aws:eu-central-1/i-0abc" }));
        assert_eq!(account_cloud(&v, &aws), None);
        assert_eq!(account_cloud(&v, &host(serde_json::Value::Null)), None);
    }
}
