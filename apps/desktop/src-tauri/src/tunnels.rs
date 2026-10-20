//! Saved port forwards: vault CRUD plus start/stop of live tunnels.

use std::time::Duration;

use mg_ssh::{Connection, Forward, Tunnel};
use mg_store::{ForwardRule, Item, ItemData, LocalVault, PortForward};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::ssh::{SshState, Target, resolve};
use crate::vault::VaultState;

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum Rule {
    Local {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    Remote {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    Dynamic {
        bind_host: String,
        bind_port: u16,
    },
}

impl From<ForwardRule> for Rule {
    fn from(r: ForwardRule) -> Self {
        match r {
            ForwardRule::Local {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => Rule::Local {
                bind_host,
                bind_port,
                target_host,
                target_port,
            },
            ForwardRule::Remote {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => Rule::Remote {
                bind_host,
                bind_port,
                target_host,
                target_port,
            },
            ForwardRule::Dynamic {
                bind_host,
                bind_port,
            } => Rule::Dynamic {
                bind_host,
                bind_port,
            },
        }
    }
}

impl From<Rule> for ForwardRule {
    fn from(r: Rule) -> Self {
        let t = |s: String| s.trim().to_owned();
        match r {
            Rule::Local {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => ForwardRule::Local {
                bind_host: t(bind_host),
                bind_port,
                target_host: t(target_host),
                target_port,
            },
            Rule::Remote {
                bind_host,
                bind_port,
                target_host,
                target_port,
            } => ForwardRule::Remote {
                bind_host: t(bind_host),
                bind_port,
                target_host: t(target_host),
                target_port,
            },
            Rule::Dynamic {
                bind_host,
                bind_port,
            } => ForwardRule::Dynamic {
                bind_host: t(bind_host),
                bind_port,
            },
        }
    }
}

fn to_forward(rule: ForwardRule) -> Forward {
    match rule {
        ForwardRule::Local {
            bind_host,
            bind_port,
            target_host,
            target_port,
        } => Forward::Local {
            bind_host,
            bind_port,
            target_host,
            target_port,
        },
        ForwardRule::Remote {
            bind_host,
            bind_port,
            target_host,
            target_port,
        } => Forward::Remote {
            bind_host,
            bind_port,
            target_host,
            target_port,
        },
        ForwardRule::Dynamic {
            bind_host,
            bind_port,
        } => Forward::Dynamic {
            bind_host,
            bind_port,
        },
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardView {
    id: String,
    vault_id: String,
    label: String,
    host_id: String,
    rule: Rule,
    running: bool,
    /// Listening port while running (allocated by the server for remote forwards on port 0).
    port: Option<u16>,
    active: usize,
    updated_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInput {
    id: Option<String>,
    #[serde(default)]
    vault_id: Option<String>,
    label: String,
    host_id: String,
    rule: Rule,
}

fn view(
    id: String,
    vault_id: String,
    updated_at: i64,
    f: PortForward,
    tunnel: Option<&Tunnel>,
) -> ForwardView {
    ForwardView {
        id,
        vault_id,
        label: f.label,
        host_id: f.host_ref,
        rule: f.rule.into(),
        running: tunnel.is_some(),
        port: tunnel.map(Tunnel::port),
        active: tunnel.map_or(0, Tunnel::active_connections),
        updated_at,
    }
}

fn forward_item(vault: &VaultState, id: &str) -> Result<(String, i64, PortForward), String> {
    match vault.guard()?.item(id).map_err(|e| e.to_string())? {
        Item {
            vault_id,
            updated_at,
            data: ItemData::PortForward(f),
            ..
        } => Ok((vault_id, updated_at, f)),
        _ => Err("not a tunnel".into()),
    }
}

/// A host whose provider's SSH forwards no ports (Vallic Cloud's) carries no tunnel. The editor
/// leaves such hosts out; this also stops tunnels saved through one before.
fn can_carry_tunnels(v: &LocalVault, host_id: &str) -> Result<(), String> {
    if let Ok(Item {
        data: ItemData::Host(h),
        ..
    }) = v.item(host_id)
        && h.source.as_ref().is_some_and(|s| s.no_forwarding)
    {
        return Err(format!(
            "\"{}\" can't carry tunnels: its cloud's SSH doesn't forward ports",
            h.label
        ));
    }
    Ok(())
}

async fn stop(ssh: &SshState, id: &str) {
    let tunnel = ssh.tunnels.lock().await.remove(id);
    if let Some(t) = tunnel {
        t.stop().await;
    }
}

#[tauri::command]
pub async fn forwards_list(
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
) -> Result<Vec<ForwardView>, String> {
    let items = vault.guard()?.items().map_err(|e| e.to_string())?;
    let mut tunnels = ssh.tunnels.lock().await;
    // Forget tunnels whose SSH connection died (network drop, server restart).
    let dead: Vec<String> = tunnels
        .iter()
        .filter(|(_, t)| !t.is_alive())
        .map(|(id, _)| id.clone())
        .collect();
    for id in dead {
        if let Some(t) = tunnels.remove(&id) {
            tauri::async_runtime::spawn(t.stop());
        }
    }
    let mut out: Vec<ForwardView> = items
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::PortForward(f) => {
                let t = tunnels.get(&i.id);
                Some(view(i.id, i.vault_id, i.updated_at, f, t))
            }
            _ => None,
        })
        .collect();
    out.sort_by_key(|f| f.label.to_lowercase());
    Ok(out)
}

/// Saving a running tunnel stops it, so it never runs with a stale configuration.
#[tauri::command]
pub async fn forward_save(
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    input: ForwardInput,
) -> Result<ForwardView, String> {
    if let Some(id) = &input.id {
        stop(&ssh, id).await;
    }
    can_carry_tunnels(&*vault.guard()?, &input.host_id)?;
    let label = match input.label.trim() {
        "" => "Tunnel".to_owned(),
        l => l.to_owned(),
    };
    let item = PortForward {
        label,
        host_ref: input.host_id,
        rule: input.rule.into(),
    };
    let Item {
        id,
        vault_id,
        updated_at,
        data,
    } = crate::vault::save(
        &mut *vault.guard()?,
        input.id.as_deref(),
        input.vault_id.as_deref(),
        ItemData::PortForward(item),
    )
    .map_err(|e| e.to_string())?;
    vault.changed();
    match data {
        ItemData::PortForward(f) => Ok(view(id, vault_id, updated_at, f, None)),
        _ => unreachable!("upsert returns the data it was given"),
    }
}

#[tauri::command]
pub async fn forward_delete(
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    id: String,
) -> Result<(), String> {
    stop(&ssh, &id).await;
    vault.guard()?.delete(&id).map_err(|e| e.to_string())?;
    vault.changed();
    Ok(())
}

/// `password` is only needed when the tunnel's host has no saved password.
#[tauri::command]
pub async fn forward_start(
    app: AppHandle,
    ssh: State<'_, SshState>,
    vault: State<'_, VaultState>,
    vpns: State<'_, crate::vpn::VpnManager>,
    id: String,
    password: Option<String>,
) -> Result<ForwardView, String> {
    let (vault_id, updated_at, f) = forward_item(&vault, &id)?;
    if let Some(t) = ssh.tunnels.lock().await.get(&id).filter(|t| t.is_alive()) {
        return Ok(view(id.clone(), vault_id, updated_at, f, Some(t)));
    }
    can_carry_tunnels(&*vault.guard()?, &f.host_ref)?;
    let saved = Target::Saved {
        host_id: f.host_ref.clone(),
        password,
        tmux: None,
    };
    crate::renew::before_connect(&vault, &saved).await?;
    let crate::ssh::Resolved {
        target,
        jumps,
        vpn,
        proxy,
    } = resolve(saved, &vault)?;
    let dialer = crate::ssh::first_hop(&app, &vault, &vpns, vpn, proxy).await?;
    crate::host_cas::trust(&vault, &ssh.known_hosts);
    let conn = Connection::open(
        target,
        jumps,
        dialer,
        Duration::from_secs(15),
        ssh.known_hosts.clone(),
        ssh.prompt(app.clone()),
    )
    .await
    .map_err(|e| crate::ssh::connect_error(&app, e))?;
    let tunnel = Tunnel::start(conn, to_forward(f.rule.clone()))
        .await
        .map_err(|e| e.to_string())?;
    let out = view(id.clone(), vault_id, updated_at, f, Some(&tunnel));
    if let Some(old) = ssh.tunnels.lock().await.insert(id, tunnel) {
        old.stop().await;
    }
    Ok(out)
}

#[tauri::command]
pub async fn forward_stop(ssh: State<'_, SshState>, id: String) -> Result<(), String> {
    stop(&ssh, &id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosts_whose_cloud_forwards_nothing_carry_no_tunnel() {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            mg_vault::KdfParams::MIN_M_KIB,
            mg_vault::KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        let host = |label: &str, source: serde_json::Value| {
            let mut h = json!({ "label": label, "hostname": "h.example", "port": 22, "user": "u",
                                "auth": { "kind": "agent" } });
            if !source.is_null() {
                h["source"] = source;
            }
            ItemData::Host(serde_json::from_value(h).unwrap())
        };
        let vallic = v
            .upsert(
                None,
                host(
                    "shop · prod",
                    json!({ "source_ref": "S1", "external_id": "env:1", "no_sftp": true, "no_forwarding": true }),
                ),
            )
            .unwrap();
        let plain = v.upsert(None, host("db", serde_json::Value::Null)).unwrap();
        assert_eq!(
            can_carry_tunnels(&v, &vallic.id).unwrap_err(),
            "\"shop · prod\" can't carry tunnels: its cloud's SSH doesn't forward ports"
        );
        assert!(can_carry_tunnels(&v, &plain.id).is_ok());
        assert!(can_carry_tunnels(&v, "gone").is_ok());
    }

    #[test]
    fn rule_shapes_match_the_frontend() {
        let input: ForwardInput = serde_json::from_value(json!({
            "id": null, "label": "pg", "hostId": "H1",
            "rule": { "kind": "local", "bindHost": "127.0.0.1", "bindPort": 15432, "targetHost": "db", "targetPort": 5432 }
        }))
        .unwrap();
        assert!(matches!(
            ForwardRule::from(input.rule),
            ForwardRule::Local {
                bind_port: 15432,
                target_port: 5432,
                ..
            }
        ));
        let socks = serde_json::to_value(Rule::Dynamic {
            bind_host: "127.0.0.1".into(),
            bind_port: 1080,
        })
        .unwrap();
        assert_eq!(
            socks,
            json!({ "kind": "dynamic", "bindHost": "127.0.0.1", "bindPort": 1080 })
        );
    }
}
