//! Cloud sources (docs/features/cloud-sources.md): hosts kept in step with Vallic Cloud, AWS,
//! Google Cloud, Azure, Hetzner Cloud and DigitalOcean. For Vallic each device signs in itself (the
//! console's device flow) and keeps its sign-in on the device; the others are listed with the
//! provider's CLI as this device has it set up. The vault syncs the source and the hosts it made. A
//! refresh brings the provider's hosts in: what the provider decides (address, port, user, login
//! and jump commands, the label until it's renamed here) follows it, what's the person's (key,
//! scheme, tags, notes, group) stays; a host the provider no longer lists is marked gone, not
//! deleted.

use std::collections::HashMap;
use std::path::PathBuf;

use mg_inventory::cli::Cli;
use mg_inventory::shape::Shape;
use mg_inventory::vallic::{DeviceAuth, Poll, Session, Vallic};
use mg_inventory::{InventoryHost, aws, azure, gcp};
use mg_store::{
    CloudReach, CloudSource, Host, HostAuth, HostGroup, HostSource, ItemData, LocalVault,
};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::vault::{VaultState, save};

/// One cloud operation at a time on this device: a refresh token is used once, and two refreshes
/// at once would replay it, which ends the sign-in.
#[derive(Default)]
pub struct CloudState(tokio::sync::Mutex<()>);

/// Where this device keeps its sign-in to a source.
fn secret_name(source_id: &str) -> String {
    format!("cloud:{source_id}")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The console at `endpoint`, else `MORPHGATE_VALLIC_CONSOLE` (a test console, as the e2e tests
/// run), else Vallic's.
fn client(endpoint: Option<&str>) -> Result<Vallic, String> {
    let test = std::env::var("MORPHGATE_VALLIC_CONSOLE").ok();
    Vallic::new(endpoint.or(test.as_deref())).map_err(|e| e.to_string())
}

/// The CLI a provider is listed with.
fn cli_name(provider: &str) -> Option<&'static str> {
    match provider {
        "aws" => Some("aws"),
        "gcp" => Some("gcloud"),
        "azure" => Some("az"),
        "hetzner" => Some("hcloud"),
        "digitalocean" => Some("doctl"),
        _ => None,
    }
}

/// Where this device keeps the path of a provider's CLI, when it's not found by itself.
fn cli_setting(provider: &str) -> String {
    format!("cloud-cli:{provider}")
}

/// The provider's CLI on this device.
fn find_cli(v: &LocalVault, provider: &str) -> Result<Cli, String> {
    let name = cli_name(provider).ok_or("not a provider with a CLI")?;
    let path = v
        .setting(&cli_setting(provider))
        .ok()
        .flatten()
        .map(PathBuf::from);
    Cli::find(name, path.as_deref()).map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    id: String,
    vault_id: String,
    label: String,
    provider: String,
    endpoint: Option<String>,
    /// Who signed in when it was made.
    account: String,
    key_id: Option<String>,
    /// Unix seconds; 0 before the first refresh.
    refreshed_at: i64,
    /// This device can refresh it: signed in (Vallic Cloud), or it lists through a CLI.
    signed_in: bool,
    hosts: usize,
    /// Hosts the provider no longer lists.
    gone: usize,
    profile: Option<String>,
    scopes: Vec<String>,
    reach: Option<String>,
    jump_id: Option<String>,
    user: Option<String>,
    group_tag: Option<String>,
    /// Where this device runs the provider's CLI from, when it was given.
    cli_path: Option<String>,
}

fn views(v: &LocalVault) -> Result<Vec<SourceView>, String> {
    let items = v.items().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for item in &items {
        let ItemData::CloudSource(c) = &item.data else {
            continue;
        };
        let kept = items.iter().filter_map(|i| match &i.data {
            ItemData::Host(h) => h.source.as_ref().filter(|s| s.source_ref == item.id),
            _ => None,
        });
        let (hosts, gone) = kept.fold((0, 0), |(n, g), s| (n + 1, g + usize::from(s.gone)));
        out.push(SourceView {
            id: item.id.clone(),
            vault_id: item.vault_id.clone(),
            label: c.label.clone(),
            provider: c.provider.clone(),
            endpoint: c.endpoint.clone(),
            account: c.account.clone(),
            key_id: c.key_ref.clone(),
            refreshed_at: c.refreshed_at,
            signed_in: c.provider != "vallic"
                || v.local_secret(&secret_name(&item.id))
                    .ok()
                    .flatten()
                    .is_some(),
            hosts,
            gone,
            profile: c.profile.clone(),
            scopes: c.scopes.clone(),
            reach: c.reach.clone(),
            jump_id: c.jump_ref.clone(),
            user: c.user.clone(),
            group_tag: c.group_tag.clone(),
            cli_path: v.setting(&cli_setting(&c.provider)).ok().flatten(),
        });
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}

#[tauri::command]
pub fn cloud_sources(vault: State<'_, VaultState>) -> Result<Vec<SourceView>, String> {
    views(&*vault.guard()?)
}

/// Starts signing in to Vallic Cloud: the code to show and the page to type it at.
#[tauri::command]
pub async fn vallic_sign_in(endpoint: Option<String>) -> Result<DeviceAuth, String> {
    client(endpoint.as_deref())?
        .sign_in(&format!("MorphGate on {}", crate::sync::device_name()))
        .await
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SignInStatus {
    /// Not approved yet: ask again after the interval (`slower`: 5 seconds longer).
    Pending {
        slower: bool,
    },
    Denied,
    Expired,
    /// Signed in: the source (new, or the one signed in to again), refreshed.
    Done {
        source: Box<SourceView>,
        refresh: RefreshResult,
    },
}

/// Looks at a sign-in in progress; once approved, makes the source (in `vault_id`, default the
/// personal vault) or signs this device in to `source_id`, and brings its hosts in.
#[tauri::command]
pub async fn vallic_sign_in_poll(
    vault: State<'_, VaultState>,
    cloud: State<'_, CloudState>,
    endpoint: Option<String>,
    device_code: String,
    source_id: Option<String>,
    vault_id: Option<String>,
) -> Result<SignInStatus, String> {
    let _one = cloud.0.lock().await;
    let v = client(endpoint.as_deref())?;
    let tokens = match v.poll(&device_code).await.map_err(|e| e.to_string())? {
        Poll::Pending => return Ok(SignInStatus::Pending { slower: false }),
        Poll::SlowDown => return Ok(SignInStatus::Pending { slower: true }),
        Poll::Denied => return Ok(SignInStatus::Denied),
        Poll::Expired => return Ok(SignInStatus::Expired),
        Poll::Approved(t) => t,
    };
    let me = v.me(&tokens.access).await.map_err(|e| e.to_string())?;
    let mut session = Session::from_tokens(tokens);
    let id = {
        let mut store = vault.guard()?;
        let id = match source_id {
            Some(id) => id,
            None => {
                let target = match vault_id.filter(|v| !v.is_empty()) {
                    Some(id) => id,
                    None => personal(&store)?,
                };
                let source = CloudSource {
                    label: "Vallic Cloud".into(),
                    provider: "vallic".into(),
                    endpoint: endpoint.clone().filter(|e| {
                        !e.trim().is_empty() && e.trim() != mg_inventory::vallic::CONSOLE
                    }),
                    account: me.user.email.clone(),
                    ..CloudSource::default()
                };
                save(
                    &mut store,
                    None,
                    Some(&target),
                    ItemData::CloudSource(source),
                )
                .map_err(|e| e.to_string())?
                .id
            }
        };
        store
            .set_local_secret(&secret_name(&id), Some(session.refresh_token()))
            .map_err(|e| e.to_string())?;
        id
    };
    vault.changed();
    let refresh = refresh_with(&vault, &v, &id, &mut session).await?;
    let source = views(&*vault.guard()?)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or("the source went away")?;
    Ok(SignInStatus::Done {
        source: Box::new(source),
        refresh,
    })
}

fn personal(v: &LocalVault) -> Result<String, String> {
    v.vaults()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|x| x.personal)
        .map(|x| x.id)
        .ok_or_else(|| "no personal vault".into())
}

#[derive(Serialize, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResult {
    added: usize,
    updated: usize,
    /// No longer listed by the provider (marked, not deleted).
    gone: usize,
    /// Environments with no shell for this person, or not running yet.
    without_shell: Vec<String>,
    /// Machines without the address the source uses (running ones, or new stopped ones).
    without_address: Vec<String>,
    /// Regions, projects or subscriptions that couldn't be listed, and why.
    skipped: Vec<String>,
}

/// Brings a source's hosts in from the provider: with this device's sign-in (Vallic Cloud), or
/// its CLI.
#[tauri::command]
pub async fn cloud_refresh(
    vault: State<'_, VaultState>,
    cloud: State<'_, CloudState>,
    source_id: String,
) -> Result<RefreshResult, String> {
    let _one = cloud.0.lock().await;
    let provider = match vault
        .guard()?
        .item(&source_id)
        .map_err(|e| e.to_string())?
        .data
    {
        ItemData::CloudSource(c) => c.provider,
        _ => return Err("not a cloud source".into()),
    };
    if provider != "vallic" {
        return refresh_cli(&vault, &source_id).await;
    }
    let (endpoint, refresh) = {
        let v = vault.guard()?;
        let ItemData::CloudSource(c) = v.item(&source_id).map_err(|e| e.to_string())?.data else {
            return Err("not a cloud source".into());
        };
        let refresh = v
            .local_secret(&secret_name(&source_id))
            .map_err(|e| e.to_string())?
            .ok_or("this device isn't signed in to it: sign in first")?;
        (c.endpoint, refresh.to_string())
    };
    let v = client(endpoint.as_deref())?;
    let mut session = Session::new(refresh);
    refresh_with(&vault, &v, &source_id, &mut session).await
}

async fn refresh_with(
    vault: &VaultState,
    v: &Vallic,
    source_id: &str,
    session: &mut Session,
) -> Result<RefreshResult, String> {
    let before = session.refresh_token().to_owned();
    let access = session.access(v).await;
    // A refresh token rotates once used: keep the new one before anything else can fail.
    if session.refresh_token() != before {
        vault
            .guard()?
            .set_local_secret(&secret_name(source_id), Some(session.refresh_token()))
            .map_err(|e| e.to_string())?;
    }
    let access = match access {
        Err(mg_inventory::Error::SignedOut(_)) => {
            let _ = vault
                .guard()?
                .set_local_secret(&secret_name(source_id), None);
            return Err("signed out of Vallic Cloud (the sign-in ended, or was used on another device): sign in again".into());
        }
        other => other.map_err(|e| e.to_string())?,
    };
    let inventory = v.inventory(&access).await.map_err(|e| e.to_string())?;
    let result = {
        let mut store = vault.guard()?;
        let mut result = apply(&mut store, source_id, &inventory.hosts)?;
        result.without_shell = inventory.without_shell;
        result
    };
    vault.changed();
    Ok(result)
}

/// A source listed with its provider's CLI: the machines, as its settings shape them.
async fn refresh_cli(vault: &VaultState, source_id: &str) -> Result<RefreshResult, String> {
    let (c, cli) = {
        let v = vault.guard()?;
        let ItemData::CloudSource(c) = v.item(source_id).map_err(|e| e.to_string())?.data else {
            return Err("not a cloud source".into());
        };
        let cli = find_cli(&v, &c.provider)?;
        (c, cli)
    };
    let e = |e: mg_inventory::Error| e.to_string();
    let listing = match c.provider.as_str() {
        "aws" => aws::machines(&cli, c.profile.as_deref(), &c.scopes)
            .await
            .map_err(e)?,
        "gcp" => gcp::machines(&cli, &c.scopes).await.map_err(e)?,
        "azure" => azure::machines(&cli, &c.scopes).await.map_err(e)?,
        "hetzner" => mg_inventory::hetzner::machines(&cli, c.profile.as_deref())
            .await
            .map_err(e)?,
        "digitalocean" => mg_inventory::digitalocean::machines(&cli, c.profile.as_deref())
            .await
            .map_err(e)?,
        other => return Err(format!("{other}: not a provider with a CLI")),
    };
    // Google Cloud: the account's OS Login user where the source names none.
    let os_login = match (c.provider.as_str(), &c.user) {
        ("gcp", None) => gcp::os_login_user(&cli).await.ok().flatten(),
        _ => None,
    };
    let shaped = mg_inventory::shape::hosts(
        &c.provider,
        &listing.machines,
        &Shape {
            private: c.reach.as_deref() == Some("private"),
            user: c.user.as_deref().or(os_login.as_deref()),
            group_tag: c.group_tag.as_deref(),
            through: c.reach.as_deref().filter(|r| CloudReach::KINDS.contains(r)),
        },
    );
    // A machine whose ids aren't shaped like the cloud's (they'd go into a command) is left out,
    // and said, rather than failing the rest.
    let mut refused = Vec::new();
    let hosts: Vec<_> = shaped
        .hosts
        .into_iter()
        .filter(|h| {
            let Some(via) = &h.via else { return true };
            let reach = CloudReach {
                kind: via.kind.clone(),
                instance: via.instance.clone(),
                place: via.place.clone(),
                project: via.project.clone(),
            };
            match reach.check() {
                Ok(()) => true,
                Err(e) => {
                    refused.push(format!("{}: {e}", h.label));
                    false
                }
            }
        })
        .collect();
    let result = {
        let mut store = vault.guard()?;
        let mut result = apply(&mut store, source_id, &hosts)?;
        result.without_address.extend(shaped.without_address);
        result.skipped = listing.skipped;
        result.skipped.extend(refused);
        result
    };
    vault.changed();
    Ok(result)
}

/// The platform's hosts into the vault of source `source_id`.
fn apply(
    v: &mut LocalVault,
    source_id: &str,
    hosts: &[InventoryHost],
) -> Result<RefreshResult, String> {
    let e = |e: mg_store::Error| e.to_string();
    let item = v.item(source_id).map_err(e)?;
    let ItemData::CloudSource(mut source) = item.data else {
        return Err("not a cloud source".into());
    };
    let vault_id = item.vault_id;
    let items = v.items().map_err(e)?;
    // The source's hosts, by the platform's id.
    let mut kept: HashMap<String, (String, Host)> = HashMap::new();
    let mut groups: HashMap<String, String> = HashMap::new();
    for i in items.into_iter().filter(|i| i.vault_id == vault_id) {
        match i.data {
            ItemData::Host(h) => {
                if let Some(s) = h.source.as_ref().filter(|s| s.source_ref == source_id) {
                    kept.insert(s.external_id.clone(), (i.id, h));
                }
            }
            ItemData::HostGroup(g) => {
                groups.insert(g.name.to_lowercase(), i.id);
            }
            _ => {}
        }
    }
    let auth = || match &source.key_ref {
        Some(k) => HostAuth::Key { key_ref: k.clone() },
        None => HostAuth::system_agent(),
    };
    // The vault's keys by label: a machine started with a key pair signs in with the key by
    // that name.
    let keys: HashMap<String, String> = v
        .items()
        .map_err(e)?
        .into_iter()
        .filter(|i| i.vault_id == vault_id)
        .filter_map(|i| match i.data {
            ItemData::SshKey(k) => Some((k.label, i.id)),
            _ => None,
        })
        .collect();
    // Private addresses go through the source's jump host.
    let source_jump = match source.reach.as_deref() {
        Some("private") => source.jump_ref.clone(),
        _ => None,
    };
    let mut result = RefreshResult::default();
    let mut ids: HashMap<String, String> = HashMap::new();
    for ih in hosts {
        let mark = |label: &str| HostSource {
            source_ref: source_id.to_owned(),
            external_id: ih.external_id.clone(),
            label: label.to_owned(),
            gone: false,
            no_sftp: ih.no_sftp,
            no_forwarding: ih.no_forwarding,
            state: ih.state.clone(),
            reach: ih.via.as_ref().map(|via| CloudReach {
                kind: via.kind.clone(),
                instance: via.instance.clone(),
                place: via.place.clone(),
                project: via.project.clone(),
            }),
        };
        match kept.remove(&ih.external_id) {
            Some((id, mut h)) => {
                let was = h.clone();
                // Renamed here: keeps its name.
                if h.source.as_ref().is_some_and(|s| s.label == h.label) {
                    h.label = ih.label.clone();
                }
                // A stopped machine without an address keeps the last one.
                if !ih.hostname.is_empty() {
                    h.hostname = ih.hostname.clone();
                }
                h.port = ih.port;
                h.user = ih.user.clone();
                h.login_command = ih.login_command.clone();
                h.jump_command = ih.jump_command.clone();
                if ih.jump.is_none() {
                    h.jump_ref = source_jump.clone().filter(|_| ih.via.is_none());
                }
                h.source = Some(Box::new(mark(&ih.label)));
                if h != was {
                    save(v, Some(&id), None, ItemData::Host(h)).map_err(e)?;
                    result.updated += 1;
                }
                ids.insert(ih.external_id.clone(), id);
            }
            // New and without an address (stopped): nothing to connect to yet.
            None if ih.hostname.is_empty() => result.without_address.push(ih.label.clone()),
            None => {
                let group_ref = match groups.get(&ih.group.to_lowercase()) {
                    Some(g) => g.clone(),
                    None => {
                        let group = HostGroup {
                            name: ih.group.clone(),
                            ..HostGroup::default()
                        };
                        let id = save(v, None, Some(&vault_id), ItemData::HostGroup(group))
                            .map_err(e)?
                            .id;
                        groups.insert(ih.group.to_lowercase(), id.clone());
                        id
                    }
                };
                let host = Host {
                    label: ih.label.clone(),
                    hostname: ih.hostname.clone(),
                    port: ih.port,
                    user: ih.user.clone(),
                    auth: match ih.key_name.as_ref().and_then(|k| keys.get(k)) {
                        Some(key) => HostAuth::Key {
                            key_ref: key.clone(),
                        },
                        None => auth(),
                    },
                    jump_ref: source_jump.clone().filter(|_| ih.via.is_none()),
                    vpn_ref: None,
                    theme_ref: None,
                    record_sessions: false,
                    tags: Vec::new(),
                    notes: String::new(),
                    group_ref: Some(group_ref),
                    identity_ref: None,
                    keep_session: false,
                    forward_agent: false,
                    login_command: ih.login_command.clone(),
                    jump_command: ih.jump_command.clone(),
                    proxy_command: None,
                    source: Some(Box::new(mark(&ih.label))),
                };
                let id = save(v, None, Some(&vault_id), ItemData::Host(host))
                    .map_err(e)?
                    .id;
                ids.insert(ih.external_id.clone(), id);
                result.added += 1;
            }
        }
    }
    // Jump hosts, now that each host has an id.
    for ih in hosts.iter().filter(|h| h.jump.is_some()) {
        let (Some(id), Some(jump)) = (
            ids.get(&ih.external_id),
            ih.jump.as_ref().and_then(|j| ids.get(j)),
        ) else {
            continue;
        };
        let ItemData::Host(mut h) = v.item(id).map_err(e)?.data else {
            continue;
        };
        if h.jump_ref.as_deref() != Some(jump) {
            h.jump_ref = Some(jump.clone());
            save(v, Some(id), None, ItemData::Host(h)).map_err(e)?;
        }
    }
    // What the platform no longer lists.
    for (id, mut h) in kept.into_values() {
        if let Some(s) = h.source.as_mut().filter(|s| !s.gone) {
            s.gone = true;
            save(v, Some(&id), None, ItemData::Host(h)).map_err(e)?;
            result.gone += 1;
        }
    }
    source.refreshed_at = now();
    save(v, Some(source_id), None, ItemData::CloudSource(source)).map_err(e)?;
    Ok(result)
}

/// Ends this device's sign-in (on the console too); the source and its hosts stay.
#[tauri::command]
pub async fn cloud_sign_out(
    vault: State<'_, VaultState>,
    cloud: State<'_, CloudState>,
    source_id: String,
) -> Result<(), String> {
    let _one = cloud.0.lock().await;
    let (endpoint, refresh) = {
        let v = vault.guard()?;
        let endpoint = match v.item(&source_id).map_err(|e| e.to_string())?.data {
            ItemData::CloudSource(c) => c.endpoint,
            _ => return Err("not a cloud source".into()),
        };
        let refresh = v.local_secret(&secret_name(&source_id)).ok().flatten();
        (endpoint, refresh.map(|r| r.to_string()))
    };
    if let Some(r) = refresh {
        // Signed out here whatever the console says.
        let _ = client(endpoint.as_deref())?.sign_out(&r).await;
    }
    vault
        .guard()?
        .set_local_secret(&secret_name(&source_id), None)
        .map_err(|e| e.to_string())
}

/// Removes a source: its hosts too (`delete_hosts`), or they stay as hosts of their own.
#[tauri::command]
pub async fn cloud_source_delete(
    vault: State<'_, VaultState>,
    cloud: State<'_, CloudState>,
    source_id: String,
    delete_hosts: bool,
) -> Result<(), String> {
    cloud_sign_out(vault.clone(), cloud, source_id.clone())
        .await
        .ok();
    {
        let mut v = vault.guard()?;
        let e = |e: mg_store::Error| e.to_string();
        let hosts: Vec<(String, Host)> = v
            .items()
            .map_err(e)?
            .into_iter()
            .filter_map(|i| match i.data {
                ItemData::Host(h)
                    if h.source.as_ref().is_some_and(|s| s.source_ref == source_id) =>
                {
                    Some((i.id, h))
                }
                _ => None,
            })
            .collect();
        if delete_hosts {
            // Hosts that jump through others first, so none is still in use when it goes.
            let (through, rest): (Vec<_>, Vec<_>) =
                hosts.into_iter().partition(|(_, h)| h.jump_ref.is_some());
            for (id, _) in through.into_iter().chain(rest) {
                v.delete(&id).map_err(e)?;
            }
        } else {
            for (id, mut h) in hosts {
                h.source = None;
                save(&mut v, Some(&id), None, ItemData::Host(h)).map_err(e)?;
            }
        }
        v.delete(&source_id).map_err(e)?;
    }
    vault.changed();
    Ok(())
}

/// The key a source's hosts sign in with (new hosts; and the source's hosts that used the one
/// before, or the agent).
#[tauri::command]
pub fn cloud_source_key(
    vault: State<'_, VaultState>,
    source_id: String,
    key_id: Option<String>,
) -> Result<(), String> {
    {
        let mut v = vault.guard()?;
        let e = |e: mg_store::Error| e.to_string();
        let ItemData::CloudSource(mut source) = v.item(&source_id).map_err(e)?.data else {
            return Err("not a cloud source".into());
        };
        let before = source.key_ref.clone();
        source.key_ref = key_id.clone().filter(|k| !k.is_empty());
        let auth = match &source.key_ref {
            Some(k) => HostAuth::Key { key_ref: k.clone() },
            None => HostAuth::system_agent(),
        };
        save(
            &mut v,
            Some(&source_id),
            None,
            ItemData::CloudSource(source),
        )
        .map_err(e)?;
        let hosts: Vec<(String, Host)> = v
            .items()
            .map_err(e)?
            .into_iter()
            .filter_map(|i| match i.data {
                ItemData::Host(h)
                    if h.source.as_ref().is_some_and(|s| s.source_ref == source_id) =>
                {
                    Some((i.id, h))
                }
                _ => None,
            })
            .collect();
        for (id, mut h) in hosts {
            let followed = match (&h.auth, &before) {
                (HostAuth::Key { key_ref }, Some(b)) => key_ref == b,
                (
                    HostAuth::Agent {
                        agent: None,
                        path: None,
                        key: None,
                    },
                    None,
                ) => true,
                _ => false,
            };
            if followed {
                h.auth = auth.clone();
                save(&mut v, Some(&id), None, ItemData::Host(h)).map_err(e)?;
            }
        }
    }
    vault.changed();
    Ok(())
}

/// `s` in a command for this system's shell, as one word.
fn quoted(s: &str) -> String {
    // A path's `%` would be read as a token by the proxy command's expansion.
    let s = s.replace('%', "%%");
    if cfg!(windows) {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The command that reaches a host through its cloud (Session Manager, an Instance Connect
/// Endpoint, IAP), built here from the host's checked fields, the source's profile and this
/// device's CLI: never a command from the vault. `%p` is the host's port.
pub(crate) fn reach_command(v: &LocalVault, source: &HostSource) -> Result<Option<String>, String> {
    let Some(reach) = &source.reach else {
        return Ok(None);
    };
    reach.check()?;
    let profile = match v.item(&source.source_ref).map(|i| i.data) {
        Ok(ItemData::CloudSource(c)) => c.profile,
        _ => None,
    };
    let profile = match profile {
        Some(p)
            if p.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) =>
        {
            format!(" --profile {p}")
        }
        Some(p) => return Err(format!("the AWS profile {p:?} can't be given to a command")),
        None => String::new(),
    };
    let provider = if reach.kind.starts_with("aws-") {
        "aws"
    } else {
        "gcp"
    };
    let cli = quoted(&find_cli(v, provider)?.program().display().to_string());
    let (instance, place) = (&reach.instance, &reach.place);
    Ok(Some(match reach.kind.as_str() {
        "aws-ssm" => format!(
            "{cli} ssm start-session --target {instance} --document-name AWS-StartSSHSession --parameters portNumber=%p --region {place}{profile}"
        ),
        "aws-eice" => format!(
            "{cli} ec2-instance-connect open-tunnel --instance-id {instance} --remote-port %p --region {place}{profile}"
        ),
        _ => format!(
            "{cli} compute start-iap-tunnel {instance} %p --listen-on-stdin --zone {place} --project {} --verbosity=warning",
            reach.project.as_deref().unwrap_or_default()
        ),
    }))
}

/// Who `provider`'s CLI is signed in as (`profile`: AWS's).
async fn whoami(cli: &Cli, provider: &str, profile: Option<&str>) -> Result<String, String> {
    match provider {
        "aws" => aws::whoami(cli, profile).await,
        "gcp" => gcp::whoami(cli).await,
        "azure" => azure::whoami(cli).await,
        "hetzner" => mg_inventory::hetzner::whoami(cli, profile).await,
        "digitalocean" => mg_inventory::digitalocean::whoami(cli, profile).await,
        other => return Err(format!("{other}: not a provider with a CLI")),
    }
    .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliCheck {
    /// The CLI found.
    path: String,
    /// Who it's signed in as.
    account: String,
}

/// Finds `provider`'s CLI on this device and asks who it's signed in as.
#[tauri::command]
pub async fn cloud_check(
    vault: State<'_, VaultState>,
    provider: String,
    profile: Option<String>,
) -> Result<CliCheck, String> {
    let cli = find_cli(&*vault.guard()?, &provider)?;
    let profile = profile.filter(|p| !p.trim().is_empty());
    let account = whoami(&cli, &provider, profile.as_deref()).await?;
    Ok(CliCheck {
        path: cli.program().display().to_string(),
        account,
    })
}

/// Where this device runs `provider`'s CLI from (`None`: wherever it's found).
#[tauri::command]
pub fn cloud_cli_path(
    vault: State<'_, VaultState>,
    provider: String,
    path: Option<String>,
) -> Result<(), String> {
    cli_name(&provider).ok_or("not a provider with a CLI")?;
    let path = path.map(|p| p.trim().to_owned()).filter(|p| !p.is_empty());
    vault
        .guard()?
        .set_setting(&cli_setting(&provider), path.as_deref())
        .map_err(|e| e.to_string())
}

/// What a CLI source lists, and how its machines become hosts.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSettings {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    /// `public` or `private`.
    #[serde(default)]
    reach: Option<String>,
    #[serde(default)]
    jump_id: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    group_tag: Option<String>,
}

fn trimmed(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

impl SourceSettings {
    fn onto(self, c: &mut CloudSource) {
        if let Some(label) = trimmed(self.label) {
            c.label = label;
        }
        c.profile = trimmed(self.profile);
        c.scopes = self
            .scopes
            .into_iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        c.reach = trimmed(self.reach).filter(|r| r != "public");
        c.jump_ref = trimmed(self.jump_id).filter(|_| c.reach.is_some());
        c.user = trimmed(self.user);
        c.group_tag = trimmed(self.group_tag);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Added {
    source: Box<SourceView>,
    refresh: RefreshResult,
}

/// Adds an AWS, Google Cloud or Azure source (in `vault_id`, default the personal vault), once
/// its CLI says who it's signed in as, and lists its machines.
#[tauri::command]
pub async fn cloud_source_add(
    vault: State<'_, VaultState>,
    cloud: State<'_, CloudState>,
    provider: String,
    vault_id: Option<String>,
    key_id: Option<String>,
    settings: SourceSettings,
) -> Result<Added, String> {
    let _one = cloud.0.lock().await;
    let cli = find_cli(&*vault.guard()?, &provider)?;
    let profile = trimmed(settings.profile.clone());
    let account = whoami(&cli, &provider, profile.as_deref()).await?;
    let id = {
        let mut store = vault.guard()?;
        let target = match vault_id.filter(|v| !v.is_empty()) {
            Some(id) => id,
            None => personal(&store)?,
        };
        let mut source = CloudSource {
            label: match (provider.as_str(), &profile) {
                ("aws", Some(p)) => format!("AWS ({p})"),
                ("aws", None) => "AWS".into(),
                ("gcp", _) => "Google Cloud".into(),
                ("hetzner", _) => format!("Hetzner Cloud ({account})"),
                ("digitalocean", Some(p)) => format!("DigitalOcean ({p})"),
                ("digitalocean", None) => "DigitalOcean".into(),
                _ => "Azure".into(),
            },
            provider: provider.clone(),
            key_ref: trimmed(key_id),
            account,
            ..CloudSource::default()
        };
        settings.onto(&mut source);
        save(
            &mut store,
            None,
            Some(&target),
            ItemData::CloudSource(source),
        )
        .map_err(|e| e.to_string())?
        .id
    };
    vault.changed();
    let refresh = refresh_cli(&vault, &id).await?;
    let source = views(&*vault.guard()?)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or("the source went away")?;
    Ok(Added {
        source: Box::new(source),
        refresh,
    })
}

/// Changes what a CLI source lists and how (the next refresh follows).
#[tauri::command]
pub fn cloud_source_settings(
    vault: State<'_, VaultState>,
    source_id: String,
    settings: SourceSettings,
) -> Result<(), String> {
    {
        let mut v = vault.guard()?;
        let e = |e: mg_store::Error| e.to_string();
        let ItemData::CloudSource(mut source) = v.item(&source_id).map_err(e)?.data else {
            return Err("not a cloud source".into());
        };
        if source.provider == "vallic" {
            return Err("Vallic Cloud lists what your sign-in reaches".into());
        }
        settings.onto(&mut source);
        save(
            &mut v,
            Some(&source_id),
            None,
            ItemData::CloudSource(source),
        )
        .map_err(e)?;
    }
    vault.changed();
    Ok(())
}

/// Puts a key's public half on the signed-in person's Vallic account.
#[tauri::command]
pub async fn cloud_add_key(
    vault: State<'_, VaultState>,
    cloud: State<'_, CloudState>,
    source_id: String,
    key_id: String,
) -> Result<(), String> {
    let _one = cloud.0.lock().await;
    let (endpoint, refresh, label, public_key) = {
        let v = vault.guard()?;
        let e = |e: mg_store::Error| e.to_string();
        let ItemData::CloudSource(c) = v.item(&source_id).map_err(e)?.data else {
            return Err("not a cloud source".into());
        };
        let ItemData::SshKey(k) = v.item(&key_id).map_err(e)?.data else {
            return Err("not an SSH key".into());
        };
        if k.algorithm.starts_with("sk-") {
            return Err("Vallic Cloud doesn't take security keys (sk-): choose another key".into());
        }
        let refresh = v
            .local_secret(&secret_name(&source_id))
            .map_err(e)?
            .ok_or("this device isn't signed in to it: sign in first")?;
        (c.endpoint, refresh.to_string(), k.label, k.public_key)
    };
    let v = client(endpoint.as_deref())?;
    let mut session = Session::new(refresh.clone());
    let access = session.access(&v).await;
    if session.refresh_token() != refresh {
        vault
            .guard()?
            .set_local_secret(&secret_name(&source_id), Some(session.refresh_token()))
            .map_err(|e| e.to_string())?;
    }
    let access = access.map_err(|e| e.to_string())?;
    v.add_ssh_key(&access, &format!("{label} (MorphGate)"), &public_key)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_vault::KdfParams;

    fn vault() -> LocalVault {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        v
    }

    fn host(id: &str, label: &str, jump: Option<&str>) -> InventoryHost {
        InventoryHost {
            external_id: id.into(),
            group: "Shop".into(),
            label: label.into(),
            hostname: format!("{id}.example"),
            port: 2417,
            user: "vc-t-acme".into(),
            login_command: None,
            jump: jump.map(str::to_owned),
            jump_command: jump.map(|_| "jump web".to_owned()),
            no_sftp: true,
            no_forwarding: true,
            state: None,
            key_name: None,
            via: None,
        }
    }

    fn hosts_of(v: &LocalVault, source: &str) -> Vec<(String, Host)> {
        let mut out: Vec<(String, Host)> = v
            .items()
            .unwrap()
            .into_iter()
            .filter_map(|i| match i.data {
                ItemData::Host(h) if h.source.as_ref().is_some_and(|s| s.source_ref == source) => {
                    Some((i.id, h))
                }
                _ => None,
            })
            .collect();
        out.sort_by(|a, b| a.1.label.cmp(&b.1.label));
        out
    }

    /// An AWS source by private addresses: through its jump host, the key named by the key
    /// pair; a stopped machine keeps its last address; a new one without any waits.
    #[test]
    fn a_cli_source_reaches_private_machines_and_keeps_stopped_ones() {
        let mut v = vault();
        let target = personal(&v).unwrap();
        let (pem, info) = mg_ssh::keys::generate_ed25519("deploy").unwrap();
        let key = save(
            &mut v,
            None,
            Some(&target),
            ItemData::SshKey(mg_store::SshKey {
                label: "deploy".into(),
                algorithm: info.algorithm,
                private_key: pem.to_string(),
                public_key: info.public_key,
                fingerprint: info.fingerprint,
                passphrase: None,
                certificate: None,
                renew: None,
            }),
        )
        .unwrap()
        .id;
        let bastion_id = v
            .upsert(None, ItemData::Host(test_host("bastion")))
            .unwrap()
            .id;
        let source = CloudSource {
            label: "AWS".into(),
            provider: "aws".into(),
            reach: Some("private".into()),
            jump_ref: Some(bastion_id.clone()),
            ..CloudSource::default()
        };
        let sid = save(&mut v, None, Some(&target), ItemData::CloudSource(source))
            .unwrap()
            .id;
        let machine = |id: &str, hostname: &str, state: Option<&str>| InventoryHost {
            external_id: format!("aws:eu-central-1/{id}"),
            group: "eu-central-1".into(),
            label: id.into(),
            hostname: hostname.into(),
            port: 22,
            user: "ec2-user".into(),
            login_command: None,
            jump: None,
            jump_command: None,
            no_sftp: false,
            no_forwarding: false,
            state: state.map(str::to_owned),
            key_name: Some("deploy".into()),
            via: None,
        };
        let first = apply(
            &mut v,
            &sid,
            &[
                machine("i-web", "10.0.0.1", None),
                machine("i-batch", "", Some("stopped")),
            ],
        )
        .unwrap();
        assert_eq!(first.added, 1);
        assert_eq!(first.without_address, ["i-batch"]);
        let (_, web) = &hosts_of(&v, &sid)[0];
        assert_eq!(web.jump_ref.as_deref(), Some(bastion_id.as_str()));
        assert_eq!(web.auth, HostAuth::Key { key_ref: key });
        assert!(!web.source.as_ref().unwrap().no_sftp);

        // Stopped, without its address now: the last one stays, and it says stopped.
        apply(&mut v, &sid, &[machine("i-web", "", Some("stopped"))]).unwrap();
        let (_, web) = &hosts_of(&v, &sid)[0];
        assert_eq!(web.hostname, "10.0.0.1");
        assert_eq!(
            web.source.as_ref().unwrap().state.as_deref(),
            Some("stopped")
        );
    }

    /// The command for a host reached through its cloud: this device's CLI, the source's
    /// profile, the host's checked fields; a field that isn't an id is refused.
    #[cfg(unix)]
    #[test]
    fn reaching_through_the_cloud_builds_the_command_here() {
        use std::os::unix::fs::PermissionsExt;
        let mut v = vault();
        let target = personal(&v).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let aws = dir.path().join("it's aws");
        std::fs::write(&aws, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();
        v.set_setting(&cli_setting("aws"), Some(aws.to_str().unwrap()))
            .unwrap();
        let sid = save(
            &mut v,
            None,
            Some(&target),
            ItemData::CloudSource(CloudSource {
                label: "AWS".into(),
                provider: "aws".into(),
                profile: Some("prod".into()),
                reach: Some("aws-ssm".into()),
                ..CloudSource::default()
            }),
        )
        .unwrap()
        .id;
        let mut source = HostSource {
            source_ref: sid,
            external_id: "aws:eu-central-1/i-0abc".into(),
            label: "web".into(),
            gone: false,
            no_sftp: false,
            no_forwarding: false,
            state: None,
            reach: Some(CloudReach {
                kind: "aws-ssm".into(),
                instance: "i-0abc".into(),
                place: "eu-central-1".into(),
                project: None,
            }),
        };
        let command = reach_command(&v, &source).unwrap().unwrap();
        assert_eq!(
            command,
            format!(
                "'{}' ssm start-session --target i-0abc --document-name AWS-StartSSHSession --parameters portNumber=%p --region eu-central-1 --profile prod",
                aws.display().to_string().replace('\'', "'\\''")
            )
        );
        source.reach.as_mut().unwrap().instance = "i-0abc; touch /tmp/x".into();
        assert!(reach_command(&v, &source).is_err());
    }

    fn test_host(label: &str) -> Host {
        Host {
            label: label.into(),
            hostname: format!("{label}.example"),
            port: 22,
            user: "ops".into(),
            auth: HostAuth::Password { password: None },
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
        }
    }

    #[test]
    fn refreshing_follows_the_platform_and_keeps_what_is_yours() {
        let mut v = vault();
        let target = personal(&v).unwrap();
        let source = CloudSource {
            label: "Vallic Cloud".into(),
            provider: "vallic".into(),
            account: "ana@example.com".into(),
            ..CloudSource::default()
        };
        let sid = save(&mut v, None, Some(&target), ItemData::CloudSource(source))
            .unwrap()
            .id;

        let first = apply(
            &mut v,
            &sid,
            &[
                host("env:1/front", "Shop · Production (front)", None),
                host("env:1", "Shop · Production", Some("env:1/front")),
            ],
        )
        .unwrap();
        assert_eq!((first.added, first.updated, first.gone), (2, 0, 0));
        let hosts = hosts_of(&v, &sid);
        let (front_id, _) = hosts
            .iter()
            .find(|(_, h)| h.label.ends_with("(front)"))
            .unwrap();
        let (prod_id, prod) = hosts
            .iter()
            .find(|(_, h)| h.label == "Shop · Production")
            .unwrap();
        assert_eq!(prod.jump_ref.as_deref(), Some(front_id.as_str()));
        assert_eq!(prod.jump_command.as_deref(), Some("jump web"));
        assert!(prod.group_ref.is_some(), "a group per project");

        // The person renames production and tags it; the platform moves its port.
        let ItemData::Host(mut mine) = v.item(prod_id).unwrap().data else {
            unreachable!()
        };
        mine.label = "prod".into();
        mine.tags = vec!["live".into()];
        save(&mut v, Some(prod_id), None, ItemData::Host(mine)).unwrap();
        let mut moved = host("env:1", "Shop · Production", Some("env:1/front"));
        moved.port = 2418;
        let second = apply(
            &mut v,
            &sid,
            &[
                host("env:1/front", "Shop · Production (front)", None),
                moved,
            ],
        )
        .unwrap();
        assert_eq!((second.added, second.updated, second.gone), (0, 1, 0));
        let ItemData::Host(after) = v.item(prod_id).unwrap().data else {
            unreachable!()
        };
        assert_eq!(
            (after.label.as_str(), after.port, after.tags.as_slice()),
            ("prod", 2418, &["live".to_owned()][..])
        );

        // Gone from the platform: marked, kept.
        let third = apply(
            &mut v,
            &sid,
            &[host("env:1/front", "Shop · Production (front)", None)],
        )
        .unwrap();
        assert_eq!(third.gone, 1);
        let ItemData::Host(gone) = v.item(prod_id).unwrap().data else {
            unreachable!()
        };
        assert!(gone.source.unwrap().gone);
    }
}
