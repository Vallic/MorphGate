//! Teams: organizations, members, invites and shared vaults. The work (and every key check) is in
//! `mg_store::sharing`; these commands bring the sync client and keep one account operation at a
//! time.

use std::collections::HashMap;
use std::sync::Arc;

use mg_store::account::AccountError;
use mg_store::sharing::{self, InvitePreview, MemberView, OrgInfo};
use mg_store::{Access, VaultInfo};
use mg_sync::{Policies, Role, SyncClient, UpdateOrg, VaultGrant};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::sync::SyncState;
use crate::vault::VaultState;

const NO_SYNC: &str = "Teams work through sync: turn on sync first (Sync in the sidebar).";

/// Runs `f` with this device's sync client, one account operation at a time, and keeps a
/// rotated session token.
pub(crate) async fn with_client<T>(
    sync: &SyncState,
    vault: &VaultState,
    f: impl AsyncFnOnce(Arc<SyncClient>) -> Result<T, AccountError>,
) -> Result<T, String> {
    // Who waited how long for the lock, and held it how long (MORPHGATE_LOG=debug).
    let by = std::any::type_name_of_val(&f);
    let waiting = std::time::Instant::now();
    let _single = sync.running.lock().await;
    let held = std::time::Instant::now();
    tracing::debug!(
        by,
        waited_ms = waiting.elapsed().as_millis() as u64,
        "sync lock taken"
    );
    let client = crate::sync::session(sync, vault)
        .await?
        .ok_or_else(|| NO_SYNC.to_owned())?;
    let result = f(client.clone()).await;
    tracing::debug!(
        by,
        held_ms = held.elapsed().as_millis() as u64,
        "sync lock released"
    );
    if let Some(t) = client.take_rotated_refresh() {
        let _ = vault.guard()?.set_sync_token(&t);
    }
    result.map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingStatus {
    available: bool,
    /// Why teams aren't available here.
    reason: Option<String>,
    account_id: Option<String>,
    /// This account's fingerprint, to read out to an admin confirming it.
    fingerprint: Option<String>,
}

#[tauri::command]
pub async fn sharing_status(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
) -> Result<SharingStatus, String> {
    let (id, keys) = {
        let v = vault.guard()?;
        let Some(info) = v.sync_info().map_err(|e| e.to_string())? else {
            return Ok(SharingStatus {
                available: false,
                reason: Some(NO_SYNC.into()),
                account_id: None,
                fingerprint: None,
            });
        };
        (
            info.config.account_id,
            v.public_keys().map_err(|e| e.to_string())?,
        )
    };
    let fingerprint = Some(mg_vault::sharing::fingerprint(&id, &keys));
    let caps = with_client(&sync, &vault, async |c| Ok(c.capabilities().await?)).await;
    let reason = match caps {
        Ok(c) if c.features.sharing.is_some() => None,
        Ok(_) => Some("This sync server doesn't support teams.".to_owned()),
        Err(e) => Some(e),
    };
    Ok(SharingStatus {
        available: reason.is_none(),
        reason,
        account_id: Some(id),
        fingerprint,
    })
}

/// Vaults on this device (works offline).
#[tauri::command]
pub fn vaults_list(vault: State<'_, VaultState>) -> Result<Vec<VaultInfo>, String> {
    vault.guard()?.vaults().map_err(|e| e.to_string())
}

/// Organizations on this device (works offline).
#[tauri::command]
pub fn orgs_list(vault: State<'_, VaultState>) -> Result<Vec<OrgInfo>, String> {
    vault.guard()?.orgs().map_err(|e| e.to_string())
}

/// The organizations whose vaults are locked: the server enforces plans and the team has no
/// usable one (none, or it ended). Their vaults can be read but not changed until it has one.
/// Empty when plans aren't enforced, or the server can't be asked (it enforces them anyway).
#[tauri::command]
pub async fn orgs_locked(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
) -> Result<Vec<String>, String> {
    let ids: Vec<String> = vault
        .guard()?
        .orgs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|o| o.id)
        .collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    with_client(&sync, &vault, async |c| {
        let enforced = c
            .capabilities()
            .await?
            .features
            .billing
            .is_some_and(|b| b.plans_enforced);
        let mut locked = Vec::new();
        if enforced {
            for id in ids {
                if let Ok(org) = c.org(&id).await
                    && !usable(org.entitlement.as_ref())
                {
                    locked.push(id);
                }
            }
        }
        Ok(locked)
    })
    .await
}

/// A plan that lets the team's vaults change, as the server counts it: a trial, an active plan or
/// its grace period.
fn usable(plan: Option<&mg_sync::Entitlement>) -> bool {
    plan.is_some_and(|p| {
        matches!(
            p.status.as_deref(),
            None | Some("trialing" | "active" | "grace")
        )
    })
}

#[tauri::command]
pub async fn org_create(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    name: String,
) -> Result<String, String> {
    let v = vault.0.clone();
    with_client(&sync, &vault, async |c| {
        sharing::create_org(&v, &c, &name).await
    })
    .await
}

#[tauri::command]
pub async fn org_vault_create(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    name: String,
) -> Result<String, String> {
    let v = vault.0.clone();
    let id = with_client(&sync, &vault, async |c| {
        sharing::create_vault(&v, &c, &org_id, &name).await
    })
    .await?;
    vault.changed();
    Ok(id)
}

#[tauri::command]
pub async fn org_members(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<Vec<MemberView>, String> {
    let v = vault.0.clone();
    with_client(&sync, &vault, async |c| {
        sharing::members(&v, &c, &org_id).await
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    id: String,
    email: String,
    role: Role,
    vaults: Vec<GrantView>,
    expires_at: String,
    /// Only right after creating it, on servers that don't email invites: pass it on.
    token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    vault_id: String,
    access: Access,
}

fn grant_view(g: VaultGrant) -> GrantView {
    GrantView {
        vault_id: g.vault_id,
        access: match g.permission {
            mg_sync::Permission::Read => Access::Read,
            mg_sync::Permission::Write => Access::Write,
            mg_sync::Permission::Manage => Access::Manage,
        },
    }
}

fn invite_view(i: mg_sync::Invite) -> InviteView {
    InviteView {
        id: i.id,
        email: i.email,
        role: i.role,
        vaults: i.vaults.into_iter().map(grant_view).collect(),
        expires_at: i.expires_at,
        token: i.token,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantInput {
    vault_id: String,
    access: String,
}

#[tauri::command]
pub async fn org_invite(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    email: String,
    role: Role,
    vaults: Vec<GrantInput>,
) -> Result<InviteView, String> {
    let grants: Vec<(String, Access)> = vaults
        .into_iter()
        .map(|g| (g.vault_id, Access::parse(&g.access)))
        .collect();
    with_client(&sync, &vault, async |c| {
        sharing::invite(&c, &org_id, &email, role, grants).await
    })
    .await
    .map(invite_view)
}

#[tauri::command]
pub async fn org_invites(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<Vec<InviteView>, String> {
    with_client(&sync, &vault, async |c| Ok(c.invites(&org_id).await?))
        .await
        .map(|list| list.into_iter().map(invite_view).collect())
}

#[tauri::command]
pub async fn org_invite_cancel(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    invite_id: String,
) -> Result<(), String> {
    with_client(&sync, &vault, async |c| {
        Ok(c.cancel_invite(&org_id, &invite_id).await?)
    })
    .await
}

#[tauri::command]
pub async fn invite_preview(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    token: String,
) -> Result<InvitePreview, String> {
    with_client(&sync, &vault, async |c| {
        sharing::preview_invite(&c, &token).await
    })
    .await
}

#[tauri::command]
pub async fn invite_accept(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    token: String,
    fingerprint: String,
) -> Result<String, String> {
    let v = vault.0.clone();
    let id = with_client(&sync, &vault, async |c| {
        sharing::accept_invite(&v, &c, &token, &fingerprint).await
    })
    .await?;
    vault.changed();
    Ok(id)
}

#[tauri::command]
pub async fn member_confirm(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
    fingerprint: String,
) -> Result<(), String> {
    let v = vault.0.clone();
    with_client(&sync, &vault, async |c| {
        sharing::confirm_member(&v, &c, &org_id, &account_id, &fingerprint).await
    })
    .await
}

#[tauri::command]
pub async fn member_role(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
    role: Role,
) -> Result<(), String> {
    let v = vault.0.clone();
    with_client(&sync, &vault, async |c| {
        sharing::set_role(&v, &c, &org_id, &account_id, role).await
    })
    .await?;
    vault.changed();
    Ok(())
}

/// Removes a member, or leaves when `account_id` is this account.
#[tauri::command]
pub async fn member_remove(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
) -> Result<(), String> {
    let v = vault.0.clone();
    with_client(&sync, &vault, async |c| {
        sharing::remove_member(&v, &c, &org_id, &account_id).await
    })
    .await?;
    vault.changed();
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAccessView {
    account_id: String,
    email: String,
    access: Access,
    /// Owners and admins: access comes with the role.
    implicit: bool,
}

#[tauri::command]
pub async fn vault_access(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    vault_id: String,
) -> Result<Vec<VaultAccessView>, String> {
    let org = vault
        .guard()?
        .vaults()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|v| v.id == vault_id)
        .and_then(|v| v.org_id)
        .ok_or("not a shared vault")?;
    let (members, emails) = with_client(&sync, &vault, async |c| {
        let members = c.vault_members(&vault_id).await?;
        let emails = c.members(&org).await?;
        Ok((members, emails))
    })
    .await?;
    Ok(members
        .into_iter()
        .map(|m| VaultAccessView {
            email: emails
                .iter()
                .find(|e| e.account_id == m.account_id)
                .map(|e| e.email.clone())
                .unwrap_or_default(),
            access: match m.permission {
                mg_sync::Permission::Read => Access::Read,
                mg_sync::Permission::Write => Access::Write,
                mg_sync::Permission::Manage => Access::Manage,
            },
            implicit: m.implicit,
            account_id: m.account_id,
        })
        .collect())
}

#[tauri::command]
pub async fn vault_access_set(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    vault_id: String,
    account_id: String,
    access: String,
) -> Result<(), String> {
    let v = vault.0.clone();
    let access = Access::parse(&access);
    with_client(&sync, &vault, async |c| {
        sharing::set_access(&v, &c, &vault_id, &account_id, access).await
    })
    .await
}

#[tauri::command]
pub async fn vault_access_revoke(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    vault_id: String,
    account_id: String,
) -> Result<(), String> {
    with_client(&sync, &vault, async |c| {
        sharing::revoke_access(&c, &vault_id, &account_id).await
    })
    .await?;
    vault.changed();
    Ok(())
}

/// A new key for the vault, sealed to everyone who still has access; this device's copies of
/// its items are re-sealed and pushed on the next sync.
#[tauri::command]
pub async fn vault_rotate(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    vault_id: String,
) -> Result<(), String> {
    let v = vault.0.clone();
    with_client(&sync, &vault, async |c| {
        sharing::rotate(&v, &c, &vault_id).await
    })
    .await?;
    vault.changed();
    Ok(())
}

#[tauri::command]
pub async fn org_transfer(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
    password: String,
) -> Result<(), String> {
    let v = vault.0.clone();
    let password = Zeroizing::new(password);
    with_client(&sync, &vault, async |c| {
        sharing::transfer(&v, &c, &org_id, &account_id, password).await
    })
    .await?;
    vault.changed();
    Ok(())
}

#[tauri::command]
pub async fn org_delete(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    password: String,
) -> Result<(), String> {
    let v = vault.0.clone();
    let password = Zeroizing::new(password);
    with_client(&sync, &vault, async |c| {
        sharing::delete_org(&v, &c, &org_id, password).await
    })
    .await?;
    vault.changed();
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoliciesView {
    require_totp: bool,
    members_can_create_vaults: bool,
    allowed_email_domains: Vec<String>,
    /// The server deletes team session logs older than this; 0 keeps them.
    #[serde(default)]
    session_log_retention_days: u32,
    /// Set on the website, with the identity provider; sent back unchanged.
    #[serde(default)]
    require_sso: bool,
    /// New devices wait for an owner's or admin's approval (or the member's, from an approved
    /// device) before they open the organization's vaults.
    #[serde(default)]
    require_device_approval: bool,
    /// Members publish their SSH keys; `None` when the server doesn't say (sent only when set).
    #[serde(default)]
    require_member_keys: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanView {
    plan: String,
    /// `trialing`, `active`, `grace`, `lapsed` or `canceled`.
    status: Option<String>,
    expires_at: Option<String>,
    grace_ends_at: Option<String>,
    seats: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgDetails {
    policies: PoliciesView,
    /// Hosted servers: the organization's plan.
    plan: Option<PlanView>,
    /// The server offers two-step verification, so it can be required.
    totp_offered: bool,
    /// The server has an account portal (plans and seats are managed there).
    portal: bool,
    /// The server sells plans (hosted): a team without one says so.
    plans_offered: bool,
    /// Vaults without a usable plan refuse changes.
    plans_enforced: bool,
    /// The plan's features (`sso`, `scim`, `session_logs`); `None`: the server has no plans.
    features: Option<Vec<String>>,
    /// The server stores session logs (blobs).
    session_logs_offered: bool,
    /// The server can put the organization behind its identity provider.
    sso_offered: bool,
}

/// What the server says about an organization now: policies and plan.
#[tauri::command]
pub async fn org_details(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<OrgDetails, String> {
    let (org, caps) = with_client(&sync, &vault, async |c| {
        Ok((c.org(&org_id).await?, c.capabilities().await?))
    })
    .await?;
    let p = org.policies;
    Ok(OrgDetails {
        policies: PoliciesView {
            require_totp: p.require_totp,
            members_can_create_vaults: p.members_can_create_vaults,
            allowed_email_domains: p.allowed_email_domains,
            session_log_retention_days: p.session_log_retention_days,
            require_sso: p.require_sso,
            require_device_approval: p.require_device_approval,
            require_member_keys: p.require_member_keys,
        },
        // No entitlement: the server has no plans, so nothing is held back.
        features: org.entitlement.as_ref().map(|e| e.features.clone()),
        plan: org.entitlement.map(|e| PlanView {
            plan: e.plan,
            status: e.status,
            expires_at: e.expires_at,
            grace_ends_at: e.grace_ends_at,
            seats: e.seats,
        }),
        totp_offered: caps.features.totp,
        portal: caps
            .features
            .billing
            .as_ref()
            .is_some_and(|b| b.web_session),
        plans_offered: caps.features.billing.is_some(),
        plans_enforced: caps
            .features
            .billing
            .as_ref()
            .is_some_and(|b| b.plans_enforced),
        session_logs_offered: caps.features.blobs.is_some(),
        sso_offered: caps.features.sso.is_some(),
    })
}

#[tauri::command]
pub async fn org_policies_set(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    policies: PoliciesView,
) -> Result<(), String> {
    let req = UpdateOrg {
        name: None,
        policies: Some(Policies {
            require_totp: policies.require_totp,
            members_can_create_vaults: policies.members_can_create_vaults,
            allowed_email_domains: policies
                .allowed_email_domains
                .iter()
                .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            session_log_retention_days: policies.session_log_retention_days.min(3650),
            require_sso: policies.require_sso,
            require_device_approval: policies.require_device_approval,
            require_member_keys: policies.require_member_keys,
        }),
    };
    with_client(&sync, &vault, async |c| {
        c.update_org(&org_id, &req).await?;
        Ok(())
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventView {
    seq: i64,
    at: String,
    kind: String,
    actor_id: Option<String>,
    target_id: Option<String>,
    vault_id: Option<String>,
    detail: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityView {
    /// Newest first.
    events: Vec<EventView>,
    /// Account and vault ids to names, as far as this device knows them.
    names: HashMap<String, String>,
    /// Older events exist beyond what was loaded.
    truncated: bool,
}

/// Events kept for the app (the newest); pages are read to the end to reach them.
const ACTIVITY_KEPT: usize = 5000;
/// Pages read at most (1000 events each), a bound against a server that never says "done".
const ACTIVITY_PAGES: usize = 1000;

/// The organization's audit log (owners and admins), newest first.
#[tauri::command]
pub async fn org_activity(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<ActivityView, String> {
    let (events, members, truncated) = with_client(&sync, &vault, async |c| {
        let mut events = std::collections::VecDeque::new();
        let mut since = 0;
        let mut truncated = false;
        for _ in 0..ACTIVITY_PAGES {
            let page = c.org_events(&org_id, since, 1000).await?;
            since = page.events.last().map_or(since, |e| e.seq);
            events.extend(page.events);
            while events.len() > ACTIVITY_KEPT {
                events.pop_front();
                truncated = true;
            }
            if !page.has_more {
                break;
            }
        }
        Ok((events, c.members(&org_id).await?, truncated))
    })
    .await?;
    let mut names = {
        let v = vault.guard()?;
        let mut names = v.known_emails().map_err(|e| e.to_string())?;
        for x in v.vaults().map_err(|e| e.to_string())? {
            if let Some(name) = x.name {
                names.insert(x.id, name);
            }
        }
        names
    };
    for m in members {
        names.insert(m.account_id, m.email);
    }
    Ok(ActivityView {
        events: events
            .into_iter()
            .rev()
            .map(|e| EventView {
                seq: e.seq,
                at: e.at,
                kind: e.kind,
                actor_id: e.actor_id,
                target_id: e.target_id,
                vault_id: e.vault_id,
                detail: e.detail,
            })
            .collect(),
        names,
        truncated,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberKeyView {
    id: String,
    account_id: String,
    /// The member's email, as far as this device knows it.
    email: Option<String>,
    public_key: String,
    label: String,
    fingerprint: Option<String>,
    /// Signed by that member.
    verified: bool,
    mine: bool,
}

/// SSH public keys members published in the organization's directory (works offline).
#[tauri::command]
pub fn member_keys(
    vault: State<'_, VaultState>,
    org_id: String,
) -> Result<Vec<MemberKeyView>, String> {
    let v = vault.guard()?;
    let names = v.known_emails().map_err(|e| e.to_string())?;
    Ok(v.member_keys(&org_id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|k| MemberKeyView {
            fingerprint: mg_ssh::keys::public_fingerprint(&k.public_key),
            email: names.get(&k.account_id).cloned(),
            id: k.id,
            account_id: k.account_id,
            public_key: k.public_key,
            label: k.label,
            verified: k.verified,
            mine: k.mine,
        })
        .collect())
}

/// Publishes the public half of one of this account's SSH keys (a vault `ssh_key` item) in the
/// organization's directory.
#[tauri::command]
pub fn member_key_publish(
    vault: State<'_, VaultState>,
    org_id: String,
    key_id: String,
) -> Result<String, String> {
    let id = {
        let mut v = vault.guard()?;
        let mg_store::ItemData::SshKey(k) = v.item(&key_id).map_err(|e| e.to_string())?.data else {
            return Err("not an SSH key".into());
        };
        v.publish_member_key(&org_id, &k.public_key, &k.label)
            .map_err(|e| e.to_string())?
    };
    vault.changed();
    Ok(id)
}

#[tauri::command]
pub fn member_key_unpublish(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(|e| e.to_string())?;
    vault.changed();
    Ok(())
}

// ------------------------------------------------------------------ single sign-on

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoView {
    configured: bool,
    required: bool,
    protocol: Option<String>,
    issuer: Option<String>,
    /// This device's session, if it has one.
    session_expires_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequestView {
    account_id: String,
    email: Option<String>,
    device_id: String,
    name: Option<String>,
    platform: Option<String>,
    /// `pending`, `approved` or `denied`.
    status: String,
    requested_at: String,
    decided_at: Option<String>,
    /// The account's own device.
    mine: bool,
    /// This device.
    this_device: bool,
}

/// Devices waiting for a decision, and the ones denied: everyone's for owners and admins, the
/// member's own otherwise.
#[tauri::command]
pub async fn org_device_requests(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<Vec<DeviceRequestView>, String> {
    let (me, device) = {
        let v = vault.guard()?;
        let info = v.sync_info().map_err(|e| e.to_string())?;
        let config = info.map(|i| i.config);
        (
            config.as_ref().map(|c| c.account_id.clone()),
            config.map(|c| c.device_id),
        )
    };
    let rows = with_client(&sync, &vault, async |c| {
        let mut rows = c.org_devices(&org_id, Some("pending")).await?;
        rows.extend(c.org_devices(&org_id, Some("denied")).await?);
        Ok(rows)
    })
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let mine = Some(&r.account_id) == me.as_ref();
            DeviceRequestView {
                this_device: mine && Some(&r.device_id) == device.as_ref(),
                mine,
                account_id: r.account_id,
                email: r.email,
                device_id: r.device_id,
                name: r.name,
                platform: r.platform,
                status: r.status,
                requested_at: r.requested_at,
                decided_at: r.decided_at,
            }
        })
        .collect())
}

/// Approves or denies a device's request to open the organization's vaults.
#[tauri::command]
pub async fn org_device_decide(
    app: AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
    device_id: String,
    approve: bool,
) -> Result<(), String> {
    with_client(&sync, &vault, async |c| {
        Ok(c.decide_device(&org_id, &account_id, &device_id, approve)
            .await?)
    })
    .await?;
    // The badge counts waiting devices: the next round recounts.
    sync.poke.notify_one();
    crate::sync::emit_status(&app, false);
    Ok(())
}

/// Saves the organization's whole activity log (`csv` or `jsonl`) in the downloads folder;
/// returns where. Owners and admins, on servers that offer it.
#[tauri::command]
pub async fn org_events_export(
    app: AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    format: String,
) -> Result<String, String> {
    let ext = match format.as_str() {
        "csv" | "jsonl" => format.clone(),
        _ => return Err("the activity log downloads as csv or jsonl".into()),
    };
    let name = vault
        .guard()?
        .orgs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|o| o.id == org_id)
        .map_or_else(|| org_id.clone(), |o| o.name);
    let text = with_client(&sync, &vault, async |c| {
        Ok(c.org_events_export(&org_id, &format).await?)
    })
    .await
    .map_err(|e| {
        if e.contains("(not_found)") || e.contains("404") {
            "this sync server doesn't offer the activity log as a download".to_owned()
        } else {
            e
        }
    })?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let day = mg_store::export::rfc3339(secs);
    let path = crate::util::download_path(
        &app,
        &format!("morphgate-activity-{name}-{}", &day[..10]),
        &ext,
    )?;
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::saved(&path))
}

/// Certifies a confirmed member again after comparing their fingerprint (owners and admins).
#[tauri::command]
pub async fn org_member_recertify(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
    account_id: String,
    fingerprint: String,
) -> Result<(), String> {
    let stored = with_client(&sync, &vault, async |c| {
        sharing::recertify(&vault.0, &c, &org_id, &account_id, Some(&fingerprint)).await
    })
    .await?;
    if stored {
        Ok(())
    } else {
        Err("this sync server can't certify members again yet".into())
    }
}

/// The organization's identity provider and this device's session with it.
#[tauri::command]
pub async fn org_sso_status(
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<SsoView, String> {
    let s = with_client(&sync, &vault, async |c| Ok(c.sso_status(&org_id).await?)).await?;
    Ok(SsoView {
        configured: s.configured,
        required: s.required,
        protocol: s.protocol,
        issuer: s.issuer,
        session_expires_at: s.session_expires_at,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoStartView {
    url: String,
    expires_in: u32,
}

/// Starts a sign-in at the organization's identity provider and opens it in the browser.
#[tauri::command]
pub async fn org_sso_start(
    app: AppHandle,
    vault: State<'_, VaultState>,
    sync: State<'_, SyncState>,
    org_id: String,
) -> Result<SsoStartView, String> {
    let start = with_client(&sync, &vault, async |c| Ok(c.sso_start(&org_id).await?)).await?;
    crate::util::open_in_browser(&app, &start.url)?;
    Ok(SsoStartView {
        url: start.url,
        expires_in: start.expires_in,
    })
}
