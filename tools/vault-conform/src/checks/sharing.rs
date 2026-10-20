//! Organizations and shared vaults, with real keys: the app's own store and sync engine sign,
//! seal and verify everything, so the server sees exactly what apps send.

use std::sync::{Arc, Mutex};

use mg_store::account::{self, SharedVault};
use mg_store::sharing::{self, RefreshReport};
use mg_store::sync::{SyncConfig, SyncReport, sync_once};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{Access, Host, HostAuth, ItemData, LocalVault};
use mg_sync::{B64, DeviceInfo, Error, MemberStatus, Policies, Role, SyncClient, UpdateOrg};
use mg_vault::KdfParams;
use zeroize::Zeroizing;

use super::auth::outcome;
use crate::report::{ensure, shown};
use crate::{Ctx, Report};

const G: &str = "sharing";
const PW: &str = "correct horse battery staple";

/// Everything this group checks, so what can't run is listed as skipped.
const PLAN: &[(&str, &str)] = &[
    ("POST /orgs", "creates an organization"),
    ("GET /orgs", "lists the account's organizations"),
    (
        "GET /orgs/{org_id}",
        "shows the organization and its ownership chain",
    ),
    ("PATCH /orgs/{org_id}", "renames it and sets policies"),
    ("POST /vaults", "creates an organization vault"),
    (
        "GET /vaults/{vault_id}/members",
        "lists who can open the vault",
    ),
    (
        "POST /orgs/{org_id}/invites",
        "invites an address with a vault grant",
    ),
    ("GET /orgs/{org_id}/invites", "lists open invites"),
    (
        "DELETE /orgs/{org_id}/invites/{invite_id}",
        "cancels an invite",
    ),
    (
        "GET /invites/{token}",
        "previews an invite with the ownership chain",
    ),
    ("POST /invites/{token}/accept", "accepts an invite"),
    (
        "GET /orgs/{org_id}/members",
        "lists members with their keys",
    ),
    (
        "POST /orgs/{org_id}/members/{account_id}/confirm",
        "confirms a member; their grant opens the vault",
    ),
    (
        "PUT /vaults/{vault_id}/members/{account_id}",
        "changes a member's access to write",
    ),
    (
        "DELETE /vaults/{vault_id}/members/{account_id}",
        "revokes a member's access",
    ),
    ("POST /vaults/{vault_id}/keys", "rotates the vault key"),
    (
        "PATCH /orgs/{org_id}/members/{account_id}",
        "makes a member an admin",
    ),
    (
        "PUT /orgs/{org_id}/members/{account_id}/certificate",
        "certifies a member again",
    ),
    ("GET /orgs/{org_id}/events", "records the audit log"),
    (
        "GET /orgs/{org_id}/events/export",
        "downloads the audit log as CSV",
    ),
    (
        "GET /orgs/{org_id}/devices",
        "lists devices waiting for approval",
    ),
    (
        "POST /orgs/{org_id}/members/{account_id}/devices/{device_id}/approve",
        "approves a device",
    ),
    (
        "POST /orgs/{org_id}/members/{account_id}/devices/{device_id}/deny",
        "denies a device",
    ),
    ("PATCH /orgs/{org_id}", "accepts require_member_keys"),
    (
        "GET /orgs/{org_id}/sso",
        "shows the identity provider (none here)",
    ),
    (
        "POST /orgs/{org_id}/sso/start",
        "refuses to start without a provider (409)",
    ),
    (
        "POST /orgs/{org_id}/transfer",
        "hands ownership to an admin",
    ),
    (
        "DELETE /orgs/{org_id}/members/{account_id}",
        "removes a member",
    ),
    ("DELETE /orgs/{org_id}", "deletes the organization"),
];

/// Lists every planned check that hasn't run yet as skipped.
fn skip_rest(r: &mut Report, why: &str) {
    for (e, w) in PLAN {
        if !r
            .checks
            .iter()
            .any(|c| c.group == G && c.endpoint == *e && c.what == *w)
        {
            r.skip(G, e, w, why);
        }
    }
}

struct Person {
    vault: SharedVault,
    client: Arc<SyncClient>,
    id: String,
    email: String,
}

fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: Some(env!("CARGO_PKG_VERSION").into()),
        public_key: B64(vec![1; 32]),
    }
}

fn fast() -> LocalVault {
    LocalVault::open_in_memory()
        .expect("an in-memory vault")
        .with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
}

/// A new account with a real vault and sync on.
async fn person(ctx: &Ctx, name: &str) -> Result<Person, String> {
    let mut v = fast();
    v.create(PW).map_err(shown)?;
    let (export, _) = v.export_for_registration(PW).map_err(shown)?;
    let client = Arc::new(ctx.client()?);
    let email = ctx.email(name);
    let info = device(name);
    let session = client
        .register(&register_request(
            &export,
            &email,
            info.clone(),
            ctx.registration_code(&client, &email).await?,
        ))
        .await
        .map_err(|e| format!("registering {email}: {e}"))?;
    client
        .create_vault(&create_vault_request(&export.vault))
        .await
        .map_err(shown)?;
    v.enable_sync(&SyncConfig {
        server_url: ctx.opts.server.clone(),
        email: email.clone(),
        account_id: session.account_id.clone(),
        device_id: info.id,
        device_public_key: [1; 32],
    })
    .map_err(shown)?;
    Ok(Person {
        vault: Arc::new(Mutex::new(v)),
        client,
        id: session.account_id,
        email,
    })
}

/// Another device of the same account, signed in with the master password.
async fn another(ctx: &Ctx, of: &Person, name: &str) -> Result<Person, String> {
    let p = Person {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(ctx.client()?),
        id: of.id.clone(),
        email: of.email.clone(),
    };
    account::sign_in(
        &p.vault,
        p.client.clone(),
        &of.email,
        Zeroizing::new(PW.into()),
        device(name),
        None,
    )
    .await
    .map_err(shown)?;
    Ok(p)
}

/// What the app does each round: organizations and shared vaults, then items.
async fn round(p: &Person) -> Result<(RefreshReport, SyncReport), String> {
    let refresh = sharing::refresh(&p.vault, &p.client)
        .await
        .map_err(|e| format!("refreshing: {e}"))?;
    let report = sync_once(&p.vault, &HttpRemote(&p.client))
        .await
        .map_err(|e| format!("syncing: {e}"))?;
    ensure(
        report.vault_errors.is_empty(),
        format!("vault errors: {:?}", report.vault_errors),
    )?;
    Ok((refresh, report))
}

fn fingerprint(p: &Person) -> Result<String, String> {
    let keys = p
        .vault
        .lock()
        .map_err(|_| "poisoned")?
        .public_keys()
        .map_err(shown)?;
    Ok(mg_vault::sharing::fingerprint(&p.id, &keys))
}

fn host(label: &str) -> ItemData {
    ItemData::Host(Host {
        label: label.into(),
        hostname: format!("{label}.internal"),
        port: 22,
        user: "deploy".into(),
        auth: HostAuth::system_agent(),
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
    })
}

fn labels(p: &Person, vault: &str) -> Vec<String> {
    let Ok(v) = p.vault.lock() else {
        return Vec::new();
    };
    let mut out: Vec<String> = v
        .items()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.vault_id == vault)
        .filter_map(|i| match i.data {
            ItemData::Host(h) => Some(h.label),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

pub async fn run(ctx: &Ctx, r: &mut Report) {
    let sharing_caps = ctx.caps.as_ref().and_then(|c| c.features.sharing.clone());
    let Some(caps) = sharing_caps else {
        return skip_rest(r, "the server doesn't offer sharing (features.sharing)");
    };
    if caps.mails_invites && ctx.opts.mailpit.is_none() {
        return skip_rest(
            r,
            "the server mails invites: pass --mailpit URL to read them",
        );
    }
    if let Err(why) = ctx.accounts() {
        return skip_rest(r, why);
    }
    let Some((alice, bob, carol)) = r
        .check(
            G,
            "POST /auth/register",
            "three people with real keys",
            async {
                Ok((
                    person(ctx, "alice").await?,
                    person(ctx, "bob").await?,
                    person(ctx, "carol").await?,
                ))
            },
        )
        .await
    else {
        return skip_rest(r, "needs three accounts");
    };

    // The organization and its vault.
    let Some(org) = r
        .check(G, PLAN[0].0, PLAN[0].1, async {
            sharing::create_org(&alice.vault, &alice.client, "Conformance")
                .await
                .map_err(shown)
        })
        .await
    else {
        return skip_rest(r, "needs the organization");
    };
    r.check(G, PLAN[1].0, PLAN[1].1, async {
        let list = alice.client.orgs().await.map_err(shown)?;
        let m = list
            .iter()
            .find(|m| m.id == org)
            .ok_or("the organization isn't listed")?;
        ensure(
            m.role == Role::Owner && m.status == MemberStatus::Confirmed,
            format!("role {:?}, status {:?}", m.role, m.status),
        )
    })
    .await;
    r.check(G, PLAN[2].0, PLAN[2].1, async {
        let o = alice.client.org(&org).await.map_err(shown)?;
        ensure(
            o.name == "Conformance" && o.owner_id == alice.id,
            "another name or owner",
        )?;
        ensure(
            o.owner_chain.len() == 1,
            format!(
                "{} links in the ownership chain, expected 1",
                o.owner_chain.len()
            ),
        )
    })
    .await;
    r.check(G, PLAN[3].0, PLAN[3].1, async {
        let o = alice
            .client
            .update_org(
                &org,
                &UpdateOrg {
                    name: Some("Conformance Ops".into()),
                    policies: Some(Policies {
                        members_can_create_vaults: true,
                        ..Default::default()
                    }),
                },
            )
            .await
            .map_err(shown)?;
        ensure(o.name == "Conformance Ops", "the name didn't change")?;
        ensure(
            o.policies.members_can_create_vaults,
            "the policy didn't take",
        )
    })
    .await;
    let Some(prod) = r
        .check(G, PLAN[4].0, PLAN[4].1, async {
            let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
                .await
                .map_err(shown)?;
            alice
                .vault
                .lock()
                .map_err(|_| "poisoned")?
                .upsert_in(&prod, None, host("db1"))
                .map_err(shown)?;
            round(&alice).await?;
            Ok(prod)
        })
        .await
    else {
        return skip_rest(r, "needs the organization vault");
    };
    r.check(G, PLAN[5].0, PLAN[5].1, async {
        let members = alice.client.vault_members(&prod).await.map_err(shown)?;
        ensure(
            members.iter().any(|m| m.account_id == alice.id),
            "the creator isn't listed",
        )
    })
    .await;

    // Bob joins: invite, preview, accept, confirm.
    let Some(invite) = r
        .check(G, PLAN[6].0, PLAN[6].1, async {
            sharing::invite(
                &alice.client,
                &org,
                &bob.email,
                Role::Member,
                vec![(prod.clone(), Access::Read)],
            )
            .await
            .map_err(shown)
        })
        .await
    else {
        return skip_rest(r, "needs an invite");
    };
    let token = match invite.token.clone() {
        Some(t) => t,
        None => match ctx.mailed_invite(&bob.email).await {
            Ok(t) => t,
            Err(e) => return skip_rest(r, &format!("the invite's token: {e}")),
        },
    };
    r.check(G, PLAN[7].0, PLAN[7].1, async {
        let list = alice.client.invites(&org).await.map_err(shown)?;
        ensure(
            list.iter()
                .any(|i| i.email.eq_ignore_ascii_case(&bob.email)),
            "Bob's invite isn't listed",
        )
    })
    .await;
    r.check(G, PLAN[8].0, PLAN[8].1, async {
        let extra = sharing::invite(
            &alice.client,
            &org,
            &ctx.email("nobody"),
            Role::Member,
            vec![],
        )
        .await
        .map_err(shown)?;
        alice
            .client
            .cancel_invite(&org, &extra.id)
            .await
            .map_err(shown)?;
        let list = alice.client.invites(&org).await.map_err(shown)?;
        ensure(
            list.iter().all(|i| i.id != extra.id),
            "the cancelled invite is still listed",
        )
    })
    .await;
    let Some(preview) = r
        .check(G, PLAN[9].0, PLAN[9].1, async {
            let preview = sharing::preview_invite(&bob.client, &token)
                .await
                .map_err(shown)?;
            ensure(
                preview.org_name == "Conformance Ops",
                format!("organization {:?}", preview.org_name),
            )?;
            ensure(
                preview.owner_fingerprint == fingerprint(&alice)?,
                "the owner's fingerprint doesn't match the owner's keys",
            )?;
            Ok(preview)
        })
        .await
    else {
        return skip_rest(r, "needs the invite preview");
    };
    r.check(G, PLAN[10].0, PLAN[10].1, async {
        sharing::accept_invite(&bob.vault, &bob.client, &token, &preview.owner_fingerprint)
            .await
            .map_err(shown)?;
        round(&bob).await.map(drop)
    })
    .await;
    r.check(G, PLAN[11].0, PLAN[11].1, async {
        let list = alice.client.members(&org).await.map_err(shown)?;
        let b = list
            .iter()
            .find(|m| m.account_id == bob.id)
            .ok_or("Bob isn't listed")?;
        ensure(
            b.status == MemberStatus::Accepted,
            format!("Bob is {:?}, expected accepted", b.status),
        )
    })
    .await;
    if r.check(G, PLAN[12].0, PLAN[12].1, async {
        sharing::confirm_member(
            &alice.vault,
            &alice.client,
            &org,
            &bob.id,
            &fingerprint(&bob)?,
        )
        .await
        .map_err(shown)?;
        round(&bob).await?;
        ensure(
            labels(&bob, &prod) == ["db1"],
            format!("Bob sees {:?}", labels(&bob, &prod)),
        )
    })
    .await
    .is_none()
    {
        return skip_rest(r, "needs Bob confirmed");
    }

    // Access: write, revoke, rotate.
    r.check(G, PLAN[13].0, PLAN[13].1, async {
        sharing::set_access(&alice.vault, &alice.client, &prod, &bob.id, Access::Write)
            .await
            .map_err(shown)?;
        round(&bob).await?;
        bob.vault
            .lock()
            .map_err(|_| "poisoned")?
            .upsert_in(&prod, None, host("db2"))
            .map_err(shown)?;
        round(&bob).await?;
        round(&alice).await?;
        ensure(
            labels(&alice, &prod) == ["db1", "db2"],
            format!("Alice sees {:?}", labels(&alice, &prod)),
        )
    })
    .await;
    r.check(G, PLAN[14].0, PLAN[14].1, async {
        sharing::revoke_access(&alice.client, &prod, &bob.id)
            .await
            .map_err(shown)?;
        round(&bob).await?;
        ensure(labels(&bob, &prod).is_empty(), "Bob still has the vault")
    })
    .await;
    r.check(G, PLAN[15].0, PLAN[15].1, async {
        sharing::rotate(&alice.vault, &alice.client, &prod)
            .await
            .map_err(shown)?;
        round(&alice).await?;
        let v = alice.client.vault(&prod).await.map_err(shown)?;
        ensure(!v.rotation_due, "the vault still wants a rotation")?;
        ensure(
            labels(&alice, &prod) == ["db1", "db2"],
            "items didn't survive the rotation",
        )
    })
    .await;

    // Bob becomes an admin, is certified again, and the log shows it all.
    r.check(G, PLAN[16].0, PLAN[16].1, async {
        sharing::set_role(&alice.vault, &alice.client, &org, &bob.id, Role::Admin)
            .await
            .map_err(shown)?;
        let list = alice.client.members(&org).await.map_err(shown)?;
        let b = list
            .iter()
            .find(|m| m.account_id == bob.id)
            .ok_or("Bob isn't listed")?;
        ensure(b.role == Role::Admin, format!("Bob is {:?}", b.role))?;
        round(&bob).await?;
        ensure(
            labels(&bob, &prod) == ["db1", "db2"],
            "as an admin, Bob doesn't open the vault",
        )
    })
    .await;
    r.check(G, PLAN[17].0, PLAN[17].1, async {
        match sharing::recertify(
            &alice.vault,
            &alice.client,
            &org,
            &bob.id,
            Some(&fingerprint(&bob)?),
        )
        .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err("the server answers 404/405: it has no PUT …/certificate".into()),
            Err(e) => Err(shown(e)),
        }
    })
    .await;
    r.check(G, PLAN[18].0, PLAN[18].1, async {
        let events = alice
            .client
            .org_events(&org, 0, 1000)
            .await
            .map_err(shown)?
            .events;
        let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
        for k in [
            "org_created",
            "member_invited",
            "member_confirmed",
            "vault_access_revoked",
            "vault_key_rotated",
        ] {
            ensure(
                kinds.contains(&k),
                format!("no {k} event (kinds: {kinds:?})"),
            )?;
        }
        Ok(())
    })
    .await;

    match alice.client.org_events_export(&org, "csv").await {
        Err(Error::Api { status: 404, .. }) => r.skip(
            G,
            PLAN[19].0,
            PLAN[19].1,
            "the server doesn't offer it (404; it's optional)",
        ),
        csv => {
            r.check(G, PLAN[19].0, PLAN[19].1, async {
                let csv = csv.map_err(shown)?;
                let header = csv.lines().next();
                ensure(
                    header.is_some_and(|h| h.starts_with("seq,at,kind")),
                    format!("header {header:?}"),
                )
            })
            .await;
        }
    }
    device_approval(ctx, r, &alice, &bob, &org, &prod).await;
    r.check(G, PLAN[23].0, PLAN[23].1, async {
        let o = alice
            .client
            .update_org(
                &org,
                &UpdateOrg {
                    name: None,
                    policies: Some(Policies {
                        require_member_keys: Some(true),
                        ..Default::default()
                    }),
                },
            )
            .await
            .map_err(shown)?;
        ensure(
            o.policies.require_member_keys == Some(true),
            format!(
                "require_member_keys is {:?}",
                o.policies.require_member_keys
            ),
        )
    })
    .await;
    sso(ctx, r, &alice, &org).await;

    // Ownership goes to Bob; Bob removes Carol, then Alice; then the organization goes.
    r.check(G, PLAN[26].0, PLAN[26].1, async {
        sharing::transfer(
            &alice.vault,
            &alice.client,
            &org,
            &bob.id,
            Zeroizing::new(PW.into()),
        )
        .await
        .map_err(shown)?;
        let o = bob.client.org(&org).await.map_err(shown)?;
        ensure(o.owner_id == bob.id, "Bob isn't the owner")?;
        ensure(
            o.owner_chain.len() == 2,
            format!(
                "{} links in the ownership chain, expected 2",
                o.owner_chain.len()
            ),
        )
    })
    .await;
    r.check(G, PLAN[27].0, PLAN[27].1, async {
        let invite = sharing::invite(&bob.client, &org, &carol.email, Role::Member, vec![])
            .await
            .map_err(shown)?;
        let token = match invite.token {
            Some(t) => t,
            None => ctx.mailed_invite(&carol.email).await?,
        };
        let preview = sharing::preview_invite(&carol.client, &token)
            .await
            .map_err(shown)?;
        sharing::accept_invite(
            &carol.vault,
            &carol.client,
            &token,
            &preview.owner_fingerprint,
        )
        .await
        .map_err(shown)?;
        sharing::remove_member(&bob.vault, &bob.client, &org, &carol.id)
            .await
            .map_err(shown)?;
        sharing::remove_member(&bob.vault, &bob.client, &org, &alice.id)
            .await
            .map_err(shown)?;
        let list = bob.client.members(&org).await.map_err(shown)?;
        ensure(
            list.iter()
                .all(|m| m.account_id != alice.id && m.account_id != carol.id),
            "a removed member is still listed",
        )?;
        match alice.client.org(&org).await {
            Err(Error::Api {
                status: 404 | 403, ..
            }) => Ok(()),
            other => Err(format!(
                "the removed owner opening it: expected 404, got {}",
                outcome(other)
            )),
        }
    })
    .await;
    r.check(G, PLAN[28].0, PLAN[28].1, async {
        sharing::delete_org(&bob.vault, &bob.client, &org, Zeroizing::new(PW.into()))
            .await
            .map_err(shown)?;
        match bob.client.org(&org).await {
            Err(Error::Api { status: 404, .. }) => Ok(()),
            other => Err(format!("expected 404, got {}", outcome(other))),
        }
    })
    .await;
}

/// Device approval, where the server knows the policy.
async fn device_approval(
    ctx: &Ctx,
    r: &mut Report,
    alice: &Person,
    bob: &Person,
    org: &str,
    prod: &str,
) {
    let on = alice
        .client
        .update_org(
            org,
            &UpdateOrg {
                name: None,
                policies: Some(Policies {
                    require_device_approval: true,
                    ..Default::default()
                }),
            },
        )
        .await;
    match on {
        Ok(o) if o.policies.require_device_approval => {}
        Ok(_) => {
            for (endpoint, what) in &PLAN[20..23] {
                r.skip(
                    G,
                    endpoint,
                    what,
                    "the server ignores require_device_approval",
                );
            }
            return;
        }
        Err(Error::PaymentRequired(_)) => {
            for (endpoint, what) in &PLAN[20..23] {
                r.skip(
                    G,
                    endpoint,
                    what,
                    "the organization's plan doesn't include device approval (402)",
                );
            }
            return;
        }
        Err(e) => {
            for (endpoint, what) in &PLAN[20..23] {
                r.skip(
                    G,
                    endpoint,
                    what,
                    &format!("the server refuses require_device_approval: {e}"),
                );
            }
            return;
        }
    }
    let Some(laptop) = r
        .check(
            G,
            "GET /vaults/{vault_id}",
            "refuses an unapproved device (403 device_approval_required)",
            async {
                let laptop = another(ctx, bob, "bob-laptop").await?;
                match laptop.client.vault(prod).await {
                    Err(Error::DeviceApprovalRequired {
                        org_id,
                        denied: false,
                    }) if org_id == org => Ok(laptop),
                    other => Err(format!(
                        "expected 403 device_approval_required (pending), got {}",
                        outcome(other)
                    )),
                }
            },
        )
        .await
    else {
        for (endpoint, what) in &PLAN[20..23] {
            r.skip(G, endpoint, what, "needs a waiting device");
        }
        return;
    };
    let device = laptop
        .vault
        .lock()
        .ok()
        .and_then(|v| v.sync_info().ok().flatten())
        .map(|i| i.config.device_id)
        .unwrap_or_default();
    r.check(G, PLAN[20].0, PLAN[20].1, async {
        let waiting = alice
            .client
            .org_devices(org, Some("pending"))
            .await
            .map_err(shown)?;
        ensure(
            waiting
                .iter()
                .any(|d| d.device_id == device && d.account_id == bob.id),
            "the new device isn't listed as pending",
        )
    })
    .await;
    r.check(G, PLAN[21].0, PLAN[21].1, async {
        let d = alice
            .client
            .decide_device(org, &bob.id, &device, true)
            .await
            .map_err(shown)?;
        ensure(d.status == "approved", format!("status {:?}", d.status))?;
        laptop
            .client
            .vault(prod)
            .await
            .map_err(|e| format!("the approved device: {e}"))?;
        Ok(())
    })
    .await;
    r.check(G, PLAN[22].0, PLAN[22].1, async {
        let d = alice
            .client
            .decide_device(org, &bob.id, &device, false)
            .await
            .map_err(shown)?;
        ensure(d.status == "denied", format!("status {:?}", d.status))?;
        match laptop.client.vault(prod).await {
            Err(Error::DeviceApprovalRequired { denied: true, .. }) => Ok(()),
            other => Err(format!(
                "the denied device: expected 403 device_approval_required (denied), got {}",
                outcome(other)
            )),
        }
    })
    .await;
    let _ = alice
        .client
        .update_org(
            org,
            &UpdateOrg {
                name: None,
                policies: Some(Policies {
                    require_device_approval: false,
                    ..Default::default()
                }),
            },
        )
        .await;
}

async fn sso(ctx: &Ctx, r: &mut Report, alice: &Person, org: &str) {
    if !ctx.caps.as_ref().is_some_and(|c| c.features.sso.is_some()) {
        r.skip(
            G,
            PLAN[24].0,
            PLAN[24].1,
            "the server doesn't offer single sign-on (features.sso)",
        );
        r.skip(
            G,
            PLAN[25].0,
            PLAN[25].1,
            "the server doesn't offer single sign-on (features.sso)",
        );
        return;
    }
    r.check(G, PLAN[24].0, PLAN[24].1, async {
        let s = alice.client.sso_status(org).await.map_err(shown)?;
        ensure(
            !s.configured && s.session_expires_at.is_none(),
            format!("{s:?}"),
        )
    })
    .await;
    r.check(G, PLAN[25].0, PLAN[25].1, async {
        match alice.client.sso_start(org).await {
            Err(Error::Api { status: 409, .. }) => Ok(()),
            other => Err(format!(
                "expected 409 sso_not_configured, got {}",
                outcome(other)
            )),
        }
    })
    .await;
}
