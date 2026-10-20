//! Device approval (`require_device_approval`) through the reference server: a member's new
//! device waits until an admin, or the member from an approved device, approves it; its team
//! vaults stay closed meanwhile and the round says why.

use std::sync::{Arc, Mutex};

use mg_store::account::{self, SharedVault};
use mg_store::sharing;
use mg_store::sync::{Hold, SyncConfig, sync_once};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{Access, Host, HostAuth, ItemData, LocalVault};
use mg_sync::{B64, DeviceInfo, Error, Policies, Role, SyncClient, UpdateOrg};
use mg_vault::KdfParams;
use zeroize::Zeroizing;

mod common;

const PW: &str = "correct horse battery";

struct Device {
    vault: SharedVault,
    client: Arc<SyncClient>,
    account: String,
    id: String,
    email: String,
}

fn fast() -> LocalVault {
    LocalVault::open_in_memory()
        .unwrap()
        .with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
}

fn info(name: &str) -> DeviceInfo {
    DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: None,
        public_key: B64(vec![1; 32]),
    }
}

fn host(label: &str) -> ItemData {
    ItemData::Host(Host {
        label: label.into(),
        hostname: format!("{label}.internal"),
        port: 22,
        user: "deploy".into(),
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
    })
}

/// Someone's first device: a new account with sync on.
async fn first(url: &str, name: &str) -> Device {
    let mut v = fast();
    v.create(PW).unwrap();
    let (export, _) = v.export_for_registration(PW).unwrap();
    let client = Arc::new(SyncClient::new(url).unwrap());
    let email = common::email(name);
    let device = info(name);
    let session = client
        .register(&register_request(&export, &email, device.clone(), None))
        .await
        .unwrap();
    client
        .create_vault(&create_vault_request(&export.vault))
        .await
        .unwrap();
    v.enable_sync(&SyncConfig {
        server_url: url.into(),
        email: email.clone(),
        account_id: session.account_id.clone(),
        device_id: device.id.clone(),
        device_public_key: [1; 32],
    })
    .unwrap();
    Device {
        vault: Arc::new(Mutex::new(v)),
        client,
        account: session.account_id,
        id: device.id,
        email,
    }
}

/// Another device of the same account, signed in with the master password.
async fn another(url: &str, of: &Device, name: &str) -> Device {
    let d = Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(url).unwrap()),
        account: of.account.clone(),
        id: String::new(),
        email: of.email.clone(),
    };
    let device = info(name);
    account::sign_in(
        &d.vault,
        d.client.clone(),
        &of.email,
        Zeroizing::new(PW.into()),
        device.clone(),
        None,
    )
    .await
    .unwrap();
    Device { id: device.id, ..d }
}

async fn round(d: &Device) -> (sharing::RefreshReport, mg_store::sync::SyncReport) {
    let refresh = sharing::refresh(&d.vault, &d.client).await.unwrap();
    let report = sync_once(&d.vault, &HttpRemote(&d.client)).await.unwrap();
    assert!(report.vault_errors.is_empty(), "{:?}", report.vault_errors);
    (refresh, report)
}

fn labels(d: &Device, vault: &str) -> Vec<String> {
    let mut out: Vec<String> = d
        .vault
        .lock()
        .unwrap()
        .items()
        .unwrap()
        .into_iter()
        .filter(|i| i.vault_id == vault)
        .map(|i| match i.data {
            ItemData::Host(h) => h.label,
            _ => String::new(),
        })
        .collect();
    out.sort();
    out
}

fn fingerprint(d: &Device) -> String {
    let keys = d.vault.lock().unwrap().public_keys().unwrap();
    mg_vault::sharing::fingerprint(&d.account, &keys)
}

#[tokio::test]
async fn a_new_device_waits_for_approval() {
    let Some((url, _)) = common::reference_state().await else {
        return;
    };
    let alice = first(&url, "alice").await;
    let bob = first(&url, "bob").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
        .await
        .unwrap();
    alice
        .vault
        .lock()
        .unwrap()
        .upsert_in(&prod, None, host("db1"))
        .unwrap();
    round(&alice).await;
    let invite = sharing::invite(
        &alice.client,
        &org,
        &bob.email,
        Role::Member,
        vec![(prod.clone(), Access::Read)],
    )
    .await
    .unwrap();
    let token = invite.token.unwrap();
    let preview = sharing::preview_invite(&bob.client, &token).await.unwrap();
    sharing::accept_invite(&bob.vault, &bob.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
    round(&bob).await;
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &bob.account,
        &fingerprint(&bob),
    )
    .await
    .unwrap();
    round(&bob).await;
    assert_eq!(labels(&bob, &prod), ["db1"]);

    // Alice turns approval on: the devices in use now are approved with it.
    alice
        .client
        .update_org(
            &org,
            &UpdateOrg {
                name: None,
                policies: Some(Policies {
                    require_device_approval: true,
                    ..Default::default()
                }),
            },
        )
        .await
        .unwrap();
    let (refresh, _) = round(&bob).await;
    assert!(refresh.held.is_empty(), "{:?}", refresh.held);

    // Bob's new device: the vault list leaves Production out (and files the request), and
    // the round says it waits.
    let bob2 = another(&url, &bob, "bob-laptop").await;
    let (refresh, _) = round(&bob2).await;
    assert_eq!(refresh.held, [(org.clone(), Hold::Approval)]);
    assert!(refresh.errors.is_empty(), "{:?}", refresh.errors);
    assert!(labels(&bob2, &prod).is_empty());
    match bob2.client.vault(&prod).await {
        Err(Error::DeviceApprovalRequired { org_id, denied }) => {
            assert_eq!((org_id.as_str(), denied), (org.as_str(), false));
        }
        other => panic!("expected device_approval_required, got {other:?}"),
    }
    // Alice sees it waiting; a device can't approve itself.
    let (refresh, _) = round(&alice).await;
    assert_eq!(refresh.approvals_waiting, [(org.clone(), 1)]);
    let waiting = alice
        .client
        .org_devices(&org, Some("pending"))
        .await
        .unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(
        (waiting[0].device_id.as_str(), waiting[0].name.as_deref()),
        (bob2.id.as_str(), Some("bob-laptop"))
    );
    assert!(matches!(
        bob2.client
            .decide_device(&org, &bob.account, &bob2.id, true)
            .await,
        Err(Error::Api { status: 403, .. })
    ));
    // Members decide only for their own devices.
    assert!(matches!(
        bob.client
            .decide_device(&org, &alice.account, &alice.id, true)
            .await,
        Err(Error::Api { status: 403, .. })
    ));

    // Alice denies it; Bob approves it from his first device.
    let denied = alice
        .client
        .decide_device(&org, &bob.account, &bob2.id, false)
        .await
        .unwrap();
    assert_eq!(denied.status, "denied");
    let (refresh, _) = round(&bob2).await;
    assert_eq!(refresh.held, [(org.clone(), Hold::Denied)]);
    let (refresh, _) = round(&bob).await;
    assert!(refresh.approvals_waiting.is_empty(), "denied isn't waiting");
    bob.client
        .decide_device(&org, &bob.account, &bob2.id, true)
        .await
        .unwrap();
    let (refresh, _) = round(&bob2).await;
    assert!(refresh.held.is_empty(), "{:?}", refresh.held);
    round(&bob2).await;
    assert_eq!(labels(&bob2, &prod), ["db1"]);

    // Signing the device out forgets its approval: after the next sign-in it asks again.
    bob.client.revoke_device(&bob2.id).await.unwrap();
    let bob3 = another(&url, &bob, "bob-laptop-again").await;
    let (refresh, _) = round(&bob3).await;
    assert_eq!(refresh.held, [(org.clone(), Hold::Approval)]);

    let events = alice.client.org_events(&org, 0, 1000).await.unwrap().events;
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    for kind in [
        "device_approval_requested",
        "device_denied",
        "device_approved",
    ] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }

    // The whole log as a download: CSV by default, JSON lines on request; admins only.
    let csv = alice.client.org_events_export(&org, "csv").await.unwrap();
    let mut lines = csv.lines();
    assert_eq!(
        lines.next(),
        Some("seq,at,kind,actor_id,actor_email,target_id,target_email,vault_id,detail")
    );
    assert_eq!(lines.count(), events.len());
    assert!(csv.contains(&format!(
        ",device_denied,{},{},",
        alice.account, alice.email
    )));
    let jsonl = alice.client.org_events_export(&org, "jsonl").await.unwrap();
    let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
    assert_eq!(
        (first["org_id"].as_str(), first["seq"].as_i64()),
        (Some(org.as_str()), Some(events[0].seq))
    );
    assert!(matches!(
        bob.client.org_events_export(&org, "csv").await,
        Err(Error::Api { status: 403, .. })
    ));
}
