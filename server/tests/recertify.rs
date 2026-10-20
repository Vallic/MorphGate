//! Certificates outliving the admin who signed them, and the member key policy, through the
//! reference server.

use std::sync::{Arc, Mutex};

use mg_store::account::{self, SharedVault};
use mg_store::sharing;
use mg_store::sync::{SyncConfig, sync_once};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{Access, Host, HostAuth, ItemData, LocalVault};
use mg_sync::{B64, DeviceInfo, Policies, Role, SyncClient, UpdateOrg};
use mg_vault::KdfParams;
use zeroize::Zeroizing;

mod common;

const PW: &str = "correct horse battery";

struct Device {
    vault: SharedVault,
    client: Arc<SyncClient>,
    account: String,
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
        email,
    }
}

/// Another device of the same account, signed in with the master password.
async fn another(url: &str, of: &Device, name: &str) -> Device {
    let d = Device {
        vault: Arc::new(Mutex::new(fast())),
        client: Arc::new(SyncClient::new(url).unwrap()),
        account: of.account.clone(),
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
    d
}

async fn round(d: &Device) -> (sharing::RefreshReport, mg_store::sync::SyncReport) {
    let refresh = sharing::refresh(&d.vault, &d.client).await.unwrap();
    let report = sync_once(&d.vault, &HttpRemote(&d.client)).await.unwrap();
    assert!(report.vault_errors.is_empty(), "{:?}", report.vault_errors);
    (refresh, report)
}

fn fingerprint(d: &Device) -> String {
    let keys = d.vault.lock().unwrap().public_keys().unwrap();
    mg_vault::sharing::fingerprint(&d.account, &keys)
}

/// Invites `who` with `role` and read access to `vault`, then `by` confirms them.
async fn join(org: &str, vault: &str, by: &Device, who: &Device, role: Role) {
    let invite = sharing::invite(
        &by.client,
        org,
        &who.email,
        role,
        vec![(vault.into(), Access::Read)],
    )
    .await
    .unwrap();
    let token = invite.token.unwrap();
    let preview = sharing::preview_invite(&who.client, &token).await.unwrap();
    sharing::accept_invite(&who.vault, &who.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
    round(who).await;
    sharing::confirm_member(&by.vault, &by.client, org, &who.account, &fingerprint(who))
        .await
        .unwrap();
    round(who).await;
}

#[tokio::test]
async fn members_outlive_the_admin_who_confirmed_them() {
    let Some((url, _)) = common::reference_state().await else {
        return;
    };
    let alice = first(&url, "alice").await;
    let carol = first(&url, "carol").await;
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
    // Alice makes Carol an admin; Carol confirms Bob. Alice's device verifies Bob through
    // Carol's certificate, and pins him.
    join(&org, &prod, &alice, &carol, Role::Admin).await;
    round(&carol).await;
    join(&org, &prod, &carol, &bob, Role::Member).await;
    let (refresh, _) = round(&alice).await;
    assert_eq!(refresh.recertified, 0, "Carol's certificate verifies");

    // Carol leaves. Alice's device still trusts Bob (its pin) and certifies him again.
    sharing::remove_member(&alice.vault, &alice.client, &org, &carol.account)
        .await
        .unwrap();
    let (refresh, _) = round(&alice).await;
    assert_eq!(refresh.recertified, 1);
    assert!(refresh.errors.is_empty(), "{:?}", refresh.errors);
    let (refresh, _) = round(&alice).await;
    assert_eq!(refresh.recertified, 0, "once is enough");

    // A fresh device of Alice's verifies Bob through Alice's new certificate.
    let fresh = another(&url, &alice, "alice-laptop").await;
    round(&fresh).await;
    let members = sharing::members(&fresh.vault, &fresh.client, &org)
        .await
        .unwrap();
    let b = members
        .iter()
        .find(|m| m.account_id == bob.account)
        .unwrap();
    assert!(b.verified, "Bob is verified on a device that never saw him");
    let events = alice.client.org_events(&org, 0, 1000).await.unwrap().events;
    assert!(events.iter().any(|e| e.kind == "member_recertified"));

    // Members can't certify anyone; a fingerprint that doesn't match certifies nothing.
    assert!(
        sharing::recertify(
            &bob.vault,
            &bob.client,
            &org,
            &alice.account,
            Some(&fingerprint(&alice))
        )
        .await
        .is_err()
    );
    assert!(
        sharing::recertify(
            &alice.vault,
            &alice.client,
            &org,
            &bob.account,
            Some(&fingerprint(&alice))
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn members_are_reminded_to_publish_their_keys() {
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
    round(&alice).await;
    join(&org, &prod, &alice, &bob, Role::Member).await;
    let (refresh, _) = round(&bob).await;
    assert!(refresh.member_keys_due.is_empty(), "no policy, no reminder");
    alice
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
        .unwrap();
    assert_eq!(
        alice
            .client
            .org(&org)
            .await
            .unwrap()
            .policies
            .require_member_keys,
        Some(true)
    );
    let (refresh, _) = round(&bob).await;
    assert_eq!(refresh.member_keys_due, std::slice::from_ref(&org));
    bob.vault
        .lock()
        .unwrap()
        .publish_member_key(
            &org,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVq4o3sCUJE0xuW0GvKcnDTB3UJm7sYyuZTm6xtFdP3 bob@laptop",
            "laptop",
        )
        .unwrap();
    let (refresh, _) = round(&bob).await;
    assert!(
        refresh.member_keys_due.is_empty(),
        "{:?}",
        refresh.member_keys_due
    );
}
