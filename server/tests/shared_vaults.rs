//! Shared vaults end to end: real local vaults (one per person), the store's sharing operations
//! and sync engine, and the server under test. Skipped when the server has no `sharing` or mails
//! its invites.

use std::sync::{Arc, Mutex};

use mg_store::account::{self, AccountError, SharedVault};
use mg_store::sharing::{self, MemberView};
use mg_store::sync::{Hold, SyncConfig, SyncReport, sync_once, sync_once_with};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{Access, Error, Host, HostAuth, ItemData, LocalVault};
use mg_sync::{
    B64, DeviceInfo, GrantKey, MemberStatus, Permission, Policies, Role, SetVaultMember,
    SyncClient, UpdateOrg,
};
use mg_vault::KdfParams;

mod common;

use common::{email, server};

const PW: &str = "correct horse battery";

struct Person {
    vault: SharedVault,
    client: Arc<SyncClient>,
    id: String,
    email: String,
}

fn host(label: &str) -> ItemData {
    ItemData::Host(Host {
        label: label.into(),
        hostname: format!("{label}.internal"),
        port: 22,
        user: "deploy".into(),
        auth: HostAuth::Password {
            password: Some(format!("{label}-secret")),
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
    })
}

async fn person(url: &str, name: &str) -> Person {
    let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
        KdfParams::MIN_M_KIB,
        KdfParams::MIN_T,
        1,
    );
    v.create(PW).unwrap();
    v.upsert(None, host(&format!("{name}-personal"))).unwrap();
    let (export, _) = v.export_for_registration(PW).unwrap();
    let client = SyncClient::new(url).unwrap();
    let email = email(name);
    let device = DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: None,
        public_key: B64(vec![1; 32]),
    };
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
        device_id: device.id,
        device_public_key: [1; 32],
    })
    .unwrap();
    Person {
        vault: Arc::new(Mutex::new(v)),
        client: Arc::new(client),
        id: session.account_id,
        email,
    }
}

/// What the app does each round: shared vaults first, then the item sync.
async fn sync(p: &Person) -> (sharing::RefreshReport, SyncReport) {
    let refresh = sharing::refresh(&p.vault, &p.client).await.unwrap();
    let report = sync_once(&p.vault, &HttpRemote(&p.client)).await.unwrap();
    assert!(report.vault_errors.is_empty(), "{:?}", report.vault_errors);
    (refresh, report)
}

/// A round as the app runs it: keeping what it fetched in `cache`, pulling only vaults that moved.
async fn cached_round(
    p: &Person,
    cache: &mut sharing::RoundCache,
) -> (sharing::RefreshReport, SyncReport) {
    let refresh = sharing::refresh_with(&p.vault, &p.client, cache)
        .await
        .unwrap();
    let report = sync_once_with(&p.vault, &HttpRemote(&p.client), &refresh.heads)
        .await
        .unwrap();
    assert!(report.vault_errors.is_empty(), "{:?}", report.vault_errors);
    (refresh, report)
}

fn labels_in(p: &Person, vault: &str) -> Vec<String> {
    let mut out: Vec<String> = p
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

fn fingerprint_of(p: &Person) -> String {
    let keys = p.vault.lock().unwrap().public_keys().unwrap();
    mg_vault::sharing::fingerprint(&p.id, &keys)
}

/// A team's vault behind single sign-on stays on the device, unsynced edits included, and the
/// round says which sign-in it waits for (the server leaves such vaults out of its list).
#[tokio::test]
async fn vaults_behind_single_sign_on_stay_on_the_device() {
    let Some((url, state)) = common::reference_state().await else {
        return;
    };
    let alice = person(&url, "alice").await;
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
    sync(&alice).await;
    // An edit that hasn't synced yet.
    alice
        .vault
        .lock()
        .unwrap()
        .upsert_in(&prod, None, host("db2"))
        .unwrap();

    // The operator puts Acme behind its identity provider, required.
    let provider = vault_sync_server::SsoProvider {
        issuer: "https://login.acme.example".into(),
        client_id: "morphgate".into(),
        client_secret: "s3cret".into(),
        session_hours: 12,
    };
    state.set_sso("Acme", &provider, true).unwrap();
    let refresh = sharing::refresh(&alice.vault, &alice.client).await.unwrap();
    assert_eq!(
        refresh.dropped, 0,
        "a vault behind sign-in is not a vault lost"
    );
    assert_eq!(refresh.held, [(org.clone(), Hold::Sso)]);
    assert!(
        refresh.errors.is_empty(),
        "waiting for a sign-in is no error: {:?}",
        refresh.errors
    );
    let report = sync_once(&alice.vault, &HttpRemote(&alice.client))
        .await
        .unwrap();
    assert_eq!(report.held, [(org.clone(), Hold::Sso)]);
    assert!(report.vault_errors.is_empty(), "{:?}", report.vault_errors);
    assert_eq!(labels_in(&alice, &prod), ["db1", "db2"]);

    // Without the requirement the vault syncs again, the edit included.
    state.remove_sso("Acme").unwrap();
    let (refresh, report) = sync(&alice).await;
    assert!(refresh.held.is_empty() && report.held.is_empty());
    assert_eq!(report.pushed, 1);
}

#[tokio::test]
async fn a_team_shares_a_vault() {
    let url = server().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    if caps
        .features
        .sharing
        .as_ref()
        .is_none_or(|s| s.mails_invites)
    {
        return;
    }
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let carol = person(&url, "carol").await;

    // Alice: an organization with a Production vault and a host in it.
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
        .await
        .unwrap();
    {
        let v = alice.vault.lock().unwrap();
        let info = v
            .vaults()
            .unwrap()
            .into_iter()
            .find(|x| x.id == prod)
            .unwrap();
        assert_eq!(
            (info.name.as_deref(), info.access),
            (Some("Production"), Access::Manage)
        );
    }
    let db1 = alice
        .vault
        .lock()
        .unwrap()
        .upsert_in(&prod, None, host("db1"))
        .unwrap();
    // References stay inside a vault.
    let personal_host = alice
        .vault
        .lock()
        .unwrap()
        .items()
        .unwrap()
        .into_iter()
        .find(|i| i.vault_id != prod)
        .unwrap();
    let ItemData::Host(mut via) = host("via-personal") else {
        unreachable!()
    };
    via.jump_ref = Some(personal_host.id.clone());
    assert!(matches!(
        alice
            .vault
            .lock()
            .unwrap()
            .upsert_in(&prod, None, ItemData::Host(via)),
        Err(Error::Invalid(_))
    ));
    sync(&alice).await;

    // Invite Bob (read access). He sees the organization and its owner's fingerprint.
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
    assert_eq!(preview.org_name, "Acme");
    assert_eq!(preview.owner_fingerprint, fingerprint_of(&alice));
    // Accepting against another fingerprint than the one shown does nothing.
    assert!(
        sharing::accept_invite(
            &bob.vault,
            &bob.client,
            &token,
            "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
        )
        .await
        .is_err()
    );
    sharing::accept_invite(&bob.vault, &bob.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
    let orgs = bob.vault.lock().unwrap().orgs().unwrap();
    assert_eq!(
        (orgs[0].name.as_str(), orgs[0].status),
        ("Acme", MemberStatus::Accepted)
    );
    assert_eq!(orgs[0].root_fingerprint, fingerprint_of(&alice));
    let (r, _) = sync(&bob).await;
    assert_eq!(r.vaults, 0, "nothing shared before an admin confirms");

    // Alice compares Bob's fingerprint with him, then confirms.
    let members = sharing::members(&alice.vault, &alice.client, &org)
        .await
        .unwrap();
    let pending: &MemberView = members.iter().find(|m| m.account_id == bob.id).unwrap();
    assert_eq!(pending.status, MemberStatus::Accepted);
    assert!(!pending.verified);
    assert_eq!(pending.fingerprint, fingerprint_of(&bob));
    assert!(
        sharing::confirm_member(
            &alice.vault,
            &alice.client,
            &org,
            &bob.id,
            &fingerprint_of(&carol)
        )
        .await
        .is_err()
    );
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &bob.id,
        &pending.fingerprint,
    )
    .await
    .unwrap();
    let members = sharing::members(&alice.vault, &alice.client, &org)
        .await
        .unwrap();
    assert!(members.iter().all(|m| m.verified));
    // Verified members are remembered by name (the activity log names people who left).
    let names = alice.vault.lock().unwrap().known_emails().unwrap();
    assert_eq!(names.get(&bob.id), Some(&bob.email));

    // Bob gets the vault, read-only, and Alice's host in it (her signature checked), and the
    // member key directory (write), which Alice's app created with the organization.
    let (r, report) = sync(&bob).await;
    assert_eq!(r.vaults, 2);
    let directory = |p: &Person| {
        p.vault
            .lock()
            .unwrap()
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.directory && v.org_id.as_deref() == Some(org.as_str()))
    };
    let dir = directory(&alice).unwrap().id;
    let bobs_dir = directory(&bob).unwrap();
    assert_eq!(
        (
            bobs_dir.id.as_str(),
            bobs_dir.name.as_deref(),
            bobs_dir.access
        ),
        (dir.as_str(), Some(sharing::DIRECTORY_NAME), Access::Write)
    );
    assert_eq!(report.pulled, 1);
    assert_eq!(labels_in(&bob, &prod), ["db1"]);
    let ItemData::Host(h) = bob.vault.lock().unwrap().item(&db1.id).unwrap().data else {
        panic!()
    };
    assert_eq!(
        h.auth,
        HostAuth::Password {
            password: Some("db1-secret".into())
        }
    );
    let info = bob
        .vault
        .lock()
        .unwrap()
        .vaults()
        .unwrap()
        .into_iter()
        .find(|x| x.id == prod)
        .unwrap();
    assert_eq!(
        (info.name.as_deref(), info.access),
        (Some("Production"), Access::Read)
    );
    assert!(matches!(
        bob.vault
            .lock()
            .unwrap()
            .upsert_in(&prod, None, host("bobs")),
        Err(Error::ReadOnly)
    ));
    assert!(matches!(
        bob.vault.lock().unwrap().delete(&db1.id),
        Err(Error::ReadOnly)
    ));

    // Write access: Bob adds a host; Alice gets it, verified against Bob's pinned key.
    sharing::set_access(&alice.vault, &alice.client, &prod, &bob.id, Access::Write)
        .await
        .unwrap();
    sync(&bob).await;
    bob.vault
        .lock()
        .unwrap()
        .upsert_in(&prod, None, host("web1"))
        .unwrap();
    assert_eq!(sync(&bob).await.1.pushed, 1);
    assert_eq!(sync(&alice).await.1.pulled, 1);
    assert_eq!(labels_in(&alice, &prod), ["db1", "web1"]);

    // Bob publishes the SSH key he uses on the organization's hosts; Alice reads it, signed by
    // him. Only member keys go in the directory, and nothing else does.
    let entry = bob
        .vault
        .lock()
        .unwrap()
        .publish_member_key(&org, &format!("{BOB_SSH_KEY} bob@laptop"), "laptop")
        .unwrap();
    let again = bob
        .vault
        .lock()
        .unwrap()
        .publish_member_key(&org, BOB_SSH_KEY, "laptop")
        .unwrap();
    assert_eq!(entry, again);
    assert!(matches!(
        bob.vault
            .lock()
            .unwrap()
            .upsert_in(&dir, None, host("sneaky")),
        Err(Error::Invalid(_))
    ));
    sync(&bob).await;
    sync(&alice).await;
    let keys = alice.vault.lock().unwrap().member_keys(&org).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        (
            keys[0].account_id.as_str(),
            keys[0].public_key.as_str(),
            keys[0].label.as_str()
        ),
        (bob.id.as_str(), BOB_SSH_KEY, "laptop")
    );
    assert!(keys[0].verified && !keys[0].mine);

    // Alice's app keeps every member able to write to the directory.
    alice
        .client
        .revoke_vault_member(&dir, &bob.id)
        .await
        .unwrap();
    sync(&alice).await;
    let members = alice.client.vault_members(&dir).await.unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.account_id == bob.id && m.permission == Permission::Write)
    );

    // A sealed key whose grant signature doesn't verify is refused: Carol joins, and Alice's
    // client (standing in for a lying server or app) grants her a key with a bad signature.
    let invite = sharing::invite(&alice.client, &org, &carol.email, Role::Member, vec![])
        .await
        .unwrap();
    let token = invite.token.unwrap();
    let fp = sharing::preview_invite(&carol.client, &token)
        .await
        .unwrap()
        .owner_fingerprint;
    sharing::accept_invite(&carol.vault, &carol.client, &token, &fp)
        .await
        .unwrap();
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &carol.id,
        &fingerprint_of(&carol),
    )
    .await
    .unwrap();
    // The real key id (the server checks it), a key of the forger's own, a bad signature.
    let real = alice.client.vault(&prod).await.unwrap();
    let forged = mg_vault::VaultKey::generate().unwrap();
    let carol_keys = carol.vault.lock().unwrap().public_keys().unwrap();
    alice
        .client
        .set_vault_member(
            &prod,
            &carol.id,
            &SetVaultMember {
                permission: Permission::Read,
                keys: vec![GrantKey {
                    key_id: real.key_id.clone(),
                    wrapped_vault_key: B64(forged.seal_to(&carol_keys.enc).unwrap()),
                    grant_sig: B64(vec![7; 64]),
                }],
            },
        )
        .await
        .unwrap();
    let (r, _) = sync(&carol).await;
    // Only the member key directory, which she was given on confirmation.
    assert_eq!(r.vaults, 1);
    assert!(directory(&carol).is_some());
    assert!(
        r.errors.iter().any(|e| e.contains("grant")),
        "{:?}",
        r.errors
    );
    assert!(labels_in(&carol, &prod).is_empty());
    alice
        .client
        .revoke_vault_member(&prod, &carol.id)
        .await
        .unwrap();

    // Granted for real, then promoted: an admin manages every vault.
    sharing::set_access(&alice.vault, &alice.client, &prod, &carol.id, Access::Read)
        .await
        .unwrap();
    sync(&carol).await;
    assert_eq!(labels_in(&carol, &prod), ["db1", "web1"]);
    sharing::set_role(&alice.vault, &alice.client, &org, &carol.id, Role::Admin)
        .await
        .unwrap();
    sync(&carol).await;
    let access = |p: &Person| {
        p.vault
            .lock()
            .unwrap()
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.id == prod)
            .map(|v| v.access)
    };
    assert_eq!(access(&carol), Some(Access::Manage));

    // A member key entry "for" Bob that Bob didn't sign is shown as unverified.
    carol
        .vault
        .lock()
        .unwrap()
        .upsert_in(
            &dir,
            None,
            ItemData::MemberKey(mg_store::MemberKey {
                account_id: bob.id.clone(),
                public_key: CAROL_SSH_KEY.into(),
                label: "not bob's".into(),
                sig: "00".repeat(64),
            }),
        )
        .unwrap();
    sync(&carol).await;
    sync(&alice).await;
    let keys = alice.vault.lock().unwrap().member_keys(&org).unwrap();
    let verified: Vec<(&str, bool)> = keys
        .iter()
        .map(|k| (k.public_key.as_str(), k.verified))
        .collect();
    assert_eq!(verified.len(), 2);
    assert!(verified.contains(&(BOB_SSH_KEY, true)));
    assert!(verified.contains(&(CAROL_SSH_KEY, false)));
    // Once Bob is caught up, a round with nothing new reports no change (the app doesn't reload).
    sync(&bob).await;
    let (r, _) = sync(&bob).await;
    assert!(!r.changed);

    // Revoke Bob: his device drops the vault on the next round.
    sharing::revoke_access(&alice.client, &prod, &bob.id)
        .await
        .unwrap();
    let (r, _) = sync(&bob).await;
    assert_eq!(r.dropped, 1);
    assert!(r.changed);
    assert!(labels_in(&bob, &prod).is_empty());
    assert!(
        bob.vault
            .lock()
            .unwrap()
            .vaults()
            .unwrap()
            .iter()
            .all(|v| v.id != prod)
    );

    // Alice rotates: a new key for whoever is left, every item re-sealed and pushed.
    sync(&alice).await;
    assert!(
        alice
            .vault
            .lock()
            .unwrap()
            .vaults()
            .unwrap()
            .iter()
            .any(|v| v.id == prod && v.rotation_due)
    );
    let old_key = alice.client.vault(&prod).await.unwrap().key_id;
    sharing::rotate(&alice.vault, &alice.client, &prod)
        .await
        .unwrap();
    let (_, report) = sync(&alice).await;
    assert_eq!(report.pushed, 2);
    let after = alice.client.vault(&prod).await.unwrap();
    assert_ne!(after.key_id, old_key);
    assert!(!after.rotation_due);
    assert_eq!(after.items_on_old_keys, Some(0));
    assert_eq!(labels_in(&alice, &prod), ["db1", "web1"]);
    // Carol, an admin, got the new key and reads the re-sealed items.
    let (_, report) = sync(&carol).await;
    assert_eq!(report.pulled, 2);
    assert_eq!(labels_in(&carol, &prod), ["db1", "web1"]);

    // Members may create vaults: Bob makes one (its first key is granted by him) with a host.
    alice
        .client
        .update_org(
            &org,
            &UpdateOrg {
                name: None,
                policies: Some(Policies {
                    members_can_create_vaults: true,
                    ..Default::default()
                }),
            },
        )
        .await
        .unwrap();
    let bobs = sharing::create_vault(&bob.vault, &bob.client, &org, "Bob's tools")
        .await
        .unwrap();
    bob.vault
        .lock()
        .unwrap()
        .upsert_in(&bobs, None, host("box"))
        .unwrap();
    sync(&bob).await;
    sync(&alice).await;
    assert_eq!(labels_in(&alice, &bobs), ["box"]);

    // Bob leaves the organization: it's gone from his device.
    sharing::remove_member(&bob.vault, &bob.client, &org, &bob.id)
        .await
        .unwrap();
    // Alice's device still verifies what he granted and signed: his vault keeps its name and its
    // items, and she rotates it without a complaint.
    let (r, _) = sync(&alice).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let name = |p: &Person, id: &str| {
        p.vault
            .lock()
            .unwrap()
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.id == id)
            .and_then(|v| v.name)
    };
    assert_eq!(name(&alice, &bobs).as_deref(), Some("Bob's tools"));
    assert_eq!(labels_in(&alice, &bobs), ["box"]);
    sharing::rotate(&alice.vault, &alice.client, &bobs)
        .await
        .unwrap();
    let (r, report) = sync(&alice).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(report.pushed, 1);
    let (r, _) = sync(&alice).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(name(&alice, &bobs).as_deref(), Some("Bob's tools"));
    assert_eq!(labels_in(&alice, &bobs), ["box"]);
    assert!(bob.vault.lock().unwrap().orgs().unwrap().is_empty());
    // His personal vault is untouched throughout.
    assert_eq!(bob.vault.lock().unwrap().items().unwrap().len(), 1);
    // Alice still finds his published key, signed by him (offboarding looks for it on hosts).
    sync(&alice).await;
    let keys = alice.vault.lock().unwrap().member_keys(&org).unwrap();
    assert!(
        keys.iter()
            .any(|k| k.account_id == bob.id && k.public_key == BOB_SSH_KEY && k.verified)
    );
}

const BOB_SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICzE0dEBoxASjK71bvsNSZNl2ebpWyECnWZm7fsbrIwX";
const CAROL_SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOV7rBdWTkUnX8JssaOJ30xGH0VcTQeQdLyitXAAZJnd";

/// Moving an item between the personal vault and a team's keeps its id: the team's members get
/// it, the old vault keeps a tombstone, and moving it back takes it off their devices.
#[tokio::test]
async fn items_move_between_personal_and_team_vaults() {
    let url = server().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    if caps
        .features
        .sharing
        .as_ref()
        .is_none_or(|s| s.mails_invites)
    {
        return;
    }
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
        .await
        .unwrap();
    sync(&alice).await;
    let invite = sharing::invite(
        &alice.client,
        &org,
        &bob.email,
        Role::Member,
        vec![(prod.clone(), Access::Write)],
    )
    .await
    .unwrap();
    let token = invite.token.unwrap();
    let preview = sharing::preview_invite(&bob.client, &token).await.unwrap();
    sharing::accept_invite(&bob.vault, &bob.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &bob.id,
        &fingerprint_of(&bob),
    )
    .await
    .unwrap();
    sync(&bob).await;
    assert!(labels_in(&bob, &prod).is_empty());

    let personal = alice.vault.lock().unwrap().vaults().unwrap()[0].id.clone();
    let host_id = alice
        .vault
        .lock()
        .unwrap()
        .items()
        .unwrap()
        .into_iter()
        .find(|i| i.vault_id == personal)
        .unwrap()
        .id;
    let none = std::collections::BTreeMap::new();
    let moved = alice
        .vault
        .lock()
        .unwrap()
        .move_items(std::slice::from_ref(&host_id), &prod, &none)
        .unwrap();
    assert_eq!(moved.ids[&host_id], host_id);
    // One round: the push lands after this round's pull, so the next pull brings Alice her own
    // item back (no clash with her tombstone, nor, once moved back, with her live copy).
    sync(&alice).await;
    sync(&bob).await;
    assert_eq!(labels_in(&bob, &prod), vec!["alice-personal".to_owned()]);
    assert!(labels_in(&alice, &personal).is_empty());

    // Back to Alice's personal vault, over its tombstone: it leaves Bob's device.
    alice
        .vault
        .lock()
        .unwrap()
        .move_items(std::slice::from_ref(&host_id), &personal, &none)
        .unwrap();
    sync(&alice).await;
    sync(&alice).await;
    sync(&bob).await;
    assert!(labels_in(&bob, &prod).is_empty());
    assert_eq!(
        labels_in(&alice, &personal),
        vec!["alice-personal".to_owned()]
    );
    assert!(labels_in(&alice, &prod).is_empty());
}

/// Deleting an account from the app: an organization's owner is refused; a member's account goes,
/// with its membership, and the device keeps its own items, with sync off, without the team's.
#[tokio::test]
async fn an_account_deletes_itself() {
    let url = server().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    if caps
        .features
        .sharing
        .as_ref()
        .is_none_or(|s| s.mails_invites)
    {
        return;
    }
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
        .await
        .unwrap();
    let invite = sharing::invite(
        &alice.client,
        &org,
        &bob.email,
        Role::Member,
        vec![(prod.clone(), Access::Write)],
    )
    .await
    .unwrap();
    let token = invite.token.unwrap();
    let preview = sharing::preview_invite(&bob.client, &token).await.unwrap();
    sharing::accept_invite(&bob.vault, &bob.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &bob.id,
        &fingerprint_of(&bob),
    )
    .await
    .unwrap();
    alice
        .vault
        .lock()
        .unwrap()
        .upsert_in(&prod, None, host("db1"))
        .unwrap();
    sync(&alice).await;
    sync(&bob).await;
    assert_eq!(labels_in(&bob, &prod), vec!["db1".to_owned()]);

    // The owner hands the organization over or deletes it first.
    let pw = || zeroize::Zeroizing::new(PW.to_owned());
    assert!(matches!(
        account::delete_account(&alice.vault, alice.client.clone(), pw()).await,
        Err(AccountError::OwnsOrg)
    ));
    sync(&alice).await;

    // A wrong password goes nowhere near the server.
    let wrong = zeroize::Zeroizing::new("wrong".to_owned());
    assert!(
        account::delete_account(&bob.vault, bob.client.clone(), wrong)
            .await
            .is_err()
    );
    sync(&bob).await;

    account::delete_account(&bob.vault, bob.client.clone(), pw())
        .await
        .unwrap();
    {
        let v = bob.vault.lock().unwrap();
        assert!(v.sync_info().unwrap().is_none(), "sync is off");
        let vaults = v.vaults().unwrap();
        assert_eq!(vaults.len(), 1, "only the personal vault stays");
    }
    let personal = bob.vault.lock().unwrap().vaults().unwrap()[0].id.clone();
    assert_eq!(labels_in(&bob, &personal), vec!["bob-personal".to_owned()]);
    assert!(labels_in(&bob, &prod).is_empty());
    assert!(bob.client.account().await.is_err(), "the account is gone");

    let members = sharing::members(&alice.vault, &alice.client, &org)
        .await
        .unwrap();
    assert!(members.iter().all(|m| m.account_id != bob.id));
    sync(&alice).await;
}

/// An organization's `rev` (`GET /orgs`) stays put while nothing changes and moves with every
/// change its members' apps fetch; a round that keeps what it fetched still sees those changes.
#[tokio::test]
async fn rounds_reuse_what_has_not_changed() {
    let url = server().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    if caps
        .features
        .sharing
        .as_ref()
        .is_none_or(|s| s.mails_invites)
    {
        return;
    }
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
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
    sync(&alice).await;
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
    sharing::confirm_member(
        &alice.vault,
        &alice.client,
        &org,
        &bob.id,
        &fingerprint_of(&bob),
    )
    .await
    .unwrap();

    let mut cache = sharing::RoundCache::default();
    let (r, report) = cached_round(&bob, &mut cache).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(report.pulled, 1);
    assert_eq!(labels_in(&bob, &prod), ["db1"]);
    let vaults = r.vaults;

    let rev = async || bob.client.orgs().await.unwrap()[0].rev;
    // A server without it: every round fetches everything, which the rest of the suite covers.
    let Some(seen) = rev().await else {
        return;
    };
    // A quiet round changes nothing, and has nothing to pull: the organization is kept.
    assert_eq!(cache.kept(), 1);
    let (r, report) = cached_round(&bob, &mut cache).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!((r.vaults, report.pulled), (vaults, 0));
    assert_eq!(rev().await, Some(seen));
    assert_eq!(cache.kept(), 1);

    // A new name moves it, and the next round shows it.
    alice
        .client
        .update_org(
            &org,
            &UpdateOrg {
                name: Some("Acme Inc".into()),
                policies: None,
            },
        )
        .await
        .unwrap();
    let renamed = rev().await.unwrap();
    assert_ne!(renamed, seen);
    cached_round(&bob, &mut cache).await;
    assert_eq!(
        bob.vault.lock().unwrap().orgs().unwrap()[0].name,
        "Acme Inc"
    );

    // So do access to its vaults and a member's role.
    let access = || {
        bob.vault
            .lock()
            .unwrap()
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.id == prod)
            .map(|v| v.access)
    };
    sharing::set_access(&alice.vault, &alice.client, &prod, &bob.id, Access::Write)
        .await
        .unwrap();
    let granted = rev().await.unwrap();
    assert_ne!(granted, renamed);
    let (r, _) = cached_round(&bob, &mut cache).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(access(), Some(Access::Write));
    sharing::set_role(&alice.vault, &alice.client, &org, &bob.id, Role::Admin)
        .await
        .unwrap();
    assert_ne!(rev().await.unwrap(), granted);
    let (r, _) = cached_round(&bob, &mut cache).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(
        bob.vault.lock().unwrap().orgs().unwrap()[0].role,
        Role::Admin
    );
    assert_eq!(access(), Some(Access::Manage));
}
