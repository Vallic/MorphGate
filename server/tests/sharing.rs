//! The `sharing` capability against the server under test (see `common`), with real keys:
//! certificates, sealed vault keys, grant signatures and envelopes are what apps make, and each
//! test checks them the way an app would. Skipped when the server doesn't advertise `sharing`.

use mg_sync::*;
use mg_vault::sharing::{self, CertKind};
use mg_vault::{ItemContext, PublicKeys, VaultKey, envelope};

mod common;

use common::{email, server};

fn ulid() -> String {
    ulid::Ulid::generate().to_string()
}

fn b(v: impl Into<Vec<u8>>) -> B64 {
    B64(v.into())
}

/// An account with real keys, signed in.
struct Person {
    client: SyncClient,
    id: String,
    email: String,
    keys: mg_vault::AccountKeys,
}

impl Person {
    fn public(&self) -> PublicKeys {
        self.keys.public()
    }
}

async fn person(url: &str, name: &str) -> Person {
    let client = SyncClient::new(url).unwrap();
    let keys = mg_vault::AccountKeys::generate().unwrap();
    let public = keys.public();
    let email = email(name);
    let session = client
        .register(&RegisterRequest {
            email: email.clone(),
            kdf: KdfParams {
                alg: "argon2id".into(),
                m_kib: 65_536,
                t: 2,
                p: 1,
                salt: b(vec![1; 16]),
            },
            auth_key: b(vec![7; 32]),
            keys: mg_sync::AccountKeys {
                enc_public_key: b(public.enc),
                sign_public_key: b(public.sign),
                wrapped_private_keys: b(vec![4; 104]),
            },
            recovery: RecoveryMaterial {
                wrapped_private_keys_rk: b(vec![5; 104]),
                recovery_proof: b(vec![6; 32]),
            },
            device: DeviceInfo {
                id: ulid(),
                name: name.into(),
                platform: "linux".into(),
                client_version: None,
                public_key: b(vec![9; 32]),
            },
            email_code: None,
            accepted_terms: None,
        })
        .await
        .unwrap();
    Person {
        client,
        id: session.account_id,
        email,
        keys,
    }
}

/// `None` when the server has no `sharing` (the tests then pass vacuously).
async fn sharing_server() -> Option<(String, Sharing)> {
    let url = server().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    caps.features.sharing.map(|s| (url, s))
}

fn key_bytes(b: &B64) -> [u8; 16] {
    b.0.as_slice().try_into().unwrap()
}

fn sealed_for(sealer: &Person, vault: &str, vk: &VaultKey, to: &Person) -> SealedFor {
    let wrapped = vk.seal_to(&to.public().enc).unwrap();
    SealedFor {
        account_id: to.id.clone(),
        grant_sig: b(sharing::sign_grant(
            &sealer.keys,
            vault,
            vk.id(),
            &to.id,
            &wrapped,
        )),
        wrapped_vault_key: b(wrapped),
    }
}

fn member_key(sealer: &Person, vault: &str, vk: &VaultKey, to: &Person) -> MemberVaultKey {
    let s = sealed_for(sealer, vault, vk, to);
    MemberVaultKey {
        vault_id: vault.into(),
        key_id: b(vk.id().to_vec()),
        wrapped_vault_key: s.wrapped_vault_key,
        grant_sig: s.grant_sig,
    }
}

/// Creates an organization vault sealed to `admins` (the creator included).
async fn org_vault(creator: &Person, org: &str, admins: &[&Person]) -> (String, VaultKey) {
    let id = ulid();
    let vk = VaultKey::generate().unwrap();
    let keys: Vec<SealedFor> = admins
        .iter()
        .map(|a| sealed_for(creator, &id, &vk, a))
        .collect();
    let mine = keys.iter().find(|k| k.account_id == creator.id).unwrap();
    let v = creator
        .client
        .create_vault(&CreateVault {
            id: id.clone(),
            key_id: b(vk.id().to_vec()),
            wrapped_vault_key: mine.wrapped_vault_key.clone(),
            meta: None,
            org_id: Some(org.into()),
            keys,
        })
        .await
        .unwrap();
    assert_eq!(v.org_id.as_deref(), Some(org));
    assert_eq!(v.permission, Some(Permission::Manage));
    (id, vk)
}

fn seal(vk: &VaultKey, author: &Person, vault: &str, item: &str, text: &str) -> B64 {
    let ctx = ItemContext {
        vault_id: vault,
        item_id: item,
        schema_version: 1,
    };
    b(envelope::seal(vk, &author.keys, &ctx, text.as_bytes()).unwrap())
}

fn put(id: &str, base_rev: i64, env: B64) -> PushItem {
    PushItem {
        id: id.into(),
        base_rev,
        deleted: false,
        envelope: Some(env),
    }
}

fn api_code<T: std::fmt::Debug>(r: Result<T, Error>) -> (u16, String) {
    match r {
        Err(Error::Api { status, code, .. }) => (status, code),
        other => panic!("expected an API error, got {other:?}"),
    }
}

/// The invite token (only servers that don't mail invites hand it back).
fn token(invite: &Invite) -> Option<String> {
    invite.token.clone()
}

#[tokio::test]
async fn invite_accept_confirm_share_rotate_remove() {
    let Some((url, _)) = sharing_server().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let carol = person(&url, "carol").await;

    let org_id = ulid();
    let org = alice
        .client
        .create_org(&CreateOrg {
            id: org_id.clone(),
            name: "Acme Ops".into(),
        })
        .await
        .unwrap();
    assert_eq!(org.owner_id, alice.id);
    assert_eq!(org.owner_chain.len(), 1);
    assert_eq!(org.owner_chain[0].sign_public_key.0, alice.public().sign);
    assert!(org.owner_chain[0].cert.is_none());

    let (vault, vk) = org_vault(&alice, &org_id, &[&alice]).await;
    let first = ulid();
    let r = alice
        .client
        .push(
            &vault,
            vec![put(&first, 0, seal(&vk, &alice, &vault, &first, "db1"))],
        )
        .await
        .unwrap();
    assert_eq!(r.results[0].status, PushStatus::Accepted);

    // Invite Bob with read access to the vault.
    let invite = alice
        .client
        .invite(
            &org_id,
            &CreateInvite {
                email: bob.email.clone(),
                role: Role::Member,
                vaults: vec![VaultGrant {
                    vault_id: vault.clone(),
                    permission: Permission::Read,
                }],
            },
        )
        .await
        .unwrap();
    let Some(token) = token(&invite) else {
        return; // The server mails invites: the rest needs the mailbox.
    };
    assert_eq!(alice.client.invites(&org_id).await.unwrap().len(), 1);

    // What Bob sees before accepting: the owner's keys to pin and fingerprint.
    let info = bob.client.invite_info(&token).await.unwrap();
    assert_eq!(
        (info.org_name.as_str(), info.role),
        ("Acme Ops", Role::Member)
    );
    assert_eq!(info.inviter_email, alice.email);
    let root = &info.owner_chain[0];
    let root_keys = PublicKeys {
        enc: root.enc_public_key.0.as_slice().try_into().unwrap(),
        sign: root.sign_public_key.0.as_slice().try_into().unwrap(),
    };
    assert_eq!(
        sharing::fingerprint(&root.account_id, &root_keys),
        sharing::fingerprint(&alice.id, &alice.public())
    );

    // Only the invited address can accept.
    assert_eq!(
        api_code(carol.client.accept_invite(&token).await),
        (403, "invite_email_mismatch".into())
    );
    let joined = bob.client.accept_invite(&token).await.unwrap();
    assert_eq!(joined.status, MemberStatus::Accepted);
    assert_eq!(
        api_code(bob.client.accept_invite(&token).await),
        (410, "invite_expired".into())
    );

    // Accepted is not confirmed: no vaults, no member list.
    assert!(
        bob.client
            .list_vaults()
            .await
            .unwrap()
            .iter()
            .all(|v| v.id != vault)
    );
    assert_eq!(api_code(bob.client.pull(&vault, 0, 10).await).0, 404);
    assert_eq!(
        api_code(bob.client.members(&org_id).await),
        (403, "not_permitted".into())
    );
    assert_eq!(bob.client.org(&org_id).await.unwrap().name, "Acme Ops");

    // Alice confirms Bob: his keys as the server shows them, certified, and the vault key.
    let members = alice.client.members(&org_id).await.unwrap();
    let pending = members.iter().find(|m| m.account_id == bob.id).unwrap();
    assert_eq!(pending.status, MemberStatus::Accepted);
    assert_eq!(
        pending.pending_vaults,
        [VaultGrant {
            vault_id: vault.clone(),
            permission: Permission::Read
        }]
    );
    assert_eq!(pending.sign_public_key.0, bob.public().sign);
    let cert = sharing::certify(
        &alice.keys,
        CertKind::Member,
        &org_id,
        &bob.id,
        &bob.public(),
    );
    assert_eq!(
        api_code(
            alice
                .client
                .confirm_member(
                    &org_id,
                    &bob.id,
                    &ConfirmMember {
                        member_cert: b(cert),
                        admin_cert: None,
                        vault_keys: vec![],
                    },
                )
                .await
        ),
        (400, "incomplete_keys".into())
    );
    let confirmed = alice
        .client
        .confirm_member(
            &org_id,
            &bob.id,
            &ConfirmMember {
                member_cert: b(cert),
                admin_cert: None,
                vault_keys: vec![member_key(&alice, &vault, &vk, &bob)],
            },
        )
        .await
        .unwrap();
    assert_eq!(confirmed.status, MemberStatus::Confirmed);
    let mc = confirmed.member_cert.unwrap();
    assert_eq!(mc.signer_id, alice.id);
    sharing::verify_cert(
        &alice.public().sign,
        CertKind::Member,
        &org_id,
        &bob.id,
        &bob.public(),
        &mc.sig.0,
    )
    .unwrap();

    // Bob's view: read access, a key granted (and signed) by Alice.
    let bv = bob
        .client
        .list_vaults()
        .await
        .unwrap()
        .into_iter()
        .find(|v| v.id == vault)
        .unwrap();
    assert_eq!(bv.permission, Some(Permission::Read));
    assert_eq!(bv.keys.len(), 1);
    let grant = bv.keys[0].grant.as_ref().unwrap();
    assert_eq!(grant.signer_id, alice.id);
    sharing::verify_grant(
        &alice.public().sign,
        &vault,
        &key_bytes(&bv.key_id),
        &bob.id,
        &bv.wrapped_vault_key.0,
        &grant.sig.0,
    )
    .unwrap();
    let bob_vk = VaultKey::open(&bob.keys, &bv.wrapped_vault_key.0).unwrap();
    assert_eq!(bob_vk.id(), vk.id());

    // Bob reads Alice's item: the server names her as its author.
    let page = bob.client.pull(&vault, 0, 10).await.unwrap();
    assert_eq!(page.items[0].author_id.as_deref(), Some(alice.id.as_str()));
    let ctx = ItemContext {
        vault_id: &vault,
        item_id: &first,
        schema_version: 1,
    };
    let plain = envelope::open(
        &bob_vk,
        &alice.public().sign,
        &ctx,
        &page.items[0].envelope.as_ref().unwrap().0,
    )
    .unwrap();
    assert_eq!(&plain[..], b"db1");

    // Read means read.
    let bobs = ulid();
    assert_eq!(
        api_code(
            bob.client
                .push(
                    &vault,
                    vec![put(&bobs, 0, seal(&bob_vk, &bob, &vault, &bobs, "x"))]
                )
                .await
        ),
        (403, "not_permitted".into())
    );
    // Write access (no keys needed: Bob has them).
    alice
        .client
        .set_vault_member(
            &vault,
            &bob.id,
            &SetVaultMember {
                permission: Permission::Write,
                keys: vec![],
            },
        )
        .await
        .unwrap();
    let r = bob
        .client
        .push(
            &vault,
            vec![put(&bobs, 0, seal(&bob_vk, &bob, &vault, &bobs, "web1"))],
        )
        .await
        .unwrap();
    assert_eq!(r.results[0].status, PushStatus::Accepted);
    let page = alice.client.pull(&vault, 0, 10).await.unwrap();
    let by_bob = page.items.iter().find(|i| i.id == bobs).unwrap();
    assert_eq!(by_bob.author_id.as_deref(), Some(bob.id.as_str()));
    let members = alice.client.vault_members(&vault).await.unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.account_id == alice.id && m.implicit)
    );
    assert!(
        members
            .iter()
            .any(|m| m.account_id == bob.id && m.permission == Permission::Write)
    );
    // A plain member can't manage access.
    assert_eq!(api_code(bob.client.vault_members(&vault).await).0, 403);

    // Revoke Bob: he's out at once, and the vault wants a new key.
    alice
        .client
        .revoke_vault_member(&vault, &bob.id)
        .await
        .unwrap();
    assert_eq!(api_code(bob.client.pull(&vault, 0, 10).await).0, 404);
    let v = alice.client.vault(&vault).await.unwrap();
    assert!(v.rotation_due);

    // Rotate: the new key for everyone with access (now just Alice).
    let vk2 = VaultKey::generate().unwrap();
    let rotate = |previous: &[u8; 16], wrapped: Vec<SealedFor>| RotateVaultKey {
        key_id: b(vk2.id().to_vec()),
        previous_key_id: b(previous.to_vec()),
        wrapped,
    };
    assert_eq!(
        api_code(
            alice
                .client
                .rotate_vault_key(
                    &vault,
                    &rotate(vk2.id(), vec![sealed_for(&alice, &vault, &vk2, &alice)])
                )
                .await
        ),
        (409, "conflict".into())
    );
    assert_eq!(
        api_code(
            alice
                .client
                .rotate_vault_key(&vault, &rotate(vk.id(), vec![]))
                .await
        ),
        (400, "incomplete_rotation".into())
    );
    assert_eq!(
        api_code(
            alice
                .client
                .rotate_vault_key(
                    &vault,
                    &rotate(
                        vk.id(),
                        vec![
                            sealed_for(&alice, &vault, &vk2, &alice),
                            sealed_for(&alice, &vault, &vk2, &bob)
                        ]
                    )
                )
                .await
        )
        .0,
        400
    );
    let v = alice
        .client
        .rotate_vault_key(
            &vault,
            &rotate(vk.id(), vec![sealed_for(&alice, &vault, &vk2, &alice)]),
        )
        .await
        .unwrap();
    assert_eq!(key_bytes(&v.key_id), *vk2.id());
    assert!(!v.rotation_due);
    assert_eq!(v.items_on_old_keys, Some(2));
    assert_eq!(
        v.keys.len(),
        2,
        "the old generation stays until nothing uses it"
    );

    // Under the old key: refused per item. Re-encrypted: accepted.
    let page = alice.client.pull(&vault, 0, 10).await.unwrap();
    let rev = |id: &str| page.items.iter().find(|i| i.id == id).unwrap().rev;
    let r = alice
        .client
        .push(
            &vault,
            vec![put(
                &first,
                rev(&first),
                seal(&vk, &alice, &vault, &first, "db1"),
            )],
        )
        .await
        .unwrap();
    assert_eq!(r.results[0].error.as_ref().unwrap().code, "stale_key");
    let r = alice
        .client
        .push(
            &vault,
            vec![
                put(
                    &first,
                    rev(&first),
                    seal(&vk2, &alice, &vault, &first, "db1"),
                ),
                put(&bobs, rev(&bobs), seal(&vk2, &alice, &vault, &bobs, "web1")),
            ],
        )
        .await
        .unwrap();
    assert!(r.results.iter().all(|r| r.status == PushStatus::Accepted));
    assert_eq!(
        alice.client.vault(&vault).await.unwrap().items_on_old_keys,
        Some(0)
    );

    // Remove Bob from the organization: it disappears for him.
    alice.client.remove_member(&org_id, &bob.id).await.unwrap();
    assert_eq!(api_code(bob.client.org(&org_id).await).0, 404);
    assert!(bob.client.orgs().await.unwrap().is_empty());

    // The audit trail, oldest first.
    let kinds: Vec<String> = alice
        .client
        .org_events(&org_id, 0, 100)
        .await
        .unwrap()
        .events
        .into_iter()
        .map(|e| e.kind)
        .collect();
    let expected = [
        "org_created",
        "vault_created",
        "member_invited",
        "member_accepted",
        "member_confirmed",
        "vault_access_changed",
        "vault_access_revoked",
        "vault_key_rotated",
        "member_removed",
    ];
    assert_eq!(kinds, expected);
    assert_eq!(
        api_code(carol.client.org_events(&org_id, 0, 100).await).0,
        404
    );
}

#[tokio::test]
async fn admins_policies_and_ownership() {
    let Some((url, _)) = sharing_server().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let carol = person(&url, "carol").await;
    let org_id = ulid();
    alice
        .client
        .create_org(&CreateOrg {
            id: org_id.clone(),
            name: "Ops".into(),
        })
        .await
        .unwrap();
    let (v1, vk1) = org_vault(&alice, &org_id, &[&alice]).await;

    // Bob joins as an admin: the owner confirms, certifies him as admin and hands him every key.
    let invite = alice
        .client
        .invite(
            &org_id,
            &CreateInvite {
                email: bob.email.clone(),
                role: Role::Admin,
                vaults: vec![],
            },
        )
        .await
        .unwrap();
    let Some(token) = token(&invite) else {
        return;
    };
    bob.client.accept_invite(&token).await.unwrap();
    let member_cert = b(sharing::certify(
        &alice.keys,
        CertKind::Member,
        &org_id,
        &bob.id,
        &bob.public(),
    ));
    let admin_cert = b(sharing::certify(
        &alice.keys,
        CertKind::Admin,
        &org_id,
        &bob.id,
        &bob.public(),
    ));
    let confirm = |keys: Vec<MemberVaultKey>| ConfirmMember {
        member_cert: member_cert.clone(),
        admin_cert: Some(admin_cert.clone()),
        vault_keys: keys,
    };
    assert_eq!(
        api_code(
            alice
                .client
                .confirm_member(&org_id, &bob.id, &confirm(vec![]))
                .await
        ),
        (400, "incomplete_keys".into())
    );
    let m = alice
        .client
        .confirm_member(
            &org_id,
            &bob.id,
            &confirm(vec![member_key(&alice, &v1, &vk1, &bob)]),
        )
        .await
        .unwrap();
    assert_eq!(m.role, Role::Admin);
    assert_eq!(m.admin_cert.unwrap().signer_id, alice.id);
    assert_eq!(
        bob.client.vault(&v1).await.unwrap().permission,
        Some(Permission::Manage)
    );

    // An admin's vault must reach every owner and admin.
    let lonely = ulid();
    let vk = VaultKey::generate().unwrap();
    let mine = sealed_for(&bob, &lonely, &vk, &bob);
    assert_eq!(
        api_code(
            bob.client
                .create_vault(&CreateVault {
                    id: lonely,
                    key_id: b(vk.id().to_vec()),
                    wrapped_vault_key: mine.wrapped_vault_key.clone(),
                    meta: None,
                    org_id: Some(org_id.clone()),
                    keys: vec![mine],
                })
                .await
        ),
        (400, "incomplete_keys".into())
    );
    let (v2, _) = org_vault(&bob, &org_id, &[&alice, &bob]).await;
    assert_eq!(
        alice.client.vault(&v2).await.unwrap().permission,
        Some(Permission::Manage)
    );

    // Admins invite members, not admins.
    assert_eq!(
        api_code(
            bob.client
                .invite(
                    &org_id,
                    &CreateInvite {
                        email: carol.email.clone(),
                        role: Role::Admin,
                        vaults: vec![]
                    }
                )
                .await
        ),
        (403, "not_permitted".into())
    );
    let invite = bob
        .client
        .invite(
            &org_id,
            &CreateInvite {
                email: carol.email.clone(),
                role: Role::Member,
                vaults: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        api_code(
            alice
                .client
                .invite(
                    &org_id,
                    &CreateInvite {
                        email: bob.email.clone(),
                        role: Role::Member,
                        vaults: vec![]
                    }
                )
                .await
        ),
        (409, "already_member".into())
    );
    carol
        .client
        .accept_invite(&invite.token.unwrap())
        .await
        .unwrap();
    bob.client
        .confirm_member(
            &org_id,
            &carol.id,
            &ConfirmMember {
                member_cert: b(sharing::certify(
                    &bob.keys,
                    CertKind::Member,
                    &org_id,
                    &carol.id,
                    &carol.public(),
                )),
                admin_cert: None,
                vault_keys: vec![],
            },
        )
        .await
        .unwrap();

    // Members create vaults only when the policy allows; theirs reach owners and admins too.
    assert_eq!(
        api_code(
            carol
                .client
                .create_vault(&CreateVault {
                    id: ulid(),
                    key_id: b(vec![1; 16]),
                    wrapped_vault_key: b(vec![1; 105]),
                    meta: None,
                    org_id: Some(org_id.clone()),
                    keys: vec![],
                })
                .await
        ),
        (403, "not_permitted".into())
    );
    let org = alice
        .client
        .update_org(
            &org_id,
            &UpdateOrg {
                name: None,
                policies: Some(Policies {
                    members_can_create_vaults: true,
                    allowed_email_domains: vec!["Example.ORG".into()],
                    ..Policies::default()
                }),
            },
        )
        .await
        .unwrap();
    assert_eq!(org.policies.allowed_email_domains, ["example.org"]);
    let (v3, _) = org_vault(&carol, &org_id, &[&alice, &bob, &carol]).await;
    assert_eq!(
        carol.client.vault(&v3).await.unwrap().permission,
        Some(Permission::Manage)
    );
    assert_eq!(
        api_code(
            alice
                .client
                .invite(
                    &org_id,
                    &CreateInvite {
                        email: "x@example.com".into(),
                        role: Role::Member,
                        vaults: vec![]
                    }
                )
                .await
        ),
        (403, "not_permitted".into())
    );

    // The owner can't leave or delete their account while they own the organization.
    assert_eq!(
        api_code(alice.client.remove_member(&org_id, &alice.id).await),
        (409, "sole_owner".into())
    );

    // Ownership goes to a confirmed admin, with a certificate from the outgoing owner.
    let owner_cert = b(sharing::certify(
        &alice.keys,
        CertKind::Owner,
        &org_id,
        &bob.id,
        &bob.public(),
    ));
    assert_eq!(
        api_code(
            alice
                .client
                .transfer_org(
                    &org_id,
                    &TransferOrg {
                        account_id: carol.id.clone(),
                        auth_key: b(vec![7; 32]),
                        owner_cert: owner_cert.clone()
                    }
                )
                .await
        )
        .0,
        400
    );
    let org = alice
        .client
        .transfer_org(
            &org_id,
            &TransferOrg {
                account_id: bob.id.clone(),
                auth_key: b(vec![7; 32]),
                owner_cert,
            },
        )
        .await
        .unwrap();
    assert_eq!(org.owner_id, bob.id);
    assert_eq!(org.owner_chain.len(), 2);
    let link = &org.owner_chain[1];
    assert_eq!(link.cert.as_ref().unwrap().signer_id, alice.id);
    sharing::verify_cert(
        &alice.public().sign,
        CertKind::Owner,
        &org_id,
        &bob.id,
        &bob.public(),
        &link.cert.as_ref().unwrap().sig.0,
    )
    .unwrap();
    let roles: Vec<(String, Role)> = bob
        .client
        .members(&org_id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| (m.account_id, m.role))
        .collect();
    assert!(roles.contains(&(bob.id.clone(), Role::Owner)));
    assert!(roles.contains(&(alice.id.clone(), Role::Admin)));

    // Deleting the organization takes its vaults.
    assert_eq!(
        api_code(
            bob.client
                .delete_org(
                    &org_id,
                    &DeleteOrg {
                        auth_key: b(vec![8; 32])
                    }
                )
                .await
        )
        .0,
        401
    );
    bob.client
        .delete_org(
            &org_id,
            &DeleteOrg {
                auth_key: b(vec![7; 32]),
            },
        )
        .await
        .unwrap();
    for v in [&v1, &v2, &v3] {
        assert_eq!(api_code(alice.client.vault(v).await).0, 404);
    }
}

#[tokio::test]
async fn cancelled_invites_and_promotion() {
    let Some((url, _)) = sharing_server().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let org_id = ulid();
    alice
        .client
        .create_org(&CreateOrg {
            id: org_id.clone(),
            name: "Ops".into(),
        })
        .await
        .unwrap();
    let (vault, vk) = org_vault(&alice, &org_id, &[&alice]).await;

    let invite = alice
        .client
        .invite(
            &org_id,
            &CreateInvite {
                email: bob.email.clone(),
                role: Role::Member,
                vaults: vec![],
            },
        )
        .await
        .unwrap();
    let Some(token) = token(&invite) else {
        return;
    };
    alice
        .client
        .cancel_invite(&org_id, &invite.id)
        .await
        .unwrap();
    assert!(alice.client.invites(&org_id).await.unwrap().is_empty());
    // A cancelled invite is gone, which is not "the vault lost history".
    let gone = bob.client.invite_info(&token).await;
    assert!(
        matches!(&gone, Err(Error::Api { status: 410, code, .. }) if code == "invite_expired"),
        "{gone:?}"
    );
    assert_eq!(api_code(bob.client.accept_invite(&token).await).0, 410);

    // A fresh invite, confirmed with no vaults; then promoted, which needs every vault key.
    let invite = alice
        .client
        .invite(
            &org_id,
            &CreateInvite {
                email: bob.email.clone(),
                role: Role::Member,
                vaults: vec![],
            },
        )
        .await
        .unwrap();
    bob.client
        .accept_invite(&invite.token.unwrap())
        .await
        .unwrap();
    alice
        .client
        .confirm_member(
            &org_id,
            &bob.id,
            &ConfirmMember {
                member_cert: b(sharing::certify(
                    &alice.keys,
                    CertKind::Member,
                    &org_id,
                    &bob.id,
                    &bob.public(),
                )),
                admin_cert: None,
                vault_keys: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(api_code(bob.client.vault(&vault).await).0, 404);
    let admin_cert = Some(b(sharing::certify(
        &alice.keys,
        CertKind::Admin,
        &org_id,
        &bob.id,
        &bob.public(),
    )));
    assert_eq!(
        api_code(
            alice
                .client
                .update_member(
                    &org_id,
                    &bob.id,
                    &UpdateMember {
                        role: Role::Admin,
                        admin_cert: admin_cert.clone(),
                        vault_keys: vec![]
                    }
                )
                .await
        ),
        (400, "incomplete_keys".into())
    );
    alice
        .client
        .update_member(
            &org_id,
            &bob.id,
            &UpdateMember {
                role: Role::Admin,
                admin_cert,
                vault_keys: vec![member_key(&alice, &vault, &vk, &bob)],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        bob.client.vault(&vault).await.unwrap().permission,
        Some(Permission::Manage)
    );

    // Demoted again: the vault he no longer may open wants a new key.
    alice
        .client
        .update_member(
            &org_id,
            &bob.id,
            &UpdateMember {
                role: Role::Member,
                admin_cert: None,
                vault_keys: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(api_code(bob.client.vault(&vault).await).0, 404);
    assert!(alice.client.vault(&vault).await.unwrap().rotation_due);
}
