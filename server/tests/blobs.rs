//! The `blobs` capability against the server under test (see `common`): encrypted session logs
//! and attachments, named by the SHA-256 of their bytes. Blobs are sealed with `mg-vault` the way
//! apps seal them. Skipped when the server doesn't advertise `blobs`.

use mg_sync::*;
use mg_vault::blob::{self, BlobKind};
use mg_vault::sharing::{self, CertKind};
use mg_vault::{PublicKeys, VaultKey};

mod common;

use common::{email, reference_with, server};

fn ulid() -> String {
    ulid::Ulid::generate().to_string()
}

fn b(v: impl Into<Vec<u8>>) -> B64 {
    B64(v.into())
}

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

/// `None` when the server has no `blobs` (the tests then pass vacuously).
async fn blob_server() -> Option<(String, BlobFeatures, Option<Sharing>)> {
    let url = server().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    let blobs = caps.features.blobs?;
    Some((url, blobs, caps.features.sharing))
}

async fn personal_vault(p: &Person) -> (String, VaultKey) {
    let id = ulid();
    let vk = VaultKey::generate().unwrap();
    p.client
        .create_vault(&CreateVault {
            id: id.clone(),
            key_id: b(vk.id().to_vec()),
            wrapped_vault_key: b(vk.seal_to(&p.public().enc).unwrap()),
            meta: None,
            org_id: None,
            keys: Vec::new(),
        })
        .await
        .unwrap();
    (id, vk)
}

fn api_code<T: std::fmt::Debug>(r: Result<T, Error>) -> (u16, String) {
    match r {
        Err(Error::Api { status, code, .. }) => (status, code),
        other => panic!("expected an API error, got {other:?}"),
    }
}

#[tokio::test]
async fn personal_blobs_named_by_their_hash() {
    let Some((url, limits, _)) = blob_server().await else {
        return;
    };
    assert!(limits.max_blob_bytes >= 1024 * 1024);
    assert!(limits.kinds.iter().any(|k| k == "session_log"));
    assert!(limits.kinds.iter().any(|k| k == "attachment"));
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let (vault, vk) = personal_vault(&alice).await;

    // A session log, sealed the way the app seals it.
    let log = b"{\"version\":2,\"width\":80,\"height\":24}\n[0.5,\"o\",\"$ \"]\n";
    let sealed = blob::seal(&vk, &vault, BlobKind::SessionLog, log).unwrap();
    let hash = blob::hash(&sealed);
    let (info, created) = alice
        .client
        .put_blob(&vault, &hash, "session_log", sealed.clone())
        .await
        .unwrap();
    assert!(created);
    assert_eq!(
        (info.hash.as_str(), info.size, info.kind.as_str()),
        (hash.as_str(), sealed.len() as u64, "session_log")
    );
    assert_eq!(info.author_id.as_deref(), Some(alice.id.as_str()));

    // The same bytes again: 200, nothing new.
    let (again, created) = alice
        .client
        .put_blob(&vault, &hash, "session_log", sealed.clone())
        .await
        .unwrap();
    assert!(!created);
    assert_eq!(again.created_at, info.created_at);

    // An attachment, then the list (oldest first) and the kind filter.
    let doc = blob::seal(&vk, &vault, BlobKind::Attachment, b"runbook").unwrap();
    let doc_hash = blob::hash(&doc);
    alice
        .client
        .put_blob(&vault, &doc_hash, "attachment", doc)
        .await
        .unwrap();
    // Oldest first; blobs from the same second may come in either order.
    let all = alice.client.blobs(&vault, None).await.unwrap();
    let mut listed: Vec<&str> = all.iter().map(|b| b.hash.as_str()).collect();
    listed.sort();
    let mut expected = [hash.as_str(), doc_hash.as_str()];
    expected.sort();
    assert_eq!(listed, expected);
    let logs = alice
        .client
        .blobs(&vault, Some("session_log"))
        .await
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].hash, hash);

    // Back and open: the bytes are what was sealed.
    let fetched = alice.client.blob(&vault, &hash).await.unwrap();
    assert_eq!(blob::hash(&fetched), hash);
    assert_eq!(
        &blob::open(&vk, &vault, BlobKind::SessionLog, &fetched).unwrap()[..],
        log
    );

    // The server checks the name, the kind and the access, never the content.
    let other = blob::seal(&vk, &vault, BlobKind::Attachment, b"other").unwrap();
    assert_eq!(
        api_code(
            alice
                .client
                .put_blob(&vault, &hash, "attachment", other.clone())
                .await
        ),
        (400, "hash_mismatch".into())
    );
    assert_eq!(
        api_code(
            alice
                .client
                .put_blob(&vault, "not-a-hash", "attachment", other.clone())
                .await
        )
        .0,
        400
    );
    let other_hash = blob::hash(&other);
    assert_eq!(
        api_code(
            alice
                .client
                .put_blob(&vault, &other_hash, "photo", other)
                .await
        )
        .0,
        400
    );
    assert_eq!(api_code(bob.client.blob(&vault, &hash).await).0, 404);
    assert_eq!(api_code(bob.client.blobs(&vault, None).await).0, 404);
    assert_eq!(
        api_code(alice.client.blob(&vault, &"0".repeat(64)).await).0,
        404
    );

    // Deleted is gone.
    alice.client.delete_blob(&vault, &doc_hash).await.unwrap();
    assert_eq!(api_code(alice.client.blob(&vault, &doc_hash).await).0, 404);
    assert_eq!(alice.client.blobs(&vault, None).await.unwrap().len(), 1);

    // Deleting the vault takes its blobs along.
    alice.client.delete_vault(&vault).await.unwrap();
    assert_eq!(api_code(alice.client.blobs(&vault, None).await).0, 404);
}

#[tokio::test]
async fn organization_blobs_follow_vault_access() {
    let Some((url, _, Some(_))) = blob_server().await else {
        return;
    };
    let alice = person(&url, "alice").await;
    let bob = person(&url, "bob").await;
    let org_id = ulid();
    alice
        .client
        .create_org(&CreateOrg {
            id: org_id.clone(),
            name: "Acme Ops".into(),
        })
        .await
        .unwrap();

    // An organization vault, sealed to Alice.
    let vault = ulid();
    let vk = VaultKey::generate().unwrap();
    let wrapped = vk.seal_to(&alice.public().enc).unwrap();
    let mine = SealedFor {
        account_id: alice.id.clone(),
        grant_sig: b(sharing::sign_grant(
            &alice.keys,
            &vault,
            vk.id(),
            &alice.id,
            &wrapped,
        )),
        wrapped_vault_key: b(wrapped.clone()),
    };
    alice
        .client
        .create_vault(&CreateVault {
            id: vault.clone(),
            key_id: b(vk.id().to_vec()),
            wrapped_vault_key: b(wrapped),
            meta: None,
            org_id: Some(org_id.clone()),
            keys: vec![mine],
        })
        .await
        .unwrap();

    // A team's session logs need the plan feature where plans apply.
    let sealed = blob::seal(&vk, &vault, BlobKind::SessionLog, b"[0.1,\"o\",\"x\"]").unwrap();
    let hash = blob::hash(&sealed);
    match alice
        .client
        .put_blob(&vault, &hash, "session_log", sealed)
        .await
    {
        Ok((_, created)) => assert!(created),
        Err(Error::PaymentRequired(p)) => {
            assert_eq!(p.code, "upgrade_required");
            assert_eq!(p.feature.as_deref(), Some("session_logs"));
        }
        Err(e) => panic!("session log refused: {e}"),
    }
    // Attachments never need it.
    let doc = blob::seal(&vk, &vault, BlobKind::Attachment, b"runbook").unwrap();
    let doc_hash = blob::hash(&doc);
    alice
        .client
        .put_blob(&vault, &doc_hash, "attachment", doc)
        .await
        .unwrap();

    // Bob joins with read access: he reads blobs, he can't write them.
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
    let Some(token) = invite.token else {
        return; // The server mails invites: the rest needs the mailbox.
    };
    assert_eq!(api_code(bob.client.blobs(&vault, None).await).0, 404);
    bob.client.accept_invite(&token).await.unwrap();
    let cert = sharing::certify(
        &alice.keys,
        CertKind::Member,
        &org_id,
        &bob.id,
        &bob.public(),
    );
    let wrapped = vk.seal_to(&bob.public().enc).unwrap();
    alice
        .client
        .confirm_member(
            &org_id,
            &bob.id,
            &ConfirmMember {
                member_cert: b(cert),
                admin_cert: None,
                vault_keys: vec![MemberVaultKey {
                    vault_id: vault.clone(),
                    key_id: b(vk.id().to_vec()),
                    grant_sig: b(sharing::sign_grant(
                        &alice.keys,
                        &vault,
                        vk.id(),
                        &bob.id,
                        &wrapped,
                    )),
                    wrapped_vault_key: b(wrapped),
                }],
            },
        )
        .await
        .unwrap();
    let seen = bob.client.blobs(&vault, Some("attachment")).await.unwrap();
    assert_eq!(seen.len(), 1);
    let bytes = bob.client.blob(&vault, &doc_hash).await.unwrap();
    assert_eq!(
        &blob::open(&vk, &vault, BlobKind::Attachment, &bytes).unwrap()[..],
        b"runbook"
    );
    let mine = blob::seal(&vk, &vault, BlobKind::Attachment, b"bob's").unwrap();
    assert_eq!(
        api_code(
            bob.client
                .put_blob(&vault, &blob::hash(&mine), "attachment", mine)
                .await
        ),
        (403, "not_permitted".into())
    );
    assert_eq!(
        api_code(bob.client.delete_blob(&vault, &doc_hash).await),
        (403, "not_permitted".into())
    );

    // The retention policy round-trips.
    let org = alice
        .client
        .update_org(
            &org_id,
            &UpdateOrg {
                name: None,
                policies: Some(Policies {
                    session_log_retention_days: 30,
                    ..Policies::default()
                }),
            },
        )
        .await
        .unwrap();
    assert_eq!(org.policies.session_log_retention_days, 30);
    assert_eq!(
        alice
            .client
            .org(&org_id)
            .await
            .unwrap()
            .policies
            .session_log_retention_days,
        30
    );
}

/// Size and quota limits, on a reference server configured small.
#[tokio::test]
async fn limits_and_quota() {
    let Some(url) = reference_with(vault_sync_server::Config {
        max_blob_bytes: 8 * 1024,
        blob_quota_bytes: 20 * 1024,
        ..Default::default()
    })
    .await
    else {
        return;
    };
    let alice = person(&url, "alice").await;
    let (vault, vk) = personal_vault(&alice).await;
    let (second, vk2) = personal_vault(&alice).await;

    let caps = alice.client.capabilities().await.unwrap();
    assert_eq!(caps.features.blobs.unwrap().quota_bytes, 20 * 1024);

    // 12 KiB of plaintext seals to more than 8 KiB.
    let big = blob::seal(&vk, &vault, BlobKind::Attachment, &[7u8; 12 * 1024]).unwrap();
    assert_eq!(
        api_code(
            alice
                .client
                .put_blob(&vault, &blob::hash(&big), "attachment", big)
                .await
        ),
        (413, "too_large".into())
    );
    // Each of these is just over 4 KiB: four fit in 20 KiB across both vaults, the fifth doesn't.
    for i in 0..4u8 {
        let (v, k) = if i % 2 == 0 {
            (&vault, &vk)
        } else {
            (&second, &vk2)
        };
        let s = blob::seal(k, v, BlobKind::Attachment, &[i; 100]).unwrap();
        alice
            .client
            .put_blob(v, &blob::hash(&s), "attachment", s)
            .await
            .unwrap();
    }
    let s = blob::seal(&vk, &vault, BlobKind::Attachment, &[9; 100]).unwrap();
    assert_eq!(
        api_code(
            alice
                .client
                .put_blob(&vault, &blob::hash(&s), "attachment", s)
                .await
        ),
        (413, "quota_exceeded".into())
    );
}
