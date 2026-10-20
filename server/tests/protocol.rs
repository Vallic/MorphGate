//! `mg_sync::SyncClient` against the server under test (see `common`).

use mg_sync::*;
mod common;

use common::{closed_server, email, server};

fn bytes(n: usize, fill: u8) -> B64 {
    B64(vec![fill; n])
}

/// An envelope-shaped blob: servers read the key generation from its clear header
/// (`version ‖ key_id`), here the test vaults' key `[1; 16]`.
fn envelope(fill: u8) -> B64 {
    let mut e = vec![1u8; 17];
    e.resize(300, fill);
    B64(e)
}

fn ulid() -> String {
    ulid::Ulid::generate().to_string()
}

fn device() -> DeviceInfo {
    DeviceInfo {
        id: ulid(),
        name: "laptop".into(),
        platform: "linux".into(),
        client_version: None,
        public_key: bytes(32, 9),
    }
}

fn kdf() -> KdfParams {
    KdfParams {
        alg: "argon2id".into(),
        m_kib: 65_536,
        t: 2,
        p: 1,
        salt: bytes(16, 1),
    }
}

fn register_req(email: &str, auth: u8) -> RegisterRequest {
    RegisterRequest {
        email: email.into(),
        kdf: kdf(),
        auth_key: bytes(32, auth),
        keys: AccountKeys {
            enc_public_key: bytes(32, 2),
            sign_public_key: bytes(32, 3),
            wrapped_private_keys: bytes(104, 4),
        },
        recovery: RecoveryMaterial {
            wrapped_private_keys_rk: bytes(104, 5),
            recovery_proof: bytes(32, 6),
        },
        device: device(),
        email_code: None,
        accepted_terms: None,
    }
}

fn put(id: &str, base_rev: i64, fill: u8) -> PushItem {
    PushItem {
        id: id.into(),
        base_rev,
        deleted: false,
        envelope: Some(envelope(fill)),
    }
}

#[tokio::test]
async fn discovery_register_login() {
    let url = server().await;
    let c = SyncClient::new(&url).unwrap();
    let caps = c.capabilities().await.unwrap();
    assert!(caps.features.registration_open && caps.limits.max_push_items == 500);

    // Unknown emails get stable but distinct fake parameters.
    let nobody = email("nobody");
    let a1 = c.prelogin(&nobody).await.unwrap();
    assert_eq!(a1, c.prelogin(&nobody.to_uppercase()).await.unwrap());
    assert_ne!(a1.salt, c.prelogin(&email("other")).await.unwrap().salt);

    let val = email("val");
    let s = c.register(&register_req(&val, 7)).await.unwrap();
    assert_eq!(s.keys.sign_public_key, bytes(32, 3));
    assert_eq!(c.prelogin(&val).await.unwrap(), kdf());
    assert!(matches!(
        c.register(&register_req(&val.to_uppercase(), 7)).await,
        Err(Error::Api { status: 409, .. })
    ));

    let other = SyncClient::new(&url).unwrap();
    let bad = LoginRequest {
        email: val.clone(),
        auth_key: bytes(32, 8),
        totp: None,
        device: device(),
    };
    assert!(matches!(
        other.login(&bad).await,
        Err(Error::Api { status: 401, .. })
    ));
    let good = LoginRequest {
        auth_key: bytes(32, 7),
        ..bad
    };
    let s2 = other.login(&good).await.unwrap();
    assert_eq!(s2.account_id, s.account_id);
    assert_eq!(other.account().await.unwrap().email, val);
    assert_eq!(c.devices().await.unwrap().len(), 2);
}

#[tokio::test]
async fn closed_registration() {
    let Some(url) = closed_server().await else {
        return;
    };
    let c = SyncClient::new(&url).unwrap();
    assert!(!c.capabilities().await.unwrap().features.registration_open);
    assert!(matches!(
        c.register(&register_req(&email("a"), 1)).await,
        Err(Error::Api { status: 403, .. })
    ));
}

#[tokio::test]
async fn push_pull_conflicts_and_tombstones() {
    let c = SyncClient::new(&server().await).unwrap();
    c.register(&register_req(&email("v"), 1)).await.unwrap();
    let vault = ulid();
    c.create_vault(&CreateVault {
        id: vault.clone(),
        key_id: bytes(16, 1),
        wrapped_vault_key: bytes(105, 2),
        meta: None,
        org_id: None,
        keys: Vec::new(),
    })
    .await
    .unwrap();
    let (a, b) = (ulid(), ulid());

    let r = c
        .push(&vault, vec![put(&a, 0, 1), put(&b, 0, 2)])
        .await
        .unwrap();
    assert_eq!(r.head_rev, 2);
    assert!(r.results.iter().all(|x| x.status == PushStatus::Accepted));

    let page = c.pull(&vault, 0, 500).await.unwrap();
    assert_eq!(
        (page.items.len(), page.head_rev, page.has_more),
        (2, 2, false)
    );

    // Stale base_rev: rejected as a conflict carrying the server copy.
    let r = c.push(&vault, vec![put(&a, 0, 9)]).await.unwrap();
    assert_eq!(r.results[0].status, PushStatus::Conflict);
    assert_eq!(
        r.results[0].current.as_ref().unwrap().envelope,
        Some(envelope(1))
    );

    // Correct base_rev wins; then delete b.
    let r = c
        .push(
            &vault,
            vec![
                put(&a, 1, 3),
                PushItem {
                    id: b.clone(),
                    base_rev: 2,
                    deleted: true,
                    envelope: None,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(r.head_rev, 4);
    let page = c.pull(&vault, 2, 500).await.unwrap();
    assert_eq!(page.items.len(), 2);
    let tomb = page.items.iter().find(|i| i.id == b).unwrap();
    assert!(tomb.deleted && tomb.envelope.is_none());

    // Pagination.
    let page = c.pull(&vault, 0, 1).await.unwrap();
    assert!(page.has_more && page.items.len() == 1);

    // Oversized envelopes and bad ids are rejected per item.
    let big = PushItem {
        id: ulid(),
        base_rev: 0,
        deleted: false,
        envelope: Some(bytes(70_000, 0)),
    };
    let bad_id = PushItem {
        id: "../x".into(),
        base_rev: 0,
        deleted: false,
        envelope: Some(bytes(1, 0)),
    };
    let r = c.push(&vault, vec![big, bad_id]).await.unwrap();
    assert!(r.results.iter().all(|x| x.status == PushStatus::Rejected));

    let v = c.list_vaults().await.unwrap();
    assert_eq!((v.len(), v[0].head_rev, v[0].item_count), (1, 4, Some(1)));
}

#[tokio::test]
async fn vaults_are_private_to_their_account() {
    let url = server().await;
    let alice = SyncClient::new(&url).unwrap();
    alice
        .register(&register_req(&email("alice"), 1))
        .await
        .unwrap();
    let vault = ulid();
    alice
        .create_vault(&CreateVault {
            id: vault.clone(),
            key_id: bytes(16, 1),
            wrapped_vault_key: bytes(105, 2),
            meta: None,
            org_id: None,
            keys: Vec::new(),
        })
        .await
        .unwrap();
    let mallory = SyncClient::new(&url).unwrap();
    mallory
        .register(&register_req(&email("mallory"), 2))
        .await
        .unwrap();
    assert!(matches!(
        mallory.pull(&vault, 0, 10).await,
        Err(Error::Api { status: 404, .. })
    ));
    assert!(matches!(
        mallory.push(&vault, vec![put(&ulid(), 0, 1)]).await,
        Err(Error::Api { status: 404, .. })
    ));
    assert!(mallory.list_vaults().await.unwrap().is_empty());
}

#[tokio::test]
async fn refresh_rotation_and_reuse_detection() {
    let url = server().await;
    let c = SyncClient::new(&url).unwrap();
    let s = c.register(&register_req(&email("r"), 1)).await.unwrap();
    let first_refresh = s.tokens.refresh_token.clone();
    assert!(c.take_rotated_refresh().is_some());

    // A new process resumes from the stored refresh token: it refreshes and rotates.
    let resumed = SyncClient::new(&url).unwrap();
    resumed.resume(first_refresh.clone());
    resumed.list_vaults().await.unwrap();
    let rotated = resumed.take_rotated_refresh().expect("rotated");
    assert_ne!(rotated, first_refresh);

    // Someone replays the old refresh token: the device is revoked for everyone holding it.
    let thief = SyncClient::new(&url).unwrap();
    thief.resume(first_refresh);
    assert!(matches!(
        thief.list_vaults().await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        resumed.list_vaults().await,
        Err(Error::Unauthorized)
    ));
}

#[tokio::test]
async fn recovery_tokens_are_narrow_and_single_use() {
    let url = server().await;
    let a = SyncClient::new(&url).unwrap();
    let owner = email("r");
    a.register(&register_req(&owner, 7)).await.unwrap();

    let thief = SyncClient::new(&url).unwrap();
    let bad = RecoverRequest {
        email: owner.clone(),
        recovery_proof: bytes(32, 99),
    };
    assert!(matches!(
        thief.recover(&bad).await,
        Err(Error::Api { status: 401, .. })
    ));

    let r = SyncClient::new(&url).unwrap();
    let resp = r
        .recover(&RecoverRequest {
            email: owner.clone(),
            recovery_proof: bytes(32, 6),
        })
        .await
        .unwrap();
    assert_eq!(resp.wrapped_private_keys_rk, bytes(104, 5));
    // Only good for setting new credentials: no account, no vaults, nothing to refresh.
    assert!(matches!(
        r.account().await,
        Err(Error::Unauthorized | Error::Api { status: 401, .. })
    ));
    assert!(matches!(
        r.list_vaults().await,
        Err(Error::Unauthorized | Error::Api { status: 401, .. })
    ));
    let rotate = RotateCredentialsRequest {
        current_auth_key: None,
        new_kdf: kdf(),
        new_auth_key: bytes(32, 8),
        wrapped_private_keys: bytes(104, 10),
        recovery: None,
    };
    let r2 = SyncClient::new(&url).unwrap();
    r2.recover(&RecoverRequest {
        email: owner.clone(),
        recovery_proof: bytes(32, 6),
    })
    .await
    .unwrap();
    r2.rotate_credentials(&rotate).await.unwrap();
    assert!(matches!(
        r2.rotate_credentials(&rotate).await,
        Err(Error::Unauthorized)
    ));
    // Everyone, including the device that registered, signs in again with the new key.
    assert!(matches!(a.account().await, Err(Error::Unauthorized)));
    let login = LoginRequest {
        email: owner.clone(),
        auth_key: bytes(32, 8),
        totp: None,
        device: device(),
    };
    let s = SyncClient::new(&url).unwrap().login(&login).await.unwrap();
    assert_eq!(s.keys.wrapped_private_keys, bytes(104, 10));
}

#[tokio::test]
async fn password_rotation_signs_out_others_but_a_new_recovery_key_does_not() {
    let url = server().await;
    let a = SyncClient::new(&url).unwrap();
    let p = email("p");
    a.register(&register_req(&p, 7)).await.unwrap();
    let b = SyncClient::new(&url).unwrap();
    b.login(&LoginRequest {
        email: p.clone(),
        auth_key: bytes(32, 7),
        totp: None,
        device: device(),
    })
    .await
    .unwrap();

    let same_password = RotateCredentialsRequest {
        current_auth_key: Some(bytes(32, 7)),
        new_kdf: kdf(),
        new_auth_key: bytes(32, 7),
        wrapped_private_keys: bytes(104, 4),
        recovery: Some(RecoveryMaterial {
            wrapped_private_keys_rk: bytes(104, 11),
            recovery_proof: bytes(32, 12),
        }),
    };
    let wrong = RotateCredentialsRequest {
        current_auth_key: Some(bytes(32, 1)),
        ..same_password.clone()
    };
    assert!(matches!(
        a.rotate_credentials(&wrong).await,
        Err(Error::Unauthorized)
    ));
    a.rotate_credentials(&same_password).await.unwrap();
    assert!(
        b.account().await.is_ok(),
        "a new recovery key keeps others signed in"
    );
    assert_eq!(
        b.account().await.unwrap().wrapped_private_keys_rk,
        Some(bytes(104, 11))
    );

    let new_password = RotateCredentialsRequest {
        new_auth_key: bytes(32, 8),
        recovery: None,
        ..same_password
    };
    a.rotate_credentials(&new_password).await.unwrap();
    assert!(
        a.account().await.is_ok(),
        "the device that changed it stays"
    );
    assert!(matches!(b.account().await, Err(Error::Unauthorized)));
}

/// Servers with `email_verification`: registering needs the code mailed by
/// `POST /auth/register/start`. Only the refusals can be checked from here (the code is in a
/// mailbox); the reference server doesn't verify addresses, so this runs only against servers
/// that do (`VAULT_SYNC_URL`).
#[tokio::test]
async fn email_verification_where_offered() {
    let url = server().await;
    let c = SyncClient::new(&url).unwrap();
    if !c.capabilities().await.unwrap().features.email_verification {
        return;
    }
    let val = email("verify");
    assert!(matches!(
        c.register(&register_req(&val, 7)).await,
        Err(Error::Api { status: 400, ref code, .. }) if code == "email_code_required"
    ));
    c.start_registration(&val).await.unwrap();
    c.start_registration(&val).await.unwrap();
    let guess = RegisterRequest {
        email_code: Some("abcdef".into()),
        accepted_terms: None,
        ..register_req(&val, 7)
    };
    assert!(matches!(
        c.register(&guess).await,
        Err(Error::Api { status: 400, ref code, .. }) if code == "invalid_code"
    ));
}
