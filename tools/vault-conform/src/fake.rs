//! Placeholder key material: right sizes and shapes, no real cryptography (servers never check
//! it). Each account's `AuthKey` is 32 bytes of one value, so tests can tell them apart.

use mg_sync::{
    AccountKeys, B64, CreateVault, DeviceInfo, KdfParams, LoginRequest, PushItem, RecoveryMaterial,
    RegisterRequest, Session, SyncClient,
};

use crate::Ctx;

pub fn bytes(n: usize, fill: u8) -> B64 {
    B64(vec![fill; n])
}

/// An envelope-shaped value: servers read the key generation from its clear header
/// (`version ‖ key_id`), here the placeholder key `[1; 16]`.
pub fn envelope(fill: u8) -> B64 {
    let mut e = vec![1u8; 17];
    e.resize(300, fill);
    B64(e)
}

pub fn ulid() -> String {
    ulid::Ulid::generate().to_string()
}

pub fn device() -> DeviceInfo {
    DeviceInfo {
        id: ulid(),
        name: "vault-conform".into(),
        platform: "linux".into(),
        client_version: Some(env!("CARGO_PKG_VERSION").into()),
        public_key: bytes(32, 9),
    }
}

pub fn kdf() -> KdfParams {
    KdfParams {
        alg: "argon2id".into(),
        m_kib: 65_536,
        t: 2,
        p: 1,
        salt: bytes(16, 1),
    }
}

pub fn register_req(email: &str, auth: u8) -> RegisterRequest {
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

pub fn login_req(email: &str, auth: u8) -> LoginRequest {
    LoginRequest {
        email: email.into(),
        auth_key: bytes(32, auth),
        totp: None,
        device: device(),
    }
}

pub fn put(id: &str, base_rev: i64, fill: u8) -> PushItem {
    PushItem {
        id: id.into(),
        base_rev,
        deleted: false,
        envelope: Some(envelope(fill)),
    }
}

pub fn vault_req(id: &str) -> CreateVault {
    CreateVault {
        id: id.into(),
        key_id: bytes(16, 1),
        wrapped_vault_key: bytes(105, 2),
        meta: None,
        org_id: None,
        keys: Vec::new(),
    }
}

/// A new account (placeholder keys, `AuthKey` all `auth`) and its signed-in client.
pub async fn account(
    ctx: &Ctx,
    name: &str,
    auth: u8,
) -> Result<(SyncClient, String, Session), String> {
    let email = ctx.email(name);
    let c = ctx.client()?;
    let req = RegisterRequest {
        email_code: ctx.registration_code(&c, &email).await?,
        // A server with terms asks new accounts to accept them.
        accepted_terms: ctx
            .caps
            .as_ref()
            .and_then(|caps| caps.features.terms.as_ref())
            .map(|t| t.version.clone()),
        ..register_req(&email, auth)
    };
    let s = c
        .register(&req)
        .await
        .map_err(|e| format!("registering {email}: {e}"))?;
    Ok((c, email, s))
}

/// The client's current access token, for raw requests.
pub fn token(c: &SyncClient) -> Result<String, String> {
    c.tokens()
        .map(|t| t.access_token)
        .ok_or_else(|| "the client has no session".into())
}
