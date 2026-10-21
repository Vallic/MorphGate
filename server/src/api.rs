//! HTTP handlers for `vault-sync/v1`.

use std::collections::HashMap;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use hmac::{Hmac, KeyInit, Mac};
use mg_sync::*;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;

use crate::AppState;
use crate::auth::{self, Caller, Refresh};
use crate::util::{Fail, now, valid_id};
use crate::{approvals, blobs, export, scim, sharing, sso};

const MAX_ENVELOPE: usize = 64 * 1024;
const MAX_PUSH: usize = 500;
const DEFAULT_PAGE: u32 = 500;
const MAX_PAGE: u32 = 1000;
pub(crate) const RECOVERY_DEVICE: &str = "recovery";

pub(crate) type R<T> = Result<Json<T>, Fail>;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/vault-sync", get(capabilities))
        .route("/v1/auth/prelogin", post(prelogin))
        .route("/v1/auth/register", post(register))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/refresh", post(refresh))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/account", get(get_account).delete(delete_account))
        .route("/v1/account/export", get(export::export))
        .route("/v1/account/keys", put(rotate_keys))
        .route("/v1/account/recover", post(recover))
        .route("/v1/devices", get(list_devices))
        .route(
            "/v1/devices/{id}",
            patch(update_device).delete(revoke_device),
        )
        .route("/v1/vaults", get(list_vaults).post(create_vault))
        .route("/v1/vaults/{id}", get(get_vault).delete(delete_vault))
        .route("/v1/vaults/{id}/changes", get(pull).post(push))
        .route("/v1/vaults/{id}/members", get(sharing::vault_members))
        .route(
            "/v1/vaults/{id}/members/{account}",
            put(sharing::set_vault_member).delete(sharing::revoke_vault_member),
        )
        .route("/v1/vaults/{id}/keys", post(sharing::rotate_vault_key))
        .route("/v1/vaults/{id}/blobs", get(blobs::list))
        .route(
            "/v1/vaults/{id}/blobs/{hash}",
            get(blobs::get).put(blobs::put).delete(blobs::delete),
        )
        .route(
            "/v1/orgs",
            get(sharing::list_orgs).post(sharing::create_org),
        )
        .route(
            "/v1/orgs/{org}",
            get(sharing::get_org)
                .patch(sharing::update_org)
                .delete(sharing::delete_org),
        )
        .route("/v1/orgs/{org}/members", get(sharing::list_members))
        .route(
            "/v1/orgs/{org}/members/{account}",
            patch(sharing::update_member).delete(sharing::remove_member),
        )
        .route(
            "/v1/orgs/{org}/members/{account}/confirm",
            post(sharing::confirm_member),
        )
        .route(
            "/v1/orgs/{org}/invites",
            get(sharing::list_invites).post(sharing::create_invite),
        )
        .route(
            "/v1/orgs/{org}/invites/{invite}",
            delete(sharing::cancel_invite),
        )
        .route("/v1/orgs/{org}/transfer", post(sharing::transfer_org))
        .route(
            "/v1/orgs/{org}/members/{member}/certificate",
            put(sharing::recertify_member),
        )
        .route("/v1/orgs/{org}/devices", get(approvals::list))
        .route(
            "/v1/orgs/{org}/members/{member}/devices/{device}/approve",
            post(approvals::approve),
        )
        .route(
            "/v1/orgs/{org}/members/{member}/devices/{device}/deny",
            post(approvals::deny),
        )
        .route("/v1/orgs/{org}/sso", get(sso::status))
        .route("/v1/orgs/{org}/sso/start", post(sso::start))
        .route("/sso/callback", get(sso::callback))
        .route("/v1/orgs/{org}/events", get(sharing::org_events))
        .route("/v1/orgs/{org}/events/export", get(crate::events::export))
        .route("/v1/invites/{token}", get(sharing::invite_info))
        .route("/v1/invites/{token}/accept", post(sharing::accept_invite))
        // SCIM 2.0 provisioning, outside vault-sync/v1.
        .merge(scim::routes())
        // 500 envelopes of 64 KiB, base64-inflated.
        .layer(DefaultBodyLimit::max(48 * 1024 * 1024))
        .with_state(state)
}

impl AppState {
    pub(crate) fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, Fail> {
        self.db.lock().map_err(|_| {
            Fail::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "database lock poisoned",
            )
        })
    }
}

/// Runs Argon2 work (and the DB access that goes with it) off the async runtime.
pub(crate) async fn blocking<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce(&AppState) -> Result<T, Fail> + Send + 'static,
) -> Result<T, Fail> {
    let st = state.clone();
    tokio::task::spawn_blocking(move || f(&st))
        .await
        .map_err(|_| {
            Fail::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "worker failed",
            )
        })?
}

// ------------------------------------------------------------------ validation

fn check_kdf(k: &KdfParams) -> Result<(), Fail> {
    if k.alg != "argon2id"
        || k.m_kib < 65_536
        || k.t < 2
        || !(1..=16).contains(&k.p)
        || k.salt.0.len() < 16
    {
        return Err(Fail::bad(
            "KDF parameters are below the vault-sync/v1 minimums",
        ));
    }
    Ok(())
}

fn check_keys(k: &AccountKeys) -> Result<(), Fail> {
    if k.enc_public_key.0.len() != 32
        || k.sign_public_key.0.len() != 32
        || !(1..=1024).contains(&k.wrapped_private_keys.0.len())
    {
        return Err(Fail::bad("malformed account keys"));
    }
    Ok(())
}

fn check_device(d: &DeviceInfo) -> Result<(), Fail> {
    if !valid_id(&d.id)
        || d.name.is_empty()
        || d.name.chars().count() > 100
        || d.platform.len() > 20
        || d.public_key.0.len() != 32
    {
        return Err(Fail::bad("malformed device"));
    }
    Ok(())
}

pub(crate) fn check_email(e: &str) -> Result<String, Fail> {
    let e = e.trim().to_owned();
    if e.len() > 254 || !e.contains('@') || e.starts_with('@') || e.ends_with('@') {
        return Err(Fail::bad("invalid email"));
    }
    Ok(e)
}

// ------------------------------------------------------------------ discovery & auth

async fn capabilities(State(s): State<AppState>) -> Json<Capabilities> {
    Json(Capabilities {
        spec: SPEC.into(),
        versions: vec![VERSION.into()],
        server: Some(ServerInfo {
            name: "vault-sync-reference".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }),
        limits: Limits {
            max_envelope_bytes: MAX_ENVELOPE as u32,
            max_push_items: MAX_PUSH as u32,
            max_items_per_vault: None,
            tombstone_retention_days: 90,
        },
        features: Features {
            registration_open: s.config.registration_open,
            terms: None,
            email_verification: false,
            sse: false,
            totp: false,
            billing: None,
            sharing: Some(Sharing {
                max_members_per_org: 0,
                max_vaults_per_org: 0,
                mails_invites: false,
            }),
            blobs: Some(BlobFeatures {
                max_blob_bytes: s.config.max_blob_bytes,
                quota_bytes: s.config.blob_quota_bytes,
                kinds: blobs::KINDS.iter().map(|k| (*k).into()).collect(),
            }),
            sso: Some(SsoFeatures {
                protocols: vec!["oidc".into()],
            }),
            signed_tombstones: true,
        },
    })
}

fn kdf_of(db: &Connection, email: &str) -> rusqlite::Result<Option<KdfParams>> {
    db.query_row(
        "SELECT kdf_m_kib, kdf_t, kdf_p, kdf_salt FROM accounts WHERE email = ?1",
        [email],
        |r| {
            Ok(KdfParams {
                alg: "argon2id".into(),
                m_kib: r.get(0)?,
                t: r.get(1)?,
                p: r.get(2)?,
                salt: B64(r.get(3)?),
            })
        },
    )
    .optional()
}

/// Unknown emails get stable, plausible parameters so accounts cannot be enumerated.
async fn prelogin(State(s): State<AppState>, Json(req): Json<PreloginRequest>) -> R<KdfParams> {
    let email = check_email(&req.email)?;
    if let Some(k) = kdf_of(&*s.conn()?, &email)? {
        return Ok(Json(k));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&s.secret).expect("any key length");
    mac.update(b"prelogin|");
    mac.update(email.to_lowercase().as_bytes());
    let salt = mac.finalize().into_bytes()[..16].to_vec();
    Ok(Json(KdfParams {
        alg: "argon2id".into(),
        m_kib: 262_144,
        t: 3,
        p: 1,
        salt: B64(salt),
    }))
}

fn upsert_device(db: &Connection, account: &str, d: &DeviceInfo) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO devices (id, account_id, name, platform, client_version, public_key, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT (account_id, id) DO UPDATE SET name = excluded.name, platform = excluded.platform,
             client_version = excluded.client_version, last_seen_at = excluded.last_seen_at, revoked = 0",
        params![d.id, account, d.name, d.platform, d.client_version, d.public_key.0, now()],
    )?;
    Ok(())
}

fn account_keys(db: &Connection, account: &str) -> rusqlite::Result<AccountKeys> {
    db.query_row(
        "SELECT enc_pub, sign_pub, wrapped FROM accounts WHERE id = ?1",
        [account],
        |r| {
            Ok(AccountKeys {
                enc_public_key: B64(r.get(0)?),
                sign_public_key: B64(r.get(1)?),
                wrapped_private_keys: B64(r.get(2)?),
            })
        },
    )
}

async fn register(
    State(s): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Session>), Fail> {
    if !s.config.registration_open {
        return Err(Fail::new(
            StatusCode::FORBIDDEN,
            "registration_closed",
            "this server does not accept new accounts",
        ));
    }
    let email = check_email(&req.email)?;
    check_kdf(&req.kdf)?;
    check_keys(&req.keys)?;
    check_device(&req.device)?;
    if req.auth_key.0.len() != 32
        || req.recovery.recovery_proof.0.len() != 32
        || req.recovery.wrapped_private_keys_rk.0.is_empty()
    {
        return Err(Fail::bad("malformed credentials"));
    }
    let session = blocking(&s, move |s| {
        let auth_hash = auth::hash_secret(&req.auth_key.0);
        let recovery_hash = auth::hash_secret(&req.recovery.recovery_proof.0);
        let mut db = s.conn()?;
        let tx = db.transaction()?;
        let exists: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM accounts WHERE email = ?1)", [&email], |r| r.get(0))?;
        if exists {
            return Err(Fail::new(StatusCode::CONFLICT, "account_exists", "an account with this email already exists"));
        }
        let id = ulid::Ulid::generate().to_string();
        tx.execute(
            "INSERT INTO accounts (id, email, kdf_m_kib, kdf_t, kdf_p, kdf_salt, auth_hash, enc_pub, sign_pub, wrapped,
                                   wrapped_rk, recovery_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                id,
                email,
                req.kdf.m_kib,
                req.kdf.t,
                req.kdf.p,
                req.kdf.salt.0,
                auth_hash,
                req.keys.enc_public_key.0,
                req.keys.sign_public_key.0,
                req.keys.wrapped_private_keys.0,
                req.recovery.wrapped_private_keys_rk.0,
                recovery_hash,
                now()
            ],
        )?;
        upsert_device(&tx, &id, &req.device)?;
        let tokens = auth::issue(&tx, &id, &req.device.id, "full")?;
        tx.commit()?;
        Ok(Session { tokens, account_id: id, keys: req.keys })
    })
    .await?;
    tracing::info!(account = %session.account_id, "account registered");
    Ok((StatusCode::CREATED, Json(session)))
}

async fn login(State(s): State<AppState>, Json(req): Json<LoginRequest>) -> R<Session> {
    let email = check_email(&req.email)?;
    check_device(&req.device)?;
    blocking(&s, move |s| {
        let row: Option<(String, String)> = s
            .conn()?
            .query_row(
                "SELECT id, auth_hash FROM accounts WHERE email = ?1",
                [&email],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((id, hash)) = row else {
            auth::burn_verify(&req.auth_key.0);
            return Err(Fail::unauthorized());
        };
        if !auth::verify_secret(&req.auth_key.0, &hash) {
            return Err(Fail::unauthorized());
        }
        let db = s.conn()?;
        upsert_device(&db, &id, &req.device)?;
        let tokens = auth::issue(&db, &id, &req.device.id, "full")?;
        Ok(Json(Session {
            tokens,
            keys: account_keys(&db, &id)?,
            account_id: id,
        }))
    })
    .await
}

async fn refresh(State(s): State<AppState>, Json(req): Json<RefreshRequest>) -> R<Tokens> {
    match auth::rotate(&*s.conn()?, &req.refresh_token)? {
        Refresh::Rotated(t) => Ok(Json(t)),
        Refresh::Invalid => Err(Fail::unauthorized()),
        Refresh::SignedOut => Err(Fail::new(
            StatusCode::UNAUTHORIZED,
            "device_revoked",
            "this device was signed out of the account",
        )),
        Refresh::AccountDeleted => Err(Fail::new(
            StatusCode::UNAUTHORIZED,
            "account_deleted",
            "the account was deleted",
        )),
        Refresh::Reused => {
            tracing::warn!("refresh token reuse detected; device revoked");
            Err(Fail::unauthorized())
        }
    }
}

async fn logout(State(s): State<AppState>, c: Caller) -> Result<StatusCode, Fail> {
    auth::revoke_device(&*s.conn()?, &c.account, &c.device)?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ account

async fn get_account(State(s): State<AppState>, c: Caller) -> R<Account> {
    require_full(&c)?;
    let db = s.conn()?;
    let (email, kdf_m, kdf_t, kdf_p, salt, wrapped_rk): (String, u32, u32, u32, Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT email, kdf_m_kib, kdf_t, kdf_p, kdf_salt, wrapped_rk FROM accounts WHERE id = ?1",
        [&c.account],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
    )?;
    Ok(Json(Account {
        keys: account_keys(&db, &c.account)?,
        id: c.account,
        email,
        kdf: KdfParams {
            alg: "argon2id".into(),
            m_kib: kdf_m,
            t: kdf_t,
            p: kdf_p,
            salt: B64(salt),
        },
        wrapped_private_keys_rk: Some(B64(wrapped_rk)),
        totp_enabled: false,
        email_verified: None,
        entitlement: None,
        terms: None,
    }))
}

async fn delete_account(
    State(s): State<AppState>,
    c: Caller,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<StatusCode, Fail> {
    blocking(&s, move |s| {
        let hash: String = s.conn()?.query_row(
            "SELECT auth_hash FROM accounts WHERE id = ?1",
            [&c.account],
            |r| r.get(0),
        )?;
        if !auth::verify_secret(&req.auth_key.0, &hash) {
            return Err(Fail::unauthorized());
        }
        let mut db = s.conn()?;
        let tx = db.transaction()?;
        sharing::leave_all(&tx, &c.account)?;
        // The account's other devices hear that it was deleted, not that their session ran out.
        tx.execute(
            "INSERT OR IGNORE INTO deleted_tokens (hash, code, expires_at)
             SELECT hash, CASE kind WHEN 'revoked' THEN 'device_revoked' ELSE 'account_deleted' END, expires_at
             FROM tokens WHERE account_id = ?1 AND kind IN ('refresh', 'revoked') AND used = 0",
            [&c.account],
        )?;
        tx.execute("DELETE FROM accounts WHERE id = ?1", [&c.account])?;
        tx.commit()?;
        tracing::info!(account = %c.account, "account deleted");
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// Password change, or the second half of recovery (with a `recover`-scoped token).
async fn rotate_keys(
    State(s): State<AppState>,
    c: Caller,
    Json(req): Json<RotateCredentialsRequest>,
) -> Result<StatusCode, Fail> {
    check_kdf(&req.new_kdf)?;
    if req.new_auth_key.0.len() != 32 || !(1..=1024).contains(&req.wrapped_private_keys.0.len()) {
        return Err(Fail::bad("malformed credentials"));
    }
    blocking(&s, move |s| {
        let hash: String = s.conn()?.query_row("SELECT auth_hash FROM accounts WHERE id = ?1", [&c.account], |r| r.get(0))?;
        let recovering = c.scope == "recover";
        if !recovering {
            let current = req.current_auth_key.as_ref().ok_or_else(Fail::unauthorized)?;
            if !auth::verify_secret(&current.0, &hash) {
                return Err(Fail::unauthorized());
            }
        }
        // A new recovery key alone keeps the password: nobody needs to sign in again.
        let password_changed = recovering || !auth::verify_secret(&req.new_auth_key.0, &hash);
        let auth_hash = auth::hash_secret(&req.new_auth_key.0);
        let recovery = req.recovery.as_ref().map(|r| (r.wrapped_private_keys_rk.0.clone(), auth::hash_secret(&r.recovery_proof.0)));
        let mut db = s.conn()?;
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE accounts SET kdf_m_kib = ?2, kdf_t = ?3, kdf_p = ?4, kdf_salt = ?5, auth_hash = ?6, wrapped = ?7 WHERE id = ?1",
            params![c.account, req.new_kdf.m_kib, req.new_kdf.t, req.new_kdf.p, req.new_kdf.salt.0, auth_hash, req.wrapped_private_keys.0],
        )?;
        if let Some((wrapped_rk, recovery_hash)) = recovery {
            tx.execute("UPDATE accounts SET wrapped_rk = ?2, recovery_hash = ?3 WHERE id = ?1", params![c.account, wrapped_rk, recovery_hash])?;
        }
        if password_changed {
            // Other devices must sign in again with the new password. After a recovery that is
            // every device; the recovery token itself is single-use.
            tx.execute("DELETE FROM tokens WHERE account_id = ?1 AND device_id != ?2", params![c.account, c.device])?;
        }
        if recovering {
            tx.execute("DELETE FROM tokens WHERE account_id = ?1 AND device_id = ?2", params![c.account, c.device])?;
        }
        tx.commit()?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

async fn recover(State(s): State<AppState>, Json(req): Json<RecoverRequest>) -> R<RecoverResponse> {
    let email = check_email(&req.email)?;
    blocking(&s, move |s| {
        let row: Option<(String, String, Vec<u8>)> = s
            .conn()?
            .query_row("SELECT id, recovery_hash, wrapped_rk FROM accounts WHERE email = ?1", [&email], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        let Some((id, hash, wrapped_rk)) = row else {
            auth::burn_verify(&req.recovery_proof.0);
            return Err(Fail::unauthorized());
        };
        if !auth::verify_secret(&req.recovery_proof.0, &hash) {
            return Err(Fail::unauthorized());
        }
        let db = s.conn()?;
        db.execute(
            "INSERT INTO devices (id, account_id, name, platform, public_key, created_at) VALUES (?1, ?2, 'Account recovery', 'unknown', x'', ?3)
             ON CONFLICT (account_id, id) DO UPDATE SET revoked = 0",
            params![RECOVERY_DEVICE, id, now()],
        )?;
        let access_token = auth::issue_access(&db, &id, RECOVERY_DEVICE, "recover")?;
        Ok(Json(RecoverResponse { wrapped_private_keys_rk: B64(wrapped_rk), access_token }))
    })
    .await
}

pub(crate) fn require_full(c: &Caller) -> Result<(), Fail> {
    if c.scope == "full" {
        Ok(())
    } else {
        Err(Fail::unauthorized())
    }
}

// ------------------------------------------------------------------ devices

async fn list_devices(State(s): State<AppState>, c: Caller) -> R<Vec<Device>> {
    require_full(&c)?;
    let db = s.conn()?;
    let mut stmt = db.prepare(
        "SELECT id, name, platform, client_version, public_key, created_at, last_seen_at FROM devices
         WHERE account_id = ?1 AND revoked = 0 AND id != ?2 ORDER BY created_at",
    )?;
    let devices = stmt
        .query_map(params![c.account, RECOVERY_DEVICE], |r| {
            let id: String = r.get(0)?;
            Ok(Device {
                current: id == c.device,
                info: DeviceInfo {
                    id,
                    name: r.get(1)?,
                    platform: r.get(2)?,
                    client_version: r.get(3)?,
                    public_key: B64(r.get(4)?),
                },
                created_at: r.get(5)?,
                last_seen_at: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(devices))
}

/// The calling device says what it is now (an app update, a renamed computer).
async fn update_device(
    State(s): State<AppState>,
    c: Caller,
    Path(id): Path<String>,
    Json(u): Json<DeviceUpdate>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    if id != c.device {
        return Err(Fail::new(
            StatusCode::FORBIDDEN,
            "not_permitted",
            "a device updates only itself",
        ));
    }
    if u.name.trim().is_empty()
        || u.name.chars().count() > 100
        || u.platform.is_empty()
        || u.platform.len() > 20
        || u.client_version.as_ref().is_some_and(|v| v.len() > 64)
    {
        return Err(Fail::bad("malformed device"));
    }
    let db = s.conn()?;
    let n = db.execute(
        "UPDATE devices SET name = ?3, platform = ?4, client_version = ?5
         WHERE account_id = ?1 AND id = ?2 AND revoked = 0",
        params![c.account, id, u.name, u.platform, u.client_version],
    )?;
    if n == 0 {
        return Err(Fail::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_device(
    State(s): State<AppState>,
    c: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    let db = s.conn()?;
    let n = db.execute(
        "UPDATE devices SET revoked = 1 WHERE account_id = ?1 AND id = ?2",
        params![c.account, id],
    )?;
    if n == 0 {
        return Err(Fail::not_found());
    }
    auth::sign_out_device(&db, &c.account, &id)?;
    approvals::forget_device(&db, &c.account, Some(&id))?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ vaults

/// A vault as the caller sees it: their permission and their copies of its keys.
pub(crate) fn vault_view(db: &Connection, account: &str, id: &str) -> Result<Vault, Fail> {
    let access = sharing::vault_access(db, account, id)?.ok_or_else(Fail::not_found)?;
    let row = db.query_row(
        "SELECT v.key_id, v.meta, v.head_rev,
                (SELECT COUNT(*) FROM items i WHERE i.vault_id = v.id AND i.deleted = 0),
                v.created_at, v.created_by, v.rotation_due,
                (SELECT COUNT(*) FROM items i WHERE i.vault_id = v.id AND i.deleted = 0
                    AND i.key_id IS NOT NULL AND i.key_id != v.key_id)
         FROM vaults v WHERE v.id = ?1",
        [id],
        |r| {
            Ok(VaultRow {
                key_id: r.get(0)?,
                meta: r.get(1)?,
                head_rev: r.get(2)?,
                item_count: r.get(3)?,
                created_at: r.get(4)?,
                created_by: r.get(5)?,
                rotation_due: r.get(6)?,
                items_on_old_keys: r.get(7)?,
            })
        },
    )?;
    let mut stmt = db.prepare(
        "SELECT key_id, wrapped, signer_id, sig, created_at FROM vault_keys
         WHERE vault_id = ?1 AND account_id = ?2 ORDER BY created_at, rowid",
    )?;
    let keys = stmt
        .query_map(params![id, account], |r| {
            let signer: Option<String> = r.get(2)?;
            let sig: Option<Vec<u8>> = r.get(3)?;
            Ok(KeyGeneration {
                key_id: B64(r.get(0)?),
                wrapped_vault_key: B64(r.get(1)?),
                grant: signer.zip(sig).map(|(signer_id, sig)| Signed {
                    signer_id,
                    sig: B64(sig),
                }),
                created_at: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let wrapped_vault_key = keys
        .iter()
        .find(|k| k.key_id.0 == row.key_id)
        .map(|k| k.wrapped_vault_key.clone())
        .unwrap_or_default();
    Ok(Vault {
        id: id.to_owned(),
        key_id: B64(row.key_id),
        wrapped_vault_key,
        meta: row.meta.map(B64),
        head_rev: row.head_rev,
        item_count: Some(row.item_count),
        created_at: row.created_at,
        org_id: access.org_id,
        created_by: row.created_by,
        permission: Some(access.permission),
        keys,
        rotation_due: row.rotation_due,
        items_on_old_keys: Some(row.items_on_old_keys),
    })
}

struct VaultRow {
    key_id: Vec<u8>,
    meta: Option<Vec<u8>>,
    head_rev: i64,
    item_count: i64,
    created_at: String,
    created_by: Option<String>,
    rotation_due: bool,
    items_on_old_keys: i64,
}

async fn list_vaults(State(s): State<AppState>, c: Caller) -> R<Vec<Vault>> {
    require_full(&c)?;
    let db = s.conn()?;
    let mut stmt = db.prepare(
        "SELECT id FROM vaults
         WHERE (org_id IS NULL AND account_id = ?1)
            OR org_id IN (SELECT org_id FROM members WHERE account_id = ?1 AND status = 'confirmed')
         ORDER BY created_at, id",
    )?;
    let ids = stmt
        .query_map([&c.account], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut vaults = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(access) = sharing::vault_access(&db, &c.account, &id)? else {
            continue;
        };
        // Vaults behind single sign-on stay out of the list until this device signs in, and
        // with device approval until the organization approves it (asking files the request).
        if let Some(org) = &access.org_id
            && (!crate::sso::open(&db, org, &c)? || approvals::gate(&db, org, &c).is_err())
        {
            continue;
        }
        vaults.push(vault_view(&db, &c.account, &id)?);
    }
    Ok(Json(vaults))
}

async fn create_vault(
    State(s): State<AppState>,
    c: Caller,
    Json(req): Json<CreateVault>,
) -> Result<(StatusCode, Json<Vault>), Fail> {
    require_full(&c)?;
    if !valid_id(&req.id)
        || req.key_id.0.len() != 16
        || req.wrapped_vault_key.0.is_empty()
        || req.wrapped_vault_key.0.len() > 1024
        || req.meta.as_ref().is_some_and(|m| m.0.len() > MAX_ENVELOPE)
    {
        return Err(Fail::bad("malformed vault"));
    }
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM vaults WHERE id = ?1)",
        [&req.id],
        |r| r.get(0),
    )?;
    if exists {
        return Err(Fail::new(
            StatusCode::CONFLICT,
            "vault_exists",
            "vault id already in use",
        ));
    }
    match &req.org_id {
        Some(org) => sharing::create_org_vault(&tx, &c, org, &req)?,
        None => {
            if !req.keys.is_empty() {
                return Err(Fail::bad(
                    "a personal vault's key is sealed to its owner only",
                ));
            }
            let stamp = now();
            tx.execute(
                "INSERT INTO vaults (id, account_id, key_id, wrapped_vault_key, meta, created_at, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?2)",
                params![req.id, c.account, req.key_id.0, req.wrapped_vault_key.0, req.meta.as_ref().map(|m| m.0.clone()), stamp],
            )?;
            tx.execute(
                "INSERT INTO vault_keys (vault_id, key_id, account_id, wrapped, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![req.id, req.key_id.0, c.account, req.wrapped_vault_key.0, stamp],
            )?;
        }
    }
    let vault = vault_view(&tx, &c.account, &req.id)?;
    tx.commit()?;
    Ok((StatusCode::CREATED, Json(vault)))
}

async fn get_vault(State(s): State<AppState>, c: Caller, Path(id): Path<String>) -> R<Vault> {
    require_full(&c)?;
    let db = s.conn()?;
    sharing::require_vault(&db, &c, &id, Permission::Read)?;
    Ok(Json(vault_view(&db, &c.account, &id)?))
}

/// The owner deletes a personal vault; an organization's owners and admins delete its vaults.
async fn delete_vault(
    State(s): State<AppState>,
    c: Caller,
    Path(id): Path<String>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    let db = s.conn()?;
    let access = sharing::require_vault(&db, &c, &id, Permission::Manage)?;
    if let Some(org) = &access.org_id {
        if !sharing::is_org_admin(&db, org, &c.account)? {
            return Err(sharing::not_permitted(
                "only owners and admins delete organization vaults",
            ));
        }
        sharing::event(
            &db,
            org,
            "vault_deleted",
            Some(&c.account),
            None,
            Some(&id),
            None,
        )?;
    }
    db.execute("DELETE FROM vaults WHERE id = ?1", [&id])?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ sync

async fn pull(
    State(s): State<AppState>,
    c: Caller,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> R<ChangePage> {
    require_full(&c)?;
    let since: i64 = q
        .get("since")
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 0)
        .ok_or_else(|| Fail::bad("since is required"))?;
    let limit: u32 = q
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PAGE)
        .clamp(1, MAX_PAGE);
    let db = s.conn()?;
    sharing::require_vault(&db, &c, &id, Permission::Read)?;
    let head_rev: i64 = db.query_row("SELECT head_rev FROM vaults WHERE id = ?1", [&id], |r| {
        r.get(0)
    })?;
    let mut stmt = db.prepare(
        "SELECT id, rev, deleted, device_id, envelope, updated_at, author_id FROM items
         WHERE vault_id = ?1 AND rev > ?2 ORDER BY rev LIMIT ?3",
    )?;
    let mut items = stmt
        .query_map(params![id, since, limit + 1], |r| {
            Ok(Item {
                id: r.get(0)?,
                rev: r.get(1)?,
                deleted: r.get(2)?,
                device_id: r.get(3)?,
                envelope: r.get::<_, Option<Vec<u8>>>(4)?.map(B64),
                updated_at: r.get(5)?,
                author_id: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = items.len() > limit as usize;
    items.truncate(limit as usize);
    Ok(Json(ChangePage {
        items,
        head_rev,
        has_more,
    }))
}

async fn push(
    State(s): State<AppState>,
    c: Caller,
    Path(id): Path<String>,
    Json(req): Json<PushRequest>,
) -> R<PushResponse> {
    require_full(&c)?;
    if req.items.is_empty() {
        return Err(Fail::bad("no items"));
    }
    if req.items.len() > MAX_PUSH {
        return Err(Fail::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            format!("at most {MAX_PUSH} items per push"),
        ));
    }
    let mut db = s.conn()?;
    let tx = db.transaction()?;
    sharing::require_vault(&tx, &c, &id, Permission::Write)?;
    let (mut head, current_key): (i64, Vec<u8>) = tx.query_row(
        "SELECT head_rev, key_id FROM vaults WHERE id = ?1",
        [&id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut results = Vec::with_capacity(req.items.len());
    let stamp = now();
    for item in req.items {
        let reject = |code: &str, msg: &str| PushResult {
            id: item.id.clone(),
            status: PushStatus::Rejected,
            rev: None,
            current: None,
            error: Some(ApiError::new(code, msg)),
        };
        if !valid_id(&item.id) {
            results.push(reject("bad_request", "item id must be a ULID"));
            continue;
        }
        // A deletion may carry its author's signed deletion: kept and returned with it.
        let envelope = item.envelope.map(|e| e.0);
        match &envelope {
            None if !item.deleted => {
                results.push(reject("bad_request", "envelope required"));
                continue;
            }
            Some(e) if item.deleted && e.len() > MAX_DELETION_ENVELOPE => {
                results.push(reject(
                    "too_large",
                    "a deletion's envelope is at most 1024 bytes",
                ));
                continue;
            }
            Some(e) if e.len() > MAX_ENVELOPE => {
                results.push(reject("too_large", "envelope exceeds max_envelope_bytes"));
                continue;
            }
            // The clear header names the key generation: `version(1) ‖ key_id(16)`.
            Some(e) if e.len() < 17 => {
                results.push(reject("bad_request", "envelope too short"));
                continue;
            }
            // A deletion carries no secret: any key generation the vault had will do.
            Some(e) if !item.deleted && e[1..17] != current_key[..] => {
                results.push(reject(
                    "stale_key",
                    "the vault has a newer key: re-encrypt and push again",
                ));
                continue;
            }
            _ => {}
        }
        let current: Option<Item> = tx
            .query_row(
                "SELECT id, rev, deleted, device_id, envelope, updated_at, author_id FROM items WHERE vault_id = ?1 AND id = ?2",
                params![id, item.id],
                |r| {
                    Ok(Item {
                        id: r.get(0)?,
                        rev: r.get(1)?,
                        deleted: r.get(2)?,
                        device_id: r.get(3)?,
                        envelope: r.get::<_, Option<Vec<u8>>>(4)?.map(B64),
                        updated_at: r.get(5)?,
                        author_id: r.get(6)?,
                    })
                },
            )
            .optional()?;
        // A deletion's envelope only for an item the server has: for one it never had, it would
        // take room that no quota counts.
        let envelope = envelope.filter(|_| !(item.deleted && current.is_none()));
        if let Some(cur) = current.filter(|cur| cur.rev != item.base_rev) {
            results.push(PushResult {
                id: item.id,
                status: PushStatus::Conflict,
                rev: None,
                current: Some(cur),
                error: None,
            });
            continue;
        }
        head += 1;
        let key_id = envelope
            .as_ref()
            .filter(|_| !item.deleted)
            .map(|e| e[1..17].to_vec());
        tx.execute(
            "INSERT INTO items (vault_id, id, rev, deleted, device_id, envelope, updated_at, author_id, key_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (vault_id, id) DO UPDATE SET rev = excluded.rev, deleted = excluded.deleted,
                 device_id = excluded.device_id, envelope = excluded.envelope, updated_at = excluded.updated_at,
                 author_id = excluded.author_id, key_id = excluded.key_id",
            params![id, item.id, head, item.deleted, c.device, envelope, stamp, c.account, key_id],
        )?;
        results.push(PushResult {
            id: item.id,
            status: PushStatus::Accepted,
            rev: Some(head),
            current: None,
            error: None,
        });
    }
    tx.execute(
        "UPDATE vaults SET head_rev = ?2 WHERE id = ?1",
        params![id, head],
    )?;
    tx.commit()?;
    Ok(Json(PushResponse {
        results,
        head_rev: head,
    }))
}
