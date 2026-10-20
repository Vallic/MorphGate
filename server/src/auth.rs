//! Credential hashing and bearer tokens.

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::util::{Fail, now_secs, random};

pub(crate) const ACCESS_TTL: i64 = 15 * 60;
pub(crate) const REFRESH_TTL: i64 = 90 * 24 * 3600;

/// Slow hash for `AuthKey` / recovery proofs (PHC string). The input already went through the
/// client's Argon2id, so this mainly makes a stolen database useless for logging in.
pub(crate) fn hash_secret(secret: &[u8]) -> String {
    Argon2::default()
        .hash_password(secret)
        .expect("argon2 hashing")
        .to_string()
}

pub(crate) fn verify_secret(secret: &[u8], phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| Argon2::default().verify_password(secret, &h).is_ok())
}

/// Spends comparable time when the account does not exist.
pub(crate) fn burn_verify(secret: &[u8]) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let phc = DUMMY.get_or_init(|| hash_secret(b"dummy"));
    let _ = verify_secret(secret, phc);
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn new_token() -> String {
    URL_SAFE_NO_PAD.encode(random::<32>())
}

/// Issues an access token alone (no way to extend it): for account recovery.
pub(crate) fn issue_access(
    db: &Connection,
    account: &str,
    device: &str,
    scope: &str,
) -> rusqlite::Result<String> {
    let access = new_token();
    db.execute(
        "INSERT INTO tokens (hash, account_id, device_id, kind, scope, expires_at) VALUES (?1, ?2, ?3, 'access', ?4, ?5)",
        params![token_hash(&access), account, device, scope, now_secs() + ACCESS_TTL],
    )?;
    Ok(access)
}

/// Issues an access + refresh pair for a device.
pub(crate) fn issue(
    db: &Connection,
    account: &str,
    device: &str,
    scope: &str,
) -> rusqlite::Result<mg_sync::Tokens> {
    let access = issue_access(db, account, device, scope)?;
    let refresh = new_token();
    let now = now_secs();
    db.execute(
        "INSERT INTO tokens (hash, account_id, device_id, kind, scope, expires_at) VALUES (?1, ?2, ?3, 'refresh', ?4, ?5)",
        params![token_hash(&refresh), account, device, scope, now + REFRESH_TTL],
    )?;
    Ok(mg_sync::Tokens {
        access_token: access,
        refresh_token: refresh,
        expires_in: ACCESS_TTL as u64,
    })
}

pub(crate) fn revoke_device(db: &Connection, account: &str, device: &str) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM tokens WHERE account_id = ?1 AND device_id = ?2",
        params![account, device],
    )?;
    Ok(())
}

/// Signs a device out for its account (from another device, or the account page): its access
/// tokens go, and its refresh tokens stay as `revoked`, so the device learns on its next refresh
/// that it was signed out (`401 device_revoked`) rather than that its session ran out.
pub(crate) fn sign_out_device(
    db: &Connection,
    account: &str,
    device: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM tokens WHERE account_id = ?1 AND device_id = ?2 AND (kind = 'access' OR used = 1)",
        params![account, device],
    )?;
    db.execute(
        "UPDATE tokens SET kind = 'revoked' WHERE account_id = ?1 AND device_id = ?2 AND kind = 'refresh'",
        params![account, device],
    )?;
    Ok(())
}

pub(crate) enum Refresh {
    Rotated(mg_sync::Tokens),
    Invalid,
    /// The account signed the device out ([`sign_out_device`]).
    SignedOut,
    /// The account was deleted (from one of its devices); this token was one of its.
    AccountDeleted,
    /// An already-used refresh token came back: assume theft, revoke the device.
    Reused,
}

pub(crate) fn rotate(db: &Connection, refresh: &str) -> rusqlite::Result<Refresh> {
    let row: Option<(String, String, String, i64, bool, String)> = db
        .query_row(
            "SELECT account_id, device_id, scope, expires_at, used, kind FROM tokens
             WHERE hash = ?1 AND kind IN ('refresh', 'revoked')",
            [token_hash(refresh)],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((account, device, scope, expires_at, used, kind)) = row else {
        let deleted: Option<(String, i64)> = db
            .query_row(
                "SELECT code, expires_at FROM deleted_tokens WHERE hash = ?1",
                [token_hash(refresh)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        return Ok(match deleted {
            Some((code, expires_at)) if expires_at >= now_secs() => {
                if code == "device_revoked" {
                    Refresh::SignedOut
                } else {
                    Refresh::AccountDeleted
                }
            }
            _ => Refresh::Invalid,
        });
    };
    if kind == "revoked" {
        return Ok(Refresh::SignedOut);
    }
    if used {
        revoke_device(db, &account, &device)?;
        crate::approvals::forget_device(db, &account, Some(&device))?;
        db.execute(
            "UPDATE devices SET revoked = 1 WHERE account_id = ?1 AND id = ?2",
            params![account, device],
        )?;
        return Ok(Refresh::Reused);
    }
    if expires_at < now_secs() {
        return Ok(Refresh::Invalid);
    }
    // Keep the used token around (marked) so a replay is recognised as reuse.
    db.execute(
        "UPDATE tokens SET used = 1 WHERE hash = ?1",
        [token_hash(refresh)],
    )?;
    db.execute(
        "DELETE FROM tokens WHERE account_id = ?1 AND device_id = ?2 AND kind = 'access'",
        params![account, device],
    )?;
    Ok(Refresh::Rotated(issue(db, &account, &device, &scope)?))
}

/// An authenticated request: `Authorization: Bearer <access token>`.
pub(crate) struct Caller {
    pub account: String,
    pub device: String,
    pub scope: String,
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = Fail;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(Fail::unauthorized)?
            .trim();
        let db = state
            .db
            .lock()
            .map_err(|_| Fail::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "lock"))?;
        let row: Option<(String, String, String)> = db
            .query_row(
                "SELECT t.account_id, t.device_id, t.scope FROM tokens t
                 JOIN devices d ON d.account_id = t.account_id AND d.id = t.device_id
                 WHERE t.hash = ?1 AND t.kind = 'access' AND t.expires_at >= ?2 AND d.revoked = 0",
                params![token_hash(token), now_secs()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (account, device, scope) = row.ok_or_else(Fail::unauthorized)?;
        db.execute(
            "UPDATE devices SET last_seen_at = ?3 WHERE account_id = ?1 AND id = ?2",
            params![account, device, crate::util::now()],
        )?;
        Ok(Caller {
            account,
            device,
            scope,
        })
    }
}
