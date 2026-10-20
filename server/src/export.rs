//! `GET /v1/account/export`: everything this server keeps about the caller's account, readable
//! (access and portability). Secrets, hashes, wrapped keys and vault contents stay out: the
//! contents are end-to-end encrypted, so only the app can export them.

use axum::Json;
use axum::extract::State;
use mg_sync::B64;
use rusqlite::Connection;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::api::{RECOVERY_DEVICE, require_full};
use crate::auth::Caller;
use crate::util::{Fail, now, now_secs, rfc3339};

pub(crate) const FORMAT: &str = "morphgate-account-export/1";

pub(crate) async fn export(State(s): State<AppState>, c: Caller) -> Result<Json<Value>, Fail> {
    require_full(&c)?;
    let db = s.conn()?;
    Ok(Json(account_export(&db, &c.account)?))
}

/// An object without its nulls ("empty values are left out").
fn object(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .filter(|(_, v)| !v.is_null())
                .collect::<Map<_, _>>(),
        ),
        other => other,
    }
}

fn account_export(db: &Connection, account: &str) -> Result<Value, Fail> {
    let (email, enc_pub, sign_pub, created_at): (String, Vec<u8>, Vec<u8>, String) = db.query_row(
        "SELECT email, enc_pub, sign_pub, created_at FROM accounts WHERE id = ?1",
        [account],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let now_secs = now_secs();
    let rows = |sql: &str,
                p: &[&dyn rusqlite::ToSql],
                f: &dyn Fn(&rusqlite::Row) -> rusqlite::Result<Value>|
     -> Result<Vec<Value>, Fail> {
        let mut stmt = db.prepare(sql)?;
        let out = stmt
            .query_map(p, |r| f(r).map(object))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(out)
    };

    let devices = rows(
        "SELECT id, name, platform, client_version, created_at, last_seen_at, revoked
         FROM devices WHERE account_id = ?1 AND id <> ?2 ORDER BY created_at",
        &[&account, &RECOVERY_DEVICE],
        &|r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "platform": r.get::<_, String>(2)?,
                "client_version": r.get::<_, Option<String>>(3)?,
                "created_at": r.get::<_, String>(4)?,
                "last_seen_at": r.get::<_, Option<String>>(5)?,
                "signed_out": r.get::<_, bool>(6)?,
            }))
        },
    )?;
    let organizations = rows(
        "SELECT m.org_id, o.name, m.role, m.status, m.joined_at
         FROM members m JOIN orgs o ON o.id = m.org_id WHERE m.account_id = ?1 ORDER BY m.joined_at",
        &[&account],
        &|r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "role": r.get::<_, String>(2)?,
                "status": r.get::<_, String>(3)?,
                "joined_at": r.get::<_, String>(4)?,
            }))
        },
    )?;
    let personal = rows(
        "SELECT v.id, v.created_at, v.head_rev,
                (SELECT COUNT(*) FROM items i WHERE i.vault_id = v.id AND i.deleted = 0),
                (SELECT COUNT(*) FROM blobs b WHERE b.vault_id = v.id),
                (SELECT COALESCE(SUM(size), 0) FROM blobs b WHERE b.vault_id = v.id)
         FROM vaults v WHERE v.account_id = ?1 AND v.org_id IS NULL ORDER BY v.created_at",
        &[&account],
        &|r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "created_at": r.get::<_, String>(1)?,
                "revision": r.get::<_, i64>(2)?,
                "items": r.get::<_, i64>(3)?,
                "blobs": r.get::<_, i64>(4)?,
                "blob_bytes": r.get::<_, i64>(5)?,
            }))
        },
    )?;
    let organization_vaults = rows(
        "SELECT vm.vault_id, v.org_id, vm.permission, v.created_by = ?1
         FROM vault_members vm JOIN vaults v ON v.id = vm.vault_id
         WHERE vm.account_id = ?1 AND v.org_id IS NOT NULL ORDER BY v.created_at",
        &[&account],
        &|r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "organization_id": r.get::<_, String>(1)?,
                "permission": r.get::<_, String>(2)?,
                "created_by_you": r.get::<_, Option<bool>>(3)?.unwrap_or(false),
            }))
        },
    )?;
    let invites = rows(
        "SELECT i.org_id, o.name, i.role, i.created_at, i.expires_at
         FROM invites i JOIN orgs o ON o.id = i.org_id
         WHERE i.email = ?1 AND i.closed = 0 AND i.expires_at >= ?2 ORDER BY i.created_at",
        &[&email, &now_secs],
        &|r| {
            Ok(json!({
                "organization_id": r.get::<_, String>(0)?,
                "organization": r.get::<_, String>(1)?,
                "role": r.get::<_, String>(2)?,
                "sent_at": r.get::<_, String>(3)?,
                "expires_at": rfc3339(r.get(4)?),
            }))
        },
    )?;
    let sso_sessions = rows(
        "SELECT org_id, device_id, sub, expires FROM sso_sessions
         WHERE account_id = ?1 AND expires >= ?2 ORDER BY org_id, device_id",
        &[&account, &now_secs],
        &|r| {
            Ok(json!({
                "organization_id": r.get::<_, String>(0)?,
                "device_id": r.get::<_, String>(1)?,
                "identity_provider_subject": r.get::<_, String>(2)?,
                "expires_at": rfc3339(r.get(3)?),
            }))
        },
    )?;
    let activity = rows(
        "SELECT org_id, at, kind, actor_id, target_id, vault_id, detail FROM events
         WHERE actor_id = ?1 OR target_id = ?1 ORDER BY seq",
        &[&account],
        &|r| {
            let actor: Option<String> = r.get(3)?;
            Ok(json!({
                "organization_id": r.get::<_, String>(0)?,
                "at": r.get::<_, String>(1)?,
                "kind": r.get::<_, String>(2)?,
                "by_you": actor.as_deref() == Some(account),
                "actor_id": actor,
                "target_id": r.get::<_, Option<String>>(4)?,
                "vault_id": r.get::<_, Option<String>>(5)?,
                "detail": r.get::<_, Option<String>>(6)?,
            }))
        },
    )?;

    Ok(json!({
        "format": FORMAT,
        "generated_at": now(),
        "about": "Everything this server keeps about your account, except secrets and hashes. \
                  Vault contents are end-to-end encrypted: export them from the MorphGate app.",
        "account": {
            "id": account,
            "email": email,
            "created_at": created_at,
            "two_step_verification": false,
            "public_keys": {
                "enc_public_key": B64(enc_pub),
                "sign_public_key": B64(sign_pub),
            },
        },
        "devices": devices,
        "organizations": organizations,
        "vaults": { "personal": personal, "organization": organization_vaults },
        "invites": invites,
        "sso_sessions": sso_sessions,
        "activity": activity,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_drops_nulls_only() {
        assert_eq!(
            object(json!({"a": 1, "b": null, "c": false, "d": []})),
            json!({"a": 1, "c": false, "d": []})
        );
    }

    #[test]
    fn unknown_account_is_an_error() {
        let mut db = Connection::open_in_memory().unwrap();
        crate::db::init(&mut db).unwrap();
        assert!(account_export(&db, "nobody").is_err());
    }
}
