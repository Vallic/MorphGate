//! Blobs: encrypted session logs and attachments, named by the SHA-256 of their bytes. The
//! server checks the name and the size, never the content.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use mg_sync::{BlobInfo, Permission};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::api::{R, require_full};
use crate::auth::Caller;
use crate::sharing::{self, VaultAccess};
use crate::util::{Fail, now, now_secs, rfc3339};

pub(crate) const KINDS: [&str; 2] = ["attachment", "session_log"];

fn valid_hash(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn info(r: &rusqlite::Row<'_>) -> rusqlite::Result<BlobInfo> {
    Ok(BlobInfo {
        hash: r.get(0)?,
        size: r.get::<_, i64>(1)? as u64,
        kind: r.get(2)?,
        author_id: r.get(3)?,
        created_at: r.get(4)?,
    })
}

/// Bytes stored by everything the vault's owner has: an account's personal vaults, or all of an
/// organization's.
fn used(db: &Connection, vault: &str, access: &VaultAccess) -> rusqlite::Result<u64> {
    let total: i64 = match &access.org_id {
        Some(org) => db.query_row(
            "SELECT COALESCE(SUM(b.size), 0) FROM blobs b JOIN vaults v ON v.id = b.vault_id
             WHERE v.org_id = ?1",
            [org],
            |r| r.get(0),
        )?,
        None => db.query_row(
            "SELECT COALESCE(SUM(b.size), 0) FROM blobs b JOIN vaults v ON v.id = b.vault_id
             WHERE v.org_id IS NULL AND v.account_id = (SELECT account_id FROM vaults WHERE id = ?1)",
            [vault],
            |r| r.get(0),
        )?,
    };
    Ok(total as u64)
}

/// Deletes the organization's session logs older than its `session_log_retention_days`.
pub(crate) fn purge_expired(db: &Connection, org: &str) -> rusqlite::Result<usize> {
    let days = sharing::org_policies(db, org)?.session_log_retention_days;
    if days == 0 {
        return Ok(0);
    }
    let cutoff = rfc3339(now_secs() - i64::from(days) * 86_400);
    db.execute(
        "DELETE FROM blobs WHERE kind = 'session_log' AND created_at < ?2
         AND vault_id IN (SELECT id FROM vaults WHERE org_id = ?1)",
        params![org, cutoff],
    )
}

fn row(db: &Connection, vault: &str, hash: &str) -> Result<BlobInfo, Fail> {
    if !valid_hash(hash) {
        return Err(Fail::not_found());
    }
    db.query_row(
        "SELECT hash, size, kind, author_id, created_at FROM blobs WHERE vault_id = ?1 AND hash = ?2",
        params![vault, hash],
        info,
    )
    .optional()?
    .ok_or_else(Fail::not_found)
}

/// `GET /vaults/{id}/blobs[?kind=]`, oldest first.
pub(crate) async fn list(
    State(s): State<AppState>,
    c: Caller,
    Path(id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> R<Vec<BlobInfo>> {
    require_full(&c)?;
    let db = s.conn()?;
    let access = sharing::require_vault(&db, &c, &id, Permission::Read)?;
    if let Some(org) = &access.org_id {
        purge_expired(&db, org)?;
    }
    let kind = q.get("kind").filter(|k| !k.is_empty());
    let mut stmt = db.prepare(
        "SELECT hash, size, kind, author_id, created_at FROM blobs
         WHERE vault_id = ?1 AND (?2 IS NULL OR kind = ?2) ORDER BY created_at, rowid",
    )?;
    let blobs = stmt
        .query_map(params![id, kind], info)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(blobs))
}

/// `PUT /vaults/{id}/blobs/{hash}`: the body is the ciphertext, `X-Blob-Kind` says what it is.
/// `201` when new; the same bytes again answer `200` and change nothing.
pub(crate) async fn put(
    State(s): State<AppState>,
    c: Caller,
    Path((id, hash)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<BlobInfo>), Fail> {
    require_full(&c)?;
    let kind = match headers.get("x-blob-kind") {
        None => "attachment",
        Some(v) => v.to_str().unwrap_or_default(),
    };
    let db = s.conn()?;
    let access = sharing::require_vault(&db, &c, &id, Permission::Write)?;
    if !KINDS.contains(&kind) {
        return Err(Fail::bad("kind must be attachment or session_log"));
    }
    if !valid_hash(&hash) {
        return Err(Fail::bad("a blob is named by the hex SHA-256 of its bytes"));
    }
    if body.len() as u64 > s.config.max_blob_bytes {
        return Err(Fail::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "the blob exceeds max_blob_bytes",
        ));
    }
    let actual: String = Sha256::digest(&body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != hash {
        return Err(Fail::new(
            StatusCode::BAD_REQUEST,
            "hash_mismatch",
            "the bytes do not match the hash",
        ));
    }
    if let Ok(existing) = row(&db, &id, &hash) {
        return Ok((StatusCode::OK, Json(existing)));
    }
    if let Some(org) = &access.org_id {
        purge_expired(&db, org)?;
    }
    if used(&db, &id, &access)? + body.len() as u64 > s.config.blob_quota_bytes {
        return Err(Fail::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "quota_exceeded",
            "blob storage is full; delete old session logs or attachments",
        ));
    }
    let blob = BlobInfo {
        hash,
        size: body.len() as u64,
        kind: kind.into(),
        author_id: Some(c.account.clone()),
        created_at: now(),
    };
    db.execute(
        "INSERT INTO blobs (vault_id, hash, size, kind, author_id, created_at, data)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            blob.hash,
            blob.size as i64,
            blob.kind,
            blob.author_id,
            blob.created_at,
            &body[..]
        ],
    )?;
    Ok((StatusCode::CREATED, Json(blob)))
}

/// `GET` (and `HEAD`) `/vaults/{id}/blobs/{hash}`: the ciphertext.
pub(crate) async fn get(
    State(s): State<AppState>,
    c: Caller,
    Path((id, hash)): Path<(String, String)>,
) -> Result<Response, Fail> {
    require_full(&c)?;
    let db = s.conn()?;
    sharing::require_vault(&db, &c, &id, Permission::Read)?;
    let meta = row(&db, &id, &hash)?;
    let data: Vec<u8> = db.query_row(
        "SELECT data FROM blobs WHERE vault_id = ?1 AND hash = ?2",
        params![id, hash],
        |r| r.get(0),
    )?;
    let mut resp = data.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", meta.hash)) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta.kind) {
        h.insert("x-blob-kind", v);
    }
    Ok(resp)
}

/// `DELETE /vaults/{id}/blobs/{hash}`.
pub(crate) async fn delete(
    State(s): State<AppState>,
    c: Caller,
    Path((id, hash)): Path<(String, String)>,
) -> Result<StatusCode, Fail> {
    require_full(&c)?;
    let db = s.conn()?;
    sharing::require_vault(&db, &c, &id, Permission::Write)?;
    row(&db, &id, &hash)?;
    db.execute(
        "DELETE FROM blobs WHERE vault_id = ?1 AND hash = ?2",
        params![id, hash],
    )?;
    Ok(StatusCode::NO_CONTENT)
}
