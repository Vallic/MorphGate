//! SCIM 2.0 provisioning, users only (`/scim/v2/{org}/…`): an organization's identity provider
//! decides who is on the team. Creating an active user invites the address as a member (an
//! admin's app still confirms them and grants vaults: that needs keys the server doesn't have);
//! deactivating or deleting one removes the member, takes their vault access, flags those vaults
//! for a new key and cancels invites to the address. The owner can't be deprovisioned.
//!
//! `scim_users` records what the provider manages, by address; it is not the member list. Each
//! organization has one bearer token, made with `vault-sync-server scim …` (see `main.rs`).
//!
//! This server sends no mail and keeps no invite token, so a provisioned invite waits in the
//! organization's invites until an admin invites the address again: that replaces it with an
//! invite whose token the admin passes on, as for any invite.

use std::collections::HashMap;
use std::sync::MutexGuard;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mg_sync::Role;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::api::check_email;
use crate::sharing::{self, event};
use crate::util::{Fail, now, now_secs, random, valid_id};

const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// Error codes that are SCIM's own, sent as `scimType`.
const SCIM_TYPES: [&str; 5] = [
    "uniqueness",
    "invalidFilter",
    "mutability",
    "invalidSyntax",
    "invalidValue",
];
/// The most users in one page.
const MAX_COUNT: u64 = 200;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/scim/v2/{org}/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/{org}/ResourceTypes", get(resource_types))
        .route("/scim/v2/{org}/Schemas", get(schemas))
        .route("/scim/v2/{org}/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/{org}/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
}

// ------------------------------------------------------------------ token

/// A new token for an organization, replacing its old one. Admin tooling, not the API.
pub(crate) fn issue_token(db: &Connection, org: &str) -> rusqlite::Result<String> {
    let token = format!("scim_{}", URL_SAFE_NO_PAD.encode(random::<32>()));
    db.execute(
        "INSERT INTO scim_tokens (org_id, token_hash, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (org_id) DO UPDATE SET token_hash = excluded.token_hash,
             created_at = excluded.created_at, last_used = NULL",
        params![org, sharing::token_hash(&token), now()],
    )?;
    event(db, org, "scim_token_created", None, None, None, None)?;
    Ok(token)
}

/// Removes an organization's token: provisioning stops (its users stay).
pub(crate) fn revoke_token(db: &Connection, org: &str) -> rusqlite::Result<()> {
    if db.execute("DELETE FROM scim_tokens WHERE org_id = ?1", [org])? > 0 {
        event(db, org, "scim_token_revoked", None, None, None, None)?;
    }
    Ok(())
}

/// The database, once the request carries the organization's token (`401` otherwise); notes
/// that the token was used.
fn authorized<'a>(
    s: &'a AppState,
    org: &str,
    headers: &HeaderMap,
) -> Result<MutexGuard<'a, Connection>, Fail> {
    if !valid_id(org) {
        return Err(Fail::not_found());
    }
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map_or("", str::trim);
    let db = s.conn()?;
    let known = !token.is_empty()
        && db.execute(
            "UPDATE scim_tokens SET last_used = ?3 WHERE org_id = ?1 AND token_hash = ?2",
            params![org, sharing::token_hash(token), now()],
        )? > 0;
    if !known {
        return Err(Fail::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid SCIM token",
        ));
    }
    Ok(db)
}

// ------------------------------------------------------------------ responses

/// A refusal in SCIM's shape (RFC 7644 §3.12): the status as a string, the message as `detail`,
/// and SCIM's own codes as `scimType`.
struct ScimFail(Fail);

impl From<Fail> for ScimFail {
    fn from(f: Fail) -> Self {
        Self(f)
    }
}

impl From<rusqlite::Error> for ScimFail {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for ScimFail {
    fn into_response(self) -> Response {
        let Fail(status, e) = self.0;
        let mut body =
            json!({ "schemas": [ERROR], "status": status.as_str(), "detail": e.message });
        if SCIM_TYPES.contains(&e.code.as_str()) {
            body["scimType"] = e.code.into();
        }
        reply(status, &body)
    }
}

type Out = Result<Response, ScimFail>;

fn reply(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [
            (CONTENT_TYPE, "application/scim+json"),
            (CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

fn invalid(code: &str, detail: &str) -> ScimFail {
    Fail::new(StatusCode::BAD_REQUEST, code, detail).into()
}

// ------------------------------------------------------------------ users

struct User {
    id: String,
    user_name: String,
    external_id: Option<String>,
    active: bool,
    created_at: String,
    updated_at: String,
}

const USER_COLS: &str = "id, user_name, external_id, active, created_at, updated_at";

fn user_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        user_name: r.get(1)?,
        external_id: r.get(2)?,
        active: r.get(3)?,
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
    })
}

fn load_user(db: &Connection, org: &str, id: &str) -> Result<User, Fail> {
    db.query_row(
        &format!("SELECT {USER_COLS} FROM scim_users WHERE org_id = ?1 AND id = ?2"),
        params![org, id],
        user_row,
    )
    .optional()?
    .ok_or_else(Fail::not_found)
}

/// Where an organization's SCIM endpoints are.
fn base(s: &AppState, org: &str) -> String {
    format!(
        "{}/scim/v2/{org}",
        s.config.public_url.trim_end_matches('/')
    )
}

impl User {
    /// The SCIM User resource; `base` is the organization's SCIM URL.
    fn resource(&self, base: &str) -> Value {
        let mut out = json!({
            "schemas": [USER],
            "id": self.id,
            "userName": self.user_name,
            "active": self.active,
            "emails": [{ "value": self.user_name, "primary": true, "type": "work" }],
            "meta": {
                "resourceType": "User",
                "created": self.created_at,
                "lastModified": self.updated_at,
                "location": format!("{base}/Users/{}", self.id),
            },
        });
        if let Some(e) = &self.external_id {
            out["externalId"] = e.as_str().into();
        }
        out
    }
}

/// The request's JSON object.
fn object(body: &[u8]) -> Result<Map<String, Value>, Fail> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(o)) => Ok(o),
        Ok(_) => Err(Fail::bad("the request body must be a JSON object")),
        Err(_) => Err(Fail::bad("the request body is not JSON")),
    }
}

/// SCIM booleans arrive as `true`/`false` or, from some providers, as `"True"`/`"False"`.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true"),
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `active` in a created or replaced user: on unless it says otherwise.
fn active_in(body: &Map<String, Value>) -> bool {
    body.get("active")
        .filter(|v| !v.is_null())
        .is_none_or(truthy)
}

/// The address of a user: `userName`, or the primary email when `userName` isn't an address.
fn address(body: &Map<String, Value>) -> Result<String, Fail> {
    let user_name = body.get("userName").filter(|v| !v.is_null());
    let mut email = user_name.and_then(Value::as_str);
    if !email.is_some_and(|e| e.contains('@')) {
        let mut set = user_name.is_some();
        let emails = body.get("emails").and_then(Value::as_array);
        for e in emails.into_iter().flatten() {
            if let Some(value) = e.get("value").and_then(Value::as_str)
                && (!set || e.get("primary").is_some_and(truthy))
            {
                email = Some(value);
                set = true;
            }
        }
    }
    check_email(email.unwrap_or_default())
}

/// The account and role of the member with an address.
fn member_by_email(
    db: &Connection,
    org: &str,
    email: &str,
) -> rusqlite::Result<Option<(String, String)>> {
    db.query_row(
        "SELECT m.account_id, m.role FROM members m JOIN accounts a ON a.id = m.account_id
         WHERE m.org_id = ?1 AND a.email = ?2",
        params![org, email],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

/// Invites the address as a member, from the owner, unless it is one already. An open invite to
/// it is kept: an admin may have passed its token on already.
fn provision(db: &Connection, org: &str, email: &str) -> Result<(), Fail> {
    if member_by_email(db, org, email)?.is_some() {
        return Ok(());
    }
    let invited: bool = db.query_row(
        "SELECT EXISTS (SELECT 1 FROM invites WHERE org_id = ?1 AND email = ?2 AND closed = 0 AND expires_at > ?3)",
        params![org, email, now_secs()],
        |r| r.get(0),
    )?;
    if !invited {
        let owner: String =
            db.query_row("SELECT owner_id FROM orgs WHERE id = ?1", [org], |r| {
                r.get(0)
            })?;
        sharing::insert_invite(db, org, email, Role::Member, &[], &owner, None)?;
    }
    Ok(())
}

/// Removes the address's membership (the vaults they could open want a new key) and cancels
/// invites to it. The owner can't be removed this way (`409 sole_owner`).
fn deprovision(db: &Connection, org: &str, email: &str) -> Result<(), Fail> {
    if let Some((account, role)) = member_by_email(db, org, email)? {
        if role == "owner" {
            return Err(Fail::new(
                StatusCode::CONFLICT,
                "sole_owner",
                "the owner can't be removed by provisioning",
            ));
        }
        sharing::remove_member_rows(db, org, &account)?;
        event(db, org, "member_removed", None, Some(&account), None, None)?;
    }
    let cancelled = db.execute(
        "UPDATE invites SET closed = 1 WHERE org_id = ?1 AND email = ?2 AND closed = 0",
        params![org, email],
    )?;
    if cancelled > 0 {
        event(db, org, "invite_cancelled", None, None, None, Some(email))?;
    }
    Ok(())
}

/// Makes the address's membership match `active`.
fn apply(db: &Connection, org: &str, email: &str, active: bool) -> Result<(), Fail> {
    if active {
        provision(db, org, email)
    } else {
        deprovision(db, org, email)
    }
}

/// Stores the given fields and makes membership follow a change of `active`, in one
/// transaction: a refused change (the owner) changes nothing.
fn update(
    db: &mut Connection,
    org: &str,
    user: &User,
    active: Option<bool>,
    external_id: Option<Option<String>>,
) -> Result<User, Fail> {
    let tx = db.transaction()?;
    if active.is_some() || external_id.is_some() {
        tx.execute(
            "UPDATE scim_users SET active = ?3, external_id = ?4, updated_at = ?5 WHERE org_id = ?1 AND id = ?2",
            params![
                org,
                user.id,
                active.unwrap_or(user.active),
                external_id.unwrap_or_else(|| user.external_id.clone()),
                now()
            ],
        )?;
    }
    if let Some(active) = active.filter(|a| *a != user.active) {
        apply(&tx, org, &user.user_name, active)?;
    }
    let out = load_user(&tx, org, &user.id)?;
    tx.commit()?;
    Ok(out)
}

/// A query number: digits only, else `None`.
fn digits(v: Option<&String>) -> Option<u64> {
    let v = v?;
    (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).then(|| v.parse().unwrap_or(u64::MAX))
}

/// `userName eq "…"` (true) or `externalId eq "…"` (false), attribute names in any case.
fn parse_filter(filter: &str) -> Option<(bool, &str)> {
    let (attribute, rest) = filter.trim().split_once(char::is_whitespace)?;
    let (op, value) = rest.trim_start().split_once(char::is_whitespace)?;
    let value = value.trim_start().strip_prefix('"')?.strip_suffix('"')?;
    if !op.eq_ignore_ascii_case("eq") || value.contains('"') {
        return None;
    }
    match attribute.to_ascii_lowercase().as_str() {
        "username" => Some((true, value)),
        "externalid" => Some((false, value)),
        _ => None,
    }
}

// ------------------------------------------------------------------ endpoints

async fn service_provider_config(
    State(s): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
) -> Out {
    drop(authorized(&s, &org, &headers)?);
    Ok(reply(
        StatusCode::OK,
        &json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_COUNT },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "The token from `vault-sync-server scim`.",
            }],
        }),
    ))
}

async fn resource_types(
    State(s): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
) -> Out {
    drop(authorized(&s, &org, &headers)?);
    Ok(reply(
        StatusCode::OK,
        &json!({
            "schemas": [LIST],
            "totalResults": 1,
            "Resources": [{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": USER,
            }],
        }),
    ))
}

async fn schemas(State(s): State<AppState>, Path(org): Path<String>, headers: HeaderMap) -> Out {
    drop(authorized(&s, &org, &headers)?);
    let attribute = |name: &str, kind: &str, required: bool, mutability: &str| {
        json!({
            "name": name,
            "type": kind,
            "multiValued": false,
            "required": required,
            "mutability": mutability,
            "returned": "default",
            "uniqueness": if name == "userName" { "server" } else { "none" },
        })
    };
    Ok(reply(
        StatusCode::OK,
        &json!({
            "schemas": [LIST],
            "totalResults": 1,
            "Resources": [{
                "id": USER,
                "name": "User",
                "attributes": [
                    attribute("userName", "string", true, "immutable"),
                    attribute("externalId", "string", false, "readWrite"),
                    attribute("active", "boolean", false, "readWrite"),
                ],
            }],
        }),
    ))
}

/// `GET /Users?filter=&startIndex=&count=`: oldest first.
async fn list_users(
    State(s): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Out {
    let db = authorized(&s, &org, &headers)?;
    let (user_name, external_id) = match q.get("filter").filter(|f| !f.is_empty()) {
        None => (None, None),
        Some(f) => match parse_filter(f) {
            Some((true, v)) => (Some(v), None),
            Some((false, v)) => (None, Some(v)),
            None => {
                return Err(invalid(
                    "invalidFilter",
                    r#"supported filters: userName eq "…", externalId eq "…""#,
                ));
            }
        },
    };
    let mut stmt = db.prepare(&format!(
        "SELECT {USER_COLS} FROM scim_users WHERE org_id = ?1 AND (?2 IS NULL OR user_name = ?2)
             AND (?3 IS NULL OR external_id = ?3) ORDER BY created_at, rowid"
    ))?;
    let users = stmt
        .query_map(params![org, user_name, external_id], user_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let start = digits(q.get("startIndex")).unwrap_or(1).max(1);
    let count = digits(q.get("count")).unwrap_or(100).min(MAX_COUNT);
    let base = base(&s, &org);
    let page: Vec<Value> = users
        .iter()
        .skip(usize::try_from(start - 1).unwrap_or(usize::MAX))
        .take(usize::try_from(count).unwrap_or(usize::MAX))
        .map(|u| u.resource(&base))
        .collect();
    Ok(reply(
        StatusCode::OK,
        &json!({
            "schemas": [LIST],
            "totalResults": users.len(),
            "startIndex": start,
            "itemsPerPage": page.len(),
            "Resources": page,
        }),
    ))
}

/// `POST /Users`: an active user is invited unless already a member.
async fn create_user(
    State(s): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Out {
    let mut db = authorized(&s, &org, &headers)?;
    let body = object(&body)?;
    let email = address(&body)?;
    let active = active_in(&body);
    // A refused change (the owner can't be deprovisioned) leaves no user row.
    let tx = db.transaction()?;
    let taken: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM scim_users WHERE org_id = ?1 AND user_name = ?2)",
        params![org, email],
        |r| r.get(0),
    )?;
    if taken {
        return Err(Fail::new(
            StatusCode::CONFLICT,
            "uniqueness",
            "a user with this userName exists",
        )
        .into());
    }
    let id = ulid::Ulid::generate().to_string();
    tx.execute(
        "INSERT INTO scim_users (org_id, id, user_name, external_id, active, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![
            org,
            id,
            email,
            body.get("externalId").and_then(Value::as_str),
            active,
            now()
        ],
    )?;
    apply(&tx, &org, &email, active)?;
    let user = load_user(&tx, &org, &id)?;
    tx.commit()?;
    Ok(reply(StatusCode::CREATED, &user.resource(&base(&s, &org))))
}

async fn get_user(
    State(s): State<AppState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Out {
    let db = authorized(&s, &org, &headers)?;
    let user = load_user(&db, &org, &id)?;
    Ok(reply(StatusCode::OK, &user.resource(&base(&s, &org))))
}

/// `PUT /Users/{id}`: replaces `active` and `externalId`; the address is fixed.
async fn replace_user(
    State(s): State<AppState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Out {
    let mut db = authorized(&s, &org, &headers)?;
    let body = object(&body)?;
    let user = load_user(&db, &org, &id)?;
    if !address(&body)?.eq_ignore_ascii_case(&user.user_name) {
        return Err(invalid(
            "mutability",
            "userName can't change; deprovision and create a new user",
        ));
    }
    let external_id = body
        .get("externalId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| user.external_id.clone());
    let user = update(
        &mut db,
        &org,
        &user,
        Some(active_in(&body)),
        Some(external_id),
    )?;
    Ok(reply(StatusCode::OK, &user.resource(&base(&s, &org))))
}

/// `PATCH /Users/{id}`: `replace` or `add` of `active` and `externalId`, with or without a path.
/// Other attributes are ignored.
async fn patch_user(
    State(s): State<AppState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Out {
    let mut db = authorized(&s, &org, &headers)?;
    let body = object(&body)?;
    let user = load_user(&db, &org, &id)?;
    let (mut active, mut external_id) = (None, None);
    let ops = body.get("Operations").and_then(Value::as_array);
    for op in ops.into_iter().flatten() {
        let kind = op.get("op").and_then(Value::as_str).unwrap_or_default();
        if !kind.eq_ignore_ascii_case("replace") && !kind.eq_ignore_ascii_case("add") {
            return Err(invalid(
                "invalidSyntax",
                "only replace and add operations are supported",
            ));
        }
        let value = op.get("value").unwrap_or(&Value::Null);
        // Without a path, the value is an object of attributes.
        let values: Vec<(&str, &Value)> = match (op.get("path").filter(|p| !p.is_null()), value) {
            (None, Value::Object(o)) => o.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            (path, _) => vec![(path.and_then(Value::as_str).unwrap_or_default(), value)],
        };
        for (attribute, value) in values {
            match attribute {
                "active" => active = Some(truthy(value)),
                "externalId" => external_id = Some(value.as_str().map(str::to_owned)),
                _ => {}
            }
        }
    }
    let user = update(&mut db, &org, &user, active, external_id)?;
    Ok(reply(StatusCode::OK, &user.resource(&base(&s, &org))))
}

/// `DELETE /Users/{id}`: deprovisions the address and forgets the user.
async fn delete_user(
    State(s): State<AppState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Out {
    let mut db = authorized(&s, &org, &headers)?;
    let user = load_user(&db, &org, &id)?;
    let tx = db.transaction()?;
    if user.active {
        deprovision(&tx, &org, &user.user_name)?;
    }
    tx.execute(
        "DELETE FROM scim_users WHERE org_id = ?1 AND id = ?2",
        params![org, id],
    )?;
    tx.commit()?;
    Ok((StatusCode::NO_CONTENT, [(CACHE_CONTROL, "no-store")]).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert_eq!(
            parse_filter(r#"userName eq "a@x.com""#),
            Some((true, "a@x.com"))
        );
        assert_eq!(
            parse_filter(r#"  USERNAME   EQ  "a b"  "#),
            Some((true, "a b"))
        );
        assert_eq!(parse_filter(r#"externalId eq """#), Some((false, "")));
        for bad in [
            r#"userName sw "a""#,
            r#"displayName eq "a""#,
            r#"userName eq "a" and active eq true"#,
            r#"userName eq a"#,
            r#"userName eq ""a"""#,
            "userName",
        ] {
            assert_eq!(parse_filter(bad), None, "{bad}");
        }
    }

    #[test]
    fn addresses() {
        let body = |v: Value| v.as_object().unwrap().clone();
        assert_eq!(
            address(&body(json!({ "userName": " a@x.com " }))).unwrap(),
            "a@x.com"
        );
        assert_eq!(
            address(&body(json!({
                "userName": "jdoe",
                "emails": [{ "value": "home@x.com" }, { "value": "work@x.com", "primary": true }],
            })))
            .unwrap(),
            "work@x.com"
        );
        // Without a userName, the first email unless one is primary.
        assert_eq!(
            address(&body(
                json!({ "emails": [{ "value": "a@x.com" }, { "value": "b@x.com" }] })
            ))
            .unwrap(),
            "a@x.com"
        );
        assert!(
            address(&body(
                json!({ "userName": "jdoe", "emails": [{ "value": "a@x.com" }] })
            ))
            .is_err()
        );
        assert!(address(&body(json!({}))).is_err());
    }

    #[test]
    fn booleans() {
        assert!(truthy(&json!(true)) && truthy(&json!("True")) && truthy(&json!("true")));
        assert!(!truthy(&json!(false)) && !truthy(&json!("False")) && !truthy(&Value::Null));
        assert!(active_in(json!({}).as_object().unwrap()));
        assert!(active_in(json!({ "active": null }).as_object().unwrap()));
        assert!(!active_in(
            json!({ "active": "False" }).as_object().unwrap()
        ));
    }
}
