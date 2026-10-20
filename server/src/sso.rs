//! Single sign-on (OpenID Connect, authorization code with PKCE), per organization: its vaults
//! answer `403 sso_required` until this device has signed in at the organization's provider. It
//! is layered on top of the `AuthKey` proof, never instead of it.
//!
//! Providers are set up with `vault-sync-server sso …` (see `main.rs`), not over the API.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mg_sync::{ApiError, SsoStart, SsoStatus};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::api::{R, require_full};
use crate::auth::Caller;
use crate::sharing;
use crate::util::{Fail, now, now_secs, random, rfc3339};

/// A started sign-in is valid this long.
const LOGIN_SECS: i64 = 600;

/// An organization's identity provider.
#[derive(Clone, Debug)]
pub struct Provider {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Sign in again after this long.
    pub session_hours: u32,
}

fn provider(db: &Connection, org: &str) -> rusqlite::Result<Option<Provider>> {
    db.query_row(
        "SELECT issuer, client_id, client_secret, session_hours FROM org_sso WHERE org_id = ?1",
        [org],
        |r| {
            Ok(Provider {
                issuer: r.get(0)?,
                client_id: r.get(1)?,
                client_secret: r.get(2)?,
                session_hours: r.get(3)?,
            })
        },
    )
    .optional()
}

/// Sets (or replaces) an organization's provider. Admin tooling, not the API.
pub fn configure(db: &Connection, org: &str, p: &Provider) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO org_sso (org_id, issuer, client_id, client_secret, session_hours, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (org_id) DO UPDATE SET issuer = excluded.issuer, client_id = excluded.client_id,
             client_secret = excluded.client_secret, session_hours = excluded.session_hours,
             updated_at = excluded.updated_at",
        params![org, p.issuer.trim_end_matches('/'), p.client_id, p.client_secret, p.session_hours, now()],
    )?;
    sharing::event(db, org, "sso_configured", None, None, None, Some(&p.issuer))?;
    Ok(())
}

/// Removes the provider: its sign-ins and sessions go, and `require_sso` is turned off.
pub fn remove(db: &Connection, org: &str) -> rusqlite::Result<()> {
    db.execute("DELETE FROM org_sso WHERE org_id = ?1", [org])?;
    db.execute("DELETE FROM sso_logins WHERE org_id = ?1", [org])?;
    db.execute("DELETE FROM sso_sessions WHERE org_id = ?1", [org])?;
    let mut p = sharing::org_policies(db, org)?;
    p.require_sso = false;
    db.execute(
        "UPDATE orgs SET policies = ?2 WHERE id = ?1",
        params![org, serde_json::to_string(&p).expect("serializable")],
    )?;
    sharing::event(db, org, "sso_removed", None, None, None, None)?;
    Ok(())
}

/// Sessions of one member of `org` (all their devices): when they leave or are removed.
pub(crate) fn end_sessions(db: &Connection, org: &str, account: &str) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM sso_sessions WHERE org_id = ?1 AND account_id = ?2",
        params![org, account],
    )?;
    Ok(())
}

fn session_expires(db: &Connection, org: &str, c: &Caller) -> rusqlite::Result<Option<i64>> {
    db.query_row(
        "SELECT expires FROM sso_sessions WHERE org_id = ?1 AND account_id = ?2 AND device_id = ?3 AND expires > ?4",
        params![org, c.account, c.device, now_secs()],
        |r| r.get(0),
    )
    .optional()
}

/// `require_sso` is on and the organization has a provider.
fn required(db: &Connection, org: &str) -> rusqlite::Result<bool> {
    Ok(sharing::org_policies(db, org)?.require_sso && provider(db, org)?.is_some())
}

/// The gate on an organization's vaults: `Err` until this device has signed in.
pub(crate) fn gate(db: &Connection, org: &str, c: &Caller) -> Result<(), Fail> {
    if required(db, org)? && session_expires(db, org, c)?.is_none() {
        let mut e = ApiError::new(
            "sso_required",
            "sign in with your organization's identity provider first",
        );
        e.org_id = Some(org.into());
        return Err(Fail(StatusCode::FORBIDDEN, Box::new(e)));
    }
    Ok(())
}

/// Whether the gate is open (for listing vaults).
pub(crate) fn open(db: &Connection, org: &str, c: &Caller) -> rusqlite::Result<bool> {
    Ok(!required(db, org)? || session_expires(db, org, c)?.is_some())
}

/// `GET /orgs/{id}/sso`: any member.
pub(crate) async fn status(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
) -> R<SsoStatus> {
    require_full(&c)?;
    let db = s.conn()?;
    sharing::require_any_member(&db, &c, &org)?;
    let Some(p) = provider(&db, &org)? else {
        return Ok(Json(SsoStatus::default()));
    };
    Ok(Json(SsoStatus {
        configured: true,
        required: sharing::org_policies(&db, &org)?.require_sso,
        protocol: Some("oidc".into()),
        issuer: Some(p.issuer),
        session_expires_at: session_expires(&db, &org, &c)?.map(rfc3339),
    }))
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

fn provider_error(e: impl std::fmt::Display) -> Fail {
    Fail::new(
        StatusCode::BAD_GATEWAY,
        "sso_provider_error",
        format!("the identity provider: {e}"),
    )
}

async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Discovery, Fail> {
    let d: Discovery = http
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(provider_error)?
        .json()
        .await
        .map_err(provider_error)?;
    if d.issuer.trim_end_matches('/') != issuer {
        return Err(provider_error(
            "its discovery document names another issuer",
        ));
    }
    Ok(d)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `POST /orgs/{id}/sso/start`: confirmed members.
pub(crate) async fn start(
    State(s): State<AppState>,
    c: Caller,
    Path(org): Path<String>,
) -> R<SsoStart> {
    require_full(&c)?;
    let (p, email) = {
        let db = s.conn()?;
        sharing::require_confirmed(&db, &c, &org)?;
        let p = provider(&db, &org)?.ok_or_else(|| {
            Fail::new(
                StatusCode::CONFLICT,
                "sso_not_configured",
                "the organization has no identity provider",
            )
        })?;
        let email: String = db.query_row(
            "SELECT email FROM accounts WHERE id = ?1",
            [&c.account],
            |r| r.get(0),
        )?;
        (p, email)
    };
    // The provider first: one that is down leaves no sign-in behind.
    let d = discover(&s.http, &p.issuer).await?;
    let (state, nonce, verifier) = (
        b64(&random::<32>()),
        b64(&random::<16>()),
        b64(&random::<32>()),
    );
    let challenge = b64(&Sha256::digest(verifier.as_bytes()));
    s.conn()?.execute(
        "INSERT INTO sso_logins (state_hash, org_id, account_id, device_id, nonce, verifier, expires)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![sha256_hex(&state), org, c.account, c.device, nonce, verifier, now_secs() + LOGIN_SECS],
    )?;
    let mut url = url::Url::parse(&d.authorization_endpoint).map_err(provider_error)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &p.client_id)
        .append_pair("redirect_uri", &s.redirect_uri())
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("login_hint", &email);
    Ok(Json(SsoStart {
        url: url.into(),
        expires_in: LOGIN_SECS as u32,
    }))
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn page(title: &str, text: &str) -> Html<String> {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    Html(format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>\
         <title>{t}</title><body style='font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>\
         <h1 style='font-size:1.4rem'>{t}</h1><p>{x}</p>",
        t = esc(title),
        x = esc(text)
    ))
}

/// `GET /sso/callback`: where the provider sends the browser back.
pub(crate) async fn callback(
    State(s): State<AppState>,
    Query(q): Query<CallbackQuery>,
) -> (StatusCode, Html<String>) {
    match finish(&s, q).await {
        Ok(org_name) => (
            StatusCode::OK,
            page(
                "Signed in",
                &format!(
                    "You are signed in to {org_name}. Return to MorphGate; its vaults open now."
                ),
            ),
        ),
        Err(Fail(status, e)) => (status, page("Single sign-on failed", &e.message)),
    }
}

async fn finish(s: &AppState, q: CallbackQuery) -> Result<String, Fail> {
    if let Some(e) = q.error {
        return Err(Fail::new(
            StatusCode::BAD_REQUEST,
            "sso_provider_error",
            q.error_description.unwrap_or(e),
        ));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return Err(Fail::bad("the provider sent no code"));
    };
    // A state works once.
    let login: Option<(String, String, String, String, String, i64)> = s
        .conn()?
        .query_row(
            "DELETE FROM sso_logins WHERE state_hash = ?1
         RETURNING org_id, account_id, device_id, nonce, verifier, expires",
            [sha256_hex(&state)],
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
    let Some((org, account, device, nonce, verifier, expires)) = login else {
        return Err(Fail::new(
            StatusCode::BAD_REQUEST,
            "sso_expired",
            "this sign-in expired; start it again from MorphGate",
        ));
    };
    if expires < now_secs() {
        return Err(Fail::new(
            StatusCode::BAD_REQUEST,
            "sso_expired",
            "this sign-in expired; start it again from MorphGate",
        ));
    }
    let (p, email, org_name) = {
        let db = s.conn()?;
        let p = provider(&db, &org)?.ok_or_else(|| {
            Fail::new(
                StatusCode::CONFLICT,
                "sso_not_configured",
                "the organization has no identity provider",
            )
        })?;
        let email: String = db.query_row(
            "SELECT email FROM accounts WHERE id = ?1",
            [&account],
            |r| r.get(0),
        )?;
        let name: String =
            db.query_row("SELECT name FROM orgs WHERE id = ?1", [&org], |r| r.get(0))?;
        (p, email, name)
    };
    let d = discover(&s.http, &p.issuer).await?;

    #[derive(Deserialize)]
    struct Tokens {
        id_token: String,
    }
    let tokens: Tokens = s
        .http
        .post(&d.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", s.redirect_uri().as_str()),
            ("client_id", p.client_id.as_str()),
            ("client_secret", p.client_secret.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(provider_error)?
        .json()
        .await
        .map_err(provider_error)?;
    let jwks: Jwks = s
        .http
        .get(&d.jwks_uri)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(provider_error)?
        .json()
        .await
        .map_err(provider_error)?;
    let claims = verify_id_token(&tokens.id_token, &jwks, &p, &nonce, now_secs())?;
    let theirs = claims.email.as_deref().unwrap_or_default();
    if !theirs.eq_ignore_ascii_case(&email) || claims.email_verified == Some(false) {
        return Err(Fail::new(
            StatusCode::FORBIDDEN,
            "sso_mismatch",
            "the identity provider signed in another address than this account's",
        ));
    }
    let db = s.conn()?;
    db.execute(
        "INSERT INTO sso_sessions (org_id, account_id, device_id, sub, expires) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (org_id, account_id, device_id) DO UPDATE SET sub = excluded.sub, expires = excluded.expires",
        params![org, account, device, claims.sub, now_secs() + i64::from(p.session_hours) * 3600],
    )?;
    sharing::event(
        &db,
        &org,
        "sso_signed_in",
        Some(&account),
        Some(&account),
        None,
        Some("oidc"),
    )?;
    Ok(org_name)
}

#[derive(Deserialize)]
pub(crate) struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    #[serde(default)]
    azp: Option<String>,
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

fn invalid(why: &str) -> Fail {
    Fail::new(
        StatusCode::UNAUTHORIZED,
        "sso_invalid_token",
        format!("the identity provider's token: {why}"),
    )
}

/// Checks an RS256 ID token: the signature against the provider's keys, then issuer, audience,
/// expiry and nonce.
pub(crate) fn verify_id_token(
    token: &str,
    jwks: &Jwks,
    p: &Provider,
    nonce: &str,
    now: i64,
) -> Result<Claims, Fail> {
    let mut parts = token.split('.');
    let (Some(h), Some(c), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("not a JWT"));
    };
    let decode = |s: &str| {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| invalid("bad encoding"))
    };

    #[derive(Deserialize)]
    struct Header {
        alg: String,
        #[serde(default)]
        kid: Option<String>,
    }
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| invalid("bad header"))?;
    if header.alg != "RS256" {
        return Err(invalid("only RS256 is accepted"));
    }
    let candidates: Vec<&Jwk> = jwks
        .keys
        .iter()
        .filter(|k| k.kty == "RSA" && (header.kid.is_none() || k.kid == header.kid))
        .collect();
    let signed = format!("{h}.{c}");
    let sig = decode(sig)?;
    let good = candidates.iter().any(|k| {
        let (Some(n), Some(e)) = (k.n.as_deref(), k.e.as_deref()) else {
            return false;
        };
        let (Ok(n), Ok(e)) = (URL_SAFE_NO_PAD.decode(n), URL_SAFE_NO_PAD.decode(e)) else {
            return false;
        };
        aws_lc_rs::rsa::PublicKeyComponents { n, e }
            .verify(
                &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                signed.as_bytes(),
                &sig,
            )
            .is_ok()
    });
    if !good {
        return Err(invalid("the signature doesn't match the provider's keys"));
    }
    let claims: Claims = serde_json::from_slice(&decode(c)?).map_err(|_| invalid("bad claims"))?;
    if claims.iss.trim_end_matches('/') != p.issuer {
        return Err(invalid("wrong issuer"));
    }
    let audiences = match &claims.aud {
        Audience::One(a) => vec![a.as_str()],
        Audience::Many(a) => a.iter().map(String::as_str).collect(),
    };
    if !audiences.contains(&p.client_id.as_str()) {
        return Err(invalid("not issued for this server"));
    }
    if audiences.len() > 1 && claims.azp.as_deref() != Some(p.client_id.as_str()) {
        return Err(invalid("not issued for this server"));
    }
    if claims.exp <= now {
        return Err(invalid("expired"));
    }
    if claims.nonce.as_deref() != Some(nonce) {
        return Err(invalid("it belongs to another sign-in"));
    }
    Ok(claims)
}
