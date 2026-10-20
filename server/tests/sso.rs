//! Single sign-on on the reference server, against an in-process OpenID provider: the gate on an
//! organization's vaults, the sign-in (authorization code with PKCE, an RS256 ID token), and what
//! it refuses. Only the in-process server can be given a provider, so this doesn't run against
//! `VAULT_SYNC_URL`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mg_sync::*;
use mg_vault::VaultKey;
use mg_vault::sharing;
use sha2::{Digest, Sha256};
use vault_sync_server::SsoProvider;

mod common;

use common::{email, reference_state};

const CLIENT_ID: &str = "morphgate";
const SECRET: &str = "s3cret";

fn ulid() -> String {
    ulid::Ulid::generate().to_string()
}

fn b(v: impl Into<Vec<u8>>) -> B64 {
    B64(v.into())
}

fn b64(v: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(v)
}

// ------------------------------------------------------------------ the provider

/// A sign-in in progress at the provider: its nonce, the address signed in, the PKCE challenge
/// and the client.
type Grant = (String, String, String, String);

#[derive(Clone)]
struct Idp {
    base: String,
    key: Arc<KeyPair>,
    /// code → (nonce, email, challenge, client_id)
    codes: Arc<Mutex<HashMap<String, Grant>>>,
    /// Sign in this address instead of the login hint (a different person at the provider).
    email: Arc<Mutex<Option<String>>>,
}

async fn discovery(State(i): State<Idp>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": i.base,
        "authorization_endpoint": format!("{}/authorize", i.base),
        "token_endpoint": format!("{}/token", i.base),
        "jwks_uri": format!("{}/jwks", i.base),
    }))
}

async fn jwks(State(i): State<Idp>) -> Json<serde_json::Value> {
    let pk = PublicKeyComponents::<Vec<u8>>::from(i.key.public_key());
    Json(
        serde_json::json!({ "keys": [{ "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": b64(&pk.n), "e": b64(&pk.e) }] }),
    )
}

async fn authorize(State(i): State<Idp>, Query(q): Query<HashMap<String, String>>) -> Redirect {
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["code_challenge_method"], "S256");
    let code = ulid();
    let who = i
        .email
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| q["login_hint"].clone());
    i.codes.lock().unwrap().insert(
        code.clone(),
        (
            q["nonce"].clone(),
            who,
            q["code_challenge"].clone(),
            q["client_id"].clone(),
        ),
    );
    Redirect::to(&format!(
        "{}?code={code}&state={}",
        q["redirect_uri"], q["state"]
    ))
}

async fn token(State(i): State<Idp>, Form(f): Form<HashMap<String, String>>) -> Response {
    let Some((nonce, email, challenge, client)) = i.codes.lock().unwrap().remove(&f["code"]) else {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid_grant").into_response();
    };
    assert_eq!(f["client_secret"], SECRET);
    assert_eq!(f["client_id"], client);
    // PKCE: the verifier hashes to the challenge the sign-in started with.
    assert_eq!(
        b64(&Sha256::digest(f["code_verifier"].as_bytes())),
        challenge
    );
    let now = vault_now();
    let header = b64(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#);
    let claims = b64(serde_json::json!({
        "iss": i.base, "sub": "person-1", "aud": client, "iat": now, "exp": now + 300,
        "nonce": nonce, "email": email, "email_verified": true,
    })
    .to_string()
    .as_bytes());
    let signed = format!("{header}.{claims}");
    let mut sig = vec![0; i.key.public_modulus_len()];
    i.key
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signed.as_bytes(),
            &mut sig,
        )
        .unwrap();
    Json(serde_json::json!({ "id_token": format!("{signed}.{}", b64(&sig)), "token_type": "Bearer", "access_token": "x" })).into_response()
}

fn vault_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn idp() -> Idp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let i = Idp {
        base: format!("http://{}", listener.local_addr().unwrap()),
        key: Arc::new(KeyPair::generate(KeySize::Rsa2048).unwrap()),
        codes: Arc::default(),
        email: Arc::default(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(i.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    i
}

// ------------------------------------------------------------------ people

struct Person {
    client: SyncClient,
    id: String,
    keys: mg_vault::AccountKeys,
}

async fn person(url: &str, name: &str) -> Person {
    let client = SyncClient::new(url).unwrap();
    let keys = mg_vault::AccountKeys::generate().unwrap();
    let public = keys.public();
    let session = client
        .register(&RegisterRequest {
            email: email(name),
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
        keys,
    }
}

/// Follows the sign-in like a browser would, one redirect at a time; returns the server's
/// callback URL and the page it answered with.
async fn browse(url: &str) -> (String, u16, String) {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let at_provider = http.get(url).send().await.unwrap();
    assert_eq!(at_provider.status(), 303);
    let callback = at_provider.headers()["location"]
        .to_str()
        .unwrap()
        .to_owned();
    let (status, page) = visit(&callback).await;
    (callback, status, page)
}

async fn visit(url: &str) -> (u16, String) {
    let r = reqwest::get(url).await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn single_sign_on_gates_an_organizations_vaults() {
    let Some((url, state)) = reference_state().await else {
        return;
    };
    let provider = idp().await;
    let caps = SyncClient::new(&url).unwrap().capabilities().await.unwrap();
    assert_eq!(caps.features.sso.unwrap().protocols, ["oidc"]);

    let alice = person(&url, "alice").await;
    let org = ulid();
    alice
        .client
        .create_org(&CreateOrg {
            id: org.clone(),
            name: "Acme Ops".into(),
        })
        .await
        .unwrap();
    let vault = ulid();
    let vk = VaultKey::generate().unwrap();
    let wrapped = vk.seal_to(&alice.keys.public().enc).unwrap();
    alice
        .client
        .create_vault(&CreateVault {
            id: vault.clone(),
            key_id: b(vk.id().to_vec()),
            wrapped_vault_key: b(wrapped.clone()),
            meta: None,
            org_id: Some(org.clone()),
            keys: vec![SealedFor {
                account_id: alice.id.clone(),
                grant_sig: b(sharing::sign_grant(
                    &alice.keys,
                    &vault,
                    vk.id(),
                    &alice.id,
                    &wrapped,
                )),
                wrapped_vault_key: b(wrapped),
            }],
        })
        .await
        .unwrap();
    // Without a provider there is nothing to sign in at.
    assert!(!alice.client.sso_status(&org).await.unwrap().configured);
    assert!(matches!(
        alice.client.sso_start(&org).await,
        Err(Error::Api { status: 409, ref code, .. }) if code == "sso_not_configured"
    ));

    // The operator puts the organization behind the provider, required.
    state
        .set_sso(
            "Acme Ops",
            &SsoProvider {
                issuer: provider.base.clone(),
                client_id: CLIENT_ID.into(),
                client_secret: SECRET.into(),
                session_hours: 12,
            },
            true,
        )
        .unwrap();
    let s = alice.client.sso_status(&org).await.unwrap();
    assert!(s.configured && s.required);
    assert_eq!(s.protocol.as_deref(), Some("oidc"));
    assert_eq!(s.issuer.as_deref(), Some(provider.base.as_str()));
    assert!(s.session_expires_at.is_none());
    assert!(alice.client.org(&org).await.unwrap().policies.require_sso);

    // Its vaults are held back: 403 sso_required naming the organization, and out of the list.
    for r in [
        alice.client.pull(&vault, 0, 10).await.map(|_| ()),
        alice.client.vault(&vault).await.map(|_| ()),
        alice.client.blobs(&vault, None).await.map(|_| ()),
    ] {
        match r {
            Err(Error::SsoRequired { org_id }) => assert_eq!(org_id, org),
            other => panic!("expected sso_required, got {other:?}"),
        }
    }
    assert!(
        alice
            .client
            .list_vaults()
            .await
            .unwrap()
            .iter()
            .all(|v| v.id != vault)
    );

    // Another address at the provider is refused, and the state can't be used twice.
    *provider.email.lock().unwrap() = Some("mallory@example.com".into());
    let start = alice.client.sso_start(&org).await.unwrap();
    assert_eq!(start.expires_in, 600);
    let (_, status, page) = browse(&start.url).await;
    assert_eq!(status, 403);
    assert!(page.contains("another address"), "{page}");
    assert!(matches!(
        alice.client.pull(&vault, 0, 10).await,
        Err(Error::SsoRequired { .. })
    ));
    *provider.email.lock().unwrap() = None;

    // The right person: signed in, the vaults open on this device.
    let start = alice.client.sso_start(&org).await.unwrap();
    let (callback, status, page) = browse(&start.url).await;
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("You are signed in to Acme Ops"), "{page}");
    alice.client.pull(&vault, 0, 10).await.unwrap();
    assert!(
        alice
            .client
            .list_vaults()
            .await
            .unwrap()
            .iter()
            .any(|v| v.id == vault)
    );
    assert!(
        alice
            .client
            .sso_status(&org)
            .await
            .unwrap()
            .session_expires_at
            .is_some()
    );
    let (status, page) = visit(&callback).await;
    assert_eq!(status, 400);
    assert!(page.contains("expired"), "{page}");

    // Removing the provider turns the requirement off and ends the sessions.
    state.remove_sso(&org).unwrap();
    let s = alice.client.sso_status(&org).await.unwrap();
    assert!(!s.configured && !s.required && s.session_expires_at.is_none());
    assert!(!alice.client.org(&org).await.unwrap().policies.require_sso);
    alice.client.pull(&vault, 0, 10).await.unwrap();
}
