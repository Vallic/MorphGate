//! A team that requires two-step verification (`require_totp`), as the hosted service enforces
//! it: the reference server has no two-step verification, so a proxy in front of it plays that
//! part for one member. Without it on the account, the team's vaults are left out of the list
//! and refused (`403 totp_setup_required`); the round says why, and a vault already on the device
//! stays there.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use mg_store::account::SharedVault;
use mg_store::sharing;
use mg_store::sync::{Hold, SyncConfig, sync_once};
use mg_store::sync_http::{HttpRemote, create_vault_request, register_request};
use mg_store::{Access, Host, HostAuth, ItemData, LocalVault};
use mg_sync::{B64, DeviceInfo, Role, SyncClient};
use mg_vault::KdfParams;
use serde_json::{Value, json};

mod common;

const PW: &str = "correct horse battery";

struct Device {
    vault: SharedVault,
    client: Arc<SyncClient>,
    account: String,
    email: String,
}

/// The hosted service's check, for whoever syncs through it: `totp` is whether their account
/// has two-step verification on.
#[derive(Clone)]
struct Gate {
    upstream: String,
    http: reqwest::Client,
    org: Arc<Mutex<String>>,
    vaults: Arc<Mutex<HashSet<String>>>,
    totp: Arc<AtomicBool>,
}

impl Gate {
    async fn serve(upstream: &str) -> (String, Gate) {
        let gate = Gate {
            upstream: upstream.into(),
            http: reqwest::Client::new(),
            org: Arc::default(),
            vaults: Arc::default(),
            totp: Arc::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .fallback(forward)
            .with_state(gate.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, gate)
    }

    fn on(&self) -> bool {
        self.totp.load(Ordering::SeqCst)
    }
}

/// Forwards to the reference server, then answers as the hosted service does for an
/// organization that requires two-step verification.
async fn forward(State(g): State<Gate>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let target = format!(
        "{}{}",
        g.upstream,
        req.uri().path_and_query().map_or("", |p| p.as_str())
    );
    let mut headers = HeaderMap::new();
    for name in [header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT] {
        if let Some(v) = req.headers().get(&name) {
            headers.insert(name, v.clone());
        }
    }
    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .unwrap();
    let org = g.org.lock().unwrap().clone();
    let vault = path
        .strip_prefix("/v1/vaults/")
        .and_then(|rest| rest.split('/').next());
    if !g.on() && vault.is_some_and(|v| g.vaults.lock().unwrap().contains(v)) {
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({
                "code": "totp_setup_required",
                "message": "this organization requires two-step verification; turn it on first",
                "org_id": org,
            }),
        );
    }
    let resp = g
        .http
        .request(method.clone(), target)
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap();
    if method != axum::http::Method::GET || !status.is_success() {
        return Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(bytes))
            .unwrap();
    }
    let mut value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return Response::builder()
                .status(status)
                .body(Body::from(bytes))
                .unwrap();
        }
    };
    if path == "/v1/vaults" && !g.on() {
        // Left out of the list, without a word.
        if let Some(list) = value.as_array_mut() {
            list.retain(|v| v["org_id"].as_str() != Some(&org));
        }
    } else if !org.is_empty() && path == format!("/v1/orgs/{org}") {
        value["policies"]["require_totp"] = json!(true);
    } else if path == "/v1/account" {
        value["totp_enabled"] = json!(g.on());
    }
    json_response(status, &value)
}

fn json_response(status: StatusCode, value: &Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(value).unwrap()))
        .unwrap()
}

fn fast() -> LocalVault {
    LocalVault::open_in_memory()
        .unwrap()
        .with_kdf_cost(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1)
}

fn host(label: &str) -> ItemData {
    ItemData::Host(Host {
        label: label.into(),
        hostname: format!("{label}.internal"),
        port: 22,
        user: "deploy".into(),
        auth: HostAuth::Password { password: None },
        jump_ref: None,
        vpn_ref: None,
        theme_ref: None,
        record_sessions: false,
        tags: vec![],
        notes: String::new(),
        group_ref: None,
        identity_ref: None,
        keep_session: false,
        forward_agent: false,
        login_command: None,
        jump_command: None,
        proxy_command: None,
        source: None,
    })
}

/// Someone's first device: a new account with sync on, through `url`.
async fn first(url: &str, name: &str) -> Device {
    let mut v = fast();
    v.create(PW).unwrap();
    let (export, _) = v.export_for_registration(PW).unwrap();
    let client = Arc::new(SyncClient::new(url).unwrap());
    let email = common::email(name);
    let device = DeviceInfo {
        id: ulid::Ulid::generate().to_string(),
        name: name.into(),
        platform: "linux".into(),
        client_version: None,
        public_key: B64(vec![1; 32]),
    };
    let session = client
        .register(&register_request(&export, &email, device.clone(), None))
        .await
        .unwrap();
    client
        .create_vault(&create_vault_request(&export.vault))
        .await
        .unwrap();
    v.enable_sync(&SyncConfig {
        server_url: url.into(),
        email: email.clone(),
        account_id: session.account_id.clone(),
        device_id: device.id,
        device_public_key: [1; 32],
    })
    .unwrap();
    Device {
        vault: Arc::new(Mutex::new(v)),
        client,
        account: session.account_id,
        email,
    }
}

/// One round: the shared part, then the vaults.
async fn round(d: &Device) -> (sharing::RefreshReport, mg_store::sync::SyncReport) {
    let refresh = sharing::refresh(&d.vault, &d.client).await.unwrap();
    let report = sync_once(&d.vault, &HttpRemote(&d.client)).await.unwrap();
    assert!(report.vault_errors.is_empty(), "{:?}", report.vault_errors);
    (refresh, report)
}

fn labels(d: &Device, vault: &str) -> Vec<String> {
    let mut out: Vec<String> = d
        .vault
        .lock()
        .unwrap()
        .items()
        .unwrap()
        .into_iter()
        .filter(|i| i.vault_id == vault)
        .map(|i| match i.data {
            ItemData::Host(h) => h.label,
            _ => String::new(),
        })
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn a_team_that_requires_two_step_verification_says_so() {
    let Some((url, _)) = common::reference_state().await else {
        return;
    };
    let (gated, gate) = Gate::serve(&url).await;
    let alice = first(&url, "alice").await;
    let bob = first(&gated, "bob").await;
    let org = sharing::create_org(&alice.vault, &alice.client, "Acme")
        .await
        .unwrap();
    let prod = sharing::create_vault(&alice.vault, &alice.client, &org, "Production")
        .await
        .unwrap();
    alice
        .vault
        .lock()
        .unwrap()
        .upsert_in(&prod, None, host("db1"))
        .unwrap();
    round(&alice).await;
    *gate.org.lock().unwrap() = org.clone();
    gate.vaults.lock().unwrap().insert(prod.clone());

    // Bob joins with access to Production, without two-step verification: the vault list leaves
    // it out and says nothing; the round finds out why.
    let invite = sharing::invite(
        &alice.client,
        &org,
        &bob.email,
        Role::Member,
        vec![(prod.clone(), Access::Read)],
    )
    .await
    .unwrap();
    let token = invite.token.unwrap();
    let preview = sharing::preview_invite(&bob.client, &token).await.unwrap();
    sharing::accept_invite(&bob.vault, &bob.client, &token, &preview.owner_fingerprint)
        .await
        .unwrap();
    round(&bob).await;
    let keys = bob.vault.lock().unwrap().public_keys().unwrap();
    let bob_fp = mg_vault::sharing::fingerprint(&bob.account, &keys);
    sharing::confirm_member(&alice.vault, &alice.client, &org, &bob.account, &bob_fp)
        .await
        .unwrap();
    let (refresh, _) = round(&bob).await;
    assert_eq!(refresh.held, [(org.clone(), Hold::Totp)]);
    assert!(labels(&bob, &prod).is_empty());

    // With it on, the vault comes.
    gate.totp.store(true, Ordering::SeqCst);
    let (refresh, report) = round(&bob).await;
    assert!(refresh.held.is_empty(), "{:?}", refresh.held);
    assert!(report.held.is_empty(), "{:?}", report.held);
    assert_eq!(labels(&bob, &prod), ["db1"]);

    // Turned off again: the vault stays on the device, and both parts of the round say why.
    gate.totp.store(false, Ordering::SeqCst);
    let (refresh, report) = round(&bob).await;
    assert_eq!(refresh.held, [(org.clone(), Hold::Totp)]);
    assert_eq!(report.held, [(org.clone(), Hold::Totp)]);
    assert_eq!(labels(&bob, &prod), ["db1"]);

    // Alice, whom the requirement doesn't hold back, sees nothing of it.
    let (refresh, _) = round(&alice).await;
    assert!(refresh.held.is_empty(), "{:?}", refresh.held);
}
