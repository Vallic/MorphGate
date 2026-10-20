//! The server under test. By default an in-process reference server per test; with
//! `VAULT_SYNC_URL=https://…` the same tests run against any vault-sync/v1 implementation
//! (it must accept new accounts), which makes them a conformance suite:
//!
//! ```sh
//! VAULT_SYNC_URL=http://127.0.0.1:8890 cargo test -p vault-sync-server --test protocol --test e2e --test account
//! ```

#![allow(dead_code)]

use vault_sync_server::{AppState, Config, router};

pub fn external() -> Option<String> {
    std::env::var("VAULT_SYNC_URL")
        .ok()
        .map(|u| u.trim_end_matches('/').to_owned())
        .filter(|u| !u.is_empty())
}

async fn reference(registration_open: bool) -> String {
    serve(Config {
        registration_open,
        ..Config::default()
    })
    .await
    .0
}

/// Serves an in-process reference server; its public URL is where it listens.
async fn serve(mut config: Config) -> (String, AppState) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    config.public_url = url.clone();
    let state = AppState::in_memory(config).unwrap();
    let app = state.clone();
    tokio::spawn(async move { axum::serve(listener, router(app)).await.unwrap() });
    (url, state)
}

/// A server that accepts new accounts.
pub async fn server() -> String {
    match external() {
        Some(url) => url,
        None => reference(true).await,
    }
}

/// An in-process reference server with `config` (`None` when testing an external server).
pub async fn reference_with(config: Config) -> Option<String> {
    if external().is_some() {
        return None;
    }
    Some(serve(config).await.0)
}

/// An in-process reference server and its state, to configure what only an operator can (an
/// identity provider, say); `None` when testing an external server.
pub async fn reference_state() -> Option<(String, AppState)> {
    if external().is_some() {
        return None;
    }
    Some(serve(Config::default()).await)
}

/// A server with registration closed; only the in-process one can be configured that way.
pub async fn closed_server() -> Option<String> {
    match external() {
        Some(_) => None,
        None => Some(reference(false).await),
    }
}

/// An email no other test (or earlier run against the same server) has used.
pub fn email(name: &str) -> String {
    format!(
        "{name}-{}@example.com",
        ulid::Ulid::generate().to_string().to_lowercase()
    )
}
