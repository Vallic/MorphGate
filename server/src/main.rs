//! `vault-sync-server [--listen ADDR] [--db PATH] [--registration open|closed] [--blob-quota-mb N]
//!                    [--public-url URL]`
//!
//! `vault-sync-server sso --db PATH --org ID|NAME --issuer URL --client-id ID --client-secret SECRET
//!                    [--session-hours 12] [--require]`
//! `vault-sync-server sso --db PATH --org ID|NAME --remove`
//!
//! `vault-sync-server scim --db PATH --org ID|NAME [--public-url URL]`
//! `vault-sync-server scim --db PATH --org ID|NAME --revoke`
//!
//! Environment equivalents: `VAULT_SYNC_LISTEN`, `VAULT_SYNC_DB`, `VAULT_SYNC_REGISTRATION`,
//! `VAULT_SYNC_BLOB_QUOTA_MB`, `VAULT_SYNC_PUBLIC_URL`. Serves plain HTTP; put it behind a TLS
//! reverse proxy (Caddy, nginx) for anything but localhost.

use std::path::PathBuf;

use vault_sync_server::{AppState, Config, SsoProvider, router};

const USAGE: &str = "vault-sync-server [--listen 127.0.0.1:8443] [--db vault-sync.sqlite3] [--registration open|closed] [--blob-quota-mb 1024] [--public-url https://sync.example.com]
vault-sync-server sso --db PATH --org ID|NAME --issuer URL --client-id ID --client-secret SECRET [--session-hours 12] [--require]
vault-sync-server sso --db PATH --org ID|NAME --remove
vault-sync-server scim --db PATH --org ID|NAME [--public-url https://sync.example.com]
vault-sync-server scim --db PATH --org ID|NAME --revoke";

struct Args {
    listen: String,
    db: PathBuf,
    registration_open: bool,
    blob_quota_mb: u64,
    public_url: Option<String>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn default_db() -> PathBuf {
    env("VAULT_SYNC_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| "vault-sync.sqlite3".into())
}

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        listen: env("VAULT_SYNC_LISTEN").unwrap_or_else(|| "127.0.0.1:8443".into()),
        db: default_db(),
        registration_open: env("VAULT_SYNC_REGISTRATION").is_none_or(|v| v != "closed"),
        blob_quota_mb: env("VAULT_SYNC_BLOB_QUOTA_MB")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024),
        public_url: env("VAULT_SYNC_PUBLIC_URL"),
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => args.listen = value()?,
            "--db" => args.db = value()?.into(),
            "--blob-quota-mb" => {
                args.blob_quota_mb = value()?
                    .parse()
                    .map_err(|_| "--blob-quota-mb needs a number of MiB".to_string())?
            }
            "--public-url" => args.public_url = Some(value()?),
            "--registration" => {
                args.registration_open = match value()?.as_str() {
                    "open" => true,
                    "closed" => false,
                    other => {
                        return Err(format!(
                            "--registration must be open or closed, not {other}"
                        ));
                    }
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(args)
}

/// `sso …`: sets or removes an organization's identity provider in the database.
fn sso(mut it: impl Iterator<Item = String>) -> Result<String, String> {
    let (mut db, mut org, mut remove, mut require) = (default_db(), None, false, false);
    let mut provider = SsoProvider {
        issuer: String::new(),
        client_id: String::new(),
        client_secret: String::new(),
        session_hours: 12,
    };
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--db" => db = value()?.into(),
            "--org" => org = Some(value()?),
            "--issuer" => provider.issuer = value()?.trim_end_matches('/').to_owned(),
            "--client-id" => provider.client_id = value()?,
            "--client-secret" => provider.client_secret = value()?,
            "--session-hours" => {
                provider.session_hours = value()?
                    .parse()
                    .ok()
                    .filter(|h| (1..=720).contains(h))
                    .ok_or("--session-hours is 1 to 720")?
            }
            "--require" => require = true,
            "--remove" => remove = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let org = org.ok_or("--org is required")?;
    let state = AppState::open(&db, Config::default())?;
    if remove {
        let id = state.remove_sso(&org)?;
        return Ok(format!("removed single sign-on from {id}"));
    }
    if !provider.issuer.starts_with("https://") && !provider.issuer.starts_with("http://") {
        return Err("--issuer must be the provider's URL".into());
    }
    if provider.client_id.is_empty() || provider.client_secret.is_empty() {
        return Err("--client-id and --client-secret are required".into());
    }
    let id = state.set_sso(&org, &provider, require)?;
    Ok(format!(
        "{id} signs in at {}{}",
        provider.issuer,
        if require { " (required)" } else { "" }
    ))
}

/// `scim …`: a new SCIM token for an organization (the old one stops working), or `--revoke`.
fn scim(mut it: impl Iterator<Item = String>) -> Result<String, String> {
    let (mut db, mut org, mut revoke) = (default_db(), None, false);
    let mut public_url = env("VAULT_SYNC_PUBLIC_URL");
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--db" => db = value()?.into(),
            "--org" => org = Some(value()?),
            "--public-url" => public_url = Some(value()?),
            "--revoke" => revoke = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let org = org.ok_or("--org is required")?;
    let state = AppState::open(&db, Config::default())?;
    if revoke {
        let id = state.revoke_scim(&org)?;
        return Ok(format!("{id} has no SCIM token now"));
    }
    let (id, token) = state.scim_token(&org)?;
    let base = public_url.as_deref().unwrap_or("<public URL>");
    Ok(format!(
        "SCIM base URL: {}/scim/v2/{id}\nBearer token (shown once; it replaces any earlier one): {token}",
        base.trim_end_matches('/')
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let mut it = std::env::args().skip(1).peekable();
    if let Some(command) = it.next_if(|a| a == "sso" || a == "scim") {
        let done = if command == "sso" { sso(it) } else { scim(it) };
        match done {
            Ok(done) => println!("{done}"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
        return;
    }
    let args = match parse(it) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let public_url = args
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.listen));
    let state = AppState::open(
        &args.db,
        Config {
            registration_open: args.registration_open,
            blob_quota_bytes: args.blob_quota_mb * 1024 * 1024,
            public_url,
            ..Config::default()
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("error: cannot open {}: {e}", args.db.display());
        std::process::exit(1);
    });
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: cannot listen on {}: {e}", args.listen);
            std::process::exit(1);
        });
    tracing::info!(
        listen = %args.listen,
        db = %args.db.display(),
        registration = if args.registration_open { "open" } else { "closed" },
        "vault-sync server ready"
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server error");
}
