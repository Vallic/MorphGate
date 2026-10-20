//! `vault-conform`: checks a `vault-sync/v1` server against the spec (`spec/openapi.yaml`),
//! endpoint by endpoint, with throwaway accounts, and reports what passed, what failed (with the
//! server's answer) and what was skipped (and why).
//!
//! Most checks speak the protocol with placeholder key material (servers only check sizes and
//! shapes, never the cryptography); the sharing checks use the app's own store and sync engine,
//! so trust, keys and grants are real.

mod checks;
mod fake;
pub mod report;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mg_sync::{Capabilities, SyncClient};
use serde_json::Value;

pub use report::{Check, Outcome, Report};

/// The groups of checks, in the order they run.
pub const GROUPS: &[&str] = &[
    "discovery",
    "auth",
    "account",
    "vaults",
    "blobs",
    "sharing",
    "exports",
    "scim",
];

#[derive(Clone, Debug)]
pub struct Options {
    /// The server's origin, e.g. `https://sync.example.com`.
    pub server: String,
    /// Domain of the throwaway accounts' addresses.
    pub email_domain: String,
    /// Run only these groups (empty: every group).
    pub only: Vec<String>,
    /// A shell command that makes the server purge tombstones now, for the `410` check.
    pub purge_command: Option<String>,
    /// SCIM: the organization's id and its bearer token.
    pub scim: Option<(String, String)>,
    /// A Mailpit server that receives the server's mail (ddev ships one), for invites the
    /// server mails instead of returning their token.
    pub mailpit: Option<String>,
}

impl Options {
    pub fn new(server: &str) -> Self {
        Self {
            server: server.trim_end_matches('/').to_owned(),
            email_domain: "example.com".into(),
            only: Vec::new(),
            purge_command: None,
            scim: None,
            mailpit: None,
        }
    }
}

/// What every check needs: the server, its capabilities, unique addresses and raw HTTP.
pub struct Ctx {
    pub opts: Options,
    pub caps: Option<Capabilities>,
    run: String,
    next: AtomicUsize,
    http: reqwest::Client,
    /// Accounts groups share, to stay under servers' registration limits: one that owns things,
    /// one that tries to read them.
    shared: tokio::sync::OnceCell<Result<Arc<SyncClient>, String>>,
    outsider: tokio::sync::OnceCell<Result<Arc<SyncClient>, String>>,
}

/// A raw response: status, JSON body (`Null` when there is none) and headers.
pub struct Raw {
    pub status: u16,
    pub body: Value,
    pub headers: reqwest::header::HeaderMap,
}

impl Ctx {
    fn new(opts: Options) -> Self {
        let run = ulid::Ulid::generate().to_string()[16..].to_lowercase();
        Self {
            opts,
            caps: None,
            run,
            next: AtomicUsize::new(0),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("an HTTP client"),
            shared: tokio::sync::OnceCell::new(),
            outsider: tokio::sync::OnceCell::new(),
        }
    }

    /// A fresh address for a throwaway account.
    pub fn email(&self, name: &str) -> String {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        format!("conform-{}-{name}{n}@{}", self.run, self.opts.email_domain)
    }

    pub fn client(&self) -> Result<SyncClient, String> {
        SyncClient::new(&self.opts.server).map_err(|e| e.to_string())
    }

    /// The account groups share for vaults, blobs and exports (made on first use).
    pub async fn shared(&self) -> Result<Arc<SyncClient>, String> {
        self.shared
            .get_or_init(|| async {
                fake::account(self, "owner", 1)
                    .await
                    .map(|(c, _, _)| Arc::new(c))
            })
            .await
            .clone()
    }

    /// Another account, to check that the shared one's things stay private.
    pub async fn outsider(&self) -> Result<Arc<SyncClient>, String> {
        self.outsider
            .get_or_init(|| async {
                fake::account(self, "outsider", 2)
                    .await
                    .map(|(c, _, _)| Arc::new(c))
            })
            .await
            .clone()
    }

    /// New accounts can be made here without a mailbox.
    pub fn accounts(&self) -> Result<(), &'static str> {
        match &self.caps {
            None => Err("the capabilities document didn't load"),
            Some(c) if !c.features.registration_open => {
                Err("the server doesn't accept new accounts")
            }
            Some(c) if c.features.email_verification && self.opts.mailpit.is_none() => {
                Err("registering needs a mailed code: pass --mailpit URL to read it")
            }
            Some(_) => Ok(()),
        }
    }

    /// A request outside the client's happy path (error cases, endpoints it doesn't call).
    pub async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<Raw, String> {
        let url = format!("{}/v1/{}", self.opts.server, path.trim_start_matches('/'));
        let mut req = self.http.request(method, url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok(Raw {
            status,
            body: serde_json::from_str(&text).unwrap_or(Value::Null),
            headers,
        })
    }

    /// The newest one-time code mailed to `to` (`"123456 is your … code"`, or a line of its own),
    /// read from Mailpit; waits up to 20 s for a mail newer than `after` (Mailpit ids).
    pub async fn mailed_code(&self, to: &str, seen: &[String]) -> Result<String, String> {
        for _ in 0..40 {
            for (id, subject, text) in self.mails_to(to).await? {
                if seen.contains(&id) {
                    continue;
                }
                let first = subject.split_whitespace().next().unwrap_or_default();
                let code = if (4..=12).contains(&first.len())
                    && first.chars().all(|c| c.is_ascii_alphanumeric())
                {
                    Some(first.to_owned())
                } else {
                    text.lines()
                        .map(str::trim)
                        .find(|l| {
                            (4..=12).contains(&l.len())
                                && l.chars().all(|c| c.is_ascii_alphanumeric())
                        })
                        .map(str::to_owned)
                };
                if let Some(code) = code {
                    return Ok(code);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(format!("no code mailed to {to} reached Mailpit"))
    }

    /// `(id, subject, text)` of the mails to `to`, newest first.
    async fn mails_to(&self, to: &str) -> Result<Vec<(String, String, String)>, String> {
        let base = self
            .opts
            .mailpit
            .as_deref()
            .ok_or("no --mailpit to read mail from")?;
        let base = base.trim_end_matches('/');
        let search = reqwest::Url::parse_with_params(
            &format!("{base}/api/v1/search"),
            &[("query", format!("to:\"{to}\"")), ("limit", "10".into())],
        )
        .map_err(|e| e.to_string())?;
        let found: Value = self
            .http
            .get(search)
            .send()
            .await
            .map_err(|e| format!("Mailpit: {e}"))?
            .json()
            .await
            .map_err(|e| format!("Mailpit: {e}"))?;
        let mut out = Vec::new();
        for m in found["messages"].as_array().into_iter().flatten() {
            let Some(id) = m["ID"].as_str() else { continue };
            let msg: Value = self
                .http
                .get(format!("{base}/api/v1/message/{id}"))
                .send()
                .await
                .map_err(|e| format!("Mailpit: {e}"))?
                .json()
                .await
                .map_err(|e| format!("Mailpit: {e}"))?;
            out.push((
                id.to_owned(),
                m["Subject"].as_str().unwrap_or_default().to_owned(),
                msg["Text"].as_str().unwrap_or_default().to_owned(),
            ));
        }
        Ok(out)
    }

    /// A code for registering `email`: asks the server to mail one and reads it (servers that
    /// verify addresses); `None` where no code is needed.
    pub async fn registration_code(
        &self,
        c: &SyncClient,
        email: &str,
    ) -> Result<Option<String>, String> {
        if !self
            .caps
            .as_ref()
            .is_some_and(|c| c.features.email_verification)
        {
            return Ok(None);
        }
        c.start_registration(email)
            .await
            .map_err(|e| format!("asking for a code for {email}: {e}"))?;
        self.mailed_code(email, &[]).await.map(Some)
    }

    /// The invite token mailed to `to`, read from Mailpit (waits up to 20 s for the mail).
    pub async fn mailed_invite(&self, to: &str) -> Result<String, String> {
        let base = self
            .opts
            .mailpit
            .as_deref()
            .ok_or("no --mailpit to read the invite from")?;
        let base = base.trim_end_matches('/');
        let search = reqwest::Url::parse_with_params(
            &format!("{base}/api/v1/search"),
            &[("query", format!("to:\"{to}\"")), ("limit", "5".into())],
        )
        .map_err(|e| e.to_string())?;
        for _ in 0..40 {
            let found: Value = self
                .http
                .get(search.clone())
                .send()
                .await
                .map_err(|e| format!("Mailpit: {e}"))?
                .json()
                .await
                .map_err(|e| format!("Mailpit: {e}"))?;
            for m in found["messages"].as_array().into_iter().flatten() {
                let Some(id) = m["ID"].as_str() else { continue };
                let msg: Value = self
                    .http
                    .get(format!("{base}/api/v1/message/{id}"))
                    .send()
                    .await
                    .map_err(|e| format!("Mailpit: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("Mailpit: {e}"))?;
                let text = msg["Text"].as_str().unwrap_or_default();
                if let Some(at) = text.find("/invite/") {
                    let token: String = text[at + 8..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                        .collect();
                    if token.len() >= 16 {
                        return Ok(token);
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(format!("no invite mail to {to} reached Mailpit"))
    }

    fn wanted(&self, group: &str) -> bool {
        self.opts.only.is_empty() || self.opts.only.iter().any(|g| g == group)
    }
}

/// Runs the checks and returns the report.
pub async fn run(opts: Options) -> Report {
    let mut ctx = Ctx::new(opts);
    let mut r = Report {
        server: ctx.opts.server.clone(),
        checks: Vec::new(),
    };
    // Discovery always runs: the rest depends on what the server says it offers.
    checks::discovery::run(&mut ctx, &mut r).await;
    if ctx.wanted("auth") {
        checks::auth::run(&ctx, &mut r).await;
    }
    if ctx.wanted("account") {
        checks::account::run(&ctx, &mut r).await;
    }
    if ctx.wanted("vaults") {
        checks::vaults::run(&ctx, &mut r).await;
    }
    if ctx.wanted("blobs") {
        checks::blobs::run(&ctx, &mut r).await;
    }
    if ctx.wanted("sharing") {
        checks::sharing::run(&ctx, &mut r).await;
    }
    if ctx.wanted("exports") {
        checks::exports::run(&ctx, &mut r).await;
    }
    if ctx.wanted("scim") {
        checks::scim::run(&ctx, &mut r).await;
    }
    r
}
