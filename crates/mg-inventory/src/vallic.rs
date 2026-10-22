//! Vallic Cloud: signing in on the console (OAuth device authorization, RFC 8628), its API
//! (`/api/vc/v1`), and an environment's SSH target as hosts, the way `vallic ssh` reaches them
//! (github.com/Vallic/vallic-cli, `internal/ssh`).

use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, InventoryHost, Result};

/// The console, which is also the authorization server.
pub const CONSOLE: &str = "https://console.vallic.com";

/// The client MorphGate signs in as: the CLI's, which is public, with no secret (the person signs
/// in, in the browser), so naming it selects a configuration and proves nothing.
pub const CLIENT_ID: &str = "vallic-cli";

const API: &str = "/api/vc/v1";
const NAME: &str = "Vallic Cloud";

/// What the console answers a sign-in request with: the code to show, and where to type it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct DeviceAuth {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    /// Seconds between polls (5 unless the console says).
    #[serde(default)]
    pub interval: Option<u64>,
}

/// One look at a sign-in in progress.
#[derive(Debug)]
pub enum Poll {
    /// Not approved yet: ask again after the interval.
    Pending,
    /// Asked too often: wait 5 seconds longer each time.
    SlowDown,
    Approved(Tokens),
    /// Declined in the browser.
    Denied,
    /// The code ran out before it was used.
    Expired,
}

#[derive(Clone, Debug)]
pub struct Tokens {
    pub access: String,
    /// A new one with every refresh: the previous one stops working (and using it again is
    /// refused, ending the sign-in).
    pub refresh: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Me {
    pub user: MeUser,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MeUser {
    pub id: u64,
    #[serde(default, deserialize_with = "nullable")]
    pub name: String,
    #[serde(default, deserialize_with = "nullable")]
    pub email: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Team {
    pub id: u64,
    pub machine_name: String,
    pub label: String,
    #[serde(default, deserialize_with = "nullable")]
    pub role: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Project {
    pub id: u64,
    pub label: String,
    pub machine_name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Environment {
    pub id: u64,
    #[serde(default, deserialize_with = "nullable")]
    pub slug: String,
    #[serde(default, deserialize_with = "nullable")]
    pub name: String,
    #[serde(default, deserialize_with = "nullable")]
    pub project: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnvironmentDetail {
    #[serde(flatten)]
    pub environment: Environment,
    /// Null where the person's role has no shell, or nothing runs the environment yet.
    #[serde(default, deserialize_with = "nullable")]
    pub ssh: Option<SshTarget>,
}

/// Where `ssh` goes, as the console describes it. Nothing here may be derived: the port, for one,
/// is random per project.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// The environment's name where its machine and port carry several (staging and
    /// development): the forced command's first word.
    #[serde(default, deserialize_with = "nullable")]
    pub name: String,
    /// The machines bound to it, the one `host` reaches among them where that runs the site;
    /// none of them can be jumped to where there's one and it runs the site (see [`hosts_of`]).
    #[serde(default, deserialize_with = "nullable")]
    pub machines: Vec<Machine>,
    /// The machine a plain login goes to where `host` runs no site.
    #[serde(default, deserialize_with = "nullable")]
    pub jump_to: String,
    /// The worker containers, by name.
    #[serde(default, deserialize_with = "nullable")]
    pub workers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Machine {
    pub name: String,
    #[serde(default, deserialize_with = "nullable")]
    pub role: String,
}

/// An optional field: absent and `null` both read as empty. The console sends `null` for a value
/// that doesn't apply (an environment's name in production, `jump_to` where the front runs the
/// site) rather than leaving the key out.
fn nullable<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// The console's client.
#[derive(Clone)]
pub struct Vallic {
    http: reqwest::Client,
    base: Url,
}

impl Vallic {
    /// The console at `base` (default [`CONSOLE`]): `https://`, or `http://` on this computer.
    pub fn new(base: Option<&str>) -> Result<Self> {
        let base = base
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .unwrap_or(CONSOLE);
        let mut url = Url::parse(base).map_err(|e| Error::Api(format!("{base}: {e}")))?;
        let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(url.scheme() == "https" || (url.scheme() == "http" && local)) {
            return Err(Error::Api(format!(
                "{base}: the console's address starts with https://"
            )));
        }
        url.set_path("/");
        url.set_query(None);
        let http = reqwest::Client::builder()
            .user_agent(concat!("MorphGate/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Api(e.to_string()))?;
        Ok(Vallic { http, base: url })
    }

    /// The console's address (`https://console.vallic.com`).
    pub fn base(&self) -> &str {
        self.base.as_str().trim_end_matches('/')
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base())
    }

    fn unreachable(&self, e: reqwest::Error) -> Error {
        Error::Unreachable(self.base().to_owned(), e.to_string())
    }

    /// Starts a sign-in: the person types `user_code` at `verification_uri`, and [`poll`]
    /// finds out when they have. `device_name` is what the console's list of sessions calls it.
    ///
    /// [`poll`]: Vallic::poll
    pub async fn sign_in(&self, device_name: &str) -> Result<DeviceAuth> {
        let response = self
            .http
            .post(self.url("/oauth/device_authorization"))
            .form(&[("client_id", CLIENT_ID), ("device_name", device_name)])
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        if !response.status().is_success() {
            return Err(Error::Api(oauth_message(response).await));
        }
        let auth: DeviceAuth = response.json().await.map_err(|e| self.unreachable(e))?;
        if auth.device_code.is_empty()
            || auth.user_code.is_empty()
            || auth.verification_uri.is_empty()
        {
            return Err(Error::Api(
                "the console's sign-in answer is missing a field".into(),
            ));
        }
        Ok(auth)
    }

    /// Whether the person has approved the sign-in yet.
    pub async fn poll(&self, device_code: &str) -> Result<Poll> {
        match self
            .token(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", CLIENT_ID),
            ])
            .await?
        {
            Ok(tokens) => Ok(Poll::Approved(tokens)),
            Err(e) => match e.error.as_str() {
                "authorization_pending" => Ok(Poll::Pending),
                "slow_down" => Ok(Poll::SlowDown),
                "access_denied" => Ok(Poll::Denied),
                "expired_token" => Ok(Poll::Expired),
                _ => Err(Error::Api(describe(&e))),
            },
        }
    }

    /// New tokens for a refresh token. A refused one ([`Error::SignedOut`]) means signing in again.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens> {
        match self
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", CLIENT_ID),
            ])
            .await?
        {
            Ok(tokens) => Ok(tokens),
            Err(e) if e.error == "invalid_grant" => Err(Error::SignedOut(NAME.into())),
            Err(e) => Err(Error::Api(describe(&e))),
        }
    }

    /// Ends a sign-in on the console.
    pub async fn sign_out(&self, refresh_token: &str) -> Result<()> {
        self.http
            .post(self.url("/oauth/revoke"))
            .form(&[("token", refresh_token), ("client_id", CLIENT_ID)])
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        Ok(())
    }

    async fn token(
        &self,
        form: &[(&str, &str)],
    ) -> Result<std::result::Result<Tokens, OAuthError>> {
        let response = self
            .http
            .post(self.url("/oauth/token"))
            .form(form)
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        if response.status().is_success() {
            let t: TokenResponse = response.json().await.map_err(|e| self.unreachable(e))?;
            return Ok(Ok(Tokens {
                access: t.access_token,
                refresh: t.refresh_token,
                expires_in: t.expires_in,
            }));
        }
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        match serde_json::from_str::<OAuthError>(&text) {
            Ok(e) => Ok(Err(e)),
            Err(_) => Err(Error::Api(format!("the console answered {status}"))),
        }
    }

    async fn get<T: DeserializeOwned>(&self, access: &str, path: &str) -> Result<T> {
        let response = self
            .http
            .get(self.url(&format!("{API}{path}")))
            .bearer_auth(access)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        match response.status().as_u16() {
            200..=299 => {
                let text = response.text().await.map_err(|e| self.unreachable(e))?;
                serde_json::from_str(&text).map_err(|e| {
                    Error::Api(format!(
                        "Vallic Cloud's answer to {path} isn't one this version can read ({e})"
                    ))
                })
            }
            401 => Err(Error::SignedOut(NAME.into())),
            status => Err(Error::Api(format!(
                "{path}: the console answered {status}{}",
                api_message(response).await
            ))),
        }
    }

    pub async fn me(&self, access: &str) -> Result<Me> {
        self.get(access, "/me").await
    }

    pub async fn teams(&self, access: &str) -> Result<Vec<Team>> {
        #[derive(Deserialize)]
        struct Out {
            teams: Vec<Team>,
        }
        Ok(self.get::<Out>(access, "/teams").await?.teams)
    }

    pub async fn projects(&self, access: &str) -> Result<Vec<Project>> {
        #[derive(Deserialize)]
        struct Out {
            projects: Vec<Project>,
        }
        Ok(self.get::<Out>(access, "/projects").await?.projects)
    }

    pub async fn environments(&self, access: &str) -> Result<Vec<Environment>> {
        #[derive(Deserialize)]
        struct Out {
            environments: Vec<Environment>,
        }
        Ok(self.get::<Out>(access, "/environments").await?.environments)
    }

    pub async fn environment(&self, access: &str, id: u64) -> Result<EnvironmentDetail> {
        #[derive(Deserialize)]
        struct Out {
            environment: EnvironmentDetail,
        }
        Ok(self
            .get::<Out>(access, &format!("/environments/{id}"))
            .await?
            .environment)
    }

    /// Puts a public key on the person's account (needs a sign-in, not a personal access token).
    pub async fn add_ssh_key(&self, access: &str, label: &str, public_key: &str) -> Result<()> {
        let response = self
            .http
            .post(self.url(&format!("{API}/me/ssh-keys")))
            .bearer_auth(access)
            .json(&serde_json::json!({ "label": label, "public_key": public_key }))
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 => Err(Error::SignedOut(NAME.into())),
            status => Err(Error::Api(format!(
                "adding the key: the console answered {status}{}",
                api_message(response).await
            ))),
        }
    }

    /// Everything the sign-in reaches, as hosts.
    pub async fn inventory(&self, access: &str) -> Result<Inventory> {
        let projects = self.projects(access).await?;
        let environments = self.environments(access).await?;
        let mut details = tokio::task::JoinSet::new();
        for e in environments {
            let (client, access) = (self.clone(), access.to_owned());
            details.spawn(async move { client.environment(&access, e.id).await });
        }
        let mut hosts = Vec::new();
        let mut without_shell = Vec::new();
        while let Some(detail) = details.join_next().await {
            let detail = detail.map_err(|e| Error::Api(e.to_string()))??;
            let project = projects
                .iter()
                .find(|p| p.id == detail.environment.project)
                .map_or_else(
                    || format!("Project {}", detail.environment.project),
                    |p| p.label.clone(),
                );
            match &detail.ssh {
                Some(target) => hosts.extend(hosts_of(&project, &detail.environment, target)),
                None => {
                    without_shell.push(format!("{project} · {}", env_name(&detail.environment)))
                }
            }
        }
        hosts.sort_by(|a, b| (&a.group, &a.label).cmp(&(&b.group, &b.label)));
        without_shell.sort();
        Ok(Inventory {
            projects,
            hosts,
            without_shell,
        })
    }
}

/// What a sign-in reaches.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub projects: Vec<Project>,
    pub hosts: Vec<InventoryHost>,
    /// Environments with no shell for this person (their role), or not running yet.
    pub without_shell: Vec<String>,
}

/// A sign-in on one device: the refresh token it keeps, and the access token in use (15
/// minutes).
pub struct Session {
    refresh: String,
    access: Option<(String, Instant)>,
}

impl Session {
    pub fn new(refresh: String) -> Self {
        Session {
            refresh,
            access: None,
        }
    }

    pub fn from_tokens(t: Tokens) -> Self {
        let mut s = Session::new(t.refresh);
        s.access = Some((t.access, expiry(t.expires_in)));
        s
    }

    /// The refresh token to keep: it changes when [`access`](Session::access) refreshes.
    pub fn refresh_token(&self) -> &str {
        &self.refresh
    }

    /// An access token, refreshing when the one in use is about to run out.
    pub async fn access(&mut self, v: &Vallic) -> Result<String> {
        if let Some((token, until)) = &self.access
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let t = v.refresh(&self.refresh).await?;
        self.refresh = t.refresh;
        self.access = Some((t.access.clone(), expiry(t.expires_in)));
        Ok(t.access)
    }
}

/// When an access token stops being worth using: a minute before it expires.
fn expiry(expires_in: u64) -> Instant {
    Instant::now() + Duration::from_secs(expires_in.clamp(60, 3600) - 60)
}

fn env_name(e: &Environment) -> String {
    if e.name.is_empty() {
        e.slug.clone()
    } else {
        e.name.clone()
    }
}

/// An environment as hosts, the way `vallic ssh` reaches them:
/// - one host where it runs on one machine: `host`, its name as the login command where the
///   machine carries several environments;
/// - on several, the front (`host`) as a jump host, and a host per machine carried on from it by
///   `<name> jump <machine>`, under the name `<machine>.<host>` (the host key's); the environment's
///   own host is `jump_to`'s, or the front's where there is none;
/// - a host per worker, opened as `<name> @<worker>` on the worker machine.
pub fn hosts_of(project: &str, env: &Environment, t: &SshTarget) -> Vec<InventoryHost> {
    let name = env_name(env);
    let id = format!("env:{}", env.id);
    let words = |rest: &str| -> Option<String> {
        let all: Vec<&str> = [t.name.as_str(), rest]
            .into_iter()
            .filter(|w| !w.is_empty())
            .collect();
        (!all.is_empty()).then(|| all.join(" "))
    };
    let host = |external_id: String, label: String, hostname: String| InventoryHost {
        external_id,
        group: project.to_owned(),
        label,
        hostname,
        port: t.port,
        user: t.user.clone(),
        login_command: words(""),
        jump: None,
        jump_command: None,
        no_sftp: true,
        no_forwarding: true,
        state: None,
        key_name: None,
        via: None,
        host_keys: Vec::new(),
        tags: Vec::new(),
    };
    // The front: a host of its own where a plain login goes on to another machine (`jump_to`),
    // else the environment's own host.
    let front = if t.jump_to.is_empty() {
        id.clone()
    } else {
        format!("{id}/front")
    };
    let through_front = |machine: &str| -> (Option<String>, Option<String>) {
        (Some(front.clone()), words(&format!("jump {machine}")))
    };
    let mut out = Vec::new();
    if !t.jump_to.is_empty() {
        out.push(host(
            front.clone(),
            format!("{project} · {name} (front)"),
            t.host.clone(),
        ));
    }
    // The environment itself.
    let mut own = host(id.clone(), format!("{project} · {name}"), t.host.clone());
    if !t.jump_to.is_empty() {
        own.hostname = format!("{}.{}", t.jump_to, t.host);
        (own.jump, own.jump_command) = through_front(&t.jump_to);
    }
    out.push(own);
    // Its other machines. The console lists the machine `host` reaches too, and an environment on
    // one machine that runs the site has none to jump to: the agent's `jump` refuses ("no other
    // machine to jump to"), as it carries on only where there are two or the front runs none.
    let machines: &[Machine] = if t.machines.len() < 2 && t.jump_to.is_empty() {
        &[]
    } else {
        &t.machines
    };
    for m in machines.iter().filter(|m| m.name != t.jump_to) {
        let mut h = host(
            format!("{id}/{}", m.name),
            match m.role.as_str() {
                "" => format!("{project} · {name} · {}", m.name),
                role => format!("{project} · {name} · {} ({role})", m.name),
            },
            format!("{}.{}", m.name, t.host),
        );
        (h.jump, h.jump_command) = through_front(&m.name);
        out.push(h);
    }
    // Its workers, on the worker machine where there is one.
    let worker_machine = machines.iter().find(|m| m.role == "worker");
    for w in &t.workers {
        let short = w.strip_prefix("worker-").unwrap_or(w);
        let mut h = host(
            format!("{id}/@{w}"),
            format!("{project} · {name} · {short}"),
            t.host.clone(),
        );
        h.login_command = words(&format!("@{w}"));
        if let Some(m) = worker_machine {
            h.hostname = format!("{}.{}", m.name, t.host);
            (h.jump, h.jump_command) = through_front(&m.name);
        }
        out.push(h);
    }
    out
}

async fn oauth_message(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<OAuthError>().await {
        Ok(e) => describe(&e),
        Err(_) => format!("the console answered {status}"),
    }
}

fn describe(e: &OAuthError) -> String {
    match &e.error_description {
        Some(d) if !d.is_empty() => format!("{} ({})", d, e.error),
        _ => e.error.clone(),
    }
}

/// The message in an API error answer (`{"message": …}` or `{"error": …}`), as ": …".
async fn api_message(response: reqwest::Response) -> String {
    let text = response.text().await.unwrap_or_default();
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("error"))
                .and_then(|m| m.as_str())
                .map(|m| format!(": {m}"))
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(id: u64, name: &str) -> Environment {
        Environment {
            id,
            slug: name.to_lowercase(),
            name: name.into(),
            project: 1,
        }
    }

    fn target(json: serde_json::Value) -> SshTarget {
        serde_json::from_value(json).unwrap()
    }

    /// `GET /environments/{id}` as console.vallic.com answers it for production: `name` and
    /// `jump_to` null, fields this client doesn't use.
    #[test]
    fn reads_the_consoles_environment() {
        let detail: EnvironmentDetail = serde_json::from_value(serde_json::json!({
            "id": 2686, "slug": "acme-production", "name": "Production", "type": "production",
            "state": "running", "git_ref": "main", "project": 41,
            "current_release": null, "auto_deploy": true, "protected": true,
            "hostnames": { "platform": "acme.vallic.app", "primary": null, "routed": [], "url": "https://acme.vallic.app" },
            "ssh": {
                "host": "production.acme.vallic.cloud", "port": 2417, "user": "vc-t-acme",
                "name": null, "machines": [{ "name": "acme-production-web", "role": "all-in-one" }],
                "jump_to": null, "workers": [],
                "db_export": null, "db_import": null, "db_cli": null, "db_size": null,
                "db_export_options": [], "files_path": "/srv/acme/shared/public",
                "writable_paths": [], "has_keys": true
            },
            "servers": [{ "id": 12, "role": "all-in-one" }]
        }))
        .unwrap();
        let ssh = detail.ssh.unwrap();
        assert_eq!((ssh.name.as_str(), ssh.jump_to.as_str()), ("", ""));
        // One machine, which `host` already is: nothing to jump to.
        let hosts = hosts_of("Acme", &detail.environment, &ssh);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].login_command, None);
        assert_eq!(hosts[0].jump, None);
    }

    #[test]
    fn an_environment_on_one_machine_is_one_host() {
        let t = target(serde_json::json!({
            "host": "production.acme.vallic.cloud", "port": 2417, "user": "vc-t-acme"
        }));
        let hosts = hosts_of("Shop", &env(7, "Production"), &t);
        assert_eq!(hosts.len(), 1);
        let h = &hosts[0];
        assert_eq!(h.external_id, "env:7");
        assert_eq!(
            (h.label.as_str(), h.group.as_str()),
            ("Shop · Production", "Shop")
        );
        assert_eq!(
            (h.hostname.as_str(), h.port, h.user.as_str()),
            ("production.acme.vallic.cloud", 2417, "vc-t-acme")
        );
        assert_eq!(h.login_command, None);
        assert!(h.no_sftp && h.no_forwarding);
    }

    #[test]
    fn staging_names_itself_at_login() {
        let t = target(serde_json::json!({
            "host": "dev.acme.vallic.cloud", "port": 2417, "user": "vc-t-acme", "name": "staging"
        }));
        let hosts = hosts_of("Shop", &env(8, "Staging"), &t);
        assert_eq!(hosts[0].login_command.as_deref(), Some("staging"));
    }

    #[test]
    fn several_machines_go_through_the_front() {
        let t = target(serde_json::json!({
            "host": "production.acme.vallic.cloud", "port": 2417, "user": "vc-t-acme",
            "machines": [{ "name": "lb", "role": "balancer" }, { "name": "web-1", "role": "web" },
                         { "name": "web-2", "role": "web" }, { "name": "jobs", "role": "worker" }],
            "jump_to": "lb",
            "workers": ["worker-queue-1"]
        }));
        let hosts = hosts_of("Shop", &env(7, "Production"), &t);
        let ids: Vec<&str> = hosts.iter().map(|h| h.external_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "env:7/front",
                "env:7",
                "env:7/web-1",
                "env:7/web-2",
                "env:7/jobs",
                "env:7/@worker-queue-1"
            ]
        );

        let own = &hosts[1];
        assert_eq!(
            own.hostname, "lb.production.acme.vallic.cloud",
            "the name its host key is kept under"
        );
        assert_eq!(own.jump.as_deref(), Some("env:7/front"));
        assert_eq!(own.jump_command.as_deref(), Some("jump lb"));

        let web2 = &hosts[3];
        assert_eq!(web2.label, "Shop · Production · web-2 (web)");
        assert_eq!(web2.jump_command.as_deref(), Some("jump web-2"));

        let worker = &hosts[5];
        assert_eq!(worker.label, "Shop · Production · queue-1");
        assert_eq!(worker.login_command.as_deref(), Some("@worker-queue-1"));
        assert_eq!(worker.hostname, "jobs.production.acme.vallic.cloud");
        assert_eq!(worker.jump_command.as_deref(), Some("jump jobs"));
    }

    #[test]
    fn a_shared_machine_names_the_environment_before_the_jump() {
        let t = target(serde_json::json!({
            "host": "dev.acme.vallic.cloud", "port": 2417, "user": "vc-t-acme", "name": "staging",
            "machines": [{ "name": "web-1", "role": "web" }, { "name": "web-2", "role": "web" }]
        }));
        let hosts = hosts_of("Shop", &env(8, "Staging"), &t);
        assert_eq!(
            hosts.len(),
            3,
            "no separate front: the environment's own host is it"
        );
        let web1 = hosts
            .iter()
            .find(|h| h.external_id == "env:8/web-1")
            .unwrap();
        assert_eq!(web1.jump.as_deref(), Some("env:8"));
        assert_eq!(web1.jump_command.as_deref(), Some("staging jump web-1"));
        assert_eq!(web1.login_command.as_deref(), Some("staging"));
        // No jump_to: the environment's own host is the front's address.
        let own = hosts.iter().find(|h| h.external_id == "env:8").unwrap();
        assert_eq!(
            (own.hostname.as_str(), own.jump.as_deref()),
            ("dev.acme.vallic.cloud", None)
        );
    }

    #[test]
    fn only_https_consoles() {
        assert!(Vallic::new(None).is_ok());
        assert!(Vallic::new(Some("http://console.vallic.com")).is_err());
        assert_eq!(
            Vallic::new(Some("http://127.0.0.1:9000/x")).unwrap().base(),
            "http://127.0.0.1:9000"
        );
    }
}
