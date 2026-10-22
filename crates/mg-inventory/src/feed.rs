//! Feeds: hosts and snippets from a URL, as a JSON document a team publishes (from Terraform
//! output, a CMDB, a cron job, an internal endpoint), read with a token (docs/features/
//! cloud-sources.md, "Feeds"). A feed carries data only: nothing in it runs on the device (no
//! proxy or local commands, no reaching through a cloud). Entries that don't hold up are skipped
//! and said; a document that doesn't is refused whole, so a bad one changes nothing.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{Error, InventoryHost, Result};

/// The format this version reads.
pub const VERSION: u64 = 1;
/// The largest document read.
pub const MAX_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_HOSTS: usize = 5_000;
pub const MAX_SNIPPETS: usize = 1_000;
/// The largest snippet body.
pub const MAX_BODY: usize = 64 * 1024;
/// How long a feed has to answer.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// An entry's `id`, and how long a label, group, tag or state may be.
const MAX_ID: usize = 200;
const MAX_TEXT: usize = 200;
const MAX_TAG: usize = 64;
const MAX_TAGS: usize = 50;
const MAX_HOST_KEYS: usize = 16;

/// Host key types a feed may list (OpenSSH's, without certificates).
const KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// A snippet as a feed gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedSnippet {
    /// `feed:<id>`: what a refresh matches the vault's snippet on.
    pub external_id: String,
    pub name: String,
    pub body: String,
    pub tags: Vec<String>,
}

/// What a feed lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Feed {
    /// What the feed calls itself (`"Vallic operations"`).
    pub name: Option<String>,
    pub hosts: Vec<InventoryHost>,
    pub snippets: Vec<FeedSnippet>,
    /// Entries left out, and why (`server-1234: the port isn't 1 to 65535`).
    pub skipped: Vec<String>,
}

fn local(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// A feed's address: `https://`, or `http://` on this computer.
pub fn check_url(url: &str) -> Result<Url> {
    let url = url.trim();
    let parsed = Url::parse(url).map_err(|e| Error::Api(format!("{url}: {e}")))?;
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && local(&parsed)) {
        Ok(parsed)
    } else {
        Err(Error::Api(format!(
            "{url}: a feed's address starts with https://"
        )))
    }
}

/// Reads the feed at `url` with `token`. `name` is the source's, for messages.
pub async fn fetch(name: &str, url: &str, token: &str) -> Result<Feed> {
    let url = check_url(url)?;
    // Redirects stay on https (or this computer); the token isn't sent to another host.
    let redirects = reqwest::redirect::Policy::custom(|attempt| {
        let ok = attempt.url().scheme() == "https"
            || (attempt.url().scheme() == "http" && local(attempt.url()));
        if attempt.previous().len() >= 5 || !ok {
            attempt.stop()
        } else {
            attempt.follow()
        }
    });
    let http = reqwest::Client::builder()
        .user_agent(concat!("MorphGate/", env!("CARGO_PKG_VERSION")))
        .timeout(TIMEOUT)
        .redirect(redirects)
        .build()
        .map_err(|e| Error::Api(e.to_string()))?;
    let failed = |e: reqwest::Error| {
        if e.is_timeout() {
            Error::Api(format!("{name} took longer than 60 s to answer"))
        } else {
            Error::Unreachable(name.to_owned(), e.to_string())
        }
    };
    let mut response = http
        .get(url)
        .bearer_auth(token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(failed)?;
    match response.status().as_u16() {
        200..=299 => {}
        401 | 403 => return Err(Error::TokenRefused(name.to_owned())),
        status => {
            return Err(Error::Api(
                format!(
                    "{name} answered {status} {}",
                    response.status().canonical_reason().unwrap_or("")
                )
                .trim_end()
                .to_owned(),
            ));
        }
    }
    let too_large = || {
        Error::Api(format!(
            "{name} sent more than 5 MiB: a feed is at most that"
        ))
    };
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(failed)? {
        if body.len() + chunk.len() > MAX_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    parse(name, &body)
}

/// An optional field: absent and `null` both read as empty.
fn nullable<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct RawHost {
    id: String,
    #[serde(default, deserialize_with = "nullable")]
    label: String,
    hostname: String,
    #[serde(default)]
    port: Option<u64>,
    user: String,
    #[serde(default, deserialize_with = "nullable")]
    group: String,
    #[serde(default, deserialize_with = "nullable")]
    tags: Vec<String>,
    #[serde(default)]
    jump: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    host_keys: Vec<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Deserialize)]
struct RawSnippet {
    id: String,
    name: String,
    body: String,
    #[serde(default, deserialize_with = "nullable")]
    tags: Vec<String>,
}

/// `[A-Za-z0-9._:/@-]`, 1 to 200 characters.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
}

/// A host name or user: no whitespace or control characters, and no leading `-` (it would read
/// as an option).
fn word(s: &str, what: &str) -> std::result::Result<String, String> {
    if s.is_empty() {
        return Err(format!("no {what}"));
    }
    if s.len() > 255 || s.starts_with('-') || s.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("the {what} {s:?} isn't one SSH can use"));
    }
    Ok(s.to_owned())
}

/// Text to show: control characters out, trimmed, at most `max` characters.
fn text(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    clean
        .trim()
        .chars()
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn tags(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in raw {
        let t = text(t, MAX_TAG);
        if !t.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    out.truncate(MAX_TAGS);
    out
}

/// Standard base64, padded.
fn base64(s: &str) -> bool {
    !s.is_empty()
        && s.len().is_multiple_of(4)
        && s.trim_end_matches('=').len() + 2 >= s.len()
        && s.trim_end_matches('=')
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// A host key line as `type base64` (a comment after it is dropped).
fn host_key(line: &str) -> std::result::Result<String, String> {
    let mut words = line.split_whitespace();
    match (words.next(), words.next()) {
        (Some(kind), Some(data)) if KEY_TYPES.contains(&kind) && base64(data) => {
            Ok(format!("{kind} {data}"))
        }
        _ => Err(format!(
            "the host key {:?} isn't an OpenSSH public key (type and base64)",
            text(line, 40)
        )),
    }
}

fn host(raw: RawHost) -> std::result::Result<(String, InventoryHost), String> {
    let hostname = word(raw.hostname.trim(), "host name")?;
    let user = word(raw.user.trim(), "user")?;
    let port = match raw.port {
        None => 22,
        Some(p @ 1..=65535) => p as u16,
        Some(_) => return Err("the port isn't 1 to 65535".into()),
    };
    let jump = match raw.jump.as_deref().map(str::trim).filter(|j| !j.is_empty()) {
        Some(j) if j == raw.id => return Err("it can't be its own jump host".into()),
        Some(j) if !valid_id(j) => {
            return Err(format!("the jump host {:?} isn't an id", text(j, 40)));
        }
        other => other.map(str::to_owned),
    };
    if raw.host_keys.len() > MAX_HOST_KEYS {
        return Err(format!("more than {MAX_HOST_KEYS} host keys"));
    }
    let host_keys = raw
        .host_keys
        .iter()
        .map(|k| host_key(k))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let label = match text(&raw.label, MAX_TEXT) {
        l if l.is_empty() => raw.id.clone(),
        l => l,
    };
    let state = raw
        .state
        .map(|s| text(&s, MAX_TAG))
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("running"));
    Ok((
        jump.unwrap_or_default(),
        InventoryHost {
            external_id: format!("feed:{}", raw.id),
            group: text(&raw.group, MAX_TEXT),
            label,
            hostname,
            port,
            user,
            login_command: None,
            jump: None,
            jump_command: None,
            no_sftp: false,
            no_forwarding: false,
            state,
            key_name: raw
                .key
                .map(|k| text(&k, MAX_TEXT))
                .filter(|k| !k.is_empty()),
            via: None,
            host_keys,
            tags: tags(&raw.tags),
        },
    ))
}

fn snippet(raw: RawSnippet) -> std::result::Result<FeedSnippet, String> {
    let name = text(&raw.name, MAX_TEXT);
    if name.is_empty() {
        return Err("no name".into());
    }
    if raw.body.trim().is_empty() {
        return Err("no body".into());
    }
    if raw.body.len() > MAX_BODY {
        return Err("the body is over 64 KiB".into());
    }
    // A terminal reads escape sequences as more than text.
    if raw
        .body
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("the body has control characters".into());
    }
    Ok(FeedSnippet {
        external_id: format!("feed:{}", raw.id),
        name,
        body: raw.body,
        tags: tags(&raw.tags),
    })
}

/// What an entry is called in messages: its id, else its place in the list.
fn entry_name(v: &Value, kind: &str, n: usize) -> String {
    match v.get("id").and_then(Value::as_str) {
        Some(id) if valid_id(id) => id.to_owned(),
        _ => format!("{kind} {}", n + 1),
    }
}

/// Reads a feed document. `name` is the source's, for messages.
pub fn parse(name: &str, bytes: &[u8]) -> Result<Feed> {
    let unreadable = |why: String| {
        Error::Api(format!(
            "{name} sent something this version can't read: {why}"
        ))
    };
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| unreadable(e.to_string()))?;
    let obj = doc
        .as_object()
        .ok_or_else(|| unreadable("not a JSON object".into()))?;
    match obj.get("version").and_then(Value::as_u64) {
        Some(VERSION) => {}
        Some(n) if n > VERSION => {
            return Err(Error::Api(format!(
                "{name} is a version {n} feed: update MorphGate to read it"
            )));
        }
        _ => return Err(unreadable("no \"version\": 1".into())),
    }
    let list = |key: &str| match obj.get(key) {
        None | Some(Value::Null) => Ok(&[][..]),
        Some(Value::Array(a)) => Ok(a.as_slice()),
        Some(_) => Err(unreadable(format!("\"{key}\" isn't a list"))),
    };
    let (raw_hosts, raw_snippets) = (list("hosts")?, list("snippets")?);
    if raw_hosts.len() > MAX_HOSTS {
        return Err(Error::Api(format!(
            "{name} lists {} hosts: a feed holds at most 5,000",
            raw_hosts.len()
        )));
    }
    if raw_snippets.len() > MAX_SNIPPETS {
        return Err(Error::Api(format!(
            "{name} lists {} snippets: a feed holds at most 1,000",
            raw_snippets.len()
        )));
    }
    let mut feed = Feed {
        name: obj
            .get("name")
            .and_then(Value::as_str)
            .map(|n| text(n, MAX_TEXT))
            .filter(|n| !n.is_empty()),
        ..Feed::default()
    };

    // Hosts, with the id of the one each jumps through.
    let mut hosts: Vec<(String, String, InventoryHost)> = Vec::new();
    let mut seen = HashSet::new();
    for (n, v) in raw_hosts.iter().enumerate() {
        let entry = entry_name(v, "host", n);
        let parsed = serde_json::from_value::<RawHost>(v.clone())
            .map_err(|e| e.to_string())
            .and_then(|raw| {
                if !valid_id(&raw.id) {
                    return Err("its id isn't 1 to 200 of A-Z, a-z, 0-9 and . _ : / @ -".into());
                }
                if !seen.insert(raw.id.clone()) {
                    return Err("another host has this id".into());
                }
                let id = raw.id.clone();
                host(raw).map(|(jump, h)| (id, jump, h))
            });
        match parsed {
            Ok(h) => hosts.push(h),
            Err(why) => feed.skipped.push(format!("{entry}: {why}")),
        }
    }
    // A jump host must be one of the feed's own, kept, and not lead round in a circle.
    let mut circular = Vec::new();
    {
        let jumps: HashMap<&str, &str> = hosts
            .iter()
            .filter(|(_, j, _)| !j.is_empty())
            .map(|(id, j, _)| (id.as_str(), j.as_str()))
            .collect();
        // In a circle: following its jump hosts comes back to it. (One that only leads into a
        // circle goes with the hosts it jumps through, below.)
        for (id, _, _) in &hosts {
            let mut at = id.as_str();
            for _ in 0..hosts.len() {
                match jumps.get(at) {
                    Some(next) if *next == id.as_str() => {
                        circular.push(id.clone());
                        break;
                    }
                    Some(next) => at = next,
                    None => break,
                }
            }
        }
    }
    hosts.retain(|(id, _, _)| {
        let keep = !circular.contains(id);
        if !keep {
            feed.skipped
                .push(format!("{id}: its jump hosts go round in a circle"));
        }
        keep
    });
    loop {
        let kept: HashSet<String> = hosts.iter().map(|(id, _, _)| id.clone()).collect();
        let before = hosts.len();
        hosts.retain(|(id, jump, _)| {
            let keep = jump.is_empty() || kept.contains(jump);
            if !keep {
                feed.skipped.push(format!(
                    "{id}: its jump host {jump:?} isn't one of the feed's hosts (or was skipped)"
                ));
            }
            keep
        });
        if hosts.len() == before {
            break;
        }
    }
    feed.hosts = hosts
        .into_iter()
        .map(|(_, jump, mut h)| {
            h.jump = (!jump.is_empty()).then(|| format!("feed:{jump}"));
            h
        })
        .collect();

    let mut seen = HashSet::new();
    for (n, v) in raw_snippets.iter().enumerate() {
        let entry = entry_name(v, "snippet", n);
        let parsed = serde_json::from_value::<RawSnippet>(v.clone())
            .map_err(|e| e.to_string())
            .and_then(|raw| {
                if !valid_id(&raw.id) {
                    return Err("its id isn't 1 to 200 of A-Z, a-z, 0-9 and . _ : / @ -".into());
                }
                if !seen.insert(raw.id.clone()) {
                    return Err("another snippet has this id".into());
                }
                snippet(raw)
            });
        match parsed {
            Ok(s) => feed.snippets.push(s),
            Err(why) => feed.skipped.push(format!("{entry}: {why}")),
        }
    }
    Ok(feed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    fn parsed(doc: Value) -> Feed {
        parse("Ops", doc.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn the_roadmap_example_reads() {
        let feed = parsed(json!({
            "version": 1,
            "name": "Vallic operations",
            "hosts": [
                { "id": "bastion-fsn1", "label": "Bastion FSN1", "hostname": "bastion-fsn1.example.net",
                  "port": 22, "user": "vallic", "group": "Bastions", "host_keys": [KEY] },
                { "id": "server-1234", "label": "acme-prod-1", "hostname": "10.0.12.34", "port": 2222,
                  "user": "vallic", "group": "Acme", "tags": ["production", "fsn1"], "jump": "bastion-fsn1",
                  "key": "vallic-customers", "host_keys": [format!("{KEY} root@bastion")], "state": "running" }
            ],
            "snippets": [
                { "id": "php-errors", "name": "PHP error log", "body": "podman logs --tail 200 php", "tags": ["diagnostics"] }
            ]
        }));
        assert_eq!(feed.name.as_deref(), Some("Vallic operations"));
        assert!(feed.skipped.is_empty(), "{:?}", feed.skipped);
        let [bastion, server] = &feed.hosts[..] else {
            panic!("two hosts: {:?}", feed.hosts)
        };
        assert_eq!(bastion.external_id, "feed:bastion-fsn1");
        assert_eq!(bastion.jump, None);
        assert_eq!(server.jump.as_deref(), Some("feed:bastion-fsn1"));
        assert_eq!(
            (
                server.hostname.as_str(),
                server.port,
                server.user.as_str(),
                server.group.as_str()
            ),
            ("10.0.12.34", 2222, "vallic", "Acme")
        );
        assert_eq!(server.key_name.as_deref(), Some("vallic-customers"));
        // The comment is dropped; "running" is no state to show.
        assert_eq!(server.host_keys, [KEY]);
        assert_eq!(server.state, None);
        assert_eq!(server.tags, ["production", "fsn1"]);
        assert!(server.login_command.is_none() && server.via.is_none());
        assert_eq!(
            feed.snippets,
            [FeedSnippet {
                external_id: "feed:php-errors".into(),
                name: "PHP error log".into(),
                body: "podman logs --tail 200 php".into(),
                tags: vec!["diagnostics".into()],
            }]
        );
    }

    #[test]
    fn defaults_and_optional_fields() {
        let feed = parsed(json!({
            "version": 1,
            "hosts": [{ "id": "web", "hostname": "web.example", "user": "deploy", "group": null,
                        "tags": null, "state": "stopped" }]
        }));
        let h = &feed.hosts[0];
        assert_eq!(
            (h.label.as_str(), h.port, h.group.as_str()),
            ("web", 22, "")
        );
        assert_eq!(h.state.as_deref(), Some("stopped"));
        assert!(h.host_keys.is_empty() && h.key_name.is_none());
        assert!(feed.name.is_none() && feed.snippets.is_empty());
    }

    #[test]
    fn invalid_entries_are_skipped_and_said() {
        let feed = parsed(json!({
            "version": 1,
            "hosts": [
                { "id": "ok", "hostname": "ok.example", "user": "u" },
                { "id": "ok", "hostname": "again.example", "user": "u" },
                { "id": "bad id!", "hostname": "x", "user": "u" },
                { "id": "dash", "hostname": "-oProxyCommand=x", "user": "u" },
                { "id": "space", "hostname": "a b", "user": "u" },
                { "id": "nouser", "hostname": "x.example" },
                { "id": "port", "hostname": "x.example", "user": "u", "port": 70000 },
                { "id": "key", "hostname": "x.example", "user": "u", "host_keys": ["ssh-dss AAAA"] },
                { "id": "notbase64", "hostname": "x.example", "user": "u", "host_keys": ["ssh-ed25519 $(id)"] },
                { "id": "orphan", "hostname": "x.example", "user": "u", "jump": "nowhere" },
                { "id": "a", "hostname": "a.example", "user": "u", "jump": "b" },
                { "id": "b", "hostname": "b.example", "user": "u", "jump": "a" },
                { "id": "behind-a", "hostname": "c.example", "user": "u", "jump": "a" },
                { "id": "self", "hostname": "s.example", "user": "u", "jump": "self" },
                "not an object"
            ],
            "snippets": [
                { "id": "ok", "name": "Uptime", "body": "uptime" },
                { "id": "esc", "name": "Sneaky", "body": "echo \u{1b}[201~" },
                { "id": "empty", "name": "Nothing", "body": "  " },
                { "id": "big", "name": "Big", "body": "x".repeat(MAX_BODY + 1) }
            ]
        }));
        assert_eq!(feed.hosts.len(), 1, "{:?}", feed.hosts);
        assert_eq!(feed.snippets.len(), 1);
        let said = feed.skipped.join("\n");
        for expected in [
            "ok: another host has this id",
            "host 3: its id isn't",
            "dash: the host name \"-oProxyCommand=x\" isn't one SSH can use",
            "space: the host name",
            "nouser: missing field `user`",
            "port: the port isn't 1 to 65535",
            "key: the host key \"ssh-dss AAAA\" isn't an OpenSSH public key",
            "notbase64: the host key",
            "orphan: its jump host \"nowhere\" isn't one of the feed's hosts",
            "a: its jump hosts go round in a circle",
            "b: its jump hosts go round in a circle",
            "behind-a: its jump host \"a\" isn't one of the feed's hosts (or was skipped)",
            "self: it can't be its own jump host",
            "host 15: invalid type",
            "esc: the body has control characters",
            "empty: no body",
            "big: the body is over 64 KiB",
        ] {
            assert!(said.contains(expected), "{expected:?} in:\n{said}");
        }
    }

    #[test]
    fn a_bad_document_is_refused_whole() {
        let err = |doc: &str| parse("Ops", doc.as_bytes()).unwrap_err().to_string();
        assert!(err("<html>").starts_with("Ops sent something this version can't read: "));
        assert!(err("[]").ends_with("not a JSON object"));
        assert!(err(r#"{"hosts": []}"#).ends_with("no \"version\": 1"));
        assert_eq!(
            err(r#"{"version": 2}"#),
            "Ops is a version 2 feed: update MorphGate to read it"
        );
        assert!(err(r#"{"version": 1, "hosts": {}}"#).ends_with("\"hosts\" isn't a list"));
        let many = json!({ "version": 1, "hosts": vec![json!({}); MAX_HOSTS + 1] });
        assert_eq!(
            err(&many.to_string()),
            "Ops lists 5001 hosts: a feed holds at most 5,000"
        );
    }

    #[test]
    fn only_https_or_this_computer() {
        assert!(check_url("https://ops.example/feed").is_ok());
        assert!(check_url("http://127.0.0.1:8080/feed").is_ok());
        assert!(check_url("http://localhost/feed").is_ok());
        assert!(check_url("http://ops.example/feed").is_err());
        assert!(check_url("file:///etc/passwd").is_err());
    }
}
