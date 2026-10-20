//! DigitalOcean through the `doctl` CLI (docs/features/cloud-sources.md): the account and its droplets.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::cli::Cli;
use crate::{Listing, Machine, Reach, Result, some};

/// `--context <context>` where the source names one, and JSON.
fn args<'a>(context: Option<&'a str>, rest: &[&'a str]) -> Vec<&'a str> {
    let mut out = rest.to_vec();
    if let Some(c) = context {
        out.extend(["--context", c]);
    }
    out.extend(["--output", "json"]);
    out
}

#[derive(Deserialize)]
struct Account {
    email: String,
    #[serde(default)]
    team: Option<Team>,
}

#[derive(Deserialize)]
struct Team {
    name: String,
}

/// Who doctl is signed in as: `sammy@example.com (My Team)`.
pub async fn whoami(cli: &Cli, context: Option<&str>) -> Result<String> {
    let a: Account = cli.json(&args(context, &["account", "get"])).await?;
    Ok(match a.team {
        Some(t) => format!("{} ({})", a.email, t.name),
        None => a.email,
    })
}

#[derive(Deserialize)]
pub(crate) struct Droplet {
    id: u64,
    name: String,
    status: String,
    #[serde(default)]
    networks: Networks,
    #[serde(default)]
    region: Option<Region>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Default, Deserialize)]
struct Networks {
    #[serde(default)]
    v4: Vec<Network>,
}

#[derive(Deserialize)]
struct Network {
    ip_address: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct Region {
    slug: String,
}

/// Tags as a map: `morphgate-user:ubuntu` is `morphgate-user` = `ubuntu` (DigitalOcean's tags
/// are single words); a plain tag maps to nothing.
fn tags_of(tags: Vec<String>) -> BTreeMap<String, String> {
    tags.into_iter()
        .map(|t| match t.split_once(':') {
            Some((k, v)) => (k.to_owned(), v.to_owned()),
            None => (t, String::new()),
        })
        .collect()
}

/// The account's droplets as machines.
pub(crate) fn machines_of(listed: Vec<Droplet>) -> Vec<Machine> {
    listed
        .into_iter()
        .map(|d| {
            let address = |kind: &str| {
                some(
                    d.networks
                        .v4
                        .iter()
                        .find(|n| n.kind == kind)
                        .map(|n| n.ip_address.clone()),
                )
            };
            let (public, private) = (address("public"), address("private"));
            let tags = tags_of(d.tags);
            Machine {
                external_id: format!("digitalocean:{}", d.id),
                name: d.name,
                place: d.region.map(|r| r.slug).unwrap_or_default(),
                public_address: public,
                private_address: private,
                user: some(tags.get("morphgate-user").cloned()),
                key_name: None,
                running: d.status == "active",
                state: d.status,
                tags,
                reach: Reach::Address,
            }
        })
        .collect()
}

/// The account's droplets.
pub async fn machines(cli: &Cli, context: Option<&str>) -> Result<Listing> {
    let listed: Vec<Droplet> = cli
        .json(&args(context, &["compute", "droplet", "list"]))
        .await?;
    let mut machines = machines_of(listed);
    machines.sort_by(|a, b| (&a.place, &a.name).cmp(&(&b.place, &b.name)));
    Ok(Listing {
        machines,
        skipped: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `doctl compute droplet list --output json`, as documented: an active droplet with a public
    /// and a private address, an off one with only a private one.
    #[test]
    fn droplets_become_machines() {
        let listed: Vec<Droplet> = serde_json::from_value(serde_json::json!([
            {
                "id": 3164444, "name": "web-1", "status": "active", "memory": 1024, "vcpus": 1,
                "networks": { "v4": [
                    { "ip_address": "104.236.32.182", "netmask": "255.255.192.0", "gateway": "104.236.0.1", "type": "public" },
                    { "ip_address": "10.128.0.2", "netmask": "255.255.0.0", "type": "private" }
                ], "v6": [] },
                "region": { "name": "Frankfurt 1", "slug": "fra1" },
                "tags": ["web", "morphgate-user:ubuntu"]
            },
            {
                "id": 3164445, "name": "batch", "status": "off",
                "networks": { "v4": [{ "ip_address": "10.128.0.3", "type": "private" }] },
                "region": { "slug": "fra1" }, "tags": []
            }
        ]))
        .unwrap();
        let m = machines_of(listed);
        assert_eq!(m[0].external_id, "digitalocean:3164444");
        assert_eq!(
            (m[0].place.as_str(), m[0].public_address.as_deref()),
            ("fra1", Some("104.236.32.182"))
        );
        assert_eq!(m[0].private_address.as_deref(), Some("10.128.0.2"));
        assert_eq!(m[0].user.as_deref(), Some("ubuntu"));
        assert!(m[0].tags.contains_key("web"));
        assert!(m[0].running);
        assert_eq!(
            (m[1].public_address.as_deref(), m[1].running),
            (None, false)
        );
    }
}
