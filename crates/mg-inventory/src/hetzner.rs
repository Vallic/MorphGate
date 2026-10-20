//! Hetzner Cloud through the `hcloud` CLI (docs/features/cloud-sources.md): a context (a project's token)
//! and its servers.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::cli::Cli;
use crate::{Listing, Machine, Reach, Result, some};

/// `--context <context>` where the source names one.
fn args<'a>(context: Option<&'a str>, rest: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    if let Some(c) = context {
        out.extend(["--context", c]);
    }
    out.extend_from_slice(rest);
    out
}

/// The context hcloud uses (it names a project's token; there's no "who am I").
pub async fn whoami(cli: &Cli, context: Option<&str>) -> Result<String> {
    if let Some(c) = context {
        return Ok(c.to_owned());
    }
    let active = cli.text(&["context", "active"]).await?;
    Ok(active.trim().to_owned())
}

#[derive(Deserialize)]
pub(crate) struct Server {
    id: u64,
    name: String,
    status: String,
    #[serde(default)]
    public_net: Option<PublicNet>,
    #[serde(default)]
    private_net: Vec<PrivateNet>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    datacenter: Option<Datacenter>,
}

#[derive(Deserialize)]
struct PublicNet {
    #[serde(default)]
    ipv4: Option<Address>,
}

#[derive(Deserialize)]
struct Address {
    ip: String,
}

#[derive(Deserialize)]
struct PrivateNet {
    ip: String,
}

#[derive(Deserialize)]
struct Datacenter {
    location: Location,
}

#[derive(Deserialize)]
struct Location {
    name: String,
}

/// The project's servers as machines.
pub(crate) fn machines_of(project: &str, listed: Vec<Server>) -> Vec<Machine> {
    listed
        .into_iter()
        .map(|s| Machine {
            external_id: format!("hetzner:{project}/{}", s.id),
            name: s.name,
            place: s
                .datacenter
                .map(|d| d.location.name)
                .unwrap_or_else(|| project.to_owned()),
            public_address: some(s.public_net.and_then(|n| n.ipv4).map(|a| a.ip)),
            private_address: some(s.private_net.into_iter().next().map(|n| n.ip)),
            user: some(s.labels.get("morphgate-user").cloned()),
            key_name: None,
            running: s.status == "running",
            state: s.status,
            tags: s.labels,
            reach: Reach::Address,
        })
        .collect()
}

/// The servers of the context's project.
pub async fn machines(cli: &Cli, context: Option<&str>) -> Result<Listing> {
    let project = whoami(cli, context).await?;
    let listed: Vec<Server> = cli
        .json(&args(context, &["server", "list", "-o", "json"]))
        .await?;
    let mut machines = machines_of(&project, listed);
    machines.sort_by(|a, b| (&a.place, &a.name).cmp(&(&b.place, &b.name)));
    Ok(Listing {
        machines,
        skipped: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hcloud server list -o json` (the API's server objects): one with a public address and a
    /// private network, one switched off without a public IPv4.
    #[test]
    fn servers_become_machines() {
        let listed: Vec<Server> = serde_json::from_value(serde_json::json!([
            {
                "id": 42, "name": "web-1", "status": "running",
                "public_net": { "ipv4": { "id": 7, "ip": "116.203.1.2", "blocked": false, "dns_ptr": "static.2.1.203.116.clients.your-server.de" },
                                "ipv6": { "ip": "2a01:4f8:c17:1234::/64" }, "floating_ips": [], "firewalls": [] },
                "private_net": [{ "network": 9, "ip": "10.0.0.2", "alias_ips": [] }],
                "labels": { "env": "prod", "morphgate-user": "deploy" },
                "datacenter": { "id": 4, "name": "fsn1-dc14", "location": { "id": 1, "name": "fsn1" } }
            },
            {
                "id": 43, "name": "batch", "status": "off",
                "public_net": { "ipv4": null, "ipv6": null, "floating_ips": [] },
                "private_net": [], "labels": {},
                "datacenter": { "name": "nbg1-dc3", "location": { "name": "nbg1" } }
            }
        ]))
        .unwrap();
        let m = machines_of("shop", listed);
        assert_eq!(m[0].external_id, "hetzner:shop/42");
        assert_eq!(
            (m[0].place.as_str(), m[0].public_address.as_deref()),
            ("fsn1", Some("116.203.1.2"))
        );
        assert_eq!(m[0].private_address.as_deref(), Some("10.0.0.2"));
        assert_eq!(m[0].user.as_deref(), Some("deploy"));
        assert!(m[0].running);
        assert_eq!(
            (
                m[1].public_address.as_deref(),
                m[1].running,
                m[1].state.as_str()
            ),
            (None, false, "off")
        );
    }
}
