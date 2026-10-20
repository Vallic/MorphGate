//! AWS EC2 through the `aws` CLI (docs/features/cloud-sources.md): who's signed in, the regions, and
//! each region's instances, listed in parallel.

use std::collections::BTreeMap;

use serde::Deserialize;
use tokio::task::JoinSet;

use crate::cli::Cli;
use crate::{Listing, Machine, Reach, Result, some};

/// `--profile <profile>` where the source names one, and JSON.
fn args<'a>(profile: Option<&'a str>, rest: &[&'a str]) -> Vec<&'a str> {
    let mut out = rest.to_vec();
    if let Some(p) = profile {
        out.extend(["--profile", p]);
    }
    out.extend(["--output", "json"]);
    out
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Identity {
    account: String,
    arn: String,
}

/// Who the profile signs in as: `123456789012 (arn:aws:sts::…:assumed-role/…/alice)`.
pub async fn whoami(cli: &Cli, profile: Option<&str>) -> Result<String> {
    let id: Identity = cli
        .json(&args(profile, &["sts", "get-caller-identity"]))
        .await?;
    Ok(format!("{} ({})", id.account, id.arn))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Regions {
    regions: Vec<Region>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Region {
    region_name: String,
}

/// The regions the account has enabled.
pub async fn regions(cli: &Cli, profile: Option<&str>) -> Result<Vec<String>> {
    let r: Regions = cli
        .json(&args(profile, &["ec2", "describe-regions"]))
        .await?;
    let mut names: Vec<String> = r.regions.into_iter().map(|r| r.region_name).collect();
    names.sort();
    Ok(names)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Instances {
    #[serde(default)]
    reservations: Vec<Reservation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Reservation {
    #[serde(default)]
    instances: Vec<Instance>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Instance {
    instance_id: String,
    state: State,
    #[serde(default)]
    public_ip_address: Option<String>,
    #[serde(default)]
    public_dns_name: Option<String>,
    #[serde(default)]
    private_ip_address: Option<String>,
    #[serde(default)]
    key_name: Option<String>,
    #[serde(default)]
    tags: Vec<Tag>,
    /// `windows` for Windows; absent otherwise.
    #[serde(default)]
    platform: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct State {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Tag {
    key: String,
    value: String,
}

/// A region's instances as machines: not Windows, not terminated.
pub(crate) fn machines_of(region: &str, listed: Instances) -> Vec<Machine> {
    let mut out = Vec::new();
    for i in listed.reservations.into_iter().flat_map(|r| r.instances) {
        let gone = matches!(i.state.name.as_str(), "terminated" | "shutting-down");
        if gone || i.platform.as_deref() == Some("windows") {
            continue;
        }
        let tags: BTreeMap<String, String> = i.tags.into_iter().map(|t| (t.key, t.value)).collect();
        out.push(Machine {
            external_id: format!("aws:{region}/{}", i.instance_id),
            name: some(tags.get("Name").cloned()).unwrap_or_else(|| i.instance_id.clone()),
            place: region.to_owned(),
            public_address: some(i.public_dns_name).or(some(i.public_ip_address)),
            private_address: some(i.private_ip_address),
            user: some(tags.get("morphgate:user").cloned()),
            key_name: some(i.key_name),
            running: i.state.name == "running",
            state: i.state.name,
            tags,
            reach: Reach::Aws {
                instance_id: i.instance_id,
                region: region.to_owned(),
            },
        });
    }
    out
}

/// The instances in `regions` (every enabled one when empty), in parallel. A region that refuses
/// (not enabled, no permission) is said in `skipped`.
pub async fn machines(cli: &Cli, profile: Option<&str>, regions: &[String]) -> Result<Listing> {
    let regions = match regions {
        [] => self::regions(cli, profile).await?,
        chosen => chosen.to_vec(),
    };
    let mut set = JoinSet::new();
    for region in regions {
        let (cli, profile) = (cli.clone(), profile.map(str::to_owned));
        set.spawn(async move {
            let listed = cli
                .json::<Instances>(&args(
                    profile.as_deref(),
                    &["ec2", "describe-instances", "--region", &region],
                ))
                .await;
            (region, listed)
        });
    }
    let mut listing = Listing::default();
    while let Some(done) = set.join_next().await {
        let Ok((region, listed)) = done else { continue };
        match listed {
            Ok(i) => listing.machines.extend(machines_of(&region, i)),
            Err(e) => listing.skipped.push(format!("{region}: {e}")),
        }
    }
    listing
        .machines
        .sort_by(|a, b| (&a.place, &a.name).cmp(&(&b.place, &b.name)));
    listing.skipped.sort();
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `aws ec2 describe-instances --output json`, as documented: an instance with a public DNS
    /// name, a stopped one without (`""`), a terminated one, a Windows one.
    #[test]
    fn instances_become_machines() {
        let listed: Instances = serde_json::from_value(serde_json::json!({
            "Reservations": [{ "Instances": [
                {
                    "InstanceId": "i-0aaa", "State": { "Code": 16, "Name": "running" },
                    "PublicIpAddress": "3.120.1.2",
                    "PublicDnsName": "ec2-3-120-1-2.eu-central-1.compute.amazonaws.com",
                    "PrivateIpAddress": "10.0.1.5", "KeyName": "deploy",
                    "PlatformDetails": "Linux/UNIX",
                    "Placement": { "AvailabilityZone": "eu-central-1a" },
                    "Tags": [{ "Key": "Name", "Value": "web-1" }, { "Key": "morphgate:user", "Value": "ubuntu" }]
                },
                {
                    "InstanceId": "i-0bbb", "State": { "Code": 80, "Name": "stopped" },
                    "PublicDnsName": "", "PrivateIpAddress": "10.0.1.6"
                },
                { "InstanceId": "i-0ccc", "State": { "Code": 48, "Name": "terminated" }, "PublicDnsName": "" },
                { "InstanceId": "i-0ddd", "State": { "Code": 16, "Name": "running" }, "Platform": "windows" }
            ]}]
        }))
        .unwrap();
        let m = machines_of("eu-central-1", listed);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].external_id, "aws:eu-central-1/i-0aaa");
        assert_eq!(m[0].name, "web-1");
        assert_eq!(
            m[0].public_address.as_deref(),
            Some("ec2-3-120-1-2.eu-central-1.compute.amazonaws.com")
        );
        assert_eq!(m[0].user.as_deref(), Some("ubuntu"));
        assert_eq!(m[0].key_name.as_deref(), Some("deploy"));
        assert!(m[0].running);
        // No Name tag: its id. Stopped: no public address, its private one kept.
        assert_eq!(m[1].name, "i-0bbb");
        assert_eq!(m[1].public_address, None);
        assert_eq!(m[1].private_address.as_deref(), Some("10.0.1.6"));
        assert_eq!((m[1].running, m[1].state.as_str()), (false, "stopped"));
        assert_eq!(
            m[1].reach,
            Reach::Aws {
                instance_id: "i-0bbb".into(),
                region: "eu-central-1".into()
            }
        );
    }
}
