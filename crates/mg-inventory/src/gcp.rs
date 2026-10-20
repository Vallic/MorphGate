//! Google Compute Engine through the `gcloud` CLI (docs/features/cloud-sources.md): the active account,
//! the projects, and each project's instances, listed in parallel.

use std::collections::BTreeMap;

use serde::Deserialize;
use tokio::task::JoinSet;

use crate::cli::Cli;
use crate::{Error, Listing, Machine, Reach, Result, some};

#[derive(Deserialize)]
struct Account {
    account: String,
    #[serde(default)]
    status: String,
}

/// The account gcloud uses.
pub async fn whoami(cli: &Cli) -> Result<String> {
    let accounts: Vec<Account> = cli.json(&["auth", "list", "--format=json"]).await?;
    accounts
        .into_iter()
        .find(|a| a.status == "ACTIVE")
        .map(|a| a.account)
        .ok_or_else(|| Error::Cli("gcloud has no active account: run `gcloud auth login`".into()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    project_id: String,
    #[serde(default)]
    lifecycle_state: String,
}

/// The projects the account sees (active ones).
pub async fn projects(cli: &Cli) -> Result<Vec<String>> {
    let projects: Vec<Project> = cli.json(&["projects", "list", "--format=json"]).await?;
    let mut ids: Vec<String> = projects
        .into_iter()
        .filter(|p| p.lifecycle_state.is_empty() || p.lifecycle_state == "ACTIVE")
        .map(|p| p.project_id)
        .collect();
    ids.sort();
    Ok(ids)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PosixAccount {
    username: String,
    #[serde(default)]
    primary: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginProfile {
    #[serde(default)]
    posix_accounts: Vec<PosixAccount>,
}

/// The account's OS Login user name, where it has one.
pub async fn os_login_user(cli: &Cli) -> Result<Option<String>> {
    let profile: LoginProfile = cli
        .json(&["compute", "os-login", "describe-profile", "--format=json"])
        .await?;
    let mut accounts = profile.posix_accounts;
    accounts.sort_by_key(|a| !a.primary);
    Ok(accounts.into_iter().next().map(|a| a.username))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Instance {
    name: String,
    /// A URL: `…/projects/<project>/zones/<zone>`.
    zone: String,
    status: String,
    #[serde(default)]
    network_interfaces: Vec<Interface>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Interface {
    #[serde(default, rename = "networkIP")]
    network_ip: Option<String>,
    #[serde(default)]
    access_configs: Vec<AccessConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessConfig {
    #[serde(default, rename = "natIP")]
    nat_ip: Option<String>,
}

/// A project's instances as machines. `TERMINATED` is Compute Engine's word for stopped.
pub(crate) fn machines_of(project: &str, listed: Vec<Instance>) -> Vec<Machine> {
    listed
        .into_iter()
        .map(|i| {
            let zone = i.zone.rsplit('/').next().unwrap_or_default().to_owned();
            let nic = i.network_interfaces.into_iter().next();
            let public = nic
                .as_ref()
                .and_then(|n| n.access_configs.iter().find_map(|a| some(a.nat_ip.clone())));
            Machine {
                external_id: format!("gcp:{project}/{zone}/{}", i.name),
                name: i.name.clone(),
                place: project.to_owned(),
                public_address: public,
                private_address: some(nic.and_then(|n| n.network_ip)),
                user: some(i.labels.get("morphgate-user").cloned()),
                key_name: None,
                running: i.status == "RUNNING",
                state: i.status,
                tags: i.labels,
                reach: Reach::Gcp {
                    project: project.to_owned(),
                    zone,
                    name: i.name,
                },
            }
        })
        .collect()
}

/// The instances in `projects` (every one the account sees when empty), in parallel. A project
/// that refuses (Compute Engine not enabled, no permission) is said in `skipped`.
pub async fn machines(cli: &Cli, projects: &[String]) -> Result<Listing> {
    let projects = match projects {
        [] => self::projects(cli).await?,
        chosen => chosen.to_vec(),
    };
    let mut set = JoinSet::new();
    for project in projects {
        let cli = cli.clone();
        set.spawn(async move {
            let listed = cli
                .json::<Vec<Instance>>(&[
                    "compute",
                    "instances",
                    "list",
                    "--project",
                    &project,
                    "--format=json",
                ])
                .await;
            (project, listed)
        });
    }
    let mut listing = Listing::default();
    while let Some(done) = set.join_next().await {
        let Ok((project, listed)) = done else {
            continue;
        };
        match listed {
            Ok(i) => listing.machines.extend(machines_of(&project, i)),
            Err(e) => listing.skipped.push(format!("{project}: {e}")),
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

    /// `gcloud compute instances list --format=json`, as documented: one with an external
    /// address, a stopped one (`TERMINATED`) with an internal one only.
    #[test]
    fn instances_become_machines() {
        let listed: Vec<Instance> = serde_json::from_value(serde_json::json!([
            {
                "id": "4823649823", "name": "web-1", "status": "RUNNING",
                "zone": "https://www.googleapis.com/compute/v1/projects/shop-prod/zones/europe-west1-b",
                "networkInterfaces": [{
                    "networkIP": "10.132.0.2",
                    "accessConfigs": [{ "name": "External NAT", "natIP": "34.76.1.2", "type": "ONE_TO_ONE_NAT" }]
                }],
                "labels": { "env": "prod", "morphgate-user": "deploy" }
            },
            {
                "id": "4823649824", "name": "batch-1", "status": "TERMINATED",
                "zone": "https://www.googleapis.com/compute/v1/projects/shop-prod/zones/europe-west1-c",
                "networkInterfaces": [{ "networkIP": "10.132.0.3" }]
            }
        ]))
        .unwrap();
        let m = machines_of("shop-prod", listed);
        assert_eq!(m[0].external_id, "gcp:shop-prod/europe-west1-b/web-1");
        assert_eq!(m[0].public_address.as_deref(), Some("34.76.1.2"));
        assert_eq!(m[0].private_address.as_deref(), Some("10.132.0.2"));
        assert_eq!(m[0].user.as_deref(), Some("deploy"));
        assert!(m[0].running);
        assert_eq!(m[1].public_address, None);
        assert_eq!((m[1].running, m[1].state.as_str()), (false, "TERMINATED"));
        assert_eq!(
            m[1].reach,
            Reach::Gcp {
                project: "shop-prod".into(),
                zone: "europe-west1-c".into(),
                name: "batch-1".into()
            }
        );
    }
}
