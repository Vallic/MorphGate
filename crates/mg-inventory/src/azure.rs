//! Azure virtual machines through the `az` CLI (docs/features/cloud-sources.md): who's signed in, the
//! subscriptions, and each subscription's machines with their addresses (`az vm list -d`).

use std::collections::BTreeMap;

use serde::Deserialize;
use tokio::task::JoinSet;

use crate::cli::Cli;
use crate::{Listing, Machine, Reach, Result, some};

#[derive(Deserialize)]
struct Account {
    id: String,
    name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    user: Option<User>,
}

#[derive(Deserialize)]
struct User {
    name: String,
}

/// Who az is signed in as, and its default subscription: `alice@example.com (Production)`.
pub async fn whoami(cli: &Cli) -> Result<String> {
    let a: Account = cli.json(&["account", "show", "-o", "json"]).await?;
    Ok(match a.user {
        Some(u) => format!("{} ({})", u.name, a.name),
        None => a.name,
    })
}

/// The enabled subscriptions, as `(id, name)`.
pub async fn subscriptions(cli: &Cli) -> Result<Vec<(String, String)>> {
    let all: Vec<Account> = cli.json(&["account", "list", "-o", "json"]).await?;
    Ok(all
        .into_iter()
        .filter(|a| a.state.is_empty() || a.state == "Enabled")
        .map(|a| (a.id, a.name))
        .collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Vm {
    id: String,
    name: String,
    resource_group: String,
    /// `VM running`, `VM deallocated`, `VM stopped`… (with `-d`).
    #[serde(default)]
    power_state: Option<String>,
    /// Comma separated (with `-d`).
    #[serde(default)]
    public_ips: Option<String>,
    #[serde(default)]
    private_ips: Option<String>,
    #[serde(default)]
    fqdns: Option<String>,
    #[serde(default)]
    os_profile: Option<OsProfile>,
    #[serde(default)]
    storage_profile: Option<StorageProfile>,
    #[serde(default)]
    tags: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OsProfile {
    #[serde(default)]
    admin_username: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageProfile {
    #[serde(default)]
    os_disk: Option<OsDisk>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OsDisk {
    #[serde(default)]
    os_type: Option<String>,
}

fn first(list: Option<String>) -> Option<String> {
    some(list.and_then(|l| l.split(',').next().map(str::to_owned)))
}

/// A subscription's machines, but Windows ones.
pub(crate) fn machines_of(listed: Vec<Vm>) -> Vec<Machine> {
    let mut out = Vec::new();
    for vm in listed {
        let os = vm
            .storage_profile
            .and_then(|s| s.os_disk)
            .and_then(|d| d.os_type)
            .unwrap_or_default();
        if os.eq_ignore_ascii_case("windows") {
            continue;
        }
        let tags = vm.tags.unwrap_or_default();
        let state = vm.power_state.unwrap_or_default();
        out.push(Machine {
            external_id: format!("azure:{}", vm.id.to_lowercase()),
            name: vm.name,
            place: vm.resource_group,
            // The DNS name stays when the address changes.
            public_address: first(vm.fqdns).or(first(vm.public_ips)),
            private_address: first(vm.private_ips),
            user: some(tags.get("morphgate-user").cloned())
                .or(some(vm.os_profile.and_then(|o| o.admin_username))),
            key_name: None,
            running: state == "VM running",
            state,
            tags,
            reach: Reach::Address,
        });
    }
    out
}

/// The machines in `subscriptions` (ids; every enabled one when empty), in parallel. A
/// subscription that refuses is said in `skipped`.
pub async fn machines(cli: &Cli, subscriptions: &[String]) -> Result<Listing> {
    let subscriptions: Vec<String> = match subscriptions {
        [] => self::subscriptions(cli)
            .await?
            .into_iter()
            .map(|(id, _)| id)
            .collect(),
        chosen => chosen.to_vec(),
    };
    let mut set = JoinSet::new();
    for subscription in subscriptions {
        let cli = cli.clone();
        set.spawn(async move {
            let listed = cli
                .json::<Vec<Vm>>(&[
                    "vm",
                    "list",
                    "-d",
                    "--subscription",
                    &subscription,
                    "-o",
                    "json",
                ])
                .await;
            (subscription, listed)
        });
    }
    let mut listing = Listing::default();
    while let Some(done) = set.join_next().await {
        let Ok((subscription, listed)) = done else {
            continue;
        };
        match listed {
            Ok(vms) => listing.machines.extend(machines_of(vms)),
            Err(e) => listing.skipped.push(format!("{subscription}: {e}")),
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

    /// `az vm list -d -o json`, as documented: a running Linux machine with a DNS name, a
    /// deallocated one without a public address, a Windows one.
    #[test]
    fn vms_become_machines() {
        let listed: Vec<Vm> = serde_json::from_value(serde_json::json!([
            {
                "id": "/subscriptions/0000/resourceGroups/SHOP/providers/Microsoft.Compute/virtualMachines/web-1",
                "name": "web-1", "resourceGroup": "SHOP", "location": "westeurope",
                "powerState": "VM running", "publicIps": "20.1.2.3", "privateIps": "10.0.0.4",
                "fqdns": "web-1.westeurope.cloudapp.azure.com",
                "osProfile": { "adminUsername": "azureuser", "computerName": "web-1" },
                "storageProfile": { "osDisk": { "osType": "Linux" } },
                "tags": { "env": "prod" }
            },
            {
                "id": "/subscriptions/0000/resourceGroups/SHOP/providers/Microsoft.Compute/virtualMachines/batch",
                "name": "batch", "resourceGroup": "SHOP",
                "powerState": "VM deallocated", "publicIps": "", "privateIps": "10.0.0.5", "fqdns": "",
                "osProfile": { "adminUsername": "azureuser" },
                "storageProfile": { "osDisk": { "osType": "Linux" } },
                "tags": { "morphgate-user": "ops" }
            },
            {
                "id": "/subscriptions/0000/resourceGroups/SHOP/providers/Microsoft.Compute/virtualMachines/win",
                "name": "win", "resourceGroup": "SHOP", "powerState": "VM running",
                "storageProfile": { "osDisk": { "osType": "Windows" } }, "tags": null
            }
        ]))
        .unwrap();
        let m = machines_of(listed);
        assert_eq!(m.len(), 2);
        assert_eq!(
            m[0].external_id,
            "azure:/subscriptions/0000/resourcegroups/shop/providers/microsoft.compute/virtualmachines/web-1"
        );
        assert_eq!(
            m[0].public_address.as_deref(),
            Some("web-1.westeurope.cloudapp.azure.com")
        );
        assert_eq!(m[0].user.as_deref(), Some("azureuser"));
        assert!(m[0].running);
        assert_eq!(m[1].public_address, None);
        assert_eq!(m[1].user.as_deref(), Some("ops"));
        assert_eq!(
            (m[1].running, m[1].state.as_str()),
            (false, "VM deallocated")
        );
    }
}
