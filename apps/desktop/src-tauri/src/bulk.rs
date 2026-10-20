//! Changes to several items at once, from the lists' selections: deleting them, and putting hosts
//! in a group. Each item is changed as on its own; the ones that can't be are said, not hidden.

use mg_store::{ItemData, LocalVault};
use serde::Serialize;
use tauri::State;

use crate::vault::{VaultState, save};

/// How many items changed, and why the others didn't.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResult {
    done: usize,
    refused: Vec<String>,
}

/// The kinds deleted here; tunnels and VPNs stop what runs first, through their own commands.
fn plain(data: &ItemData) -> bool {
    matches!(
        data,
        ItemData::Host(_)
            | ItemData::HostGroup(_)
            | ItemData::SshKey(_)
            | ItemData::Identity(_)
            | ItemData::Snippet(_)
            | ItemData::HostCa(_)
    )
}

/// Deletes the items, in an order that works: something still used by another item in the
/// selection goes after it (a jump host after the hosts behind it, a key after its identity). An
/// item used by something that stays is kept, and said why.
pub(crate) fn delete_items(v: &mut LocalVault, ids: &[String]) -> BulkResult {
    let mut result = BulkResult::default();
    let mut left: Vec<String> = Vec::new();
    for id in ids {
        match v.item(id) {
            Ok(item) if plain(&item.data) => left.push(id.clone()),
            Ok(_) => result
                .refused
                .push(format!("{id}: delete it on its own page")),
            Err(e) => result.refused.push(e.to_string()),
        }
    }
    // Each round deletes what nothing uses any more; a round that deletes nothing ends it.
    while !left.is_empty() {
        let tried = left.len();
        let mut why = Vec::new();
        left.retain(|id| match v.delete(id) {
            Ok(()) => false,
            Err(e) => {
                why.push(e.to_string());
                true
            }
        });
        result.done += tried - left.len();
        if left.len() == tried {
            result.refused.extend(why);
            break;
        }
    }
    result
}

/// Puts hosts in a group (`None`: in none). The group must be in the hosts' vault.
pub(crate) fn set_group(v: &mut LocalVault, ids: &[String], group: Option<&str>) -> BulkResult {
    let mut result = BulkResult::default();
    for id in ids {
        let item = match v.item(id) {
            Ok(i) => i,
            Err(e) => {
                result.refused.push(e.to_string());
                continue;
            }
        };
        let ItemData::Host(mut h) = item.data else {
            result.refused.push(format!("{id}: not a host"));
            continue;
        };
        if h.group_ref.as_deref() == group {
            result.done += 1;
            continue;
        }
        let label = h.label.clone();
        h.group_ref = group.map(str::to_owned);
        match save(v, Some(id), None, ItemData::Host(h)) {
            Ok(_) => result.done += 1,
            Err(e) => result.refused.push(format!("{label}: {e}")),
        }
    }
    result
}

#[tauri::command]
pub fn items_delete(vault: State<'_, VaultState>, ids: Vec<String>) -> Result<BulkResult, String> {
    let result = delete_items(&mut *vault.guard()?, &ids);
    if result.done > 0 {
        vault.changed();
    }
    Ok(result)
}

#[tauri::command]
pub fn hosts_set_group(
    vault: State<'_, VaultState>,
    ids: Vec<String>,
    group_id: Option<String>,
) -> Result<BulkResult, String> {
    let group = group_id.filter(|g| !g.is_empty());
    let result = set_group(&mut *vault.guard()?, &ids, group.as_deref());
    if result.done > 0 {
        vault.changed();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mg_store::{Host, HostAuth, HostGroup, Snippet};
    use mg_vault::KdfParams;

    fn vault() -> LocalVault {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        v
    }

    fn host(v: &mut LocalVault, label: &str, jump: Option<&str>) -> String {
        let h = Host {
            label: label.into(),
            hostname: format!("{label}.example"),
            port: 22,
            user: "ops".into(),
            auth: HostAuth::Password { password: None },
            jump_ref: jump.map(str::to_owned),
            vpn_ref: None,
            theme_ref: None,
            record_sessions: false,
            tags: vec![],
            notes: String::new(),
            group_ref: None,
            identity_ref: None,
            keep_session: false,
            forward_agent: false,
            login_command: None,
            jump_command: None,
            proxy_command: None,
            source: None,
        };
        v.upsert(None, ItemData::Host(h)).unwrap().id
    }

    fn labels(v: &LocalVault) -> Vec<String> {
        let mut out: Vec<String> = v
            .items()
            .unwrap()
            .into_iter()
            .filter_map(|i| match i.data {
                ItemData::Host(h) => Some(h.label),
                _ => None,
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn deletes_a_jump_host_with_the_hosts_behind_it() {
        let mut v = vault();
        let front = host(&mut v, "front", None);
        let web = host(&mut v, "web", Some(&front));
        host(&mut v, "other", None);
        // The jump host first: it's still used then, and goes once its host has.
        let r = delete_items(&mut v, &[front, web]);
        assert_eq!((r.done, r.refused.len()), (2, 0), "{:?}", r.refused);
        assert_eq!(labels(&v), ["other"]);
    }

    #[test]
    fn keeps_what_a_host_that_stays_still_uses() {
        let mut v = vault();
        let front = host(&mut v, "front", None);
        host(&mut v, "web", Some(&front));
        let lone = host(&mut v, "lone", None);
        let r = delete_items(&mut v, &[front, lone]);
        assert_eq!(r.done, 1);
        assert_eq!(r.refused.len(), 1);
        assert!(
            r.refused[0].contains("still used by: web"),
            "{:?}",
            r.refused
        );
        assert_eq!(labels(&v), ["front", "web"]);
    }

    #[test]
    fn deletes_snippets_and_groups_and_says_what_it_leaves() {
        let mut v = vault();
        let snippet = v
            .upsert(
                None,
                ItemData::Snippet(Snippet {
                    name: "df".into(),
                    body: "df -h".into(),
                    tags: vec![],
                }),
            )
            .unwrap()
            .id;
        let group = v
            .upsert(
                None,
                ItemData::HostGroup(HostGroup {
                    name: "Shop".into(),
                    ..HostGroup::default()
                }),
            )
            .unwrap()
            .id;
        let r = delete_items(&mut v, &[snippet, group, "nope".into()]);
        assert_eq!((r.done, r.refused.len()), (2, 1), "{:?}", r.refused);
    }

    #[test]
    fn puts_hosts_in_a_group_and_out_again() {
        let mut v = vault();
        let a = host(&mut v, "a", None);
        let b = host(&mut v, "b", None);
        let group = v
            .upsert(
                None,
                ItemData::HostGroup(HostGroup {
                    name: "Shop".into(),
                    ..HostGroup::default()
                }),
            )
            .unwrap()
            .id;
        let ids = [a.clone(), b];
        let r = set_group(&mut v, &ids, Some(&group));
        assert_eq!((r.done, r.refused.len()), (2, 0), "{:?}", r.refused);
        let in_group = |v: &LocalVault, id: &str| match v.item(id).unwrap().data {
            ItemData::Host(h) => h.group_ref,
            _ => None,
        };
        assert_eq!(in_group(&v, &a).as_deref(), Some(group.as_str()));
        let r = set_group(&mut v, &ids, Some("no-such-group"));
        assert_eq!((r.done, r.refused.len()), (0, 2));
        assert!(r.refused[0].starts_with("a: "), "{:?}", r.refused);
        set_group(&mut v, &ids, None);
        assert_eq!(in_group(&v, &a), None);
    }
}
