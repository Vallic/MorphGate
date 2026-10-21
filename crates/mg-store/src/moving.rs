//! Moving and copying items to another vault: from the personal vault to a team's, between team
//! vaults, and back.
//!
//! A move keeps the item's id (sessions, tunnels and links that name it keep working) and leaves a
//! tombstone in the old vault; a copy gets a new id and leaves the original where it was. What an
//! item uses (its key, identity, jump host, VPN, theme) comes along, what belongs to it rides along
//! (a host's attachments and tunnels, a group's hosts), and the links between them are rewritten to
//! match. Something still used by an item that stays can't move: a copy goes instead. Session logs
//! never move: a recording stays in the vault it was made in.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::vault::now;
use crate::{Access, BlobKind, Error, HostAuth, Item, ItemData, LocalVault, Result};

/// What happens to an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carry {
    /// To the other vault, with the same id; gone from this one.
    Move,
    /// A copy (with a new id) goes; this one stays.
    Copy,
    /// Stays, and what goes stops using it (only for a jump host, VPN, terminal theme, a group's
    /// identity, or an attachment's host).
    Leave,
}

/// Why an item is part of a move.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Why {
    /// Picked.
    Chosen,
    /// Belongs to an item that goes: a host's attachments and tunnels, a group's hosts.
    Rides { with: String },
    /// Items that go use it.
    Used { by: Vec<String> },
}

/// One item in a move, and what happens to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Planned {
    pub id: String,
    pub kind: &'static str,
    pub label: String,
    pub why: Why,
    pub carry: Carry,
    /// What it can be switched to; empty when there is no choice.
    pub choices: Vec<Carry>,
    /// Items that stay and use it (which is why a copy goes instead).
    pub kept_by: Vec<String>,
}

/// What a move would do, for the user to check (and adjust) before it happens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MovePlan {
    pub from: String,
    pub to: String,
    pub items: Vec<Planned>,
    /// Things worth knowing: hosts leaving a group, session logs staying, who can use what goes.
    pub notes: Vec<String>,
}

/// What a move did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Moved {
    pub moved: usize,
    pub copied: usize,
    /// For each picked item, its id in the other vault (a copy's is new).
    pub ids: BTreeMap<String, String>,
}

/// An item's name, for plans and messages.
pub fn label(data: &ItemData) -> String {
    match data {
        ItemData::Host(h) => h.label.clone(),
        ItemData::SshKey(k) => k.label.clone(),
        ItemData::Snippet(s) => s.name.clone(),
        ItemData::PortForward(f) => f.label.clone(),
        ItemData::Vpn(v) => v.label.clone(),
        ItemData::MemberKey(k) => k.label.clone(),
        ItemData::TerminalTheme(t) => t.name.clone(),
        ItemData::SessionLog(l) => l.title.clone(),
        ItemData::Attachment(a) => a.name.clone(),
        ItemData::Identity(i) => i.label.clone(),
        ItemData::HostGroup(g) => g.name.clone(),
        ItemData::CloudSource(c) => c.label.clone(),
        ItemData::HostCa(c) => c.label.clone(),
        ItemData::Unknown => "item".into(),
    }
}

fn key(a: &HostAuth) -> Option<&str> {
    match a {
        HostAuth::Key { key_ref } => Some(key_ref.as_str()),
        _ => None,
    }
}

/// A theme item (the app's built-in themes aren't items).
fn theme(t: &Option<String>) -> Option<&str> {
    t.as_deref()
        .filter(|t| !t.starts_with(crate::model::TerminalTheme::BUILTIN))
}

/// The items `data` uses, and whether each could be left out (`true`) or is needed. A host's
/// group isn't among them: hosts ride with their group, and leave a group that stays.
fn uses(data: &ItemData) -> Vec<(&str, bool)> {
    let mut out = Vec::new();
    match data {
        ItemData::Host(h) => {
            out.extend(key(&h.auth).map(|k| (k, false)));
            out.extend(h.identity_ref.as_deref().map(|i| (i, false)));
            out.extend(h.jump_ref.as_deref().map(|j| (j, true)));
            out.extend(h.vpn_ref.as_deref().map(|v| (v, true)));
            out.extend(theme(&h.theme_ref).map(|t| (t, true)));
        }
        ItemData::Identity(i) => out.extend(key(&i.auth).map(|k| (k, false))),
        ItemData::HostGroup(g) => {
            out.extend(g.identity_ref.as_deref().map(|i| (i, true)));
            out.extend(g.jump_ref.as_deref().map(|j| (j, true)));
            out.extend(g.vpn_ref.as_deref().map(|v| (v, true)));
            out.extend(theme(&g.theme_ref).map(|t| (t, true)));
        }
        ItemData::PortForward(f) => out.push((f.host_ref.as_str(), false)),
        ItemData::Attachment(a) => out.extend(a.host_ref.as_deref().map(|h| (h, true))),
        ItemData::CloudSource(c) => {
            out.extend(c.key_ref.as_deref().map(|k| (k, true)));
            out.extend(c.jump_ref.as_deref().map(|j| (j, true)));
        }
        _ => {}
    }
    out
}

/// Whether `data` refers to `id` in any way (its group included). Session logs don't count: a
/// recording may keep naming a host that moved.
fn refers_to(data: &ItemData, id: &str) -> bool {
    let group = matches!(data, ItemData::Host(h) if h.group_ref.as_deref() == Some(id));
    group || uses(data).iter().any(|(r, _)| *r == id)
}

/// Rewrites `data`'s links: to items going (`map`: old id → id in the other vault), or dropped
/// (`leave`).
fn relink(
    data: ItemData,
    map: &HashMap<String, String>,
    leave: &BTreeSet<String>,
) -> Result<ItemData> {
    let need = |id: &str| {
        map.get(id)
            .cloned()
            .ok_or_else(|| Error::Invalid(format!("item {id} would be left behind")))
    };
    let optional = |id: Option<String>| -> Result<Option<String>> {
        match id {
            None => Ok(None),
            Some(t) if t.starts_with(crate::model::TerminalTheme::BUILTIN) => Ok(Some(t)),
            Some(id) if leave.contains(&id) => Ok(None),
            Some(id) => need(&id).map(Some),
        }
    };
    let auth = |a: HostAuth| -> Result<HostAuth> {
        Ok(match a {
            HostAuth::Key { key_ref } => HostAuth::Key {
                key_ref: need(&key_ref)?,
            },
            other => other,
        })
    };
    Ok(match data {
        ItemData::Host(h) => ItemData::Host(crate::Host {
            auth: auth(h.auth)?,
            identity_ref: h.identity_ref.map(|i| need(&i)).transpose()?,
            jump_ref: optional(h.jump_ref)?,
            vpn_ref: optional(h.vpn_ref)?,
            theme_ref: optional(h.theme_ref)?,
            group_ref: h.group_ref.map(|g| need(&g)).transpose()?,
            // Kept by its cloud source where that goes too; else an ordinary host there.
            source: h.source.and_then(|s| {
                map.get(&s.source_ref).map(|to| {
                    Box::new(crate::HostSource {
                        source_ref: to.clone(),
                        ..*s
                    })
                })
            }),
            ..h
        }),
        ItemData::Identity(i) => ItemData::Identity(crate::Identity {
            auth: auth(i.auth)?,
            ..i
        }),
        ItemData::HostGroup(g) => ItemData::HostGroup(crate::HostGroup {
            identity_ref: optional(g.identity_ref)?,
            jump_ref: optional(g.jump_ref)?,
            vpn_ref: optional(g.vpn_ref)?,
            theme_ref: optional(g.theme_ref)?,
            ..g
        }),
        ItemData::PortForward(f) => ItemData::PortForward(crate::PortForward {
            host_ref: need(&f.host_ref)?,
            ..f
        }),
        ItemData::Attachment(a) => ItemData::Attachment(crate::Attachment {
            host_ref: optional(a.host_ref)?,
            ..a
        }),
        ItemData::CloudSource(c) => ItemData::CloudSource(crate::CloudSource {
            key_ref: optional(c.key_ref)?,
            jump_ref: optional(c.jump_ref)?,
            ..c
        }),
        other => other,
    })
}

/// An item while a plan is worked out.
struct Entry {
    why: Why,
    carry: Carry,
    /// Something going can't do without it.
    required: bool,
}

impl LocalVault {
    /// What moving the items `ids` (all in one vault) to vault `to` would do. `choices` switch
    /// items to what their [`Planned::choices`] allow; others take the default.
    pub fn plan_move(
        &self,
        ids: &[String],
        to: &str,
        choices: &BTreeMap<String, Carry>,
    ) -> Result<MovePlan> {
        let (plan, _) = self.work_out(ids, to, choices)?;
        Ok(plan)
    }

    /// Moves (or copies) the items `ids` to vault `to`, as [`plan_move`](Self::plan_move) says:
    /// all of it, or nothing. Attachments' files must be on this device.
    pub fn move_items(
        &mut self,
        ids: &[String],
        to: &str,
        choices: &BTreeMap<String, Carry>,
    ) -> Result<Moved> {
        let (plan, source) = self.work_out(ids, to, choices)?;
        let from = plan.from.clone();
        let going: Vec<&Planned> = plan
            .items
            .iter()
            .filter(|p| p.carry != Carry::Leave)
            .collect();
        let map: HashMap<String, String> = going
            .iter()
            .map(|p| {
                let id = match p.carry {
                    Carry::Copy => Ulid::generate().to_string(),
                    _ => p.id.clone(),
                };
                (p.id.clone(), id)
            })
            .collect();
        let leave: BTreeSet<String> = plan
            .items
            .iter()
            .filter(|p| p.carry == Carry::Leave)
            .map(|p| p.id.clone())
            .collect();

        // Everything is read and rewritten first: nothing is written until the whole move holds.
        let mut writes: Vec<(String, ItemData, Option<String>)> = Vec::new();
        let mut files: Vec<(String, zeroize::Zeroizing<Vec<u8>>)> = Vec::new();
        for p in &going {
            let item = &source[&p.id];
            let mut data = item.data.clone();
            // A host leaving a group that stays keeps what it took from it.
            if let ItemData::Host(h) = &data
                && let Some(g) = h.group_ref.as_deref().filter(|g| !map.contains_key(*g))
                && let Some(Item {
                    data: ItemData::HostGroup(group),
                    ..
                }) = source.get(g)
            {
                data = ItemData::Host(h.clone().without_group(&item.id, group));
            }
            let mut old_blob = None;
            if let ItemData::Attachment(a) = &data {
                let plain = self
                    .open_blob(&from, BlobKind::Attachment, &a.blob)?
                    .ok_or_else(|| {
                        Error::Invalid(format!(
                            "the file {} isn't on this device yet: open the host and save it first",
                            a.name
                        ))
                    })?;
                files.push((p.id.clone(), plain));
                old_blob = (p.carry == Carry::Move).then(|| a.blob.clone());
            }
            writes.push((p.id.clone(), relink(data, &map, &leave)?, old_blob));
        }

        self.conn.execute_batch("SAVEPOINT move_items")?;
        let done = (|| -> Result<Moved> {
            let stamp = now();
            for p in going.iter().filter(|p| p.carry == Carry::Move) {
                self.tombstone(&from, &p.id, stamp)?;
            }
            let mut forget = Vec::new();
            for (id, data, old_blob) in &mut writes {
                if let ItemData::Attachment(a) = data {
                    let (_, plain) = files.iter().find(|(f, _)| f == id).expect("read above");
                    a.blob = self.add_blob(to, BlobKind::Attachment, plain)?.hash;
                }
                self.write(to, &map[id.as_str()], data)?;
                forget.extend(old_blob.clone());
            }
            // Checked together: a group's jump host may be one of its own hosts.
            for (id, data, _) in &writes {
                self.validate(to, Some(&map[id.as_str()]), data)?;
            }
            let hashes: Vec<&str> = forget.iter().map(String::as_str).collect();
            self.forget_blobs(&from, &hashes)?;
            Ok(Moved {
                moved: going.iter().filter(|p| p.carry == Carry::Move).count(),
                copied: going.iter().filter(|p| p.carry == Carry::Copy).count(),
                ids: ids
                    .iter()
                    .filter_map(|id| map.get(id).map(|m| (id.clone(), m.clone())))
                    .collect(),
            })
        })();
        match done {
            Ok(moved) => {
                self.conn.execute_batch("RELEASE move_items")?;
                Ok(moved)
            }
            Err(e) => {
                self.conn
                    .execute_batch("ROLLBACK TO move_items; RELEASE move_items")?;
                Err(e)
            }
        }
    }

    /// The plan, and the source vault's items by id.
    fn work_out(
        &self,
        ids: &[String],
        to: &str,
        choices: &BTreeMap<String, Carry>,
    ) -> Result<(MovePlan, HashMap<String, Item>)> {
        let keys = self.unlocked()?;
        let first = ids
            .first()
            .ok_or_else(|| Error::Invalid("nothing to move".into()))?;
        let all = self.items()?;
        let from = all
            .iter()
            .find(|i| i.id == *first)
            .ok_or_else(|| Error::NotFound(first.clone()))?
            .vault_id
            .clone();
        if from == to {
            return Err(Error::Invalid("it is in that vault already".into()));
        }
        if keys.access(to)? < Access::Write {
            return Err(Error::ReadOnly);
        }
        let (target_personal, target_directory) = self.vault_flags(to)?;
        if target_directory {
            return Err(Error::Invalid(
                "the member key directory only holds members' public keys".into(),
            ));
        }
        let (source_personal, _) = self.vault_flags(&from)?;
        let can_move = keys.access(&from)? >= Access::Write;
        let source: HashMap<String, Item> = all
            .into_iter()
            .filter(|i| i.vault_id == from)
            .map(|i| (i.id.clone(), i))
            .collect();
        for id in ids {
            match source.get(id).map(|i| &i.data) {
                None => return Err(Error::Invalid("pick items from one vault".into())),
                Some(ItemData::SessionLog(_)) => {
                    return Err(Error::Invalid(
                        "session logs stay in the vault they were recorded in".into(),
                    ));
                }
                Some(ItemData::MemberKey(_) | ItemData::Unknown) => {
                    return Err(Error::Invalid("that item can't be moved".into()));
                }
                Some(_) => {}
            }
        }

        // Items that must stay copies: something staying uses them. Found by trying, until
        // nothing changes (each round only adds).
        let mut stuck: BTreeSet<String> = BTreeSet::new();
        let mut needed: BTreeSet<String> = BTreeSet::new();
        let (entries, order) = loop {
            let (entries, order) = self.gather(ids, &source, choices, &stuck, &needed, can_move);
            let mut changed = false;
            for (id, e) in &entries {
                if e.carry == Carry::Move && !staying_users(id, &source, &entries).is_empty() {
                    changed |= stuck.insert(id.clone());
                }
                if e.carry == Carry::Leave && e.required {
                    changed |= needed.insert(id.clone());
                }
            }
            if !changed {
                break (entries, order);
            }
        };

        let mut items: Vec<Planned> = order
            .iter()
            .map(|id| {
                let e = &entries[id];
                let item = &source[id];
                let kept_by = staying_users(id, &source, &entries);
                let choices = match e.why {
                    Why::Rides { .. } => Vec::new(),
                    Why::Chosen if stuck.contains(id) || !can_move => Vec::new(),
                    Why::Chosen => vec![Carry::Move, Carry::Copy],
                    Why::Used { .. } => {
                        let mut c = Vec::new();
                        if can_move && !stuck.contains(id) {
                            c.push(Carry::Move);
                        }
                        c.push(Carry::Copy);
                        if !e.required {
                            c.push(Carry::Leave);
                        }
                        if c.len() == 1 { Vec::new() } else { c }
                    }
                };
                Planned {
                    id: id.clone(),
                    kind: item.data.kind(),
                    label: label(&item.data),
                    why: e.why.clone(),
                    carry: e.carry,
                    choices,
                    kept_by,
                }
            })
            .collect();
        items.sort_by_key(|p| match p.why {
            Why::Chosen => 0,
            Why::Rides { .. } => 1,
            Why::Used { .. } => 2,
        });

        let mut notes = Vec::new();
        let goes = |id: &str| entries.get(id).is_some_and(|e| e.carry != Carry::Leave);
        for p in items.iter().filter(|p| p.carry != Carry::Leave) {
            if let ItemData::Host(h) = &source[&p.id].data
                && let Some(g) = h.group_ref.as_deref().filter(|g| !goes(g))
                && let Some(group) = source.get(g)
            {
                notes.push(format!(
                    "{} leaves the group {} and keeps the settings it took from it.",
                    p.label,
                    label(&group.data)
                ));
            }
        }
        let logs = source
            .values()
            .filter(|i| {
                matches!(&i.data, ItemData::SessionLog(l)
                    if l.host_ref.as_deref().is_some_and(|h| entries.get(h).is_some_and(|e| e.carry == Carry::Move)))
            })
            .count();
        match logs {
            0 => {}
            1 => notes
                .push("A session log stays where it was recorded: recordings don't move.".into()),
            n => notes.push(format!(
                "{n} session logs stay where they were recorded: recordings don't move."
            )),
        }
        let secrets =
            items
                .iter()
                .filter(|p| p.carry != Carry::Leave)
                .any(|p| match &source[&p.id].data {
                    ItemData::SshKey(_) | ItemData::Vpn(_) => true,
                    ItemData::Host(crate::Host { auth, .. })
                    | ItemData::Identity(crate::Identity { auth, .. }) => {
                        matches!(auth, HostAuth::Password { password: Some(_) })
                    }
                    _ => false,
                });
        if secrets && !target_personal {
            notes.push(
                "Everyone who can open that vault can use the keys, passwords and VPN profiles that go there.".into(),
            );
        }
        if !source_personal && items.iter().any(|p| p.carry == Carry::Move) {
            notes.push("What moves leaves this team vault: its other members lose it.".into());
        }
        Ok((
            MovePlan {
                from,
                to: to.to_owned(),
                items,
                notes,
            },
            source,
        ))
    }

    /// The items a move takes along, breadth first from the picked ones.
    fn gather(
        &self,
        ids: &[String],
        source: &HashMap<String, Item>,
        choices: &BTreeMap<String, Carry>,
        stuck: &BTreeSet<String>,
        needed: &BTreeSet<String>,
        can_move: bool,
    ) -> (BTreeMap<String, Entry>, Vec<String>) {
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
        let mut order = Vec::new();
        let mut queue: VecDeque<(String, Why, Option<Carry>, bool)> = ids
            .iter()
            .map(|id| (id.clone(), Why::Chosen, None, true))
            .collect();
        let movable = |id: &str| can_move && !stuck.contains(id);
        while let Some((id, why, parent, required)) = queue.pop_front() {
            let Some(item) = source.get(&id) else {
                continue;
            };
            if let Some(e) = entries.get_mut(&id) {
                e.required |= required;
                if let (Why::Used { by }, Why::Used { by: more }) = (&mut e.why, &why) {
                    for b in more {
                        if !by.contains(b) {
                            by.push(b.clone());
                        }
                    }
                }
                continue;
            }
            let chosen = choices.get(&id).copied();
            let carry = match &why {
                Why::Chosen => match chosen {
                    Some(Carry::Copy) => Carry::Copy,
                    _ if movable(&id) => Carry::Move,
                    _ => Carry::Copy,
                },
                Why::Rides { .. } => match parent {
                    Some(Carry::Move) if movable(&id) => Carry::Move,
                    _ => Carry::Copy,
                },
                Why::Used { .. } => match chosen {
                    Some(Carry::Leave) if !required && !needed.contains(&id) => Carry::Leave,
                    Some(Carry::Copy) => Carry::Copy,
                    _ if movable(&id) => Carry::Move,
                    _ => Carry::Copy,
                },
            };
            entries.insert(
                id.clone(),
                Entry {
                    why,
                    carry,
                    required,
                },
            );
            order.push(id.clone());
            if carry == Carry::Leave {
                continue;
            }
            let name = label(&item.data);
            // What belongs to it rides along: a host's files (and, when it moves, its tunnels),
            // a group's hosts.
            for other in source.values() {
                let rides = match &other.data {
                    ItemData::Attachment(a) => {
                        matches!(item.data, ItemData::Host(_))
                            && a.host_ref.as_deref() == Some(id.as_str())
                    }
                    ItemData::PortForward(f) => carry == Carry::Move && f.host_ref == id,
                    ItemData::Host(h) => {
                        matches!(item.data, ItemData::HostGroup(_))
                            && h.group_ref.as_deref() == Some(id.as_str())
                    }
                    _ => false,
                };
                if rides {
                    queue.push_back((
                        other.id.clone(),
                        Why::Rides { with: name.clone() },
                        Some(carry),
                        true,
                    ));
                }
            }
            // What it uses comes along; a host whose group stays brings what it took from it.
            let mut data = item.data.clone();
            if let ItemData::Host(h) = &data
                && let Some(g) = h.group_ref.as_deref()
                // Only picking a group takes it along.
                && !ids.iter().any(|i| i == g)
                && let Some(Item {
                    data: ItemData::HostGroup(group),
                    ..
                }) = source.get(g)
            {
                data = ItemData::Host(h.clone().without_group(&id, group));
            }
            for (used, optional) in uses(&data) {
                queue.push_back((
                    used.to_owned(),
                    Why::Used {
                        by: vec![name.clone()],
                    },
                    None,
                    !optional,
                ));
            }
        }
        (entries, order)
    }

    /// Whether the vault is the personal one, and whether it is a member key directory.
    fn vault_flags(&self, vault: &str) -> Result<(bool, bool)> {
        Ok(self.conn.query_row(
            "SELECT personal, directory FROM vaults WHERE id = ?1",
            [vault],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }
}

/// Items that stay (aren't moving) and use `id`.
fn staying_users(
    id: &str,
    source: &HashMap<String, Item>,
    entries: &BTreeMap<String, Entry>,
) -> Vec<String> {
    let mut users: Vec<String> = source
        .values()
        .filter(|i| i.id != id)
        .filter(|i| !entries.get(&i.id).is_some_and(|e| e.carry == Carry::Move))
        .filter(|i| refers_to(&i.data, id))
        .map(|i| label(&i.data))
        .collect();
    users.sort();
    users
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Ring;
    use crate::{
        ForwardRule, Host, HostGroup, Identity, PortForward, SessionLog, SshKey, VpnKind,
        VpnProfile,
    };
    use mg_vault::{KdfParams, VaultKey};

    fn vault() -> LocalVault {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        v
    }

    /// A team vault this account can open with `access`.
    fn team(v: &mut LocalVault, id: &str, access: Access) {
        let key = VaultKey::generate().unwrap();
        v.conn
            .execute(
                "INSERT INTO vaults (id, key_id, wrapped_vault_key, created_at, personal, org_id, permission, name)
                 VALUES (?1, ?2, x'02', 1, 0, 'ORG', ?3, ?1)",
                rusqlite::params![id, key.id().as_slice(), access.as_str()],
            )
            .unwrap();
        v.keys.as_mut().unwrap().shared.insert(
            id.into(),
            Ring {
                current: *key.id(),
                keys: vec![key],
                access,
            },
        );
    }

    fn personal(v: &LocalVault) -> String {
        v.unlocked().unwrap().vault_id.clone()
    }

    fn key(v: &mut LocalVault, label: &str) -> String {
        v.upsert(
            None,
            ItemData::SshKey(SshKey {
                label: label.into(),
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
                passphrase: None,
                public_key: format!("ssh-ed25519 AAAA {label}"),
                algorithm: "ed25519".into(),
                fingerprint: format!("SHA256:{label}"),
                certificate: None,
                renew: None,
            }),
        )
        .unwrap()
        .id
    }

    fn host_data(label: &str, f: impl FnOnce(&mut Host)) -> ItemData {
        let mut h = Host {
            label: label.into(),
            hostname: format!("{label}.internal"),
            port: 22,
            user: "deploy".into(),
            auth: HostAuth::system_agent(),
            jump_ref: None,
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
        f(&mut h);
        ItemData::Host(h)
    }

    fn host(v: &mut LocalVault, label: &str, f: impl FnOnce(&mut Host)) -> String {
        v.upsert(None, host_data(label, f)).unwrap().id
    }

    fn carry(plan: &MovePlan, id: &str) -> Carry {
        plan.items.iter().find(|p| p.id == id).unwrap().carry
    }

    fn live(v: &LocalVault, vault: &str) -> Vec<Item> {
        v.items()
            .unwrap()
            .into_iter()
            .filter(|i| i.vault_id == vault)
            .collect()
    }

    #[test]
    fn a_host_takes_its_key_files_and_tunnels_along() {
        let mut v = vault();
        team(&mut v, "TEAM", Access::Write);
        let me = personal(&v);
        let k = key(&mut v, "deploy");
        let h = host(&mut v, "db1", |h| {
            h.auth = HostAuth::Key { key_ref: k.clone() }
        });
        let file = v
            .attach(
                &me,
                Some(&h),
                "runbook.md",
                b"restart: systemctl restart app",
            )
            .unwrap();
        let tunnel = v
            .upsert(
                None,
                ItemData::PortForward(PortForward {
                    label: "pg".into(),
                    host_ref: h.clone(),
                    rule: ForwardRule::Local {
                        bind_host: "127.0.0.1".into(),
                        bind_port: 15432,
                        target_host: "127.0.0.1".into(),
                        target_port: 5432,
                    },
                }),
            )
            .unwrap()
            .id;
        let old_blob = match v.item(&file).unwrap().data {
            ItemData::Attachment(a) => a.blob,
            _ => unreachable!(),
        };

        let plan = v
            .plan_move(std::slice::from_ref(&h), "TEAM", &BTreeMap::new())
            .unwrap();
        assert_eq!(plan.from, me);
        for id in [&h, &k, &file, &tunnel] {
            assert_eq!(carry(&plan, id), Carry::Move, "{id}");
        }
        assert!(matches!(&plan.items[0].why, Why::Chosen));
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("Everyone who can open that vault"))
        );

        let moved = v
            .move_items(std::slice::from_ref(&h), "TEAM", &BTreeMap::new())
            .unwrap();
        assert_eq!((moved.moved, moved.copied), (4, 0));
        assert_eq!(moved.ids[&h], h, "a move keeps the id");
        assert!(live(&v, &me).is_empty());
        let there = live(&v, "TEAM");
        assert_eq!(there.len(), 4);
        // The file is sealed again in the team vault; the personal copy is gone.
        let ItemData::Attachment(a) = v.item(&file).unwrap().data else {
            unreachable!()
        };
        assert_ne!(a.blob, old_blob);
        let plain = v
            .open_blob("TEAM", BlobKind::Attachment, &a.blob)
            .unwrap()
            .unwrap();
        assert_eq!(&plain[..], b"restart: systemctl restart app");
        assert!(
            v.open_blob(&me, BlobKind::Attachment, &old_blob)
                .unwrap()
                .is_none()
        );
        // The old copies sync away as tombstones.
        let tombstones: i64 = v
            .conn
            .query_row(
                "SELECT COUNT(*) FROM items WHERE vault_id = ?1 AND deleted = 1 AND dirty = 1",
                [&me],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tombstones, 4);
        // And back again, over the tombstones.
        v.move_items(std::slice::from_ref(&h), &me, &BTreeMap::new())
            .unwrap();
        assert_eq!(live(&v, &me).len(), 4);
        assert!(live(&v, "TEAM").is_empty());
    }

    #[test]
    fn something_still_used_here_is_copied_instead() {
        let mut v = vault();
        team(&mut v, "TEAM", Access::Write);
        let me = personal(&v);
        let k = key(&mut v, "shared");
        let auth = |k: &String| HostAuth::Key { key_ref: k.clone() };
        let web = host(&mut v, "web", |h| h.auth = auth(&k));
        host(&mut v, "db", |h| h.auth = auth(&k));

        let plan = v
            .plan_move(std::slice::from_ref(&web), "TEAM", &BTreeMap::new())
            .unwrap();
        let shared = plan.items.iter().find(|p| p.id == k).unwrap();
        assert_eq!(shared.carry, Carry::Copy);
        assert_eq!(shared.kept_by, vec!["db".to_owned()]);
        assert!(shared.choices.is_empty(), "nothing else is possible");

        v.move_items(std::slice::from_ref(&web), "TEAM", &BTreeMap::new())
            .unwrap();
        let ItemData::Host(moved) = v.item(&web).unwrap().data else {
            unreachable!()
        };
        let HostAuth::Key { key_ref } = moved.auth else {
            unreachable!()
        };
        assert_ne!(key_ref, k, "the copy has its own id");
        assert_eq!(v.item(&key_ref).unwrap().vault_id, "TEAM");
        assert_eq!(v.item(&k).unwrap().vault_id, me, "db keeps its key");
    }

    #[test]
    fn a_group_goes_with_its_hosts_identity_and_bastion() {
        let mut v = vault();
        team(&mut v, "TEAM", Access::Manage);
        let k = key(&mut v, "ops");
        let ops = v
            .upsert(
                None,
                ItemData::Identity(Identity {
                    label: "ops".into(),
                    user: "ops".into(),
                    auth: HostAuth::Key { key_ref: k.clone() },
                }),
            )
            .unwrap()
            .id;
        let bastion = host(&mut v, "bastion", |_| {});
        let group = v
            .upsert(
                None,
                ItemData::HostGroup(HostGroup {
                    name: "prod".into(),
                    identity_ref: Some(ops.clone()),
                    jump_ref: Some(bastion.clone()),
                    ..Default::default()
                }),
            )
            .unwrap()
            .id;
        // The bastion is in the group it is the jump host of.
        v.upsert(
            Some(&bastion),
            host_data("bastion", |h| h.group_ref = Some(group.clone())),
        )
        .unwrap();
        let db = host(&mut v, "db", |h| {
            h.user = String::new();
            h.group_ref = Some(group.clone());
        });

        let plan = v
            .plan_move(std::slice::from_ref(&group), "TEAM", &BTreeMap::new())
            .unwrap();
        for id in [&group, &bastion, &db, &ops, &k] {
            assert_eq!(carry(&plan, id), Carry::Move, "{id}");
        }
        v.move_items(std::slice::from_ref(&group), "TEAM", &BTreeMap::new())
            .unwrap();
        assert_eq!(live(&v, "TEAM").len(), 5);
        let (_, target) = v.route(&db).unwrap();
        assert_eq!(v.effective_host(&target).unwrap().user, "ops");
    }

    #[test]
    fn a_host_leaving_its_group_keeps_what_it_took_from_it() {
        let mut v = vault();
        team(&mut v, "TEAM", Access::Write);
        let me = personal(&v);
        let ops = v
            .upsert(
                None,
                ItemData::Identity(Identity {
                    label: "ops".into(),
                    user: "ops".into(),
                    auth: HostAuth::system_agent(),
                }),
            )
            .unwrap()
            .id;
        let group = v
            .upsert(
                None,
                ItemData::HostGroup(HostGroup {
                    name: "prod".into(),
                    identity_ref: Some(ops.clone()),
                    keep_session: true,
                    ..Default::default()
                }),
            )
            .unwrap()
            .id;
        let db = host(&mut v, "db", |h| {
            h.user = String::new();
            h.group_ref = Some(group.clone());
        });

        let plan = v
            .plan_move(std::slice::from_ref(&db), "TEAM", &BTreeMap::new())
            .unwrap();
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("db leaves the group prod"))
        );
        // The group stays, and still uses the identity: a copy goes with db.
        assert_eq!(carry(&plan, &ops), Carry::Copy);
        v.move_items(std::slice::from_ref(&db), "TEAM", &BTreeMap::new())
            .unwrap();
        let ItemData::Host(h) = v.item(&db).unwrap().data else {
            unreachable!()
        };
        assert_eq!(h.group_ref, None);
        assert!(h.keep_session);
        let identity = h.identity_ref.unwrap();
        assert_eq!(v.item(&identity).unwrap().vault_id, "TEAM");
        assert_eq!(v.item(&group).unwrap().vault_id, me);
    }

    #[test]
    fn a_vpn_can_be_left_behind() {
        let mut v = vault();
        team(&mut v, "TEAM", Access::Write);
        let me = personal(&v);
        let vpn = v
            .upsert(
                None,
                ItemData::Vpn(VpnProfile {
                    label: "home".into(),
                    vpn: VpnKind::Wireguard {
                        config: "[Interface]\nPrivateKey = x\n".into(),
                    },
                }),
            )
            .unwrap()
            .id;
        let h = host(&mut v, "nas", |h| h.vpn_ref = Some(vpn.clone()));

        let default = v
            .plan_move(std::slice::from_ref(&h), "TEAM", &BTreeMap::new())
            .unwrap();
        let p = default.items.iter().find(|p| p.id == vpn).unwrap();
        assert_eq!(p.carry, Carry::Move);
        assert_eq!(p.choices, vec![Carry::Move, Carry::Copy, Carry::Leave]);

        let leave = BTreeMap::from([(vpn.clone(), Carry::Leave)]);
        v.move_items(std::slice::from_ref(&h), "TEAM", &leave)
            .unwrap();
        let ItemData::Host(moved) = v.item(&h).unwrap().data else {
            unreachable!()
        };
        assert_eq!(moved.vpn_ref, None);
        assert_eq!(v.item(&vpn).unwrap().vault_id, me);
    }

    #[test]
    fn from_a_read_only_vault_only_copies_and_logs_stay() {
        let mut v = vault();
        team(&mut v, "TEAM", Access::Manage);
        let me = personal(&v);
        let h = v
            .upsert_in("TEAM", None, host_data("db", |_| {}))
            .unwrap()
            .id;
        v.upsert_in(
            "TEAM",
            None,
            ItemData::SessionLog(SessionLog {
                host_ref: Some(h.clone()),
                title: "db".into(),
                address: "deploy@db:22".into(),
                started_at: 1,
                ended_at: None,
                cols: 80,
                rows: 24,
                chunks: vec![],
                output_bytes: 0,
                device: "laptop".into(),
            }),
        )
        .unwrap();
        let plan = v
            .plan_move(std::slice::from_ref(&h), &me, &BTreeMap::new())
            .unwrap();
        assert_eq!(carry(&plan, &h), Carry::Move);
        assert!(plan.notes.iter().any(|n| n.contains("session log")));
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("its other members lose it"))
        );

        v.keys
            .as_mut()
            .unwrap()
            .shared
            .get_mut("TEAM")
            .unwrap()
            .access = Access::Read;
        let plan = v
            .plan_move(std::slice::from_ref(&h), &me, &BTreeMap::new())
            .unwrap();
        assert_eq!(carry(&plan, &h), Carry::Copy);
        assert!(plan.items[0].choices.is_empty());
        let copied = v
            .move_items(std::slice::from_ref(&h), &me, &BTreeMap::new())
            .unwrap();
        assert_eq!((copied.moved, copied.copied), (0, 1));
        assert_eq!(v.item(&h).unwrap().vault_id, "TEAM");
        assert_eq!(v.item(&copied.ids[&h]).unwrap().vault_id, me);
    }

    #[test]
    fn nothing_moves_into_a_vault_it_cant_write_or_out_of_two_vaults() {
        let mut v = vault();
        team(&mut v, "READ", Access::Read);
        team(&mut v, "TEAM", Access::Write);
        let a = host(&mut v, "a", |_| {});
        let b = v
            .upsert_in("TEAM", None, host_data("b", |_| {}))
            .unwrap()
            .id;
        assert!(matches!(
            v.plan_move(std::slice::from_ref(&a), "READ", &BTreeMap::new()),
            Err(Error::ReadOnly)
        ));
        assert!(v.plan_move(&[a, b], "TEAM", &BTreeMap::new()).is_err());
    }
}
