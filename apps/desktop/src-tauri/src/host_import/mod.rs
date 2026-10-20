//! Importing hosts from other SSH clients: OpenSSH's configuration (`~/.ssh/config`), PuTTY's
//! saved sessions, CSV files (Termius' import template, and the exports of other managers) and
//! Royal TS documents. Each source becomes a plan: hosts, the keys they sign in with, their jump
//! hosts and groups. A preview shows it; then the hosts the person picked are imported, with the
//! jump hosts they need.

pub(crate) mod csv;
mod putty;
mod royal;
mod ssh_config;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use mg_store::{Host, HostAuth, HostGroup, ItemData, LocalVault, SshKey};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::util::{expand_home, tilde};
use crate::vault::{VaultState, save};

/// Where the hosts come from.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSource {
    kind: SourceKind,
    /// A file (PuTTY: a `.reg` export or its sessions folder); none for the source's usual place.
    path: Option<String>,
    /// A file chosen in the app instead (base64), and its name.
    data: Option<String>,
    name: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SourceKind {
    SshConfig,
    Putty,
    Csv,
    Royal,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    /// What was read (`~/.ssh/config`, a file's name, "PuTTY's saved sessions").
    source: String,
    hosts: Vec<PreviewHost>,
    keys: Vec<PreviewKey>,
    /// About the source: what was skipped, what couldn't be read.
    warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewHost {
    /// What to pick it by (an alias, a session name, a row).
    id: String,
    label: String,
    hostname: String,
    port: u16,
    user: String,
    /// `key`, `agent` or `password`.
    auth: &'static str,
    /// A password comes along (saved in the vault).
    password: bool,
    /// The key file it signs in with (`~/…`).
    key: Option<String>,
    /// The jump hosts it goes through, first to last.
    jumps: Vec<String>,
    /// The agent it signs in with, when not the system's (`1Password`, `Pageant`, a socket…).
    agent: Option<String>,
    /// The one agent key it offers (`SHA256:…`).
    agent_key: Option<String>,
    forward_agent: bool,
    /// A command on this computer that connects it (`ProxyCommand`), shown before it's imported:
    /// importing it allows it on this device.
    proxy_command: Option<String>,
    /// The group it goes in (made when the vault has none by that name).
    group: Option<String>,
    tags: Vec<String>,
    /// What the other client does for it that the import leaves out.
    unsupported: Vec<String>,
    /// A host with this address, port and user is in the vault already.
    exists: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewKey {
    /// `~/…`
    path: String,
    fingerprint: Option<String>,
    algorithm: Option<String>,
    /// Needs its passphrase to be imported (none came with the source).
    encrypted: bool,
    /// The vault has this key already: hosts use that one.
    in_vault: bool,
    /// Why it can't be imported.
    error: Option<String>,
    /// How its hosts sign in when it can't be imported: `agent` or `password`.
    fallback: &'static str,
    /// Its OpenSSH certificate, which comes along.
    certificate: Option<mg_ssh::keys::CertInfo>,
    /// The hosts (ids) that sign in with it.
    used_by: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportInput {
    source: ImportSource,
    /// The hosts to import; the jump hosts they need come along.
    ids: Vec<String>,
    /// Where the items go (default: personal).
    vault_id: Option<String>,
    /// Passphrases of encrypted keys, by path as the preview showed it.
    #[serde(default)]
    passphrases: HashMap<String, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    hosts: usize,
    keys: usize,
    groups: usize,
    /// Certificates added to keys (new ones, or keys the vault had).
    certificates: usize,
    /// What didn't go as in the other client (keys left out, jump loops).
    notes: Vec<String>,
}

/// How an imported host signs in.
#[derive(Clone, Debug, PartialEq)]
enum PlannedAuth {
    Key(PathBuf),
    /// An agent (`None`: the system's), and maybe one of its keys (`SHA256:…`).
    Agent(AgentPick),
    /// A saved password, or `None` to ask every time.
    Password(Option<Zeroizing<String>>),
}

/// Which agent, as a host stores it (`HostAuth::Agent`).
#[derive(Clone, Debug, Default, PartialEq)]
struct AgentPick {
    agent: Option<String>,
    path: Option<String>,
    key: Option<String>,
}

impl AgentPick {
    fn named(agent: &str) -> AgentPick {
        AgentPick {
            agent: Some(agent.into()),
            ..AgentPick::default()
        }
    }

    /// What the preview calls it.
    fn name(&self) -> Option<String> {
        match self.agent.as_deref() {
            None => None,
            Some("1password") => Some("1Password".into()),
            Some("bitwarden") => Some("Bitwarden".into()),
            Some("secretive") => Some("Secretive".into()),
            Some("pageant") => Some("Pageant".into()),
            Some(_) => self.path.clone(),
        }
    }
}

/// A host to create.
#[derive(Clone, Debug)]
struct Planned {
    label: String,
    hostname: String,
    port: u16,
    user: String,
    auth: PlannedAuth,
    /// The plan key of its jump host.
    jump: Option<String>,
    forward_agent: bool,
    proxy_command: Option<String>,
    /// The name of its group.
    group: Option<String>,
    tags: Vec<String>,
    /// Its notes in the other client.
    notes: String,
    /// Certificate files it names (`CertificateFile`, PuTTY's detached certificate): the one
    /// for its key comes along with it.
    certificates: Vec<PathBuf>,
    unsupported: Vec<String>,
}

impl Planned {
    fn new(label: String, hostname: String, port: u16, user: String, auth: PlannedAuth) -> Self {
        Planned {
            label,
            hostname,
            port,
            user,
            auth,
            jump: None,
            forward_agent: false,
            proxy_command: None,
            group: None,
            tags: Vec::new(),
            notes: String::new(),
            certificates: Vec::new(),
            unsupported: Vec::new(),
        }
    }
}

struct Plan {
    /// By plan key: an id the preview lists, or a jump host only (`user@host:port`).
    hosts: BTreeMap<String, Planned>,
    /// Every host, each after its jump host: the order to create them.
    order: Vec<String>,
    notes: Vec<String>,
}

impl Plan {
    /// `hosts` ordered so that each comes after its jump host; a jump that goes round in a loop
    /// is dropped, with a note.
    fn ordered(hosts: Vec<(String, Planned)>) -> Plan {
        let mut plan = Plan {
            hosts: hosts.into_iter().collect(),
            order: Vec::new(),
            notes: Vec::new(),
        };
        let keys: Vec<String> = plan.hosts.keys().cloned().collect();
        let mut done = HashSet::new();
        for key in keys {
            plan.place(&key, &mut done, &mut Vec::new());
        }
        plan
    }

    fn place(&mut self, key: &str, done: &mut HashSet<String>, stack: &mut Vec<String>) {
        if done.contains(key) {
            return;
        }
        stack.push(key.to_owned());
        if let Some(jump) = self.hosts[key].jump.clone() {
            if !self.hosts.contains_key(&jump) {
                self.hosts.get_mut(key).unwrap().jump = None;
            } else if stack.contains(&jump) {
                self.notes.push(format!(
                    "{}: its jump hosts go round in a loop; imported without one",
                    self.hosts[key].label
                ));
                self.hosts.get_mut(key).unwrap().jump = None;
            } else {
                self.place(&jump, done, stack);
            }
        }
        stack.pop();
        done.insert(key.to_owned());
        self.order.push(key.to_owned());
    }

    /// The plan keys to create for `ids`: those, and the jump hosts they go through, in order.
    fn needed(&self, ids: &[String]) -> Vec<String> {
        let mut set = HashSet::new();
        for id in ids {
            let mut hop = Some(id.clone());
            while let Some(key) = hop {
                if !self.hosts.contains_key(&key) || !set.insert(key.clone()) {
                    break;
                }
                hop = self.hosts[&key].jump.clone();
            }
        }
        self.order
            .iter()
            .filter(|k| set.contains(*k))
            .cloned()
            .collect()
    }
}

/// A source, read.
struct Loaded {
    /// What was read, as the preview names it.
    source: String,
    /// Where the notes of an imported host say it came from (`~/.ssh/config`, `PuTTY`).
    origin: &'static str,
    plan: Plan,
    /// The hosts the preview lists (plan keys), in order.
    listed: Vec<String>,
    warnings: Vec<String>,
    /// Key passphrases that came with the source (a CSV's `KeyPassphrase`).
    passphrases: HashMap<PathBuf, Zeroizing<String>>,
}

async fn load(source: &ImportSource) -> Result<Loaded, String> {
    match source.kind {
        SourceKind::SshConfig => ssh_config::load(source.path.as_deref()),
        SourceKind::Putty => putty::load(source).await,
        SourceKind::Csv => {
            let (name, bytes) = read(source)?;
            csv::load(name, &text(&bytes))
        }
        SourceKind::Royal => {
            let (name, bytes) = read(source)?;
            royal::load(name, &bytes)
        }
    }
}

/// The file a source names: a chosen file's content, or a path.
fn read(source: &ImportSource) -> Result<(String, Vec<u8>), String> {
    if let Some(data) = &source.data {
        let bytes = STANDARD
            .decode(data.trim())
            .map_err(|_| "the chosen file couldn't be read")?;
        let name = source
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "the chosen file".into());
        return Ok((name, bytes));
    }
    let path = source
        .path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or("choose a file")?;
    let path = expand_home(path);
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", tilde(&path)))?;
    Ok((tilde(&path), bytes))
}

/// A file's text: UTF-8 (with or without a byte order mark) or UTF-16 with one (what Windows'
/// `reg export` and some spreadsheets write).
fn text(bytes: &[u8]) -> String {
    let utf16 = |be: bool| {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if be {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, ..] => utf16(false),
        [0xFE, 0xFF, ..] => utf16(true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
}

fn agent_available() -> bool {
    cfg!(windows) || std::env::var_os("SSH_AUTH_SOCK").is_some()
}

/// How a host signs in when its key can't be imported.
fn fallback() -> PlannedAuth {
    if agent_available() {
        PlannedAuth::Agent(AgentPick::default())
    } else {
        PlannedAuth::Password(None)
    }
}

/// `host`, `user@host`, `host:port`, `[v6]:port`: the parts given.
fn split_address(address: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match address.rsplit_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_owned()), r),
        _ => (None, address),
    };
    if let Some((host, after)) = rest.strip_prefix('[').and_then(|v6| v6.split_once(']')) {
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        return (user, host.to_owned(), port);
    }
    match rest.rsplit_once(':') {
        // One colon: a port. More: an IPv6 address.
        Some((host, port)) if !host.contains(':') => match port.parse() {
            Ok(p) => (user, host.to_owned(), Some(p)),
            Err(_) => (user, rest.to_owned(), None),
        },
        _ => (user, rest.to_owned(), None),
    }
}

/// What a key file holds.
struct KeyFile {
    pem: Option<Zeroizing<String>>,
    /// Its public key (`authorized_keys` line), when known.
    public_key: Option<String>,
    fingerprint: Option<String>,
    algorithm: Option<String>,
    encrypted: bool,
    error: Option<String>,
}

/// A private key file (OpenSSH, PEM or PuTTY's `.ppk`), or its public half for what can't be
/// read without a passphrase: a `.ppk` holds it, an OpenSSH key has it beside it (`.pub`).
fn read_key(path: &Path, passphrase: Option<&str>) -> KeyFile {
    let failed = |error: String| KeyFile {
        pem: None,
        public_key: None,
        fingerprint: None,
        algorithm: None,
        encrypted: false,
        error: Some(error),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => Zeroizing::new(t),
        Err(e) => return failed(e.to_string()),
    };
    match mg_ssh::keys::inspect(&text, passphrase) {
        Ok(info) => KeyFile {
            pem: Some(text),
            public_key: Some(info.public_key),
            fingerprint: Some(info.fingerprint),
            algorithm: Some(info.algorithm),
            encrypted: info.encrypted,
            error: None,
        },
        Err(mg_ssh::Error::KeyNeedsPassphrase) => {
            let public = if mg_ssh::keys::is_ppk(&text) {
                mg_ssh::keys::ppk_public_key(&text)
            } else {
                std::fs::read_to_string(path.with_extension(match path.extension() {
                    Some(e) => format!("{}.pub", e.to_string_lossy()),
                    None => "pub".into(),
                }))
                .ok()
            };
            KeyFile {
                pem: Some(text),
                fingerprint: public.as_deref().and_then(mg_ssh::keys::public_fingerprint),
                public_key: public.clone(),
                algorithm: public
                    .as_deref()
                    .and_then(|p| p.split_whitespace().next().map(str::to_owned)),
                encrypted: true,
                error: None,
            }
        }
        Err(e) => failed(e.to_string()),
    }
}

/// The certificate for the key in `file` (public half `public_key`): one of `named` (the hosts'
/// certificate files), or the one beside it (`<file>-cert.pub`, where ssh looks), whichever
/// certifies this key.
fn certificate_for(
    file: &Path,
    named: &[PathBuf],
    public_key: &str,
) -> Option<mg_ssh::keys::CertInfo> {
    let beside = PathBuf::from(format!("{}-cert.pub", file.display()));
    named
        .iter()
        .chain(std::iter::once(&beside))
        .filter_map(|c| std::fs::read_to_string(c).ok())
        .find_map(|t| mg_ssh::keys::certificate(&t, public_key).ok())
}

/// The certificate files each key file's hosts name.
fn named_certificates(plan: &Plan, keys: &[String]) -> HashMap<PathBuf, Vec<PathBuf>> {
    let mut named: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    for k in keys {
        if let PlannedAuth::Key(file) = &plan.hosts[k].auth {
            named
                .entry(file.clone())
                .or_default()
                .extend(plan.hosts[k].certificates.iter().cloned());
        }
    }
    named
}

/// Hosts in the vault, by address, port and user (lowercase host name).
fn existing_hosts(
    v: &LocalVault,
    vault_id: Option<&str>,
) -> Result<HashMap<(String, u16, String), String>, String> {
    Ok(v.items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|i| vault_id.is_none_or(|id| i.vault_id == id))
        .filter_map(|i| match i.data {
            ItemData::Host(h) => Some(((h.hostname.to_lowercase(), h.port, h.user), i.id)),
            _ => None,
        })
        .collect())
}

/// Keys in the vault (or one of its vaults), by fingerprint.
fn existing_keys(
    v: &LocalVault,
    vault_id: Option<&str>,
) -> Result<HashMap<String, String>, String> {
    Ok(v.items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|i| vault_id.is_none_or(|id| i.vault_id == id))
        .filter_map(|i| match i.data {
            ItemData::SshKey(k) => Some((k.fingerprint, i.id)),
            _ => None,
        })
        .collect())
}

/// Groups in one vault, by lowercase name.
fn existing_groups(v: &LocalVault, vault_id: &str) -> Result<HashMap<String, String>, String> {
    Ok(v.items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|i| i.vault_id == vault_id)
        .filter_map(|i| match i.data {
            ItemData::HostGroup(g) => Some((g.name.to_lowercase(), i.id)),
            _ => None,
        })
        .collect())
}

fn auth_kind(auth: &PlannedAuth) -> &'static str {
    match auth {
        PlannedAuth::Key(_) => "key",
        PlannedAuth::Agent(_) => "agent",
        PlannedAuth::Password(_) => "password",
    }
}

fn preview(loaded: Loaded, v: &LocalVault) -> Result<ImportPreview, String> {
    let hosts_in_vault = existing_hosts(v, None)?;
    let keys_in_vault = existing_keys(v, None)?;
    let plan = &loaded.plan;
    let mut keys: BTreeMap<PathBuf, (KeyFile, Vec<String>)> = BTreeMap::new();
    let mut hosts = Vec::new();
    for id in &loaded.listed {
        let Some(h) = plan.hosts.get(id) else {
            continue;
        };
        let mut jumps = Vec::new();
        let mut hop = h.jump.clone();
        while let Some(key) = hop {
            let Some(j) = plan.hosts.get(&key) else { break };
            if jumps.contains(&j.label) {
                break;
            }
            jumps.insert(0, j.label.clone());
            hop = j.jump.clone();
        }
        let key = match &h.auth {
            PlannedAuth::Key(file) => {
                let passphrase = loaded.passphrases.get(file).map(|p| p.as_str());
                keys.entry(file.clone())
                    .or_insert_with(|| (read_key(file, passphrase), Vec::new()))
                    .1
                    .push(id.clone());
                Some(tilde(file))
            }
            _ => None,
        };
        let agent = match &h.auth {
            PlannedAuth::Agent(a) => Some(a),
            _ => None,
        };
        hosts.push(PreviewHost {
            id: id.clone(),
            label: h.label.clone(),
            hostname: h.hostname.clone(),
            port: h.port,
            user: h.user.clone(),
            auth: auth_kind(&h.auth),
            password: matches!(h.auth, PlannedAuth::Password(Some(_))),
            key,
            jumps,
            agent: agent.and_then(AgentPick::name),
            agent_key: agent.and_then(|a| a.key.clone()),
            forward_agent: h.forward_agent,
            proxy_command: h.proxy_command.clone(),
            group: h.group.clone(),
            tags: h.tags.clone(),
            unsupported: h.unsupported.clone(),
            exists: hosts_in_vault.contains_key(&(
                h.hostname.to_lowercase(),
                h.port,
                h.user.clone(),
            )),
        });
    }
    let named = named_certificates(plan, &loaded.listed);
    let keys = keys
        .into_iter()
        .map(|(path, (k, used_by))| PreviewKey {
            certificate: k.public_key.as_deref().and_then(|p| {
                certificate_for(&path, named.get(&path).map_or(&[][..], Vec::as_slice), p)
            }),
            path: tilde(&path),
            in_vault: k
                .fingerprint
                .as_ref()
                .is_some_and(|f| keys_in_vault.contains_key(f)),
            fingerprint: k.fingerprint,
            algorithm: k.algorithm,
            // A passphrase came with the source (it was read with it): nothing to ask.
            encrypted: k.encrypted && !loaded.passphrases.contains_key(&path),
            error: k.error,
            fallback: auth_kind(&fallback()),
            used_by,
        })
        .collect();
    let mut warnings = loaded.warnings;
    warnings.extend(plan.notes.iter().cloned());
    Ok(ImportPreview {
        source: loaded.source,
        hosts,
        keys,
        warnings,
    })
}

/// Imports `ids` (and the jump hosts they need) into the vault `target`.
fn apply(
    v: &mut LocalVault,
    target: &str,
    loaded: &Loaded,
    ids: &[String],
    passphrases: &HashMap<String, String>,
) -> Result<ImportResult, String> {
    let plan = &loaded.plan;
    let needed = plan.needed(ids);
    let mut notes = plan.notes.clone();
    let mut hosts_in_vault = existing_hosts(v, Some(target))?;
    let mut keys_in_vault = existing_keys(v, Some(target))?;
    let mut groups_in_vault = existing_groups(v, target)?;

    // Keys first: a key the vault has (same fingerprint) is used as it is.
    let mut key_ids: HashMap<PathBuf, String> = HashMap::new();
    let mut new_keys = 0;
    let files: Vec<PathBuf> = needed
        .iter()
        .filter_map(|k| match &plan.hosts[k].auth {
            PlannedAuth::Key(f) => Some(f.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let named = named_certificates(plan, &needed);
    let mut certificates = 0;
    let instead = match fallback() {
        PlannedAuth::Agent(_) => "its hosts use the SSH agent",
        _ => "its hosts ask for a password",
    };
    for file in files {
        let passphrase = passphrases
            .get(&tilde(&file))
            .filter(|p| !p.is_empty())
            .map(|p| Zeroizing::new(p.clone()))
            .or_else(|| loaded.passphrases.get(&file).cloned());
        let k = read_key(&file, passphrase.as_deref().map(String::as_str));
        let cert = k.public_key.as_deref().and_then(|p| {
            certificate_for(&file, named.get(&file).map_or(&[][..], Vec::as_slice), p)
        });
        if let Some(id) = k.fingerprint.as_ref().and_then(|f| keys_in_vault.get(f)) {
            // The vault's copy gets the certificate, unless it has one that lasts as long.
            if let (Some(cert), Ok(item)) = (&cert, v.item(id))
                && let ItemData::SshKey(mut existing) = item.data
            {
                let stored = existing
                    .certificate
                    .as_deref()
                    .and_then(|c| mg_ssh::keys::certificate(c, &existing.public_key).ok());
                if stored.is_none_or(|s| s.valid_before < cert.valid_before) {
                    existing.certificate = Some(cert.certificate.clone());
                    save(v, Some(id), None, ItemData::SshKey(existing))
                        .map_err(|e| e.to_string())?;
                    certificates += 1;
                }
            }
            key_ids.insert(file, id.clone());
            continue;
        }
        let (Some(pem), None) = (&k.pem, &k.error) else {
            notes.push(format!(
                "{}: {} ({instead})",
                tilde(&file),
                k.error.as_deref().unwrap_or("not a private key")
            ));
            continue;
        };
        if k.encrypted && passphrase.is_none() {
            notes.push(format!(
                "{}: encrypted, and no passphrase given ({instead})",
                tilde(&file)
            ));
            continue;
        }
        // A PuTTY key is kept as an OpenSSH one.
        let (pem, info) =
            match mg_ssh::keys::for_vault(pem, passphrase.as_deref().map(String::as_str)) {
                Ok(k) => k,
                Err(e) => {
                    notes.push(format!("{}: {e} ({instead})", tilde(&file)));
                    continue;
                }
            };
        let key = SshKey {
            label: file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Imported key".into()),
            private_key: pem.to_string(),
            passphrase: if info.encrypted {
                passphrase.map(|p| p.to_string())
            } else {
                None
            },
            certificate: cert
                .as_ref()
                .filter(|c| mg_ssh::keys::certificate(&c.certificate, &info.public_key).is_ok())
                .map(|c| c.certificate.clone()),
            renew: None,
            public_key: info.public_key,
            algorithm: info.algorithm,
            fingerprint: info.fingerprint.clone(),
        };
        if key.certificate.is_some() {
            certificates += 1;
        }
        let item = save(v, None, Some(target), ItemData::SshKey(key)).map_err(|e| e.to_string())?;
        keys_in_vault.insert(info.fingerprint, item.id.clone());
        key_ids.insert(file, item.id);
        new_keys += 1;
    }

    // Then hosts, each after its jump host; a host the vault has (same address, port and user)
    // is used as it is, as a jump host too. Groups are found by name, or made.
    let mut host_ids: HashMap<String, String> = HashMap::new();
    let mut new_hosts = 0;
    let mut new_groups = 0;
    for key in &needed {
        let h = &plan.hosts[key];
        let address = (h.hostname.to_lowercase(), h.port, h.user.clone());
        if let Some(id) = hosts_in_vault.get(&address) {
            host_ids.insert(key.clone(), id.clone());
            continue;
        }
        let auth = match &h.auth {
            PlannedAuth::Key(file) => match key_ids.get(file) {
                Some(id) => HostAuth::Key {
                    key_ref: id.clone(),
                },
                None => match fallback() {
                    PlannedAuth::Agent(_) => HostAuth::system_agent(),
                    _ => HostAuth::Password { password: None },
                },
            },
            PlannedAuth::Agent(a) => HostAuth::Agent {
                agent: a.agent.clone(),
                path: a.path.clone(),
                key: a.key.clone(),
            },
            PlannedAuth::Password(p) => HostAuth::Password {
                password: p.as_ref().map(|p| p.to_string()),
            },
        };
        let group_ref = match h.group.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
            None => None,
            Some(name) => Some(match groups_in_vault.get(&name.to_lowercase()) {
                Some(id) => id.clone(),
                None => {
                    let group = HostGroup {
                        name: name.to_owned(),
                        ..HostGroup::default()
                    };
                    let item = save(v, None, Some(target), ItemData::HostGroup(group))
                        .map_err(|e| e.to_string())?;
                    groups_in_vault.insert(name.to_lowercase(), item.id.clone());
                    new_groups += 1;
                    item.id
                }
            }),
        };
        let mut host_notes = h.notes.trim().to_owned();
        if !h.unsupported.is_empty() {
            if !host_notes.is_empty() {
                host_notes.push_str("\n\n");
            }
            host_notes.push_str(&format!(
                "From {}, not imported: {}",
                loaded.origin,
                h.unsupported.join("; ")
            ));
        }
        let host = Host {
            label: h.label.clone(),
            hostname: h.hostname.clone(),
            port: h.port,
            user: h.user.clone(),
            auth,
            jump_ref: h.jump.as_ref().and_then(|j| host_ids.get(j).cloned()),
            vpn_ref: None,
            theme_ref: None,
            record_sessions: false,
            tags: h.tags.clone(),
            notes: host_notes,
            group_ref,
            identity_ref: None,
            keep_session: false,
            forward_agent: h.forward_agent,
            login_command: None,
            jump_command: None,
            proxy_command: h.proxy_command.clone(),
            source: None,
        };
        let item = save(v, None, Some(target), ItemData::Host(host)).map_err(|e| e.to_string())?;
        // From this device's own configuration, shown before importing: allowed here.
        if let Some(command) = &h.proxy_command {
            crate::proxy::allow(v, command)?;
        }
        hosts_in_vault.insert(address, item.id.clone());
        host_ids.insert(key.clone(), item.id);
        new_hosts += 1;
    }
    Ok(ImportResult {
        hosts: new_hosts,
        keys: new_keys,
        groups: new_groups,
        certificates,
        notes,
    })
}

/// What importing from `source` would bring.
#[tauri::command]
pub async fn import_preview(
    vault: State<'_, VaultState>,
    source: ImportSource,
) -> Result<ImportPreview, String> {
    let loaded = load(&source).await?;
    preview(loaded, &*vault.guard()?)
}

/// Imports the hosts `input.ids` (and the jump hosts they need) into `input.vault_id`.
#[tauri::command]
pub async fn import_hosts(
    vault: State<'_, VaultState>,
    input: ImportInput,
) -> Result<ImportResult, String> {
    let loaded = load(&input.source).await?;
    let result = {
        let mut v = vault.guard()?;
        let target = match input.vault_id.as_deref().filter(|v| !v.is_empty()) {
            Some(id) => id.to_owned(),
            None => v
                .vaults()
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|x| x.personal)
                .map(|x| x.id)
                .ok_or("no personal vault")?,
        };
        apply(&mut v, &target, &loaded, &input.ids, &input.passphrases)?
    };
    vault.changed();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(label: &str, jump: Option<&str>) -> (String, Planned) {
        let mut h = Planned::new(
            label.into(),
            format!("{label}.example.com"),
            22,
            "me".into(),
            PlannedAuth::Password(None),
        );
        h.jump = jump.map(str::to_owned);
        (label.into(), h)
    }

    #[test]
    fn jump_hosts_go_first_and_loops_are_broken() {
        let plan = Plan::ordered(vec![
            host("app", Some("bastion")),
            host("bastion", None),
            host("a", Some("b")),
            host("b", Some("a")),
            host("lost", Some("nowhere")),
        ]);
        let pos = |k: &str| plan.order.iter().position(|o| o == k).unwrap();
        assert!(pos("bastion") < pos("app"));
        assert_eq!(plan.order.len(), 5);
        assert_eq!(plan.notes.len(), 1, "{:?}", plan.notes);
        assert_eq!(plan.hosts["lost"].jump, None);
        assert_eq!(plan.needed(&["app".into()]), ["bastion", "app"]);
        assert_eq!(plan.needed(&["bastion".into()]), ["bastion"]);
    }

    #[test]
    fn addresses_split() {
        assert_eq!(split_address("web"), (None, "web".into(), None));
        assert_eq!(
            split_address("ops@web:2222"),
            (Some("ops".into()), "web".into(), Some(2222))
        );
        assert_eq!(
            split_address("2001:db8::1"),
            (None, "2001:db8::1".into(), None)
        );
        assert_eq!(
            split_address("root@[2001:db8::1]:22"),
            (Some("root".into()), "2001:db8::1".into(), Some(22))
        );
    }

    const USER: &str = include_str!("../../../../../crates/mg-ssh/tests/data/user.pub");
    const USER_CERT: &str = include_str!("../../../../../crates/mg-ssh/tests/data/user-cert.pub");
    const HOST_CERT: &str = include_str!("../../../../../crates/mg-ssh/tests/data/host-cert.pub");

    #[test]
    fn certificates_come_from_beside_the_key_or_the_files_named() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        std::fs::write(dir.path().join("id_ed25519-cert.pub"), USER_CERT).unwrap();
        assert_eq!(
            certificate_for(&key, &[], USER).unwrap().key_id,
            "alice@example"
        );
        assert!(certificate_for(&dir.path().join("work"), &[], USER).is_none());
        // Named files: one that certifies another key (a host) is passed over.
        let host = dir.path().join("host-cert.pub");
        let named = dir.path().join("certs-alice.pub");
        std::fs::write(&host, HOST_CERT).unwrap();
        std::fs::write(&named, USER_CERT).unwrap();
        let found = certificate_for(&dir.path().join("work"), &[host, named], USER).unwrap();
        assert_eq!(found.principals, ["deploy", "ops"]);
    }

    #[test]
    fn text_in_any_encoding() {
        assert_eq!(text(b"\xEF\xBB\xBFa,b"), "a,b");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("Windows Registry".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(text(&utf16), "Windows Registry");
    }
}
