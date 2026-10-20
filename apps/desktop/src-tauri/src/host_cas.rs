//! Host CAs: vault items trusting host keys a CA signed (OpenSSH's `@cert-authority`) for the
//! hosts their patterns match, instead of pinning each host's key. In a team's vault they cover
//! every member. The connection code (mg-ssh) asks for and checks host certificates where one
//! applies; [`trust`] hands it the vault's before each connection.

use mg_ssh::{HostAuthority, KnownHosts};
use mg_store::{HostCa, ItemData, LocalVault};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::vault::{VaultState, save};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCaView {
    id: String,
    vault_id: String,
    label: String,
    public_key: String,
    algorithm: String,
    /// `SHA256:…`
    fingerprint: String,
    hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCaInput {
    #[serde(default)]
    id: Option<String>,
    /// A new one goes in this vault (default: the personal one).
    #[serde(default)]
    vault_id: Option<String>,
    label: String,
    /// The CA's public key, or a whole `@cert-authority` line from a known_hosts file.
    public_key: String,
    /// Host patterns; from the line when it has them and these are empty.
    #[serde(default)]
    hosts: Vec<String>,
}

fn view(id: String, vault_id: String, c: HostCa) -> HostCaView {
    let (algorithm, fingerprint) = HostAuthority::new(&c.public_key, Vec::new(), "")
        .map(|a| a.describe())
        .unwrap_or_default();
    HostCaView {
        id,
        vault_id,
        label: c.label,
        public_key: c.public_key,
        algorithm,
        fingerprint,
        hosts: c.hosts,
    }
}

/// Every vault's host CAs, as the connection code trusts them.
fn authorities(v: &LocalVault) -> Vec<HostAuthority> {
    v.items()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::HostCa(c) => HostAuthority::new(&c.public_key, c.hosts, c.label).ok(),
            _ => None,
        })
        .collect()
}

/// Hands the vault's host CAs to the connection code, before a connection.
pub(crate) fn trust(vault: &VaultState, known_hosts: &KnownHosts) {
    if let Ok(v) = vault.guard() {
        known_hosts.set_authorities(authorities(&v));
    }
}

/// The key and patterns from what was pasted: a public key, or an `@cert-authority` line.
fn parse(input: &str, hosts: Vec<String>) -> Result<(String, Vec<String>), String> {
    let text = input.trim();
    let (key, from_line) = match text.strip_prefix("@cert-authority") {
        Some(rest) => {
            let mut words = rest.split_whitespace();
            let patterns: Vec<String> = words
                .next()
                .map(|p| p.split(',').map(str::to_owned).collect())
                .unwrap_or_default();
            (words.collect::<Vec<_>>().join(" "), patterns)
        }
        None => (text.to_owned(), Vec::new()),
    };
    // Refused unless it's an SSH public key.
    HostAuthority::new(&key, Vec::new(), "")?;
    // The key as `type base64`, without a comment.
    let key: String = key.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let hosts: Vec<String> = hosts
        .into_iter()
        .flat_map(|h| {
            h.split([',', ' ', '\n'])
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    Ok((key, if hosts.is_empty() { from_line } else { hosts }))
}

#[tauri::command]
pub fn host_cas_list(vault: State<'_, VaultState>) -> Result<Vec<HostCaView>, String> {
    let mut out: Vec<HostCaView> = vault
        .guard()?
        .items()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|i| match i.data {
            ItemData::HostCa(c) => Some(view(i.id, i.vault_id, c)),
            _ => None,
        })
        .collect();
    out.sort_by_key(|c| c.label.to_lowercase());
    Ok(out)
}

#[tauri::command]
pub fn host_ca_save(
    vault: State<'_, VaultState>,
    input: HostCaInput,
) -> Result<HostCaView, String> {
    let (public_key, hosts) = parse(&input.public_key, input.hosts)?;
    let ca = HostCa {
        label: input.label.trim().to_owned(),
        public_key,
        hosts,
    };
    let item = {
        let mut v = vault.guard()?;
        save(
            &mut v,
            input.id.as_deref(),
            input.vault_id.as_deref(),
            ItemData::HostCa(ca),
        )
        .map_err(|e| e.to_string())?
    };
    vault.changed();
    match item.data {
        ItemData::HostCa(c) => Ok(view(item.id, item.vault_id, c)),
        _ => Err("not a host CA".into()),
    }
}

/// The CA that vouches for `host:port`, by name (a vault item's, or a known_hosts line's place),
/// where one does.
#[tauri::command]
pub fn host_certified_by(
    vault: State<'_, VaultState>,
    ssh: State<'_, crate::ssh::SshState>,
    host: String,
    port: u16,
) -> Option<String> {
    trust(&vault, &ssh.known_hosts);
    ssh.known_hosts
        .authorities_for(host.trim(), port)
        .into_iter()
        .next()
        .map(|a| a.from)
}

#[tauri::command]
pub fn host_ca_delete(vault: State<'_, VaultState>, id: String) -> Result<(), String> {
    vault.guard()?.delete(&id).map_err(|e| e.to_string())?;
    vault.changed();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRbMaf7RI+oSkPOCPrFjPoMWJEIu96Drte4Q3r9OQYR";

    #[test]
    fn a_key_or_a_known_hosts_line() {
        assert_eq!(
            parse(
                &format!("{CA} ca@example"),
                vec!["*.example.com, 10.0.*".into()]
            )
            .unwrap(),
            (CA.to_owned(), vec!["*.example.com".into(), "10.0.*".into()])
        );
        assert_eq!(
            parse(
                &format!("@cert-authority *.example.com,!bastion.example.com {CA} ca"),
                vec![]
            )
            .unwrap(),
            (
                CA.to_owned(),
                vec!["*.example.com".into(), "!bastion.example.com".into()]
            )
        );
        assert!(parse("not a key", vec!["*".into()]).is_err());
    }
}
