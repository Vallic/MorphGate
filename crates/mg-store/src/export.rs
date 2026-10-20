//! A plaintext copy of the vault for the person it belongs to: what this device holds, readable,
//! as JSON (`morphgate-vault-export/1`). The sync server can't produce this; only a device with
//! the keys can. Passwords, private keys and VPN credentials are in it only when asked for.

use rusqlite::OptionalExtension;
use serde_json::{Map, Value, json};

use crate::{Item, ItemData, LocalVault, Result};

pub const FORMAT: &str = "morphgate-vault-export/1";

/// What goes into an export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExportOptions {
    /// Passwords, private keys and VPN credentials, in the clear.
    pub secrets: bool,
    /// The team vaults this device can open, besides the personal one.
    pub team_vaults: bool,
}

/// Stands in for a secret left out of an export.
const LEFT_OUT: &str = "(not exported)";

/// Inline blocks of an OpenVPN profile that hold keys or passwords.
const OPENVPN_SECRET_BLOCKS: &[&str] = &[
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "secret",
    "pkcs12",
    "askpass",
    "auth-user-pass",
];

impl LocalVault {
    /// The vault's items, readable, grouped by vault. Member key directories and kinds from
    /// newer apps are left out; session logs and attachments are listed without their contents
    /// (save those one by one).
    pub fn export_plaintext(&self, opts: ExportOptions) -> Result<Value> {
        let items = self.items()?;
        let mut vaults = Vec::new();
        for v in self.vaults()? {
            if v.directory || !(v.personal || opts.team_vaults) {
                continue;
            }
            let organization = match &v.org_id {
                Some(org) => self
                    .conn
                    .query_row("SELECT name FROM orgs WHERE id = ?1", [org], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()?,
                None => None,
            };
            let list: Vec<Value> = items
                .iter()
                .filter(|i| i.vault_id == v.id)
                .filter_map(|i| item(i, opts.secrets))
                .collect();
            vaults.push(without_nulls(json!({
                "id": v.id,
                "name": if v.personal { Some("Personal".to_owned()) } else { v.name },
                "organization": organization,
                "personal": v.personal,
                "items": list,
            })));
        }
        Ok(json!({
            "format": FORMAT,
            "exported_at": rfc3339(crate::vault::now() / 1000),
            "about": "Your MorphGate vault, decrypted on this device. Anyone with this file can read it: keep it safe, and delete it when you're done.",
            "secrets_included": opts.secrets,
            "vaults": vaults,
        }))
    }
}

fn item(i: &Item, secrets: bool) -> Option<Value> {
    if matches!(i.data, ItemData::Unknown | ItemData::MemberKey(_)) {
        return None;
    }
    let Value::Object(mut fields) = serde_json::to_value(&i.data).ok()? else {
        return None;
    };
    // Recordings and files are blobs: their contents are saved one by one, not exported here.
    fields.remove("chunks");
    fields.remove("blob");
    if !secrets {
        redact(&mut fields);
    }
    let mut out = Map::new();
    out.insert("id".into(), i.id.clone().into());
    out.extend(fields);
    out.insert("updated_at".into(), rfc3339(i.updated_at / 1000).into());
    Some(Value::Object(out))
}

/// Takes the secrets out of a serialized item (field names are the item schema's).
fn redact(fields: &mut Map<String, Value>) {
    let left_out = |obj: &mut Map<String, Value>, key: &str| {
        if obj.get(key).is_some_and(|v| !v.is_null()) {
            obj.insert(key.into(), LEFT_OUT.into());
        }
    };
    if let Some(Value::Object(auth)) = fields.get_mut("auth") {
        left_out(auth, "password");
    }
    left_out(fields, "private_key");
    left_out(fields, "passphrase");
    if let Some(Value::Object(vpn)) = fields.get_mut("vpn") {
        left_out(vpn, "password");
        let kind = vpn
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if let Some(Value::String(config)) = vpn.get_mut("config") {
            *config = match kind.as_str() {
                "wireguard" => wireguard_without_keys(config),
                _ => openvpn_without_keys(config),
            };
        }
    }
}

/// `PrivateKey` and `PresharedKey` lines with their values left out.
fn wireguard_without_keys(config: &str) -> String {
    config
        .lines()
        .map(|line| {
            let key = line.split('=').next().unwrap_or_default().trim();
            if key.eq_ignore_ascii_case("PrivateKey") || key.eq_ignore_ascii_case("PresharedKey") {
                format!("{key} = {LEFT_OUT}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Inline key blocks (`<key>`, `<tls-crypt>`, …) emptied out.
fn openvpn_without_keys(config: &str) -> String {
    let mut out = Vec::new();
    let mut inside: Option<&str> = None;
    for line in config.lines() {
        let tag = line.trim();
        match inside {
            Some(block) if tag == format!("</{block}>") => {
                out.push(LEFT_OUT.to_owned());
                out.push(line.to_owned());
                inside = None;
            }
            Some(_) => {}
            None => {
                out.push(line.to_owned());
                inside = OPENVPN_SECRET_BLOCKS
                    .iter()
                    .find(|b| tag == format!("<{b}>"))
                    .copied();
            }
        }
    }
    out.join("\n")
}

/// An object without its nulls.
fn without_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).collect()),
        other => other,
    }
}

/// RFC 3339 UTC, second precision.
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Host, HostAuth, SshKey, VpnKind, VpnProfile};
    use mg_vault::KdfParams;

    fn vault() -> LocalVault {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create("correct horse battery").unwrap();
        v.upsert(
            None,
            ItemData::Host(Host {
                label: "db1".into(),
                hostname: "db1.internal".into(),
                port: 22,
                user: "deploy".into(),
                auth: HostAuth::Password {
                    password: Some("hunter2".into()),
                },
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
            }),
        )
        .unwrap();
        v.upsert(
            None,
            ItemData::SshKey(SshKey {
                label: "deploy".into(),
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
                passphrase: None,
                public_key: "ssh-ed25519 AAAA deploy".into(),
                algorithm: "ed25519".into(),
                fingerprint: "SHA256:x".into(),
                certificate: None,
                renew: None,
            }),
        )
        .unwrap();
        v.upsert(
            None,
            ItemData::Vpn(VpnProfile {
                label: "office".into(),
                vpn: VpnKind::Wireguard {
                    config: "[Interface]\nPrivateKey = c2VjcmV0\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = cHVi".into(),
                },
            }),
        )
        .unwrap();
        v
    }

    #[test]
    fn secrets_only_when_asked() {
        let v = vault();
        let plain = v.export_plaintext(ExportOptions::default()).unwrap();
        let text = plain.to_string();
        assert_eq!(plain["format"], FORMAT);
        assert_eq!(plain["vaults"][0]["name"], "Personal");
        assert_eq!(plain["vaults"][0]["items"].as_array().unwrap().len(), 3);
        for secret in ["hunter2", "BEGIN OPENSSH", "c2VjcmV0"] {
            assert!(!text.contains(secret), "{secret} exported");
        }
        assert!(text.contains("ssh-ed25519 AAAA deploy"), "public keys stay");
        assert!(
            text.contains("PublicKey = cHVi"),
            "the rest of a config stays"
        );

        let full = v
            .export_plaintext(ExportOptions {
                secrets: true,
                team_vaults: false,
            })
            .unwrap()
            .to_string();
        for secret in ["hunter2", "BEGIN OPENSSH", "c2VjcmV0"] {
            assert!(full.contains(secret), "{secret} missing");
        }
    }

    #[test]
    fn openvpn_key_blocks_are_emptied() {
        let config = "client\n<ca>\nCA\n</ca>\n<key>\nSECRET\n</key>\n<tls-crypt>\nTC\n</tls-crypt>\n\
             <askpass>\nKEYPASS\n</askpass>\n<auth-user-pass>\nalice\nhunter2\n</auth-user-pass>\nverb 3";
        let out = openvpn_without_keys(config);
        assert!(out.contains("<ca>\nCA\n</ca>"));
        for secret in ["SECRET", "TC\n", "KEYPASS", "hunter2"] {
            assert!(!out.contains(secret), "{secret} exported");
        }
        assert!(out.ends_with("verb 3"));
    }

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_792_195_200), "2026-10-17T00:00:00Z");
    }
}
