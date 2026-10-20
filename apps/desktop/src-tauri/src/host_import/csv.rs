//! CSV files: Termius' import template (`Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,
//! Password`), what tools that export Termius' data write, and other managers' exports. Columns
//! are found by their header, in any order; the only one needed names the host. Commas,
//! semicolons (spreadsheets in many languages) or tabs separate the values.

use std::collections::HashMap;

use super::{Loaded, Plan, Planned, PlannedAuth, local_user, split_address};
use crate::util::expand_home;

/// Header names (lowercase, letters and digits only) for each value.
const HOST: &[&str] = &[
    "hostnameip",
    "hostname",
    "host",
    "address",
    "ipaddress",
    "ip",
    "uri",
    "server",
    "computername",
];
const LABEL: &[&str] = &["label", "name", "alias", "title", "displayname"];
const GROUP: &[&str] = &["groups", "group", "folder", "path"];
const TAGS: &[&str] = &["tags", "tag"];
const PORT: &[&str] = &["port"];
const USER: &[&str] = &["username", "user", "login", "credentialusername"];
const PASSWORD: &[&str] = &["password", "credentialpassword"];
const PROTOCOL: &[&str] = &["protocol", "connectiontype", "type"];
const KEY: &[&str] = &[
    "identityfile",
    "sshkey",
    "privatekey",
    "privatekeypath",
    "keyfile",
    "key",
];
const PASSPHRASE: &[&str] = &["keypassphrase", "passphrase"];
const NOTES: &[&str] = &["notes", "description", "comment", "comments"];
const PROXY: &[&str] = &["proxyhost"];

pub(super) fn load(name: String, text: &str) -> Result<Loaded, String> {
    let rows = parse(text);
    let Some((header, rows)) = rows.split_first() else {
        return Err(format!("{name} is empty"));
    };
    let header = names(header);
    let column = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| header.iter().position(|h| h == n))
    };
    let host_column = column(HOST).ok_or(
        "the file has no column for the host (a header like Hostname/IP, Hostname, Host or Address)",
    )?;
    let at = |row: &[String], names: &[&str]| {
        column(names)
            .and_then(|c| row.get(c))
            .map(|v| v.trim())
            .unwrap_or("")
            .to_owned()
    };

    let local = local_user();
    let mut hosts = Vec::new();
    let mut listed = Vec::new();
    let mut passphrases = HashMap::new();
    let mut other = Vec::new();
    let mut ports = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        // The header is line 1.
        let line = i + 2;
        let address = row.get(host_column).map_or("", |h| h.trim());
        if address.is_empty() {
            continue;
        }
        let (user_in_address, hostname, port_in_address) = split_address(address);
        let label = Some(at(row, LABEL))
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| hostname.clone());
        let protocol = at(row, PROTOCOL).to_ascii_lowercase();
        let mosh = protocol == "mosh";
        if !(protocol.is_empty() || protocol.starts_with("ssh") || mosh) {
            other.push(format!("{label} ({protocol})"));
            continue;
        }
        let port = match at(row, PORT).as_str() {
            "" => port_in_address.unwrap_or(22),
            p => match p.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    ports.push(format!("{label} ({p})"));
                    22
                }
            },
        };
        let user = Some(at(row, USER))
            .filter(|u| !u.is_empty())
            .or(user_in_address)
            .unwrap_or_else(|| local.clone());
        let key = at(row, KEY);
        let password = at(row, PASSWORD);
        let auth = if !key.is_empty() {
            let file = expand_home(&key);
            let passphrase = at(row, PASSPHRASE);
            if !passphrase.is_empty() {
                passphrases.insert(file.clone(), passphrase.into());
            }
            PlannedAuth::Key(file)
        } else if !password.is_empty() {
            PlannedAuth::Password(Some(password.into()))
        } else {
            PlannedAuth::Password(None)
        };
        let mut host = Planned::new(label, hostname, port, user, auth);
        host.group = Some(at(row, GROUP)).filter(|g| !g.is_empty());
        host.tags = at(row, TAGS)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        host.notes = at(row, NOTES);
        if mosh {
            host.unsupported.push("Mosh (connects over SSH)".into());
        }
        let proxy = at(row, PROXY);
        if !proxy.is_empty() {
            host.unsupported.push(format!("a proxy ({proxy})"));
        }
        let id = format!("line {line}");
        listed.push(id.clone());
        hosts.push((id, host));
    }
    let mut warnings = Vec::new();
    if !other.is_empty() {
        warnings.push(format!("Not SSH, so not imported: {}.", other.join(", ")));
    }
    if !ports.is_empty() {
        warnings.push(format!("Not a port, so 22 instead: {}.", ports.join(", ")));
    }
    Ok(Loaded {
        source: name,
        origin: "the CSV file",
        plan: Plan::ordered(hosts),
        listed,
        warnings,
        passphrases,
    })
}

/// A header row's names as columns are looked up: lowercase letters and digits only, so
/// `Hostname/IP`, `hostname_ip` and a spreadsheet's byte order mark all match `hostnameip`.
pub(crate) fn names(header: &[String]) -> Vec<String> {
    header
        .iter()
        .map(|h| {
            h.chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .collect()
}

/// Rows of values: quoted values may hold the separator, quotes (doubled) and line breaks. The
/// separator is what the first line has most of: a comma, a semicolon or a tab.
pub(crate) fn parse(text: &str) -> Vec<Vec<String>> {
    let first = text.lines().next().unwrap_or("");
    let separator = [',', ';', '\t']
        .into_iter()
        .max_by_key(|s| first.matches(*s).count())
        .unwrap_or(',');
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut value = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    value.push('"');
                    chars.next();
                }
                '"' => quoted = false,
                c => value.push(c),
            }
            continue;
        }
        match c {
            '"' if value.trim().is_empty() => {
                value.clear();
                quoted = true;
            }
            c if c == separator => row.push(std::mem::take(&mut value)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut value));
                if row.iter().any(|v| !v.trim().is_empty()) {
                    rows.push(std::mem::take(&mut row));
                }
                row.clear();
            }
            c => value.push(c),
        }
    }
    row.push(value);
    if row.iter().any(|v| !v.trim().is_empty()) {
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(loaded: &Loaded) -> Vec<&Planned> {
        loaded
            .listed
            .iter()
            .map(|id| &loaded.plan.hosts[id])
            .collect()
    }

    #[test]
    fn termius_template() {
        let loaded = load(
            "hosts.csv".into(),
            "Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password\n\
             Production,web-1,\"web,prod\",web1.example.com,ssh,2222,deploy,s3cret\n\
             ,router,,10.0.0.1,telnet,23,,\n\
             Staging,\"db, \"\"main\"\"\",,db.staging.internal,,,postgres,\n\
             ,,,,,,,\n",
        )
        .unwrap();
        let h = hosts(&loaded);
        assert_eq!(h.len(), 2);
        assert_eq!(
            (
                h[0].label.as_str(),
                h[0].hostname.as_str(),
                h[0].port,
                h[0].user.as_str()
            ),
            ("web-1", "web1.example.com", 2222, "deploy")
        );
        assert_eq!(h[0].group.as_deref(), Some("Production"));
        assert_eq!(h[0].tags, ["web", "prod"]);
        assert_eq!(
            h[0].auth,
            PlannedAuth::Password(Some("s3cret".to_owned().into()))
        );
        assert_eq!(h[1].label, "db, \"main\"");
        assert_eq!(
            (h[1].port, h[1].auth.clone()),
            (22, PlannedAuth::Password(None))
        );
        assert_eq!(
            loaded.warnings,
            ["Not SSH, so not imported: router (telnet)."]
        );
        assert_eq!(loaded.listed, ["line 2", "line 4"]);
    }

    #[test]
    fn other_exports_and_separators() {
        // termius-export's columns, with a key and its passphrase.
        let loaded = load(
            "export.csv".into(),
            "Groups,Label,Tags,Hostname,Protocol,Port,Username,Password,IdentityFile,KeyLabel,KeyPassphrase\r\n\
             ,app,,ops@app.example.com:2200,ssh,,,,/keys/app,app key,pw\r\n",
        )
        .unwrap();
        let h = hosts(&loaded);
        assert_eq!((h[0].user.as_str(), h[0].port), ("ops", 2200));
        assert!(matches!(&h[0].auth, PlannedAuth::Key(p) if p.ends_with("keys/app")));
        assert_eq!(loaded.passphrases.len(), 1);

        // A spreadsheet in a language that writes decimals with commas.
        let loaded = load(
            "servers.csv".into(),
            "Name;Address;Port;User;Description\nweb;web.example.com;abc;root;the \"front\"\n",
        )
        .unwrap();
        let h = hosts(&loaded);
        assert_eq!(
            (h[0].label.as_str(), h[0].port, h[0].notes.as_str()),
            ("web", 22, "the \"front\"")
        );
        assert_eq!(loaded.warnings, ["Not a port, so 22 instead: web (abc)."]);

        assert!(load("x.csv".into(), "Name,Port\nweb,22\n").is_err());
    }

    #[test]
    fn quoted_values_hold_line_breaks() {
        assert_eq!(
            parse("a,b\n\"one\ntwo\",\"x\"\"y\"\n"),
            [vec!["a", "b"], vec!["one\ntwo", "x\"y"]]
        );
    }
}
