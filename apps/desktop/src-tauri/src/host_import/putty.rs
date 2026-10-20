//! PuTTY's saved sessions: on Windows from the registry (a `reg export` of
//! `HKCU\Software\SimonTatham\PuTTY\Sessions`), elsewhere from PuTTY's sessions folder, or from a
//! `.reg` file exported on Windows. SSH sessions become hosts, their `.ppk` keys OpenSSH keys in
//! the vault, and an SSH proxy (PuTTY's jump host) the host's jump host.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::{
    AgentPick, ImportSource, Loaded, Plan, Planned, PlannedAuth, local_user, read, split_address,
    text,
};
use crate::util::{expand_home, tilde};

/// One saved session: its name and settings (numbers as decimal text).
#[derive(Debug, Default)]
struct Session {
    name: String,
    values: HashMap<String, String>,
}

impl Session {
    fn get(&self, key: &str) -> &str {
        self.values.get(key).map_or("", |v| v.trim())
    }
}

pub(super) async fn load(source: &ImportSource) -> Result<Loaded, String> {
    let path = source
        .path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    let (name, sessions) = match path {
        _ if source.data.is_some() => {
            let (name, bytes) = read(source)?;
            (name, parse_reg(&text(&bytes)))
        }
        Some(path) => {
            let path = expand_home(path);
            if path.is_dir() {
                (tilde(&path), parse_dir(&path)?)
            } else {
                let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", tilde(&path)))?;
                (tilde(&path), parse_reg(&text(&bytes)))
            }
        }
        None => saved_sessions()?,
    };
    if sessions.is_empty() {
        return Err(format!("{name} has no PuTTY sessions"));
    }
    let (hosts, listed, warnings) = plan(sessions, &local_user(), pageant_running().await);
    Ok(Loaded {
        source: name,
        origin: "PuTTY",
        plan: Plan::ordered(hosts),
        listed,
        warnings,
        passphrases: HashMap::new(),
    })
}

/// The sessions PuTTY saved on this computer.
#[cfg(windows)]
fn saved_sessions() -> Result<(String, Vec<Session>), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let file = std::env::temp_dir().join(format!("morphgate-putty-{}.reg", std::process::id()));
    let out = std::process::Command::new("reg")
        .args(["export", r"HKCU\Software\SimonTatham\PuTTY\Sessions"])
        .arg(&file)
        .arg("/y")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("reg export: {e}"))?;
    let bytes = std::fs::read(&file);
    let _ = std::fs::remove_file(&file);
    if !out.status.success() {
        return Err("PuTTY has no saved sessions on this computer".into());
    }
    let bytes = bytes.map_err(|e| e.to_string())?;
    Ok(("PuTTY's saved sessions".into(), parse_reg(&text(&bytes))))
}

/// The sessions PuTTY saved on this computer (`~/.config/putty/sessions` or `~/.putty/sessions`).
#[cfg(not(windows))]
fn saved_sessions() -> Result<(String, Vec<Session>), String> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| expand_home("~/.config"));
    let found = [config.join("putty/sessions"), expand_home("~/.putty/sessions")]
        .into_iter()
        .find(|d| d.is_dir())
        .ok_or("PuTTY has no saved sessions here (~/.putty/sessions); choose a .reg file exported from PuTTY on Windows")?;
    Ok((tilde(&found), parse_dir(&found)?))
}

async fn pageant_running() -> bool {
    cfg!(windows)
        && mg_ssh::agent::keys(&mg_ssh::AgentSource::Pageant)
            .await
            .is_ok()
}

/// PuTTY writes a session's name with `%XX` for characters a registry key or file name can't
/// hold (`My%20server`).
fn unmunge(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = name
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Sessions in a `.reg` file (`reg export`, or regedit's Export): the keys under
/// `…\PuTTY\Sessions\`, with their strings and numbers (`dword`); other values are skipped.
fn parse_reg(text: &str) -> Vec<Session> {
    let mut sessions: Vec<Session> = Vec::new();
    let mut current = false;
    let mut continued = false;
    for line in text.lines().map(str::trim) {
        // A value goes on over lines that end in `\` (binary ones).
        if continued {
            continued = line.ends_with('\\');
            continue;
        }
        if let Some(key) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let at = key.to_ascii_lowercase().rfind("\\sessions\\");
            current = match at {
                Some(at) if !key.starts_with('-') => {
                    let name = &key[at + "\\sessions\\".len()..];
                    let ok = !name.is_empty() && !name.contains('\\');
                    if ok {
                        sessions.push(Session {
                            name: unmunge(name),
                            ..Session::default()
                        });
                    }
                    ok
                }
                _ => false,
            };
            continue;
        }
        let Some(session) = sessions.last_mut().filter(|_| current) else {
            continue;
        };
        let Some((name, value)) = line.strip_prefix('"').and_then(|l| l.split_once("\"=")) else {
            continue;
        };
        if let Some(s) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            let s = s.replace("\\\"", "\"").replace("\\\\", "\\");
            session.values.insert(name.to_owned(), s);
        } else if let Some(n) = value
            .strip_prefix("dword:")
            .and_then(|d| u32::from_str_radix(d, 16).ok())
        {
            session.values.insert(name.to_owned(), n.to_string());
        } else {
            continued = value.ends_with('\\');
        }
    }
    sessions
}

/// Sessions in PuTTY's folder on Linux and macOS: a file per session, `Key=value` lines.
fn parse_dir(dir: &Path) -> Result<Vec<Session>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", tilde(dir)))?;
    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(content) = std::fs::read(&path) else {
            continue;
        };
        let values = text(&content)
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.to_owned()))
            .collect();
        sessions.push(Session {
            name: unmunge(&entry.file_name().to_string_lossy()),
            values,
        });
    }
    Ok(sessions)
}

fn protocol_name(protocol: &str) -> String {
    match protocol {
        "telnet" => "Telnet".into(),
        "rlogin" => "Rlogin".into(),
        "serial" => "serial".into(),
        "raw" => "raw".into(),
        "supdup" => "SUPDUP".into(),
        other => other.into(),
    }
}

/// PuTTY's proxy types (`ProxyMethod`) other than its SSH jump host (6).
fn proxy_name(method: &str) -> &'static str {
    match method {
        "1" => "a SOCKS 4 proxy",
        "2" => "a SOCKS 5 proxy",
        "3" => "an HTTP proxy",
        "4" => "a Telnet proxy",
        "5" => "a local proxy command",
        _ => "an SSH proxy that runs a command",
    }
}

/// The hosts (by session name; jump hosts that are no session as `jump:user@host:port`), the
/// sessions listed, and what was skipped.
fn plan(
    mut sessions: Vec<Session>,
    local_user: &str,
    pageant: bool,
) -> (Vec<(String, Planned)>, Vec<String>, Vec<String>) {
    sessions.sort_by_key(|s| s.name.to_lowercase());
    let names: HashMap<String, String> = sessions
        .iter()
        .map(|s| (s.name.to_lowercase(), s.name.clone()))
        .collect();
    // Without a key, PuTTY tries Pageant, then asks for a password.
    let without_key = |s: &Session| {
        if pageant && s.get("TryAgent") != "0" {
            PlannedAuth::Agent(AgentPick::named("pageant"))
        } else {
            PlannedAuth::Password(None)
        }
    };
    let mut hosts = Vec::new();
    let mut listed = Vec::new();
    let mut jumps: HashSet<String> = HashSet::new();
    let mut other = Vec::new();
    for s in &sessions {
        let address = s.get("HostName");
        // "Default Settings", and sessions that only keep settings.
        if address.is_empty() || s.name == "Default Settings" {
            continue;
        }
        let protocol = match s.get("Protocol") {
            "" => "ssh",
            p => p,
        };
        if protocol != "ssh" {
            other.push(format!("{} ({})", s.name, protocol_name(protocol)));
            continue;
        }
        let (user_in_address, hostname, port_in_address) = split_address(address);
        let port = s
            .get("PortNumber")
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .or(port_in_address)
            .unwrap_or(22);
        let user = Some(s.get("UserName"))
            .filter(|u| !u.is_empty())
            .map(str::to_owned)
            .or(user_in_address)
            .unwrap_or_else(|| local_user.to_owned());
        let auth = match s.get("PublicKeyFile") {
            "" => without_key(s),
            file => PlannedAuth::Key(expand_home(file)),
        };
        let mut host = Planned::new(s.name.clone(), hostname, port, user.clone(), auth);
        host.forward_agent = s.get("AgentFwd") == "1";
        match s.get("ProxyMethod") {
            "" | "0" => {}
            // An SSH proxy: a saved session's host, or a host of its own.
            "6" => {
                let proxy = s.get("ProxyHost");
                if let Some(name) = names.get(&proxy.to_lowercase()) {
                    host.jump = Some(name.clone());
                } else if !proxy.is_empty() {
                    let (u, h, p) = split_address(proxy);
                    let port = s.get("ProxyPort").parse().ok().or(p).unwrap_or(22);
                    let user = Some(s.get("ProxyUsername"))
                        .filter(|u| !u.is_empty())
                        .map(str::to_owned)
                        .or(u)
                        .unwrap_or_else(|| user.clone());
                    let key = format!("jump:{user}@{h}:{port}");
                    if jumps.insert(key.clone()) {
                        let hop = Planned::new(h.clone(), h, port, user, without_key(s));
                        hosts.push((key.clone(), hop));
                    }
                    host.jump = Some(key);
                }
            }
            method => host.unsupported.push(format!(
                "{} ({}:{})",
                proxy_name(method),
                s.get("ProxyHost"),
                s.get("ProxyPort")
            )),
        }
        if !s.get("PortForwardings").is_empty() {
            host.unsupported
                .push(format!("port forwards ({})", s.get("PortForwardings")));
        }
        if s.get("X11Forward") == "1" {
            host.unsupported.push("X11 forwarding".into());
        }
        if !s.get("RemoteCommand").is_empty() {
            host.unsupported
                .push(format!("a remote command ({})", s.get("RemoteCommand")));
        }
        if !s.get("DetachedCertificate").is_empty() {
            host.certificates
                .push(expand_home(s.get("DetachedCertificate")));
        }
        listed.push(s.name.clone());
        hosts.push((s.name.clone(), host));
    }
    let mut warnings = Vec::new();
    if !other.is_empty() {
        warnings.push(format!("Not SSH, so not imported: {}.", other.join(", ")));
    }
    (hosts, listed, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As `reg export` writes it (in UTF-16, with a byte order mark).
    const REG: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions]

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""
"PortNumber"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Web%20(prod)]
"Present"=dword:00000001
"HostName"="deploy@web.example.com"
"PortNumber"=dword:000008ae
"Protocol"="ssh"
"PublicKeyFile"="C:\\Users\\me\\keys\\web.ppk"
"AgentFwd"=dword:00000001
"PortForwardings"="L8080=localhost:80"
"ProxyMethod"=dword:00000006
"ProxyHost"="Bastion"
"Colour0"="187,187,187"
"SshHostKeys"=hex(7):73,00,73,00,68,00,2d,00,\
  65,00,64,00,00,00,00,00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\bastion]
"HostName"="jump.example.com"
"UserName"="ops"
"Protocol"="ssh"
"TryAgent"=dword:00000001

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\db]
"HostName"="db.internal"
"UserName"="dba"
"ProxyMethod"=dword:00000006
"ProxyHost"="gate.example.com"
"ProxyPort"=dword:00000016
"ProxyUsername"="me"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\router]
"HostName"="10.0.0.1"
"Protocol"="telnet"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\socks]
"HostName"="behind.example.com"
"ProxyMethod"=dword:00000002
"ProxyHost"="proxy.example.com"
"ProxyPort"=dword:00000438
"#;

    fn reg_utf16() -> Vec<u8> {
        [0xFF, 0xFE]
            .into_iter()
            .chain(
                REG.replace('\n', "\r\n")
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect()
    }

    #[test]
    fn sessions_from_a_reg_export() {
        let sessions = parse_reg(&text(&reg_utf16()));
        let names: Vec<&str> = sessions.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Default Settings",
                "Web (prod)",
                "bastion",
                "db",
                "router",
                "socks"
            ]
        );
        let web = &sessions[1];
        assert_eq!(web.get("PortNumber"), "2222");
        assert_eq!(web.get("PublicKeyFile"), r"C:\Users\me\keys\web.ppk");
        assert_eq!(web.get("Colour0"), "187,187,187");
        assert!(
            !web.values.contains_key("SshHostKeys"),
            "binary values are skipped"
        );
        assert_eq!(
            sessions[2].get("UserName"),
            "ops",
            "after a value over two lines"
        );
    }

    #[test]
    fn ssh_sessions_become_hosts() {
        let (hosts, listed, warnings) = plan(parse_reg(REG), "me", false);
        assert_eq!(listed, ["bastion", "db", "socks", "Web (prod)"]);
        assert_eq!(warnings, ["Not SSH, so not imported: router (Telnet)."]);
        let hosts: HashMap<String, Planned> = hosts.into_iter().collect();

        let web = &hosts["Web (prod)"];
        assert_eq!(
            (web.hostname.as_str(), web.port, web.user.as_str()),
            ("web.example.com", 2222, "deploy")
        );
        assert!(
            matches!(&web.auth, PlannedAuth::Key(p) if p.to_string_lossy().ends_with("web.ppk"))
        );
        assert!(web.forward_agent);
        assert_eq!(
            web.jump.as_deref(),
            Some("bastion"),
            "a saved session as the SSH proxy"
        );
        assert_eq!(web.unsupported, ["port forwards (L8080=localhost:80)"]);

        // No key, no Pageant: a password, as PuTTY asks.
        assert_eq!(hosts["bastion"].auth, PlannedAuth::Password(None));
        assert_eq!(hosts["bastion"].user, "ops");

        // An SSH proxy that is no session: a host of its own.
        let db = &hosts["db"];
        assert_eq!(db.jump.as_deref(), Some("jump:me@gate.example.com:22"));
        let gate = &hosts["jump:me@gate.example.com:22"];
        assert_eq!(
            (gate.hostname.as_str(), gate.user.as_str()),
            ("gate.example.com", "me")
        );

        assert_eq!(
            hosts["socks"].unsupported,
            ["a SOCKS 5 proxy (proxy.example.com:1080)"]
        );
        assert_eq!(
            hosts["socks"].user, "me",
            "the local user when the session has none"
        );
    }

    #[test]
    fn pageant_signs_in_where_it_runs() {
        let (hosts, _, _) = plan(parse_reg(REG), "me", true);
        let hosts: HashMap<String, Planned> = hosts.into_iter().collect();
        assert_eq!(
            hosts["bastion"].auth,
            PlannedAuth::Agent(AgentPick::named("pageant"))
        );
    }

    #[test]
    fn sessions_from_putty_on_linux() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("my%20box"),
            "HostName=box.example.com\nPortNumber=2200\nUserName=me\nProtocol=ssh\n",
        )
        .unwrap();
        let sessions = parse_dir(dir.path()).unwrap();
        assert_eq!(sessions[0].name, "my box");
        let (hosts, _, _) = plan(sessions, "local", false);
        assert_eq!(
            (hosts[0].1.hostname.as_str(), hosts[0].1.port),
            ("box.example.com", 2200)
        );
    }
}
