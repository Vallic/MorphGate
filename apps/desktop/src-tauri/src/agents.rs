//! SSH agents on this device: where the ones a host can name listen here (1Password, Bitwarden,
//! Secretive, Pageant, the system's), whether they run, and the keys they hold. A vault item
//! names the agent (and maybe one key's fingerprint), never a path: the same item works on every
//! device that runs that agent.

use std::path::PathBuf;

use mg_ssh::{AgentKey, AgentSource};
use serde::Serialize;

use crate::util::{expand_home, tilde};

/// What `HostAuth::Agent.agent` may name, as the UI calls it.
const KINDS: [(&str, &str); 6] = [
    ("system", "System agent"),
    ("1password", "1Password"),
    ("bitwarden", "Bitwarden"),
    ("secretive", "Secretive"),
    ("pageant", "Pageant"),
    ("custom", "Other socket or pipe"),
];

/// Where `agent` listens on this device (`path` for `custom`).
pub fn source(agent: Option<&str>, path: Option<&str>) -> Result<AgentSource, String> {
    match agent.unwrap_or("system") {
        "system" => Ok(AgentSource::System),
        "1password" => one_password(),
        "bitwarden" => bitwarden(),
        "secretive" => secretive(),
        "pageant" => Ok(AgentSource::Pageant),
        "custom" => match path.map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => Ok(AgentSource::Path(expand_home(p))),
            None => Err("no socket or pipe set for this host's agent".into()),
        },
        other => Err(format!(
            "this host's agent ({other}) is one this version of MorphGate doesn't know"
        )),
    }
}

/// On Windows, 1Password and Bitwarden take over OpenSSH's pipe.
fn one_password() -> Result<AgentSource, String> {
    if cfg!(windows) {
        return Ok(AgentSource::System);
    }
    let path = if cfg!(target_os = "macos") {
        "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
    } else {
        "~/.1password/agent.sock"
    };
    Ok(AgentSource::Path(expand_home(path)))
}

fn bitwarden() -> Result<AgentSource, String> {
    if cfg!(windows) {
        return Ok(AgentSource::System);
    }
    // The Flatpak and Snap builds keep it inside their own folders.
    let candidates = [
        "~/.bitwarden-ssh-agent.sock",
        "~/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock",
        "~/snap/bitwarden/current/.bitwarden-ssh-agent.sock",
    ]
    .map(expand_home);
    let found = candidates.iter().find(|p| p.exists()).cloned();
    Ok(AgentSource::Path(
        found.unwrap_or_else(|| candidates[0].clone()),
    ))
}

fn secretive() -> Result<AgentSource, String> {
    if cfg!(target_os = "macos") {
        Ok(AgentSource::Path(expand_home(
            "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh",
        )))
    } else {
        Err("Secretive runs on macOS only".into())
    }
}

/// The agents this device can have.
fn kinds_here() -> Vec<(&'static str, &'static str)> {
    KINDS
        .into_iter()
        .filter(|(id, _)| {
            (*id != "secretive" || cfg!(target_os = "macos")) && (*id != "pageant" || cfg!(windows))
        })
        .collect()
}

fn location(source: &AgentSource) -> String {
    match source {
        AgentSource::System if cfg!(windows) => r"\\.\pipe\openssh-ssh-agent".into(),
        AgentSource::System => std::env::var_os("SSH_AUTH_SOCK")
            .map(|p| tilde(&PathBuf::from(p)))
            .unwrap_or_else(|| "SSH_AUTH_SOCK (not set)".into()),
        AgentSource::Path(p) => tilde(p),
        AgentSource::Pageant => "Pageant".into(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentView {
    /// What a host stores (`system`, `1password`, …, `custom`).
    id: &'static str,
    name: &'static str,
    /// Where it listens here (`~/…`); empty for `custom`.
    location: String,
    /// It answered: `keys` is what it holds.
    running: bool,
    keys: Vec<AgentKey>,
    /// Why it didn't answer.
    error: Option<String>,
}

/// The agents this device can have, each with the keys it holds now (`custom` with `path`'s).
#[tauri::command]
pub async fn agents_list(path: Option<String>) -> Vec<AgentView> {
    let mut out = Vec::new();
    for (id, name) in kinds_here() {
        let source = match source(Some(id), path.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                out.push(AgentView {
                    id,
                    name,
                    location: String::new(),
                    running: false,
                    keys: Vec::new(),
                    error: Some(e),
                });
                continue;
            }
        };
        let (running, keys, error) = match mg_ssh::agent::keys(&source).await {
            Ok(keys) => (true, keys, None),
            Err(e) => (false, Vec::new(), Some(e.to_string())),
        };
        out.push(AgentView {
            id,
            name,
            location: location(&source),
            running,
            keys,
            error,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_resolve_to_places() {
        assert_eq!(source(None, None).unwrap(), AgentSource::System);
        assert_eq!(source(Some("system"), None).unwrap(), AgentSource::System);
        assert_eq!(
            source(Some("custom"), Some("/run/agent.sock")).unwrap(),
            AgentSource::Path("/run/agent.sock".into())
        );
        assert!(source(Some("custom"), Some(" ")).is_err());
        assert!(
            source(Some("future-agent"), None)
                .unwrap_err()
                .contains("future-agent")
        );
        #[cfg(target_os = "linux")]
        {
            let AgentSource::Path(p) = source(Some("1password"), None).unwrap() else {
                panic!("a socket")
            };
            assert!(p.ends_with(".1password/agent.sock"));
            assert!(source(Some("secretive"), None).is_err());
        }
    }
}
