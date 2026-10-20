//! OpenSSH's configuration (`~/.ssh/config`): each `Host` alias becomes a host, the private keys
//! its `IdentityFile`s name become key items (or the vault's copy, by fingerprint), and
//! `ProxyJump` becomes the host's jump host.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use mg_ssh::ssh_config::{JumpSpec, Resolved, SshConfig};

use super::{AgentPick, Loaded, Plan, Planned, PlannedAuth, agent_available, local_user};
use crate::util::{expand_home, tilde};

const DEFAULT_CONFIG: &str = "~/.ssh/config";
/// What `ssh` tries when a host names no `IdentityFile`, in its order.
const DEFAULT_KEYS: [&str; 3] = ["~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_rsa"];

pub(super) fn load(path: Option<&str>) -> Result<Loaded, String> {
    let path = expand_home(
        path.map(str::trim)
            .filter(|p| !p.is_empty())
            .unwrap_or(DEFAULT_CONFIG),
    );
    let home = std::env::home_dir().ok_or("no home folder")?;
    let config = SshConfig::load(&path, &home, &local_user()).map_err(|e| e.to_string())?;
    let listed = config.hosts().to_vec();
    Ok(Loaded {
        source: tilde(&path),
        origin: "~/.ssh/config",
        plan: plan(&config, &listed),
        listed,
        warnings: config.warnings.clone(),
        passphrases: HashMap::new(),
    })
}

impl AgentPick {
    /// The agent an `IdentityAgent` socket belongs to: the ones MorphGate knows by name (so the
    /// host works on every device that runs it), else that socket.
    fn from_socket(socket: Option<&str>) -> AgentPick {
        let Some(socket) = socket else {
            return AgentPick::default();
        };
        if socket.contains("/.1password/agent.sock")
            || socket.contains("com.1password/t/agent.sock")
        {
            AgentPick::named("1password")
        } else if socket.ends_with(".bitwarden-ssh-agent.sock") {
            AgentPick::named("bitwarden")
        } else if socket.contains("com.maxgoedjen.Secretive") {
            AgentPick::named("secretive")
        } else {
            AgentPick {
                agent: Some("custom".into()),
                path: Some(tilde(Path::new(socket))),
                key: None,
            }
        }
    }
}

/// Whether a file holds a public key (an `IdentityFile` naming a key that lives in an agent).
fn is_public_key(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|t| mg_ssh::keys::public_fingerprint(t.lines().next().unwrap_or("")).is_some())
        .unwrap_or(false)
}

/// How `ssh` would sign in: the first `IdentityFile` there is (a public one means its key is
/// in the agent: only that key is offered), else the default keys, else the agent
/// (`IdentityAgent`'s, or the system's), else a password.
fn auth_for(resolved: &Resolved) -> PlannedAuth {
    let no_agent = resolved
        .identity_agent
        .as_deref()
        .is_some_and(|a| a.eq_ignore_ascii_case("none"));
    let agent = || AgentPick::from_socket(resolved.identity_agent.as_deref());
    for file in &resolved.identity_files {
        if !file.is_file() {
            continue;
        }
        if is_public_key(file) {
            if no_agent {
                continue;
            }
            let key = std::fs::read_to_string(file)
                .ok()
                .and_then(|t| mg_ssh::keys::public_fingerprint(t.lines().next().unwrap_or("")));
            return PlannedAuth::Agent(AgentPick { key, ..agent() });
        }
        return PlannedAuth::Key(file.clone());
    }
    if let Some(file) = DEFAULT_KEYS
        .iter()
        .map(|k| expand_home(k))
        .find(|k| k.is_file())
    {
        return PlannedAuth::Key(file);
    }
    if resolved.identity_agent.is_some() && !no_agent {
        PlannedAuth::Agent(agent())
    } else if agent_available() && !no_agent {
        PlannedAuth::Agent(AgentPick::default())
    } else {
        PlannedAuth::Password(None)
    }
}

fn planned(
    config: &SshConfig,
    resolved: Resolved,
    label: String,
    user: Option<String>,
    port: Option<u16>,
) -> Planned {
    let auth = auth_for(&resolved);
    let mut host = Planned::new(
        label,
        resolved.hostname,
        port.unwrap_or(resolved.port),
        user.or(resolved.user)
            .unwrap_or_else(|| config.local_user().to_owned()),
        auth,
    );
    host.forward_agent = resolved.forward_agent;
    host.proxy_command = resolved.proxy_command;
    host.certificates = resolved.certificate_files;
    host.unsupported = resolved.unsupported;
    host
}

fn hop_key(spec: &JumpSpec) -> String {
    let mut key = String::new();
    if let Some(u) = &spec.user {
        key.push_str(u);
        key.push('@');
    }
    key.push_str(&spec.host);
    if let Some(p) = spec.port {
        key.push_str(&format!(":{p}"));
    }
    key
}

/// The hosts `aliases` need: each alias, and its jump hosts. A hop that is an alias with no
/// user or port of its own is that alias's host; others (`ops@bastion:2222`) are hosts of their
/// own, from what their host name resolves to. In a chain `a,b`, `b` goes through `a`.
fn plan(config: &SshConfig, aliases: &[String]) -> Plan {
    let mut plan = Plan {
        hosts: BTreeMap::new(),
        order: Vec::new(),
        notes: Vec::new(),
    };
    for alias in aliases {
        let resolved = config.resolve(alias);
        let jumps = resolved.jumps.clone();
        let host = planned(config, resolved, alias.clone(), None, None);
        visit(
            config,
            &mut plan,
            alias.clone(),
            host,
            jumps,
            &mut Vec::new(),
        );
    }
    plan
}

/// Plans `host` (plan key `key`) after the hops in `jumps`.
fn visit(
    config: &SshConfig,
    plan: &mut Plan,
    key: String,
    mut host: Planned,
    jumps: Vec<JumpSpec>,
    stack: &mut Vec<String>,
) {
    if plan.hosts.contains_key(&key) {
        return;
    }
    if stack.contains(&key) {
        plan.notes.push(format!(
            "{key}: its jump hosts go round in a loop; imported without one"
        ));
        return;
    }
    stack.push(key.clone());
    let mut previous: Option<String> = None;
    for spec in jumps {
        let alias = spec.user.is_none()
            && spec.port.is_none()
            && config
                .hosts()
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&spec.host));
        let resolved = config.resolve(&spec.host);
        let hop = if alias {
            spec.host.clone()
        } else {
            hop_key(&spec)
        };
        // An alias hop keeps its own jump hosts; another hop goes through the one before it in
        // this chain.
        if alias {
            let own = resolved.jumps.clone();
            let h = planned(config, resolved, spec.host.clone(), None, None);
            visit(config, plan, hop.clone(), h, own, stack);
        } else {
            let mut h = planned(
                config,
                resolved,
                spec.host.clone(),
                spec.user.clone(),
                spec.port,
            );
            h.jump = previous.clone();
            visit(config, plan, hop.clone(), h, Vec::new(), stack);
        }
        // A hop that broke a loop isn't planned: nothing to go through.
        if plan.hosts.contains_key(&hop) {
            previous = Some(hop);
        }
    }
    host.jump = host.jump.take().or(previous);
    stack.pop();
    plan.hosts.insert(key.clone(), host);
    plan.order.push(key);
}

#[cfg(test)]
mod tests {
    use super::super::read_key;
    use super::*;

    fn config(text: &str) -> (tempfile::TempDir, SshConfig) {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        std::fs::write(home.path().join(".ssh/config"), text).unwrap();
        let c = SshConfig::load(&home.path().join(".ssh/config"), home.path(), "me").unwrap();
        (home, c)
    }

    #[test]
    fn jump_hosts_come_along_in_order() {
        let (_h, c) = config(
            "Host app\n  HostName app.internal\n  User deploy\n  ProxyJump bastion\n\
             Host bastion\n  HostName jump.example.com\n  User ops\n\
             Host deep\n  HostName deep.internal\n  ProxyJump bastion,ops@inner.example.com:2222\n",
        );
        let p = plan(&c, &["app".into(), "deep".into()]);
        assert_eq!(
            p.order,
            ["bastion", "app", "ops@inner.example.com:2222", "deep"]
        );
        assert_eq!(p.hosts["app"].jump.as_deref(), Some("bastion"));
        let inner = &p.hosts["ops@inner.example.com:2222"];
        assert_eq!((inner.user.as_str(), inner.port), ("ops", 2222));
        assert_eq!(inner.jump.as_deref(), Some("bastion"));
        assert_eq!(
            p.hosts["deep"].jump.as_deref(),
            Some("ops@inner.example.com:2222")
        );
        assert_eq!(p.hosts["deep"].user, "me", "the local user, as ssh");
        // Picking one alias brings only the hosts it needs.
        assert_eq!(p.needed(&["app".into()]), ["bastion", "app"]);
    }

    #[test]
    fn a_proxy_command_comes_along() {
        let (_h, c) = config(
            "Host private\n  HostName i-0abc123\n  User ec2-user\n\
             \x20 ProxyCommand sh -c \"aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'\"\n",
        );
        let p = plan(&c, &["private".into()]);
        assert_eq!(
            p.hosts["private"].proxy_command.as_deref(),
            Some(
                "sh -c \"aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'\""
            )
        );
        assert!(p.hosts["private"].unsupported.is_empty());
    }

    #[test]
    fn jump_loops_are_broken() {
        let (_h, c) = config("Host a\n  ProxyJump b\nHost b\n  ProxyJump a\n");
        let p = plan(&c, &["a".into()]);
        assert_eq!(p.order, ["b", "a"]);
        assert_eq!(p.hosts["b"].jump, None);
        assert_eq!(p.hosts["a"].jump.as_deref(), Some("b"));
        assert_eq!(p.notes.len(), 1);
    }

    #[test]
    fn identity_files_pick_the_auth() {
        let (home, c) = config(
            "Host k\n  IdentityFile ~/.ssh/missing\n  IdentityFile ~/.ssh/work\n\
             Host a\n  IdentityFile ~/.ssh/agent.pub\n",
        );
        let ssh = home.path().join(".ssh");
        let (pem, info) = mg_ssh::keys::generate_ed25519("work").unwrap();
        std::fs::write(ssh.join("work"), pem.as_bytes()).unwrap();
        std::fs::write(ssh.join("agent.pub"), format!("{}\n", info.public_key)).unwrap();
        assert_eq!(
            auth_for(&c.resolve("k")),
            PlannedAuth::Key(ssh.join("work"))
        );
        // A public key names the agent key to offer.
        assert_eq!(
            auth_for(&c.resolve("a")),
            PlannedAuth::Agent(AgentPick {
                key: Some(info.fingerprint.clone()),
                ..AgentPick::default()
            })
        );
        let k = read_key(&ssh.join("work"), None);
        assert_eq!(k.fingerprint.as_deref(), Some(info.fingerprint.as_str()));
        assert!(!k.encrypted && k.error.is_none());
    }

    #[test]
    fn identity_agents_are_named() {
        let pick = |s: &str| AgentPick::from_socket(Some(s));
        assert_eq!(
            pick("/home/me/.1password/agent.sock").agent.as_deref(),
            Some("1password")
        );
        assert_eq!(
            pick("/Users/me/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock")
                .agent
                .as_deref(),
            Some("1password")
        );
        assert_eq!(
            pick("/home/me/.bitwarden-ssh-agent.sock").agent.as_deref(),
            Some("bitwarden")
        );
        let custom = pick("/run/user/1000/gnupg/S.gpg-agent.ssh");
        assert_eq!(
            (custom.agent.as_deref(), custom.path.as_deref()),
            (Some("custom"), Some("/run/user/1000/gnupg/S.gpg-agent.ssh"))
        );
    }
}
