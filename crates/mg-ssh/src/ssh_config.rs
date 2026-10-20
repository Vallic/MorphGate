//! OpenSSH's client configuration (`~/.ssh/config`), read to import its hosts: what each `Host`
//! alias resolves to, the way `ssh` resolves it. The first value of a keyword wins, `Host`
//! patterns take `*`, `?` and `!`, `Include` reads other files in place (globs too), and
//! `IdentityFile` adds up. `Match` blocks can't be evaluated here: they are skipped, and said so.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// `Include` inside `Include`, as deep as `ssh` allows.
const MAX_DEPTH: usize = 16;

/// A configuration, parsed.
#[derive(Debug, Clone)]
pub struct SshConfig {
    lines: Vec<Line>,
    hosts: Vec<String>,
    /// About the files themselves: `Match` blocks skipped, includes that can't be read.
    pub warnings: Vec<String>,
    home: PathBuf,
    local_user: String,
}

/// A setting and the `Host` pattern lists that must all match for it to apply (its block, and
/// the block the `Include` that brought it sat in).
#[derive(Debug, Clone)]
struct Line {
    when: Vec<Vec<String>>,
    /// Inside a `Match` block: never applies here.
    in_match: bool,
    key: String,
    args: Vec<String>,
}

/// What an alias resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    /// `None`: `ssh` would use the local user name.
    pub user: Option<String>,
    /// Every `IdentityFile`, in order, `~` and `%` tokens expanded.
    pub identity_files: Vec<PathBuf>,
    /// Every `CertificateFile`, the same way (ssh also tries `<identity file>-cert.pub`).
    pub certificate_files: Vec<PathBuf>,
    /// `ProxyJump` hops, first to last; empty to connect directly.
    pub jumps: Vec<JumpSpec>,
    /// `IdentityAgent`: the agent's socket or pipe (`~` expanded); `None` for the default
    /// (`SSH_AUTH_SOCK`), `Some("none")` for no agent.
    pub identity_agent: Option<String>,
    /// `ForwardAgent` other than `no`.
    pub forward_agent: bool,
    /// `ProxyCommand` (as written, with its `%` tokens), unless `ProxyJump` is set or it's
    /// `none`.
    pub proxy_command: Option<String>,
    /// What `ssh` would do for this host that an import can't, for the person to see.
    pub unsupported: Vec<String>,
}

/// One `ProxyJump` hop: `[user@]host[:port]` (or `ssh://…`). `host` may be another alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpSpec {
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
}

impl SshConfig {
    /// Reads `path` and what it includes. Relative `Include` paths are under `home/.ssh`, as for
    /// a user's own configuration.
    pub fn load(path: &Path, home: &Path, local_user: &str) -> Result<SshConfig> {
        let mut config = SshConfig {
            lines: Vec::new(),
            hosts: Vec::new(),
            warnings: Vec::new(),
            home: home.to_owned(),
            local_user: local_user.to_owned(),
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        config.read(&text, &[], 0);
        Ok(config)
    }

    /// The aliases a configuration names (the first concrete pattern of each `Host` line), in
    /// order. Lines of only wildcards are defaults, not hosts.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The user `ssh` signs in as when the configuration names none.
    pub fn local_user(&self) -> &str {
        &self.local_user
    }

    fn read(&mut self, text: &str, outer: &[Vec<String>], depth: usize) {
        let mut block: Option<Vec<String>> = None;
        let mut in_match = false;
        for raw in text.lines() {
            let Some((key, args)) = split_line(raw) else {
                continue;
            };
            let mut when = outer.to_vec();
            when.extend(block.clone());
            match key.as_str() {
                "host" => {
                    in_match = false;
                    let patterns: Vec<String> = args
                        .iter()
                        .flat_map(|a| a.split(','))
                        .filter(|p| !p.is_empty())
                        .map(str::to_owned)
                        .collect();
                    // A Host line inside a conditional include only names hosts that also
                    // match the outer block: rare enough to take its aliases as they are.
                    if let Some(alias) = patterns
                        .iter()
                        .find(|p| !p.starts_with('!') && !p.contains(['*', '?']))
                        && !self.hosts.iter().any(|h| h.eq_ignore_ascii_case(alias))
                    {
                        self.hosts.push(alias.clone());
                    }
                    block = Some(patterns);
                }
                "match" => {
                    if args.len() == 1 && args[0].eq_ignore_ascii_case("all") {
                        in_match = false;
                        block = Some(vec!["*".into()]);
                    } else {
                        in_match = true;
                        block = None;
                        let note = "Match blocks are skipped: their settings aren't imported.";
                        if !self.warnings.iter().any(|w| w == note) {
                            self.warnings.push(note.into());
                        }
                    }
                }
                "include" if in_match => {}
                "include" => {
                    if depth >= MAX_DEPTH {
                        self.warnings
                            .push("Include nests too deep: stopped there.".into());
                        continue;
                    }
                    for arg in &args {
                        let pattern = self.include_path(arg);
                        for file in glob(&pattern) {
                            match std::fs::read_to_string(&file) {
                                Ok(text) => self.read(&text, &when, depth + 1),
                                Err(e) => self
                                    .warnings
                                    .push(format!("Include {}: {e}", file.display())),
                            }
                        }
                    }
                }
                _ => self.lines.push(Line {
                    when,
                    in_match,
                    key,
                    args,
                }),
            }
        }
    }

    fn include_path(&self, arg: &str) -> PathBuf {
        let expanded = self.tilde(arg);
        if expanded.is_absolute() {
            expanded
        } else {
            self.home.join(".ssh").join(expanded)
        }
    }

    fn tilde(&self, s: &str) -> PathBuf {
        match s.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None if s == "~" => self.home.clone(),
            None => PathBuf::from(s),
        }
    }

    /// What `alias` resolves to: the first value of each keyword among the lines that apply,
    /// `IdentityFile` and the forwards from all of them.
    pub fn resolve(&self, alias: &str) -> Resolved {
        let mut first: HashMap<&str, &[String]> = HashMap::new();
        let mut identity_files: Vec<&str> = Vec::new();
        let mut certificate_files: Vec<&str> = Vec::new();
        let mut forwards: Vec<String> = Vec::new();
        for line in self.lines.iter().filter(|l| {
            !l.in_match && !l.args.is_empty() && l.when.iter().all(|p| matches(p, alias))
        }) {
            match line.key.as_str() {
                "identityfile" => identity_files.push(&line.args[0]),
                "certificatefile" => certificate_files.push(&line.args[0]),
                "localforward" | "remoteforward" | "dynamicforward" => {
                    forwards.push(format!("{} {}", keyword(&line.key), line.args.join(" ")))
                }
                key => {
                    first.entry(key).or_insert(&line.args);
                }
            }
        }
        let value = |k: &str| first.get(k).map(|a| a[0].as_str());
        let hostname = value("hostname")
            .map(|h| expand(h, &[('h', alias)]))
            .unwrap_or_else(|| alias.to_owned());
        let port = value("port").and_then(|p| p.parse().ok()).unwrap_or(22);
        let user = value("user").map(str::to_owned);
        let remote_user = user.clone().unwrap_or_else(|| self.local_user.clone());
        let home = self.home.to_string_lossy().into_owned();
        let port_text = port.to_string();
        let tokens = [
            ('d', home.as_str()),
            ('u', self.local_user.as_str()),
            ('h', hostname.as_str()),
            ('r', remote_user.as_str()),
            ('p', port_text.as_str()),
            ('n', alias),
        ];
        let files = |list: Vec<&str>| -> Vec<PathBuf> {
            list.into_iter()
                .filter(|f| !f.eq_ignore_ascii_case("none"))
                .map(|f| self.tilde(&expand(f, &tokens)))
                .collect()
        };
        let identity_files = files(identity_files);
        let certificate_files = files(certificate_files);
        let jumps = match first.get("proxyjump") {
            Some(args) if !args[0].eq_ignore_ascii_case("none") => args
                .join(",")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(JumpSpec::parse)
                .collect(),
            _ => Vec::new(),
        };

        let mut unsupported = Vec::new();
        // ProxyJump wins over ProxyCommand, as in ssh.
        let proxy_command = first
            .get("proxycommand")
            .filter(|c| !c[0].eq_ignore_ascii_case("none") && !first.contains_key("proxyjump"))
            .map(|c| c[0].clone());
        unsupported.extend(forwards);
        let forward_agent = value("forwardagent").is_some_and(|v| !v.eq_ignore_ascii_case("no"));
        let identity_agent = value("identityagent")
            .filter(|a| !a.eq_ignore_ascii_case("SSH_AUTH_SOCK"))
            .map(|a| {
                self.tilde(&expand(a, &tokens))
                    .to_string_lossy()
                    .into_owned()
            });
        if let Some(cmd) = value("remotecommand").filter(|c| !c.eq_ignore_ascii_case("none")) {
            unsupported.push(format!("RemoteCommand {cmd}"));
        }

        Resolved {
            alias: alias.to_owned(),
            hostname,
            port,
            user,
            identity_files,
            certificate_files,
            jumps,
            identity_agent,
            forward_agent,
            proxy_command,
            unsupported,
        }
    }
}

impl JumpSpec {
    /// `[user@]host[:port]`, `[user@][v6]:port` or `ssh://[user@]host[:port]`.
    pub fn parse(spec: &str) -> Option<JumpSpec> {
        let spec = spec.strip_prefix("ssh://").unwrap_or(spec);
        let (user, rest) = match spec.rsplit_once('@') {
            Some((u, r)) => (Some(u.to_owned()), r),
            None => (None, spec),
        };
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (host, after) = v6.split_once(']')?;
            (host, after.strip_prefix(':'))
        } else if rest.matches(':').count() == 1 {
            let (h, p) = rest.split_once(':')?;
            (h, Some(p))
        } else {
            (rest, None)
        };
        if host.is_empty() {
            return None;
        }
        let port = match port {
            Some(p) => Some(p.parse().ok()?),
            None => None,
        };
        Some(JumpSpec {
            host: host.to_owned(),
            user,
            port,
        })
    }
}

/// One line as a lowercase keyword and its arguments (`Keyword args` or `Keyword=args`;
/// double quotes group, `#` starts a comment).
fn split_line(raw: &str) -> Option<(String, Vec<String>)> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..end].to_ascii_lowercase();
    let rest = line[end..].trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    // A command is the rest of the line, as written, for a shell to read (as ssh takes it).
    if key == "proxycommand" {
        return Some((key, vec![rest.to_owned()]));
    }
    let mut args = Vec::new();
    let mut chars = rest.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '#' {
            break;
        }
        let mut arg = String::new();
        if c == '"' {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                arg.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                arg.push(c);
                chars.next();
            }
        }
        args.push(arg);
    }
    Some((key, args))
}

/// Whether `host` matches a `Host` pattern list: some pattern matches and no `!pattern` does.
fn matches(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let mut hit = false;
    for p in patterns {
        let p = p.to_ascii_lowercase();
        match p.strip_prefix('!') {
            Some(neg) if wildcard(neg, &host) => return false,
            Some(_) => {}
            None => hit |= wildcard(&p, &host),
        }
    }
    hit
}

/// `*` and `?` wildcards.
fn wildcard(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The files an `Include` names: the path itself, or a `*`/`?` pattern in its last part.
fn glob(pattern: &Path) -> Vec<PathBuf> {
    let name = pattern
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return if pattern.exists() {
            vec![pattern.to_owned()]
        } else {
            Vec::new()
        };
    }
    let dir = pattern.parent().unwrap_or(Path::new("."));
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| wildcard(&name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// `%x` tokens (`%%` is `%`); unknown ones stay as they are.
fn expand(s: &str, tokens: &[(char, &str)]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some(t) => match tokens.iter().find(|(k, _)| *k == t) {
                Some((_, v)) => out.push_str(v),
                None => {
                    out.push('%');
                    out.push(t);
                }
            },
            None => out.push('%'),
        }
    }
    out
}

/// The keyword as `ssh_config(5)` spells it, for messages.
fn keyword(key: &str) -> &str {
    match key {
        "localforward" => "LocalForward",
        "remoteforward" => "RemoteForward",
        "dynamicforward" => "DynamicForward",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(files: &[(&str, &str)]) -> (tempfile::TempDir, SshConfig) {
        let home = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = home.path().join(".ssh").join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let config = SshConfig::load(&home.path().join(".ssh/config"), home.path(), "me").unwrap();
        (home, config)
    }

    #[test]
    fn first_value_wins_and_wildcards_are_defaults() {
        let (home, c) = load(&[(
            "config",
            "# mine\n\
             Host web web.example.com\n  HostName 10.0.0.5\n  User deploy\n  Port=2222\n\
             Host db\n  HostName %h.internal\n\
             Host *.example.com !skip.example.com\n  User ops\n\
             Host *\n  User fallback\n  Port 2200\n  IdentityFile ~/.ssh/id_ed25519\n",
        )]);
        assert_eq!(c.hosts(), ["web", "db"]);
        let web = c.resolve("web");
        assert_eq!(
            (web.hostname.as_str(), web.port, web.user.as_deref()),
            ("10.0.0.5", 2222, Some("deploy"))
        );
        assert_eq!(web.identity_files, [home.path().join(".ssh/id_ed25519")]);
        let db = c.resolve("db");
        assert_eq!(
            (db.hostname.as_str(), db.port, db.user.as_deref()),
            ("db.internal", 2200, Some("fallback"))
        );
        assert_eq!(c.resolve("a.example.com").user.as_deref(), Some("ops"));
        assert_eq!(
            c.resolve("skip.example.com").user.as_deref(),
            Some("fallback")
        );
    }

    #[test]
    fn identity_files_add_up_with_tokens() {
        let (home, c) = load(&[(
            "config",
            "Host app\n  HostName app.example.com\n  User \"deploy\"\n  IdentityFile ~/.ssh/%h_%r\n\
             \x20 CertificateFile ~/.ssh/%r-cert.pub\n\
             Host *\n  IdentityFile %d/.ssh/id_rsa\n  IdentityFile none\n",
        )]);
        let app = c.resolve("app");
        assert_eq!(
            app.identity_files,
            [
                home.path().join(".ssh/app.example.com_deploy"),
                home.path().join(".ssh/id_rsa"),
            ]
        );
        assert_eq!(
            app.certificate_files,
            [home.path().join(".ssh/deploy-cert.pub")]
        );
        assert!(app.unsupported.is_empty(), "{:?}", app.unsupported);
    }

    #[test]
    fn includes_read_in_place_and_inside_blocks() {
        let (_home, c) = load(&[
            (
                "config",
                "Include config.d/*\nHost later\n  HostName later.example.com\n\
                 Host bastion\n  Include bastion.conf\n",
            ),
            (
                "config.d/10-team",
                "Host team1\n  HostName t1.example.com\n  ProxyJump deploy@bastion:2201\n",
            ),
            (
                "config.d/20-more",
                "Host team2\n  HostName t2.example.com\n",
            ),
            ("bastion.conf", "HostName jump.example.com\nUser jumper\n"),
        ]);
        assert_eq!(c.hosts(), ["team1", "team2", "later", "bastion"]);
        assert_eq!(
            c.resolve("team1").jumps,
            [JumpSpec {
                host: "bastion".into(),
                user: Some("deploy".into()),
                port: Some(2201)
            }]
        );
        let b = c.resolve("bastion");
        assert_eq!(
            (b.hostname.as_str(), b.user.as_deref()),
            ("jump.example.com", Some("jumper"))
        );
        // The included lines belong to `Host bastion` only.
        assert_eq!(c.resolve("later").user, None);
    }

    #[test]
    fn match_blocks_are_skipped_and_said_so() {
        let (_home, c) = load(&[(
            "config",
            "Host a\n  HostName a.example.com\n\
             Match host a exec \"true\"\n  User matched\n\
             Host b\n  User bee\n",
        )]);
        assert_eq!(c.resolve("a").user, None);
        assert_eq!(c.resolve("b").user.as_deref(), Some("bee"));
        assert_eq!(c.warnings.len(), 1);
    }

    #[test]
    fn what_cannot_be_imported_is_listed_and_agents_are_read() {
        let (_home, c) = load(&[(
            "config",
            "Host x\n  ProxyCommand sh -c \"nc %h %p\"  # as written\n  ForwardAgent yes\n  LocalForward 8080 localhost:80\n\
             \x20 IdentityAgent ~/.1password/agent.sock\n\
             Host y\n  ProxyJump a,b:2022\n  ProxyCommand nc %h %p\n",
        )]);
        let x = c.resolve("x");
        assert_eq!(x.unsupported, ["LocalForward 8080 localhost:80"]);
        // A command is the rest of the line, quotes and all, as ssh hands it to the shell.
        assert_eq!(
            x.proxy_command.as_deref(),
            Some("sh -c \"nc %h %p\"  # as written")
        );
        // The agent settings are imported.
        assert!(x.forward_agent);
        let agent = x.identity_agent.unwrap();
        assert!(
            agent.ends_with("/.1password/agent.sock") && !agent.starts_with('~'),
            "{agent}"
        );
        // ProxyJump wins over ProxyCommand, as in ssh.
        let y = c.resolve("y");
        assert!(y.unsupported.is_empty());
        assert_eq!(y.proxy_command, None);
        assert_eq!(y.jumps.len(), 2);
        assert_eq!(y.jumps[1].port, Some(2022));
    }

    #[test]
    fn jump_specs() {
        let p = |s| JumpSpec::parse(s).unwrap();
        assert_eq!(p("bastion").host, "bastion");
        let full = p("ssh://ops@jump.example.com:2222");
        assert_eq!(
            (full.user.as_deref(), full.host.as_str(), full.port),
            (Some("ops"), "jump.example.com", Some(2222))
        );
        assert_eq!(p("[2001:db8::1]:22").host, "2001:db8::1");
        assert_eq!(p("2001:db8::1").port, None);
        assert!(JumpSpec::parse("host:notaport").is_none());
    }
}
