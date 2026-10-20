//! Trust-on-first-use host key verification against OpenSSH-format known_hosts files, and host
//! CAs: a host certificate signed by a CA trusted for the host is accepted without pinning
//! (OpenSSH's `@cert-authority`, from those files or the vault).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::{Certificate, HashAlg, PublicKey, known_hosts};

use crate::{Error, Result};

/// Where host keys are trusted from.
///
/// `primary` is MorphGate's own file (read + write). `read_only` files (typically
/// `~/.ssh/known_hosts`) are consulted but never modified. Host CAs come from `@cert-authority`
/// lines in those files and from the app ([`KnownHosts::set_authorities`]).
#[derive(Clone, Debug)]
pub struct KnownHosts {
    primary: PathBuf,
    read_only: Vec<PathBuf>,
    authorities: Arc<Mutex<Vec<HostAuthority>>>,
}

/// A host CA: host keys it signed are trusted for the hosts its patterns match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAuthority {
    /// OpenSSH host patterns: `*.example.com`, `10.0.?.*`, `!bastion.example.com`,
    /// `[*.example.com]:2222`.
    pub patterns: Vec<String>,
    pub key: PublicKey,
    /// Where it's from, for messages: a vault item's name, or `~/.ssh/known_hosts:12`.
    pub from: String,
}

impl HostAuthority {
    /// A CA from its public key (`ssh-ed25519 AAAA…`), trusted for `patterns`.
    pub fn new(
        public_key: &str,
        patterns: Vec<String>,
        from: impl Into<String>,
    ) -> std::result::Result<Self, String> {
        let key = PublicKey::from_openssh(public_key.trim())
            .map_err(|_| "not an SSH public key (ssh-ed25519 AAAA…)".to_owned())?;
        Ok(Self {
            patterns,
            key: bare(&key),
            from: from.into(),
        })
    }

    /// `(algorithm, SHA256 fingerprint)`, as OpenSSH prints them.
    pub fn describe(&self) -> (String, String) {
        describe(&self.key)
    }
}

/// `name` matches the glob `pattern` (`*` any run, `?` one character), ignoring case.
fn glob(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob(&pattern[1..], name) || (!name.is_empty() && glob(pattern, &name[1..]))
        }
        (Some(b'?'), Some(_)) => glob(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) if p.eq_ignore_ascii_case(n) => glob(&pattern[1..], &name[1..]),
        _ => false,
    }
}

/// OpenSSH's host matching: the name is `host`, or `[host]:port` off port 22; a negated pattern
/// that matches wins over any other. `any_port`: a bare pattern matches the host on any port
/// (the vault's CAs: people write `*.example.com` and mean it).
fn matches(patterns: &[String], host: &str, port: u16, any_port: bool) -> bool {
    let bracketed = format!("[{host}]:{port}");
    let names: Vec<&str> = match (port, any_port) {
        (22, _) => vec![host],
        (_, true) => vec![host, &bracketed],
        (_, false) => vec![&bracketed],
    };
    let mut matched = false;
    for p in patterns {
        let (negated, p) = match p.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, p.as_str()),
        };
        if names.iter().any(|n| glob(p.as_bytes(), n.as_bytes())) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// The `@cert-authority` lines of a known_hosts file (hashed host names can't be patterns).
fn file_authorities(path: &Path) -> Vec<HostAuthority> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut words = line.split_whitespace();
        if words.next() != Some("@cert-authority") {
            continue;
        }
        let (Some(hosts), Some(kind), Some(data)) = (words.next(), words.next(), words.next())
        else {
            continue;
        };
        if hosts.starts_with('|') {
            continue;
        }
        if let Ok(key) = PublicKey::from_openssh(&format!("{kind} {data}")) {
            out.push(HostAuthority {
                patterns: hosts.split(',').map(str::to_owned).collect(),
                key,
                from: format!("{}:{}", path.display(), n + 1),
            });
        }
    }
    out
}

/// Whether `cert` is a host certificate for `host` that one of `authorities` signed and that is
/// valid now; why not, otherwise.
pub(crate) fn certified(
    cert: &Certificate,
    host: &str,
    authorities: &[HostAuthority],
) -> std::result::Result<(), String> {
    if cert.cert_type() != CertType::Host {
        return Err("it's a user certificate, not a host's".into());
    }
    let Some(ca) = authorities
        .iter()
        .find(|a| a.key.key_data() == cert.signature_key())
    else {
        return Err(format!(
            "it's signed by {}, which isn't a CA trusted for this host",
            cert.signature_key().fingerprint(HashAlg::Sha256)
        ));
    };
    let fingerprint = ca.key.fingerprint(HashAlg::Sha256);
    cert.validate([&fingerprint]).map_err(|_| {
        "it isn't valid now (expired, not yet valid), or its signature doesn't check out".to_owned()
    })?;
    let principals = cert.valid_principals();
    if !principals.is_empty() && !principals.iter().any(|p| p.eq_ignore_ascii_case(host)) {
        return Err(format!("it's for {}, not {host}", principals.join(", ")));
    }
    if !cert.critical_options().is_empty() {
        return Err("it has critical options, which host certificates don't".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyCheck {
    Trusted,
    Unknown,
    /// A different key of the same algorithm is recorded: possible MITM.
    Changed {
        path: PathBuf,
        line: usize,
    },
}

/// What the user is shown when a host key needs a decision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// `SHA256:…`, as printed by OpenSSH.
    pub fingerprint: String,
    /// Set when the key differs from a recorded one: (file, line).
    #[serde(skip)]
    pub changed_in: Option<(PathBuf, usize)>,
    /// The recorded key when it differs: `(algorithm, SHA256 fingerprint)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned: Option<(String, String)>,
}

fn describe(key: &PublicKey) -> (String, String) {
    (
        key.algorithm().to_string(),
        key.fingerprint(HashAlg::Sha256).to_string(),
    )
}

impl HostKeyInfo {
    pub(crate) fn new(host: &str, port: u16, key: &PublicKey) -> Self {
        Self {
            host: host.to_owned(),
            port,
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            changed_in: None,
            pinned: None,
        }
    }
}

impl KnownHosts {
    pub fn new(primary: impl Into<PathBuf>) -> Self {
        Self {
            primary: primary.into(),
            read_only: Vec::new(),
            authorities: Arc::default(),
        }
    }

    /// The host CAs the app trusts (the vault's), besides the files' `@cert-authority` lines.
    pub fn set_authorities(&self, authorities: Vec<HostAuthority>) {
        *self.authorities.lock().expect("not poisoned") = authorities;
    }

    /// The host CAs trusted for `host:port`.
    pub fn authorities_for(&self, host: &str, port: u16) -> Vec<HostAuthority> {
        let mut out: Vec<HostAuthority> = self
            .authorities
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|a| matches(&a.patterns, host, port, true))
            .cloned()
            .collect();
        for path in std::iter::once(&self.primary).chain(&self.read_only) {
            out.extend(
                file_authorities(path)
                    .into_iter()
                    .filter(|a| matches(&a.patterns, host, port, false)),
            );
        }
        out
    }

    pub fn with_read_only(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_only.push(path.into());
        self
    }

    /// `~/.ssh/known_hosts`, if a home directory exists.
    pub fn openssh_default() -> Option<PathBuf> {
        std::env::home_dir().map(|h| h.join(".ssh").join("known_hosts"))
    }

    pub fn primary(&self) -> &Path {
        &self.primary
    }

    /// A changed key in any file wins over a match elsewhere: we fail closed.
    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> Result<HostKeyCheck> {
        let key = &bare(key);
        let mut trusted = false;
        for path in std::iter::once(&self.primary).chain(&self.read_only) {
            match known_hosts::check_known_hosts_path(host, port, key, path) {
                Ok(true) => trusted = true,
                Ok(false) => {}
                Err(russh::keys::Error::KeyChanged { line }) => {
                    return Ok(HostKeyCheck::Changed {
                        path: path.clone(),
                        line,
                    });
                }
                Err(e) => return Err(Error::KnownHosts(format!("{}: {e}", path.display()))),
            }
        }
        Ok(if trusted {
            HostKeyCheck::Trusted
        } else {
            HostKeyCheck::Unknown
        })
    }

    /// The key recorded for `host:port`, as `(algorithm, SHA256 fingerprint)`: what a connection
    /// is pinned to (the first match, MorphGate's own file first).
    pub fn pinned(&self, host: &str, port: u16) -> Option<(String, String)> {
        std::iter::once(&self.primary)
            .chain(&self.read_only)
            .filter_map(|path| known_hosts::known_host_keys_path(host, port, path).ok())
            .flatten()
            .map(|(_, key)| describe(&key))
            .next()
    }

    /// The key on `line` of `path` (1-based, as a change reports it).
    pub(crate) fn recorded(
        &self,
        host: &str,
        port: u16,
        path: &Path,
        line: usize,
    ) -> Option<(String, String)> {
        known_hosts::known_host_keys_path(host, port, path)
            .ok()?
            .into_iter()
            .find(|(l, _)| *l == line)
            .map(|(_, key)| describe(&key))
    }

    /// Records the key in the primary file (creating it and its directory if needed).
    pub fn learn(&self, host: &str, port: u16, key: &PublicKey) -> Result<()> {
        known_hosts::learn_known_hosts_path(host, port, &bare(key), &self.primary)
            .map_err(|e| Error::KnownHosts(format!("{}: {e}", self.primary.display())))
    }
}

/// `russh` compares keys including their comment; known_hosts entries never carry one.
fn bare(key: &PublicKey) -> PublicKey {
    PublicKey::new(key.key_data().clone(), "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR")))
            .unwrap()
    }

    fn authority(patterns: &[&str], file: &str) -> HostAuthority {
        HostAuthority {
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            key: PublicKey::from_openssh(data(file).trim()).unwrap(),
            from: "test".into(),
        }
    }

    #[test]
    fn host_patterns_match_as_openssh_does() {
        let p = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(matches(
            &p(&["*.example.com"]),
            "web.EXAMPLE.com",
            22,
            false
        ));
        assert!(!matches(&p(&["*.example.com"]), "example.com", 22, false));
        assert!(matches(&p(&["10.0.?.*"]), "10.0.1.20", 22, false));
        // A negation wins.
        assert!(!matches(
            &p(&["*.example.com", "!bastion.example.com"]),
            "bastion.example.com",
            22,
            false
        ));
        // Off port 22 the name is [host]:port, unless the pattern is the vault's (any port).
        assert!(!matches(
            &p(&["*.example.com"]),
            "web.example.com",
            2222,
            false
        ));
        assert!(matches(
            &p(&["[*.example.com]:2222"]),
            "web.example.com",
            2222,
            false
        ));
        assert!(matches(
            &p(&["*.example.com"]),
            "web.example.com",
            2222,
            true
        ));
    }

    #[test]
    fn a_host_certificate_from_a_trusted_ca_is_accepted() {
        let cert = Certificate::from_openssh(data("host-cert.pub").trim()).unwrap();
        let ca = [authority(&["*.example.com"], "user-ca.pub")];
        assert_eq!(certified(&cert, "web.example.com", &ca), Ok(()));
        // Not the host it names.
        let e = certified(&cert, "db.example.com", &ca).unwrap_err();
        assert!(
            e.contains("it's for web.example.com, not db.example.com"),
            "{e}"
        );
        // Signed by a CA not trusted for it.
        let other = [authority(&["*"], "other.pub")];
        assert!(
            certified(&cert, "web.example.com", &other)
                .unwrap_err()
                .contains("isn't a CA trusted")
        );
        // A user certificate isn't a host's.
        let user = Certificate::from_openssh(data("user-cert.pub").trim()).unwrap();
        assert!(
            certified(&user, "web.example.com", &ca)
                .unwrap_err()
                .contains("user certificate")
        );
    }

    #[test]
    fn cert_authority_lines_and_the_vaults_cas() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        std::fs::write(
            &file,
            format!(
                "# a comment\n@cert-authority *.example.com,!bastion.example.com {}\n@revoked * {}\n",
                data("user-ca.pub").trim(),
                data("other.pub").trim()
            ),
        )
        .unwrap();
        let kh = KnownHosts::new(dir.path().join("mine")).with_read_only(&file);
        let found = kh.authorities_for("web.example.com", 22);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].from.ends_with("known_hosts:2"),
            "{}",
            found[0].from
        );
        assert!(kh.authorities_for("bastion.example.com", 22).is_empty());
        assert!(kh.authorities_for("web.example.com", 2222).is_empty());
        // The plain-key check reads past those lines.
        let key = PublicKey::from_openssh(data("other.pub").trim()).unwrap();
        assert_eq!(
            kh.check("web.example.com", 22, &key).unwrap(),
            HostKeyCheck::Unknown
        );
        // The vault's: a bare pattern on any port.
        kh.set_authorities(vec![authority(&["*.example.com"], "user-ca.pub")]);
        assert_eq!(kh.authorities_for("web.example.com", 2222).len(), 1);
    }

    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRbMaf7RI+oSkPOCPrFjPoMWJEIu96Drte4Q3r9OQYR test";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8ttLoasjnhpcovdFKLunHTySEEOQZL+W6hoRC+NfM5 test";

    fn key(s: &str) -> PublicKey {
        PublicKey::from_openssh(s).unwrap()
    }

    #[test]
    fn unknown_then_learned_then_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts::new(dir.path().join("sub/known_hosts"));
        assert_eq!(
            kh.check("example.com", 22, &key(KEY_A)).unwrap(),
            HostKeyCheck::Unknown
        );
        kh.learn("example.com", 22, &key(KEY_A)).unwrap();
        assert_eq!(
            kh.check("example.com", 22, &key(KEY_A)).unwrap(),
            HostKeyCheck::Trusted
        );
        assert_eq!(
            kh.check("example.com", 2222, &key(KEY_A)).unwrap(),
            HostKeyCheck::Unknown
        );
    }

    #[test]
    fn changed_key_is_detected_even_in_read_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let openssh = dir.path().join("openssh_known_hosts");
        std::fs::write(&openssh, format!("db.internal {KEY_A}\n")).unwrap();
        let kh = KnownHosts::new(dir.path().join("mine")).with_read_only(&openssh);
        assert_eq!(
            kh.check("db.internal", 22, &key(KEY_A)).unwrap(),
            HostKeyCheck::Trusted
        );
        assert!(matches!(
            kh.check("db.internal", 22, &key(KEY_B)).unwrap(),
            HostKeyCheck::Changed { line: 1, .. }
        ));
        assert!(
            !dir.path().join("mine").exists(),
            "check must not create the primary file"
        );
    }

    #[test]
    fn the_pinned_key_is_found_by_host_and_by_line() {
        let dir = tempfile::tempdir().unwrap();
        let openssh = dir.path().join("openssh_known_hosts");
        std::fs::write(
            &openssh,
            format!("other {KEY_B}\n[db.internal]:2222 {KEY_A}\n"),
        )
        .unwrap();
        let kh = KnownHosts::new(dir.path().join("mine")).with_read_only(&openssh);
        let a = HostKeyInfo::new("db.internal", 2222, &key(KEY_A));
        let expect = Some(("ssh-ed25519".to_owned(), a.fingerprint));
        assert_eq!(kh.pinned("db.internal", 2222), expect);
        assert_eq!(kh.pinned("db.internal", 22), None);
        assert_eq!(kh.recorded("db.internal", 2222, &openssh, 2), expect);
        assert_eq!(kh.recorded("db.internal", 2222, &openssh, 1), None);
    }

    #[test]
    fn fingerprint_matches_openssh() {
        let info = HostKeyInfo::new("h", 22, &key(KEY_A));
        assert_eq!(
            info.fingerprint,
            "SHA256:cS8T+87q/3OOXl3+m1vOyYgIbZg5M0XGFpdH+32DQwg"
        );
        assert_eq!(info.algorithm, "ssh-ed25519");
    }
}
