//! Plaintext item schema (`schema_version` 1). Only ever exists in memory, never on disk.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
// Hosts are the largest; items are handled one at a time, never in arrays that their size
// would weigh on, and boxing them would put a `Box` in every match on a host.
#[allow(clippy::large_enum_variant)]
pub enum ItemData {
    Host(Host),
    SshKey(SshKey),
    Snippet(Snippet),
    PortForward(PortForward),
    Vpn(VpnProfile),
    /// Only in an organization's directory vault.
    MemberKey(MemberKey),
    TerminalTheme(TerminalTheme),
    SessionLog(SessionLog),
    Attachment(Attachment),
    Identity(Identity),
    HostGroup(HostGroup),
    CloudSource(CloudSource),
    HostCa(HostCa),
    /// A kind this version doesn't know (a newer app wrote it): kept and synced as it is, left
    /// out of listings, never edited.
    #[serde(other)]
    Unknown,
}

impl ItemData {
    /// Blobs (by hash) the item refers to; the rest of a vault's blobs are unreferenced.
    pub fn blob_refs(&self) -> Vec<&str> {
        match self {
            ItemData::SessionLog(l) => l.chunks.iter().map(|c| c.hash.as_str()).collect(),
            ItemData::Attachment(a) => vec![a.blob.as_str()],
            _ => Vec::new(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ItemData::Host(_) => "host",
            ItemData::SshKey(_) => "ssh_key",
            ItemData::Snippet(_) => "snippet",
            ItemData::PortForward(_) => "port_forward",
            ItemData::Vpn(_) => "vpn",
            ItemData::MemberKey(_) => "member_key",
            ItemData::TerminalTheme(_) => "terminal_theme",
            ItemData::SessionLog(_) => "session_log",
            ItemData::Attachment(_) => "attachment",
            ItemData::Identity(_) => "identity",
            ItemData::HostGroup(_) => "host_group",
            ItemData::CloudSource(_) => "cloud_source",
            ItemData::HostCa(_) => "host_ca",
            ItemData::Unknown => "unknown",
        }
    }
}

/// Terminal colors, imported from another terminal's theme file or made in the app. Colors are
/// `#rrggbb`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TerminalTheme {
    pub name: String,
    pub background: String,
    pub foreground: String,
    pub cursor: String,
    /// The character under a block cursor.
    pub cursor_accent: String,
    pub selection_background: String,
    /// `None` keeps the text's own colors in a selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_foreground: Option<String>,
    /// The 16 ANSI colors: black, red, green, yellow, blue, magenta, cyan, white, then the same
    /// eight bright.
    pub ansi: Vec<String>,
}

impl TerminalTheme {
    /// Prefix of the themes built into the app, as `theme_ref` names them.
    pub const BUILTIN: &'static str = "builtin:";

    /// Every color, for checks.
    pub fn colors(&self) -> impl Iterator<Item = &str> {
        [
            &self.background,
            &self.foreground,
            &self.cursor,
            &self.cursor_accent,
            &self.selection_background,
        ]
        .into_iter()
        .chain(self.selection_foreground.as_ref())
        .chain(&self.ansi)
        .map(String::as_str)
    }
}

/// `#rrggbb`.
pub fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// An SSH public key a member uses on the organization's hosts, published so that offboarding can
/// find it in `authorized_keys`. Valid only with the member's own signature
/// (`mg_vault::sharing::sign_member_key`): anyone with write on the directory can store an entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberKey {
    pub account_id: String,
    /// OpenSSH `type base64`, without a comment.
    pub public_key: String,
    pub label: String,
    /// The member's signature, hex.
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub auth: HostAuth,
    /// Host item to tunnel through (OpenSSH `ProxyJump`); it may itself have a jump host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_ref: Option<String>,
    /// VPN profile the connection's first hop runs through (only used when this host is dialed
    /// directly, i.e. it is the target with no jump host, or the first jump host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_ref: Option<String>,
    /// The terminal's colors for this host instead of the device's choice: a `terminal_theme`
    /// item in the same vault, or a theme built into the app (`builtin:<id>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme_ref: Option<String>,
    /// Record its sessions into the vault (`session_log` items and blobs).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record_sessions: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    /// The group it belongs to (a `host_group` item in the same vault): what the host leaves
    /// empty (jump host, VPN, theme, and credentials when `user` is empty) comes from there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_ref: Option<String>,
    /// Shared credentials (an `identity` item in the same vault) instead of `user` and `auth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_ref: Option<String>,
    /// Attach to a tmux session on the server, created when missing, so a dropped connection, a
    /// restart or another device picks up where it was.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_session: bool,
    /// Forward the SSH agent to it (OpenSSH `ForwardAgent`): programs on the host can sign with
    /// the agent's keys while a session is open. Off unless set: only for hosts trusted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forward_agent: bool,
    /// Run at login, with a terminal, instead of the login shell (`ssh -t host <command>`): a
    /// platform's forced command that takes the environment's name, `tmux attach`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_command: Option<String>,
    /// How its jump host carries it: a command the jump host runs, whose stdin and stdout carry
    /// this host's SSH (`nc %h %p`, Vallic's `<env> jump <machine>`), instead of a forwarded TCP
    /// connection. `%h`, `%p` and `%r` are this host's address, port and user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_command: Option<String>,
    /// A command run on the device connecting, whose stdin and stdout are the connection to
    /// this host (OpenSSH's `ProxyCommand`; `%h`, `%p`, `%r`), when it's the first hop. A device
    /// runs it only once it has allowed it (a shared vault mustn't hand out commands to run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_command: Option<String>,
    /// The cloud source that keeps it in step with a provider, if one does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Box<HostSource>>,
}

/// Where a host a cloud source keeps came from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostSource {
    /// The `cloud_source` item, in the same vault.
    pub source_ref: String,
    /// The provider's id for it (`env:12/web-2`): what a refresh matches on.
    pub external_id: String,
    /// The label the provider gave it: a host still called that follows the provider's renames;
    /// one renamed in MorphGate keeps its name.
    #[serde(default)]
    pub label: String,
    /// The provider no longer lists it (kept, not deleted).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gone: bool,
    /// The provider's hosts offer no SFTP, or no port and agent forwarding.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_sftp: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_forwarding: bool,
    /// The machine's state where it isn't running (`stopped`, `VM deallocated`): it keeps its
    /// last address meanwhile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// How it's reached when its source goes through the cloud rather than an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<CloudReach>,
    /// The server's host keys as its feed gives them (`ssh-ed25519 AAAA…`): trusted when
    /// connecting to this host, without asking; a server with another key is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_keys: Vec<String>,
    /// The tags its feed gave it, among the host's: a refresh replaces these and keeps the
    /// person's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Where a snippet a feed keeps came from: the feed decides it (it's read-only in the app).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnippetSource {
    /// The `cloud_source` item, in the same vault.
    pub source_ref: String,
    /// `feed:<id>`: what a refresh matches on.
    pub external_id: String,
}

/// A machine reached through its cloud: what the command needs, never the command itself (a vault
/// mustn't hand out commands to run). The app builds it, with these checked against what the
/// cloud's ids look like ([`CloudReach::check`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CloudReach {
    /// `aws-ssm` (Session Manager), `aws-eice` (an EC2 Instance Connect Endpoint) or `gcp-iap`.
    pub kind: String,
    /// The EC2 instance id, or the Compute Engine instance's name.
    pub instance: String,
    /// The AWS region, or the Compute Engine zone.
    pub place: String,
    /// Google Cloud's project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

/// `s` is made of `ok` characters only, and not empty.
fn made_of(s: &str, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.chars().all(ok)
}

impl CloudReach {
    pub const KINDS: [&'static str; 3] = ["aws-ssm", "aws-eice", "gcp-iap"];

    /// Refuses what isn't shaped like the cloud's ids: they go into a command.
    pub fn check(&self) -> Result<(), String> {
        let lower = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        let ok = match self.kind.as_str() {
            "aws-ssm" | "aws-eice" => {
                self.instance.starts_with("i-")
                    && made_of(&self.instance[2..], |c| c.is_ascii_hexdigit())
                    && made_of(&self.place, lower)
                    && self.project.is_none()
            }
            "gcp-iap" => {
                made_of(&self.instance, lower)
                    && made_of(&self.place, lower)
                    && self
                        .project
                        .as_deref()
                        .is_some_and(|p| made_of(p, |c| lower(c) || c == '.' || c == ':'))
            }
            _ => return Err(format!("{}: not a way to reach a machine", self.kind)),
        };
        if ok {
            Ok(())
        } else {
            Err(format!(
                "{} {} in {}: not an id this cloud gives",
                self.kind, self.instance, self.place
            ))
        }
    }
}

/// Hosts kept in step with a cloud provider (docs/features/cloud-sources.md): Vallic Cloud, AWS, Google
/// Cloud, Azure, Hetzner Cloud or DigitalOcean, or a feed. No cloud credentials: each device signs in
/// to Vallic itself and keeps that on the device; the others are listed with their CLI as the device
/// has it set up. A feed's token is the exception: it only reads a host list, and every device that
/// refreshes needs it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CloudSource {
    pub label: String,
    /// `vallic`, `aws`, `gcp`, `azure`, `hetzner`, `digitalocean` or `feed`.
    pub provider: String,
    /// The provider's address, when not its usual one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The key its hosts sign in with (an `ssh_key` in the same vault); none: the SSH agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    /// Who signed in when it was made (`ana@example.com`), to tell sources apart.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account: String,
    /// When its hosts last came from the provider (unix seconds), on any device.
    #[serde(default)]
    pub refreshed_at: i64,
    /// AWS: the CLI's profile; Hetzner Cloud and DigitalOcean: the CLI's context. None for its
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The regions (AWS), projects (Google Cloud) or subscription ids (Azure) it lists; empty:
    /// every one the sign-in sees.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// How a machine is reached: `public` (none means it too: its public address; one without
    /// is left out) or `private` (its private address, through `jump_ref`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<String>,
    /// The jump host `private` goes through (a host in the same vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_ref: Option<String>,
    /// Who to log in as where a machine doesn't say (AWS doesn't).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Groups its hosts by this tag's (or label's) value instead of the region, project or
    /// resource group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_tag: Option<String>,
    /// A feed's address (`https://`, or `http://` on the device itself).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The token a feed is read with (`Authorization: Bearer`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl CloudSource {
    /// The same source, but for when it was last refreshed: what two devices refreshing at once
    /// differ in.
    pub fn same_but_refreshed(&self, other: &CloudSource) -> bool {
        CloudSource {
            refreshed_at: other.refreshed_at,
            ..self.clone()
        } == *other
    }
}

impl Host {
    /// The host out of `group` (its own id is `id`), connecting as before: what it took from the
    /// group becomes its own.
    pub fn without_group(self, id: &str, group: &HostGroup) -> Host {
        let identity_ref = self.identity_ref.or_else(|| {
            group
                .identity_ref
                .clone()
                .filter(|_| self.user.trim().is_empty())
        });
        let jump_ref = self
            .jump_ref
            .or_else(|| group.jump_ref.clone().filter(|j| j != id));
        Host {
            group_ref: None,
            identity_ref,
            jump_ref,
            vpn_ref: self.vpn_ref.or_else(|| group.vpn_ref.clone()),
            theme_ref: self.theme_ref.or_else(|| group.theme_ref.clone()),
            keep_session: self.keep_session || group.keep_session,
            ..self
        }
    }
}

/// Credentials several hosts share: a user and how to sign in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub label: String,
    pub user: String,
    pub auth: HostAuth,
}

/// Hosts that belong together, and what they have in common: each host takes what it leaves
/// empty from its group.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HostGroup {
    pub name: String,
    /// Credentials for the group's hosts that have none of their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme_ref: Option<String>,
    /// Every host in the group keeps its session on the server (tmux).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_session: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostAuth {
    /// `None` = ask every time.
    Password {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    /// `key_ref` is the id of an `ssh_key` item.
    Key { key_ref: String },
    /// Keys from an SSH agent. `agent` names which: `None` is the system's (`SSH_AUTH_SOCK`, or
    /// OpenSSH's pipe on Windows); `1password`, `bitwarden`, `secretive`, `pageant`, or `custom`
    /// with `path` (a socket or pipe on this device). `key` offers only that key (`SHA256:…`),
    /// as OpenSSH's `IdentitiesOnly`; `None` offers every key the agent holds. Apps that predate
    /// these fields read it as the system's agent.
    Agent {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
}

impl HostAuth {
    /// The system's agent, every key it holds.
    pub fn system_agent() -> HostAuth {
        HostAuth::Agent {
            agent: None,
            path: None,
            key: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SshKey {
    pub label: String,
    /// OpenSSH or PEM private key, exactly as imported (may itself be encrypted).
    pub private_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    pub public_key: String,
    pub algorithm: String,
    pub fingerprint: String,
    /// An OpenSSH user certificate for this key (`…-cert-v01@openssh.com AAAA…`), presented
    /// when signing in. Public, like the public key; apps that predate it sign in with the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// How its short-lived certificate is renewed before it runs out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renew: Option<CertRenewal>,
}

/// Renewing a key's certificate: a command run on the device connecting (once that device has
/// allowed it, as a proxy command), given the public key on stdin and as a file (`%k`), that
/// prints the new certificate (`vault write -field=signed_key ssh/sign/<role> public_key=-`,
/// `step ssh certificate --sign …`, `ssh-keygen -s …`), or writes it to `file`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertRenewal {
    pub command: String,
    /// Where the command leaves the certificate, when it doesn't print it (`~` is the home).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// A host CA (OpenSSH's `@cert-authority`): a host key it signed is trusted for the hosts its
/// patterns match, without pinning. In a team's vault, for every member.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostCa {
    pub label: String,
    /// The CA's public key, `ssh-ed25519 AAAA…`.
    pub public_key: String,
    /// OpenSSH host patterns: `*.example.com`, `10.0.*`, `!bastion.example.com`. A bare pattern
    /// matches the host on any port.
    pub hosts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snippet {
    pub name: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The feed that keeps it, if one does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SnippetSource>,
}

/// A saved tunnel through `host_ref`, started on demand.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortForward {
    pub label: String,
    pub host_ref: String,
    pub rule: ForwardRule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ForwardRule {
    /// `ssh -L bind_host:bind_port:target_host:target_port`
    Local {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    /// `ssh -R bind_host:bind_port:target_host:target_port` (bind is on the server)
    Remote {
        bind_host: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },
    /// `ssh -D bind_host:bind_port` (SOCKS5)
    Dynamic { bind_host: String, bind_port: u16 },
}

/// A VPN a host can be reached through. Lives in the vault, so it syncs like everything else.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VpnProfile {
    pub label: String,
    pub vpn: VpnKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VpnKind {
    /// A `wg-quick` style config, run in-process (userspace, no root).
    Wireguard { config: String },
    /// An `.ovpn` client profile with every referenced file embedded, run in-process.
    Openvpn {
        config: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        /// `None` = ask when connecting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    /// A server reached through the `openconnect` program (AnyConnect, GlobalProtect, …).
    Openconnect {
        /// Host or URL, possibly with a group path.
        server: String,
        /// openconnect `--protocol` (`anyconnect`, `gp`, `fortinet`, …).
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authgroup: Option<String>,
        /// `pin-sha256:…` of a server certificate the user chose to trust.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_cert: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub id: String,
    /// The vault it lives in: the personal vault or a shared one.
    pub vault_id: String,
    /// Unix milliseconds of the last local change.
    pub updated_at: i64,
    pub data: ItemData,
}

/// A recorded terminal session: an asciicast v2 recording, deflated and sealed into blobs of
/// kind `session_log` in the same vault. Concatenated, the chunks' plaintexts are the `.cast`
/// file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionLog {
    /// The saved host it recorded (an item in the same vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ref: Option<String>,
    /// What the session was called: the host's label, or `user@host`.
    pub title: String,
    /// `user@host:port`, as connected.
    pub address: String,
    /// Unix ms.
    pub started_at: i64,
    /// Unix ms; absent while recording (or when the recorder stopped without saying).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    pub cols: u16,
    pub rows: u16,
    /// In order.
    #[serde(default)]
    pub chunks: Vec<LogChunk>,
    /// Bytes the session printed.
    #[serde(default)]
    pub output_bytes: u64,
    /// The device that recorded it.
    pub device: String,
}

/// A file kept in the vault with a host (a certificate, a runbook, a VPN profile's notes): sealed
/// into one blob of kind `attachment` in the same vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// The file's name, as added.
    pub name: String,
    /// The host it belongs to (an item in the same vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ref: Option<String>,
    /// The blob's name: hex SHA-256 of its bytes.
    pub blob: String,
    /// The file's size, in bytes.
    pub size: u64,
}

/// The largest file an attachment holds (sealed, it stays under servers' 25 MiB blob limit).
pub const MAX_ATTACHMENT_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogChunk {
    /// The blob's name: hex SHA-256 of its bytes.
    pub hash: String,
    /// The blob's size.
    pub size: u64,
}

#[cfg(test)]
mod reach_tests {
    use super::CloudReach;

    fn reach(kind: &str, instance: &str, place: &str, project: Option<&str>) -> CloudReach {
        CloudReach {
            kind: kind.into(),
            instance: instance.into(),
            place: place.into(),
            project: project.map(str::to_owned),
        }
    }

    #[test]
    fn only_what_the_clouds_ids_look_like() {
        assert!(
            reach("aws-ssm", "i-0abc123def4567890", "eu-central-1", None)
                .check()
                .is_ok()
        );
        assert!(
            reach("aws-eice", "i-0abc", "us-east-1", None)
                .check()
                .is_ok()
        );
        assert!(
            reach("gcp-iap", "web-1", "europe-west1-b", Some("shop-prod"))
                .check()
                .is_ok()
        );
        assert!(
            reach(
                "gcp-iap",
                "web-1",
                "europe-west1-b",
                Some("example.com:shop")
            )
            .check()
            .is_ok()
        );
        // Anything that could be read as more than an id is refused.
        assert!(
            reach("aws-ssm", "i-0abc; rm -rf ~", "eu-central-1", None)
                .check()
                .is_err()
        );
        assert!(
            reach("aws-ssm", "i-0abc", "eu-central-1 --profile x", None)
                .check()
                .is_err()
        );
        assert!(
            reach("aws-ssm", "web-1", "eu-central-1", None)
                .check()
                .is_err()
        );
        assert!(
            reach("gcp-iap", "web-1", "europe-west1-b", None)
                .check()
                .is_err()
        );
        assert!(
            reach("gcp-iap", "$(id)", "europe-west1-b", Some("p"))
                .check()
                .is_err()
        );
        assert!(
            reach("ssh-anything", "i-0abc", "eu-central-1", None)
                .check()
                .is_err()
        );
    }
}
