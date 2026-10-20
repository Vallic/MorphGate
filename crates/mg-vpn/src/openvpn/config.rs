//! `.ovpn` client profiles: the options that matter to an in-app client. Host-level options
//! (OS routes, scripts, `user`/`group`, device names, …) are ignored on purpose: nothing is
//! configured on the system.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::{IpNet, VpnError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" | "udp4" | "udp6" => Some(Self::Udp),
            "tcp" | "tcp4" | "tcp6" | "tcp-client" | "tcp4-client" | "tcp6-client" => {
                Some(Self::Tcp)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub proto: Proto,
}

impl fmt::Display for Remote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.proto {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        };
        if self.host.contains(':') {
            write!(f, "[{}]:{}/{proto}", self.host, self.port)
        } else {
            write!(f, "{}:{}/{proto}", self.host, self.port)
        }
    }
}

/// Data channel ciphers MorphGate speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc,
    Aes256Cbc,
}

impl Cipher {
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "AES-128-GCM" => Some(Self::Aes128Gcm),
            "AES-256-GCM" => Some(Self::Aes256Gcm),
            "CHACHA20-POLY1305" => Some(Self::ChaCha20Poly1305),
            "AES-128-CBC" => Some(Self::Aes128Cbc),
            "AES-256-CBC" => Some(Self::Aes256Cbc),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::ChaCha20Poly1305 => "CHACHA20-POLY1305",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
        }
    }

    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305
        )
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Cbc => 16,
            _ => 32,
        }
    }
}

/// `auth`: the HMAC digest for `tls-auth` and CBC data packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA384" => Some(Self::Sha384),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Output (and key) size in bytes.
    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub(crate) fn hmac(self) -> aws_lc_rs::hmac::Algorithm {
        use aws_lc_rs::hmac;
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// A 2048-bit OpenVPN static key (`tls-auth` / `tls-crypt`).
#[derive(Clone)]
pub struct StaticKey(Zeroizing<[u8; 256]>);

impl StaticKey {
    pub fn parse(text: &str) -> Result<Self, VpnError> {
        let bad = || VpnError::Config("invalid OpenVPN static key (tls-auth / tls-crypt)".into());
        let body = text
            .split_once("-----BEGIN OpenVPN Static key V1-----")
            .and_then(|(_, rest)| rest.split_once("-----END OpenVPN Static key V1-----"))
            .map(|(b, _)| b)
            .ok_or_else(bad)?;
        let hex: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        if hex.len() != 512 {
            return Err(bad());
        }
        let mut key = Zeroizing::new([0u8; 256]);
        for (i, pair) in hex.chunks(2).enumerate() {
            let s = std::str::from_utf8(pair).map_err(|_| bad())?;
            key[i] = u8::from_str_radix(s, 16).map_err(|_| bad())?;
        }
        Ok(Self(key))
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut key = Zeroizing::new([0u8; 256]);
        key.copy_from_slice(bytes.get(..256)?);
        Some(Self(key))
    }

    /// Key `n` (0 or 1) of the pair: 64 cipher bytes then 64 HMAC bytes.
    pub(crate) fn cipher(&self, n: usize) -> &[u8] {
        &self.0[n * 128..n * 128 + 64]
    }

    pub(crate) fn hmac(&self, n: usize) -> &[u8] {
        &self.0[n * 128 + 64..n * 128 + 128]
    }
}

impl fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaticKey(…)")
    }
}

/// Longest wrapped client key OpenVPN accepts (`TLS_CRYPT_V2_MAX_WKC_LEN`).
const MAX_WKC: usize = 1024;
/// Tag, an encrypted 2048-bit key, and the length field: the shortest possible wrapped key.
const MIN_WKC: usize = 32 + 256 + 2;

/// A tls-crypt-v2 client key: the client's own tls-crypt key `Kc`, and `WKc`, the same key
/// wrapped (encrypted and authenticated) with the server's key. The client sends `WKc` along
/// with its first packets, so the server learns `Kc` without keeping a list of clients.
#[derive(Clone)]
pub struct TlsCryptV2Key {
    pub(crate) key: StaticKey,
    pub(crate) wrapped: Vec<u8>,
}

impl TlsCryptV2Key {
    /// The `-----BEGIN OpenVPN tls-crypt-v2 client key-----` PEM `openvpn --genkey
    /// tls-crypt-v2-client` writes: base64 of `Kc || WKc`.
    pub fn parse(text: &str) -> Result<Self, VpnError> {
        if text.contains("tls-crypt-v2 server key") {
            return Err(VpnError::Config(
                "this is the server's tls-crypt-v2 key; the profile needs a client key made from \
                 it (openvpn --tls-crypt-v2 server.key --genkey tls-crypt-v2-client client.key)"
                    .into(),
            ));
        }
        let bad = || VpnError::Config("invalid tls-crypt-v2 client key".into());
        let body = text
            .split_once("-----BEGIN OpenVPN tls-crypt-v2 client key-----")
            .and_then(|(_, rest)| rest.split_once("-----END OpenVPN tls-crypt-v2 client key-----"))
            .map(|(b, _)| b)
            .ok_or_else(bad)?;
        let b64: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let raw = Zeroizing::new(STANDARD.decode(b64).map_err(|_| bad())?);
        let wrapped = raw.get(256..).ok_or_else(bad)?;
        // WKc ends with its own length (big endian), which must match.
        let declared = wrapped
            .last_chunk::<2>()
            .map(|l| usize::from(u16::from_be_bytes(*l)));
        if !(MIN_WKC..=MAX_WKC).contains(&wrapped.len()) || declared != Some(wrapped.len()) {
            return Err(bad());
        }
        Ok(Self {
            key: StaticKey::from_bytes(&raw[..256]).ok_or_else(bad)?,
            wrapped: wrapped.to_vec(),
        })
    }
}

impl fmt::Debug for TlsCryptV2Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsCryptV2Key(…)")
    }
}

#[derive(Clone, Debug)]
pub enum TlsWrap {
    /// `tls-auth`: HMAC on every control packet. `direction` is `key-direction`.
    Auth {
        key: StaticKey,
        direction: Option<u8>,
    },
    /// `tls-crypt`: control packets encrypted and authenticated.
    Crypt(StaticKey),
    /// `tls-crypt-v2`: like tls-crypt, with a key of this client's own.
    CryptV2(TlsCryptV2Key),
}

impl TlsWrap {
    /// The option's name, for display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Auth { .. } => "tls-auth",
            Self::Crypt(_) => "tls-crypt",
            Self::CryptV2(_) => "tls-crypt-v2",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameType {
    /// The whole subject (`C=US, O=Acme, CN=vpn`).
    Subject,
    /// The common name.
    Name,
    NamePrefix,
}

/// Compression framing. MorphGate never compresses what it sends; it only speaks the framing
/// and decompresses what a server compresses anyway.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compress {
    #[default]
    None,
    /// `comp-lzo no`: one `0xFA` byte in front of every packet.
    LzoStub,
    /// `comp-lzo [yes|adaptive]`, `compress lzo`.
    Lzo,
    /// `compress` / `compress stub`: the "swap" framing.
    Stub,
    /// `compress stub-v2`.
    StubV2,
    /// `compress lz4` (swap framing).
    Lz4,
    /// `compress lz4-v2`.
    Lz4V2,
}

impl Compress {
    pub(crate) fn from_compress(arg: Option<&str>) -> Option<Self> {
        Some(match arg.map(str::to_ascii_lowercase).as_deref() {
            None | Some("stub") => Self::Stub,
            Some("stub-v2") => Self::StubV2,
            Some("lzo") => Self::Lzo,
            Some("lz4") => Self::Lz4,
            Some("lz4-v2") => Self::Lz4V2,
            // `migrate` means "no compression unless the server says otherwise".
            Some("migrate") => Self::None,
            _ => return None,
        })
    }

    pub(crate) fn from_comp_lzo(arg: Option<&str>) -> Option<Self> {
        Some(match arg.map(str::to_ascii_lowercase).as_deref() {
            None | Some("yes") | Some("adaptive") => Self::Lzo,
            Some("no") => Self::LzoStub,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StaticChallenge {
    pub text: String,
    pub echo: bool,
    /// `concat`: the response is appended to the password instead of the `SCRV1` format.
    pub concat: bool,
}

/// A parsed client profile. Build with [`Config::parse`]; embed referenced files first with
/// [`inline_files`].
#[derive(Clone)]
pub struct Config {
    pub remotes: Vec<Remote>,
    pub remote_random: bool,
    /// CA certificate(s), PEM. May be empty when `peer-fingerprint` pins the server instead.
    pub ca: String,
    /// `peer-fingerprint` SHA-256 pins of the server certificate.
    pub peer_fingerprints: Vec<[u8; 32]>,
    /// Client certificate chain, PEM (`cert` + `extra-certs`).
    pub cert: Option<String>,
    /// Client key, PEM; possibly encrypted (see [`Config::needs_passphrase`]).
    pub key: Option<Zeroizing<String>>,
    /// A PKCS#12 bundle (DER) with the client certificate and key, and usually the CA.
    pub pkcs12: Option<Zeroizing<Vec<u8>>>,
    /// The key's or bundle's passphrase, from an inline `<askpass>` block.
    pub askpass: Option<Zeroizing<String>>,
    pub tls_wrap: Option<TlsWrap>,
    pub auth: Digest,
    /// Offered data ciphers, preferred first (`data-ciphers`).
    pub data_ciphers: Vec<Cipher>,
    /// Used when the server doesn't negotiate (`data-ciphers-fallback`, or the old `cipher`).
    pub fallback_cipher: Option<Cipher>,
    pub auth_user_pass: bool,
    /// From an inline `<auth-user-pass>` block.
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub static_challenge: Option<StaticChallenge>,
    pub verify_x509_name: Option<(String, NameType)>,
    pub compress: Compress,
    pub tun_mtu: u16,
    pub ping: Option<u32>,
    pub ping_restart: Option<u32>,
    pub route_nopull: bool,
    pub dns: Vec<IpAddr>,
    pub domains: Vec<String>,
    pub routes: Vec<IpNet>,
    /// How long TLS + authentication may take once the server answered.
    pub hand_window: Duration,
    /// How long to wait for the first answer from each server.
    pub server_poll_timeout: Duration,
    /// Offer RFC 5705 key derivation (tls-ekm). Off only to test the legacy PRF.
    pub(crate) ekm: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("remotes", &self.remotes)
            .field("data_ciphers", &self.data_ciphers)
            .field("tls_wrap", &self.tls_wrap.as_ref().map(TlsWrap::name))
            .field("client_cert", &self.cert.is_some())
            .field("auth_user_pass", &self.auth_user_pass)
            .field("compress", &self.compress)
            .finish_non_exhaustive()
    }
}

/// Directives that take a file (or an inline block).
const FILE_OPTIONS: &[&str] = &[
    "ca",
    "cert",
    "key",
    "extra-certs",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "auth-user-pass",
    "askpass",
    "pkcs12",
    "secret",
    "crl-verify",
];

/// Base64 in 64-character lines, as `<pkcs12>` blocks hold their binary bundle.
fn base64_lines(bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(bytes);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
        .collect();
    lines.join("\n")
}

struct Directive {
    name: String,
    args: Vec<String>,
    /// Content of an inline `<name>…</name>` block.
    inline: Option<String>,
    /// Directives inside a `<connection>` block.
    nested: Vec<Directive>,
    line: usize,
}

fn config_err(line: usize, msg: impl fmt::Display) -> VpnError {
    VpnError::Config(format!("line {line}: {msg}"))
}

/// Splits one line like OpenVPN does: whitespace-separated, `"…"` with backslash escapes,
/// `'…'` literal, and `#` / `;` starting a comment at the beginning of a token.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&c) = chars.peek() else { break };
        if c == '#' || c == ';' {
            break;
        }
        let mut tok = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                break;
            }
            chars.next();
            match c {
                '"' => loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e) => tok.push(e),
                            None => return Err("unterminated escape".into()),
                        },
                        Some(ch) => tok.push(ch),
                        None => return Err("unterminated quote".into()),
                    }
                },
                '\'' => loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => tok.push(ch),
                        None => return Err("unterminated quote".into()),
                    }
                },
                '\\' => match chars.next() {
                    Some(e) => tok.push(e),
                    None => return Err("unterminated escape".into()),
                },
                _ => tok.push(c),
            }
        }
        out.push(tok);
    }
    Ok(out)
}

fn read_directives(text: &str, first_line: usize) -> Result<Vec<Directive>, VpnError> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let n = first_line + i;
        let trimmed = lines[i].trim();
        i += 1;
        if let Some(name) = trimmed
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .filter(|s| !s.starts_with('/') && !s.contains(char::is_whitespace))
        {
            let name = name.to_ascii_lowercase();
            let close = format!("</{name}>");
            let start = i;
            while i < lines.len() && !lines[i].trim().eq_ignore_ascii_case(&close) {
                i += 1;
            }
            if i == lines.len() {
                return Err(config_err(n, format!("<{name}> is never closed")));
            }
            let body = lines[start..i].join("\n");
            i += 1;
            if name == "connection" {
                out.push(Directive {
                    name,
                    args: vec![],
                    inline: None,
                    nested: read_directives(&body, n + 1)?,
                    line: n,
                });
            } else {
                out.push(Directive {
                    name,
                    args: vec![],
                    inline: Some(body),
                    nested: vec![],
                    line: n,
                });
            }
            continue;
        }
        let mut tokens = tokenize(trimmed).map_err(|e| config_err(n, e))?;
        if tokens.is_empty() {
            continue;
        }
        let name = tokens.remove(0);
        let name = name.trim_start_matches("--").to_ascii_lowercase();
        out.push(Directive {
            name,
            args: tokens,
            inline: None,
            nested: vec![],
            line: n,
        });
    }
    Ok(out)
}

/// Embeds the files a profile refers to (`ca ca.crt`, `tls-auth ta.key 1`, …) as inline blocks,
/// resolving relative paths against `dir`, so the profile can be stored on its own.
pub fn inline_files(text: &str, dir: &Path) -> Result<String, VpnError> {
    inline_files_with(text, |file| {
        let path = dir.join(file);
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    })
}

/// [`inline_files`] with each file's bytes from `read`, given the name the profile uses (files
/// picked along with it, say). An error from `read` says what's missing; the directive is added.
pub fn inline_files_with(
    text: &str,
    read: impl Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<String, VpnError> {
    let mut out = String::with_capacity(text.len() + 4096);
    let mut block: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(close) = &block {
            if trimmed.eq_ignore_ascii_case(close) {
                block = None;
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .filter(|s| !s.starts_with('/'))
            && name != "connection"
        {
            block = Some(format!("</{name}>"));
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let tokens = tokenize(trimmed).map_err(|e| config_err(i + 1, e))?;
        let name = tokens
            .first()
            .map(|t| t.trim_start_matches("--").to_ascii_lowercase());
        let file = tokens
            .get(1)
            .filter(|f| !f.eq_ignore_ascii_case("[inline]"));
        match (name.as_deref(), file) {
            (Some(name), Some(file)) if FILE_OPTIONS.contains(&name) => {
                let bytes = read(file).map_err(|e| VpnError::Config(format!("{e} ({name})")))?;
                // A PKCS#12 bundle is binary; inline, OpenVPN wants it base64.
                let content = if name == "pkcs12" {
                    base64_lines(&bytes)
                } else {
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                if name == "tls-auth"
                    && let Some(dir) = tokens.get(2)
                {
                    out.push_str(&format!("key-direction {dir}\n"));
                }
                out.push_str(&format!("<{name}>\n{}\n</{name}>\n", content.trim_end()));
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Ok(out)
}

#[derive(Default)]
struct Builder {
    remotes: Vec<(String, Option<u16>, Option<Proto>)>,
    port: Option<u16>,
    proto: Option<Proto>,
    remote_random: bool,
    ca: Option<String>,
    peer_fingerprints: Vec<[u8; 32]>,
    cert: Option<String>,
    extra_certs: Option<String>,
    key: Option<Zeroizing<String>>,
    pkcs12: Option<Zeroizing<Vec<u8>>>,
    askpass: Option<Zeroizing<String>>,
    tls_auth: Option<StaticKey>,
    tls_crypt: Option<StaticKey>,
    tls_crypt_v2: Option<TlsCryptV2Key>,
    key_direction: Option<u8>,
    auth: Option<Digest>,
    data_ciphers: Option<Vec<Cipher>>,
    cipher: Option<Cipher>,
    fallback: Option<Cipher>,
    auth_user_pass: bool,
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    static_challenge: Option<StaticChallenge>,
    verify_x509_name: Option<(String, NameType)>,
    compress: Compress,
    tun_mtu: Option<u16>,
    ping: Option<u32>,
    ping_restart: Option<u32>,
    route_nopull: bool,
    dns: Vec<IpAddr>,
    domains: Vec<String>,
    routes: Vec<IpNet>,
    hand_window: Option<u64>,
    server_poll_timeout: Option<u64>,
}

fn num<T: std::str::FromStr>(d: &Directive, i: usize) -> Result<T, VpnError> {
    d.args
        .get(i)
        .and_then(|a| a.parse().ok())
        .ok_or_else(|| config_err(d.line, format!("`{}` needs a number", d.name)))
}

fn arg(d: &Directive, i: usize) -> Result<&str, VpnError> {
    d.args
        .get(i)
        .map(String::as_str)
        .ok_or_else(|| config_err(d.line, format!("`{}` is missing an argument", d.name)))
}

impl Builder {
    /// The inline block or an error explaining that files must be embedded first.
    fn content(d: &Directive) -> Result<String, VpnError> {
        match (&d.inline, d.args.first()) {
            (Some(text), _) => Ok(text.clone()),
            (None, Some(file)) if !file.eq_ignore_ascii_case("[inline]") => Err(config_err(
                d.line,
                format!(
                    "`{}` refers to the file \"{file}\"; import the .ovpn file itself (not pasted \
                     text) so MorphGate can embed it",
                    d.name
                ),
            )),
            _ => Err(config_err(d.line, format!("`{}` has no content", d.name))),
        }
    }

    fn apply(&mut self, directives: &[Directive]) -> Result<(), VpnError> {
        for d in directives {
            self.apply_one(d)?;
        }
        Ok(())
    }

    fn apply_one(&mut self, d: &Directive) -> Result<(), VpnError> {
        let unsupported = |what: &str| Err(config_err(d.line, what));
        match d.name.as_str() {
            "client" | "tls-client" | "pull" => {}
            "tls-server" | "server" | "server-bridge" => {
                return unsupported("this is a server configuration; import the client profile");
            }
            "mode" if d.args.first().is_some_and(|m| m == "server") => {
                return unsupported("this is a server configuration; import the client profile");
            }
            "dev" if d.args.first().is_some_and(|a| a.starts_with("tap")) => {
                return unsupported("TAP (layer 2) VPNs are not supported, only `dev tun`");
            }
            "dev-type" if d.args.first().is_some_and(|a| a == "tap") => {
                return unsupported("TAP (layer 2) VPNs are not supported, only `dev tun`");
            }
            "proto" => {
                self.proto = Some(
                    Proto::parse(arg(d, 0)?)
                        .ok_or_else(|| config_err(d.line, "unknown `proto`"))?,
                )
            }
            "port" | "rport" => self.port = Some(num(d, 0)?),
            "remote" => {
                let host = arg(d, 0)?.to_owned();
                let port = d.args.get(1).map(|_| num(d, 1)).transpose()?;
                let proto = match d.args.get(2) {
                    Some(p) => Some(
                        Proto::parse(p).ok_or_else(|| config_err(d.line, "unknown protocol"))?,
                    ),
                    None => None,
                };
                self.remotes.push((host, port, proto));
            }
            "remote-random" => self.remote_random = true,
            "connection" => {
                let mut sub = Builder::default();
                sub.apply(&d.nested)?;
                for (host, port, proto) in sub.remotes {
                    self.remotes
                        .push((host, port.or(sub.port), proto.or(sub.proto)));
                }
            }
            "ca" => self.ca = Some(Self::content(d)?),
            "peer-fingerprint" => {
                let text = match &d.inline {
                    Some(t) => t.clone(),
                    None => arg(d, 0)?.to_owned(),
                };
                for fp in text.split(|c: char| c.is_whitespace() || c == ',') {
                    let fp = fp.trim();
                    if fp.is_empty() || fp.starts_with('#') {
                        continue;
                    }
                    let hex: String = fp
                        .trim_start_matches("sha256:")
                        .chars()
                        .filter(|c| *c != ':')
                        .collect();
                    let bytes: Option<Vec<u8>> = (0..hex.len())
                        .step_by(2)
                        .map(|i| {
                            hex.get(i..i + 2)
                                .and_then(|h| u8::from_str_radix(h, 16).ok())
                        })
                        .collect();
                    match bytes.and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                        Some(b) => self.peer_fingerprints.push(b),
                        None => {
                            return unsupported("invalid `peer-fingerprint` (SHA-256 expected)");
                        }
                    }
                }
            }
            "cert" => self.cert = Some(Self::content(d)?),
            "extra-certs" => self.extra_certs = Some(Self::content(d)?),
            "key" => self.key = Some(Zeroizing::new(Self::content(d)?)),
            "tls-auth" => {
                self.tls_auth = Some(StaticKey::parse(&Self::content(d)?)?);
                if d.inline.is_none()
                    && let Some(dir) = d.args.get(1)
                {
                    self.key_direction = dir.parse().ok();
                }
            }
            "key-direction" => {
                self.key_direction = Some(
                    num::<u8>(d, 0)
                        .ok()
                        .filter(|k| *k <= 1)
                        .ok_or_else(|| config_err(d.line, "`key-direction` must be 0 or 1"))?,
                )
            }
            "tls-crypt" => self.tls_crypt = Some(StaticKey::parse(&Self::content(d)?)?),
            "tls-crypt-v2" => self.tls_crypt_v2 = Some(TlsCryptV2Key::parse(&Self::content(d)?)?),
            "secret" => {
                return unsupported("static-key mode (`secret`) is not supported, only TLS");
            }
            "pkcs12" => {
                let b64: String = Self::content(d)?
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                let der = STANDARD
                    .decode(b64)
                    .ok()
                    .filter(|der| der.first() == Some(&0x30))
                    .ok_or_else(|| {
                        config_err(d.line, "<pkcs12> must hold a base64 PKCS#12 bundle")
                    })?;
                self.pkcs12 = Some(Zeroizing::new(der));
            }
            // Without a value (or with a file we can't read) the passphrase is asked for.
            "askpass" => {
                if let Some(text) = &d.inline {
                    self.askpass = text
                        .lines()
                        .next()
                        .map(|p| Zeroizing::new(p.trim_end_matches('\r').to_owned()));
                }
            }
            "cryptoapicert"
            | "pkcs11-id"
            | "pkcs11-providers"
            | "management-external-key"
            | "management-external-cert" => {
                return unsupported(
                    "certificates in hardware tokens or OS stores are not supported",
                );
            }
            "http-proxy" | "socks-proxy" => {
                return unsupported("connecting through a proxy is not supported yet");
            }
            "fragment" => return unsupported("`fragment` is not supported"),
            "auth" => {
                self.auth = Some(
                    Digest::parse(arg(d, 0)?)
                        .ok_or_else(|| config_err(d.line, "unsupported `auth` digest"))?,
                )
            }
            "cipher" => self.cipher = Cipher::parse(arg(d, 0)?),
            "data-ciphers" | "ncp-ciphers" => {
                self.data_ciphers = Some(
                    arg(d, 0)?
                        .split(':')
                        .filter_map(|c| Cipher::parse(c.trim_start_matches('?')))
                        .collect(),
                )
            }
            "data-ciphers-fallback" => self.fallback = Cipher::parse(arg(d, 0)?),
            "auth-user-pass" => {
                self.auth_user_pass = true;
                match (&d.inline, d.args.first()) {
                    (Some(text), _) => {
                        let mut lines = text.lines().map(str::trim);
                        self.username = lines.next().filter(|u| !u.is_empty()).map(Into::into);
                        self.password = lines
                            .next()
                            .filter(|p| !p.is_empty())
                            .map(|p| Zeroizing::new(p.to_owned()));
                    }
                    (None, Some(_)) => {
                        Self::content(d)?;
                    }
                    (None, None) => {}
                }
            }
            "static-challenge" => {
                self.static_challenge = Some(StaticChallenge {
                    text: arg(d, 0)?.to_owned(),
                    echo: d.args.get(1).is_some_and(|e| e == "1"),
                    concat: d.args.get(2).is_some_and(|f| f == "concat"),
                })
            }
            "verify-x509-name" => {
                let kind = match d.args.get(1).map(String::as_str) {
                    None | Some("subject") => NameType::Subject,
                    Some("name") => NameType::Name,
                    Some("name-prefix") => NameType::NamePrefix,
                    Some(_) => return unsupported("unknown `verify-x509-name` type"),
                };
                self.verify_x509_name = Some((arg(d, 0)?.to_owned(), kind));
            }
            "tls-version-max"
                if matches!(d.args.first().map(String::as_str), Some("1.0" | "1.1")) =>
            {
                return unsupported("TLS below 1.2 is not supported");
            }
            "comp-lzo" => {
                self.compress = Compress::from_comp_lzo(d.args.first().map(String::as_str))
                    .ok_or_else(|| config_err(d.line, "unknown `comp-lzo` mode"))?
            }
            "compress" => {
                self.compress = Compress::from_compress(d.args.first().map(String::as_str))
                    .ok_or_else(|| config_err(d.line, "unknown `compress` algorithm"))?
            }
            "tun-mtu" => self.tun_mtu = Some(num::<u16>(d, 0)?.clamp(576, 9000)),
            "keepalive" => {
                self.ping = Some(num(d, 0)?);
                self.ping_restart = Some(num(d, 1)?);
            }
            "ping" => self.ping = Some(num(d, 0)?),
            "ping-restart" => self.ping_restart = Some(num(d, 0)?),
            "route-nopull" => self.route_nopull = true,
            "route" => {
                let net = arg(d, 0)?;
                let mask = d
                    .args
                    .get(1)
                    .map(String::as_str)
                    .unwrap_or("255.255.255.255");
                if let (Ok(a), Ok(m)) = (net.parse(), mask.parse())
                    && let Some(n) = IpNet::from_netmask(a, m)
                {
                    self.routes.push(n);
                }
            }
            "dhcp-option" => match d.args.first().map(|a| a.to_ascii_uppercase()).as_deref() {
                Some("DNS" | "DNS6") => {
                    if let Ok(ip) = arg(d, 1)?.parse() {
                        self.dns.push(ip);
                    }
                }
                Some("DOMAIN" | "DOMAIN-SEARCH") => self.domains.push(arg(d, 1)?.to_owned()),
                _ => {}
            },
            "hand-window" => self.hand_window = Some(num(d, 0)?),
            "server-poll-timeout" | "connect-timeout" => {
                self.server_poll_timeout = Some(num(d, 0)?)
            }
            _ => {}
        }
        Ok(())
    }

    fn finish(self) -> Result<Config, VpnError> {
        let port = self.port.unwrap_or(1194);
        let proto = self.proto.unwrap_or(Proto::Udp);
        let remotes: Vec<Remote> = self
            .remotes
            .into_iter()
            .map(|(host, p, pr)| Remote {
                host,
                port: p.unwrap_or(port),
                proto: pr.unwrap_or(proto),
            })
            .collect();
        if remotes.is_empty() {
            return Err(VpnError::Config(
                "the profile has no `remote` server".into(),
            ));
        }
        let ca = self.ca.unwrap_or_default();
        // A PKCS#12 bundle usually brings the CA; whether it does is known once it's open.
        if ca.trim().is_empty() && self.peer_fingerprints.is_empty() && self.pkcs12.is_none() {
            return Err(VpnError::Config(
                "the profile has no CA certificate (<ca>)".into(),
            ));
        }
        let cert = match (self.cert, self.extra_certs) {
            (Some(c), Some(extra)) => Some(format!("{c}\n{extra}")),
            (c, _) => c,
        };
        if self.pkcs12.is_some() && (cert.is_some() || self.key.is_some()) {
            return Err(VpnError::Config(
                "the profile has both <pkcs12> and <cert> / <key>; it needs one or the other"
                    .into(),
            ));
        }
        if cert.is_some() != self.key.is_some() {
            return Err(VpnError::Config(
                "the profile has a client certificate without its key (or the other way round)"
                    .into(),
            ));
        }
        let tls_wrap = match (self.tls_crypt_v2, self.tls_crypt, self.tls_auth) {
            (Some(k), _, _) => Some(TlsWrap::CryptV2(k)),
            (None, Some(k), _) => Some(TlsWrap::Crypt(k)),
            (None, None, Some(key)) => Some(TlsWrap::Auth {
                key,
                direction: self.key_direction,
            }),
            (None, None, None) => None,
        };
        let mut data_ciphers = self.data_ciphers.unwrap_or_else(|| {
            vec![
                Cipher::Aes256Gcm,
                Cipher::Aes128Gcm,
                Cipher::ChaCha20Poly1305,
            ]
        });
        let fallback = self.fallback.or(self.cipher);
        if let Some(c) = fallback
            && !data_ciphers.contains(&c)
        {
            data_ciphers.push(c);
        }
        if data_ciphers.is_empty() {
            return Err(VpnError::Config(
                "none of the profile's data ciphers are supported (AES-GCM, ChaCha20-Poly1305, \
                 AES-CBC)"
                    .into(),
            ));
        }
        let cfg = Config {
            remotes,
            remote_random: self.remote_random,
            ca,
            peer_fingerprints: self.peer_fingerprints,
            cert,
            key: self.key,
            pkcs12: self.pkcs12,
            askpass: self.askpass,
            tls_wrap,
            auth: self.auth.unwrap_or(Digest::Sha1),
            data_ciphers,
            fallback_cipher: fallback,
            auth_user_pass: self.auth_user_pass,
            username: self.username,
            password: self.password,
            static_challenge: self.static_challenge,
            verify_x509_name: self.verify_x509_name,
            compress: self.compress,
            tun_mtu: self.tun_mtu.unwrap_or(1500),
            ping: self.ping,
            ping_restart: self.ping_restart,
            route_nopull: self.route_nopull,
            dns: self.dns,
            domains: self.domains,
            routes: self.routes,
            hand_window: Duration::from_secs(self.hand_window.unwrap_or(60).clamp(5, 600)),
            server_poll_timeout: Duration::from_secs(
                self.server_poll_timeout.unwrap_or(10).clamp(2, 120),
            ),
            ekm: true,
        };
        // Fail at import, not at connect, on certificates we can't use.
        super::tls::check(&cfg)?;
        Ok(cfg)
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, VpnError> {
        let mut b = Builder::default();
        b.apply(&read_directives(text, 1)?)?;
        b.finish()
    }

    /// How the client proves who it is, for display.
    pub fn auth_summary(&self) -> &'static str {
        match (
            self.cert.is_some() || self.pkcs12.is_some(),
            self.auth_user_pass,
        ) {
            (true, true) => "certificate + username/password",
            (true, false) => "certificate",
            (false, true) => "username/password",
            (false, false) => "none",
        }
    }

    /// The client key is encrypted, or in a PKCS#12 bundle: connecting needs its passphrase
    /// (from `<askpass>`, or asked; a bundle without a password opens without asking).
    pub fn needs_passphrase(&self) -> bool {
        self.pkcs12.is_some()
            || self
                .key
                .as_ref()
                .is_some_and(|k| super::keyfile::is_encrypted(k))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const STATIC_KEY: &str = "#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
423cea742242106cb2916a8a4c829756
3d22c7e5cef430b1103c6f66eb1fc5b3
75a672f158e2e2e936c3faa48b035a6d
e17beaac23b5f03b10b868d53d03521d
8ba115059da777a60cbfd7b2c9c57472
78a15b8f6e68a3ef7fd583ec9f398c8b
d4735dab40cbd1e3c62a822e97489186
c30a0b48c7c38ea32ceb056d3fa5a710
e10ccc7a0ddb363b08c3d2777a3395e1
0c0b6080f56309192ab5aacd4b45f55d
a61fc77af39bd81a19218a79762c3386
2df55785075f37d8c71dc8a42097ee43
344739a0dd48d03025b0450cf1fb5e8c
aeb893d9a96d1f15519bb3c4dcb40ee3
16672ea16c012664f8a9f11255518deb
-----END OpenVPN Static key V1-----
";

    /// `openvpn --genkey tls-crypt-v2-server srv.key` (OpenVPN 2.6.23).
    pub(crate) const TLS_CRYPT_V2_SERVER_KEY: &str = "\
-----BEGIN OpenVPN tls-crypt-v2 server key-----
dQdasRy/5Wc+TlA050QDXdmgbXq9hNhENVvQvGyuVJAYj8HvIaNicjwaHPDlHDqV
LCVBf9ZMiTks0orM9pWxFNTx5uVB9TnQlT5mTdaI3CaSghbLtlmZFJ8/Bc6lVT39
bGUdUHFwpETs8MMzuVTDg8eRreDuQOiRTJER7d5GGuc=
-----END OpenVPN tls-crypt-v2 server key-----
";

    /// `openvpn --tls-crypt-v2 srv.key --genkey tls-crypt-v2-client cli.key`, from the server
    /// key above (with the default timestamp metadata).
    pub(crate) const TLS_CRYPT_V2_CLIENT_KEY: &str = "\
-----BEGIN OpenVPN tls-crypt-v2 client key-----
gK6jGQBLYguJ8KZvBg9G853F4qsWdDn0WzNfqV8EzpE9HB7Ub0nYIt4Xpn/aR4EI
pzhhV6tbuPmH1xF7EXu/0KEOaec0vKSEPanbqFCNf+AU56Xh5PrAJp7dhSVeVLZd
qUuAI+Gf0eXQOuB0HCnVNyYtctbDMjtB85amZfFHBWyER04ekziYhDiQUt3AwN/9
pC/o9vviEmGGo4C5nVL98YxnTsn3nko59+SGq/qCfYNN0PScGK8RCn14xIWvXM2u
hm4eKrOA8RI7LQpkWCNCVqtaQi6Ed9adp/2CTzDWyXvbwoTFodLvdvQMC8uC/VHF
CBF4c5nN7LWt8SvtM24IujgVceEfmBgRSyORDJh43QYveuXJLgJhgej61Io9s7v/
3/u/4G4URWnCIIoKeUgJvPxX7b45BXVfURMoYHyBDapT+7xnm4yq3OkU+P1uuzod
wfQWqbS0eSc9Jf5/tDNbbO5uzXM0Ej2cfiGfJudmfw81Gln671DZMw/DBdeC7BAo
BKh5x4E7foqxEMpCWGKSgQ46IAZvWvWMBb2K5oGB4VqjQZE7TQsJ+4NPrctBcUxU
L/Hi0hxI46W+0lKvPyDvhNwsVetavL1xdIQbFuXc+s0xGiWnt75aP7synT60FJUD
oudyyOvnqcUoM68CiwXWE7ZrKzfw9Dtvpj1vrt4czZLUOWWlL5NMUM6vJkFoJIqO
7anOWxf/NgnccZtCmqXhUdG6Eq5HIrgjpgEr
-----END OpenVPN tls-crypt-v2 client key-----
";

    /// What a tls-crypt-v2 server does with `WKc` (doc/tls-crypt-v2.txt): `Ke` is the first
    /// 256 bits of the server key's key 1, `Ka` those of key 2; `WKc = T || AES-256-CTR(Ke,
    /// IV = T[..16], Kc || metadata) || len`, with `T = HMAC-SHA256(Ka, len || Kc || metadata)`.
    pub(crate) fn unwrap_wkc(server_key: &str, wkc: &[u8]) -> Option<Vec<u8>> {
        use aws_lc_rs::cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
        use aws_lc_rs::hmac;
        use aws_lc_rs::iv::FixedLength;

        let b64: String = server_key
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let raw = STANDARD.decode(b64).ok()?;
        let (ke, ka) = (&raw[..32], &raw[64..96]);
        let (tag, rest) = wkc.split_at(32);
        let (ct, len) = rest.split_at(rest.len() - 2);
        let mut plain = ct.to_vec();
        let iv: [u8; 16] = tag[..16].try_into().ok()?;
        EncryptingKey::ctr(UnboundCipherKey::new(&AES_256, ke).ok()?)
            .ok()?
            .less_safe_encrypt(&mut plain, EncryptionContext::Iv128(FixedLength::from(iv)))
            .ok()?;
        let mut signed = len.to_vec();
        signed.extend_from_slice(&plain);
        hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, ka), &signed, tag).ok()?;
        Some(plain)
    }

    fn ca() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn tokenizer_follows_openvpn_quoting() {
        assert_eq!(
            tokenize(r#"remote "my host" 1194 # comment"#).unwrap(),
            vec!["remote", "my host", "1194"]
        );
        assert_eq!(
            tokenize(r#"static-challenge 'Enter "OTP"' 1"#).unwrap(),
            vec!["static-challenge", "Enter \"OTP\"", "1"]
        );
        assert_eq!(tokenize("; all comment").unwrap(), Vec::<String>::new());
        assert_eq!(tokenize(r"x a\ b").unwrap(), vec!["x", "a b"]);
        assert!(tokenize("x \"open").is_err());
    }

    #[test]
    fn parses_a_typical_profile() {
        let text = format!(
            "client
dev tun
proto udp
remote vpn1.example.com 1194
remote vpn2.example.com 443 tcp
remote-random
resolv-retry infinite
nobind
persist-key
remote-cert-tls server
verify-x509-name \"server\" name
auth SHA256
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-128-GCM:BF-CBC
comp-lzo no
auth-user-pass
static-challenge \"Enter PIN\" 1
key-direction 1
setenv opt block-outside-dns
<ca>
{}</ca>
<tls-auth>
{STATIC_KEY}</tls-auth>
",
            ca()
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.remotes.len(), 2);
        assert_eq!(c.remotes[0].to_string(), "vpn1.example.com:1194/udp");
        assert_eq!(c.remotes[1].to_string(), "vpn2.example.com:443/tcp");
        assert!(c.remote_random);
        assert_eq!(c.auth, Digest::Sha256);
        assert_eq!(
            c.data_ciphers,
            vec![Cipher::Aes256Gcm, Cipher::Aes128Gcm, Cipher::Aes256Cbc]
        );
        assert_eq!(c.fallback_cipher, Some(Cipher::Aes256Cbc));
        assert_eq!(c.compress, Compress::LzoStub);
        assert!(c.auth_user_pass);
        assert!(c.static_challenge.as_ref().unwrap().echo);
        assert_eq!(c.verify_x509_name, Some(("server".into(), NameType::Name)));
        assert!(matches!(
            c.tls_wrap,
            Some(TlsWrap::Auth {
                direction: Some(1),
                ..
            })
        ));
        assert_eq!(c.auth_summary(), "username/password");
    }

    #[test]
    fn connection_blocks_and_defaults() {
        let text = format!(
            "client
port 1300
<connection>
remote a.example
proto tcp-client
</connection>
<connection>
remote b.example 53
</connection>
<ca>
{}</ca>
",
            ca()
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.remotes[0].to_string(), "a.example:1300/tcp");
        assert_eq!(c.remotes[1].to_string(), "b.example:53/udp");
    }

    #[test]
    fn explains_what_it_cannot_do() {
        let base = format!("client\nremote x\n<ca>\n{}</ca>\n", ca());
        let err = |extra: &str| {
            Config::parse(&format!("{base}{extra}\n"))
                .unwrap_err()
                .to_string()
        };
        assert!(err("dev tap0").contains("TAP"));
        assert!(err("ca ca.crt").contains("import the .ovpn file"));
        assert!(err("pkcs12 x.p12").contains("import the .ovpn file"));
        assert!(err("<pkcs12>\nnot base64!\n</pkcs12>").contains("base64 PKCS#12"));
        assert!(err("tls-crypt-v2 x.key").contains("tls-crypt-v2"));
        assert!(err("http-proxy p 8080").contains("proxy"));
        assert!(err("data-ciphers BF-CBC").contains("ciphers"));
        assert!(
            Config::parse("client\nremote x\n")
                .unwrap_err()
                .to_string()
                .contains("CA")
        );
        assert!(
            Config::parse(&format!("client\n<ca>\n{}</ca>\n", ca()))
                .unwrap_err()
                .to_string()
                .contains("remote")
        );
    }

    #[test]
    fn inline_files_embeds_references() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.crt"), ca()).unwrap();
        std::fs::write(dir.path().join("ta.key"), STATIC_KEY).unwrap();
        std::fs::write(dir.path().join("pass.txt"), "alice\ns3cret\n").unwrap();
        let text = "client\nremote x 1194\nca ca.crt\ntls-auth ta.key 1\nauth-user-pass pass.txt\n";
        let inlined = inline_files(text, dir.path()).unwrap();
        assert!(inlined.contains("<ca>") && inlined.contains("key-direction 1"));
        let c = Config::parse(&inlined).unwrap();
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.password.as_deref().map(String::as_str), Some("s3cret"));
        assert!(matches!(
            c.tls_wrap,
            Some(TlsWrap::Auth {
                direction: Some(1),
                ..
            })
        ));
        // Already-inline profiles pass through untouched.
        assert_eq!(inline_files(&inlined, dir.path()).unwrap(), inlined);
        assert!(inline_files("ca missing.crt\n", dir.path()).is_err());
    }

    #[test]
    fn static_key_parsing() {
        let k = StaticKey::parse(STATIC_KEY).unwrap();
        assert_eq!(k.cipher(0)[0], 0x6a);
        assert_eq!(k.hmac(1).len(), 64);
        assert!(StaticKey::parse("nope").is_err());
    }

    #[test]
    fn tls_crypt_v2_client_key_holds_kc_and_the_servers_wrapping_of_it() {
        let k = TlsCryptV2Key::parse(TLS_CRYPT_V2_CLIENT_KEY).unwrap();
        // 256 bytes of Kc, then WKc: tag, Kc + 9 bytes of timestamp metadata, length.
        assert_eq!(k.key.cipher(0)[..2], [0x80, 0xae]);
        assert_eq!(k.wrapped.len(), 32 + 256 + 9 + 2);
        let plain = unwrap_wkc(TLS_CRYPT_V2_SERVER_KEY, &k.wrapped).expect("WKc authenticates");
        assert_eq!(&plain[..256], &k.key.0[..], "WKc wraps Kc");
        assert_eq!(plain[256], 0x01, "TIMESTAMP metadata");
        assert_eq!(format!("{k:?}"), "TlsCryptV2Key(…)");

        let err = |text: &str| TlsCryptV2Key::parse(text).unwrap_err().to_string();
        assert!(err(TLS_CRYPT_V2_SERVER_KEY).contains("server's tls-crypt-v2 key"));
        assert!(err(STATIC_KEY).contains("invalid"));
        // A corrupted length field.
        let corrupted = TLS_CRYPT_V2_CLIENT_KEY.replace("jpgEr\n", "jpgEq\n");
        assert!(err(&corrupted).contains("invalid"));
    }

    #[test]
    fn tls_crypt_v2_in_a_profile() {
        let text = format!(
            "client\nremote x\n<ca>\n{}</ca>\n<tls-crypt-v2>\n{TLS_CRYPT_V2_CLIENT_KEY}</tls-crypt-v2>\n",
            ca()
        );
        let c = Config::parse(&text).unwrap();
        assert!(matches!(c.tls_wrap, Some(TlsWrap::CryptV2(_))));
        assert_eq!(c.tls_wrap.as_ref().map(TlsWrap::name), Some("tls-crypt-v2"));
        // A referenced key file is embedded on import.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.crt"), ca()).unwrap();
        std::fs::write(dir.path().join("client-v2.key"), TLS_CRYPT_V2_CLIENT_KEY).unwrap();
        let inlined = inline_files(
            "client\nremote x\nca ca.crt\ntls-crypt-v2 client-v2.key\n",
            dir.path(),
        )
        .unwrap();
        assert!(inlined.contains("<tls-crypt-v2>"));
        assert!(matches!(
            Config::parse(&inlined).unwrap().tls_wrap,
            Some(TlsWrap::CryptV2(_))
        ));
    }

    #[test]
    fn protected_keys_and_bundles_import_without_their_passphrase() {
        use crate::openvpn::keyfile::tests::{CA, CLIENT_CERT, LEGACY_AES128, P12, PKCS8_AES256};

        for key in [PKCS8_AES256, LEGACY_AES128] {
            let c = Config::parse(&format!(
                "client\nremote x\n<ca>\n{CA}</ca>\n<cert>\n{CLIENT_CERT}</cert>\n<key>\n{key}</key>\n"
            ))
            .unwrap();
            assert!(c.needs_passphrase());
            assert_eq!(c.auth_summary(), "certificate");
        }

        // A bundle can stand in for <ca>, <cert> and <key>.
        let bundle = format!(
            "client\nremote x\n<pkcs12>\n{}\n</pkcs12>\n",
            base64_lines(P12)
        );
        let c = Config::parse(&bundle).unwrap();
        assert!(c.needs_passphrase() && c.askpass.is_none());
        assert_eq!(c.pkcs12.as_deref().map(Vec::as_slice), Some(P12));
        assert_eq!(c.auth_summary(), "certificate");
        let c = Config::parse(&format!("{bundle}<askpass>\ns3cret pass\n</askpass>\n")).unwrap();
        assert_eq!(
            c.askpass.as_deref().map(String::as_str),
            Some("s3cret pass")
        );
        // `askpass` alone means "ask".
        assert!(
            Config::parse(&format!("{bundle}askpass\n"))
                .unwrap()
                .askpass
                .is_none()
        );

        let both = format!("{bundle}<cert>\n{CLIENT_CERT}</cert>\n<key>\n{PKCS8_AES256}</key>\n");
        assert!(
            Config::parse(&both)
                .unwrap_err()
                .to_string()
                .contains("one or the other")
        );
        let damaged = format!(
            "client\nremote x\n<pkcs12>\n{}\n</pkcs12>\n",
            base64_lines(&P12[..800])
        );
        assert!(
            Config::parse(&damaged)
                .unwrap_err()
                .to_string()
                .contains("PKCS#12")
        );
        let key_only = format!("client\nremote x\n<ca>\n{CA}</ca>\n<key>\n{PKCS8_AES256}</key>\n");
        assert!(Config::parse(&key_only).is_err());
    }

    #[test]
    fn importing_embeds_bundles_as_base64_and_askpass_files() {
        use crate::openvpn::keyfile::tests::P12;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("client.p12"), P12).unwrap();
        std::fs::write(dir.path().join("pass.txt"), "s3cret pass\n").unwrap();
        let inlined = inline_files(
            "client\nremote x 1194\npkcs12 client.p12\naskpass pass.txt\n",
            dir.path(),
        )
        .unwrap();
        assert!(inlined.contains("<pkcs12>\nMII"), "{inlined}");
        assert!(inlined.lines().all(|l| l.len() <= 64));
        let c = Config::parse(&inlined).unwrap();
        assert_eq!(c.pkcs12.as_deref().map(Vec::as_slice), Some(P12));
        assert_eq!(
            c.askpass.as_deref().map(String::as_str),
            Some("s3cret pass")
        );
        // `askpass` without a file stays as it is.
        assert_eq!(inline_files("askpass\n", dir.path()).unwrap(), "askpass\n");
    }
}
