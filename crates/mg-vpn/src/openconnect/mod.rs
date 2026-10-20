//! openconnect VPNs (Cisco AnyConnect / ocserv, Palo Alto GlobalProtect, Fortinet, Pulse /
//! Ivanti, F5, Juniper, Array) through the system's `openconnect` program.
//!
//! openconnect runs in `--script-tun` mode: it speaks the VPN protocol and hands over raw IP
//! packets on a socket instead of configuring a TUN device. Its "script" is MorphGate's own
//! binary in helper mode ([`tun_helper_main`]), which passes that socket and the tunnel settings
//! back to the app over a private Unix socket. The packets then feed the in-app TCP/IP stack, so
//! nothing on the system changes and no root is needed, as with every MorphGate tunnel.
//!
//! Prompts openconnect prints (passwords, one-time codes, group choice, untrusted server
//! certificates) are relayed to the user through a [`Prompter`].
//!
//! Single sign-on (SAML) in the user's browser: openconnect 9 and later take an
//! `--external-browser` program, which they start with the sign-in page when a server offers
//! that (AnyConnect's "external browser" SSO). Ours is a small script that runs the same helper
//! with the page in `MG_OC_URL`; the helper hands it to the app, which opens it through
//! [`Prompter::web_sign_in`] and waits while openconnect collects the result.
//!
//! Not on Windows: openconnect's Windows build can't run a `--script-tun` script
//! (`openconnect_setup_tun_script()` in its `tun-win32.c` only reports "Spawning tunnel scripts
//! is not yet supported on Windows", as of 9.21 and master), and its only other way out for
//! packets is a TAP-Windows or Wintun adapter, which takes a driver and admin rights: the
//! opposite of an in-app tunnel. It would take either script-tun support upstream (a socket
//! pair the script inherits as `VPNFD`, read and written in place of the adapter handle), or
//! MorphGate speaking the tunnel protocols itself after `openconnect --authenticate` (cookie and
//! gateway): CSTP over TLS, plus DTLS, for AnyConnect and ocserv first; GlobalProtect,
//! Fortinet, Pulse and the rest each need their own.

#[cfg(unix)]
mod helper;
#[cfg(all(test, unix))]
mod tests;

use std::path::PathBuf;

use zeroize::Zeroizing;

#[cfg(unix)]
pub use helper::tun_helper_main;

use crate::{Prompter, Tunnel, VpnError};

/// `--protocol` values and what they're called in the UI.
pub const PROTOCOLS: &[(&str, &str)] = &[
    ("anyconnect", "Cisco AnyConnect / ocserv"),
    ("gp", "Palo Alto GlobalProtect"),
    ("fortinet", "Fortinet FortiGate"),
    ("pulse", "Pulse / Ivanti Connect Secure"),
    ("f5", "F5 BIG-IP"),
    ("nc", "Juniper Network Connect"),
    ("array", "Array Networks"),
];

pub struct OcConfig {
    /// `vpn.example.com`, or a URL with a group path (`https://vpn.example.com/engineering`).
    pub server: String,
    pub protocol: String,
    pub username: Option<String>,
    /// Saved password; otherwise openconnect's prompt reaches the user.
    pub password: Option<Zeroizing<String>>,
    /// Login group (`--authgroup`).
    pub authgroup: Option<String>,
    /// Pinned server certificate (`pin-sha256:…`), for servers the system doesn't trust.
    pub server_cert: Option<String>,
    /// The command openconnect runs as its tun script: MorphGate's binary in helper mode.
    pub helper: Vec<String>,
    /// The openconnect program; `None` = look in `PATH` and the usual install locations.
    pub program: Option<PathBuf>,
}

/// Where openconnect is installed, if it is.
pub fn find_openconnect() -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    // GUI apps on macOS don't see the shell's PATH.
    for d in [
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/opt/local/bin",
        "/opt/local/sbin",
    ] {
        dirs.push(d.into());
    }
    let name = if cfg!(windows) {
        "openconnect.exe"
    } else {
        "openconnect"
    };
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

pub fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "openconnect is not installed; install it with `brew install openconnect`"
    } else if cfg!(unix) {
        "openconnect is not installed; install it from your distribution (e.g. `sudo dnf install \
         openconnect` or `sudo apt install openconnect`)"
    } else {
        UNSUPPORTED
    }
}

/// Why openconnect VPNs don't work on this system (see the module docs).
const UNSUPPORTED: &str = "openconnect VPNs don't work on Windows yet: openconnect can only \
                           hand its traffic to a network adapter there, and MorphGate keeps VPN \
                           traffic inside the app";

/// Phones and tablets can't run other programs.
const ON_PHONES: &str = "openconnect VPNs work in the desktop app: phones and tablets can't run \
                         the openconnect program";

/// Why openconnect VPNs can't be used here, if they can't: not supported on this system, or
/// the program isn't installed.
pub fn unavailable() -> Option<&'static str> {
    if cfg!(not(unix)) {
        return Some(UNSUPPORTED);
    }
    if cfg!(any(target_os = "android", target_os = "ios")) {
        return Some(ON_PHONES);
    }
    find_openconnect().is_none().then(install_hint)
}

/// Connects through openconnect and returns the running tunnel.
#[cfg(unix)]
pub async fn start(
    cfg: OcConfig,
    prompter: &dyn Prompter,
    label: &str,
) -> Result<Tunnel, VpnError> {
    helper::start(cfg, prompter, label).await
}

#[cfg(not(unix))]
pub async fn start(_: OcConfig, _: &dyn Prompter, _: &str) -> Result<Tunnel, VpnError> {
    Err(VpnError::Config(install_hint().into()))
}
