//! Asks the operating system to confirm that the user is at the computer before the app does
//! something sensitive (here: unlocking the vault with the key kept in the system keychain).
//!
//! - macOS: Touch ID, falling back to the login password or an Apple Watch (LocalAuthentication).
//! - iOS and iPadOS: Face ID or Touch ID, falling back to the passcode (LocalAuthentication).
//! - Windows: Windows Hello (face, fingerprint or PIN).
//! - Linux: polkit, which asks for whatever the system's PAM stack accepts: a fingerprint where
//!   fprintd is set up, otherwise the login password. This needs MorphGate's polkit action to be
//!   installed; [`setup`] does that through `pkexec`, and packages ship it.
//!
//! This is a check made by the app, not a key the OS releases only after verification: it keeps
//! someone at an unlocked computer out of the vault, not malware running as the user (which can
//! read the keychain entry directly).
//!
//! Every function blocks, some for as long as a dialog is open: call them off the UI thread.

#[cfg(windows)]
mod hello;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod local_auth;
#[cfg(target_os = "linux")]
mod polkit;

#[cfg(windows)]
use hello as platform;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use local_auth as platform;
#[cfg(target_os = "linux")]
use polkit as platform;

/// What the OS will ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    TouchId,
    /// iPhones and iPads with Face ID.
    FaceId,
    WindowsHello,
    /// iOS: the device passcode (no Face ID or Touch ID set up).
    Passcode,
    /// The system's own authentication: polkit on Linux; the login password or an Apple Watch
    /// on a Mac without Touch ID.
    System,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Ready,
    /// Linux: MorphGate's polkit action isn't installed yet (see [`setup`]).
    NeedsSetup,
    /// Not usable here, with a reason to show.
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Availability {
    pub kind: Kind,
    pub status: Status,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Failed(String),
}

/// A native window to attach the prompt to. On Windows, the `HWND` (the Hello dialog otherwise
/// opens behind the app); ignored elsewhere.
#[derive(Clone, Copy, Debug, Default)]
pub struct Parent(pub Option<isize>);

/// Whether, and with what, the user can be verified here.
pub fn availability() -> Availability {
    platform::availability()
}

/// Shows the OS prompt and returns once the user has been verified.
///
/// `reason` finishes the sentence "MorphGate is trying to …", which is how macOS shows it
/// (e.g. `"unlock your vault"`); Windows shows it as a sentence of its own, and polkit shows the
/// message of the installed action instead.
pub fn verify(reason: &str, parent: Parent) -> Result<(), Error> {
    platform::verify(reason, parent)
}

/// Linux: installs MorphGate's polkit action, asking for an administrator password. Elsewhere
/// there is nothing to set up.
pub fn setup() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    return polkit::setup();
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios", windows)))]
mod platform {
    use super::*;

    pub fn availability() -> Availability {
        Availability {
            kind: Kind::System,
            status: Status::Unavailable("not supported on this platform".into()),
        }
    }

    pub fn verify(_: &str, _: Parent) -> Result<(), Error> {
        Err(Error::Unavailable("not supported on this platform".into()))
    }
}

#[cfg(test)]
mod tests {
    /// Never prompts: only asks what's available, which must not fail or hang anywhere.
    #[test]
    fn availability_answers() {
        let a = super::availability();
        println!("{a:?}");
    }
}
