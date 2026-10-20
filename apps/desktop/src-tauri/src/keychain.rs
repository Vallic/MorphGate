//! The OS keychain (Secret Service on Linux, Keychain on macOS, Credential Manager on Windows,
//! the data protection keychain on iOS) as a home for the device key that unlocks the vault
//! without the master password.

use mg_vault::DeviceKey;
#[cfg(not(target_os = "ios"))]
use zeroize::Zeroizing;

const SERVICE: &str = "MorphGate";

#[cfg(target_os = "ios")]
pub use ios::{available, delete, load, store};

#[cfg(not(target_os = "ios"))]
fn entry(key_id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, &format!("vault-unlock:{key_id}")).map_err(describe)
}

#[cfg(not(target_os = "ios"))]
fn describe(e: keyring::Error) -> String {
    match e {
        keyring::Error::NoDefaultStore => {
            "no system keychain is available (on Linux, a Secret Service such as GNOME Keyring or \
             KWallet must be running)"
                .into()
        }
        keyring::Error::NoEntry => "the key is no longer in the system keychain".into(),
        other => format!("system keychain: {other}"),
    }
}

/// Whether a keychain can be used here (calls into the OS; run off the async runtime).
#[cfg(not(target_os = "ios"))]
pub fn available() -> bool {
    keyring::Entry::store_status().is_ok()
}

#[cfg(not(target_os = "ios"))]
pub fn store(key_id: &str, key: &DeviceKey) -> Result<(), String> {
    entry(key_id)?.set_secret(key.as_bytes()).map_err(describe)
}

/// `Ok(None)` when the entry is gone (removed by the user or another tool).
#[cfg(not(target_os = "ios"))]
pub fn load(key_id: &str) -> Result<Option<DeviceKey>, String> {
    match entry(key_id)?.get_secret() {
        Ok(bytes) => device_key(&Zeroizing::new(bytes)).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(describe(e)),
    }
}

#[cfg(not(target_os = "ios"))]
pub fn delete(key_id: &str) -> Result<(), String> {
    match entry(key_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(describe(e)),
    }
}

fn device_key(bytes: &[u8]) -> Result<DeviceKey, String> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "the system keychain entry is not a MorphGate key".to_owned())?;
    Ok(DeviceKey::from_bytes(key))
}

/// iOS, where keyring has no store: the device key is an item of the data protection keychain
/// that stays on this device (no backup or iCloud takes it along), exists only while the device
/// has a passcode, and that iOS releases only after Face ID, Touch ID or the passcode, each
/// time. So the check is iOS's, not the app's, as Android's Keystore does it.
#[cfg(target_os = "ios")]
mod ios {
    use mg_vault::DeviceKey;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
    use zeroize::Zeroizing;

    use super::{SERVICE, device_key};
    use crate::device::CANCELLED;

    const NOT_FOUND: i32 = -25300; // errSecItemNotFound
    const USER_CANCELED: i32 = -128; // errSecUserCanceled
    const AUTH_FAILED: i32 = -25293; // errSecAuthFailed
    const NO_INTERACTION: i32 = -25308; // errSecInteractionNotAllowed

    fn options(key_id: &str) -> PasswordOptions {
        let mut o =
            PasswordOptions::new_generic_password(SERVICE, &format!("vault-unlock:{key_id}"));
        o.use_protected_keychain();
        o
    }

    fn describe(e: security_framework::base::Error) -> String {
        match e.code() {
            USER_CANCELED => CANCELLED.into(),
            AUTH_FAILED => {
                "Face ID didn't confirm it's you: try again, or use the master password".into()
            }
            NO_INTERACTION => {
                "the keychain can't ask for Face ID right now: unlock the device first".into()
            }
            _ => format!("keychain: {e}"),
        }
    }

    /// A passcode is set: without one, the item can't exist.
    pub fn available() -> bool {
        mg_presence::availability().status == mg_presence::Status::Ready
    }

    pub fn store(key_id: &str, key: &DeviceKey) -> Result<(), String> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            AccessControlOptions::USER_PRESENCE.bits(),
        )
        .map_err(describe)?;
        let mut o = options(key_id);
        o.set_access_control(access);
        set_generic_password_options(key.as_bytes(), o).map_err(describe)
    }

    /// Asks for Face ID (iOS shows the prompt). `Ok(None)` when the item is gone: removed with the
    /// passcode, say.
    pub fn load(key_id: &str) -> Result<Option<DeviceKey>, String> {
        match generic_password(options(key_id)) {
            Ok(bytes) => device_key(&Zeroizing::new(bytes)).map(Some),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(describe(e)),
        }
    }

    pub fn delete(key_id: &str) -> Result<(), String> {
        match delete_generic_password_options(options(key_id)) {
            Err(e) if e.code() != NOT_FOUND => Err(describe(e)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes to, reads from and removes an entry in the real keychain of the logged-in user.
    #[test]
    #[ignore = "set MG_TEST_KEYCHAIN=1 to use the session's real keychain"]
    fn round_trip_in_the_session_keychain() {
        if std::env::var_os("MG_TEST_KEYCHAIN").is_none() {
            return;
        }
        assert!(available());
        let id = format!("test-{}", std::process::id());
        let key = DeviceKey::generate().unwrap();
        store(&id, &key).unwrap();
        assert_eq!(load(&id).unwrap().unwrap().as_bytes(), key.as_bytes());
        delete(&id).unwrap();
        assert!(load(&id).unwrap().is_none());
        delete(&id).unwrap();
    }
}
