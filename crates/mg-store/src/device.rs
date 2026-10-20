//! Things that belong to this device only and never sync: unlocking with a key kept in the OS
//! keychain, and settings such as auto-lock.

use mg_vault::{AccountKeys, DeviceKey};
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;

use crate::vault::now;
use crate::{Error, LocalVault, Result};

impl LocalVault {
    /// Lets this device unlock without the master password: returns a new device key (to put
    /// in the OS keychain under the returned id) and keeps the account keys wrapped under it.
    /// Replaces an earlier one. Needs the vault unlocked.
    pub fn enable_device_unlock(&mut self) -> Result<(String, DeviceKey)> {
        let key = DeviceKey::generate()?;
        let wrapped = self.unlocked()?.account.wrap_with_device(&key)?;
        let key_id = Ulid::generate().to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO device_unlock (id, key_id, wrapped, created_at) VALUES (1, ?1, ?2, ?3)",
            params![key_id, wrapped, now()],
        )?;
        Ok((key_id, key))
    }

    /// The keychain entry this device unlocks with, if any (readable while locked).
    pub fn device_unlock_id(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT key_id FROM device_unlock WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn disable_device_unlock(&mut self) -> Result<()> {
        self.conn.execute("DELETE FROM device_unlock", [])?;
        Ok(())
    }

    /// Unlocks with the device key from the OS keychain.
    pub fn unlock_with_device_key(&mut self, key: &DeviceKey) -> Result<()> {
        let row = self.account_row()?.ok_or(Error::NotInitialized)?;
        let wrapped: Vec<u8> = self
            .conn
            .query_row("SELECT wrapped FROM device_unlock WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or_else(|| Error::Invalid("unlocking with the system keychain is off".into()))?;
        let account = AccountKeys::unwrap_with_device(key, &wrapped).map_err(|e| match e {
            mg_vault::Error::Decrypt => {
                Error::Invalid("the system keychain holds a different key for this vault".into())
            }
            other => other.into(),
        })?;
        self.finish_unlock(account, &row)
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// A secret that stays on this device and never syncs (a provider's sign-in): sealed with
    /// the personal vault's key, so it reads only while the vault is unlocked. `None` removes it.
    pub fn set_local_secret(&self, name: &str, value: Option<&str>) -> Result<()> {
        let key = format!("secret:{name}");
        let Some(value) = value else {
            return self.set_setting(&key, None);
        };
        let u = self.unlocked()?;
        let sealed = mg_vault::envelope::seal(
            &u.vault_key,
            &u.account,
            &local_context(name),
            value.as_bytes(),
        )?;
        let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
        self.set_setting(&key, Some(&hex))
    }

    /// A secret [`set_local_secret`](Self::set_local_secret) kept; `None` when there's none.
    pub fn local_secret(&self, name: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
        let Some(hex) = self.setting(&format!("secret:{name}"))? else {
            return Ok(None);
        };
        let u = self.unlocked()?;
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .map_err(|_| Error::Crypto(mg_vault::Error::Malformed("local secret")))?;
        let plain =
            mg_vault::envelope::open(&u.vault_key, &u.sign_pub, &local_context(name), &bytes)?;
        let text = String::from_utf8(plain.to_vec())
            .map_err(|_| Error::Crypto(mg_vault::Error::Malformed("local secret")))?;
        Ok(Some(zeroize::Zeroizing::new(text)))
    }

    pub fn set_setting(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => self.conn.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, v],
            )?,
            None => self
                .conn
                .execute("DELETE FROM settings WHERE key = ?1", [key])?,
        };
        Ok(())
    }
}

/// Where a device secret is bound: a context of its own, so it can't pass for any item.
fn local_context(name: &str) -> mg_vault::ItemContext<'_> {
    mg_vault::ItemContext {
        vault_id: "this-device",
        item_id: name,
        schema_version: 1,
    }
}

#[cfg(test)]
mod tests {
    use mg_vault::KdfParams;

    use super::*;
    use crate::{HostAuth, ItemData};

    const PW: &str = "correct horse battery";

    fn vault() -> LocalVault {
        let mut v = LocalVault::open_in_memory().unwrap().with_kdf_cost(
            KdfParams::MIN_M_KIB,
            KdfParams::MIN_T,
            1,
        );
        v.create(PW).unwrap();
        v
    }

    #[test]
    fn local_secrets_need_the_vault_unlocked() {
        let mut v = vault();
        v.set_local_secret("vallic:S1", Some("refresh-token"))
            .unwrap();
        assert_eq!(
            v.local_secret("vallic:S1")
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("refresh-token")
        );
        // Stored sealed, not as text.
        assert!(
            !v.setting("secret:vallic:S1")
                .unwrap()
                .unwrap()
                .contains("refresh")
        );
        // A sealed secret doesn't open under another name.
        let sealed = v.setting("secret:vallic:S1").unwrap();
        v.set_setting("secret:vallic:S2", sealed.as_deref())
            .unwrap();
        assert!(v.local_secret("vallic:S2").is_err());
        v.lock();
        assert!(v.local_secret("vallic:S1").is_err(), "locked");
        v.unlock(PW).unwrap();
        v.set_local_secret("vallic:S1", None).unwrap();
        assert_eq!(v.local_secret("vallic:S1").unwrap(), None);
    }

    #[test]
    fn device_key_unlocks_and_survives_password_changes() {
        let mut v = vault();
        let host = v
            .upsert(
                None,
                ItemData::Host(crate::Host {
                    label: "db".into(),
                    hostname: "db.internal".into(),
                    port: 22,
                    user: "u".into(),
                    auth: HostAuth::system_agent(),
                    jump_ref: None,
                    vpn_ref: None,
                    theme_ref: None,
                    record_sessions: false,
                    tags: vec![],
                    notes: String::new(),
                    group_ref: None,
                    identity_ref: None,
                    keep_session: false,
                    forward_agent: false,
                    login_command: None,
                    jump_command: None,
                    proxy_command: None,
                    source: None,
                }),
            )
            .unwrap();
        assert_eq!(v.device_unlock_id().unwrap(), None);
        let (id, key) = v.enable_device_unlock().unwrap();
        assert_eq!(v.device_unlock_id().unwrap(), Some(id));

        v.lock();
        v.unlock_with_device_key(&key).unwrap();
        assert_eq!(v.item(&host.id).unwrap().id, host.id);

        // The device key wraps the account keys, not the password: a new password keeps it.
        v.change_password(PW, "another password").unwrap();
        v.lock();
        v.unlock_with_device_key(&key).unwrap();

        v.lock();
        assert!(
            v.unlock_with_device_key(&DeviceKey::generate().unwrap())
                .is_err()
        );
        v.unlock("another password").unwrap();
        v.disable_device_unlock().unwrap();
        v.lock();
        assert!(v.unlock_with_device_key(&key).is_err());
        assert_eq!(v.device_unlock_id().unwrap(), None);
    }

    #[test]
    fn enabling_needs_an_unlocked_vault() {
        let mut v = vault();
        v.lock();
        assert!(matches!(v.enable_device_unlock(), Err(Error::Locked)));
    }

    #[test]
    fn settings_round_trip() {
        let v = vault();
        assert_eq!(v.setting("auto_lock_minutes").unwrap(), None);
        v.set_setting("auto_lock_minutes", Some("15")).unwrap();
        v.set_setting("auto_lock_minutes", Some("30")).unwrap();
        assert_eq!(
            v.setting("auto_lock_minutes").unwrap().as_deref(),
            Some("30")
        );
        v.set_setting("auto_lock_minutes", None).unwrap();
        assert_eq!(v.setting("auto_lock_minutes").unwrap(), None);
    }
}
