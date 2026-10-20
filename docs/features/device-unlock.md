# Keychain and biometric unlock

Each device can open the vault without the master password. A random 32-byte device key is kept by the operating system (the keychain on desktops and iOS, sealed by the Keystore on Android), and the vault keeps the account private keys wrapped under it. Because the device key wraps the account keys and not the password, it keeps working after a password change or recovery. It never syncs and is never sent anywhere. On desktops the OS can be asked to confirm the user first (Touch ID, Windows Hello, polkit); on Android and iOS that check is part of the key. Opt-in, per device, and the master password always keeps working. Code: `crates/mg-store/src/device.rs`, `DeviceKey` in `crates/mg-vault/src/account.rs`, `apps/desktop/src-tauri/src/device.rs` (Tauri commands), `keychain.rs`, `biometric.rs`, `apps/desktop/src-tauri/gen/android/app/src/main/java/com/morphgate/app/BiometricKeyPlugin.kt`, `crates/mg-presence`, `ThisDevice` in `apps/desktop/src/SecurityPanel.tsx`.

## How it works

| Step | Code |
| --- | --- |
| Turn on: check the master password (this adds a way into the vault), make a device key, wrap the account keys under HKDF(device key, `morphgate/v1/device-kek`) into `device_unlock`, hand the key to the OS. Replaces an earlier one | `LocalVault::enable_device_unlock`, `keychain_enable` |
| Unlock: get the key back from the OS, unwrap the account keys, open the vaults as a password unlock does | `LocalVault::unlock_with_device_key`, `vault_unlock_keychain` |
| Turn off: delete the OS copy (best effort: without the wrapped keys it is useless) and the `device_unlock` row | `disable_device_unlock`, `keychain_disable` |

The unlock screen tries it by itself once, at app launch; after a lock it takes a click ([Vault and unlock](vault-and-unlock.md#unlocking)). Erasing the device removes the OS copy too.

## Tauri commands

| Command | Does |
| --- | --- |
| `device_status` | Keychain available and enabled, auto-lock minutes, presence kind (`touchId`, `faceId`, `windowsHello`, `system`, `passcode`, `biometric`) and status (`ready`, `setup`, `unavailable` with a reason), whether presence is required (always on Android and iOS), update checks. Works while locked |
| `keychain_enable` | Turns it on, with the master password. Rolls back if the OS refuses to store the key |
| `keychain_disable` | Turns it off |
| `vault_unlock_keychain` | Runs the presence check if required (without holding the vault while the dialog is up), reads the key, unlocks |
| `presence_require` | Turns the desktop presence check on, after one successful check so a broken setup can't lock anyone out of the quick path, or off. Needs the vault unlocked ("Unlock the vault first.") and keychain unlock on ("Turn on unlocking with the system keychain first.") |
| `presence_setup` | Linux: installs the polkit action |
| `set_auto_lock`, `set_auto_update_check` | Other device settings |

A cancelled OS prompt becomes the error `cancelled` (`CANCELLED`), which the UI shows as nothing (`isCancelled`).

## Desktop keychains

| Platform | Store (`keyring` 4) |
| --- | --- |
| Linux | Secret Service: GNOME Keyring or KWallet must be running |
| macOS | Keychain |
| Windows | Credential Manager |

The entry is service `MorphGate`, account `vault-unlock:<ULID>`. If it has gone (removed by the user or another tool), keychain unlock turns itself off: "The key is no longer in the system keychain, so keychain unlock was turned off. Unlock with the master password." A key that doesn't open the vault is "the system keychain holds a different key for this vault".

In Security, under **This device**:

| State | UI |
| --- | --- |
| Off, keychain available | Hint (anyone who can use the logged-in account can then open MorphGate), **Master password (to confirm)**, **Unlock with system keychain** ("Turning on…") |
| On | "Unlocks with the system keychain on this device." and **Turn off**, then the presence option |
| No keychain | "No system keychain is available here (on Linux, GNOME Keyring or KWallet must be running), so the master password is always needed." |

## The presence check (desktops)

With the setting `unlock_requires_presence` = `1`, `mg_presence::verify("unlock your vault")` runs before the keychain is read:

| Platform | Kind | How |
| --- | --- | --- |
| macOS | Touch ID; "system authentication" on a Mac without it | LocalAuthentication `deviceOwnerAuthentication`, shown as "MorphGate is trying to unlock your vault"; the Mac's password or an Apple Watch as fallback |
| Windows | Windows Hello | `UserConsentVerifier` (face, fingerprint or PIN), attached to the app's window so the dialog doesn't open behind it |
| Linux | System authentication | polkit `CheckAuthorization` for `com.morphgate.desktop.unlock` (`auth_self`, without `_keep`, so every unlock asks). PAM decides: a fingerprint where fprintd is set up, else the login password |

| State | UI |
| --- | --- |
| Ready | The checkbox **Ask for … before unlocking** (**Ask for Touch ID before unlocking**, **Ask for Windows Hello before unlocking**, **Ask for system authentication before unlocking**) and a hint per kind |
| Linux without the action | A hint and **Set up**: `pkexec` writes `/usr/share/polkit-1/actions/com.morphgate.desktop.policy`, through a pipe so nobody can swap the file in between, world-readable whatever the umask. The `.deb` and `.rpm` ship the file |
| Unavailable | "… can't be used here: …" with the name and the reason (e.g. "this PC has no Windows Hello camera, fingerprint reader or PIN", "polkit is not running") and, if the check is on, "Until it works again, unlock with the master password." |

Why it is only a check (`mg-presence`): it keeps someone at an unlocked computer out of the vault, not malware running as the user, which can read the keychain entry directly. The UI says so: "That keeps out someone at your unlocked computer, not programs running as you." Binding the desktop key to biometrics (Keychain access control, a Windows Hello key credential), as iOS and Android do, isn't done yet ([Roadmap](../../ROADMAP.md)).

## Android: fingerprint or face

The device key is encrypted with an AES-256-GCM key in Android's Keystore (alias `morphgate-vault-unlock`, in secure hardware where the phone has it) that Android lets the app use only right after a strong biometric check, each time (Android 11 and later), and that enrolling a new fingerprint or face invalidates. The sealed bytes (`IV(12) ‖ ciphertext`) are kept base64 in the setting `android_unlock_sealed`. The check is part of the key, so presence is always required.

| Moment | Prompt / message |
| --- | --- |
| Turning on | Master password, then "Unlock with fingerprint or face" ("Turn on unlocking MorphGate with it") |
| Unlocking | "Unlock MorphGate" ("Use your fingerprint or face") |
| Fingerprints or faces changed (`INVALIDATED`, `GONE`) | Turned off: "The fingerprints or faces on this phone changed, so unlocking with them stopped working: unlock with the master password, then turn it on again in Security." |

Security shows **Master password (to confirm)** and **Unlock with fingerprint or face**, or "Unlocks with your fingerprint or face on this phone." with **Turn off**. Joining a sync account with other keys turns it off ([Sync](sync.md)).

## iOS: Face ID, Touch ID or the passcode

`keyring` has no iOS store, so `keychain.rs` has its own (`mod ios`). The device key is an item of the data protection keychain (`security-framework`), `AccessibleWhenPasscodeSetThisDeviceOnly` with the `USER_PRESENCE` access control: it stays on this device (no backup or iCloud), exists only while the device has a passcode, and iOS releases it only after Face ID, Touch ID or the passcode, every time. So the check is iOS's, always on (`presence_required` is true on iOS), and the app doesn't add one; the keychain counts as available when that check is (`mg-presence` reports `faceId`, `touchId`, or `passcode` without either). Turning it on stores the key and reads it back at once, so iOS asks then; if that fails, it is turned off again rather than left to fail at every unlock. The Face ID prompt shows `NSFaceIDUsageDescription` from `Info.ios.plist`.

Security offers it as one step (`IosUnlockOption`): **Master password (to confirm)** and **Unlock with Face ID** (or Touch ID, or your passcode), or "Unlocks with Face ID on this device." with **Turn off**. Removing the device's passcode removes the key; the next unlock finds it gone and turns keychain unlock off, as on desktops. A failed check is "Face ID didn't confirm it's you: try again, or use the master password"; a cancelled one shows nothing.

## Device settings

Kept in the vault's `settings` table, never synced:

| Key | Meaning |
| --- | --- |
| `auto_lock_minutes` | Auto-lock ([Vault and unlock](vault-and-unlock.md#locking-and-auto-lock)) |
| `unlock_requires_presence` | `1`: the desktop presence check |
| `update_check` | `0`: no automatic update checks ([Updates](updates.md)) |
| `android_unlock_sealed` | Android's sealed device key |
| `terminal` | Appearance ([Appearance](appearance.md)) |
| `proxy-allowed:<sha256>`, `cloud-cli:<provider>` | Commands this device allowed, CLI paths |
| `secret:<name>` | Device-local secrets such as cloud sign-ins, sealed with the personal vault key (`set_local_secret`); readable only while unlocked |

## Tests

| Where | Covers |
| --- | --- |
| `crates/mg-store/src/device.rs` | The device key unlocks and survives a password change, a wrong key fails, turning off works, enabling needs an unlocked vault, local secrets are sealed and bound to their name |
| `crates/mg-vault/src/account.rs` | `device_key_wrap_is_its_own_domain` |
| `apps/desktop/src-tauri/src/device.rs` | `keychain_unlock_waits_for_the_os_check` (cancel and failure never read the keychain), `without_the_setting_there_is_no_prompt`, `presence_views_match_the_frontend` |
| `apps/desktop/src-tauri/src/keychain.rs` | Round trip in the session's real keychain: ignored unless `MG_TEST_KEYCHAIN=1 cargo test -p morphgate-desktop -- --ignored round_trip` |
| `crates/mg-presence` | polkit against a mock on a private D-Bus, the policy file and `setup`; `real_polkitd_understands_us` with `MG_TEST_POLKIT=1` (CI runs it where polkitd is up); Windows prompt sentences. macOS and Windows CI only ask for availability: runners have no Touch ID or Hello |

## Limits

- On desktops the presence check is the app's, not the keychain's; see above.
- With keychain unlock on, anyone who can use the logged-in OS account can open MorphGate (unless the presence check is on).
- macOS and Windows presence code builds and runs in CI but, per the [Roadmap](../../ROADMAP.md), is untried on hardware.
- The iOS simulator returns the keychain item without asking, so the Face ID prompt shows only on a real device.
