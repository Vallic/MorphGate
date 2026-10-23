# Vault and unlock

The vault is one SQLite file on the device that holds every item as a signed, encrypted envelope. It exists before any server is involved, works fully offline, and its rows are exactly what sync pushes and pulls. The master password unlocks it, the recovery key replaces a forgotten password, and the vault locks itself when idle. Each device can add a quicker unlock, described in [Keychain and biometric unlock](device-unlock.md). The cryptography is in [Vault cryptography](vault-crypto.md); the sync side of password changes and recovery is in [Account and devices](account-and-devices.md). Code: `crates/mg-store/src/vault.rs` (`LocalVault`), `schema.rs`, `model.rs`, `export.rs`, `error.rs`; `apps/desktop/src-tauri/src/vault.rs` (Tauri commands), `password.rs`, `device.rs` (auto-lock); `apps/desktop/src/VaultGate.tsx`, `SecurityPanel.tsx`, `mobile/MobileUnlock.tsx`, `App.tsx` (`useIdleLock`).

## The file

`vault.sqlite3` in Tauri's `app_data_dir` (identifier `com.morphgate.desktop`; `com.morphgate.app` on Android and iOS, see [Platforms and mobile](platforms-and-mobile.md)):

| Platform | Folder |
| --- | --- |
| Linux | `$XDG_DATA_HOME/com.morphgate.desktop/`, usually `~/.local/share/com.morphgate.desktop/` |
| macOS | `~/Library/Application Support/com.morphgate.desktop/` |
| Windows | `%APPDATA%\com.morphgate.desktop\` |

`LocalVault::open` creates the file with mode 0600 on Unix, turns on `foreign_keys` and `secure_delete` (deleted rows are overwritten, not only unlinked), and migrates by `PRAGMA user_version` (8 migrations in `schema.rs`). A file from a newer app is refused, and left as it is (`Error::NewerVault`): the app still starts, without the vault, and its window says "this vault was saved by a newer version of MorphGate (vault format N; this version reads up to M). Install the latest version from morphgate.com/download to open it; the vault is unchanged." (`vault_status` returns it; nothing else runs). On desktops a second launch hands over to the running app (single instance per data folder), so only one process opens the file. The tables are listed in [App architecture](../architecture.md#the-sqlite-schema).

### What is in the clear

| Table | In the clear | Encrypted |
| --- | --- | --- |
| `account` | KDF parameters and salt, public keys, `recovery_proof` (kept so sync can be turned on later; the server needs it at registration), `created_at` | Account private keys, under the password and under the recovery key |
| `vaults` | Ids, key ids, `head_rev`, personal or organization, permission, `rotation_due`, `directory`, and a team vault's name (from its decrypted `vault-meta`) | Each vault key, sealed to the account |
| `vault_keys` | Vault and key ids | Every key generation of a shared vault |
| `items` | Vault and item ids, `rev`, `dirty`, `deleted`, `updated_at`, `author_id` | The item (`envelope`); NULL for a deleted item |
| `orgs`, `pinned_keys` | Organization names, roles, pinned root and member public keys, members' emails | |
| `sync_state` | Server URL, email, account and device ids, device public key, last sync and error | The refresh token, sealed as an envelope |
| `device_unlock` | The keychain entry's id | The account private keys under the device key |
| `settings` | This device's settings (below), allowed commands by SHA-256 | `secret:<name>` values (cloud sign-ins), sealed with the personal vault key |
| `blobs`, `blob_deletes` | Vault id, hash, kind, upload state | The blob |

Nothing a host, key or snippet holds is in the clear: `persists_and_stores_only_ciphertext` greps the file for a hostname, user, password and key material. The `known_hosts` file next to it is plain text ([SSH connections](ssh-connections.md)).

## States

`vault_status` returns `Status`: `uninitialized` (no `account` row), `locked`, or `unlocked`. Unlocked, the process holds `Unlocked`: the account keys, the personal vault key, the key rings of shared vaults, the signing keys of pinned members, and the sync account id. Locked, it holds nothing secret, and every item call fails with "the vault is locked". Readable while locked: the status, public keys, device settings (the unlock screen needs `device_status`), and whether a sync session exists.

Every read verifies the envelope's signature and binding, then parses the JSON. A tampered or swapped row fails the call (`items()` fails as a whole) instead of being skipped. A kind written by a newer app (`ItemData::Unknown`) is kept and synced, left out of lists, and refused for editing ("this app can't edit that kind of item").

## Item types

Each item's plaintext is an `ItemData`, JSON with a `type` tag (`model.rs`, `SCHEMA_VERSION` 1). New ids are ULIDs.

| `type` | What | Doc |
| --- | --- | --- |
| `host`, `host_group`, `identity`, `attachment` | Hosts and what they inherit; files kept with a host | [Hosts, groups and identities](hosts-groups-identities.md) |
| `ssh_key`, `host_ca` | Private keys, certificate authorities for host keys | [SSH keys and agents](ssh-keys-and-agents.md) |
| `snippet` | Commands to paste or run | [Terminal and snippets](terminal-and-snippets.md) |
| `port_forward` | Local, remote and dynamic tunnels | [Port forwarding](port-forwarding.md) |
| `vpn` | VPN profiles | [VPN](vpn.md) |
| `session_log` | A recorded session, its chunks in blobs | [Session logs](session-logs.md) |
| `terminal_theme` | Imported color schemes | [Appearance](appearance.md) |
| `cloud_source` | A cloud account or feed whose machines become hosts | [Cloud sources](cloud-sources.md) |
| `member_key` | A member's SSH public key, in an organization's directory vault | [Teams](teams.md) |

Store-level rules that apply to every type:

| Refusal | Error |
| --- | --- |
| Changing an item into another type | `item <id> is a <existing>, not a <requested>` |
| Writing in a view-only shared vault | `this vault is read-only for you` |
| A reference to an item in another vault | `items can only refer to items in the same vault` |
| Saving an existing item into another vault | `to put an item in another vault, copy or move it` |
| Deleting an item others refer to | `<what> is still used by: <labels>` |

Deleting leaves a tombstone (`deleted` 1) holding the signed deletion (`{"type":"deleted","item_version":n}` in an envelope of the item) so the deletion syncs, and other devices can tell it from one a server made up ([Item history](sync.md#item-history)). Deleting a host deletes its attachments; deleting a group makes what its hosts took from it their own.

## First run

`App.tsx` shows `SetupScreen` while the status is `uninitialized`. A segmented choice offers **New vault** (on this device only; if sync is still off a week later, it is offered once), **New account** (the vault and the sync account that keeps it on other devices, in one go) and **Sign in** (an existing sync account; see [Sync](sync.md#signing-in)). The same screen, on every platform.

| Step | UI |
| --- | --- |
| **Create your vault** | **Master password**, the strength meter, **Suggest a strong password**, **Repeat password** ("Passwords don't match."), **Create vault** (enabled once the password is strong and repeated; "Deriving keys…" while busy) |
| **Create your account** | **Sync server**, **Email**, the password fields as above, the server's terms where it has them, **Continue** (the server mails a code: **Code sent to {email}**) or **Create account**. It creates the vault (`vault_create`), then the account with the same password (`sync_enable`). If the account then fails (a wrong code, say), the vault stays and the form keeps the rest: another try needs no new vault, and **Use the vault without an account for now** goes on to the recovery key (and sync is offered a week later, as after **New vault**) |
| **Save your recovery key** | The code in groups, **Copy to clipboard** ("Copied", and "MorphGate clears the clipboard when you continue, so the key doesn't stay there."), the checkbox **I stored it somewhere safe, away from this device**, then **Open my vault** (enabled once ticked), which clears the clipboard if the key was copied; a minute on the screen clears it too, where the webview allows that without a click (`RecoveryCode` in `VaultGate.tsx`) |

`vault_create` checks the password (`password::check`), then `LocalVault::create` runs in one transaction: new KDF parameters, the master key, random account keys, a random recovery key, a personal vault (ULID) and its key sealed to the account. It returns the recovery key; the command returns its code, which the UI shows once and never stores. A vault created without an account gets a one-time offer to turn on sync a week later, not at once: the first screen offered an account already. The time is kept in the WebView's local storage (`syncOfferTime` in `SyncPanel.tsx`), checked when the workspace opens, and dropped once the offer is answered or sync is on. After a device was erased, the first screen says why above the form (see [Resetting](#resetting)).

**Invited before there's a vault.** An invite link opened before the vault exists (the website's **Open in MorphGate**) waits in the link queue; the first screen reads it without taking it (`links_peek`) and looks it up on the server the link names, which needs no account (`invite_peek`, `GET /v1/invites/{token}`). Above the choice: "{inviter} invited {email} to join {team} as a member. Create your account with that address, or sign in if you have one: Teams then opens with the invite." The choice starts on **New account** with the server and address filled in. Without a link, **Joining a team? Paste your invite** takes the code, the invite page's address or a `morphgate://invite` link (`links_add_invite`) and does the same; a bare code is looked up on morphgate.com, quietly. Once there's an account, the workspace takes the invite and opens Teams with it looked up ([Deep links](deep-links.md)).

**Suggested passwords.** **Suggest a strong password** (in `NewPasswordFields`, so also for recovery and password change) asks `password_suggest`: five words picked with the system's random generator from EFF's long wordlist (`src-tauri/wordlist/`, 7772 words without the four that contain a hyphen, about 64 bits), joined by hyphens, drawn again in the rare case the strength check would refuse them. Both fields get it, and it shows in the clear under the meter ("Five random words. Write them down, or save them in a password manager: you'll need them to unlock MorphGate.") with **Suggest another**, until either field changes. Never a fixed example: those end up in cracking wordlists.

## Master password rules

| Rule | Where | Value |
| --- | --- | --- |
| Length, in characters (not bytes) | `mg_store::MIN_PASSWORD_CHARS`, also `password::MIN_CHARS` and `MIN_CHARS` in `VaultGate.tsx` | 10 |
| Hard to guess: zxcvbn's estimate | `password::MIN_GUESSES_LOG10` (`zxcvbn` 3.1) | at least 10^10 guesses |
| Character classes | None | |

Why (`password.rs`): the password is stretched with Argon2id at 256 MiB and 3 passes, so 10^10 guesses is months for a rig of GPUs. Rules like "one digit, one symbol" produce exactly the predictable choices ("Summer2024!") that the estimate refuses, while passphrases of unrelated words pass (NIST SP 800-63B). Passwords set before the rule keep working: it applies only when a password is set (`vault_create`, `vault_change_password`, `vault_recover`).

| Error | From |
| --- | --- |
| "the master password needs at least 10 characters" | `password::check` |
| "that master password is too easy to guess: … A few unrelated words make a strong one.", with zxcvbn's warning (or "it follows a pattern cracking tools try early") in the gap | `password::check` |
| "master password must be at least 10 characters" | `mg-store` (`check_password`) |

The meter (`NewPasswordFields`, used by setup, recovery and password change) asks `password_strength` 120 ms after typing stops. Empty, it reads "At least 10 characters, not easy to guess: a few unrelated words make a strong one." Then: "Too short: at least 10 characters"; "Checking…"; "Too easy to guess." with zxcvbn's warning or first suggestion (two bars from 10^8 guesses, one below); "Strong" (three bars). The submit buttons stay disabled until the estimate says `ok`.

## Unlocking

`UnlockScreen` (`VaultGate.tsx`), titled **Unlock MorphGate**:

| Control | Does |
| --- | --- |
| **Unlock with Touch ID** (or Face ID, Windows Hello, system authentication, your passcode, fingerprint or face) / **Unlock with system keychain** | Shown when keychain unlock is on: `vault_unlock_keychain`. Without a presence check it reads **Unlock with system keychain** |
| **Master password**, **Unlock** ("Unlocking…") | `vault_unlock` |
| **Forgot password? Use your recovery key** | The recovery form below |

The footnote says "Locks after N minutes without use. Locking closes open sessions." (only the second sentence with auto-lock off). Keychain unlock is tried by itself once, at app launch; after any lock it takes a click (`triedKeychain`, set for good by `noKeychainAutoUnlock` once the workspace opens). A cancelled OS prompt shows nothing.

`vault_unlock` runs Argon2id on a blocking thread (about a second), unwraps the account keys ("wrong master password" on failure), opens the personal vault key and checks its id, opens every shared vault's key ring, loads the pinned keys, and pokes the sync loop. On phones, `MobileUnlock` shows the same choices for thumbs: a large presence button, **Unlock with …**, **Use master password**, **Unlock**, and **Forgot password? Use your recovery key**; the password field shows first when there is no presence unlock.

## Locking and auto-lock

`vault_lock` stops every tunnel, closes the SFTP browsers, shuts down VPNs, and forgets the keys. The webview then shows the unlock screen; the workspace unmounts, and each terminal disconnects its session as it unmounts (`TerminalView`). The lock button is the lock icon at the top of the sidebar ("Lock vault (closes open sessions)") or in the phone header.

| Setting | Value |
| --- | --- |
| Key | `auto_lock_minutes` in `settings` (`AUTO_LOCK`) |
| Default | 15 minutes while unset (`AUTO_LOCK_DEFAULT`). Devices from before the default, which stored "never" as no value, lock after 15 minutes now |
| Never | `0`, stored as a value so it stays apart from "not chosen" |
| Maximum | 24 hours (`set_auto_lock` caps it) |
| Choices | **Lock when idle** in Security: **Never**, **After 5 minutes**, **After 15 minutes**, **After 30 minutes**, **After 1 hour**, **After 4 hours** |

The timer is the webview's (`useIdleLock` in `App.tsx`): `keydown`, `mousedown`, `mousemove`, `wheel` and `touchstart` in MorphGate's window reset it, and it checks every 10 seconds. Use of other apps doesn't count.

## Recovery key

The code is shown once, at creation and when a new one is made (`RecoveryCode`: copy, the "I stored it somewhere safe" checkbox, then the action button). Neither the key nor the code is stored.

**Forgot the password, on this device.** **Forgot password? Use your recovery key** opens **Use your recovery key**: **Recovery key** (a text area), **Master password**, **Repeat password**, **Set new password** ("Re-encrypting…"), **Back to unlock**. The footnote says whether sync is on. `vault_recover` checks the new password, then without sync `LocalVault::recover`: parse the code, unwrap the account keys from the local `wrapped_private_keys_rk`, check they are this vault's ("that recovery key does not match this vault"), wrap them under the new password with fresh KDF parameters, and unlock. With sync the server goes first (`mg_store::account::recover`). On a fresh device, recovery goes through **Sign in**, **Forgot the master password? Use your recovery key** ("Reset password and sign in", **Reset and sign in**).

**A new recovery key.** Security, **Recovery key**: **Master password**, **Create a new recovery key** ("Creating…"). `vault_new_recovery_code` makes a new key and replaces `wrapped_private_keys_rk` and `recovery_proof`; the password wrapping stays. The old code stops working at once (on the server too, with sync on). Nobody is signed out.

## Changing the master password

Security, **Master password**: **Current master password**, **New master password**, **Repeat password**, **Change master password** ("Re-encrypting…"; disabled until the new password is strong, repeated and different from the current one, and while the device is signed out of sync). On success: "Master password changed." (with sync: "… here and on the sync server.").

`vault_change_password` verifies the current password, derives the new one with fresh KDF parameters, and re-wraps the account keys (`prepare_password_change`, then `apply_credentials`). No item is re-encrypted, and keychain unlock keeps working because the device key wraps the account keys, not the password. With sync on, the server takes the new credentials first and the other devices are signed out until they sign in with the new password ([Account and devices](account-and-devices.md)).

## Keychain and biometric unlock

Each device can add a quicker unlock: a random device key kept by the OS keychain (optionally behind Touch ID, Windows Hello or polkit), sealed by Android's Keystore behind a fingerprint or face, or kept in the iOS keychain behind Face ID, Touch ID or the passcode. The vault keeps the account keys wrapped under it in `device_unlock`. It survives password changes and recovery and never syncs. Commands (`keychain_enable`, `keychain_disable`, `vault_unlock_keychain`, `presence_require`, `presence_setup`, `device_status`), platforms, UI and the device settings it shares a table with: [Keychain and biometric unlock](device-unlock.md).

## Export

Security, **Export**: **Include passwords, private keys and VPN credentials**, **Include the team vaults you can open** (a warning appears with secrets ticked), **Master password (to confirm)**, **Export vault** ("Exporting…"), then "Saved" and the file's path.

`vault_export` verifies the master password and calls `LocalVault::export_plaintext`. The file is JSON, format `morphgate-vault-export/1`: `format`, `exported_at`, `about`, `secrets_included`, and `vaults` (each with `id`, `name` ("Personal" for the personal vault), `organization`, `personal`, `items`, every item with its `id`, its fields and `updated_at`). It is written as `morphgate-vault-<date>.json` in Downloads (the home folder if there is none, Documents on iOS), `-2`, `-3`… if taken, new and mode 0600 on Unix.

| Left out | How |
| --- | --- |
| Member key directories, unknown kinds | Not exported |
| Session-log chunks, attachment contents | `chunks` and `blob` removed; saved one by one elsewhere |
| Without secrets | `auth.password`, `private_key`, `passphrase`, the VPN `password`, WireGuard `PrivateKey` and `PresharedKey` lines, and OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<askpass>`, `<auth-user-pass>` blocks become `(not exported)` |

Only a device with the keys can make this file; the sync server's account export holds no vault contents ([Account and devices](account-and-devices.md#download-your-data)).

## Resetting

| How | What goes |
| --- | --- |
| Signed out from another device (`401 device_revoked`), or **Disconnect** choosing to remove everything | `erase_device`: tunnels, SFTP and VPNs stop, the keychain entry (or Android's Keystore key) goes, `LocalVault::erase` empties every table and runs `VACUUM`, sync state is forgotten, and the window returns to first run with `device-erased`. The notice names the sync account. See [Account and devices](account-and-devices.md) |
| Deleting `vault.sqlite3` with the app closed | Everything on this device that didn't sync. A keychain entry stays behind, harmless without the wrapped keys |

`erase` leaves the schema and the `known_hosts` file. There is no reset button for a vault that doesn't sync.

## Errors

| Error (`mg_store::Error`) | Shown as |
| --- | --- |
| `NotInitialized` / `AlreadyInitialized` | "no vault has been set up yet" / "a vault already exists" |
| `Locked` | "the vault is locked" |
| `WrongPassword` | "wrong master password" |
| `WrongRecoveryKey` | "that recovery key does not match this vault" |
| `Invalid` | Its message, e.g. a malformed recovery code ("malformed data: recovery code has a typo (checksum mismatch)") |
| `Corrupt` | "vault data is corrupt: …" |
| `Crypto` | The `mg-vault` message ([Vault cryptography](vault-crypto.md)) |

## Tests

| Where | Covers |
| --- | --- |
| `crates/mg-store/src/vault.rs` | `lifecycle_status`, `short_password_is_rejected`, `persists_and_stores_only_ciphertext` (and mode 0600), `tampered_or_swapped_envelopes_are_rejected`, `recovery_resets_password_and_keeps_items`, `change_password`, `prepared_credentials_change_nothing_until_applied`, `another_accounts_keys_are_refused`, `erase_leaves_a_first_run_device` (nothing of the old vault left in the file) |
| `crates/mg-store/src/device.rs` | `settings_round_trip` |
| `crates/mg-store/src/export.rs` | Secrets only when asked, OpenVPN key blocks emptied, dates |
| `apps/desktop/src-tauri/src/password.rs` | Predictable passwords refused, passphrases pass |
| `apps/desktop/src-tauri/src/device.rs` | `auto_lock_is_15_minutes_until_chosen` |
| `apps/desktop/e2e/` | Every scenario creates a vault (`createVault`); `appimage.mjs` unlocks the same vault after a self-update; `mobile.mjs` locks and unlocks on the phone screen. `flows.mjs` defines `changePassword`, `recoverOnUnlock` and `createVaultKeepingKey`, which no scenario calls yet |

`cargo test -p mg-store`; tests derive keys at the KDF floors (`with_kdf_cost`). The keychain, presence and biometric tests are listed in [Keychain and biometric unlock](device-unlock.md#tests).

## Limits

- The idle timer sees only input in MorphGate's own window. With **Never**, the vault stays unlocked until it is locked by hand or the app quits.
- With a forgotten password and no recovery key, the vault can't be opened. A device that still unlocks through the keychain can use its items but can't export, change the password or make a new recovery key: all three ask for the master password.
- A copy of `vault.sqlite3` holds `recovery_proof` and, with sync on, the account email in the clear. The proof can't decrypt anything, but the server accepts it at `POST /account/recover`.
- The fresh-device recovery command (`sync_recover_sign_in`) enforces only the 10-character length in Rust; the zxcvbn bar is the form's.
