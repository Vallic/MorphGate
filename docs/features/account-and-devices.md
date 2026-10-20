# Account and devices

Each install that signs in to a sync account is a device. The server keeps a record of it (name, platform, app version), lists it to the account's other devices, and can sign it out; a device signed out that way erases itself the next time it connects, so a lost laptop stops holding the account's vault once it is back online. This page covers the device record, the **Devices** list, signing devices out and disconnecting, password changes and recovery with sync, the account's email and terms, the server's web account page, deleting the account, and the two things an organization can make a device wait for: approval and single sign-on. Code: `apps/desktop/src-tauri/src/sync.rs` (`device_name`, `device_info`, the account and device commands), `crates/mg-store/src/account.rs` (`change_password`, `recover`, `delete_account`, `change_email`), `crates/mg-store/src/sync.rs` (`disable_sync`), `apps/desktop/src-tauri/src/vault.rs` (`erase_device`), `apps/desktop/src/SyncPanel.tsx` (`Devices`, `Enabled`, `Account`, `EmailChange`, `DeleteAccount`, `TermsUpdate`), `apps/desktop/src/VaultGate.tsx` (`erasedNotice`), `apps/desktop/src/ApprovalWait.tsx`, `apps/desktop/src/SsoSignIn.tsx`, `apps/desktop/src-tauri/src/orgs.rs` (`org_sso_status`, `org_sso_start`).

`apps/desktop/src-tauri/src/device.rs` is about unlocking this device (keychain, biometrics, auto-lock), not the server's device record; see [Keychain and biometric unlock](device-unlock.md) and [Vault and unlock](vault-and-unlock.md). Signing in, tokens and the sync round are in [Sync](sync.md).

## The device record

`device_info()` builds what the device says about itself (`mg_sync::DeviceInfo`):

| Field | Value |
| --- | --- |
| `id` | A new ULID for each sign-up and fresh sign-in (`new_device`: `sync_enable`, `sync_sign_in`, `sync_join`, `sync_recover_sign_in`). **Sign in again** and recovery on a synced device keep the stored one. Kept in `sync_state.device_id` |
| `name` | `device_name()`, cut to 100 characters (below) |
| `platform` | `macos`, `windows`, `android` or `ios`; anything else (Linux, a BSD) is `linux`, the spec's closest |
| `client_version` | The app version (`CARGO_PKG_VERSION`) |
| `public_key` | The Ed25519 public half of a throwaway key pair. "A device key is not used for signing yet; a valid Ed25519 public key keeps the door open." Kept in `sync_state.device_public_key` |

| Platform | `device_name()` |
| --- | --- |
| Windows | `COMPUTERNAME` |
| macOS, Linux | `gethostname()`, without macOS's `.local` |
| Android | Maker and model from system properties, "Google Pixel 8"; a model that already starts with its maker stays as it is |
| iOS | "iPhone" or "iPad": all an app may know there (the simulator reports the model it plays) |
| Fallback | "MorphGate desktop", "Android device", "iPhone" |

The same name labels session logs and the Vallic Cloud sign-in ("MorphGate on {name}").

The device sends the record in the `device` field of `POST /v1/auth/register` and `POST /v1/auth/login`. Because a name or version changes later (an app update, a renamed computer, a phone that once said Linux), `sync::run` also sends `PATCH /v1/devices/{device}` with `{name, platform, client_version}` once per app run, after the first round that worked (`SyncState.device_told`). A `404` or `405` (a server without it) counts as done; any other error is tried again next round. Servers refuse another device's id (`403`) and a blank name (`400`).

## Devices

The Sync panel lists the account's devices under **Devices** (hidden while signed out). `sync_devices` calls `GET /v1/devices`; the list loads again after every round and after a sign-out.

| Shown | From |
| --- | --- |
| Name, in bold | `name` |
| **this device** badge | `current` |
| Platform | `platformName()`: macOS, iOS, Linux, Windows, Android |
| "last seen 5 min ago", or "added …" for a device never seen | `last_seen_at`, `created_at` |

The app version is in the record but not shown (`DeviceView` leaves `client_version` out).

## Signing out another device

Every row except this device has **Sign out**, which turns into **Really sign out?**. That calls `sync_revoke_device`, `DELETE /v1/devices/{id}`. The hint under the list: "Signing a device out stops it syncing and, the next time it connects, removes everything MorphGate keeps on it. Changes it hadn't synced yet are lost." This device leaves with **Disconnect this device** instead. Signing a device out also makes the server forget its organization approvals ([spec](../sync-crypto-spec.md#auth--devices)).

## A signed-out device

A device signed out from elsewhere learns it on its next token refresh: `401 device_revoked`, which servers keep answering for as long as the device's refresh token would have lasted, so a device that was offline learns it too. That happens in a round, and rounds run only while the vault is unlocked (the refresh token reads only then); a device that is never unlocked or never reaches the server again keeps its vault, encrypted with the master password.

`erase_device(app, "signedOut")` then:

1. stops tunnels, closes SFTP sessions and VPNs;
2. on Android forgets the biometric key; elsewhere deletes the keychain entry;
3. empties every table of the vault and runs `VACUUM`, so the data is gone from the file too (`LocalVault::erase`);
4. drops the sync session and what the last rounds learnt (`SyncState::forget`);
5. emits `device-erased` with `{reason, email}`, and the window returns to the first screen with:

> This device was signed out of {email} from another device, so MorphGate removed everything it kept here. To use the account again, sign in under “I have an account”.

The spec's reason: the account signed this device out, so the device forgets what it keeps from the account. Every other `401` on refresh only means "sign in again" and keeps the data; see [Sync](sync.md#tokens).

## Disconnecting

| Control | Does |
| --- | --- |
| **Disconnect this device** | Opens the choice: "Disconnect this device from {email}? Your other devices keep syncing, and the account keeps everything that has synced." |
| **Remove everything from this device** | `sync_disable(remove: true)` |
| **Keep a copy here** | `sync_disable(remove: false)` |
| **Cancel** | Closes the choice |

Both first end the session with `POST /v1/auth/logout` when one is open, ignoring errors: offline, the session stays on the server until it expires or another device signs this one out.

- **Remove everything** runs `erase_device(app, "disconnected")` as above, and the first screen says: "MorphGate removed everything it kept on this device. Your vaults are still in {email}: sign in under “I have an account” to get them back." Unsynced changes are lost.
- **Keep a copy** runs `disable_sync()`: it deletes the sync settings and token, the team vaults and organizations (they belong to the team on the server) and tombstones, and marks every remaining item unsynced (`rev` 0, dirty) with every vault's `head_rev` back to 0. Unsynced changes stay. Turning sync on again, on any server, uploads the whole personal vault.

Moving to another server: on one device **Keep a copy here**, then **Enable sync** with the new address. Other devices either remove everything and sign in on the first screen, or keep a copy and use **I have an account** in the Sync panel; their items join the account's vault with the same ids, so identical items merge and differing ones become "(conflict)" copies ([Sync](sync.md#conflicts)).

## Changing the email

Offered as **Change email** when the server verifies addresses (`features.email_verification`).

| Step | Controls | Call |
| --- | --- | --- |
| 1 | **New email**, **Send code** ("Sending…") | `sync_email_start`: `POST /v1/account/email/start {new_email}`; `409 account_exists` is "That address already has an account on this server." |
| 2 | **Code sent to {email}**, **Master password**, **Change email** ("Changing…") | `sync_email_change`: `PUT /v1/account/email {new_email, code, auth_key}`; a wrong code is "that code is wrong or has expired" |

The password is checked locally and sent as the AuthKey. On success this device stores the new address (`set_sync_email`); it signs in with it from then on. The hint says "Your other devices pick up the new address on their own. The old address gets a notice." Another device does so when its Sync panel loads the account (`sync_account` compares the server's address with the stored one).

## Password changes and recovery

The master password and the recovery key are the account's, so with sync on the server takes new credentials first; if it can't be reached or refuses, this device keeps its current password, "so the two never disagree about which password opens the vault" (`crates/mg-store/src/account.rs`). The screens are in [Vault and unlock](vault-and-unlock.md); the sync side:

| Action | Command | With sync |
| --- | --- | --- |
| Change the master password (Security) | `vault_change_password` | `account::change_password`: checks the current password here and prepares new KDF parameters, AuthKey and wrapped keys, sends `PUT /v1/account/keys {current_auth_key, new_kdf, new_auth_key, wrapped_private_keys}`, then applies them here. The server signs the other devices out; each shows **Sign in again** and, with the new password, re-wraps its own keys (`sign_in_again`, `adopt_credentials`) |
| New recovery key (Security) | `vault_new_recovery_code` | `account::new_recovery_key`: the same request with the password unchanged and a new `recovery {wrapped_private_keys_rk, recovery_proof}`. Nobody is signed out; the old code stops working on the server too |
| Forgot the password, on a synced device (unlock screen) | `vault_recover` | `account::recover`: `POST /v1/account/recover {email, recovery_proof}` returns the recovery-wrapped keys and a short-lived token that only allows `PUT /v1/account/keys`; the new credentials are made here from the recovery code and sent without a current AuthKey; then the device signs in again with the new password and its own device id, without a code (recovery turns two-step verification off), and only then stores them. Every other device is signed out |
| Forgot the password, fresh device (**I have an account**, **Forgot the master password? Use your recovery key**) | `sync_recover_sign_in` | `account::recover_and_sign_in`: the same on the server, then an ordinary sign-in with the new password ([Sync](sync.md#signing-in)) |

A recovery code the server doesn't accept is "the sync server doesn't accept this recovery code for that account". While signed out, account changes stop at "this device is signed out of sync; sign in again (Sync panel) before changing the account". Server side: `PUT /v1/account/keys` and `POST /v1/account/recover` in `spec/openapi.yaml`, and the single-use recovery token in the [spec](../sync-crypto-spec.md#auth--devices).

## Terms

When the server has terms (`features.terms`) and the account hasn't accepted their current version, the Account section shows "The terms of use and the privacy policy are new or have changed since you accepted them: please review and accept them." with both links and **Accept**, which sends `PUT /v1/account/terms {accepted_terms: <version>}` (`sync_accept_terms`). New accounts accept them at sign-up ([Sync](sync.md#creating-an-account)).

## The Account section

Beside the Sync panel while signed in (`sync_account`: `GET /v1/account` plus discovery). It shows only what the server offers, and loads again after every round.

| Shown | When |
| --- | --- |
| **Plan** | The server sends a plan ([Sync](sync.md#plans-and-payment-errors) has the texts) |
| **Email**: Not verified | `email_verified` is false |
| **Two-step verification**: On / Off | `features.totp` |
| **Turn on two-step verification** / **Turn off two-step verification** | `features.totp`; see [Sync](sync.md#two-step-verification) |
| **Change email** | `features.email_verification` |
| **Manage account ↗** | `features.billing.web_session`, and not on iPhone, iPad or Android (`mobileOs`), whose stores don't allow pointing at buying elsewhere |
| **Download your data** | Always; a server without an export says "this sync server doesn't offer a data export" |
| **Delete account…** | Always |

### Opening the account page

**Manage account ↗** calls `sync_open_portal`, which asks for `POST /v1/account/web-session` and opens the returned single-use `url` in the browser (`util::open_in_browser`, web addresses only). With `next`, the link lands on that page instead of `/account`: Teams sends `/account/team/{org}/billing` (**Choose a plan ↗**, **Manage plan ↗** on a team) and `/account` (the team-limit notice). The spec allows only `/account`, `/account/two-step` and `/account/team/{org}[/{tab}]` (anything else is `400 bad_request`), and the link is valid for the `expires_in` seconds the server returns.

### Download your data

`sync_export_account` fetches `GET /v1/account/export` and saves it as `morphgate-account-{date}.json` in Downloads (the date from the export's `generated_at`; on iOS the app's documents, shown as "Files › MorphGate"). The panel says "Saved {path}: what the server keeps about your account. Your hosts and keys aren't in it; the server can't read them."

## Deleting the account

**Delete account…** in the Account section:

- If the account owns a team (from the Teams list), the panel says "You own {teams}. Transfer it to an admin or delete it in Teams first: an account that owns a team can't be deleted." with **Cancel** and **Open Teams**.
- Otherwise: "Deletes {email} from the sync server with everything it keeps for it: the synced copy of your vault, your devices, your team memberships and any subscription. This can't be undone.", then "This device keeps its vault, with sync off; items from team vaults leave it. Your other devices stop syncing and keep what they have. A team you own has to be transferred or deleted first.", **Master password** and **Delete account** ("Deleting…").

`sync_delete_account` checks the password locally (Argon2id) and sends `DELETE /v1/account {auth_key}`.

| Answer | What happens |
| --- | --- |
| `204` | `disable_sync()` as for **Keep a copy here**; the session is dropped; the panel says "Your account {email} is deleted. This device keeps its vault, with sync off." |
| `409 sole_owner` | "you own a team: transfer it to an admin or delete it (Teams), then delete your account"; the button becomes **Open Teams** |
| `billing_unavailable` | "the subscription couldn't be cancelled just now, so nothing was deleted: try again in a minute" |
| `invalid_credentials` | "the sync server doesn't take this master password: if it was changed on another device, sign in again first" |

The account's other devices hear `401 account_deleted` on their next refresh (a device signed out before the deletion still hears `device_revoked` and erases itself). They turn sync off the same way, keeping the personal vault, now the only copy, and dropping team vaults, and the window says "The sync account {email} was deleted (on another device or the website). Its team vaults left this device; your own vault stays here, no longer syncing." Deleting the account on a server's website, where it has one, has the same effect.

## When an organization holds this device

An organization can keep its vaults from a device until something is settled. Its vaults that are already here stay, unsynced edits included, and sync once it is settled; the personal vault is never affected. The shared part of each round notes the hold (`Hold` in `crates/mg-store/src/sync.rs`) from a `403 sso_required` or `403 device_approval_required` on the organization's vaults, and, with device approval on, from this device's row in `GET /v1/orgs/{org}/devices`. `SyncStatusView` carries them as `ssoRequired` and `approvalRequired`. The team side (approving others, policies) is in [Teams](teams.md#device-approval-single-sign-on-and-activity).

### Waiting for approval

| Where | Shows |
| --- | --- |
| Sidebar foot | **Waiting for approval · {team}**, or **{team} denied this device** |
| Phone, hosts screen | "Waiting for {team}" (or "{team} denied this device") with a line saying why |
| `ApprovalWait` dialog | Title "Waiting for {team}" or "{team} denied this device"; who can approve: "An owner or admin can approve this one, or you can, from another of your devices that the team approved: Teams › {team} there."; **Close** and **Check again** (runs a round, then closes) |

The first refusal files the request on the server, so the device only waits ([spec](../sync-crypto-spec.md#auth--devices)).

### Single sign-on

**Sign in to {team}** in the sidebar (or on the phone's hosts screen, or **Sign in** on the team page) opens `SsoSignIn`:

1. It reads `GET /v1/orgs/{org}/sso` (`org_sso_status`) to name the provider by its issuer's host, and explains: "{team} keeps its vaults behind single sign-on. Sign in at {provider} in your browser; its vaults sync on this device once you're back. Your master password still protects everything: single sign-on only adds to it."
2. **Sign in** (disabled when the organization has no provider) calls `org_sso_start`: `POST /v1/orgs/{org}/sso/start`, which returns `{url, expires_in}`; the command opens the URL in the browser.
3. The dialog says "Finish signing in in your browser. This updates by itself.", offers **Open it** in case the page didn't open, and polls the status every 2 seconds (`POLL_MS`) until it has `session_expires_at`. Then it runs a round and closes. Past `expires_in`: "The sign-in expired. Start it again."

**Not now** (or **Cancel** while waiting) closes it; the sidebar keeps offering it. The protocol side is in the [spec](../sync-crypto-spec.md#auth--devices).

## Tauri commands

| Command | Does |
| --- | --- |
| `sync_account` | The account and what the server offers for it; stores a changed address |
| `sync_devices` | The account's devices |
| `sync_revoke_device` | Signs another device out |
| `sync_disable` | Signs this device out; `remove` erases it, otherwise keeps the personal vault unsynced |
| `sync_email_start`, `sync_email_change` | Changing the address |
| `sync_accept_terms` | Accepts the server's current terms |
| `sync_open_portal` | Opens the account page signed in, optionally on `next` |
| `sync_export_account` | Saves the account data export; returns where |
| `sync_delete_account` | Deletes the account; this device keeps its vault |
| `org_sso_status`, `org_sso_start` | Single sign-on status and start (in `orgs.rs`) |
| `vault_change_password`, `vault_new_recovery_code`, `vault_recover` | In `vault.rs`; the server goes first when sync is on ([above](#password-changes-and-recovery)) |

All of them hold the sync lock, and those that keep the session store a rotated refresh token afterwards ([Sync](sync.md#tokens)).

## Endpoints

| Endpoint | Used by |
| --- | --- |
| `GET /v1/account` | **Account** section, address check |
| `GET /v1/devices` | **Devices** |
| `PATCH /v1/devices/{device}` | Once per run, this device's record |
| `DELETE /v1/devices/{device}` | **Sign out** |
| `POST /v1/auth/logout` | **Disconnect this device** |
| `POST /v1/account/email/start`, `PUT /v1/account/email` | **Change email** |
| `PUT /v1/account/terms` | **Accept** |
| `POST /v1/account/web-session` | **Manage account ↗**, team plan buttons |
| `GET /v1/account/export` | **Download your data** |
| `PUT /v1/account/keys` | Password change, new recovery key, recovery |
| `POST /v1/account/recover` | Recovery |
| `DELETE /v1/account` | **Delete account** |
| `GET /v1/orgs/{org}/sso`, `POST /v1/orgs/{org}/sso/start` | `SsoSignIn` |
| `GET /v1/orgs/{org}/devices` | Each round, for organizations that require approval |

## Tests

| Where | What |
| --- | --- |
| `server/tests/account.rs` | `signing_out_another_device` (the other device gets `DeviceRevoked`, signs in again), `a_device_updates_what_it_says_about_itself` (and can't rename another, nor to blank), `deleting_an_account_tells_its_other_devices` (`AccountDeleted`, and `DeviceRevoked` for one signed out before), `the_data_export_tells_what_the_server_keeps` |
| `server/tests/account.rs`, `protocol.rs` | `password_change_reaches_every_device`, `recovery_on_a_synced_device_and_on_a_fresh_one`, `a_new_recovery_key_replaces_the_old_one_without_signing_anyone_out`, `password_rotation_signs_out_others_but_a_new_recovery_key_does_not`, `recovery_tokens_are_narrow_and_single_use` |
| `server/tests/device_approval.rs` | `a_new_device_waits_for_approval` |
| `crates/mg-store/src/sync.rs`, `vault.rs` | `token_and_config_roundtrip_and_disable` (what **Keep a copy here** leaves), `erase_leaves_a_first_run_device` |
| `apps/desktop/e2e/teams.mjs` | Bob signs his second device out from his first: it erases itself, the first screen says why, and signing in brings his vault back; a new device waits for approval, is denied, then approved from Bob's first device; Alice signs in to her team's identity provider from **Sign in to {team}**; **Download your data**; **Delete account…** sends an owner to Teams, deletes Bob's account, and his second device says the account was deleted |

The server tests run against another server with `VAULT_SYNC_URL`; see [Sync](sync.md#tests).

## Limits

- The app can't sign itself out of the server without disconnecting; **Sign out** is only offered for other devices.
- A signed-out device erases itself only when it is unlocked and reaches the server. Until then it holds its vault, encrypted; after a theft, also change the master password and the secrets the device held.
- Another device stores a changed address only when its Sync panel loads the account. If it is signed out before that, **Sign in again** uses the old address and fails ("wrong email or master password").
- **Manage account ↗** and the plan buttons don't exist on iPhone, iPad and Android.
