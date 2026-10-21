# Sync

Sync keeps the vault on every device through a server that speaks `vault-sync/v1`: morphgate.com (the hosted service the app offers by default) or a server you run, such as the [reference server](reference-server.md). The device encrypts and signs each item before it uploads it and checks each item it downloads, so the server only ever holds ciphertext, wrapped keys and revision numbers. Conflicts are resolved on the device, because only the device can read the data. This page covers the client: choosing a server, creating an account and signing in, tokens, the round that pulls and pushes, revisions, conflicts, plan errors and what the window shows. Code: `crates/mg-sync/src/client.rs` (`SyncClient`), `crates/mg-sync/src/types.rs` (wire types), `crates/mg-store/src/sync.rs` (the engine, `sync_once_with`), `crates/mg-store/src/sync_http.rs` (`HttpRemote`, wire conversions), `crates/mg-store/src/account.rs` (sign-in and account flows), `crates/mg-store/src/blobs.rs`, `apps/desktop/src-tauri/src/sync.rs` (Tauri commands, the background loop), `apps/desktop/src/SyncPanel.tsx`, `apps/desktop/src/SyncServerField.tsx`, `apps/desktop/src/TotpCode.tsx`.

Devices, disconnecting, password changes and recovery, email, the account page and deletion are in [Account and devices](account-and-devices.md); shared vaults in [Teams](teams.md); key derivation and envelopes in [Vault cryptography](vault-crypto.md); the order of a round in [App architecture](../architecture.md#how-sync-runs).

## Choosing a server

`SyncServerField` is the same everywhere a server is asked for (sign-up, both sign-ins):

| Control | Does |
| --- | --- |
| **Sync server**: **morphgate.com** / **Your own server** | Segmented choice. morphgate.com is the default (`HOSTED_SERVER` = `https://morphgate.com`), with the hint "MorphGate's hosted sync. Like any vault-sync server, it only ever stores what this device encrypted." |
| **Server address** | Only for your own server; placeholder `https://sync.example.com` |
| Warning | An `http://` address other than `localhost`, `127.0.0.1` or `[::1]`: "Plain http:// would send your sign-in unencrypted over the network, so MorphGate takes it only for a server on this computer (localhost). Use https://." The sync client then refuses the address (below) |
| **Check** | Sign-up form only: runs discovery (below) |

`SyncClient::new` takes `https://`, and `http://` only for this computer (`localhost` or a loopback address): elsewhere the `AuthKey` and the tokens would cross the network readable ("use https:// (plain http:// only for a server on this computer: localhost, 127.0.0.1 or [::1])"). An address with a user name or password is refused. It keeps only the origin: it drops any path, query and fragment, so the API is always `<origin>/v1/` and discovery `<origin>/.well-known/vault-sync`. Redirects aren't followed (the API never redirects, and following one could leave HTTPS or the server). Every request has a 30-second timeout and the user agent `MorphGate/<version>`.

### Discovery

`sync_check` calls `GET /.well-known/vault-sync` (no session). The client refuses a document whose `spec` isn't `vault-sync` or whose `versions` lacks `v1`, and also a request that fails or a body that doesn't parse, all as "{origin} does not speak vault-sync/v1".

| Field | What the client does with it |
| --- | --- |
| `server.name`, `server.version` | The line under **Check**: the name (or "vault-sync server"), the version only when it starts with a digit (a server built from source says `dev`), then "— accepts new accounts" or "— not accepting new accounts" |
| `features.registration_open` | The same line. `sync_enable` refuses before sending anything: "This server does not accept new accounts." |
| `features.terms` (`version`, `terms_url`, `privacy_url`) | The **I accept the terms of use and the privacy policy.** checkbox at sign-up (both links open in the browser), and later the notice when the terms change ([Account and devices](account-and-devices.md#terms)) |
| `features.email_verification` | A mailed code at sign-up; **Change email** in the Account section |
| `features.totp` | The two-step verification buttons |
| `features.billing` | `web_session`: **Manage account ↗**; `plans_enforced`: teams without a plan become read-only ([Teams](teams.md#plans)) |
| `features.sharing`, `features.blobs`, `features.sso` | Teams, attachments and session logs, single sign-on |
| `features.sse`, `limits` | Not read. The client polls, and uses its own page and batch size of 500 (`PAGE` in `sync_http.rs`, `MAX_PUSH` in `sync.rs`), the `max_push_items` the reference server advertises |

For morphgate.com the sign-up form runs discovery when it opens, so the terms checkbox is there before anything is typed. For your own server, **Check** runs it, or **Enable sync** does. The round keeps the document for an hour (`CAPABILITIES_FOR` in `crates/mg-store/src/sharing.rs`).

## Creating an account

Sync starts from the Sync panel (the sidebar foot reads **Sync off**), or from the **Sync this vault?** dialog offered once right after a vault is created (`SyncOffer`, with **Not now**). Under **New account**, the device makes an account from the vault it already has. The aside lists **What the server stores**: the email and devices, encrypted items it can count but not read, and never the master password.

| Control | Notes |
| --- | --- |
| **New account** / **I have an account** | Segmented choice; the second is [joining](#signing-in) |
| **Email** | |
| **Master password (to confirm)** | This vault's password; it becomes the account's. Hint: "Your master password becomes the sync account password. It is never sent; only a key derived from it is." |
| **Code sent to {email}** | Appears after the first **Enable sync** on a server with `email_verification`, with **send a new code** and **sign in to it** (switches to **I have an account**) |
| Terms checkbox | When the server has terms; **Enable sync** stays disabled until it is ticked |
| **Enable sync** | Busy text "Creating account and uploading…" once a code was sent, "Checking…" otherwise (on a server without codes, for the whole sign-up) |

`sync_enable`:

1. Takes the sync lock (`SyncState.running`), so no round starts with an old token meanwhile.
2. Runs discovery and refuses a closed server.
3. `export_for_registration` checks the password here (Argon2id) and gathers what the server needs. A vault created before recovery proofs were stored gets a new recovery key, shown once: "This vault predates stored recovery keys, so a new recovery key was created for your sync account. The old one no longer works."
4. Makes a device id and key (`new_device`, see [Account and devices](account-and-devices.md#the-device-record)).
5. `POST /v1/auth/register`, then `POST /v1/vaults` with the personal vault's id, key id and wrapped vault key.
6. Stores the server, email, account and device ids (`sync_state`) and the sealed refresh token, then runs a round. Every item is still `rev` 0 and dirty, so the round uploads the whole vault.

The register body:

| Field | Holds |
| --- | --- |
| `email`, `email_code`, `accepted_terms` | The address, the mailed code (when asked), the terms version ticked |
| `kdf` | `{alg: "argon2id", m_kib, t, p, salt}` |
| `auth_key` | Derived from the master key; the server stores only a slow hash of it |
| `keys` | `enc_public_key`, `sign_public_key`, `wrapped_private_keys` (the account private keys under the password-derived key) |
| `recovery` | `wrapped_private_keys_rk` (the same keys under the recovery key), `recovery_proof` |
| `device` | `id`, `name`, `platform`, `client_version`, `public_key` |

Nothing in it decrypts anything. See [Vault cryptography](vault-crypto.md) for how the keys are made.

| Server answer | The form says |
| --- | --- |
| `409` | This email already has an account on that server: choose "I have an account" to sign in to it. |
| `email_code_required` | This server needs the code it mails to that address. |
| `invalid_code` | That code is wrong or has expired. Send a new one. |
| `terms_not_accepted` (the form checks first) | Accept the terms of use and the privacy policy first. |
| Wrong password (checked locally) | wrong master password |

### Email verification codes

On a server with `email_verification`, the first **Enable sync** sends `POST /v1/auth/register/start {email}` (`sync_start_registration`) and shows the code field. The server answers the same whether the address is free or taken; for a taken one it mails a notice instead of a code, so the form can't be used to find accounts, and the hint says so. The field is `TotpCode` with its own label: digits only, six of them (`isTotpCode`). Changing the email or the server starts over. Code lifetime and limits are the server's.

## Signing in

| Where | Command | What it does |
| --- | --- | --- |
| First screen, **I have an account**, titled **Sign in to sync** | `sync_sign_in` | For a device with no vault ("This device already has a vault." otherwise): takes the account's keys and vault key, unlocks; items arrive with the first round |
| Sync panel, **I have an account** | `sync_join` | For a device with a vault of its own that never synced: its items, files included, move into the account's vault with the same ids, and it opens with the account's master password and recovery key from then on. Keychain unlock is set up again with the account's keys (Android's fingerprint unlock goes off). Refused with "this device syncs already" or "this device has team vaults: it synced before". A wrong password changes nothing |
| Sync panel while signed out, **Sign in again** | `sync_sign_in_again` | Same device id; re-wraps this vault's keys under the account's current password (it may have changed on another device) |
| First screen, **Forgot the master password? Use your recovery key** | `sync_recover_sign_in` | New password with the recovery key, then a sign-in; see [Account and devices](account-and-devices.md#password-changes-and-recovery) |

The join form's labels are **Email**, **The account's master password** and **Sign in** ("Signing in and merging…"); afterwards it says the device "opens with the account's master password. The password you chose on this device no longer works, and the account's recovery key replaces this device's."

A sign-in (`account::signed_in`):

1. `POST /v1/auth/prelogin {email}` returns the KDF parameters. Anything but Argon2id is refused ("unsupported KDF …"), and `mg-vault` refuses costs below its minimums.
2. Argon2id runs on a blocking thread; the master key gives the AuthKey.
3. `POST /v1/auth/login {email, auth_key, totp?, device}` returns the tokens, `account_id` and keys.
4. `GET /v1/account` (with the recovery-wrapped keys) and `GET /v1/vaults`; the vault without `org_id` is the personal one ("this account has no vault yet; enable sync from the device that created it" if none).
5. The keys are unwrapped with the password and checked against their public halves, and the vault key against its id ("the server's account keys do not match their public halves"), before anything is stored.

A `401` from login other than `invalid_totp` is "wrong email or master password": the server answers prelogin for unknown addresses with stable made-up parameters, so the client can't tell which was wrong.

### Two-step verification

Signing in: the first try goes without a code. The server answers `428 totp_required`, the command returns the bare string `totp_required` (`TOTP_REQUIRED`; `isTotpRequired()` in `api.ts`), and the form adds **Authenticator code** and submits again. `TotpCode` keeps digits only, at most six, with `autocomplete="one-time-code"` and placeholder `123456`. The first screen adds "This account has two-step verification. Lost the authenticator? Use your recovery key below." A wrong code (`401 invalid_totp`) is "that authenticator code is wrong; use the newest one". This applies to all three sign-ins; recovery needs no code, because recovery turns two-step verification off. Signed-in devices never need a code: refreshing a token doesn't ask.

Turning it on and off, in the Sync panel's **Account** section, only when the server has `features.totp`:

| Step | Control | Call |
| --- | --- | --- |
| Start | **Turn on two-step verification**, then "Confirm with your master password to set up an authenticator app.", **Master password**, **Continue** | `sync_totp_start`: `POST /v1/account/totp/start {auth_key}` returns the Base32 secret and an `otpauth://` URI; the app draws the QR code as SVG (`qrcode`, dark on white so it scans in either theme) |
| Scan | QR code, "Can't scan it? Enter this key instead:" (the secret in groups of four), **Authenticator code**, **Turn on** | `sync_totp_enable`: `POST /v1/account/totp/enable {code}` |
| Off | **Turn off two-step verification**, "New devices will sign in with the master password alone.", **Master password**, **Authenticator code**, **Turn off** | `sync_totp_disable`: `DELETE /v1/account/totp {auth_key, code}` |

The master password is checked locally first (`LocalVault::auth_key`, "wrong master password") and goes to the server as the AuthKey it wants as proof. While it is off, the section says "With two-step verification, signing in on a new device also needs a code from an authenticator app."

## Tokens

| What | How |
| --- | --- |
| Refresh token | The only token stored. Sealed as an envelope under the personal vault key with the pseudo item id `sync:refresh-token` (`TOKEN_ID`), in `sync_state.token`. It reads only while the vault is unlocked, so sync only runs unlocked |
| Access token | In memory. `SyncClient::resume` starts with an empty one, so the first request refreshes. A `401` on a request refreshes once and retries once. `expires_in` is ignored |
| Rotation | `POST /v1/auth/refresh` returns a new refresh token every time. Callers take it with `take_rotated_refresh()` after their calls and store it (`keep_token`, `keep_rotated`) |
| One at a time | Every round and every account command holds `SyncState.running`: "two requests refreshing the same token at once would look like token theft to the server", which signs a device out when an old refresh token comes back. Sign-up and sign-in commands hold it until the new client is in place |

A `401` on refresh:

| Code | Client error | Result |
| --- | --- | --- |
| `device_revoked` | `DeviceRevoked` | The device erases itself ([Account and devices](account-and-devices.md#a-signed-out-device)) |
| `account_deleted` | `AccountDeleted` | Sync goes off; the personal vault stays ([Account and devices](account-and-devices.md#deleting-the-account)) |
| Anything else (`invalid_credentials`: expired, a reused token, the password changed elsewhere) | `Unauthorized` | The stored token is cleared and the status becomes `signedOut`: the sidebar reads **Sign in to sync**, the panel says "Signed out of sync. If the master password was changed on another device, sign in again with the new one." (`SIGNED_OUT`) and shows **Master password of the sync account** with **Sign in again**. Nothing local is lost |

The first two stick (`SyncClient.ended`): whichever call hears them first, every later call gets the same answer instead of a bare "signed out". Token lifetimes are the server's.

## When sync runs

`spawn_loop` waits, then debounces, then runs one round:

| Situation | Wait |
| --- | --- |
| Someone is using the app: the window is visible and there was input in the last 5 minutes | 60 s (`INTERVAL`) |
| Nobody is | 300 s (`AWAY`) |
| A local edit or an unlock (`VaultState::changed()`), a device decision in Teams, or the user coming back (`sync_presence` turning true) | At once |
| Then, every time | 1.5 s (`DEBOUNCE`) |

The webview reports presence from `useSyncPresence` in `App.tsx`: keydown, mousedown, mousemove, wheel, touchstart and focus count as input, visibility changes report at once, and it re-checks every 30 s. **Sync now** (`sync_now`) runs a round at once, and sign-up and every sign-in run one when they finish. There are no push notifications: the client has no code for the spec's optional `GET /vaults/{id}/events`, and the reference server doesn't implement it (it advertises `sse: false`).

A round does nothing while the vault is locked, while sync is off, or while signed out.

## A round

`sync::run` holds the sync lock and marks `in_round` (what **Syncing…** shows), then:

1. **Shared vaults** (`sharing::refresh_with`): organizations, members, device approvals, and `GET /v1/vaults`, whose `head_rev` per vault decides what to pull. See [Teams](teams.md#each-sync-round).
2. **Every vault**, personal first (`sync_once_with`, `sync_vault`):
   1. Pull, unless the vault list showed the revision this device already has: `GET /v1/vaults/{id}/changes?since=<head_rev>&limit=500`, page after page until `has_more` is false.
   2. Drop local blobs no item refers to any more (a session log deleted elsewhere).
   3. With write access only: upload waiting blobs (`PUT /v1/vaults/{id}/blobs/{hash}`, before the items that refer to them), send blob deletions, and in a shared vault re-seal items still under an older key, finishing a rotation whoever started it.
   4. Push: up to 4 batches of 500 dirty items, `POST /v1/vaults/{id}/changes` with `{id, base_rev, deleted, envelope}` each.
3. **Afterwards**: store a rotated token; record `last_sync_at`, or `last_error`; tell the server what this device is (`PATCH /v1/devices/{device}`, once a run, after a round that worked); erase the device or turn sync off if the account said so; note which organizations hold their vaults; emit `vault-changed` (something pulled, or a conflict), `session-logs-changed` (blobs uploaded or refused) and `sync-status`.

The personal vault failing fails the round. A shared vault failing is listed and the others go on, except for `Unauthorized`, `DeviceRevoked`, `AccountDeleted` and a poisoned lock, which stop everything.

| Push result | What happens |
| --- | --- |
| `accepted` | The new `rev` is stored and `dirty` cleared, unless the item changed during the push (`updated_at` compared), in which case it goes again |
| `conflict` | The server's copy is applied as in [Conflicts](#conflicts) |
| `rejected`, `stale_key` | The item is re-sealed under the vault's current key and goes in the next batch |
| `rejected`, any other code | Skipped for the rest of the round, still dirty, tried again next round. Not shown anywhere (`SyncReport.rejected`) |

A deletion goes up as a tombstone (`deleted: true`) with its signed deletion envelope ([Item history](#item-history)); servers with `signed_tombstones` keep it (for items they have), others drop it. An item deleted before it ever synced (`rev` 0) is removed locally and never sent. A read-only vault only pulls.

## Revisions and anti-rollback

Each vault row keeps `head_rev`, the highest server revision this device has applied; each item keeps `rev`, the revision it is based on (0: never synced), and `dirty`. Pulled pages move the cursor to the last item's `rev` while `has_more`, then to the page's `head_rev`, in the same transaction as the items.

| Check | Effect |
| --- | --- |
| Every envelope in a page is verified (signature, author, vault key) before anything is written | One bad item rejects the whole page; nothing from it is applied |
| A shared vault's item may not take the id of a live personal item (lookups go by id) | "item {id} of a shared vault has the id of one in your personal vault" |
| A page whose `head_rev` is below the local `head_rev` | The vault fails: "the sync server sent older data (revision {remote}) than this device already has ({local}); refusing to roll back" (`SyncError::Rollback`) |
| A pulled item no newer than the local copy | Ignored |
| A pulled item or deletion with a version below the last one the server confirmed for it | The vault fails: "the sync server sent an older copy of item {id} (version {remote}) than this device already has (version {seen}); refusing to roll it back" (`Error::OlderItem`). Nothing from the page is applied |
| `410` on a pull (code `gone` or none; `410 invite_expired` is something else) | The cursor goes back to 0 and the vault is pulled in full; afterwards, clean synced items the server didn't send are deleted here (`drop_unseen`). The `head_rev` check doesn't apply to this full pull; the per-item check does |

## Item history

Every write carries a version inside its signed envelope (`crates/mg-store/src/history.rs`, the spec's [Item history](../sync-crypto-spec.md#sync-protocol)): the time of the write in milliseconds, or one more than the highest version this device knows of the item when that is larger (`LocalVault::next_version`). Edits, conflict copies, re-seals under a rotated key (`reseal`) and deletions (`LocalVault::tombstone`, from `delete` and from moves) all take a new one. Each item row keeps `version`, the one in its envelope, and `seen_version`, the one of the last copy the server confirmed: set by `apply_remote` and by `mark_pushed`.

| Pulled | Effect |
| --- | --- |
| A versioned copy at or above `seen_version` | Applied; `seen_version` follows it |
| A versioned copy below it | Refused (`Error::OlderItem`, above) |
| A copy without a version, or a deletion without a valid signed envelope (apps before item history, 0.2.0) | Applied; `seen_version` goes to 0, so the next versioned copy is taken whatever its version (its writer may not have seen the earlier ones) |
| The same, with strict item history on (`LocalVault::set_strict_history`, off for now) | Refused when the item has a version (`Error::UnversionedItem`) |
| An item whose row is from before item history (`seen_version` NULL) | Compared with the version in its stored envelope |

## Conflicts

From the code's own statement: the server copy always wins for an item id, and a local edit that lost is kept as a new "(conflict)" item, so nothing is silently discarded. A conflict is found either when a pull brings a newer revision of an item that is dirty here, or when a push answers `conflict` with the server's current copy.

| Local | Server | Result |
| --- | --- | --- |
| An edit | An edit with the same content (both re-sealed it, say) | No copy, no conflict |
| An edit | A different edit | The server's version under the id; the local one as a new item (new ULID, `rev` 0, dirty), pushed like any new item |
| An edit | A deletion that got there first | The item is deleted; the edit survives as a copy |
| A deletion | An edit that got there first | No copy; the item comes back with the server's edit |

The copy's name gets " (conflict)" appended: a host's or key's label, a snippet's or group's name, a session log's title, and so on. An attachment gets it before the extension (`notes (conflict).txt`) so it still opens. The number of conflicts isn't shown; `vault-changed` refreshes the lists.

## Plans and payment errors

Only a server with plans (such as morphgate.com) sends these; how it sells them is outside `vault-sync/v1` ([spec](../sync-crypto-spec.md#plans-optional)). A `402` becomes `Error::PaymentRequired(Payment)` with `code`, `reason`, `billing_url`, `plan`, `feature` and `limit`. Its message (`payment_message`):

| `code` / `reason` | Desktop | iOS and Android |
| --- | --- | --- |
| `reason: trial_ended` | the trial has ended: choose a plan in the account portal | the trial has ended |
| `reason: lapsed` | the plan has lapsed: renew it in the account portal | the plan has lapsed |
| `seats_exceeded` | every seat of the organization's plan is taken: the owner can add seats in the account portal | every seat of the organization's plan is taken |
| `upgrade_required` | this needs the {Plan} plan (or "this needs a higher plan") | the same |
| `team_limit` | you own {a team, or n teams} without a plan: choose a plan for one of them, or delete one, before creating another | …the most you can: delete one before creating another |
| anything else | subscription inactive | the same |

Store builds leave out where plans are bought because the stores don't allow pointing at buying outside them (App Store 3.1.3, Google Play's payments policy).

| Where | What the user sees |
| --- | --- |
| Pushing to the personal vault | The round fails: the panel shows "sync server: the trial has ended: choose a plan in the account portal" and the sidebar **Sync problem**. The pull ran first, so other devices' changes still arrive, and local changes wait, dirty |
| Pushing to a team's vault | "{team} has no plan: its vaults can be read, not changed, until it has one"; the other vaults go on |
| Uploading a blob | That blob is marked failed with the reason (and `billing_url` for `upgrade_required`); session logs and attachments show it, other uploads go on. See [Session logs](session-logs.md) |
| Creating a team | `team_limit`, shown in Teams with **Choose a plan ↗** ([Teams](teams.md#plans)) |

The **Account** section shows the account's plan when the server sends one (`entitlement`). The name is the server's, with `personal` shown as "Hosted sync":

| `status` | **Plan** line |
| --- | --- |
| `trialing` | Free trial until {expires} |
| `active` | {name}, renews {expires} |
| `grace` | {name} ended {expires}; still syncing until {grace end} ("for a few days" without a date) |
| `grace` from a team seat (`source: team_seat`) | Your seat in {team} ended {expires}; hosted sync keeps working until {grace end} |
| `lapsed`, `canceled` | {name} ended {expires} |

The section loads again after every round, so a plan bought in the browser shows without a restart.

## What the window shows

| Sidebar foot | When |
| --- | --- |
| **Sync off** | Sync isn't set up |
| **Sign in to sync** | Signed out (`signedOut`) |
| **Syncing…** | A round is running |
| **Sync problem** | `last_error` is set; the error is the tooltip |
| **Synced** {5 min ago} | The last round worked |
| **Sync pending** | Set up, no round finished yet |

Phones show the same texts as the subtitle of **Sync** in the More list ("Off" instead of **Sync off**) and, while sync is on, as a line on the hosts screen (`syncText` in `apps/desktop/src/mobile/MobileWorkspace.tsx`).

The Sync panel shows **Server**, **Account** and **Last sync** ("Syncing…", the time, or "Not yet"), the last error, the hint "Changes sync within seconds, and the vault checks for others' every minute while you use the app (every 5 while you don't, and at once when you're back)…", **Sync now** (disabled while a round runs or signed out) and **Disconnect this device**, then **Devices**, with the **Account** section beside it. `morphgate://sync` opens this panel ([Deep links](deep-links.md)).

The `sync-status` event and `sync_status` carry `SyncStatusView`: `enabled`, `server`, `email`, `lastSyncAt`, `lastError`, `syncing`, `signedOut`, `ssoRequired`, `approvalRequired`, `approvalsWaiting`, `memberKeysDue`.

## Offline

- Edits stay dirty and go with the next round that reaches the server. A device keeps working from its own copy, indefinitely.
- An unreachable server is a failed round ("cannot reach the sync server: …", shown as **Sync problem**); the loop keeps trying at its interval.
- **Check** can't tell a network failure from a server that isn't one: both say "{origin} does not speak vault-sync/v1".
- Nothing syncs while the vault is locked; the status still reads.

## Tauri commands

| Command | Does |
| --- | --- |
| `sync_status` | The status view (works while locked) |
| `sync_presence` | Someone is or isn't using the app; coming back pokes the loop |
| `sync_check` | Discovery for a server address |
| `sync_start_registration` | Mails the sign-up code |
| `sync_enable` | Creates the account from this vault and uploads it; returns a recovery code when one had to be made |
| `sync_sign_in`, `sync_join`, `sync_recover_sign_in`, `sync_sign_in_again` | The sign-ins above |
| `sync_now` | One round now |
| `sync_totp_start`, `sync_totp_enable`, `sync_totp_disable` | Two-step verification |

The account and device commands (`sync_account`, `sync_devices`, `sync_revoke_device`, `sync_disable`, `sync_email_*`, `sync_open_portal`, `sync_export_account`, `sync_delete_account`, `sync_accept_terms`) are in [Account and devices](account-and-devices.md#tauri-commands).

## Endpoints the client calls

All under `<origin>/v1` except discovery. The full contract is `spec/openapi.yaml`.

| Endpoint | When | Body or query |
| --- | --- | --- |
| `GET /.well-known/vault-sync` | **Check**, sign-up, sign-in, each round (cached for an hour) | |
| `POST /auth/prelogin` | Before every sign-in | `{email}` |
| `POST /auth/register/start` | Sign-up on servers with `email_verification` | `{email}` |
| `POST /auth/register` | **Enable sync** | See above |
| `POST /vaults` | **Enable sync**, after registering | `{id, key_id, wrapped_vault_key}` |
| `POST /auth/login` | Every sign-in | `{email, auth_key, totp?, device}` |
| `POST /auth/refresh` | First request of a session, and after a `401` | `{refresh_token}` |
| `GET /account` | Sign-in; the Account section | |
| `GET /vaults` | Sign-in (find the personal vault); each round on servers with `sharing` (without it, every vault is pulled every round) | |
| `GET /vaults/{id}/changes` | Each round, per vault that moved | `since`, `limit=500` |
| `POST /vaults/{id}/changes` | Each round, per vault with dirty items | `{items: [{id, base_rev, deleted, envelope}]}` |
| `PUT`, `DELETE /vaults/{id}/blobs/{hash}` | Each round, waiting blobs | Bytes with `X-Blob-Kind` (`attachment`, `session_log`) |
| `PATCH /devices/{device}` | Once a run | `{name, platform, client_version}` |
| `POST /account/totp/start`, `POST /account/totp/enable`, `DELETE /account/totp` | Two-step verification | `{auth_key}`, `{code}`, `{auth_key, code}` |

Organization endpoints are listed in [Teams](teams.md); account and device endpoints, password change and recovery (`PUT /account/keys`, `POST /account/recover`) in [Account and devices](account-and-devices.md#endpoints).

## Tests

| Where | What |
| --- | --- |
| `crates/mg-store/src/sync.rs` (`cargo test -p mg-store`) | The engine against an in-memory server (`Fake`, two items per page): `items_flow_between_devices`, `concurrent_edits_keep_both_versions`, `edit_beats_delete_as_a_copy_and_delete_loses_to_edit`, `never_synced_deletes_are_not_uploaded`, `tampered_server_data_is_rejected_whole`, `rollback_is_refused`, `an_older_copy_of_an_item_is_refused`, `a_deleted_item_cant_be_brought_back`, `changes_from_apps_before_item_history_still_sync`, `strict_history_refuses_unversioned_changes`, `copies_from_before_item_history_keep_their_version`, `resealing_gives_a_new_version`, `deletions_sync_through_servers_that_drop_their_envelope`, `up_to_date_vaults_arent_pulled`, `a_device_with_its_own_vault_joins_an_account`, `a_shared_vault_cant_shadow_a_personal_item`, `kinds_from_newer_apps_are_kept_but_not_listed`, `token_and_config_roundtrip_and_disable`, `vaults_without_a_stored_recovery_proof_rotate_on_registration`, `adopt_requires_the_right_password_and_a_fresh_device`, and the blob tests (`session_log_blobs_upload_fetch_and_delete`, `refused_blobs_are_reported_and_retried`, `attachments_sync_and_go_with_their_host`) |
| `crates/mg-sync/src/client.rs` | `payment_errors_say_what_to_do` |
| `server/tests/e2e.rs`, `protocol.rs`, `account.rs` | Real vaults through the reference server over HTTP: a second device signs in and syncs, push, pull, conflicts and tombstones, refresh rotation and reuse detection, email verification and two-step verification where offered. `VAULT_SYNC_URL=https://… cargo test -p vault-sync-server --test protocol --test e2e --test account` runs them against another server |
| `tools/vault-conform` | The `auth`, `account` and `vaults` groups check a server's side of all of this. See [Development](../development.md#conformance-suite) |
| `apps/desktop/e2e/layout.mjs`, `teams.mjs` | The packaged app turns sync on from the first-run offer and from the Sync panel, joins from a second device, and ends with clean syncs. `E2E_SKIP_BUILD=1 E2E_ONLY=teams apps/desktop/e2e/run.sh` |

## Limits

- A server must sit at the root of its origin: the client drops any path from the address.
- No push notifications; changes from other devices arrive within a minute while the app is used, five while it isn't.
- The client doesn't read the server's `limits`. It pushes 500 items per request and at most 4 requests per vault per round, so a vault with more than 2000 unsynced items takes several rounds.
- A per-item refusal other than `stale_key` is retried every round and never shown to the user.
- **I have an account** in the Sync panel only takes a vault that isn't syncing and holds no team vaults; a syncing device disconnects first.
- Moving to another server is disconnecting with **Keep a copy here** and turning sync on with the new address ([Account and devices](account-and-devices.md#disconnecting)); team vaults don't move.
