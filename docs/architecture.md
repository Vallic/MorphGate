# App architecture

How the MorphGate app is put together: the webview, the Tauri commands behind it, the crates that do the work, what it keeps on disk, and how a connection and a sync run. Paths are relative to the repository root.

## System overview

```
+-------------------------------------------------------------------------------+
| Webview: React + TypeScript (apps/desktop/src), xterm.js                      |
|   pages, editors, terminal tabs; api.ts wraps every command                   |
+------------------------|-----------------------------------^------------------+
          invoke(command, args)                  Channel (terminal bytes, status)
                         |                       events (vault-changed, prompts)
+------------------------v-----------------------------------|------------------+
| Tauri shell: apps/desktop/src-tauri/src (crate morphgate-desktop)            |
|   #[tauri::command] handlers, managed state, the sync loop, deep links        |
|                                                                               |
|   mg-store ── local vault (SQLite), sync engine, sharing                      |
|      └ mg-vault ── keys, envelopes, sealed vault keys                         |
|      └ mg-sync ─── vault-sync/v1 types and HTTPS client                       |
|   mg-ssh ──── russh sessions, keys, agents, known_hosts, forwards, SFTP       |
|   mg-vpn ──── WireGuard, OpenVPN, openconnect over an in-app TCP/IP stack     |
|   mg-presence ─ Touch ID / Face ID / Windows Hello / polkit                   |
|   mg-inventory ─ hosts from cloud providers                                   |
+-----|-----------------|----------------|-----------------|--------------------+
      v                 v                v                 v
  SSH hosts (direct,  sync server      cloud APIs       update feed
  jump hosts, VPN,    (morphgate.com   and CLIs         (GitHub releases,
  proxy command)      or server/)                       desktop only)
```

| Piece | Where | Role |
| --- | --- | --- |
| Webview | `apps/desktop/src` | Every screen. Holds no secrets: views sent from Rust leave out passwords and private keys (`vault.rs`: "Secrets flow *into* Rust only") |
| Tauri shell | `apps/desktop/src-tauri/src` | Commands the webview calls, one module per area (`ssh.rs`, `vault.rs`, `sync.rs`, `orgs.rs`, `vpn.rs`, …), registered in `lib.rs` |
| `mg-vault` | `crates/mg-vault` | The cryptography of `vault-sync/v1`: Argon2id and HKDF, XChaCha20-Poly1305 envelopes, signed and padded items, sealed vault keys, recovery codes. See [Vault cryptography](features/vault-crypto.md) |
| `mg-store` | `crates/mg-store` | The local vault in SQLite, item model, sync engine (push, pull, conflicts, blobs), shared vaults and organizations, moving items between vaults, export. See [Vault and unlock](features/vault-and-unlock.md) |
| `mg-sync` | `crates/mg-sync` | Types that mirror `spec/openapi.yaml` and the HTTPS client. Sees only opaque bytes. See [Sync](features/sync.md) |
| `mg-ssh` | `crates/mg-ssh` | One `Session` per connection on `russh`: PTY shell, authentication, host-key pinning, agents, port forwards, SFTP, `ssh_config` parsing. See [SSH connections](features/ssh-connections.md) |
| `mg-vpn` | `crates/mg-vpn` | VPN tunnels that run inside the app with their own smoltcp stack; `Tunnel::connect` returns a byte stream to a host behind the VPN. See [VPN](features/vpn.md) |
| `mg-presence` | `crates/mg-presence` | Asks the OS to confirm the user is there before the keychain unlock. See [Keychain and biometric unlock](features/device-unlock.md) |
| `mg-inventory` | `crates/mg-inventory` | Lists machines from Vallic Cloud (API) and AWS, Google Cloud, Azure, Hetzner Cloud, DigitalOcean (their CLIs). See [Cloud sources](features/cloud-sources.md) |
| Reference server | `server/` (`vault-sync-server`) | A self-hostable `vault-sync/v1` server. See [Reference server](features/reference-server.md) |
| Conformance suite | `tools/vault-conform` | Checks any `vault-sync/v1` server against the protocol, endpoint by endpoint. See [Development](development.md#conformance-suite) |

The whole repository is one Cargo workspace (`Cargo.toml`, edition 2024, Rust 1.91 or newer, one version for every crate: 0.2.0). Argon2 and BLAKE2 are compiled optimized even in debug builds, because unoptimized Argon2 makes tests unusable.

## The webview and the shell

The webview calls Rust through `invoke()`; `apps/desktop/src/api.ts` wraps each command in a typed function, grouped by area. Rust answers with plain JSON views. Three channels go the other way:

| Mechanism | Used for |
| --- | --- |
| Command result | Almost everything: lists, saves, sync status |
| `tauri::ipc::Channel` | Per-session streams: `ssh_connect` takes `on_output` (terminal bytes, sent as raw binary) and `on_status`; SFTP transfers report progress the same way |
| Events (`app.emit`) | Things that start in Rust: `vault-changed` (sync pulled something), `hostkey-prompt` (a host key needs a decision), `vpn-prompt` and `vpn-prompt-closed` (a VPN asks for a password or code), `session-logs-changed`, `orgs-gone` (no longer in a team), `device-erased` (signed out from another device), `account-deleted`, `links-pending` (a `morphgate://` link arrived) |

Keystrokes go back with `ssh_write`. `api.ts` keeps them in order: one write in flight, and everything typed meanwhile goes in the next one.

### Managed state

`lib.rs` creates one of each at startup and hands them to commands through `tauri::State`:

| State | Holds |
| --- | --- |
| `VaultState` | The `LocalVault` behind a mutex, and a `Notify` poked after every local edit so sync runs soon. Argon2id work (about a second) runs on a blocking thread |
| `SshState` | Open sessions and tunnels, and the app's `known_hosts` |
| `SyncState` | The signed-in `SyncClient`, the one-round-at-a-time lock, whether someone is using the app, a cache for shared-vault refreshes |
| `VpnManager` | Running tunnels, shared by every host that names the same VPN |
| `CloudState`, `SftpState`, `UpdateState`, `Links` | Cloud refreshes, open SFTP sessions and transfers, a found update, links waiting for the webview |

On exit (and before restarting into an update) the shell stops tunnels, SFTP transfers and VPNs, with a 3-second limit, so an openconnect child process doesn't outlive the app.

### Startup details

- **One app per vault.** On desktop, `tauri-plugin-single-instance` hands a second launch's link to the running app and exits. On Linux the D-Bus name includes a hash of the data folder, so apps with different `XDG_DATA_HOME` (several people on one desktop, as the e2e suite runs them) stay separate.
- **Deep links.** `tauri-plugin-deep-link`; an AppImage registers `morphgate://` itself at startup, since nothing installed it. See [Deep links](features/deep-links.md).
- **Updates.** `tauri-plugin-updater`, desktop only; phones update through their store. See [Updates](features/updates.md).
- **openconnect helper.** openconnect starts MorphGate's own binary as its tun script and, for single sign-on, its browser; `tun_helper_if_requested()` runs that helper instead of the app.
- **Logging.** Off unless `MORPHGATE_LOG` holds a filter (`debug`, `mg_sync=debug,morphgate_desktop_lib=debug`); it goes to stderr and never includes vault contents.

## Data on disk

Everything lives in the app's data folder (Tauri's `app_data_dir` for the identifier `com.morphgate.desktop`; `~/.local/share/com.morphgate.desktop/` on Linux; other platforms in [Platforms and mobile](features/platforms-and-mobile.md)).

| File | What |
| --- | --- |
| `vault.sqlite3` | The vault. Items are `vault-sync/v1` envelopes: hosts, users, passwords and keys exist only inside them. In the clear: ids, timestamps and revisions, KDF parameters, public keys, the recovery proof, the sync server and email, team and team-vault names, pinned members' emails, and device settings ([Vault and unlock](features/vault-and-unlock.md) has the table). Deleting it resets the app to first-run setup and destroys what wasn't synced |
| `known_hosts` | Host keys accepted in the app. `~/.ssh/known_hosts` is also trusted, read-only; a changed key in either file blocks the connection |
| OS keychain entry | Only with keychain unlock on: service `MorphGate`, account `vault-unlock:<key id>`, holding the device key. On iOS it is a data-protection keychain item that stays on this device and that iOS releases only after Face ID, Touch ID or the passcode. Android has no keychain entry: the device key is sealed by a Keystore key that only a biometric check releases, and kept sealed in `settings` |

### The SQLite schema

`crates/mg-store/src/schema.rs` migrates by `PRAGMA user_version` (7 migrations). A vault written by a newer app is refused ("please update the app") instead of being misread.

| Table | Holds |
| --- | --- |
| `account` | KDF parameters and salt, public keys, the account private keys wrapped by the password-derived key and by the recovery key, the recovery proof |
| `vaults` | Each vault: its wrapped key, `head_rev` (the highest server revision seen, the rollback guard), personal or organization, permission, name, `rotation_due`, `directory` (an organization's member key directory) |
| `vault_keys` | Every key generation of a shared vault, sealed to this account |
| `items` | One row per item per vault: envelope (NULL for a deleted item), `rev` (the server revision it is based on; 0 = never synced), `dirty` (not pushed yet), `author_id` |
| `orgs` | Organizations this account is in, with the root of trust pinned on joining |
| `pinned_keys` | Other accounts' keys this device verified through certificates; a change is a hard error |
| `sync_state` | Server, email, account and device ids, the device's public key, the refresh token sealed as an envelope, last sync and last error |
| `device_unlock` | The account private keys wrapped by the device key (keychain unlock) |
| `settings` | This device's settings (auto-lock, update checks, terminal settings, allowed commands); never synced |
| `blobs`, `blob_deletes` | Sealed session-log chunks and attachments waiting to upload or uploaded, and deletions to send |

### Items

Each item's plaintext is an `ItemData` (`crates/mg-store/src/model.rs`), serialized, signed, padded and encrypted into its envelope:

| Kind | Doc |
| --- | --- |
| `Host`, `HostGroup`, `Identity`, `Attachment` | [Hosts, groups and identities](features/hosts-groups-identities.md) |
| `SshKey`, `HostCa` | [SSH keys and agents](features/ssh-keys-and-agents.md), [SSH connections](features/ssh-connections.md) |
| `Snippet` | [Terminal and snippets](features/terminal-and-snippets.md) |
| `PortForward` | [Port forwarding](features/port-forwarding.md) |
| `Vpn` | [VPN](features/vpn.md) |
| `SessionLog` | [Session logs](features/session-logs.md) |
| `TerminalTheme` | [Appearance](features/appearance.md) |
| `CloudSource` | [Cloud sources](features/cloud-sources.md) |
| `MemberKey` | Only in an organization's directory vault. [Teams](features/teams.md) |
| `Unknown` | A kind a newer app wrote: kept and synced as it is, left out of lists, never edited, so an older device doesn't destroy it |

## Keys, in one picture

```
master password ──Argon2id──▶ MasterKey ──HKDF──▶ AuthKey  (sent to the server, which stores a slow hash)
                                         └─HKDF──▶ KEK      (never leaves the device)
KEK / RecoveryKey / device key ──wraps──▶ AccountKeys (X25519 + Ed25519)
AccountKeys (X25519) ──sealed box──▶ VaultKey ──XChaCha20-Poly1305──▶ item envelopes, blobs
```

The server sees the AuthKey, public keys, wrapped keys and envelopes. A shared vault's key is sealed to every member's X25519 key. Details, formats and the minimums the client enforces: [Vault cryptography](features/vault-crypto.md).

## How a connection runs

`ssh_connect` (`apps/desktop/src-tauri/src/ssh.rs`) for a saved host or quick connect:

1. **Certificates.** `renew::before_connect` renews any of the host's key certificates that are missing or expire within five minutes, by running the key's renewal command if this device allowed it.
2. **Route.** `resolve()` reads the host and what it inherits (group defaults, identity), and works out the target, its jump hosts, and how the first hop is reached: directly, through the host's VPN (started or reused from `VpnManager`), or through a proxy command this device allowed (`proxy.rs`).
3. **Host CAs.** `host_cas::trust` gives the connection code the vault's host CAs before it connects.
4. **Connect.** `mg_ssh::Session::connect` dials the first hop, then each jump host in turn through the previous one. Every hop's key is checked against `known_hosts`; an unknown key raises `hostkey-prompt` and waits for `hostkey_answer`, and a changed key stops the connection.
5. **Sign in.** With what the host is set to: a password (keyboard-interactive answers the password prompt when plain password sign-in is refused), keys with their certificates, or an SSH agent. Quick connect uses what the form says: a password, a key chosen from a file or pasted (for that connection only, unless **Save to vault** imports it), or an agent.
6. **Session.** A PTY shell, or the host's login command, or a tmux session when the host keeps its session on the server; agent forwarding if the host asks for it. Output streams to the tab over the `on_output` channel. `SessionEvent`s go through a bounded channel (256 events), so a connection loop that can't hand output on stops reading from the server instead of growing without bound; the relay to the webview itself never waits. See [Terminal and snippets](features/terminal-and-snippets.md).

Port forwards and SFTP open their own sessions over the same route. See [SSH connections](features/ssh-connections.md), [VPN](features/vpn.md), [Port forwarding](features/port-forwarding.md) and [SFTP](features/sftp.md).

## How sync runs

`sync::spawn_loop` (`apps/desktop/src-tauri/src/sync.rs`) runs one round at a time:

| When | Wait |
| --- | --- |
| Someone is using the app (window shown, input in the last 5 minutes; the webview reports it with `sync_presence`) | Every 60 s (`INTERVAL`) |
| Nobody is | Every 300 s (`AWAY`) |
| A local edit or unlock pokes the loop, or the user comes back | At once, after a 1.5 s debounce (`DEBOUNCE`) |

A round does nothing unless the vault is unlocked and sync is on. Otherwise:

1. **Shared vaults first** (`mg_store::sharing::refresh_with`): organizations, verified member keys, vault grants and access changes, and which vaults the server says changed.
2. **Items** (`mg_store::sync::sync_once_with`), vault by vault: pull newer revisions for the vaults that changed (a vault revision older than `head_rev` is an error), drop blobs nothing refers to, upload new blobs and send blob deletions, seal items under an old key again with the current one, then push local changes. When the server already has a newer copy of an item changed here, the server's wins and the local edit is kept as a separate "(conflict)" item.
3. **Outcomes.** A signed-out token stops syncing until the user signs in again. A device signed out from elsewhere (`DeviceRevoked`) erases its vaults and settings and returns to first-run setup (`device-erased`). A deleted account turns sync off and keeps the personal vault (`account-deleted`).

See [Sync](features/sync.md), [Account and devices](features/account-and-devices.md) and [Teams](features/teams.md).

## Trust boundaries

| The app does not trust | So |
| --- | --- |
| The sync server | Items are signed and checked before decrypting; a revision older than one already seen is an error; KDF parameters below the minimum are refused; shared vault keys count only when signed by a member this device verified, and a changed member key is a hard error |
| Other members of a shared vault | A command that arrives in a vault (a proxy command, a certificate renewal command) runs only after this device allowed it, by its exact text |
| The webview | Private keys and passwords go into Rust and never come back out to the webview |
| Its own server, with cloud credentials | Cloud provider calls go from the device to the provider; the credentials never reach the sync server |
| Links | A `morphgate://` link only opens a screen, filled in; it never joins, connects or changes anything, and passwords or keys in it are ignored |

What it relies on: the OS user account (the keychain unlock and the presence check keep someone at an unlocked computer out, not malware running as the user) and the host keys the user accepts.

## Platforms

The same code builds for Linux, macOS, Windows, Android and iOS. Phones get a separate layout (`apps/desktop/src/mobile/`), biometric unlock is part of the key on Android and iOS, there is no updater on phones, and some features are desktop only. See [Platforms and mobile](features/platforms-and-mobile.md).
