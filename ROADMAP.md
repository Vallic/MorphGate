# MorphGate roadmap

SSH client: Rust core, Tauri v2 shell (desktop, Android, iOS), xterm.js terminal,
end-to-end encrypted sync through the open `vault-sync/v1` protocol ([spec](docs/sync-crypto-spec.md), [OpenAPI](spec/openapi.yaml)).

## Architecture

```text
Client (Tauri v2)                         Sync server (vault-sync/v1)
├─ crates/mg-ssh    SSH/SFTP (russh)      ├─ Hosted: morphgate.com
├─ crates/mg-vault  vault crypto          ├─ Self-hosted: reference server (single binary + SQLite)
├─ crates/mg-store  local vault (SQLite)  └─ Stores opaque encrypted blobs + revisions only
├─ crates/mg-sync   vault-sync/v1 client
├─ crates/mg-vpn    in-app VPNs: WireGuard, OpenVPN, openconnect
└─ apps/desktop     xterm.js UI
```

Why Rust + Tauri: one codebase for Linux/macOS/Windows and iOS/Android; `russh` is a mature SSH client;
xterm.js in the webview avoids writing a terminal renderer.

## Core

- [x] Workspace scaffold
- [x] `mg-vault`: key hierarchy, wrapped keys, sealed vault keys, signed + padded envelopes
- [x] `mg-ssh`: password/keyboard-interactive/key/agent auth, known_hosts TOFU, PTY shell, resize, key generate/import
- [x] Desktop: quick connect + xterm.js tabs
- [x] Local vault (`mg-store`): SQLite of encrypted envelopes, master password unlock, recovery code, password change
- [x] Saved hosts and SSH keys in the vault (sidebar, editor, key manager)
- [x] Live SSH tests (local key-only sshd; CI with password + key via container)
- [x] Unlock with the OS keychain (Secret Service / Keychain / Credential Manager; per device, opt-in), auto-lock on idle
- [x] Ask the OS to verify the user before keychain unlock (`mg-presence`): Touch ID (or the Mac's password),
      Face ID or Touch ID on iPhones and iPads (always asked there), Windows Hello, polkit on Linux (fingerprint via PAM/fprintd, or the login password; deb/rpm ship the
      polkit action, other installs set it up with `pkexec`). Linux tested against a mock and the real polkitd;
      macOS and Windows build in CI but are untried on hardware
- [ ] Bind the keychain key to biometrics where the OS can (Keychain access control on signed macOS builds,
      a Windows Hello key credential) instead of an app-side check
- [x] Snippets: vault-stored, paste or run into the last active terminal (bracketed paste)
- [x] Host groups (defaults a host takes when it leaves them empty) and shared identities; keeping a
      session on the server (tmux, one per tab) and reconnecting lost sessions
- [x] Terminal appearance: built-in themes plus themes imported from Ghostty, Alacritty, iTerm2 and Windows
      Terminal files (vault items, synced), a theme per host, and this device's font, size and cursor
- [x] Jump hosts (ProxyJump chains via direct-tcpip, per-hop host-key pinning)
- [x] Cloud sources: hosts kept in step with Vallic Cloud (its API), AWS, Google Cloud, Azure, Hetzner Cloud and
      DigitalOcean (their CLIs), and feeds: hosts and snippets from a JSON document a team publishes at a URL,
      read with a token, refreshed every 15 minutes, with the host keys it lists trusted for its hosts
- [x] Port forwarding: local / remote / dynamic SOCKS5 tunnels saved in the vault, start/stop from the sidebar
- [x] SFTP tabs (`russh-sftp`): local + remote panes, drag and drop (also from the OS), recursive upload/download
      with progress, cancel and replace, mkdir/rename/chmod/delete
- [x] `mg-sync`: vault-sync/v1 client (prelogin/register/login, token rotation, pull/push)
- [x] Sync engine in `mg-store`: paginated pull, rollback guard, conflict copies, sealed refresh token
- [x] Item history: every write carries a version inside its signed envelope, deletions are signed, and
      a device refuses a copy of an item older than one it has seen (servers keep the signed deletion:
      `signed_tombstones`)
- [ ] Strict item history on by default (refusing unversioned changes, which only apps before item history
      send), and signed vault checkpoints for devices with no copy to compare
- [x] Reference sync server (`server/`, axum + SQLite) with protocol + two-device e2e tests
- [x] Desktop sync: enable from an existing vault, sign in on a fresh device, background sync, disconnect
- [x] Password change / recovery / new recovery key while synced (server first, other devices sign in again
      and re-wrap locally), recovery sign-in on a fresh device, device list with sign-out
- [x] Conformance: the server tests run against any URL (`VAULT_SYNC_URL`, see `server/README.md`)
- [x] Standalone `vault-conform` CLI with a per-endpoint report (`tools/vault-conform`), incl. 410 after
      a purge (`--purge-command`), mailed invites (`--mailpit`) and SCIM (`--scim`)
- [x] Per-host VPN: embedded WireGuard (`mg-vpn`, userspace, no root), shared per profile, synced in the vault
- [x] OpenVPN client in Rust (rustls control channel; tls-auth/tls-crypt; GCM/ChaCha/CBC; certificates,
      username/password, static + dynamic challenges, auth-token; LZO/LZ4 decompression; renegotiation), tested
      against a real OpenVPN 2.6 server
- [x] openconnect (AnyConnect, GlobalProtect, Fortinet, Pulse, F5, …) via the `openconnect` program in
      `--script-tun` mode: prompts (password, OTP, group) and certificate pinning in the app
- [x] VPN: tls-crypt-v2 (incl. the 2.6 wrapped-key resend), PKCS#12 / encrypted keys (PKCS#8, legacy PEM,
      `askpass`), web (SAML) sign-in for OpenVPN (`WEB_AUTH` / `OPEN_URL`, `AUTH_PENDING` timeouts) and
      openconnect (AnyConnect external-browser SSO, openconnect 9+), WireGuard with multiple peers (cryptokey
      routing); tested against openvpn 2.6 and openconnect 9.12
- [ ] openconnect on Windows: not possible with the stock program. Its Windows build can't run a `--script-tun`
      script (`openconnect_setup_tun_script()` in `tun-win32.c` only reports "not yet supported", as of 9.21 and
      master) and otherwise needs a TAP-Windows or Wintun adapter (driver, admin rights). Needs either script-tun
      upstream (a socket pair the script inherits as `VPNFD`, used in place of the adapter handle), or MorphGate
      speaking the tunnel protocols after `openconnect --authenticate`: CSTP over TLS (+ DTLS) for AnyConnect /
      ocserv first, then GlobalProtect, Fortinet, Pulse… each on its own. Meanwhile the app says so up front
- [x] Packaging: AppImage, deb, rpm (x86_64, arm64), universal dmg, NSIS + MSI, built by the release workflow (a
      push to `main`) into a draft GitHub release; signed self-updates (About panel, auto-check at launch and twice a day).
      AppImage update path tested end to end (tampered update refused, signed one installed, restart, vault kept)
- [x] Code signing: Apple Developer ID + notarization, Windows (Azure Artifact Signing), the Android release
      key ([RELEASING.md](RELEASING.md))

## Teams

- [x] Sharing in vault-sync/v1: organizations, single-use invites, member confirmation, per-vault access
      (read/write/manage), key generations with grant signatures, rotation after revocation, ownership
      transfer, audit events; reference server, OpenAPI spec and conformance tests
- [x] Shared vaults in `mg-store` and the sync engine; trust from the pinned organization root through the
      owner chain and admin/member certificates; fingerprints compared when joining and confirming
- [x] Desktop: Teams panel (organizations, vaults, access, members, invites, rotation, transfer, delete),
      vault choice for new items, shared items tagged, view-only vaults; two-app e2e of the packaged build
- [x] Policies (two-step verification, member-created vaults, invite domains) and the
      activity log in the app
- [x] Member key directory: members publish the SSH public keys they use on the organization's hosts,
      signed by them (a directory vault flagged in its encrypted meta; no server changes)
- [x] Offboarding: what the member could open, removal with key rotation, their published keys found and
      removed from every host's `authorized_keys` (atomic replace over SFTP), and shared SSH keys replaced
      on every host that uses them (installed and tried first, then switched, then the old key removed)
- [x] A policy that asks members to publish their keys (the apps remind those who haven't)
- [x] Re-certify members whose confirming admin left: owners' and admins' apps do it for the members
      they verified; others after a fingerprint comparison (needs `PUT …/members/{id}/certificate`)
- [x] Single sign-on per organization (OIDC in the reference server, SAML where a server offers it):
      vaults wait on the device until it signs in at the provider, and stay there meanwhile
- [x] Device approval: new devices wait for an owner, an admin, or the member's approved device
- [x] SCIM 2.0 provisioning (the identity provider invites and removes members)
- [x] Audit log download (CSV, JSON lines)
- [ ] Mosh: would keep sessions alive while iOS suspends the app (no mature Rust client; a port or FFI)

## Session logs and data

- [x] Session logs: per-host recording into the vault (asciicast, sealed blobs), playback, `.cast`
      export; team retention
- [x] Attachments: files kept with a host, sealed blobs fetched on demand
- [x] Data export: what the server keeps (`GET /v1/account/export`) and the vault itself, readable,
      from the app
- [x] Sync starts on morphgate.com; "Your own server" takes any address

## Mobile

- [x] Phone layout (extra keys, full-screen terminal, one-folder SFTP), also for narrow windows
- [x] Android app (`com.morphgate.app`): Google Play bundles and APKs, fingerprint unlock
- [x] iOS build, store builds and signing: TestFlight from CI, Play bundles ([RELEASING.md](RELEASING.md))

