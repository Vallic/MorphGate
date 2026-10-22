# MorphGate docs

Developer documentation for MorphGate: the SSH client with a per-host VPN and an end-to-end encrypted vault that syncs through MorphGate's hosted service or any `vault-sync/v1` server (Rust, Tauri v2, React and TypeScript). These docs describe the app from its code; paths in them are relative to the repository root.

Start with [Architecture](architecture.md), then the feature you're working on. [Development](development.md) covers building and testing, [RELEASING.md](../RELEASING.md) releases, and [CONTRIBUTING.md](../CONTRIBUTING.md) how changes come in.

## Documentation

| Doc | What it covers |
| --- | --- |
| [Sync and crypto spec](sync-crypto-spec.md) | The protocol's design: threat model, key hierarchy, wire formats, sync, sharing, the self-hosting contract |
| [Architecture](architecture.md) | Crates and layers, Tauri commands and events, data on disk and the SQLite schema, item kinds, how a connection and a sync run, trust boundaries |
| [Development](development.md) | Building and running, the workspace, unit, live, e2e and conformance tests, CI, versions and releases |
| **Vault** | |
| [Vault and unlock](features/vault-and-unlock.md) | The local vault file, first run, master password rules, unlock, lock and auto-lock, recovery key, password change, export, reset |
| [Keychain and biometric unlock](features/device-unlock.md) | The device key in the OS keychain, Touch ID, Windows Hello and polkit, Android Keystore, iOS |
| [Vault cryptography](features/vault-crypto.md) | Key hierarchy, KDF minimums, envelopes, signing and padding, recovery codes, sealed vault keys, blobs, the rollback guard |
| **Connections** | |
| [Hosts, groups and identities](features/hosts-groups-identities.md) | Item kinds and fields, group defaults, identities, attachments, lists and bulk changes, moving items between vaults |
| [SSH connections](features/ssh-connections.md) | How a connection is made, sign-in order, host keys and host CAs, jump hosts, proxy commands, keepalive and reconnect |
| [SSH keys and agents](features/ssh-keys-and-agents.md) | Generating and importing keys, certificates and their renewal, SSH agents (1Password, Bitwarden, Secretive, Pageant), agent forwarding |
| [Per-host VPN](features/vpn.md) | How a host uses a VPN, tunnel lifetime and sharing, prompts, the in-app TCP/IP stack, DNS |
| [VPN protocols](features/vpn-protocols.md) | WireGuard, OpenVPN and openconnect in detail: what is parsed, refused and asked for |
| [Terminal and snippets](features/terminal-and-snippets.md) | The terminal, tabs, split panes and broadcast, the route bar, snippets, tmux sessions |
| [Port forwarding](features/port-forwarding.md) | Local, remote and SOCKS tunnels |
| [SFTP](features/sftp.md) | The file browser, transfers, conflicts |
| [Session logs](features/session-logs.md) | Recording sessions, sealed chunks, uploading and playback |
| [Importing](features/importing.md) | Hosts from OpenSSH, PuTTY, CSV and Royal TS; snippets from CSV |
| [Cloud sources](features/cloud-sources.md) | Hosts from Vallic Cloud, AWS, Google Cloud, Azure, Hetzner Cloud and DigitalOcean, and hosts and snippets from a feed |
| **Sync and teams** | |
| [Sync](features/sync.md) | Choosing a server, signing up and in, two-step verification, the push and pull cycle, conflicts, plans and limits |
| [Account and devices](features/account-and-devices.md) | The device list, signing devices out, erasing a revoked device, disconnecting, deleting the account, the website account page, device approval, single sign-on |
| [Teams](features/teams.md) | Creating and joining teams, verifying members, roles, shared vaults and key rotation, policies, the member key directory |
| [Offboarding](features/offboarding.md) | What a leaving member could read, removing their keys from servers, replacing a shared key |
| **The app** | |
| [Platforms and mobile](features/platforms-and-mobile.md) | Linux, macOS, Windows, Android and iOS: packages, data folders, the phone layout, what differs |
| [Updates](features/updates.md) | The signed updater, release notes, About and open-source licenses |
| [Deep links](features/deep-links.md) | `morphgate://` links and what each opens |
| [Appearance](features/appearance.md) | App themes, terminal color schemes, fonts |
| [Reference server](features/reference-server.md) | `vault-sync-server`: what it implements, configuration, running it |

## Elsewhere

| Where | What |
| --- | --- |
| [`spec/openapi.yaml`](../spec/openapi.yaml) | The `vault-sync/v1` API: the contract servers and the app follow |
| [`server/README.md`](../server/README.md), [`tools/vault-conform/README.md`](../tools/vault-conform/README.md) | Running the reference server; checking a server against the spec |
| [`apps/desktop/e2e/README.md`](../apps/desktop/e2e/README.md) | The end-to-end suite that drives the packaged app |
| [ROADMAP.md](../ROADMAP.md), [CHANGELOG.md](../CHANGELOG.md) | What's done and open; what each release changed |
| [morphgate.com/docs](https://morphgate.com/docs) | The user docs, which say the same things for people using the app |
