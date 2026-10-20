<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/morphgate-lockup-on-dark.svg">
  <img alt="MorphGate" src="assets/brand/morphgate-lockup-on-light.svg" height="40">
</picture>

# MorphGate

**Every host behind its own gate.** SSH client for desktop, Android and iOS, with end-to-end
encrypted sync you can self-host.

- **Client**: Rust + Tauri v2, xterm.js terminal — `apps/desktop`
- **SSH**: `russh` session layer with TOFU host-key pinning, key generation/import, port forwarding, SFTP — `crates/mg-ssh`
- **Local vault**: hosts and keys as encrypted envelopes in SQLite, master password + recovery code — `crates/mg-store`
- **Per-host VPN**: WireGuard, OpenVPN and openconnect (AnyConnect, GlobalProtect, Fortinet, …) inside the app, each
  with its own TCP/IP stack: no TUN device, no routes, no root, overlapping client subnets fine — `crates/mg-vpn`
- **Vault crypto**: Argon2id → HKDF key hierarchy, sealed vault keys, signed + padded envelopes — `crates/mg-vault`
- **Sync**: `vault-sync/v1`, open OpenAPI contract — [`spec/openapi.yaml`](spec/openapi.yaml); client `crates/mg-sync`,
  self-hostable reference server [`server/`](server)

Docs: [developer docs](docs/README.md) · [sync & crypto spec](docs/sync-crypto-spec.md) · [roadmap](ROADMAP.md) · [releasing](RELEASING.md) ·
[changelog](CHANGELOG.md)

## Install

Download from the [Releases](../../releases) page:

| | |
| --- | --- |
| Linux | `.AppImage` (any distribution: `chmod +x`, run), `.deb` (Debian, Ubuntu), `.rpm` (Fedora, openSUSE); x86_64 and arm64 |
| macOS | `.dmg` (Apple silicon and Intel) |
| Windows | `-setup.exe` or `.msi` |
| Android | `.apk` (arm64); Google Play is coming |
| iOS, iPadOS | the App Store is coming |

MorphGate updates itself: it checks at launch and twice a day (you can turn this off under **About**) and installs
only updates signed with the project's key. Releases are code-signed: notarized by Apple on macOS, signed by
Vallic d.o.o. on Windows.

## Develop

Prerequisites: Rust ≥ 1.91, Node 22, and the [Tauri Linux deps](https://v2.tauri.app/start/prerequisites/)
(`webkit2gtk4.1-devel libsoup3-devel openssl-devel` on Fedora).

```sh
cd apps/desktop
npm install
npm run tauri dev       # run the app
npm run tauri build -- --config '{"bundle":{"createUpdaterArtifacts":false}}'   # unsigned AppImage / deb / rpm
```

Signed release builds need the update key; see [RELEASING.md](RELEASING.md). Building and testing in more depth: [docs/development.md](docs/development.md).

```sh
cargo test --workspace            # unit tests
cargo clippy --workspace --all-targets
```

Try sync locally: `cargo run -p vault-sync-server` (listens on `127.0.0.1:8443`), then in the app open
**Sync** in the sidebar and use `http://127.0.0.1:8443`.

Live SSH tests run against a throwaway sshd; see the header of
[`crates/mg-ssh/tests/live.rs`](crates/mg-ssh/tests/live.rs). OpenVPN live tests start a real `openvpn` server in a
throwaway network namespace (no real root needed):

```sh
cargo test -p mg-vpn --no-run
unshare -Urn sh -c 'ip link set lo up && MG_OVPN_LIVE=1 cargo test --offline -p mg-vpn openvpn::live -- --ignored'
```

OpenConnect VPNs need the `openconnect` program (`dnf install openconnect`, `apt install openconnect`,
`brew install openconnect`); its tests run it against an in-process AnyConnect server.

App data lives in `~/.local/share/com.morphgate.desktop/` on Linux:

- `vault.sqlite3` — the encrypted vault (ciphertext only; unlock needs the master password or recovery code)
- `known_hosts` — host keys you accepted; `~/.ssh/known_hosts` is also trusted read-only, and a changed key in
  either file blocks the connection

Deleting `vault.sqlite3` resets the app to first-run setup (and permanently destroys the saved hosts and keys).

Troubleshooting: `MORPHGATE_LOG=debug morphgate` (a `tracing` filter, e.g.
`MORPHGATE_LOG=mg_sync=debug,morphgate_desktop_lib=debug`) prints what the app does on stderr:
each sync request (method, path, status, time), sync rounds, and who waited on the sync lock.
Nothing from the vault is logged. The e2e runs pass it through to the apps they start.

## Supporting MorphGate

If you want to support this project, take a hosted sync plan on [morphgate.com](https://morphgate.com/pricing), or
host your apps on [Vallic Cloud](https://vallic.com/cloud). Either way keeps MorphGate running and funded.

## License

| Component | License |
| --- | --- |
| `apps/*`, `crates/mg-ssh`, `crates/mg-store`, `crates/mg-vpn`, `crates/mg-presence` | [MPL-2.0](LICENSE) |
| `crates/mg-vault` | [Apache-2.0](crates/mg-vault/LICENSE-APACHE) OR [MIT](crates/mg-vault/LICENSE-MIT) |
| `crates/mg-sync` | [Apache-2.0](crates/mg-sync/LICENSE-APACHE) OR [MIT](crates/mg-sync/LICENSE-MIT) |
| `crates/mg-inventory` | [Apache-2.0](crates/mg-inventory/LICENSE-APACHE) OR [MIT](crates/mg-inventory/LICENSE-MIT) |
| `server/` | [AGPL-3.0](server/LICENSE) |
| `spec/openapi.yaml` | [CC0-1.0](spec/LICENSE) |

 Contributions are accepted under the DCO; see [CONTRIBUTING.md](CONTRIBUTING.md).
