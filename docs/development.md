# Development

How to build and run the MorphGate app, how its tests are organized (unit, live SSH and VPN, the packaged-app e2e suite, the conformance tool), what CI runs, and how versions and releases are made. Paths are relative to the repository root. The repository's layout and the crates' roles are in the [docs index](README.md) and [Architecture](architecture.md).

## Building and running

Prerequisites: Rust 1.91 or newer (`rust-version` in the workspace `Cargo.toml`), Node 22, and the [Tauri system libraries](https://v2.tauri.app/start/prerequisites/): on Fedora `webkit2gtk4.1-devel libsoup3-devel openssl-devel`; CI installs `libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libgtk-3-dev librsvg2-dev` on Ubuntu.

```sh
cd apps/desktop
npm install
npm run tauri dev       # the app, with the webview served by Vite on localhost:1420
npm run tauri build -- --config '{"bundle":{"createUpdaterArtifacts":false}}'   # unsigned AppImage, deb, rpm
```

Bundles land in `target/release/bundle/`. A build without that `--config` needs the update signing key, or it fails at the end ([Updates](features/updates.md#signing)).

| npm script | Does |
| --- | --- |
| `dev` | Vite on port 1420 (`tauri dev` starts it) |
| `build` | `scripts/licenses.mjs` (third-party notices), `tsc --noEmit`, `vite build` into `apps/desktop/dist` |
| `typecheck` | `tsc --noEmit` |
| `tauri` | The Tauri CLI |

`tauri::generate_context!` embeds `apps/desktop/dist`, so on a fresh checkout run `npm run build` once before `cargo clippy` or `cargo test` of the app crate (CI does).

Mobile builds go through the same CLI: `npx tauri android build --apk --target aarch64 --config '{"version":"0.2.0"}'` (pass the version, or the APK says 1.0; it needs the Android SDK and NDK, `ANDROID_HOME` and `NDK_HOME`) and, on a Mac with Xcode, `npx tauri ios build --debug --target aarch64-sim` for the simulator (`xcrun simctl install booted src-tauri/gen/apple/build/arm64-sim/MorphGate.app`, then `xcrun simctl launch booted com.morphgate.app`). `cargo check -p morphgate-desktop --target aarch64-apple-ios-sim` is the quick check that the Rust side builds for iOS. Platform details: [Platforms and mobile](features/platforms-and-mobile.md).

To try sync locally, run the reference server (`cargo run -p vault-sync-server`, on `127.0.0.1:8443`) and in the app choose **Sync** → **Your own server** → `http://127.0.0.1:8443` ([Reference server](features/reference-server.md)). On Linux the app's data is in `~/.local/share/com.morphgate.desktop/`; deleting `vault.sqlite3` there resets the app to first-run setup and destroys what wasn't synced.

### Environment variables

| Variable | Read by | Does |
| --- | --- | --- |
| `MORPHGATE_LOG` | `lib.rs` | A `tracing` filter (`debug`, `mg_sync=debug,morphgate_desktop_lib=debug`): what the app does, on stderr (each sync request with method, path, status and time, sync rounds, who waited on the sync lock). Nothing from the vault is logged. Off when unset |
| `MORPHGATE_UPDATE_ENDPOINT` | `update.rs` | Another update feed; updates must still be signed with MorphGate's key |
| `MORPHGATE_BROWSER` | `util.rs` | A program to open web pages with instead of the system browser (the e2e runs use `e2e/browser.sh`) |
| `MORPHGATE_VALLIC_CONSOLE` | `cloud.rs` | A stand-in Vallic Cloud console (`e2e/vallic-console.mjs`) |
| `MORPHGATE_CLOUD_CLI_DIR` | `mg-inventory` | Where to look for cloud CLIs first (`e2e/clouds/aws` is a stand-in) |
| `MORPHGATE_ANDROID_KEYSTORE`, `…_KEYSTORE_PASSWORD`, `…_KEY_ALIAS` | `gen/android/app/build.gradle.kts` | Sign an Android release build; unsigned without them |
| `MORPHGATE_CHANNEL=dev` | `build.gradle.kts` | Build the Android dev app (`com.morphgate.app.dev`, "MorphGate Dev") |

## Unit tests

```sh
cargo test --workspace                     # CI adds --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
(cd apps/desktop && npm run build)         # typechecks the webview
```

Unit tests sit next to the code in every crate and in `apps/desktop/src-tauri/src/*.rs`. Integration tests are in `crates/mg-ssh/tests/live.rs`, `crates/mg-inventory/tests/` (`console.rs`, and `clis.rs` against real cloud CLIs), `server/tests/` ([Reference server](features/reference-server.md#tests)) and `tools/vault-conform/tests/reference.rs`. The webview has no unit tests; the e2e suite drives it.

Tests that need something outside the workspace are skipped unless asked for:

| Variable | Test | Needs |
| --- | --- | --- |
| `MG_TEST_SSH=host:port`, `MG_TEST_USER`, `MG_TEST_KEY`, `MG_TEST_PASSWORD`, `MG_TEST_HOST_CA` | `crates/mg-ssh/tests/live.rs`; `mg-vpn` `ssh_session_over_wireguard`, `ssh_session_over_openconnect` | An OpenSSH server with TCP forwarding (below) |
| `MG_OVPN_LIVE=1` | `mg-vpn` `openvpn::live` | `openvpn` and a network namespace (below) |
| `MG_TEST_POLKIT=1` | `mg-presence` `real_polkitd` | A running polkitd; never prompts |
| `MG_TEST_KEYCHAIN=1` | `keychain.rs` round trip | The session's real keychain |
| `MG_TEST_AWS` (`MG_TEST_AWS_PROFILE`), `MG_TEST_GCLOUD`, `MG_TEST_AZ`, `MG_TEST_HCLOUD`, `MG_TEST_DOCTL` | `crates/mg-inventory/tests/clis.rs` | That provider's CLI, signed in; prints counts, not names |
| `VAULT_SYNC_URL` | `server/tests/` | Another `vault-sync/v1` server ([Conformance suite](#conformance-suite)) |

The openconnect tests run the real `openconnect` program (`dnf install openconnect`, `apt install openconnect`, `brew install openconnect`) against an in-process AnyConnect server; without the program they skip.

## Live SSH and VPN tests

Any OpenSSH server with TCP forwarding works, for example a throwaway one run as yourself (the header of `crates/mg-ssh/tests/live.rs`):

```sh
d=$(mktemp -d); ssh-keygen -q -t ed25519 -N '' -f $d/host; ssh-keygen -q -t ed25519 -N '' -f $d/key
cp $d/key.pub $d/authorized_keys
printf '%s\n' "Port 2222" "ListenAddress 127.0.0.1" "HostKey $d/host" "PidFile $d/pid" \
  "AuthorizedKeysFile $d/authorized_keys" "PasswordAuthentication no" "UsePAM no" \
  "Subsystem sftp internal-sftp" > $d/cfg
/usr/sbin/sshd -f $d/cfg
MG_TEST_SSH=127.0.0.1:2222 MG_TEST_USER=$USER MG_TEST_KEY=$d/key \
  cargo test -p mg-ssh --test live -- --include-ignored --test-threads=1
```

Without `MG_TEST_PASSWORD` the tests sign in with the key and skip the password test. CI starts a real sshd on the runner with a throwaway user and password (PAM), a key, and a host certificate from a CA made for the run (`MG_TEST_HOST_CA`), then runs the live tests (password, key, jump hosts, `-L`/`-R`/`-D`, SFTP) and SSH over WireGuard and openconnect.

OpenVPN's live tests start a real `openvpn` 2.6 server, which needs a TUN device: they run in a throwaway network namespace, so nothing touches the machine's network and no real root is needed:

```sh
cargo test -p mg-vpn --no-run
unshare -Urn sh -c 'ip link set lo up && MG_OVPN_LIVE=1 cargo test --offline -p mg-vpn openvpn::live -- --ignored'
```

They cover tls-auth, tls-crypt, TCP, CBC with the PRF, LZO and renegotiation ([VPN](features/vpn.md)).

## The app's e2e suite

`apps/desktop/e2e/` drives the real packaged app (AppImage, deb, rpm; not a dev build) over WebDriver (`tauri-driver` with WebKitWebDriver) in a headless `mutter` inside `dbus-run-session`. Its README is `apps/desktop/e2e/README.md`.

```sh
apps/desktop/e2e/run.sh                                   # builds test packages (about 10 minutes), then every scenario
E2E_SKIP_BUILD=1 apps/desktop/e2e/run.sh                  # reuses the last build
E2E_SKIP_BUILD=1 E2E_ONLY="teams mobile" apps/desktop/e2e/run.sh   # appimage, rpm, deb, teams, layout, mobile
E2E_SKIP_BUILD=1 E2E_ONLY=demo apps/desktop/e2e/run.sh    # only when asked: the README's demo
E2E_SKIP_BUILD=1 E2E_ONLY=monkey MONKEY_STEPS=1500 apps/desktop/e2e/run.sh   # only when asked: a monkey test of each package
node apps/desktop/e2e/android-monkey.mjs <debug apk> target/e2e/android-monkey   # Android's monkey, on an emulator adb reaches
```

| Scenario | Checks |
| --- | --- |
| `appimage.mjs` | A vault (sync offered a week later, once, not with it); SSH to the throwaway sshd; imports from `~/.ssh/config`, PuTTY (`.ppk`), a Termius-style CSV and Royal TS; Vallic Cloud, AWS, DigitalOcean and a feed through stand-ins; user and host certificates; proxy and login commands; groups, bulk move and delete; an agent and agent forwarding; split panes and broadcast; a `morphgate://connect` link from a second launch; appearance; About and the license list; a tampered update refused, the signed update installed and the same vault unlocked in the new version |
| `package.mjs` (deb, rpm) | The desktop entry handles `morphgate://`; the binary knows its package, finds the update and warns about the administrator password |
| `teams.mjs` | Three apps (`E2E_PEOPLE="alice bob carol"`; Carol's app is Bob's second device) and the reference server: sync, an organization, invites with fingerprint checks, shared edits, moving items, published member keys, revocation and rotation, policies, the activity log and its export, device approval, attachments, offboarding against the sshd, shared credentials and tmux sessions, single sign-on against `idp.mjs`, the data export, signing a device out, deleting accounts |
| `layout.mjs` | Every page filled, at 860, 1024, 1280 and 1600 px: nothing overlaps or leaves its column; closing editors and pages returns where they came from |
| `mobile.mjs` | The phone layout in a 390 × 844 window ([Platforms and mobile](features/platforms-and-mobile.md#tests)) |
| `monkey.mjs` (`E2E_ONLY=monkey` only) | A monkey test of the AppImage, the deb and the rpm in turn: a vault with a key, groups, hosts (pointing where nothing listens, so no server's files are in reach) and a snippet, then `MONKEY_STEPS` (500) seeded random steps: clicks on whatever is enabled, typing anything from digits to emoji and 2,000-character strings, Escape, Enter (submitting forms), Tab and arrows, selects, typing into sessions (never Enter), the sidebar, window sizes from a phone's to 1600 px. After every step the page must have thrown nothing (errors and unhandled promise rejections), still render and still answer; afterwards no log may hold a Rust panic. It doesn't click what ends the walk or opens a native dialog (Lock, Install and restart, file pickers, exports, erasing). A failure writes `failure.txt` (the seed, the step and the last 25 steps) and `failure.png` in `monkey-<package>/`; `MONKEY_SEED` repeats a walk |
| `android-monkey.mjs` (not in `run.sh`; CI's "Android monkey" job) | Android's monkey (`adb shell monkey`) on a debug build (`npx tauri android build --debug --apk --target x86_64`) in an emulator: the vault created and unlocked over the WebView's DevTools, then `MONKEY_ROUNDS` (5) rounds of `MONKEY_EVENTS` (1000) touches, swipes, screen turns and navigation keys, each from a fresh start with the app's task pinned. A crash, an ANR, a Rust panic or Java exception in logcat, an error the page throws, the process ending or a blank page fails it, with the seed in `failure.txt` (`MONKEY_SEED`). It clears the app's data first. CI runs it in an API 35 emulator on every pull request, not as a required check |
| `demo.mjs` (`E2E_ONLY=demo` only) | The README's demo: the AppImage with a few hosts in groups. Its Hosts page is captured as shapes (`tools/readme-demo/snapshot.js`: boxes, text and icons where the layout put them), web-1 is clicked, and its session view is captured and recorded by the app's session recording (the login command runs a clean bash with a demo prompt in a demo home). `tools/readme-demo/demo-svg.mjs` draws both scenes, a pointer's click and the replayed session (xterm.js headless; each row's states are a strip a CSS animation steps through) as one animated SVG in the app's fonts. This machine's user and loopback address are swapped for demo ones, and nothing that still shows them or your home folder is saved. Copy `target/e2e/run-<time>/demo/morphgate.svg` to `assets/demo/morphgate.svg` |

What `run.sh` sets up, all on loopback and on free ports (`E2E_SSH_PORT`, `E2E_FEED_PORT`, `E2E_SYNC_PORT`, `E2E_IDP_PORT`, `E2E_VALLIC_PORT`, `E2E_DRIVER_PORT` pin them):

| Piece | What it is |
| --- | --- |
| Test packages | The current version (AppImage, deb, rpm) and the next patch version (AppImage), signed with a throwaway update key whose public half replaces the real one, and allowed to fetch updates over plain HTTP. Moved out of `target/release/bundle` to `target/e2e/packages/`; never publish them |
| sshd | On 127.0.0.1, 127.0.0.2, 127.0.0.3 and 127.0.0.4, key login for the current user, a user CA it trusts and a host certificate for 127.0.0.3; SFTP starts in the run's `sshd/home`, whose `authorized_keys` is the one sshd reads, so offboarding never edits your real `~/.ssh` |
| `feed.mjs` | The update feed (`MORPHGATE_UPDATE_ENDPOINT`), serving a good and a tampered `latest.json` |
| `vallic-console.mjs`, `clouds/aws`, `clouds/doctl`, `host-feed.mjs` | Stand-ins for the Vallic console, the `aws` and `doctl` CLIs and a feed (`E2E_HOST_FEED`, with its token in `E2E_HOST_FEED_TOKEN`), whose machines are the sshd (the feed's on 127.0.0.4, with its host key listed) |
| `vault-sync-server`, `idp.mjs` | The reference server (open registration, invite codes instead of mail) and an OpenID provider, for `teams` and `layout` |
| `session.sh` | One `tauri-driver` per person, each with its own `HOME` and XDG folders in the run directory, so your vault, session bus and keyring are never touched |

`webdriver.mjs` clicks and types through the DOM, because WebKitGTK's automation cannot synthesize input on Wayland. `flows.mjs` holds the steps people take (sign up, sign in, teams, invites, device approval, password change, signing out, deleting an account), tagged with journey IDs (J joining, S signing out, T teams, P plans). The hosted service's own end-to-end suite imports it too, so its steps drive the app only through its UI and assume nothing about the server. Screenshots and logs go to `target/e2e/run-<time>/`; CI uploads them as the `e2e-run` artifact for 7 days.

Requirements: Node 22, `mutter`, `dbus-run-session`, WebKitWebDriver (Fedora `webkitgtk6.0`, Debian and Ubuntu `webkit2gtk-driver`), `tauri-driver` (`cargo install tauri-driver --locked`, or `TAURI_DRIVER`), OpenSSH, `rpm2cpio`, `cpio`, `ar`, and the Tauri build dependencies.

## Conformance suite

`tools/vault-conform` checks any `vault-sync/v1` server against the spec, endpoint by endpoint, with throwaway accounts, and reports each check as passed, failed (with the server's answer) or skipped (with the reason). It exits 0 when nothing failed, 1 when something did and 2 on a usage error, so it fits CI.

```sh
cargo run --release -p vault-conform -- https://sync.example.com
cargo run --release -p vault-conform -- https://sync.example.com --mailpit http://127.0.0.1:8025
cargo test -p vault-conform              # against an in-process reference server: nothing may fail
```

| Group | Checks |
| --- | --- |
| `discovery` | The capabilities document (always runs) |
| `auth` | Prelogin, registration (and email verification's refusals), sign-in, refresh-token rotation and reuse detection, logout, devices, account deletion |
| `account` | The account, password change and a new recovery key, recovery, two-step verification (`features.totp`), the portal link (`features.billing`), email change end to end with `--mailpit` |
| `vaults` | Create, list, push, pull, conflicts, tombstones, paging, per-item refusals, privacy, deletion, `410` after a purge, change notifications (`features.sse`) |
| `blobs` | Upload (201, then 200), hash and size refusals, download, `HEAD`, listing, deletion, privacy (`features.blobs`) |
| `sharing` | Organizations, invites, confirmation, vault access, rotation, roles, re-certification, the audit log and export, device approval, the member key policy, single sign-on status, transfer, removal, deletion (`features.sharing`) |
| `exports` | `GET /account/export` |
| `scim` | SCIM 2.0 provisioning, with `--scim ORG_ID:TOKEN` |

| Option | Does |
| --- | --- |
| `--only GROUP[,GROUP…]` | Runs only these groups (discovery always runs) |
| `--email-domain DOMAIN` | Domain of the throwaway addresses (default `example.com`) |
| `--purge-command CMD` | A shell command that makes the server purge tombstones now, for the `410` check; skipped without it |
| `--scim ORG_ID:TOKEN` | An organization's SCIM token |
| `--mailpit URL` | A Mailpit that receives the server's mail: sign-up codes, invites and email-change codes are read from there |
| `--json`, `--no-color` | Report formats |

Most checks use placeholder key material (servers check sizes and shapes, never the cryptography); the sharing checks use the app's own store and sync engine, so certificates, sealed keys and grants are real. A full run registers 8 accounts and signs in about 15 times from one address: a server that limits registrations or sign-ins per address needs its limits raised on a test instance, or the groups run apart (`--only sharing` needs 3 accounts).

The reference server's tests (`server/tests/`) are the older conformance suite: with `VAULT_SYNC_URL` they drive the real client code against another server (`cargo test -p vault-sync-server --test protocol --test e2e --test account --test sharing --test shared_vaults --test blobs`). The server must accept accounts without mailed codes.

## CI

`.github/workflows/ci.yml` runs on pull requests into `develop` and `main`, and by hand. A fork's pull request runs only after a maintainer approves it. A newer push cancels the run in progress.

| Job | Runner | Runs |
| --- | --- | --- |
| Lint, test, live SSH and VPN (`check`) | `ubuntu-24.04` | `npm ci && npm run build`, `cargo fmt --check`, clippy with `-D warnings`, `cargo test --workspace --all-features`, the polkit check against the runner's polkitd, the live SSH tests against a real sshd, SSH over WireGuard and openconnect, OpenVPN live tests in a namespace |
| Desktop (`macos-15`, `windows-2025`) | GitHub's macOS and Windows | Clippy for the app and `mg-presence`, tests of `mg-presence`, `mg-store`, `mg-vault`. Only for pull requests into `main` and manual runs |
| End to end (Linux) | `ubuntu-24.04` | `apps/desktop/e2e/run.sh`, every scenario |
| Android build | `ubuntu-24.04` | The APK, unsigned |

All jobs run on GitHub's runners.

`.github/workflows/release.yml` builds releases on pushes to `develop` and `main` ([Releasing](#releasing)): a `plan` job (channel, version, build number, platforms, the release to upload to), the desktop matrix through `tauri-action`, a `macos-notarize` job for the DMG, the Android APK, and on iOS the signed `.ipa` and a `testflight` upload job on Linux. The jobs that only talk to Apple are apart from the builds, so re-running a failed one doesn't build again; Windows signing retries the timestamp server inside the build ([RELEASING.md](../RELEASING.md)).

## Versioning

The whole workspace has one version, `[workspace.package] version` in `Cargo.toml` (0.2.0), which is also the app's version (`package.json`, About, `client_version` in the account's device list).

`scripts/bump-version.sh X.Y.Z` sets it in `Cargo.toml`, runs `cargo update --workspace --offline` for `Cargo.lock`, sets `package.json` with `npm version`, sets the Android `versionCode` in `tauri.android.conf.json` to X·1000000 + Y·10000 + Z·100 (leaving 99 more uploads of the same version to Google Play), and reminds you when `CHANGELOG.md` has no `## X.Y.Z` section.

Dev builds are `X.Y.Z-<build>`, where the build number is the workflow's run number plus the repository variable `RUN_NUMBER_OFFSET` (so a new repository carries on from an old one); it is also the dev Android app's version code and the iOS build number. iOS versions are the plain `X.Y.Z`, because App Store versions have at most three numbers.

## Releasing

Work goes into `develop` through pull requests; `develop` goes into `main` through a pull request to release.

| Branch | Builds | Result |
| --- | --- | --- |
| `develop` | Every push: Linux and Android by default; macOS, Windows or iOS with a manual run's `platforms` input or `DEV_ALL_PLATFORMS=true` | The `dev` pre-release, replaced each time: **MorphGate Dev** ([Platforms and mobile](features/platforms-and-mobile.md#builds)) |
| `main` | Every push, every platform; nothing when that version is published already | A draft release `vX.Y.Z` with the version's `CHANGELOG.md` section as notes, plus an iOS build on TestFlight |

To release: bump the version and write the changelog section on `develop`, merge into `main`, try the draft's installers, then publish the draft; installed apps find it within 12 hours, or at once with **Check now**. The secrets (the update key, the Android release key, Apple and Azure signing), build numbers, iOS and TestFlight are in [RELEASING.md](../RELEASING.md).
