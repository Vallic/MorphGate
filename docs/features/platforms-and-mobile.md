# Platforms and mobile

One codebase builds the app for Linux, macOS, Windows, Android and iOS. The Rust shell and the React webview are the same everywhere; what changes per platform is the package, where data lives, how the vault unlocks without the master password, and which features exist at all, because phones and tablets cannot run other programs and store builds must not point at buying outside the store. Phones also get their own layout. Code: `apps/desktop/src-tauri/tauri.conf.json` and its platform overlays (`tauri.linux.conf.json`, `tauri.android.conf.json`, `tauri.ios.conf.json`), `apps/desktop/src-tauri/src/lib.rs` (startup, plugins per platform), `apps/desktop/src-tauri/src/android.rs`, `apps/desktop/src/mobile/useMobile.ts`, `apps/desktop/src/mobile/MobileWorkspace.tsx`, `crates/mg-presence`.

## Builds

| Platform | Identifier | Packages | Updates |
| --- | --- | --- | --- |
| Linux x86_64, arm64 | `com.morphgate.desktop` | `morphgate_<v>_amd64.AppImage`, `morphgate_<v>_amd64.deb`, `morphgate-<v>-1.x86_64.rpm` (lowercase names and binary `morphgate`: `tauri.linux.conf.json` sets `productName` to `morphgate`) | Itself ([Updates](updates.md)) |
| macOS (universal: Apple silicon and Intel) | `com.morphgate.desktop` | `.dmg`; `.app.tar.gz` for updates | Itself |
| Windows x64 | `com.morphgate.desktop` | `-setup.exe` (NSIS), `.msi` | Itself (the installer, `installMode: passive`) |
| Android | `com.morphgate.app` | `morphgate-<v>-arm64.apk` (release workflow, arm64 only); an `.aab` for Google Play, built by hand with arm64, armv7 and x86_64 | Google Play, or installing the next APK over it |
| iOS, iPadOS | `com.morphgate.app` | An `.ipa`, uploaded to TestFlight; iOS 15.0 or newer (`gen/apple/project.yml`), arm64 with Metal | The App Store |

The release workflow (`.github/workflows/release.yml`) builds Linux arm64 only while the repository is public (GitHub's arm64 runner is free only there). Dev builds from `develop` are a separate app, **MorphGate Dev**: identifier `com.morphgate.desktop.dev` or `com.morphgate.app.dev`, binary `morphgate-dev`, links `morphgate-dev://`, their own update feed and data folder, so they install next to the release. They have no `.rpm` (an rpm version cannot hold the `-` of `X.Y.Z-<build>`), and iOS has no dev variant. How releases are cut is in [Development](../development.md#releasing).

## Configuration files

All under `apps/desktop/src-tauri/`.

| File | What it sets |
| --- | --- |
| `tauri.conf.json` | Product name, identifier, binary `morphgate`; the window (1180 × 760, at least 360 × 440); the content security policy; bundles (`targets: all`, `createUpdaterArtifacts: true`, the polkit file in deb and rpm); the `deep-link` and `updater` plugins |
| `tauri.linux.conf.json` | `productName: morphgate`, and the desktop entry template `linux/morphgate.desktop` for deb and rpm (`Categories=Network;RemoteAccess;`, `Exec=… %u` and a `MimeType` line when links are registered) |
| `tauri.android.conf.json` | Identifier `com.morphgate.app`; `bundle.android.versionCode`, which `scripts/bump-version.sh` sets to X·1000000 + Y·10000 + Z·100 (0.2.0 is 20000) |
| `tauri.ios.conf.json` | Identifier `com.morphgate.app` and the Apple development team |
| `Info.plist` | Merged into the macOS app's (and the iOS app's) `Info.plist`: `NSLocalNetworkUsageDescription`, which macOS 15 and iOS show before the app first reaches a device on the local network |
| `Info.ios.plist` | iOS only: `ITSAppUsesNonExemptEncryption` false (export compliance); `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` (the Files app shows the app's Documents folder); `NSFaceIDUsageDescription` |
| `capabilities/default.json` | The `main` window gets `core:default` and nothing else |
| `gen/android/` | The Android project: `AndroidManifest.xml`, `MainActivity.kt`, `BiometricKeyPlugin.kt`, `app/build.gradle.kts` |
| `gen/apple/` | The Xcode project, made with xcodegen from `project.yml` |

Two security choices follow from the shell owning every secret. The capability grants no plugin permissions to the page: the updater, opener and deep-link plugins are called from Rust, and the page only invokes the app's own commands. The content security policy's `connect-src ipc: http://ipc.localhost` keeps the page off the network: every SSH, sync and HTTP request goes through Rust.

### Android project

| File | What it does |
| --- | --- |
| `AndroidManifest.xml` | Only the `INTERNET` permission; one `singleTask` activity with `adjustResize`; the `morphgate` intent filter ([Deep links](deep-links.md)); `usesCleartextTraffic` false in release builds and true in debug ones |
| `MainActivity.kt` | Edge to edge (as every app is from Android 15), the window no longer shrinks for the keyboard and the WebView is not told about it, so the activity sets the WebView's bottom margin to the keyboard's height: the terminal and its extra keys stay above the keyboard |
| `BiometricKeyPlugin.kt` | The Keystore key that seals the device key, released only after a strong biometric check (`src/biometric.rs` on the Rust side) |
| `app/build.gradle.kts` | `minSdk` 24, `targetSdk` 37. Release builds are signed with the key at `MORPHGATE_ANDROID_KEYSTORE` (password `MORPHGATE_ANDROID_KEYSTORE_PASSWORD`, alias `MORPHGATE_ANDROID_KEY_ALIAS`, default `morphgate`), unsigned without it. `MORPHGATE_CHANNEL=dev` adds the `.dev` suffix and the name "MorphGate Dev". The Kotlin half of `rustls-platform-verifier` is pinned to the version in `Cargo.lock` |

`src/android.rs` runs once at startup: HTTPS certificates are checked by Android's own verifier (`rustls-platform-verifier`, under the sync client), which calls into the JVM, so the app hands it the JVM and the application context before the first request. Without that, the first request fails. A failure is logged ("setting up HTTPS certificate checks: …") and startup continues.

## Data folders

The vault and `known_hosts` live in Tauri's `app_data_dir()`, the platform's data folder plus the identifier ([Data on disk](../architecture.md#data-on-disk) lists the files).

| Platform | Folder |
| --- | --- |
| Linux | `$XDG_DATA_HOME/com.morphgate.desktop/`, by default `~/.local/share/com.morphgate.desktop/` |
| macOS | `~/Library/Application Support/com.morphgate.desktop/` |
| Windows | `%APPDATA%\com.morphgate.desktop\` |
| Android | The app's private storage for `com.morphgate.app`; uninstalling removes it. Android's backups leave it out (`allowBackup="false"`, and `res/xml/data_extraction_rules.xml` for cloud backup and device-to-device transfer on Android 12 and newer): the vault and the unlock key sealed by this phone's Keystore stay on the phone |
| iOS, iPadOS | `Library/Application Support/com.morphgate.app/` inside the app's container, not shown in Files |

Dev builds use the `.dev` identifiers, so their vault is separate. Files the app saves for the person (vault and account exports, attachments, recordings) go elsewhere: `util::download_path()` picks the Downloads folder (the home folder without one) and never overwrites, adding `-2`, `-3`; on iOS it is the app's Documents folder, and the app says "x.json in Files › MorphGate". SFTP downloads on a phone go to `downloadDir()`.

On desktop, one app runs per vault. A second launch hands its arguments (a link) to the running app and exits (`tauri-plugin-single-instance`). On Linux the D-Bus name is the identifier plus a hash of the data folder (`single_instance_id()`), so apps with a different `XDG_DATA_HOME` stay apart, as the e2e runs need.

## What differs per platform

| Area | Linux | macOS | Windows | Android | iOS, iPadOS |
| --- | --- | --- | --- | --- | --- |
| Updates | Updater plugin | Updater plugin | Updater plugin | Store or APK; no updater plugin | App Store; no updater plugin |
| Keychain unlock | Secret Service (GNOME Keyring, KWallet) | Keychain | Credential Manager | A Keystore key that only a biometric check releases | A data-protection keychain item that iOS releases only after Face ID, Touch ID or the passcode |
| "Confirm it's you" before keychain unlock (optional on desktop) | polkit: fingerprint (fprintd) or login password; needs the polkit action | Touch ID, or the login password or an Apple Watch | Windows Hello (face, fingerprint, PIN), attached to the app's window | Always: part of the key | Always: iOS asks when the key is read |
| SSH agent | `SSH_AUTH_SOCK`, other sockets | `SSH_AUTH_SOCK`, other sockets, Secretive | OpenSSH's pipe `\\.\pipe\openssh-ssh-agent` (1Password and Bitwarden take it over), Pageant, other pipes | None | None |
| Proxy and renewal commands | `sh -c` | `sh -c` | `cmd /D /S /C`, no console window | None | None |
| openconnect VPNs | With the `openconnect` program | With `openconnect` (Homebrew) | No | No | No |
| Cloud CLIs (AWS, Google Cloud, Azure, Hetzner, DigitalOcean) | Yes | Yes | Yes | No (Vallic Cloud only) | No (Vallic Cloud only) |
| Importing hosts | Yes | Yes | Yes (PuTTY from the registry with `reg export`) | No | No |
| Device name in the account's device list | Host name | Host name without `.local` | `COMPUTERNAME` | Maker and model ("Google Pixel 8") | "iPhone" or "iPad" |

The device's `platform` sent to the sync server is `linux`, `macos`, `windows`, `android` or `ios` (anything else counts as `linux`). The unlock options are described in [Keychain and biometric unlock](device-unlock.md); agents in [SSH keys and agents](ssh-keys-and-agents.md); VPNs in [VPN](vpn.md); imports in [Importing](importing.md).

### Left out on phones and tablets

`mobileOs` (below) hides what a phone or tablet cannot do or must not show:

| What | Where | Why |
| --- | --- | --- |
| SSH agent sign-in and agent forwarding | `HostEditor.tsx`, `ConnectForm.tsx`, `Identities.tsx` (still shown when an item already uses it) | Phones have no agent |
| The route option "A command on this computer (proxy command)" | `HostEditor.tsx` (kept for a host that already has one, with "Phones and tablets can't run it: connect to this host from the desktop app.") | Cannot run programs |
| openconnect in the VPN type picker | `VpnPanel.tsx` | Cannot run the `openconnect` program ("openconnect VPNs work in the desktop app: phones and tablets can't run the openconnect program") |
| **Import…** and **Clouds…** on the hosts page; **Add AWS** and the other CLI providers | `Lists.tsx`, `CloudPage.tsx` | Import reads local files of other clients; cloud CLIs are programs |
| Updates section in About | `AboutPanel.tsx` | The store updates the app |
| **Manage account ↗**, **Choose a plan ↗**, **Upgrade**, the plan line's portal link | `SyncPanel.tsx`, `TeamsPanel.tsx`, `Attachments.tsx`, `SessionLogs.tsx` | Store rules (App Store 3.1.3, Google Play's payments policy): no pointing at buying outside the store. The sync client drops "in the account portal" from payment errors too (`STORE_BUILD` in `crates/mg-sync/src/client.rs`) |

A host that needs one of these (an agent, a proxy command, an AWS or Google Cloud route) on itself or its first jump host shows a **desktop** chip, and its sheet says "Desktop only." with the reason from `desktopOnly()` in `RouteBar.tsx`, with **Connect** and **Files** disabled. Text the iOS app shows never names Google Play or Android (`onIos`; App Store 2.3.10).

## The phone layout

`useMobile.ts` answers three questions:

| Name | True on | Used for |
| --- | --- | --- |
| `onPhone` | A user agent with Android, iPhone, iPad or iPod. iPadOS's web view says it is a Mac, so iPads are not included | The phone layout always; no autofocus on fields |
| `mobileOs` | `onPhone`, or a "Mac" with more than one touch point (an iPad) | Leaving out what phones and tablets can't do (above) |
| `onIos` | iPhone, iPod, or an iPad | iOS wording (App Store, Face ID) |
| `useMobile()` | `onPhone`, or a window narrower than 640 px (`useNarrow()`) | Which layout to render |

A narrow desktop window gets the phone layout too. The workspace follows the window's width only while no session is open (`App.tsx`), because switching layouts would reopen every session. iPads get the desktop layout on a touch screen; there `focusOnlyByTouch()` (`src/touchFocus.ts`) blurs a field that took focus by itself, because the on-screen keyboard would cover half the screen and move the layout from under the next tap. A field keeps focus only after a tap on it, its label or its terminal, or a key press within the last second. `mobile.css` pads for the status bar and home indicator (`env(safe-area-inset-*)`) and uses 44 px touch targets.

### Screens

`MobileWorkspace.tsx` replaces the sidebar and tabs.

| Part | Controls |
| --- | --- |
| Bottom bar | **Hosts**, **Keys**, **Snippets**, **VPNs**, **More** |
| Header | Section title, lock button ("Lock vault"), and a **+** ("New host", "New key", "New snippet", "New VPN") |
| Hosts | Cards for organizations that need single sign-on ("Sign in to {org}") or device approval ("Waiting for {org}", "{org} denied this device"); **Search hosts**; **Open sessions** (status, SFTP and PROD markers, route, how long it has been open); **All hosts · N** and one list per group, with **VPN**, **desktop** and shared-vault chips; the sync line at the bottom |
| Keys, Snippets, VPNs | One list each; an empty list offers "Generate or import a key", "Save a command you run often", "Add a client's VPN". Snippets also has **Import from a CSV file…** |
| More | **Quick connect**, **Tunnels** (with on/off switches below the list), **Session logs**, **Teams**, **Sync**, **Security**, **Settings** ("App theme and terminal appearance"), **About** ("Version and updates") |
| Host sheet | The connection path (VPN with its state, each jump host, the host with its pinned key's short fingerprint or "Key pinned on first connect"), the sign-in method, **Connect**, **Files** (unless the host's cloud source turned SFTP off), **Edit host** |
| Terminal | A bar with back ("Hosts"), status, PROD marker, route line, an open-sessions count and a menu (**Files**, **Snippets**, **Disconnect**); the **Open sessions** sheet with **New session**; the **Snippets** sheet, where a tap pastes and **Run** runs |
| Extra keys | **Esc**, **Tab**, **Ctrl**, **↑**, **\|**, **~**, **/**, **←**, **↓**, **→** |

Editors and settings open full screen with a back button. Sessions stay mounted, hidden, while the person browses, so they keep running. **Ctrl** latches: it applies to the next key typed in the session, then turns off. Pressing an extra key never moves the keyboard: the button does not take focus, and when the keyboard is down the terminal lets go of focus, because Android raises the keyboard for a focused text field on any tap. Whether the keyboard is up is guessed from the page height: more than 120 px below the tallest height seen in that orientation.

`MobileUnlock.tsx` is the unlock screen: the app icon, "Unlock MorphGate", a large button for the device's check ("Unlock with Face ID", "Unlock with fingerprint or face"), **Use master password**, and **Forgot password? Use your recovery key**. The password field shows first only when the device has no keychain unlock.

`MobileSftp.tsx` browses one remote folder at a time: tap a folder to open it, a file to select it. The toolbar has **Upload** (a sheet, "Upload from this device", that browses local folders), **New folder**, and for a selection **Rename**, **Delete** and **Download** (to Downloads). The desktop's two-pane browser is in [SFTP](sftp.md).

## Linux polkit action

On Linux, "confirm it's you" goes through polkit, which needs MorphGate's action installed: `com.morphgate.desktop.unlock`, in `/usr/share/polkit-1/actions/com.morphgate.desktop.policy` (source `crates/mg-presence/polkit/com.morphgate.desktop.policy`). The deb and rpm packages install it; the dev packages ship the same file, so a dev and a release deb or rpm can't be installed together (AppImages can).

| Setting | Value | Why |
| --- | --- | --- |
| `allow_active` | `auth_self` | The active user authenticates as themselves; PAM decides with what (a fingerprint where fprintd is set up, otherwise the login password) |
| `allow_any`, `allow_inactive` | `no` | Remote and inactive sessions never pass |
| No `_keep` | | One success does not cover the next unlock |

The deb and rpm packages install the file (`bundle.linux.deb.files` and `rpm.files` in `tauri.conf.json`). Elsewhere (an AppImage, a build from source) `device_status` reports the presence status `setup`, and Security shows "MorphGate needs to add a polkit rule to the system" with **Set up**, which runs `presence_setup` → `mg_presence::setup()`: `pkexec /bin/sh -c 'umask 022 && exec tee "$0"'` with the policy piped in. The content goes through a pipe, never a file the user could swap in between, because a policy can grant `pkexec` rights to anything; `umask 022` keeps it readable for polkitd. Exit code 126 is a dismissed prompt, 127 "not authorized to install MorphGate's polkit action". The check itself is `CheckAuthorization` for the app's system-bus name, which cannot be raced the way a PID can. A dev deb or rpm ships the same file, so it cannot be installed next to a release deb or rpm (AppImages can).

## Tests

| Test | Covers |
| --- | --- |
| `apps/desktop/e2e/mobile.mjs` | The phone layout in a 390 × 844 window: imports a key and saves a host on the phone screens, connects from the host sheet, Ctrl and ↑ from the extra keys, the session kept behind the host list, SFTP into a folder and a download, lock and unlock on the phone unlock screen |
| `apps/desktop/e2e/layout.mjs` | Every desktop page at 860, 1024, 1280 and 1600 px: nothing overlaps or leaves its column |
| `apps/desktop/e2e/package.mjs` | The deb's and rpm's desktop entry (`Exec=morphgate %u`, `MimeType=x-scheme-handler/morphgate`), and that the binary knows its package |
| `crates/mg-presence` unit tests | polkit against a private `dbus-daemon`, installing the policy through a stand-in for `pkexec`, `availability_answers` on every platform; `MG_TEST_POLKIT=1 cargo test -p mg-presence -- --include-ignored real_polkitd` asks the real polkitd (CI does) |
| `keychain.rs` | `MG_TEST_KEYCHAIN=1` writes, reads and removes an entry in the session's real keychain |
| CI `desktop` job | On macOS 15 and Windows 2025 (pull requests into `main`, manual runs): clippy for the app and `mg-presence`, tests of `mg-presence`, `mg-store`, `mg-vault` |
| CI `android` job | `npx tauri android build --apk --target aarch64`, unsigned |

The webview has no unit tests: `npm run build` typechecks it and the e2e flows drive it. Android and iOS are tried by hand, in an emulator or the simulator ([Development](../development.md#building-and-running)); the simulator returns keychain items without asking for Face ID, so that needs a device.

## Limits

- iPads get the desktop layout, with touch handling, not the phone layout.
- Phones and tablets have no SSH agent, proxy commands, cloud CLIs, host import, openconnect or self-update (above).
- openconnect does not work on Windows: "openconnect VPNs don't work on Windows yet: openconnect can only hand its traffic to a network adapter there, and MorphGate keeps VPN traffic inside the app".
- The release APK is arm64 only.
- The "confirm it's you" check on macOS and Windows is an app-side check that builds in CI but is untried on hardware. Binding the keychain key to biometrics there, as Android and iOS do, is open in the [roadmap](../../ROADMAP.md).
