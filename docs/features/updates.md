# Updates

The desktop app updates itself from the project's GitHub releases. Every update is signed with MorphGate's update key, and the app checks that signature against the public key built into it before it installs anything, so a compromised download host or a tampered file cannot ship code to users. Phones and tablets update through their store instead. The About panel shows the version, the update and the third-party licenses. Code: `apps/desktop/src-tauri/src/update.rs` (Tauri commands, `tauri-plugin-updater`), `plugins.updater` in `apps/desktop/src-tauri/tauri.conf.json`, `useUpdateChecks()` in `apps/desktop/src/App.tsx`, `apps/desktop/src/AboutPanel.tsx`, `apps/desktop/src/Licenses.tsx`, `apps/desktop/scripts/licenses.mjs`.

## How a check runs

| Step | What happens |
| --- | --- |
| When | `useUpdateChecks()` checks 5 seconds after the unlocked workspace opens, then every 12 hours (`UPDATE_EVERY_MS`) while the app stays open, as long as **Check for updates automatically** is on. Never on phones and tablets (`mobileOs`). Nothing is checked while the vault is locked |
| Where | `update_check` asks the updater plugin for the feed in `plugins.updater.endpoints`: production builds read `https://github.com/Vallic/MorphGate/releases/latest/download/latest.json`, dev builds `…/releases/download/dev/latest.json`. The release workflow writes the repository's own URLs into `tauri.release.conf.json` at build time |
| What is sent | One HTTPS request for `latest.json`. Nothing from the vault |
| Result | The plugin compares the feed's version with the running one. A newer release becomes an `UpdateInfo` (version, notes, publication date), kept in `UpdateState` for the install |
| Failure | Automatic checks fail quietly (offline is normal). **Check now** shows the error ("Couldn't check for updates: …") |

`releases/latest/download/` serves only the latest published release, never a draft or a pre-release, so nothing reaches installed apps until a maintainer publishes the draft. `MORPHGATE_UPDATE_ENDPOINT` points a build at another feed for trying the update path; updates from it must still carry MorphGate's signature.

The bottom of the sidebar shows **Update to X** once a check found one, and both it and the logo at the top of the sidebar ("About MorphGate and updates") open About. On phones it is More → **About**.

## Tauri commands

| Command | Does |
| --- | --- |
| `about` | `{version, package}`: the app's version and how this copy was installed, from `tauri::utils::platform::bundle_type()`: `appimage`, `deb`, `rpm`, `app`, `dmg`, `msi` or `nsis`. No `package` for a development build |
| `update_check` | The newer release (`{version, notes, date}`) or `null`. On phones: "On phones, MorphGate updates through the app store." |
| `update_install` | Downloads, verifies and installs the update the last check found, then restarts. Reports through a `Channel<Progress>`: `{kind: "downloading", downloaded, total}` at most every 100 ms, then `{kind: "installing"}`. "Check for updates first." without a found update; "The update couldn't be installed: …" on failure, and the update stays in `UpdateState`, so **Install and restart** can be tried again without a new check |
| `set_auto_update_check` | Turns automatic checks on or off for this device (`device.rs`): the device setting `update_check` is `0` when off and absent when on. `device_status` reports it as `autoUpdateCheck` |

## Signing

The update key is a minisign key pair made with `npx tauri signer generate`. The public half is `plugins.updater.pubkey` in `tauri.conf.json`; the private half and its password are the release workflow's secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Tauri signs each update bundle at build time (a `.sig` beside it), and `tauri-action` writes `latest.json` with every platform's URL and signature. The plugin verifies the signature before installing. A wrong signature fails the install and leaves the installed app untouched.

This is separate from code signing of the installers (Apple Developer ID and notarization, Azure Artifact Signing on Windows, the Android release key), which the operating system checks. Losing the update key means installed apps can no longer update; anyone holding it who can also publish a release can ship code to every user.

Because `bundle.createUpdaterArtifacts` is on, a release build without the key fails at the end. A local unsigned build turns it off: `npm run tauri build -- --config '{"bundle":{"createUpdaterArtifacts":false}}'`.

## What gets installed

| Installed as | Update | Note |
| --- | --- | --- |
| AppImage | The new AppImage replaces the file | No password asked |
| deb, rpm | The new package | Installing asks for an administrator password; About says so before **Install and restart** |
| macOS app (`app`, `dmg`) | The `.app.tar.gz` replaces the bundle | |
| Windows (`nsis`, `msi`) | The installer, in passive mode (`plugins.updater.windows.installMode`) | A progress window, no questions |
| Development build (no package) | Nothing | "This is a development build, which can't update itself. Install a release package to get updates." |

After installing, `app.restart()` quits. On the way out the shell stops tunnels, SFTP transfers and VPNs, with a 3-second limit, so an openconnect child process does not outlive the app. The vault is not touched.

## About

| Control | Does |
| --- | --- |
| Version line | "Version 0.2.0 · AppImage" (`PACKAGE_NAMES`: AppImage, Debian package, RPM package, macOS app, Windows installer (MSI), Windows installer), or "· development build". Phones show the version alone |
| **Open-source licenses** | The third-party notices ([below](#open-source-licenses)) |
| **Check for updates automatically** | `set_auto_update_check`. Hint: "At launch and twice a day MorphGate asks GitHub for the latest release. Nothing from your vault is sent. Updates are signed, and MorphGate installs only ones signed with its key." |
| Update notice | "MorphGate X is available", "Released …", and the release notes |
| **Install and restart** | `update_install`. Before it: "Open terminals, file browsers, tunnels and VPNs close when MorphGate restarts." (plus "Installing a package asks for an administrator password." for deb and rpm). During: a progress bar, "Downloading… 12.3 MiB of 40.1 MiB", then "Installing… MorphGate restarts when it's done." |
| **Check now** | `update_check`; "Checking…" while it runs, and **Install and restart** waits for it (Install takes the update the last finished check found); "MorphGate is up to date." when nothing is newer |
| **Close** | Back to the workspace |

On phones the Updates section is one line instead: "MorphGate updates through the App Store." on iOS, "MorphGate updates through Google Play, or by installing the next APK." on Android.

## Release notes

The notes come from `CHANGELOG.md`. The release workflow takes the `## X.Y.Z` section for the version being built (`awk` in the `notes` step of `.github/workflows/release.yml`) and makes it the release body, which `latest.json` carries and About shows next to **Install and restart**. A production build fails when the section is missing. Dev builds use the section being written, prefixed with "Development build X.Y.Z-N from develop at abc1234.", or "Development build." when there is none. Write the section for users.

## Open-source licenses

Most dependencies (MIT, BSD, Apache, ISC, OFL) require their notices to come with every copy. `apps/desktop/scripts/licenses.mjs` runs first in `npm run build`, so in every Tauri build, and writes `apps/desktop/src/generated/licenses.json` (ignored by git) for the platform being built:

| Source | What it lists |
| --- | --- |
| Rust crates | What `morphgate-desktop` links on Tauri's target (`TAURI_ENV_TARGET_TRIPLE`, this computer's without one; a universal macOS build counts as Apple silicon): `cargo metadata --filter-platform`, normal dependencies only, not build or dev ones, and not the workspace's own crates |
| npm packages | The non-dev packages in `package-lock.json` (what the web bundle contains) |
| Fonts | Martian Mono, Atkinson Hyperlegible Next, Atkinson Hyperlegible Mono, under the OFL (`src/assets/fonts/OFL.txt`) |
| Android libraries | On Android targets, every `implementation(…)` in the app's and the Tauri plugins' Gradle files, plus a line for the AndroidX and Kotlin libraries they use |

The texts are the license files in each package's folder (`LICENSE*`, `COPYING*`, `NOTICE*` and the like), deduplicated. A package without one gets its license's standard text with its authors as the holder; the script warns about any it cannot place. The file holds `{target, components, texts}`.

`Licenses.tsx` loads the file only when opened (it is most of a megabyte): a search box ("Search N components", matching name or license), one row per component (name, version, license), and a component's page with its kind, license, repository and full texts, **All components** and **Back**. Under `npm run dev` there is no file, and the page says "This build has no list: it's made when the app is built for release."

## Tests

| Test | Covers |
| --- | --- |
| `update.rs` `shapes_match_the_frontend` | The JSON shapes of `Progress` and `About` the webview expects |
| `apps/desktop/e2e/appimage.mjs` | About says "Version X · AppImage"; the license list opens and shows russh with the Apache License; a tampered update is refused (the error names the signature) twice, the second time without a new check, and the AppImage is unchanged; the signed update installs over the AppImage, the app restarts, the same vault unlocks in the new version, and **Check now** finds nothing newer |
| `apps/desktop/e2e/package.mjs` | A deb's and an rpm's binary say "Version X · Debian package" / "RPM package", find the update, and warn about the administrator password (installing needs root, so it stops there) |

`run.sh` builds the e2e packages with a throwaway update key (its public half replaces the real one, and `dangerousInsecureTransportProtocol` allows the local plain-HTTP feed) and serves the next patch version from `feed.mjs`, with `MORPHGATE_UPDATE_ENDPOINT` pointing there. These packages must never be published. See [Development](../development.md#the-apps-e2e-suite).

## Limits

- Phones and tablets have no updater: the plugin is not even loaded there (`lib.rs`). An Android APK from GitHub updates by installing the next APK, which Android accepts only when it is signed with the same release key.
- A development build cannot update itself.
- Only a newer version is offered; there is no way to go back to an older release from the app.
- Checks run only while the vault is unlocked.
- Dev builds read their own feed (the `dev` pre-release) and never see production releases, and the other way round.
