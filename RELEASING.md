# Releasing MorphGate

Two branches, two channels. Work goes into `develop` through pull requests; `develop` goes into
`main` through a pull request when it's time to release.

| Branch | Built by | Release | App |
| --- | --- | --- | --- |
| `develop` | every push | the `dev` **pre-release**, replaced each time, version `X.Y.Z-<build>` | **MorphGate Dev**: its own app id (`com.morphgate.desktop.dev`, `com.morphgate.app.dev`), data and update feed, so it installs next to the release |
| `main` | every push | a **draft** release `vX.Y.Z` (the version in `Cargo.toml`) | MorphGate |

[`.github/workflows/release.yml`](.github/workflows/release.yml) builds:

| Platform | Installers | Updates itself from |
| --- | --- | --- |
| Linux x86_64, arm64 | `.AppImage`, `.deb`, `.rpm` | the same format (deb/rpm ask for an administrator password) |
| macOS (universal) | `.dmg` | `.app.tar.gz` |
| Windows x64 | `-setup.exe` (NSIS), `.msi` | the NSIS installer, run in passive mode |
| Android arm64 | `.apk`, signed with the release key | a newer APK installed over it; Google Play's installs from Play |
| iOS, iPadOS | none here: uploaded to TestFlight ([below](#ios-testflight)) | the App Store, once a build is submitted there |

plus a `.sig` file for each update bundle and `latest.json`. Production apps read
`https://github.com/<owner>/<repo>/releases/latest/download/latest.json`, which only serves
**published** releases (never pre-releases), so nothing reaches users until you publish the
draft. Dev apps read `…/releases/download/dev/latest.json`.

Dev builds have no `.rpm` (rpm versions can't contain the `-` of `X.Y.Z-<build>`): on Fedora,
use the dev AppImage. Dev builds are Linux and Android unless a manual run (Actions → Release → Run workflow, on
`develop`; `gh workflow run release.yml --ref develop -f platforms=all`) picks *platforms*
`all`, `macos`, `windows` or `ios`, or the repository variable `DEV_ALL_PLATFORMS` is `true`
(all of them; they're the slow builds). A dev iOS build goes to TestFlight like a production
one. Linux arm64 builds only for production releases, and only on a public repository (GitHub's
arm64 runner is free only there).

Dev versions (`X.Y.Z-<build>`), the dev Android app's version code and iOS build numbers all use
the build number: the workflow's run number plus the repository variable `RUN_NUMBER_OFFSET`
(50 here, the last run of the repository before this one). Each must keep growing: Android
installs only a higher version code, the updater only a higher version, and TestFlight takes each
build number of a version once.

## Secrets and keys

Set in Settings → Secrets and variables → Actions, from the keys kept outside the repository:

```sh
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/morphgate-updater.key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD < ~/.tauri/morphgate-updater.key.password
base64 -w0 ~/.android/morphgate-release.jks | gh secret set ANDROID_KEYSTORE_BASE64
gh secret set ANDROID_KEYSTORE_PASSWORD < ~/.android/morphgate-release.password
gh secret set ANDROID_KEY_ALIAS --body morphgate
```

(The Apple, Azure and iOS ones are under [Code signing](#code-signing) and [iOS](#ios-testflight).)

**The update signing key** (made with `npx tauri signer generate`): its public half is
`plugins.updater.pubkey` in `apps/desktop/src-tauri/tauri.conf.json`, and installed apps accept
only updates signed with it.

**The Android release key** (`~/.android/morphgate-release.jks`, alias `morphgate`, RSA 4096,
valid until 2056; certificate SHA-256
`3E:19:14:48:14:F5:93:31:1B:1C:76:C1:5E:55:87:ED:E5:73:61:11:00:4B:AC:87:CB:78:92:BC:54:BC:4B:A8`):
Android installs an update only when it is signed with the same key as the installed app, and
Google Play ties the app to it. Play App Signing uses this key (exported with Google's PEPK tool
and uploaded before the first Play release), and it is also the upload key: Play installs and the
GitHub APKs carry the same signature, so either updates the other.

For both keys:
- **Back them up**, with their passwords (password manager or offline). Lost, existing installs
  can't update any more: users must uninstall and install again.
- **Keep them secret.** Anyone with a key who can also publish releases can ship code to every
  user.

## Cutting a release

On `develop`:

```sh
scripts/bump-version.sh 0.2.0          # Cargo workspace, Cargo.lock, package.json
$EDITOR CHANGELOG.md                   # a "## 0.2.0" section: these notes are shown in the app
git commit -am "Release 0.2.0"
```

then open a pull request from `develop` into `main` and merge it once CI passes. The push to
`main` builds the draft release `v0.2.0` (it checks that `CHANGELOG.md` has the section; a version
that is published already builds nothing). When it's done:

1. Open the draft release and try the installers (at least one per OS).
2. Publish it (that creates the tag). Apps that check automatically find it within 12 hours, or
   right away via **About → Check now**.

Pushing to `main` again before publishing rebuilds the draft. After a release, start the next
version on `develop` (bump it again), so dev builds number past the release.

To try an update without publishing, point a build at another feed:
`MORPHGATE_UPDATE_ENDPOINT=http://127.0.0.1:8000/latest.json`. The update must still be
signed with the key above.

## Code signing

A production release (`main`) is signed on every platform or not built: the Plan job stops when any of the secrets and variables below is missing. Dev builds go unsigned where they aren't set up:
- **macOS**: Gatekeeper blocks the first launch. Users right-click → Open, or System
  Settings → Privacy & Security → Open Anyway.
- **Windows**: SmartScreen shows "Windows protected your PC". Users choose More info → Run
  anyway.

Updates are signed regardless (see above).

- **macOS** (Developer ID + notarization, Vallic d.o.o., team `988D7A4F4L`): the release
  workflow's "Apple signing" step puts these in the build's environment where they exist (an
  empty `APPLE_CERTIFICATE` would fail the build):
  - secrets `APPLE_CERTIFICATE` (the Developer ID Application certificate and its key, a
    base64 `.p12`), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_API_KEY_P8` (the App Store Connect
    API key's `.p8`, for notarization);
  - variables `APPLE_SIGNING_IDENTITY` (`Developer ID Application: Vallic d.o.o. (988D7A4F4L)`),
    `APPLE_API_KEY` (the key's ID), `APPLE_API_ISSUER` (App Store Connect → Users and Access →
    Integrations → App Store Connect API: the Issuer ID).
  Without the API key, builds are signed but not notarized. Tauri notarizes the app, and "Check
  the macOS signature" shows its signing authority, stapled ticket and Gatekeeper's verdict. The
  DMG goes on as an artifact to the **macOS notarize** job, which notarizes it too, staples it
  (tried five times: Apple's ticket service drops connections), checks it the same way and puts
  it in the release in place of the one the build uploaded. That job only talks to Apple, so
  when it fails, re-running it takes a minute or two instead of a new build. Either check fails
  the run where something is wrong.
  A dev build with *platforms* `macos` is the cheapest check of a change to any of this. The
  certificate was made from a
  CSR on Linux (`openssl req -newkey rsa:2048`); make a new one before it expires
  (Certificates → + → Developer ID Application, G2 Sub-CA; the Account Holder
  only), and the `.p12` with `openssl pkcs12 -export -legacy` (macOS's `security import` wants
  the legacy format).
- **Windows**: Azure Artifact Signing (Vallic d.o.o.'s account; the installers' publisher,
  `bundle.publisher`, is the same legal name as the certificate's), through
  `bundle.windows.signCommand` and [`artifact-signing-cli`](https://crates.io/crates/artifact-signing-cli).
  The release workflow signs Windows builds once these exist (unsigned until then):
  - repository variables `ARTIFACT_SIGNING_ENDPOINT` (the account's region, e.g.
    `https://weu.codesigning.azure.net`), `ARTIFACT_SIGNING_ACCOUNT`, `ARTIFACT_SIGNING_PROFILE`
    (the certificate profile: it exists once the organization's identity validation is done);
  - secrets `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`: an app registration
    holding only the "Artifact Signing Certificate Profile Signer" role on the account. Its
    secret expires: renew it (`az ad app credential reset`) and the secret before then. Its
    only role is on the signing account, so the workflow's "Windows signing setup" gives
    `artifact-signing-cli` an `az` that logs in with `--allow-no-subscriptions`. Recreating the
    account (or moving it to another region) drops that role: add "Artifact Signing
    Certificate Profile Signer" for the app registration on the new account (Access
    control), and set `ARTIFACT_SIGNING_ENDPOINT` to its URI.

  The profile is `morphgate` (public trust, from the account's identity validation). Its
  certificates last a few days and renew by themselves; signatures are timestamped, so they stay
  valid after. The validation expires: its date is on the portal's Identity validation page, it
  can be renewed there from 60 days before, and Microsoft mails a reminder. Once it lapses,
  certificates stop renewing and signing stops (a new validation then needs the profile
  replaced, same name). Signing needs Microsoft's timestamp server, which doesn't always
  answer: the sign command tries each file four times, 20 seconds apart. "Check the Windows
  signature" after the build shows each file's signer and timestamp, and fails the build where
  one is missing.

## iOS (TestFlight)

The release workflow builds the iOS app and uploads it to TestFlight: on every production release
(`main`), and for a dev build when a manual run asks for *platforms* `ios` or `all`. The **iOS**
job (macOS runner) builds and signs the .ipa; the **TestFlight** job (Linux) uploads it with
`scripts/upload-ios.py`, through the App Store Connect API, and waits until Apple has processed
it. Requests Apple drops are tried again, and a build App Store Connect has already (an earlier
attempt that got through though its answer didn't) counts as uploaded, so re-running the job is
always safe. The version is the one in `Cargo.toml` (a dev build's too, without its `-<build>`:
App Store versions are at most three numbers), and the build number is the release workflow's:
its run number plus `RUN_NUMBER_OFFSET` (above). A build uploaded by hand needs a number above
the last one.

It needs the secrets `IOS_CERTIFICATE` (an Apple Distribution certificate with its key, a .p12 in
base64), `IOS_CERTIFICATE_PASSWORD`, and `IOS_MOBILE_PROVISION` (an App Store provisioning
profile for `com.morphgate.app`, base64), and the App Store Connect API key the Mac app's
notarization uses (`APPLE_API_KEY`, `APPLE_API_ISSUER`, `APPLE_API_KEY_P8`), with access to
upload builds. The certificate and the profile last a year: renew both and update the secrets
before they expire. Once a version is live on the App Store, App Store Connect takes no more
builds of it: bump the version before the next iOS upload.

Export compliance: the app uses standard encryption (SSH, WireGuard, TLS, the vault's), none
proprietary. `src-tauri/Info.ios.plist` answers Apple's question (`ITSAppUsesNonExemptEncryption`),
so uploads don't ask.

## Third-party notices

Most of the app's dependencies (MIT, BSD, Apache, ISC, OFL, …) require their license notices to
come with every copy. `apps/desktop/scripts/licenses.mjs`, run by `npm run build` (so by every
Tauri build), collects them for the platform being built: the crates the app links (cargo
metadata for Tauri's target), the npm packages in the web bundle, the fonts, and on Android the
Java libraries named in the Gradle files. The app shows them in About → Open-source licenses.
A package that ships no license file gets its license's standard text with its authors as the
holder; the script warns about any it can't place. `npm run dev` has no list.

## Building locally

Android, signed with the release key (without the `MORPHGATE_ANDROID_*` variables the APK comes
out unsigned; `MORPHGATE_CHANNEL=dev` makes the dev app):

```sh
cd apps/desktop
MORPHGATE_ANDROID_KEYSTORE=~/.android/morphgate-release.jks \
MORPHGATE_ANDROID_KEYSTORE_PASSWORD="$(cat ~/.android/morphgate-release.password)" \
  npx tauri android build --apk --target aarch64 --config '{"version":"0.2.0"}'
```

The version must be passed (it is the one in `Cargo.toml`): without it the APK says 1.0.

For Google Play, the bundle (same variables), with the phone ABIs and the emulator's:

```sh
npx tauri android build --aab --target aarch64 --target armv7 --target x86_64 \
  --config '{"version":"0.2.0"}'
```

It lands in `src-tauri/gen/android/app/build/outputs/bundle/universalRelease/`. Play takes each
version code once. The code is `bundle.android.versionCode` in `src-tauri/tauri.android.conf.json`,
which `scripts/bump-version.sh` sets to X·1000000 + Y·10000 + Z·100 for version X.Y.Z (0.2.0 is
20000); to upload the same version again, raise it by one there. The APKs carry the same code,
so a Play install and a GitHub APK of the same version can replace each other.

Desktop:

```sh
cd apps/desktop
TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/morphgate-updater.key)" \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$(cat ~/.tauri/morphgate-updater.key.password)" \
  npx tauri build
```

Bundles land in `target/release/bundle/`. Without the key variables the build fails at the
end: the config asks for update artifacts. For a quick unsigned build, add
`--config '{"bundle":{"createUpdaterArtifacts":false}}'`.
