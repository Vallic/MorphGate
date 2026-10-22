# End-to-end tests of the packaged app (Linux)

These run the real AppImage, deb and rpm binaries, not a dev build, and drive them over WebDriver:

| Scenario | What it checks |
| --- | --- |
| `appimage.mjs` | Creates a vault, which isn't offered sync then but is a week later (the page reloaded with the time moved on), once; SSHes to a throwaway local sshd and runs a command; imports two hosts and their key from a `~/.ssh/config` (one behind the other as its jump host) and connects through it; imports a PuTTY session with a new key in a `.ppk` file, a Termius-style CSV file with a group and a Royal TS document, and signs in with the PuTTY key; connects Vallic Cloud through a stand-in console (`vallic-console.mjs`: device sign-in, rotating tokens, an environment that is this sshd) and signs in to its host; adds AWS and DigitalOcean through stand-in CLIs (`clouds/`); adds a feed (`host-feed.mjs`) whose host connects with the host key it lists, whose wrongly listed host is refused and whose changed snippet asks before it runs; signs in with a key that only has a certificate from the run's user CA (which sshd trusts), from the vault and from an agent; reaches a host by a command its jump host runs (with a login command instead of the shell), and another by a proxy command on this computer (both the relay in `crates/mg-ssh/tests/relay.py`); selects two hosts, moves them into a group and deletes them; signs in to a host with one key from an `ssh-agent` (its own socket) and forwards it (`ssh-add -l` on the host lists it); splits a tab into three panes (beside and below, one through a jump host), broadcasts a command to all of them and then types into one, drags a border and closes them; opens a `morphgate://connect` link from a second launch (which hands it over and exits) and connects from the filled-in quick connect, and refuses an unknown link; refuses a tampered update twice without touching the AppImage; installs the signed update, restarts, unlocks the same vault as the new version, and finds nothing newer |
| `package.mjs` (deb, rpm) | The binary knows how it was installed, finds the update, and warns that installing asks for an administrator password (installing needs root, so it stops there) |
| `teams.mjs` | Two apps side by side (Alice and Bob) with a local reference sync server: both turn on sync; Alice creates an organization and a vault and invites Bob; Bob joins only after the owner's fingerprint matches, and Alice confirms him only after his matches; a host saved in the shared vault reaches Bob, his edit reaches Alice; Bob publishes his SSH key; Alice revokes him (the vault leaves his device) and rotates the vault key; members may create vaults; the activity log tells the story. Then Alice offboards Bob against the local sshd: removal and key rotation, his key found and removed from `authorized_keys`, and the host's shared key replaced (she still logs in) |
| `layout.mjs` | Turns sync on from the offer a vault without sync gets a week on, fills every page (hosts in a group, a key, a snippet, a tunnel, a team with an invite to a long address), and at 860, 1024, 1280 and 1600 px wide checks that nothing on a page overlaps or runs out of its column. Closing an editor returns to the page it was opened from, and closing a page to the session under it; with no session open, a page takes the tab bar's place |
| `monkey.mjs` | Only with `E2E_ONLY=monkey`: each package (AppImage, deb, rpm) takes `MONKEY_STEPS` seeded random clicks, typing, keys, selects and resizes over a vault with hosts where nothing listens; any page error, blank page, unanswered call or Rust panic fails it, with the seed and the last steps in `monkey-<package>/failure.txt` (`MONKEY_SEED` repeats it) |
| `demo.mjs` | Only with `E2E_ONLY=demo`: the README's demo. The AppImage's Hosts page, a click on a host and its recorded session (in a demo shell), drawn by `tools/readme-demo/demo-svg.mjs` as `demo/morphgate.svg` (copy it to `assets/demo/morphgate.svg`) |
| `mobile.mjs` | The phone layout in a 390 × 844 window: imports a key and saves a host on the phone screens, connects from the host's sheet, interrupts a command with Ctrl from the extra-key row and repeats one with ↑, keeps the session open behind the host list, browses into a folder over SFTP and downloads a file to Downloads, then locks and unlocks on the phone unlock screen |

```sh
apps/desktop/e2e/run.sh                         # builds test packages (~10 min), then runs everything
E2E_SKIP_BUILD=1 apps/desktop/e2e/run.sh        # reuses the packages from the last build
E2E_SKIP_BUILD=1 E2E_ONLY=teams apps/desktop/e2e/run.sh   # just some scenarios: appimage, rpm, deb, teams, layout, mobile
```

Screenshots and logs go to `target/e2e/run-<time>/`.

## Android monkey

`android-monkey.mjs` isn't one of `run.sh`'s scenarios: it runs Android's own monkey
(`adb shell monkey`) on the Android app, on an emulator or a phone adb reaches. CI's "Android
monkey" job runs a basic one in an API 35 emulator on every pull request (3 rounds of 500 events,
ANRs noted, a 720 × 1600 screen); it isn't a required check.

It takes a debug build (for the emulator's processor), whose WebView answers DevTools: through it
the app's first screen creates the vault (then a key, groups, hosts where nothing listens and a
snippet go in), its unlock screen opens it, and what the page throws is heard (with when: the
app's start, the setup or the walk). It never reloads the page, which would drop the app's calls
still under way. It waits for the device to finish what it does after booting (up to 5 minutes;
a fresh emulator compiles apps for a while). Then `MONKEY_ROUNDS` (5) rounds of `MONKEY_EVENTS`
(1000) touches, swipes, screen turns and navigation keys, each round from a fresh start with the
app's task pinned (so Back and swipes stay in it; starts of other apps are refused). It fails on a
crash or an ANR, a Rust panic or a Java exception in the log, an error the page throws, the process
ending, the page going blank or the app no longer drawing a frame at the end of a round, writing
`failure.txt` with the seed; `MONKEY_SEED` repeats the events (not always what they hit: timing
differs). On an emulator, where the ANR reports can be read (through `su`), the main thread's stack
goes to the round's `anr.txt`. `MONKEY_ANR=note` notes ANRs instead of failing on them, for an
emulator drawing in software, whose frames can take longer than the 5 seconds Android gives a
touch; the app still has to draw again by the end of the round. It starts by clearing the app's
data, so don't point it at a phone whose MorphGate you use.

```sh
cd apps/desktop && npx tauri android build --debug --apk --target x86_64 && cd ../..
node apps/desktop/e2e/android-monkey.mjs \
  apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk target/e2e/android-monkey
```

Each round's logcat, the monkey's output and a screenshot go to `round-<n>/`; CI uploads them as
the `android-monkey` artifact for 7 days.

## How it stays out of your way

- **Display:** each scenario runs in a headless `mutter` inside `dbus-run-session`. Nothing shows on your
  screen, and nothing reaches your session bus or keyring.
- **Data:** `HOME` and the XDG directories point at the run directory, so your vault and settings are
  never read or written.
- **Network:** everything is on loopback (sshd on 127.0.0.1 to 127.0.0.4), on ports free when the
  run starts, so runs can share a machine: sshd (`E2E_SSH_PORT`), the update feed
  (`E2E_FEED_PORT`), the sync server (`E2E_SYNC_PORT`), the test identity provider
  (`E2E_IDP_PORT`), the stand-in feed of hosts (`E2E_HOST_FEED_PORT`), and two per tauri-driver (`E2E_DRIVER_PORT`: from that port up). Set them to
  pin a port.
- **Files on the "server":** sshd's SFTP sessions start in the run's `sshd/home`, whose
  `.ssh/authorized_keys` is the file sshd reads, so the offboarding steps edit that copy and never
  your real `~/.ssh`.
- **Several people:** with `E2E_PEOPLE="alice bob"`, `session.sh` starts one tauri-driver per person,
  each with its own `HOME`, so their apps have separate vaults in the same headless display.

## Test packages

`run.sh` builds the app twice: the current version (AppImage, deb, rpm) and the next patch version
(AppImage only), which is the update. Both differ from release builds in two ways:
- they trust a throwaway update key generated for the run (stored in `target/e2e/packages/`) instead
  of the real one;
- they may fetch updates over plain HTTP, from the local feed (`feed.mjs`).

The test packages are moved out of `target/release/bundle` so they can't be mistaken for release
builds. Never publish them.

## Requirements

- Node 22, `mutter`, `dbus-run-session`
- `WebKitWebDriver`: Fedora `webkitgtk6.0`, Debian/Ubuntu `webkit2gtk-driver`
- `tauri-driver`: `cargo install tauri-driver --locked`, or set `TAURI_DRIVER` to its path
- OpenSSH (`sshd`, `ssh-keygen`), `rpm2cpio`, `cpio`, `ar`
- The usual Tauri build dependencies

## Why the DOM instead of WebDriver input

WebKitGTK's automation can't synthesize keyboard or mouse input on Wayland ("unsupported
operation"). So `webdriver.mjs` clicks and types through the DOM:
- Fields are set the way React notices.
- The terminal gets xterm's input events, as an input method would send them.

Screenshots and script execution go through WebDriver as usual.
