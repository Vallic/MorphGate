# Deep links

`morphgate://` links let a web page open a screen of the app: the website's invite and account pages, and consoles that list servers (the Vallic console's Shell access card). Anyone can put such a link on a page, so a link only opens a screen, filled in. It never joins a team, connects, or changes anything by itself, and it ignores passwords, keys and anything else it does not list; the person reads the screen and acts. Links that arrive while the vault is locked wait until it is unlocked. Code: `apps/desktop/src-tauri/src/links.rs` (parsing, the queue, `links_take`), `plugins.deep-link` in `apps/desktop/src-tauri/tauri.conf.json`, the deep-link setup in `apps/desktop/src-tauri/src/lib.rs`, `openLink` in `apps/desktop/src/App.tsx`, `apps/desktop/src/ConnectForm.tsx` (the filled-in quick connect).

## Links

| Link | Opens | Who sends it |
| --- | --- | --- |
| `morphgate://invite?token=<code>&server=<origin>` | Teams → **Join with an invite**, with the code looked up; the person compares the owner's fingerprint and chooses **Join {team}** ([Teams](teams.md#joining)) | The website's invite page, **Open in MorphGate** |
| `morphgate://invite/<code>` | The same, without a server | |
| `morphgate://sync` | The Sync page | The website's account page, **Open MorphGate** |
| `morphgate://teams` | The Teams page | |
| `morphgate://teams/<org id>` | That team's page | The team page, **Open this team in MorphGate** |
| `morphgate://connect?host=<host>&port=<port>&user=<user>&label=<name>` | Quick connect, filled in, with "Filled in from a link for {label}. Check the address before you connect."; on phones the Quick connect screen. `label` names the tab | Server consoles |

Dev builds answer `morphgate-dev://` instead (`SCHEMES` accepts both; the release workflow registers only `morphgate-dev` for them), so a dev build never takes the release app's links.

## What the app accepts

`parse()` reads the action from the URL's host part (case-insensitive) and values from URL-encoded query parameters. Values are trimmed, an empty value counts as absent, and the first of a repeated parameter wins.

| Value | Accepted | Refused with |
| --- | --- | --- |
| `token` (or the first path segment) | 16 to 256 characters of `A-Z a-z 0-9 - _` | "the invite link has no code", "the invite code in the link isn't valid" |
| `server` | An `https://` origin, or `http://` for `localhost`, `127.0.0.1` and `[::1]`; no user name or password. Reduced to its origin | "the server in the link isn't a sync server address" |
| org id (path) | 26 letters and digits (a ULID), uppercased | "the team in the link isn't valid" |
| `host` | Up to 253 characters of letters, digits, `.`, `-`, `:`, `[`, `]`; brackets around an IPv6 address are removed | "the link names no host", "the host in the link isn't a host name or address" |
| `port` | 1 to 65535 | "the port in the link isn't valid" |
| `user` | Up to 64 characters of `A-Z a-z 0-9 . _ -` | "the user in the link isn't valid" |
| `label` | Anything; control characters are dropped and it is cut to 64 characters | |
| no action | | "the link says nothing to open" |
| another action | | "this version of MorphGate doesn't know “{action}” links" |

A refused link shows a banner: "MorphGate can't open this link: {reason}".

## What is ignored, and why

| Case | What happens | Why |
| --- | --- | --- |
| Parameters the table does not list (`password`, `key`, `identity`, a command) | Dropped | A link can come from any page. A secret in a URL also ends up in browser history and logs |
| Another scheme (`https://…`) handed to the app | Dropped silently (`received()` keeps only its own schemes) | |
| `connect` | Fills in host, port, user and label only. The person picks how to sign in, and the host key is checked as for any connection | Connecting is the person's decision; a link could point at a look-alike host |
| Host or user with other characters (`a;rm -rf`, `root;id`) | Refused | Only names and addresses get through, never shell syntax or options |
| `invite` while sync is off or signed out | Notice "This is an invite to a team on {server}. Turn on sync with the invited address first, then open the link again." and the Sync page opens | An invite is accepted by a signed-in account |
| `invite` whose `server` is not the server this device syncs with | Notice "This invite is for a team on {server}, but this device syncs with {other}."; nothing opens | Invite codes are only valid on the server that made them |

Joining still needs the fingerprint check and a click on **Join {team}**; quick connect still needs **Connect**. [Trust boundaries](../architecture.md#trust-boundaries) lists links among the app's inputs.

## Delivery

1. The operating system hands the URL to `tauri-plugin-deep-link`: at launch (`get_current()` in setup) or while running (`on_open_url`).
2. On Windows and Linux a link starts a second copy of the app. `tauri-plugin-single-instance` (with its `deep-link` feature) passes the URL to the copy already running for this user's vault and the second copy exits. On macOS and the phones the system delivers the URL to the running app.
3. `links::received()` parses each URL into a `Received {link, error}`, appends it to the `Links` queue, brings the window forward on desktop (`show()`: unminimize, show, focus) and emits `links-pending`.
4. The unlocked workspace calls `links_take` when it mounts and on every `links-pending`, and opens each link (`openLink` in `App.tsx`). While the vault is locked nothing takes them, so they wait in the queue until unlock.

| Command or event | Does |
| --- | --- |
| `links_take` | Returns and empties the queue of received links |
| `links-pending` (event) | A link arrived; the workspace takes it |

## Registering the scheme

`plugins.deep-link` in `tauri.conf.json` names the scheme for desktop and mobile; the bundler and the plugin do the rest.

| Platform | How the scheme is registered |
| --- | --- |
| Windows | The NSIS and MSI installers register `morphgate` for the user |
| Linux, deb and rpm | The package's desktop entry (`linux/morphgate.desktop` template) has `MimeType=x-scheme-handler/morphgate` and `Exec=morphgate %u` |
| Linux, AppImage | Nothing installs an AppImage, so it registers itself at every start: `register_all()` writes a desktop entry to `~/.local/share/applications` and calls `xdg-mime`. A failure is logged ("registering morphgate:// links: …") and the app starts anyway |
| macOS | `CFBundleURLTypes` in the app bundle's `Info.plist` |
| Android | An intent filter (`VIEW`, `BROWSABLE`, `scheme="morphgate"`) that the plugin writes into `gen/android/app/src/main/AndroidManifest.xml`. `appLink: false`: a custom scheme, not a verified `https` App Link |
| iOS | `CFBundleURLTypes` in `gen/apple/morphgate-desktop_iOS/Info.plist` |

A development build (`npm run tauri dev`) is not registered by anything; try links with a package or an AppImage. On Linux the e2e runs launch the AppImage with the link as its argument, the way the desktop does.

## Tests

| Test | Covers |
| --- | --- |
| `links.rs` `invites` | Both invite forms, the server reduced to its origin, short codes, plain-HTTP servers elsewhere than this computer and servers with credentials refused, the local reference server allowed |
| `links.rs` `pages` | `sync`, `teams`, a team id uppercased, `teams/../../etc` refused, an unknown action named in the error, an `https` URL refused |
| `links.rs` `connect_fills_in_and_ignores_secrets` | `password=` dropped, IPv6 brackets removed, shell syntax in host or user refused, port 0 refused, no host refused |
| `apps/desktop/e2e/appimage.mjs` | A second launch with `morphgate://connect?…&password=hunter2` exits and the running app shows quick connect filled in, without the password; it connects once a key is pasted and **Connect** is clicked. `morphgate://format-disk` shows "doesn't know “format-disk” links" |
| `apps/desktop/e2e/package.mjs` | The deb's and rpm's desktop entries handle `x-scheme-handler/morphgate` |

## Limits

- No `https` links (App Links, Universal Links): only the custom scheme.
- A link cannot open a saved host, start a session, or name a key or a VPN.
- Links open only in the unlocked workspace.
