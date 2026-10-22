# Terminal and snippets

Once a connection is open, each SSH session is a terminal: xterm.js in the webview, a PTY on the server, and raw bytes between them over Tauri channels. Sessions live in tabs, a tab can be split into panes (and typing broadcast to all of them), the route bar above a session shows how it gets there, and snippets paste or run saved commands. A host can also keep its session in tmux on the server, so a dropped connection picks up where it was. How the connection itself is made (route, sign-in, host keys) is in [SSH connections](ssh-connections.md); the overview is in [App architecture](../architecture.md#how-a-connection-runs). Code: `crates/mg-ssh/src/session.rs` (`Session`, `SessionEvent`), `apps/desktop/src-tauri/src/ssh.rs` (Tauri commands, `tmux_command`), `apps/desktop/src/TerminalView.tsx`, `apps/desktop/src/api.ts` (`connect`, `createWriter`), `apps/desktop/src/App.tsx` (tabs, splits, broadcast), `apps/desktop/src/splits.ts`, `apps/desktop/src/RouteBar.tsx`, `apps/desktop/src/SnippetPanel.tsx`.

## Bytes in and out

```
xterm.js ──onData──> createWriter ──ssh_write──> Session::write ──> channel data
xterm.js <──write── on_output (raw bytes) <── relay task <── mpsc(256) <── reader task <── russh
```

| Step | What happens |
| --- | --- |
| Open | `Session::open` opens a session channel, asks for agent forwarding when the host forwards the agent, requests a PTY (`xterm-256color`, the tab's columns and rows, no terminal modes), then starts a shell or `exec`s a command (see [What the session runs](#what-the-session-runs)) |
| Output | A reader task turns `ChannelMsg::Data` and `ExtendedData` (stderr joins the same stream) into `SessionEvent::Output`, `ExitStatus` into `Exit { status }`, and `Close` into `Closed`, on a bounded channel of `EVENT_BUFFER` (256) events |
| Relay | `ssh_connect` spawns a task that feeds output to the session recorder (if the host records, see [Session logs](session-logs.md)) and sends it on the `on_output` channel as `InvokeResponseBody::Raw`: an `ArrayBuffer` in the webview, no JSON or base64. Exit and close go on `on_status` |
| Display | `connect()` in `api.ts` hands the bytes to `term.write()`. xterm.js decodes UTF-8 itself, including sequences split across chunks |
| Input | `term.onData` goes through `createWriter(id)`: one `ssh_write` in flight at a time, and whatever is typed meanwhile is joined into the next call. Keystrokes stay in order (separate IPC calls could finish out of order) and a paste is one write |
| Resize | The `FitAddon` fits the terminal to its element on every `ResizeObserver` change while it is visible (`offsetParent` set), when the tab is shown, and after a font change. xterm's `onResize` calls `ssh_resize`, which logs the size in the recording and sends `window-change` |

**Back-pressure.** When 256 events are queued, the reader task waits in `tx.send()` and stops reading the channel; once russh's own per-channel buffer (`channel_buffer_size`, 100 messages) is full, russh's connection loop waits too, stops reading the socket, and TCP slows the server. (russh refills the SSH window as data arrives, so it is the stalled connection, not the window, that pushes back. Each terminal has its own connection, so only that tab stalls.) The relay does not wait for the webview: Tauri's `Channel::send` returns at once, so under a flood the queue drains as fast as messages can be posted, and bursts collect in xterm.js's write buffer.

### Tauri commands

| Command | Arguments | Does |
| --- | --- | --- |
| `ssh_connect` | `request: {target, size}`, `onOutput`, `onStatus` channels | Opens the session and returns its id. Starts a recorder for hosts with `record_sessions` |
| `ssh_write` | `id`, `data` (string) | Sends input. "session is closed" when the id is gone |
| `ssh_resize` | `id`, `size: {cols, rows}` | Window change; an `r` event in the recording |
| `ssh_disconnect` | `id` | Closes the channel and the connection |
| `host_pinned_key` | `host`, `port` | The route bar's pinned key |
| `host_certified_by` | `host`, `port` | The host CA that vouches for an unpinned host |

`on_status` carries `{kind: "exit", status}`, `{kind: "closed"}` and `{kind: "recording", logId}`. The target is `{kind: "saved", hostId, password?, tmux?}` or `{kind: "adhoc", host, port, user, auth}` (quick connect).

## What the session runs

| Host (with its group and identity applied) | The channel runs |
| --- | --- |
| **Login command (optional)** set (`login_command`) | `exec` of that command, with the PTY (as `ssh -t host <command>`) |
| **Keep the session on the server (tmux)** (`keep_session`, also from the group's **Keep sessions on the server (tmux)**) | `tmux new-session -A -s <name> \|\| exec $SHELL -l` |
| Neither, or quick connect | The login shell |

A login command wins; the host editor disables the tmux checkbox while one is set.

### Keeping the session on the server

- `connectHost()` in `App.tsx` gives each terminal tab of the host the first name not used by another open tab of that host: `morphgate`, `morphgate-2`, `morphgate-3`, …
- `new-session -A` attaches when the session exists and creates it otherwise. Without tmux on the server the command fails and `exec $SHELL -l` gives a login shell. The command is written to work in sh, bash, zsh, fish and tcsh.
- The name comes from the webview, so `tmux_command()` only accepts up to 64 ASCII letters, digits, `-` and `_`; anything else becomes `morphgate`. This keeps it out of the shell command line.
- A reconnect reuses the tab's target, so it attaches to the same tmux session. A new tab after one was closed reuses the lowest free name, so it attaches to that tmux session again; another device's first tab is `morphgate` too, so both show the same session.
- Closing a tab only detaches. The app never kills a tmux session: exit the shell in it, or `tmux kill-session`.
- SFTP tabs and tunnels never use tmux.

## Reconnecting

| How the session ended | In the terminal | Bar under the tab | Retries |
| --- | --- | --- | --- |
| The remote side exited (exit status, then close) | `[process exited with status N]`, `[connection closed]` | "The session ended." **Reconnect** | No |
| The connection dropped (closed without an exit status) | `[connection lost]` | "Connection lost. Retrying in N s…" **Retry now**; after the last try "Connection lost." **Reconnect** | After 2, 5, 15 and 30 s (`RETRIES`) |
| It never opened | The error, in red | "Couldn't connect." **Reconnect** | Only if this tab was connected before |

- A retry that comes due while `navigator.onLine` is false waits for the `online` event.
- Each attempt is a new `ssh_connect` in the same xterm.js instance, so the scrollback stays ("Reconnecting to …"). A successful open, or **Reconnect**, resets the attempts.
- Dead connections are noticed by keepalives: `keepalive_interval` 30 s, `keepalive_max` 3, so about 90 s on a silent network. Each hop has a 15 s connect timeout.
- A password typed for a host without a saved one, and quick-connect credentials (the password, or the key's text and passphrase), stay in the tab's target in webview memory until the tab closes: reconnects and "this host again" splits use them.

## Tabs

| In a tab | Meaning |
| --- | --- |
| Dot | Status: `connecting`, `connected`, `failed`, `closed` |
| **PROD** | The host uses the Production scheme ([Appearance](appearance.md)) |
| **REC** | Recorded into the vault, while connected (title "This session is recorded into the vault") |
| **SFTP** | A file browser tab ([SFTP](sftp.md)) |
| `+N` | A split with N more panes; the title says when typing goes to all of them |
| Close (×) | "Close tab", or "Close the tab and its panes" for a split |

Sessions open from the sidebar (click a host), the Hosts page (**Connect**), and **Quick connect** (the plus at the end of the tab bar, or the Hosts page's **Quick connect**). A host can have any number of tabs. Every `TerminalView` stays mounted whatever is shown, so hidden sessions keep running. Locking the vault unmounts the workspace, and each `TerminalView` disconnects as it goes; `vault_lock` itself stops tunnels, SFTP and VPNs. Tabs are kept in memory only: they are not restored after a restart or an unlock.

## Split panes

A split is a tree (`splits.ts`): `{pane: key}`, or `{dir: "row" | "column", parts, sizes}` with `sizes` as fractions that add up to 1. `Split` adds `broadcast` and `focus` (the pane the tab reopens on).

| Control | Does |
| --- | --- |
| **Split** (route bar) | A menu: **Side by side** or **Below**, then the current host ("This host again, a new session") or a host found under **Another host…** (label, hostname, user, tags; the first 8). "This host again" reuses the tab's target, quick-connect credentials or typed password included |
| Divider drag | `moveDivider()`; each part keeps at least `MIN` (10 %) of its row or column |
| Pane header | Status, **PROD**, the title, **BROADCAST** while on, and close ("Close the pane …") |
| **Broadcast** / **Broadcasting to N** (route bar, split tabs only) | Turns broadcast on or off |

- Splitting along the row or column a pane is already in adds a sibling with half of its share (`addPane`); the other direction nests a new split, 50/50.
- Each pane is a full session: its own connection, tmux session and recording. The tab bar shows one tab per split, and clicking it returns to the pane last used.
- Closing a pane gives its share to its neighbours (`removePane`). When one pane is left, the split becomes a plain tab.
- With broadcast on, what is typed in one pane (`onData`) is sent as is to every other connected pane of the split (`broadcastFrom`). Snippets from the route bar go to every connected pane; snippets sent from the Snippets page or a snippet's editor go to one terminal only.

## The route bar

Shown above terminal tabs (`RouteBar.tsx`). Its menus close on a click elsewhere or Escape.

| Item | Shows or does |
| --- | --- |
| VPN chip | The first hop's VPN; its address once up, "comes up with the session" before |
| Jump host chips | `jumpChain()`, first hop first; stops after 8 or at a loop |
| Host chip | Label and `user@host:port` |
| **Recording** | When recorded; opens the host's session logs |
| Key | The pinned key's type and a short fingerprint (`SHA256:q3Xv…T0wE`), read once connected |
| "certified by …" | No pinned key, but a trusted host CA signed its certificate |
| **Files** | Opens an SFTP tab to the host; saved hosts only |
| **Broadcast**, **Split** | See above |
| **Snippets** | Each snippet pastes on click, **Run** pastes and presses Enter; disabled until connected. "Broadcasting: snippets go to all N panes." while broadcasting. **New snippet…** opens the editor |

## Snippets

A `snippet` item: `name` (trimmed), `body` (exactly as typed), `tags` (trimmed, empty ones dropped, left out of the JSON when there are none), and `source` (`SnippetSource {source_ref, external_id}`) when a feed keeps it. Lists sort by name, ignoring case. A snippet lives in any vault; in a view-only vault it can be sent but not edited. Importing from CSV is in [Importing](importing.md).

### A feed's snippets

A feed ([Cloud sources](cloud-sources.md#feeds)) brings snippets as well as hosts. The feed decides them whole: each refresh sets name, body and tags, and deletes one the feed no longer lists (nobody's edits are lost: they can't be edited). In the app they are read-only:

| Where | Difference |
| --- | --- |
| Snippets page | "From {feed} (read-only)" under the snippet's name; the row's icon is **Open** rather than **Edit** |
| Editor | "From the feed **{feed}**: it changes there, and is read-only here." with **Make a copy** (a snippet of one's own, "{name} (copy)", in the same vault, or the personal one when that's view-only, which then opens); the fields are read-only, and there's no **Save** or **Delete** |
| `snippet_save`, `snippet_delete` | Refused: "\"{name}\" comes from {feed}: it changes there, or make a copy to change it here" |
| Bulk delete | Left out: "\"{name}\" comes from a feed: it goes when the feed drops it" |
| Removing the feed | **Remove it, its hosts and snippets** deletes them; **Remove it, keep the hosts and snippets** makes them ordinary snippets |

**Run** and **Paste** ask first when the feed changed the body since this device last sent it: "{name} changed", "Changed by **{feed}** on {date}, since you last ran it on this device. It now runs:" with the body, **Cancel** and **Run it** (or **Paste it**) (`SnippetCheck.tsx`). Every place a snippet is sent goes through `guardSnippet` in `App.tsx`: the route bar's menu, the Snippets page, the editor and the phone's **Snippets** sheet. After a feed's snippet is sent, `snippet_sent` keeps the SHA-256 of its body on this device (setting `snippet-sent:<id>`, not synced); `snippets_list` sets `changed` when that hash is there and differs from the body's. A snippet never sent from this device doesn't ask.

| Control (`SnippetPanel.tsx`) | Does |
| --- | --- |
| **Vault** | Where a new snippet goes |
| **Name**, **Commands**, **Tags** | Both of the first two are required; tags are comma-separated |
| **Paste** ("Insert without pressing Enter"), **Run** | Send to the target terminal: "Send to **title**", or "Open a connected terminal tab to paste or run this snippet." |
| **Delete**, then **Really delete?** | Deletes |
| **Close**, **Save snippet** / **Save changes** | |

The Snippets page (sidebar **Snippets**) lists them as a table (name, the command's first line, tags), with **Edit** per row (or the name), and **Paste** and **Run** while a terminal is connected, a search and tag filters, **Select** for bulk delete and move, **Import…** and **New snippet**. On a phone, the terminal's **More** menu has **Snippets**.

| Behavior | Detail |
| --- | --- |
| Target | The route bar's menu sends to its own session. The Snippets page and the editor send to the last terminal tab (or pane) shown, if it is connected, and switch to it |
| Paste | `term.paste()`: xterm.js wraps the text in bracketed paste when the remote side turned it on, so a multi-line snippet arrives as one block, and turns newlines into CR |
| Run | Trailing newlines removed, pasted, then Enter (`\r`). Without bracketed paste, the shell runs each line as it arrives |
| After Esc | When the last key sent was the extra-key row's Esc alone, the next paste first sends Ctrl+G: readline would otherwise read the snippet's first byte as Meta+key. Ctrl+G is readline's abort and harmless elsewhere |

| Command | Does |
| --- | --- |
| `snippets_list` | All snippets in every vault |
| `snippet_save` | `{id?, vaultId?, name, body, tags}`; a new snippet goes to `vaultId` or the personal vault |
| `snippet_delete` | `id` |
| `snippet_sent` | `id`: this device sent a feed's snippet (keeps its body's hash) |

## Keyboard

| Where | Keys | Does |
| --- | --- | --- |
| Terminal | Everything | Goes to the session as xterm.js encodes it. The app adds no key bindings and no menu accelerators; copy and paste are what xterm.js and the platform's webview do |
| Route bar menus | Escape | Closes the menu |
| Phone extra-key row | **Esc**, **Tab**, **Ctrl**, **↑** **↓** **←** **→**, **\|**, **~**, **/** | **Ctrl** latches for the next key: `@`, letters and `[\]^_` become control characters, space NUL, `?` DEL, an arrow `ESC [1;5A`… Arrows follow xterm's application cursor mode (`ESC O` or `ESC [`) |
| SFTP panes | See [SFTP](sftp.md#selection-and-keyboard) | |

## Settings and the phone layout

The terminal has 10,000 lines of scrollback and a line height of 1.15. Theme, font, size, cursor, bold-in-bright and minimum contrast come from the host's scheme or this device's settings and apply to open sessions ([Appearance](appearance.md)).

The phone layout (`mobile/MobileWorkspace.tsx`) is used on Android and iPhone, and in windows up to 640 px wide (`NARROW`). The width is only followed while no tab is open, since switching layouts would reopen every session. It has a full-screen terminal, a sheet of open sessions, **More** (**Files**, **Snippets**, **Disconnect**) and the extra-key row; no splits. See [Platforms and mobile](platforms-and-mobile.md).

## Tests

| Test | Covers |
| --- | --- |
| `apps/desktop/src-tauri/src/ssh.rs`: `tmux_sessions_are_named_safely`, `connect_request_shapes_match_the_frontend` | tmux names; the JSON the webview sends |
| `crates/mg-ssh/tests/live.rs`: `shell_resize_exit_and_tofu` | A real PTY shell: output, resize, exit status. Needs `MG_TEST_SSH` (the file's header shows a throwaway sshd); run with `cargo test -p mg-ssh --test live -- --include-ignored --test-threads=1` |
| `apps/desktop/e2e/appimage.mjs` | Splits a tab into three panes (beside and below, one through a jump host), broadcasts, types into one, drags a border, closes them |
| `apps/desktop/e2e/teams.mjs` | A group's identity and tmux session; **Reconnect** picks the tmux session back up |
| `apps/desktop/e2e/mobile.mjs` | Ctrl and ↑ from the extra-key row; Esc then a snippet runs as written; a snippet imported from CSV |
| `apps/desktop/src-tauri/src/bulk.rs`: `deletes_snippets_and_groups_and_says_what_it_leaves` | Bulk delete |
| `apps/desktop/e2e/appimage.mjs` (the feed) | A feed's snippet runs; it's read-only with **Make a copy**; changed by the feed, running it asks first, once |

The e2e scenarios run with `apps/desktop/e2e/run.sh` (`E2E_ONLY=appimage`, `teams` or `mobile` for one).

## Limits

| Not there | Detail |
| --- | --- |
| Shortcuts | No keys for new tab, switching tabs, splitting or closing |
| Search, links, GPU renderer | Only `@xterm/addon-fit` is loaded: no find in scrollback, no clickable URLs, the default renderer |
| Binary input | xterm's `onBinary` (legacy X10 mouse reports past column 95) is not forwarded |
| Splits on phones | The phone layout has no splits or broadcast |
| Restoring tabs | Tabs and splits are not saved; tmux is the way to keep work across restarts and locks |
| Background on iOS | No Mosh: a session doesn't outlast iOS suspending the app. A host that keeps its session in tmux picks it up again on reconnect |
