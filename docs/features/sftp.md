# SFTP

The file browser opens a saved host in a tab of its own: this computer on the left, the server on the right, and transfers between them with progress, cancel and replace. Each tab has its own SSH connection over the host's whole route (saved sign-in, jump hosts, VPN or proxy command) and runs the `sftp` subsystem on it. Phones get a one-folder browser instead. Code: `crates/mg-ssh/src/sftp.rs` (`Sftp`, transfers), `apps/desktop/src-tauri/src/sftp.rs` (Tauri commands, `SftpState`), `apps/desktop/src/SftpView.tsx`, `apps/desktop/src/mobile/MobileSftp.tsx`.

## Opening a browser

| Where | Control |
| --- | --- |
| Sidebar | The folder icon on a host row ("Browse files (SFTP)") |
| Hosts page, a group's page | **Files** |
| Route bar of a terminal | **Files** |
| Phone | **Files** on the host's sheet, or **More** › **Files** in a terminal |

Only saved hosts have a browser; quick-connect sessions don't. A host whose cloud provider reports no SFTP (`source.no_sftp`) has no **Files** in the sidebar, the Hosts page or on a phone (the route bar's **Files** doesn't check it). The tab is marked **SFTP** and titled with the host's label.

`sftp_open` resolves the route like a terminal ([SSH connections](ssh-connections.md)), connects with a 15 s timeout per hop, and `Sftp::open` requests the `sftp` subsystem on a session channel (`russh-sftp`, up to 32 reads and 32 writes in flight, 30 s per request). It returns the connection id and the login directory (`canonicalize(".")`). SFTP tabs never use tmux, a login command or recording.

## Tauri commands

| Command | Arguments | Does |
| --- | --- | --- |
| `sftp_open` | `target` | Connects; `{id, home}` |
| `sftp_close` | `id` | Drops the connection |
| `sftp_list` | `id`, `path` | The server makes the path absolute; `{path, entries}` |
| `sftp_mkdir` | `id`, `path` | New folder |
| `sftp_rename` | `id`, `from`, `to` | Refuses when `to` exists |
| `sftp_remove` | `id`, `paths` | Files, links and whole trees |
| `sftp_chmod` | `id`, `path`, `mode` | Permission bits (`mode & 0o7777`) |
| `sftp_download` | `id`, `paths`, `localDir`, `overwrite`, `onEvent` | Starts a transfer in the background; returns its id |
| `sftp_upload` | `id`, `paths`, `remoteDir`, `overwrite`, `onEvent` | The same, the other way |
| `sftp_cancel` | `transfer` | Stops a transfer |
| `local_home`, `local_list`, `local_mkdir` | `path` | The left pane: home folder, listing (`~` expanded, path made absolute), new folder |

An entry is `{name, kind: "dir" | "file" | "symlink" | "other", size, modified, mode, linkDir}`. Listings put folders first, then sort by name ignoring case. A symlink is looked up: one pointing at a folder gets `linkDir` and opens like a folder; one pointing at a file shows the target's size.

## The panes

| Control (`SftpView.tsx`) | Does |
| --- | --- |
| **This computer** / the host's label | Pane titles; the remote one says "(connecting…)" until connected. Both start in the home folder |
| Up arrow ("Parent folder") | The parent folder |
| The path | Click to type a path; Enter goes there, Escape cancels |
| Refresh | Lists the folder again |
| **Name**, **Size**, **Modified**, **Permissions** | Columns; permissions as `drwxr-xr-x` |
| **New folder** | Both panes |
| **Upload →** | The local selection into the remote pane's folder |
| **← Download** | The remote selection into the local pane's folder |
| **Rename**, **Permissions** | One remote item |
| **Delete** | The remote selection, after a confirmation |

Windows paths work in the local pane (`\`, drive roots).

### Selection and keyboard

| Input | Does |
| --- | --- |
| Click, Ctrl/Cmd-click, Shift-click | Select one, toggle one, select a range |
| Double-click | Opens a folder or a link to one |
| Ctrl/Cmd+A | Selects everything in the pane |
| Backspace | Parent folder |
| Enter | Opens the selected folder (one selected) |
| Delete | Deletes the remote selection (remote pane) |

The keys work while the pane has the focus and not inside a text field.

## Transfers

| Way | Detail |
| --- | --- |
| Buttons | **Upload →**, **← Download** |
| Drag between panes | Onto the pane: its current folder. Onto a folder row: into that folder. Dropping on the pane it came from does nothing |
| From the desktop | Files dropped from the OS onto the remote pane (Tauri's `onDragDropEvent`, hit-tested against the pane) go into the remote pane's current folder |

How a transfer runs (`Sftp::download`, `Sftp::upload`):

1. **Plan.** The selected trees are walked first (local ones in a blocking task) into folders to create and files to copy. Folder links, dangling links and special files (sockets, devices) are skipped; links to files are followed and their contents copied.
2. **Conflicts.** Unless it may overwrite, each top-level name is checked at the destination before anything is written (see below).
3. **Folders**, parents first; ones that already exist are kept.
4. **Files**, one after another, in 256 KiB reads (`CHUNK`). A download is written to `name.mgpart` and renamed when complete, so an interrupted one never looks finished. An upload is written in place.
5. **Modes.** On Unix, a downloaded file gets the remote mode (`& 0o777`) and an uploaded one is `chmod`ed to the local mode. On Windows uploads keep the server's default. Modification times and owners are not kept.

Progress events are sent at most every 120 ms (`PROGRESS_EVERY`), plus the first and the last: `{bytesDone, bytesTotal, filesDone, filesTotal, current}`. The transfer row shows "*done* of *total* · file *i* of *n* · *speed*/s" ("Preparing…" before the first event), then "Done · *n* files, *size*" with " · skipped *n* linked folder(s)" when something was skipped (the count covers every skipped entry, not only folder links), and refreshes the destination pane. **Cancel** sets a flag checked between chunks: the file being copied is removed (the local `.mgpart`, or the partial remote file), files already copied stay, and the row says "Cancelled". A failed file is removed the same way. Several transfers can run at once on one connection.

### Conflicts and overwrite

| Case | Behavior |
| --- | --- |
| A top-level name exists at the destination | Nothing is copied; the row says "*name* already exists" and offers **Replace** |
| **Replace** | Runs the transfer again with `overwrite: true`: files are replaced (remote files truncated, local ones renamed over), folders are merged, and files at the destination that the source doesn't have stay |
| A file appears at the destination during an upload | Uploads that may not overwrite create files exclusively (`CREATE | EXCLUDE`), so it isn't clobbered: "*path* already exists" |
| Rename onto an existing name | "*path* already exists". Checked before the rename, not atomic |

## Managing remote files

| Action | Dialog | Detail |
| --- | --- | --- |
| **New folder** | "New folder", "In *path*", **Create** | `sftp_mkdir` or `local_mkdir` |
| **Rename** | "Rename", "New name", **Rename** | Within the current folder |
| **Permissions** | "Permissions of *name*", "Octal mode (e.g. 644, 755, 600)", **Apply** | Three or four octal digits, else "Use three or four octal digits, like 644 or 0755." Four digits can set setuid, setgid and sticky bits |
| **Delete** | "Delete “*name*”?" or "Delete *n* items?", "This deletes … on *host*. It can't be undone." (", including everything inside" when a folder is selected), **Delete** | Depth first, without recursion; links are removed, never followed |

The local pane only creates folders: no rename, delete or permissions there.

## Errors

| Message | When |
| --- | --- |
| A connection error (the terminal's messages) | `sftp_open` failed; the tab shows it and stays. Close it and open **Files** again |
| `sftp: the server has no SFTP subsystem (…)` | The server has no `Subsystem sftp` |
| `sftp: path: no such file or directory`, `sftp: path: permission denied`, `sftp: path: server message` | SFTP status errors |
| `path: OS error` | A local file or folder |
| `the SFTP connection is closed` | The connection id is gone (closed tab, lock) |
| `sftp: path: this server can't replace files atomically (no posix-rename@openssh.com)` | Only from `Sftp::replace_file`, which offboarding uses for `authorized_keys` ([Offboarding](offboarding.md)); the browser never calls it |

## Phones

`MobileSftp.tsx` shows one remote folder at a time.

| Control | Does |
| --- | --- |
| Tap a folder, parent button | Opens it, goes up |
| Tap a file | Selects or deselects it; folders can't be selected |
| **Download** | The selected files into the device's Downloads folder (`downloadDir()`, else the home folder) |
| Upload (header) | A sheet that picks files from local folders, starting at Downloads; **Upload *n* files** |
| New folder (header), **Rename**, **Delete** | As on the desktop; "Folders are deleted with everything in them. This can't be undone." |

Phones never overwrite: there is no **Replace**, and an existing name fails the transfer. There is no **Permissions**, and one transfer is shown at a time.

## Limits and defaults

| Item | Value |
| --- | --- |
| Read and write size | 256 KiB (`CHUNK`) |
| Requests in flight | 32 reads, 32 writes (`russh_sftp::client::Config`) |
| Request timeout | 30 s |
| Partial downloads | `name.mgpart` (`PART`) |
| Progress interval | 120 ms (`PROGRESS_EVERY`) |
| Connect timeout | 15 s per hop |

Not built: reconnecting a dropped browser (close the tab and open **Files** again), resuming an interrupted transfer, dragging files out of the app to the desktop, previewing or editing files, keeping modification times, and rename or delete in the local pane.

## Tests

| Test | Covers |
| --- | --- |
| `crates/mg-ssh/src/sftp.rs`: `posix_paths`, `local_listing_puts_directories_first` | Path helpers; local listing order and kinds |
| `apps/desktop/src-tauri/src/sftp.rs`: `ipc_shapes_match_the_frontend` | Transfer events and entries as the webview reads them |
| `crates/mg-ssh/tests/live.rs`: `sftp_browse_transfer_and_manage` | Uploading a tree, refusing to overwrite, downloading it back byte for byte, rename refusing to clobber, chmod, deleting a tree, cancel removing the partial file, a full-size round trip. Needs `MG_TEST_SSH` with `Subsystem sftp` |
| `crates/mg-ssh/tests/live.rs`: `authorized_keys_are_replaced_atomically` | `replace_file` |
| `apps/desktop/e2e/teams.mjs`, `apps/desktop/e2e/mobile.mjs` | **Files** in the route bar lists the server; on a phone, browsing into a folder and downloading a file to Downloads |
