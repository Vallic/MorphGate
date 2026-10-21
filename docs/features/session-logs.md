# Session logs

A saved host with **Record sessions into the vault** on has what each terminal session prints recorded as an asciicast v2 stream. The stream is deflated in chunks, each chunk sealed under the host's vault key as a blob, and a `session_log` item in the same vault lists the chunks. Sync uploads the blobs as encrypted `session_log` blobs and other devices fetch them when a recording is played, so the sync server stores recordings it cannot read. Recordings in a team's vault need a server that stores blobs (`features.blobs`) and, on a server with plans (such as morphgate.com), a team plan whose features include `session_logs`. The server's side is the `blobs` part of `spec/openapi.yaml`. Code: `apps/desktop/src-tauri/src/session_log.rs` (`Recorder`, Tauri commands), `apps/desktop/src-tauri/src/ssh.rs` (`ssh_connect`, `ssh_resize`), `crates/mg-store/src/blobs.rs`, `crates/mg-vault/src/blob.rs`, `crates/mg-store/src/sync.rs` (uploads), `apps/desktop/src/SessionLogs.tsx`.

## Turning it on

`record_sessions` is a field of the host item, set by the checkbox **Record sessions into the vault** in the host editor (not inherited from groups). With it ticked the editor says: "What each session prints is saved, encrypted with the vault's key, and synced with it. In a team's vault, everyone who can open the vault can play it back; hosted MorphGate keeps team recordings on the Business plan." For a host in a team's vault it asks the server (`org_details`) and warns:

| Server says | Warning |
| --- | --- |
| No `blobs` feature in discovery | "This sync server doesn't store session logs: recordings stay on this device." |
| The plan's features lack `session_logs` | "The team's plan doesn't include session logs: recordings stay on this device until it is on the Business plan, then upload." |

## What is recorded

| Recorded | Not recorded |
| --- | --- |
| Terminal sessions to saved hosts with the field on, from the moment the session opens | Quick-connect sessions, SFTP tabs, tunnels |
| Everything the session prints, stdout and stderr, as `[t, "o", text]` | Keystrokes: there are no `i` events. Whatever the server echoes, typed commands included, is output; a password typed at a prompt that doesn't echo is not |
| Size changes, as `[t, "r", "COLSxROWS"]` (from `ssh_resize`) | |

`t` is seconds since the start, to the microsecond. The first line is the header `{"version": 2, "width", "height", "timestamp", "title", "env": {"TERM": "xterm-256color"}}`. A UTF-8 sequence split across two reads is held until it is complete; invalid bytes become U+FFFD.

Each `ssh_connect` makes its own log: every reconnect and every split pane. Recording needs write access to the host's vault; without it (or if the item can't be created) the session runs unrecorded, with only a warning in the log. While a session records, `on_status` sends `{kind: "recording", logId}`: the tab shows **REC** and the route bar **Recording** ("This session is recorded, encrypted, into the host's vault. Open its session logs"), which opens the host's logs.

## How it is stored

| Step | Detail |
| --- | --- |
| Start | `Recorder::start` creates the `session_log` item in the host's vault and wakes sync |
| Gather | Output becomes asciicast lines in memory |
| Seal a chunk | When 512 KiB of text has gathered (`CHUNK_BYTES`), or when output arrives 60 s or more after the last chunk (`FLUSH_EVERY`): raw deflate (logs shrink to a tenth or less), then `LocalVault::add_blob` seals it and stores it in the `blobs` table as `pending`, and the item is updated with the new chunk and `output_bytes` |
| Finish | When the session closes: the rest as a last chunk, and `ended_at` |
| Failure | If saving a chunk fails once (vault locked, no write access), the rest of the session isn't recorded |

The `session_log` item (`SessionLog` in `crates/mg-store/src/model.rs`):

| Field | Value |
| --- | --- |
| `host_ref` | The host, in the same vault |
| `title` | The host's label |
| `address` | `user@host:port` |
| `started_at`, `ended_at` | Unix ms; no `ended_at` while recording or if the recorder never finished |
| `cols`, `rows` | Size at the start |
| `chunks` | `[{hash, size}]`, in order. Inflated and joined, they are the `.cast` file |
| `output_bytes` | Bytes printed |
| `device` | The recording device's name |

A blob (`crates/mg-vault/src/blob.rs`) is `version (1) ‖ key_id (16) ‖ nonce (24) ‖ ciphertext`, XChaCha20-Poly1305 under the vault's current key. The plaintext is padded to 4 KiB buckets, so exact sizes don't show. The associated data binds the blob to its vault and kind (`morphgate/v1/blob`, vault id, `session_log`, version, key id), so the server can't move it to another vault or pass it off as an attachment. The blob's name is the SHA-256 of its bytes, and it carries no signature of its own: the signed item holds the hash. On disk, chunks live in `vault.sqlite3` (table `blobs`: vault, hash, kind, sealed bytes, `state` `pending` / `uploaded` / `failed`, the refusal and upgrade URL), and deletions waiting for the server in `blob_deletes` (see [App architecture](../architecture.md#data-on-disk)).

## Sync

Each sync round, for every vault this device can write to, pending blobs go up before the items that refer to them:

| Request | When |
| --- | --- |
| `PUT /v1/vaults/{vault}/blobs/{hash}`, header `X-Blob-Kind: session_log`, the sealed bytes | Each pending chunk |
| `GET /v1/vaults/{vault}/blobs/{hash}` | Playing or saving a recording whose chunk isn't on this device. The bytes are checked against the name and kept, as `uploaded` |
| `DELETE /v1/vaults/{vault}/blobs/{hash}` | Chunks of a deleted log that had reached the server. A 404 or a refusal also clears the queue entry |

| Upload answer | Result |
| --- | --- |
| `201`, or `200` for bytes already stored | `uploaded` |
| `402 upgrade_required` | `failed`: "this needs the {Plan} plan" (from `plan`), with the `billing_url` for the **Upgrade** button |
| Other `402` | `failed`, with the app's wording of the refusal ("the trial has ended…", "the plan has lapsed…") and no **Upgrade** |
| `400`, `403`, `413` (`too_large`, `quota_exceeded`) | `failed`, with the server's message |
| `404`, `405` (a server without blobs) | `failed`: "the sync server doesn't store session logs" |
| Anything else (network, `5xx`) | The sync round fails and the chunk stays `pending` for the next one |

A refused chunk is not retried by itself: **Try again** (`session_logs_retry`) puts every failed blob of every vault back in the queue, attachments included. The item is pushed whatever happens to its chunks, so other devices list a refused recording as **On another device** but can't play it. A round that uploaded or refused blobs emits `session-logs-changed`, and the list reloads. After each pull, `drop_unreferenced_blobs` removes uploaded chunks that no item refers to anymore (a log deleted on another device). Without sync, chunks stay `pending` and the list shows **Uploading**.

## Retention

A team's owners and admins set `session_log_retention_days` in the app's team policies: "Delete the team's session logs after this many days (0 keeps them)", 0 to 3650, shown when the server stores blobs. The server then deletes that team's `session_log` blobs older than that. Personal vaults have no retention.

The server can't read or delete items, so the log stays listed everywhere. Devices that already hold its chunks (the one that recorded it, and any that played it) can still play it; others get "part of this recording is no longer on the sync server (the team's retention policy may have removed it)". Deleting the log is what removes it from devices.

## Viewing and replay

The Session logs page (`SessionLogsPanel`) lists recordings from every vault, newest first, or one host's ("Session logs · *host*"), as a table: Session (its title and address; the name plays it), Started, Length, Recorded on (the device, "*size* printed") and State. Above it, a search (title, address, device) and menus that narrow it to one **Vault**, **Group** or **Host**, each shown when the recordings come from more than one.

| Way in | Where |
| --- | --- |
| **Session logs** | The sidebar's page list, shown while any host has recording on |
| **Session logs…** | Host editor |
| **Recording** | Route bar of a recorded session |
| **More** › **Session logs** | Phone |

| In a row | Shows or does |
| --- | --- |
| State | **Synced** (`local`: every chunk here and uploaded), **Uploading** (a chunk pending), **On another device** (a chunk not here; fetched when played), **Not uploaded** (a chunk refused; the reason in the title) |
| Length | "recording or cut short" without an end |
| **Play** ("Opening…") | Assembles the cast (`session_log_cast`) and opens the player |
| **Save .cast** | `session_log_save`: Downloads (on iOS, Files › MorphGate) as `title-<first 10 characters of the id>.cast`; characters other than letters, digits, `-` and `.` become `-`, and `-2`, `-3`… avoid overwriting |
| **Delete**, then **Really delete?** | Deletes the item; its chunks go here and, at the next sync, on the server |

When recordings were refused, a notice above the list gives the reason, with **Upgrade** (opens the plan's page; not shown on phones and tablets, whose store rules forbid pointing at outside purchases) and **Try again**.

The player (`SessionPlayer`) is its own xterm.js terminal with input disabled, 5,000 lines of scrollback, and the recorded size; `r` events resize it. It uses this device's scheme and font, not the host's.

| Control | Does |
| --- | --- |
| **Play** / **Pause** / **Replay** | Plays from the position, or from the start at the end |
| Position slider | Seeks; going back replays from the start |
| **1×**, **2×**, **4×**, **8×** | Speed (`SPEEDS`) |
| **Save .cast**, **Close** | |

Pauses longer than 2 s (`MAX_IDLE`) play as 2 s, and the player says so.

## Tauri commands

| Command | Arguments | Does |
| --- | --- | --- |
| `session_logs` | `hostId` (or null) | The list, with each log's state and refusal |
| `session_log_cast` | `id` | The whole `.cast` text, fetching missing chunks |
| `session_log_save` | `id` | Saves the `.cast` file; returns where |
| `session_log_delete` | `id` | Deletes a log |
| `session_logs_retry` | | Queues refused blobs again; returns how many |

## Tests

| Test | Covers |
| --- | --- |
| `apps/desktop/src-tauri/src/session_log.rs`: `deflate_round_trip` | Chunks shrink to under a tenth and inflate back |
| `crates/mg-store/src/sync.rs`: `session_log_blobs_upload_fetch_and_delete`, `refused_blobs_are_reported_and_retried` | Upload before the item, fetch on another device, deletion; refusals and **Try again** |
| `crates/mg-vault/src/blob.rs`: `round_trip_padded_and_named`, `bound_to_vault_kind_and_key`, `hash_matches_a_known_vector`, `too_large_is_refused` | The blob format |
| `server/tests/blobs.rs`, `tools/vault-conform` (`checks/blobs.rs`) | A server's blob endpoints: the reference server's, or any other's |
| `apps/desktop/e2e/mobile.mjs` | Records a session on a phone and plays it back from Session logs |

## Limits

| Case | Behavior |
| --- | --- |
| Locking during a recorded session | `vault_lock` locks the vault before the webview closes the sessions, so the recorder can't save its last chunk: what gathered since the last one (up to 512 KiB or about a minute) is lost and the log has no end time ("recording or cut short"). Quitting doesn't finish recorders either |
| No write access to the vault | Not recorded |
| Access | Everyone who can open the vault can play its recordings; there is no per-member encryption |
| `address` | Built from the host item's own `user`, so a host that takes its user from an identity or group records `@host:port` |
| Memory | Playing or saving assembles the whole recording in memory |
| Size | One chunk is far below a server's `max_blob_bytes` (25 MiB on the reference server); the server's storage quota (`quota_bytes`) still applies |
