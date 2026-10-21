# Hosts, groups and identities

The vault holds the servers a person connects to (hosts), what several hosts have in common (groups, whose settings a host takes where it leaves its own empty), the credentials several hosts share (identities), and files kept with a host (attachments). Every item can refer only to items in its own vault, so a teammate who can open a host can also open its key, jump host and VPN. Items can be changed several at a time from the list pages, and moved or copied to another vault with what they use. How a host is connected is in [SSH connections](ssh-connections.md). Code: `crates/mg-store/src/model.rs` (`Host`, `HostGroup`, `Identity`, `Attachment`), `crates/mg-store/src/vault.rs` (`validate()`, `effective_host()`, `delete()`, `attach()`), `crates/mg-store/src/moving.rs`, `apps/desktop/src-tauri/src/vault.rs`, `attachments.rs`, `bulk.rs`, `moving.rs` (Tauri commands), `apps/desktop/src/HostEditor.tsx`, `Identities.tsx`, `Lists.tsx`, `Sidebar.tsx`, `Selection.tsx`, `Move.tsx`, `Attachments.tsx`.

## Item kinds

An item is an `ItemData` serialized as JSON with a `type` tag (`{"type": "host", …}`, `SCHEMA_VERSION` 1), sealed into its vault's envelope; the plaintext exists only in memory ([architecture](../architecture.md#items)). Ids are ULIDs. Optional fields are left out of the JSON when empty and default when missing, so an app that predates a field reads the item as before.

| `type` | Holds | Doc |
| --- | --- | --- |
| `host` | A server and how to reach it | Here; connecting in [SSH connections](ssh-connections.md) |
| `host_group` | Hosts that belong together, and their shared defaults | Here |
| `identity` | A user and a sign-in method several hosts share | Here |
| `attachment` | A file kept with a host, sealed into a blob | Here |
| `ssh_key`, `host_ca` | Private keys, certificates; trusted host CAs | [SSH keys and agents](ssh-keys-and-agents.md) |
| `snippet` | A saved command (name, body, tags) | [Terminal and snippets](terminal-and-snippets.md) |
| `port_forward` | A saved tunnel through a host | [Port forwarding](port-forwarding.md) |
| `vpn` | A VPN profile a host can go through | [VPN](vpn.md) |
| `terminal_theme` | Terminal colors | [Appearance](appearance.md) |
| `session_log` | A recorded session (blobs) | [Session logs](session-logs.md) |
| `cloud_source` | Hosts kept in step with a cloud | [Cloud sources](cloud-sources.md) |
| `member_key` | A member's published SSH public key; only in an organization's directory vault | [Teams](teams.md) |
| unknown | A kind a newer app wrote: kept and synced, left out of lists, never edited or moved | |

Rules for every write and delete (`LocalVault::upsert_in()`, `validate()`, `delete()`):

| Rule | Error |
| --- | --- |
| Writing needs write access to the vault | "this vault is read-only for you" |
| A saved item keeps its kind | "item {id} is a {existing}, not a {requested}" |
| A saved item keeps its vault | "to put an item in another vault, copy or move it" |
| A reference points into the same vault (teammates would otherwise see hosts whose key they can't open) | "items can only refer to items in the same vault" |
| Member keys only in a directory vault, nothing else there | "the member key directory only holds members' public keys" |
| Deleting something another item still uses | "key \"deploy\" is still used by: web, identity ops" |

## Host fields

| Field | Editor (`HostEditor.tsx`) | Notes |
| --- | --- | --- |
| `label` | **Label** | Empty: the hostname (`host_save`) |
| `hostname` | **Hostname or IP** | Required ("hostname is required") |
| `port` | **Port** | 1 to 65535 ("port must be between 1 and 65535"); 22 in a new host |
| `user` | **User** | Required unless the host or its group has an identity ("user is required (or an identity)") |
| `auth` | **Password**, **SSH key**, **SSH agent** | `{"kind": "password", "password"?}` (none: ask every time), `{"kind": "key", "key_ref"}`, `{"kind": "agent", "agent"?, "path"?, "key"?}` |
| `identity_ref` | **Sign in as** | An `identity` instead of `user` and `auth` |
| `group_ref` | **Group** | A `host_group` |
| `jump_ref` | **Connect via**: "Jump host: …" | Chains up to `MAX_JUMPS` (8); loops refused |
| `jump_command` | **Through the jump host by a command (optional)** | The jump host runs it (`nc %h %p`) |
| `proxy_command` | **Connect via**: "A command on this computer (proxy command)", then **Proxy command** | Runs only once this device allowed it; excludes a jump host and a VPN, own or the group's |
| `vpn_ref` | **VPN** | A `vpn`; with a jump host, the first hop's VPN applies |
| `theme_ref` | **Terminal scheme** | A `terminal_theme` id, or `builtin:<id>` |
| `login_command` | **Login command (optional)** | Run with a terminal instead of the shell |
| `keep_session` | **Keep the session on the server (tmux)** | Disabled in the editor while a login command is set, or when the group keeps sessions |
| `forward_agent` | **Forward the SSH agent** | With a warning |
| `record_sessions` | **Record sessions into the vault** | |
| `tags` | **Tags** | Comma separated; trimmed, empty ones dropped |
| `notes` | **Notes** | Free text; imports add what they left out |
| `source` | None | Set by a cloud source; `host_save` keeps it ([Cloud sources](cloud-sources.md)) |

For a password, `AuthInput::Password` carries `null` to keep the saved password, `""` to forget it, anything else to replace it; the editor shows "Password (saved — type to replace)" and **Forget the saved password and ask every time**. Above the fields, `VaultField` shows a **Vault** choice for a new item (two writable vaults or more), or for an existing one "In your personal vault." / "In the shared vault **…**." with **Move to…**. The buttons are **Delete host** (then **Really delete?**), **Cancel**, **Save** and **Save & connect**; beside the form, **Connection path** and a terminal preview. Validation errors name what is missing: "the selected group (identity, jump host, VPN, terminal theme, SSH key) does not exist", "a host cannot reach itself through its jump hosts", "jump hosts form a loop or a chain that is too long", "a host with a proxy command connects through it, not a jump host or a VPN too".

## Groups

A `host_group` has `name` (required: "a group needs a name") and the defaults `identity_ref`, `jump_ref`, `vpn_ref`, `theme_ref`, `keep_session`. A host takes from its group what it leaves empty; `LocalVault::effective_host()` works it out, and connections, routes and lists use the result:

| Host leaves empty | Taken from the group |
| --- | --- |
| `jump_ref` | The group's jump host, unless that is the host itself (a group's bastion can be one of its hosts) |
| `vpn_ref`, `theme_ref` | The group's |
| `keep_session` | On if the group's is on |
| `identity_ref`, and `user` is empty | The group's identity |

Then the identity, if any, replaces `user` and `auth` ("the identity of \"web\" is missing from the vault" when it's gone). `HostView` carries both: the effective fields, and `own` (what the host itself says, which the editor edits). In the editor a group default shows as the empty choice, "From the group: …". The group editor (`GroupEditor` in `Identities.tsx`) has **Name**, **Identity** ("None: each host signs in its own way"), **Connect via**, **VPN**, **Terminal scheme**, **Keep sessions on the server (tmux)**, and **Hosts in the group** beside it.

Deleting a group keeps its hosts: each becomes `Host::without_group()`, so what it took from the group becomes its own and it connects as before.

## Identities

An `identity` is `label` (**Name**, required: "an identity needs a name"), `user` (required) and `auth`, with the same password rules as a host. Hosts pick it under **Sign in as** ("Identity: ops (deploy)"), groups under **Identity**. Changing it changes how every host using it signs in; the editor lists them under **Used by**. Identities live on the **Keys** page (**New identity**).

## Tags and notes

Hosts and snippets have `tags`; nothing else does. The sidebar search ("Search hosts") and the Hosts page search ("Search by name, address, user or tag") match the label, hostname, user and tags. Notes are free text on hosts; an import appends "From PuTTY, not imported: …" ([Importing](importing.md)).

## Attachments

An `attachment` is `name` (as added, without a path), `host_ref`, `blob` (hex SHA-256 of the sealed bytes) and `size`. The file is sealed with the vault's current key into a blob of kind `attachment` (`LocalVault::attach()`, `add_blob()`), kept in the local `blobs` table as `pending`, and uploaded by the next sync before the items that refer to it. The server's side is the `blobs` part of `spec/openapi.yaml`.

| `AttachmentView.state` | Shown | Means |
| --- | --- | --- |
| `local` | Nothing | On this device and uploaded |
| `uploading` | "Uploading" | Waiting for the next sync |
| `remote` | "On the server" | Added on another device; fetched when saved |
| `failed` | "Not uploaded", and "{name} wasn't uploaded: {reason}" with **Upgrade** when the server sent a billing link (desktop) | The server refused it |

**Attach files** (in the host editor, once the host is saved) sends each file's bytes as the raw request body, with headers `x-host-id` and `x-file-name` (percent-encoded). **Save** writes the file to the Downloads folder (documents on iOS), fetching it from the sync server first if needed. **Delete** asks "Delete {name}?". Deleting an attachment, or the host it belongs to, forgets its blob here and on the server at the next sync.

| Limit or error | Value |
| --- | --- |
| Largest file | `MAX_ATTACHMENT_BYTES`, 20 MiB, so the sealed blob stays under servers' 25 MiB; "attachments are up to 20 MB" (the page checks first: "{name} is larger than 20 MB") |
| File name | Not empty, no `/` or `\` ("an attachment needs a file name") |
| Not a host | "attachments go with a host" |
| Not on the server yet | "this file is not on the sync server (yet): the device that added it uploads it when it syncs" |

## Lists and the sidebar

The sidebar (`Sidebar.tsx`) is for connecting; the pages (`Lists.tsx`) are for managing.

On desktop, once the vault has hosts, the Hosts page is home: the workspace opens on it after unlocking, and closing the last tab or page returns to it (`home()` in `App.tsx`). With no hosts, home is quick connect. Closing the Hosts page itself goes to quick connect. On phones the start screen is the host list either way.

| Sidebar part | What it does |
| --- | --- |
| Navigation | **Hosts**, **Groups**, **Keys** (keys and identities counted together), **Snippets**, **Tunnels** ("2 on"), **VPNs** ("1 up"), and **Session logs** once a host records |
| Search | "Search hosts": label, hostname, user, tags |
| Hosts | The plus (**New host**) and the group icon (**New group**); "Add your first host" when empty; hosts without a group, then each group, folding (remembered in `localStorage` as `morphgate.collapsed-groups`), with **Open the group** |
| A host row | Click connects; `user@host:port`, "via" the jump host, a VPN mark, "gone" for a host its cloud no longer lists, the shared vault's name; **Browse files (SFTP)** (hidden when its cloud offers no SFTP) and **Edit host** |

| Page | Content |
| --- | --- |
| Hosts | **Quick connect**, **Import…** and **Clouds…** (desktop), **Select**, **New group**, **New host**; "Not in a group", then a section per group with **Edit group** and what its hosts use; rows with **Connect**, **Files**, **Edit**, tags, and badges "gone from AWS" or the machine's state ("stopped") |
| Groups | Each group with its host count and defaults; **Open**, **Edit** |
| A group | Its hosts, the tunnels through them, their files (**Save**), and "What its hosts use" (identities, keys, jump hosts, VPNs); **Move to…**, **Edit group** |
| Keys | Keys, then **Identities** (**New identity**) and **Host CAs** |

## Bulk changes

**Select** on a list page turns its rows into checkboxes, and a bar says "3 hosts selected" with **Select all** / **Select none**, **Delete…** ("Delete 3 hosts?", **Delete**, **Cancel**), **Move to…** (when the chosen items are in one vault), on the Hosts page **Move to group…** (that vault's groups, and **No group**), and **Done**. The outcome is one line: "Deleted 2 hosts." followed by why the others weren't.

| Command | Does |
| --- | --- |
| `items_delete(ids)` | Deletes hosts, groups, keys, identities, snippets and host CAs, each as on its own. Rounds: what nothing uses goes first, so a jump host goes after the hosts behind it and a key after its identity; a round that deletes nothing ends it and reports why ("… is still used by: web"). Other kinds: "{id}: delete it on its own page" |
| `hosts_set_group(ids, group_id)` | Puts hosts in a group, or none for `null`; "{label}: {error}" for a host that can't be |

Tunnels and VPNs are deleted one by one through their own commands (`Selection.tsx` `eachOf()`), which stop what is running first.

## Moving and copying to another vault

A move keeps the item's id (tabs, tunnels and links that name it keep working) and leaves a tombstone in the old vault; a copy gets a new id and leaves the original. What the picked items need comes along, and links are rewritten to match (`relink()`). It is all or nothing: the writes happen inside a SQLite savepoint and are validated together afterwards (a group's jump host may be one of its own hosts).

| Why an item is in the plan (`Why`) | Items | Choices (`Carry`) |
| --- | --- | --- |
| `chosen` | The picked items | **Move** (default) or **Copy** |
| `rides` | A host's attachments; a host's tunnels when the host moves; a group's hosts | Follows the item it goes with |
| `used` | A host's or identity's key, a host's identity and a tunnel's host (needed); a jump host, VPN, terminal theme, a group's defaults, an attachment's host, a cloud source's key and jump host (optional) | **Move**, **Copy**, and **Leave out** for optional ones (the link is dropped) |

Something still used by an item that stays can't move: it is copied instead ("Still used here by …: a copy goes, this one stays."), worked out by repeating the plan until nothing changes. From a vault this account can only read, everything is a copy. A host leaving a group that stays keeps what it took from it; a host kept by a cloud source stays linked only if the source goes too. Attachments are opened and sealed again under the target vault's key (a new blob name); `items_move` first fetches the files this device doesn't have yet ("fetching an attached file to move it: …").

The plan's notes: "{host} leaves the group {group} and keeps the settings it took from it.", "A session log stays where it was recorded: recordings don't move.", "Everyone who can open that vault can use the keys, passwords and VPN profiles that go there." (into a team vault), "What moves leaves this team vault: its other members lose it." From personal to a team vault the dialog adds that the item then belongs to the team.

| Refused | Error |
| --- | --- |
| Same vault | "it is in that vault already" |
| Target read-only or a directory | "this vault is read-only for you", "the member key directory only holds members' public keys" |
| Items from two vaults | "pick items from one vault" |
| A session log | "session logs stay in the vault they were recorded in" |
| A member key or an unknown kind | "that item can't be moved" |

**Move to…** appears in item editors (`VaultField`), on a group's page and in the selection bar, when there is another writable vault that isn't a directory (`moveTargets()`). The dialog ("Move {label}") has **To** (from the personal vault a team's is preselected, from a team's the personal one), a row per planned item with its kind, "Goes with …" or "Used by …", and **Move** / **Copy** / **Leave out** where there is a choice; the button says **Copy** when nothing moves. After a copy the open editor follows the new id.

## Tauri commands

| Command | Does |
| --- | --- |
| `hosts_list`, `host_save(input)`, `host_delete(id)` | Hosts as `HostView`, sorted by label; save creates in `input.vault_id` (default personal) or replaces |
| `groups_list`, `group_save(input)`, `group_delete(id)` | Groups (`GroupView`) |
| `identities_list`, `identity_save(input)`, `identity_delete(id)` | Identities (`IdentityView`) |
| `attachments(host_id)`, `attachment_add`, `attachment_save(id)`, `attachment_delete(id)` | A host's files: list, add (raw body), save to Downloads, delete |
| `items_delete(ids)`, `hosts_set_group(ids, group_id)` | Bulk changes (`BulkResult {done, refused}`) |
| `items_move_plan(ids, to, choices)`, `items_move(ids, to, choices)` | The plan (`MovePlan`), then the move (`Moved {moved, copied, ids}`) |

## Platform differences

| Where | Difference |
| --- | --- |
| Phones and tablets (`mobileOs`) | No **Import…** or **Clouds…**; **SSH agent**, the proxy command and **Forward the SSH agent** are offered only on a host that already has them; no **Upgrade** button |

## Tests

- `crates/mg-store/src/vault.rs`: `identities_and_groups_fill_in_what_hosts_leave_empty`, `type_and_reference_checks`, `jump_routes_and_loops`, `a_proxy_command_is_the_only_way_to_its_host`, and the VPN, theme and tunnel reference tests.
- `crates/mg-store/src/moving.rs`: a host takes its key, files and tunnels; something still used is copied; a group goes with its hosts, identity and bastion; a host leaving its group; leaving a VPN out; copies only from a read-only vault; refusals.
- `crates/mg-store/src/sync.rs`: `attachments_sync_and_go_with_their_host` (including a refused oversize file), `kinds_from_newer_apps_are_kept_but_not_listed`.
- `apps/desktop/src-tauri/src/bulk.rs` (delete order, refusals, groups) and `attachments.rs` (header names). `cargo test -p mg-store`, `cargo test -p morphgate-desktop`.
- e2e: `apps/desktop/e2e/appimage.mjs` selects two hosts, moves them into a group and deletes them; `teams.mjs` moves a host into a team vault and saves Alice's attachment on Bob's second device; `layout.mjs` checks the move dialog's layout; `flows.mjs` has `moveHost()`.

## Limits

- One group per host; groups don't nest, and a group doesn't carry a port, user (only an identity), login command, agent forwarding or recording.
- Attachments go with a host (the item allows none, the app doesn't), are up to 20 MiB, and can't be renamed. A refused upload is retried only by **Try again** on the Session logs page (`session_logs_retry`), which queues every refused blob again.
- Session logs, member keys and unknown kinds never move.
