# SSH connections

A connection is one SSH transport to a host, possibly through jump hosts, a VPN or a proxy command, with a PTY shell on top. Every hop's host key is checked before anything is sent to it: pinned on first use in `known_hosts`, or vouched for by a host CA. Each hop signs in with the one method its host is set to. A lost connection reconnects by itself. Code: `crates/mg-ssh/src/connection.rs` (`Connection`, `Hop`, `Auth`, `Verifier`), `crates/mg-ssh/src/session.rs` (`Session`, `ConnectOptions`), `crates/mg-ssh/src/known_hosts.rs` (`KnownHosts`, `HostAuthority`), `crates/mg-ssh/src/proxy_command.rs`, `crates/mg-ssh/src/command_stream.rs`, `crates/mg-ssh/src/error.rs`, `apps/desktop/src-tauri/src/ssh.rs` (Tauri commands), `apps/desktop/src-tauri/src/proxy.rs`, `apps/desktop/src-tauri/src/host_cas.rs`, `apps/desktop/src/ConnectForm.tsx`, `apps/desktop/src/HostKeyDialog.tsx`, `apps/desktop/src/HostCaPanel.tsx`, `apps/desktop/src/TerminalView.tsx`.

Keys, certificates and agents are in [SSH keys and agents](ssh-keys-and-agents.md); the host item and its editor in [Hosts, groups and identities](hosts-groups-identities.md); the overview in [App architecture](../architecture.md#how-a-connection-runs).

## How `ssh_connect` runs

1. **What the session runs.** For a saved host: its login command, or a tmux command when it keeps its session on the server, and whether the agent is forwarded (all read from the route's target).
2. **Certificates.** `renew::before_connect` renews due certificates of the keys on the route (saved hosts only; see [SSH keys and agents](ssh-keys-and-agents.md#renewal-by-command)).
3. **Route.** `resolve()` turns the request into `Resolved { target, jumps, vpn, proxy }`. Quick connect is one hop. A saved host goes through `LocalVault::route` (`crates/mg-store/src/vault.rs`), which applies identities and group defaults (`effective_host`) and returns the jump hosts nearest first. `saved_hop()` reads each hop's sign-in from the vault.
4. **First hop.** `first_hop()` picks the first hop's `Dialer`: the proxy command if there is one, else the host's VPN (`VpnManager::dialer`, started or reused), else the OS network stack.
5. **Host CAs.** `host_cas::trust` hands the vault's host CAs to `KnownHosts`.
6. **Connect.** `Session::connect` (or `connect_running` with a command) calls `Connection::open`: per hop, connect, verify the host key, sign in. Then one session channel: agent forwarding if asked, a PTY (`xterm-256color`, the tab's size), and the shell or the command.
7. **Stream.** The session gets an id; output goes to the `on_output` channel as raw bytes, lifecycle to `on_status`. The host's session recording starts here if it has one ([Session logs](session-logs.md)).

`SessionEvent`s pass through a bounded channel (`EVENT_BUFFER`, 256), so a slow webview slows the SSH window instead of filling memory. stdout and stderr both go to the terminal.

## Tauri commands and events

| Command | Does |
| --- | --- |
| `ssh_connect(request, on_output, on_status)` | Opens a session; returns its id. `request.target` is `{kind: "adhoc", host, port, user, auth}` (auth `{kind: "password", password}`, `{kind: "key", privateKey, passphrase?}` or `{kind: "agent"}`) or `{kind: "saved", hostId, password?, tmux?}`; `request.size` is `{cols, rows}` |
| `ssh_write(id, data)` | Sends typed text |
| `ssh_resize(id, size)` | Window change (and the recording's size) |
| `ssh_disconnect(id)` | Closes the channel, then the target, then the jump hosts in reverse |
| `hostkey_answer(promptId, accept)` | Answers a `hostkey-prompt` |
| `host_pinned_key(host, port)` | The pinned key as `{algorithm, fingerprint}`, or null |
| `host_allow_proxy(id)` | Lets this device run the host's current proxy command |
| `host_cas_list`, `host_ca_save(input)`, `host_ca_delete(id)` | Host CA items |
| `host_certified_by(host, port)` | The name of the first host CA trusted for `host:port`, or null |

| Event or channel message | When |
| --- | --- |
| `hostkey-prompt` `{promptId, host, port, algorithm, fingerprint}` | A hop's key is unknown |
| `hostkey-changed` `{host, port, algorithm, fingerprint, pinnedAlgorithm, pinnedFingerprint, file, line}` | A hop's key differs from the pinned one (also behind a jump host: `connect_error()` unwraps `Error::Jump`) |
| `security-key` `{host, key}` | An agent's `sk-` key waits for a touch; `key: null` when done |
| `on_status`: `exit {status}`, `closed`, `recording {logId}` | The remote command exited, the channel closed, the session is recorded |

## Quick connect

`ConnectForm.tsx` (the plus at the end of the tab bar, or a `morphgate://connect` link, see [Deep links](deep-links.md)). Nothing goes into the vault unless asked; quick connect has no jump host, VPN or proxy command, but the host key is checked as always.

| Control | Does |
| --- | --- |
| **Host**, **Port**, **User** | The target. Remembered with the sign-in kind in `localStorage` (`morphgate.lastTarget`), never a secret |
| **Password** / **Key** / **SSH agent** | The sign-in. **SSH agent** is hidden on phones, unless it was the last one used. The agent is always the system agent, every key ("Uses the identities loaded in $SSH_AUTH_SOCK.") |
| **From file** / **Paste** | With **Key**: a file picker ("Private key file (id_ed25519, a .pem or PuTTY's .ppk)", up to 1 MB, read in the webview) or a **Private key** text area. The key's text is sent as `{kind: "key", privateKey, passphrase?}` and used from memory for this connection only (`Auth::Key`, OpenSSH, PEM or PuTTY via `keys::decode`). It isn't remembered between quick connects: `localStorage` keeps only that it was a key |
| **Passphrase (if encrypted)** | For an encrypted key |
| **Save to vault** | Reads "Save to vault (including the password)" or "(with the key)" for those sign-ins. Saves the host first. With a password, the password is saved; with a key, the key is imported into the vault (`key_import`, named after its file or "{label} key") and the host signs in with it; with the agent, the host uses the system agent |
| **Connect** | Opens a tab |

A link only fills the form ("Filled in from a link… Check the address before you connect."); it never connects.

## Signing in

Each hop uses exactly the method its host (or identity) names. A failed method is not followed by another one.

| Method (`Auth`) | Order on the wire |
| --- | --- |
| `Password` | `password`, then keyboard-interactive, answering every hidden prompt with the same password, for up to 4 rounds. A prompt that echoes (a username, a menu) ends it as failed |
| `Key` (from the vault, or chosen or pasted in quick connect) | The OpenSSH certificate first, if the key has one that parses, then the key alone, as `ssh` does. RSA keys sign with the best hash the server allows (`rsa-sha2-512`/`-256`) |
| `Agent` | The agent's keys, only the one with the saved fingerprint when set (OpenSSH's `IdentitiesOnly`), certificates first, each in turn. See [SSH keys and agents](ssh-keys-and-agents.md#signing-in-through-an-agent) |

`mg-ssh` also has `Auth::KeyFile`, a key read from a path on disk; its live tests use it, the app doesn't.

A saved host with a password but none saved asks for it first (`PasswordDialog`: "Password for {user}@{host}", "Not saved in the vault. It is used for this connection only."). Only the target can be asked: a jump host needs a saved password, a key or an agent.

## Host keys

### Pinning on first use

`Verifier::check_server_key` checks each hop's key with `KnownHosts::check`:

| Result | What happens |
| --- | --- |
| `Trusted` (a matching line in any file) | Continues |
| `Unknown` | `hostkey-prompt`; on **Trust and connect** the key is appended to the app's file (`learn`) before signing in; on **Cancel**, Escape, or no answer within 120 s (`HOSTKEY_PROMPT_TIMEOUT`), the connection fails and nothing is written |
| `Changed` (a line for this host with the same key type but another key, in any file) | Fails closed, even if another file trusts the key: `hostkey-changed`, then `Error::HostKeyChanged` |

The connect timeout pauses while a prompt is open. A key of another type than the recorded one counts as unknown and is asked about.

### `known_hosts` files

| File | Use |
| --- | --- |
| `<data folder>/known_hosts` (`SshState::new`) | The app's own: read and written. Created with its folder on the first accepted key. Entries are `host type base64`, or `[host]:port type base64` off port 22, not hashed |
| `~/.ssh/known_hosts` (`KnownHosts::openssh_default`) | Read only, never changed. Hashed (`\|1\|…`) entries match |

Both files' `@cert-authority` lines count as host CAs. An `@revoked` line in either file (for hosts its patterns cover; hashed names aren't patterns) refuses that key outright, before any pin, CA or prompt: a revoked host key, or a host certificate whose key or signing CA is revoked, fails with "the host key of {host}:{port} ({fingerprint}) is revoked in {file}:{line}: refused" (`KnownHosts::revoked`, `HostKeyCheck::Revoked`). Host keys stay on the device and don't sync; host CA items do.

### The dialogs

| Dialog | Shows | Buttons |
| --- | --- | --- |
| **Unknown host key** (`HostKeyDialog`) | `host` or `[host]:port`, **Presented** key type and `SHA256:` fingerprint, "Once trusted, the key is pinned…" | **Cancel**, **Trust and connect** |
| **Host key changed** (`HostKeyChangedDialog`) | The host's label and address, **Pinned** (with `known_hosts line N`) and **Presented now**, and **What to do** (ask the admin; only if it matches, remove that line from the named file) | **Copy details**, **Close** |

Prompts queue, one dialog at a time; a host's changed-key dialog shows once however many connections it refused. The route bar shows the pinned key ("Host key pinned on first connect: …"), and the host editor's **Connection path** says "key pinned".

### Host CAs

A `host_ca` item (`HostCa { label, public_key, hosts }`) trusts host certificates its CA signed for hosts matching `hosts`, instead of pinning each key (OpenSSH's `@cert-authority`). In a team vault it covers every member. Opened from the **Keys** page, section **Host CAs**, **New host CA** or **Edit**.

| Control | Does |
| --- | --- |
| **Name** | The label, also shown in the route bar ("certified by {name}") |
| **The CA's public key** | `ssh-ed25519 AAAA…`, or a whole `@cert-authority` line, whose patterns are used when **For hosts** is empty. Stored without its comment; anything else: "not an SSH public key (ssh-ed25519 AAAA…)" |
| **For hosts** | Comma-separated patterns: `*` and `?` match, `!` excludes and wins, case does not matter. A bare pattern matches the host on any port; `[host]:port` one port. (In a `known_hosts` file a bare pattern means port 22 only, as in OpenSSH) |
| **Delete** → **Really delete?**, **Close**, **Save host CA** / **Save changes** | Hidden or disabled in a vault you can only view |

Where a CA is trusted for a hop, `client_config(true)` asks the server for host certificates (Ed25519, ECDSA P-256/384/521, RSA SHA-512/256). A certificate is accepted, and nothing pinned, only if `known_hosts::certified` agrees: it is a host certificate, signed by one of the CAs trusted for this host, valid now with a good signature, its principals are empty or include the hostname, and it has no critical options. Otherwise the connection fails with the reason, as OpenSSH does; it does not fall back to pinning. A server that answers with a plain key is pinned as usual. Without a CA for the host, certificates are never asked for.

## Jump hosts

A host's `jump_ref` (or its group's) names another host to go through; that one can have its own. `LocalVault::route` follows the chain, at most 8 jump hosts (`MAX_JUMPS`), refusing loops ("jump hosts form a loop or a chain that is too long"); saving refuses them too. A jump host must be in the same vault.

Each hop is its own SSH connection with its own host-key check and sign-in, opened through the previous hop with a `direct-tcpip` channel; the next hop starts only after the previous one is verified and signed in. The 15-second timeout applies per hop. A failure deep in the chain reads "via jump host {host}:{port}: …". Remote-forward channels and agent forwarding exist only on the target; a jump host's attempts to open them are refused. See also [Port forwarding](port-forwarding.md) and [SFTP](sftp.md), which use the same route.

### Through the jump host by a command

`Host.jump_command` (editor: **Through the jump host by a command (optional)**, placeholder `nc %h %p`) is for bastions that refuse forwarding but hand a connection on. The previous hop runs it in an exec channel without a PTY; its stdin and stdout carry this hop's SSH (`command_stream()`), as `ProxyCommand ssh jump-host <command>`. What it writes to stderr is kept (up to 4096 bytes, `STDERR_LIMIT`) and becomes the error when the handshake fails: "could not reach {addr}: {command}: {stderr}". It runs on the jump host, not on this device, so it is not on the allow-list below.

## Proxy commands

`Host.proxy_command` (**Connect via** → **A command on this computer (proxy command)**, then **Proxy command**) is OpenSSH's `ProxyCommand`: a command run on this device whose stdin and stdout are the first hop's connection (AWS Session Manager, EC2 Instance Connect Endpoint, IAP, `nc -X 5 -x proxy:1080 %h %p`). It applies when the host is the first hop: the target without a jump host, or the first jump host of another host's chain. A host with one can't also have a jump host or a VPN, its own or its group's ("a host with a proxy command connects through it, not a jump host or a VPN too").

| Detail | Behavior |
| --- | --- |
| Tokens | `%h`, `%p`, `%r` (the hop's host, port, user), `%%`. Another `%x` stays as it is |
| Injection guard | A used `%h` must be letters, digits, `.-_:[]`; a used `%r` letters, digits, `.-_@` and not start with `-` (as OpenSSH 9.6). Otherwise "the host name \"…\" can't be given to a command (%h)" |
| Shell | `sh -c` on Unix; `cmd /D /S /C "…"` with no console window on Windows |
| Lifetime | Killed when the connection is dropped (`kill_on_drop`) |
| Errors | stderr (up to 4096 bytes) is the error when SSH through it fails: "could not reach {addr} via the proxy command `…`: {stderr}" |
| Phones | Refused: "\"{label}\" connects through a command run on the computer: connect to it from the desktop app" |

Hosts kept by a cloud source carry no command: `cloud::reach_command` builds one from checked fields, and it needs no allowing ([Cloud sources](cloud-sources.md)).

### The per-device allow-list

A vault syncs, and a shared one is written by others, so a command in it runs only once this device has allowed it (`proxy.rs`). The device keeps `proxy-allowed:<SHA-256 of the command>` in its `settings` table, never synced; a changed command, even by a space, asks again.

| Allowed by | Note |
| --- | --- |
| Saving a host with a new or changed command in the editor (`host_save`) | A command saved unchanged is not allowed by saving |
| Importing it from this device's `~/.ssh/config` | [Hosts, groups and identities](hosts-groups-identities.md) |
| **Allow on this device** in the host editor (`host_allow_proxy`) | Shown under "This command came with the vault. It runs on this computer only once you allow it here, after reading it: {command}" |

Until then: "\"{label}\" connects by running a command on this computer, which this device hasn't allowed: {command}. Open the host to allow it." Certificate renewal commands share this list.

## VPN

A host's VPN carries only the first hop: with a jump host, the jump host's VPN setting applies. The VPN's `Dialer` opens the TCP stream inside the app's tunnel; errors name it ("{addr} via VPN \"{label}\""). See [VPN](vpn.md).

## Keepalive and reconnect

`client_config` sets `keepalive_interval` 30 s and `keepalive_max` 3 for every hop, and `TCP_NODELAY`. A server that stops answering is dropped after three missed keepalives, and the tab sees the channel close.

`TerminalView.tsx` handles what follows:

| Case | Terminal and bar |
| --- | --- |
| Remote command exited | "[process exited with status N]", "[connection closed]"; **The session ended.** with **Reconnect** |
| Connection lost | "[connection lost]"; **Connection lost. Retrying in N s…** with **Retry now**. Retries after 2, 5, 15 and 30 s (`RETRIES`), waiting for the `online` event while offline; then **Connection lost.** with **Reconnect** |
| Never opened | The error in red; **Couldn't connect.** with **Reconnect**. No automatic retry, unless the tab had connected before |

Each attempt is a new session in the same terminal ("Reconnecting to {title}…"); a host that keeps its session reattaches to the same tmux session ([Terminal and snippets](terminal-and-snippets.md)).

## Errors the user sees

Connection errors are `mg_ssh::Error`'s text, written in red in the tab.

| Text | Cause |
| --- | --- |
| "could not connect to {addr}: timed out" | No handshake within 15 s for a hop |
| "could not connect to {addr}: {OS error}" | TCP failed. On macOS, "no route to host" adds "…allow it in System Settings → Privacy & Security → Local Network, then connect again" (`connect_failed`) |
| "could not reach {addr}: {reason}" | A jump host refused the forward, or a command failed (see above) |
| "via jump host {host}:{port}: …" | Wraps any error from a later hop |
| "REMOTE HOST KEY CHANGED for {host}:{port} ({type} {fingerprint})…" | Changed key; the dialog shows first |
| "host key for {host}:{port} was not accepted" | Prompt cancelled or timed out |
| "the host certificate of {host}:{port} isn't accepted: {why}" | Why: "it's a user certificate, not a host's", "it's signed by {fp}, which isn't a CA trusted for this host", "it isn't valid now (expired, not yet valid), or its signature doesn't check out", "it's for {principals}, not {host}", "it has critical options, which host certificates don't" |
| "authentication failed" | The server refused the method |
| "password required" / "jump host \"{label}\" has no saved password; save one or switch it to a key" | No password to send |
| "the SSH key of \"{label}\" is missing from the vault" / "the host's VPN profile is missing from the vault" | A dangling reference |
| "known_hosts: {file}: {why}" | A line for the host in a `known_hosts` file can't be read, or the app's file can't be written |
| "private key is encrypted; a passphrase is required", "could not load private key: …", "ssh agent: …" | See [SSH keys and agents](ssh-keys-and-agents.md#errors) |

## Limits and defaults

| What | Value |
| --- | --- |
| Connect timeout | 15 s per hop, paused during a host-key prompt (`ssh.rs`, also `sftp.rs`, `tunnels.rs`) |
| Host-key prompt | 120 s (`HOSTKEY_PROMPT_TIMEOUT`) |
| Keepalive | 30 s, 3 missed (`client_config`) |
| Jump hosts | 8 (`MAX_JUMPS`, `crates/mg-store/src/vault.rs`) |
| Command stderr kept | 4096 bytes (`STDERR_LIMIT`) |
| Keyboard-interactive | 4 rounds |
| Automatic reconnects | 4, after 2, 5, 15, 30 s (`RETRIES`) |
| Terminal type | `xterm-256color` |

## Not built

- `~/.ssh/config` is not read when connecting: it is only an import source, so `ServerAliveInterval`, `IdentityFile` and the like matter only as far as the import maps them.
- Plain `known_hosts` lines match the host name literally (or hashed); wildcard patterns there are not matched. Hosts are recorded as written in the host item, unhashed.
- Keyboard-interactive answers only hidden prompts, all with the password: a one-time code can't be entered.
- No X11 forwarding (imports list it as unsupported), no GSSAPI/Kerberos sign-in.
- Quick connect has no jump host, VPN, proxy command or certificate.
- On phones: no proxy commands, cloud CLI routes, agents or certificate renewal ([Platforms and mobile](platforms-and-mobile.md)). No Mosh, so a session doesn't outlast iOS suspending the app.

## Tests

| Where | Covers |
| --- | --- |
| `crates/mg-ssh/src/known_hosts.rs` | Unknown, learned, trusted; a changed key caught in a read-only file without creating the app's; pinned key by host and line; OpenSSH fingerprints; host pattern matching; `@cert-authority` lines and vault CAs; host certificate checks; `@revoked` keys refused, over a pinned key too |
| `crates/mg-ssh/src/proxy_command.rs` | Token expansion, refused host and user names, bytes both ways, stderr as the error |
| `crates/mg-ssh/src/connection.rs` | The macOS local-network hint |
| `apps/desktop/src-tauri/src/ssh.rs`, `proxy.rs`, `host_cas.rs` | A synced proxy command waits for allowing; tmux names; request shapes match the webview; a changed command asks again; parsing a CA key or `@cert-authority` line |
| `crates/mg-ssh/tests/live.rs` | Against a real sshd: shell, resize, exit and TOFU; a rejected key isn't learned; a changed key fails closed; wrong password; key file; unreachable port; jump host tunnel; jump command; proxy command, and failing ones that say why; a host certificate from a trusted CA (`MG_TEST_HOST_CA`); the first hop through a dialer |
| `apps/desktop/e2e/appimage.mjs` | Quick connect with a key file chosen in the form, and with a pasted key after a `morphgate://` link; **Trust and connect**, the pinned key in the route bar, **Host key changed** for an edited `known_hosts`, a jump host from `~/.ssh/config`, a jump command and a proxy command (via `crates/mg-ssh/tests/relay.py`), a host CA with "certified by" and no prompt |

The live tests are ignored unless `MG_TEST_SSH=host:port` is set (and `MG_TEST_USER`, `MG_TEST_KEY`, optionally `MG_TEST_PASSWORD`); the header of `live.rs` starts a throwaway user-level sshd. Run them with `cargo test -p mg-ssh --test live -- --include-ignored --test-threads=1`. See [Development](../development.md) for the e2e runner.

## Related

- [SSH keys and agents](ssh-keys-and-agents.md), [Hosts, groups and identities](hosts-groups-identities.md), [VPN](vpn.md)
- [Port forwarding](port-forwarding.md), [SFTP](sftp.md), [Terminal and snippets](terminal-and-snippets.md), [Cloud sources](cloud-sources.md)
- [App architecture](../architecture.md)
