# Port forwarding

A tunnel forwards a port through a saved host: local (`ssh -L`), remote (`ssh -R`) or a SOCKS5 proxy (`ssh -D`). Every tunnel is a `port_forward` item in a vault, so it syncs with that vault and team members can use it; there are no ad hoc forwards. A tunnel runs only when started, on an SSH connection of its own that takes the host's whole route (saved sign-in, jump hosts, VPN or proxy command). Code: `crates/mg-ssh/src/forward.rs` (`Forward`, `Tunnel`, the SOCKS5 server), `apps/desktop/src-tauri/src/tunnels.rs` (Tauri commands), `apps/desktop/src/ForwardEditor.tsx`, `apps/desktop/src/Lists.tsx` (`TunnelsPage`), `apps/desktop/src/App.tsx` (`startForward`, `toggleForward`).

## Kinds

| Kind (`rule.kind`) | Label | Listens | Each connection |
| --- | --- | --- | --- |
| `local` | **Local** | On this computer: `TcpListener::bind(bind_host, bind_port)` | A `direct-tcpip` channel to the destination, opened by the server, with the client's address as originator; bytes copied both ways |
| `remote` | **Remote** | On the server: a `tcpip-forward` request. Port 0 lets the server choose, and the chosen port is shown | The server opens a `forwarded-tcpip` channel; the app connects to the destination over TCP from this computer and copies both ways |
| `dynamic` | **SOCKS proxy** | On this computer | A SOCKS5 handshake (no authentication, `CONNECT` only, IPv4, IPv6 or a domain name), then a `direct-tcpip` channel to what the client asked for. Names are passed to the server as they are, so they resolve there |

## The item

`PortForward` in `crates/mg-store/src/model.rs`:

| Field | Value |
| --- | --- |
| `label` | The name. Blank on save becomes "Tunnel"; the editor fills "*host* → *destination*:*port*" or "SOCKS via *host*" first |
| `host_ref` | The host it runs through, in the same vault |
| `rule` | `{kind: "local" \| "remote", bind_host, bind_port, target_host, target_port}` or `{kind: "dynamic", bind_host, bind_port}`. Addresses are trimmed on save |

The webview sees `ForwardView`: the item plus `running`, `port` (the port listening while running; the server's choice for a remote port 0) and `active` (connections open through it). Running tunnels live in `SshState.tunnels`, keyed by item id, in memory only.

## The editor

| Control (`ForwardEditor.tsx`) | Does |
| --- | --- |
| **Vault** | Where a new tunnel goes. Changing it picks the first host of that vault |
| **Name** | Optional (placeholder "Postgres on prod") |
| **Through host** | Hosts of the tunnel's own vault, as "label (user@host)" |
| **Local** / **Remote** / **SOCKS proxy** | The kind, with a line of help under it |
| **Listen on (this computer)** or **Listen on (server)**, **Port** | Address and port to listen on. Placeholders `15432`, `0 = any` (remote), `1080` (SOCKS) |
| **Destination (as seen from the server)** or **Destination (as seen from this computer)**, **Port** | Local and remote only |
| **Delete**, then **Really delete?** | Stops the tunnel and deletes it |
| **Cancel**, **Save**, **Save & start** | |

The form is valid with a host, a listen address, a listen port from 1 to 65535 (0 allowed for remote), and for local and remote a destination and a port from 1 to 65535. Editing a running tunnel says "This tunnel is running; saving changes stops it.": `forward_save` stops it first, so it never runs with a stale configuration. With no saved host at all the editor says "A tunnel runs through one of your saved hosts. Add a host first."

## Bind addresses and safety

| Rule | Detail |
| --- | --- |
| Default | `127.0.0.1` as the listen address for every kind (and as the destination) |
| Loopback | `isLoopback()`: `127.*`, `localhost`, `::1` |
| Warning | A local or SOCKS tunnel on any other address shows "Listening on *address* lets other machines on your network use this tunnel." It is a warning, not a refusal |
| SOCKS on the network | The SOCKS server has no authentication: anyone who can reach the port can use the server as a proxy |
| Remote | No warning; the server decides. OpenSSH's sshd keeps remote listeners on loopback unless its `GatewayPorts` setting allows more (default `no`) |
| Destinations | Not restricted by the app; the server's `AllowTcpForwarding` and `PermitOpen` apply |

## Starting and stopping

| Where | Control |
| --- | --- |
| Tunnels page (sidebar **Tunnels**, whose count reads "N on" while some run) | A table: the switch first ("Start tunnel" / "Stop tunnel"), the name, what it forwards (`L :15432 → db:5432`, `R server:8080 → 127.0.0.1:3000` or `SOCKS :1080`), the host it goes through with its status, and its state ("Running", "Running · N open", "Stopped", "Starting…"); **Edit**, a "Running" filter, **Select** for bulk delete and move, **New tunnel** |
| A group's page | The tunnels through its hosts, with the same switch |
| The editor | **Save & start** |
| Phone | The **More** screen lists tunnels with switches |

`forward_start`:

1. Returns the tunnel as it is if it already runs.
2. Renews key certificates that are about to expire (`renew::before_connect`), resolves the host's route (`ssh::resolve`), dials the first hop (VPN or proxy command, `ssh::first_hop`) and trusts the vault's host CAs, as a terminal does.
3. `Connection::open` with a 15 s timeout per hop; unknown host keys raise the usual prompt.
4. `Tunnel::start` binds (or asks the server to listen) and spawns the accept loop. A bind failure fails the start.

A host without a saved password is asked for one first ("Password for *user*@*host*", "Not saved in the vault. It is used for this connection only."). Anyone who can open the vault can start its tunnels; editing needs write access.

While any tunnel runs, the app lists tunnels every 3 s (`App.tsx`), which updates the counters and lets `forwards_list` drop tunnels whose accept loop ended or whose connection closed (`Tunnel::is_alive`). A tunnel whose connection dropped therefore turns itself off; it is not restarted. Keepalives (every 30 s, 3 missed) notice a silent network loss.

Stopping aborts the accept loop, cancels a remote listener (`cancel-tcpip-forward`) and closes the connection, which drops the connections open through it. Every tunnel stops on lock (`vault_lock`), when the device is erased, and on quit (`RunEvent::Exit`, with SFTP and VPNs, within 3 s). Tunnels never start by themselves, on launch or on unlock.

## Tauri commands

| Command | Arguments | Does |
| --- | --- | --- |
| `forwards_list` | | Every tunnel with its live state; forgets dead ones |
| `forward_save` | `input: {id?, vaultId?, label, hostId, rule}` | Creates or updates; stops it first if running |
| `forward_delete` | `id` | Stops and deletes |
| `forward_start` | `id`, `password?` | Starts; `password` only for a host without a saved one |
| `forward_stop` | `id` | Stops |

## Errors

| Situation | What the user sees |
| --- | --- |
| Start fails | A banner: `Tunnel “label”: ` and the error |
| Port in use or not allowed | `could not listen on 127.0.0.1:15432: Address already in use (os error 98)` (the OS's text) |
| Server refuses a remote listener | `could not listen on 127.0.0.1:8080 on the server: …` |
| Connecting fails | The terminal's messages ([SSH connections](ssh-connections.md)), e.g. `jump host "bastion" has no saved password; save one or switch it to a key`, or a proxy command this device hasn't allowed |
| Not a tunnel item | `not a tunnel` |
| One connection through the tunnel fails (destination down, forwarding refused) | Nothing in the UI, logged at debug level. Local: the accepted socket closes. SOCKS: reply 5 (connection refused). Remote: the channel closes |
| SOCKS client without "no authentication", or asking for `BIND`, `UDP ASSOCIATE`, an unknown address type, or SOCKS4 | Method `0xFF`, reply 7 (command not supported), reply 8 (address type not supported); SOCKS4 is dropped |

## Tests

| Test | Covers |
| --- | --- |
| `crates/mg-ssh/src/forward.rs`: `socks5_connect_requests`, `socks5_rejections` | The SOCKS5 handshake: IPv4, domain, IPv6; refusals |
| `apps/desktop/src-tauri/src/tunnels.rs`: `rule_shapes_match_the_frontend` | The JSON the webview sends and gets |
| `crates/mg-ssh/tests/live.rs`: `local_forward`, `dynamic_socks_forward`, `remote_forward` | Real forwards against an sshd with TCP forwarding on. Needs `MG_TEST_SSH`; see [Terminal and snippets](terminal-and-snippets.md#tests) for the command |
| `apps/desktop/e2e/layout.mjs` | Creates a tunnel and checks the Tunnels page layout (it does not start one) |

## Limits

| Not there | Detail |
| --- | --- |
| Ad hoc forwards | Every tunnel is saved. Quick-connect hosts can't carry one, and a terminal's connection is never reused: each tunnel has its own |
| Auto start, restart | Neither on launch nor after a drop |
| SOCKS | SOCKS5 `CONNECT` only, no authentication, no UDP |
| Other forwards | No Unix-socket forwarding, no X11 forwarding |
| Cloud hosts | A host whose provider's SSH forwards no ports (`source.no_forwarding`: Vallic Cloud's) carries no tunnel. The editor leaves it out (it stays listed only for a tunnel saved through it before, with "This host's cloud doesn't forward ports, so this tunnel can't start."), and `forward_save` and `forward_start` refuse it: "\"{host}\" can't carry tunnels: its cloud's SSH doesn't forward ports" (`can_carry_tunnels` in `tunnels.rs`) |
| Phones | A host reached through a proxy command, a cloud CLI or an SSH agent can't be used from a phone (the same errors as a terminal) |
