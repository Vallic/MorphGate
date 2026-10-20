# Per-host VPN

Many client servers are only reachable through the client's VPN. In MorphGate a VPN is a vault item that hosts point to; it comes up when a session, SFTP tab or port forward to such a host needs it, and stops after the last one closes. Every tunnel runs inside the app with its own TCP/IP stack (smoltcp), so nothing on the system changes: no TUN device, no routes, no root, and two clients' VPNs with the same private subnet can be up at once. WireGuard and OpenVPN are implemented in Rust; openconnect (Cisco AnyConnect, GlobalProtect, Fortinet, …) runs through the system's `openconnect` program, whose packets are fed into the same in-app stack. This page covers the app side; protocol details are in [VPN protocols](vpn-protocols.md). Code: `crates/mg-vpn/src/lib.rs` (`Tunnel`, `Prompter`), `crates/mg-vpn/src/netstack/`, `crates/mg-vpn/src/wireguard/`, `crates/mg-vpn/src/openvpn/`, `crates/mg-vpn/src/openconnect/`, `apps/desktop/src-tauri/src/vpn.rs` (Tauri commands, `VpnManager`), `apps/desktop/src/VpnPanel.tsx`, `apps/desktop/src/VpnPromptDialog.tsx`, `VpnProfile` / `VpnKind` in `crates/mg-store/src/model.rs`.

## The vault item

A VPN is a `vpn` item (`ItemData::Vpn(VpnProfile)`), encrypted and synced like any other (see [Architecture](../architecture.md)). `vpn.type` picks the kind:

| Field | Kinds | Holds |
| --- | --- | --- |
| `label` | all | The name ("VPN name is required") |
| `vpn.config` | `wireguard`, `openvpn` | The wg-quick text (private key included), or the `.ovpn` profile with every file it refers to embedded as inline blocks |
| `vpn.username`, `vpn.password` | `openvpn`, `openconnect` | Optional; whatever is missing is asked when connecting |
| `vpn.server`, `vpn.protocol` | `openconnect` | Host or URL (with a group path), and the openconnect `--protocol` |
| `vpn.authgroup` | `openconnect` | Login group (`--authgroup`) |
| `vpn.server_cert` | `openconnect` | `pin-sha256:…` of a server certificate the user chose to trust |

Saving refuses an empty config or server ("WireGuard configuration is empty", "OpenVPN profile is empty", "VPN server is required"). Deleting a VPN that hosts or groups still use is refused (`VPN "name" is still used by: …`). A vault export replaces the saved password, WireGuard `PrivateKey` / `PresharedKey` lines, and the OpenVPN `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`, `<pkcs12>`, `<askpass>` and `<auth-user-pass>` blocks with `(not exported)` unless passwords are included (`crates/mg-store/src/export.rs`).

## How a host names its VPN

A host (and a host group) has `vpn_ref`, the id of a `vpn` item. A host that leaves it empty takes its group's (`Host::effective`). The reference is checked on save:

| Rule | Error |
| --- | --- |
| The VPN must be in the host's own vault, so everyone with access can connect | "items can only refer to items in the same vault" |
| It must exist and be a VPN | "the selected VPN does not exist" |
| A host with a proxy command connects through it, not a VPN | "a host with a proxy command connects through it, not a jump host or a VPN too" |

The VPN carries only the first hop. `resolve()` in `apps/desktop/src-tauri/src/ssh.rs` reads `vpn_ref` from the first jump host, or from the target when there is none; a target behind a jump host is reached from the jump host, and its own VPN setting is not used. The host editor shows this: with a jump host the **VPN** select is disabled and reads "From the jump host: …"; with a proxy command it reads "None: the proxy command connects it". Otherwise it offers "None (your normal network)" (or "From the group: …") and the vault's VPNs as "label (Kind · server)".

## Routing the SSH connection

`first_hop()` turns the resolved `VpnRef` into an `mg_ssh::Dialer`: `VpnManager::dialer()` gets the running tunnel (or starts one) and wraps it in `VpnDialer`, whose `dial(host, port)` is `Tunnel::connect()`. A proxy command, or a cloud reach command, wins over a VPN. The SSH session, every SFTP tab (`sftp.rs`) and every port forward (`tunnels.rs`) go through `first_hop()`, so they all use the host's VPN. The rest of the connection (host keys, jump hosts over SSH, authentication) is the same as without a VPN: see [SSH connections](ssh-connections.md).

Errors carry the VPN's name. A tunnel that can't start fails the connect with `VPN "name": …` (the protocol's reason). A host that can't be reached through a running tunnel fails as `could not connect to host:port via VPN "name": …` with the stack's reason (below). The VPN's start is not bounded by the 15 s SSH connect timeout; each protocol has its own timeouts.

## Tunnel lifetime and sharing

`VpnManager` (Tauri state) keeps one tunnel per profile id, shared by every session, SFTP tab and port forward that uses it.

| Behavior | How |
| --- | --- |
| Sharing | `tunnels` maps profile id to `Weak<Tunnel>`. Each `mg_ssh::Connection` keeps its dialer (an `Arc<Tunnel>`) for its lifetime, so the tunnel lives exactly as long as some connection uses it |
| One start at a time | `starting` holds a lock per profile: a second connect waits for the first (which may be waiting on a password prompt) and then shares its tunnel |
| Stop | When the last connection closes, the stack ends after its last stream and the link stops, logging out where the protocol has a logout (OpenVPN over UDP sends an exit notice; openconnect gets SIGTERM, then a kill after 5 s) |
| Edit or delete | `vpn_save` and `vpn_delete` forget the running tunnel: new connections start a fresh one with the new settings; open ones keep theirs |
| Lock, erase, quit | `shutdown_all()` cuts every tunnel at once and cancels waiting prompts: on `vault_lock`, `erase_device`, and the app's exit (bounded to 3 s, so an openconnect child doesn't outlive the app) |
| Link lost | No automatic reconnect. Open streams end (the session sees EOF, or "the VPN connection was lost: reason"); the next connection starts a new tunnel, since `running()` skips tunnels whose stack has ended |

## Tauri commands

| Command | Does |
| --- | --- |
| `vpns_list` | Every `vpn` item as a `VpnView`, sorted by label: kind, server, read-only facts, WireGuard public key, saved username, `hasPassword`, openconnect protocol, group and pin, `active` and `address` while a tunnel runs, and `problem` when the stored profile doesn't parse (or openconnect can't run here) |
| `vpn_save` | Creates or updates a profile from `VpnInput` (below), parsing it first so a bad profile fails at save, not at connect. The type of an existing VPN can't change ("A VPN's type can't change; create a new VPN instead.") |
| `vpn_delete` | Deletes the item (refused while in use) and forgets its tunnel |
| `vpn_test` | Starts (or reuses) the tunnel, which proves the handshake, sign-in and address assignment, and returns `{server, address, millis}`. The tunnel then stops unless a connection is using it |
| `vpn_prompt_answer` | Answers a `vpn-prompt`: `answers` is one string per field, `[]` to trust a certificate, `null` to cancel |

`VpnInput`: `id`, `vaultId` (new items), `kind`, `label`, `config` (pasted or picked text; empty on edit keeps the stored one), `configFiles` (`[{name, data}]`, base64: the files a picked `.ovpn` refers to), `configPath` (a path on disk, whose `.ovpn` references are read from its folder; the UI no longer sends it), `server`, `protocol`, `authgroup`, `username`, `password` (absent keeps the saved one, `""` removes it), `forgetServerCert`. An empty label becomes "WireGuard *endpoint host*", "OpenVPN *first server*" or the openconnect server's host name. An openconnect pin is kept only while the server stays the same and **Forget** wasn't used.

## Prompts while connecting

Connects ask through the `Prompter` trait; the app's `UiPrompter` emits `vpn-prompt` and waits for `vpn_prompt_answer`. A prompt the connect stops waiting for (signed in, failed, timed out) is withdrawn with `vpn-prompt-closed`. `App.tsx` queues prompts and shows the first in `VpnPromptDialog`:

| `kind` | Dialog | Controls |
| --- | --- | --- |
| `fields` | Title "Sign in to *name*", the server's message, one input per field (hidden for passwords and one-time codes) | **Cancel**, **Continue** |
| `certificate` | **Untrusted VPN server**: host, reason, fingerprint, and advice to compare it with the admin's | **Cancel**, **Trust and connect** |
| `browser` | "Finish signing in in your browser. *name* connects as soon as the VPN server confirms it.", the **Sign-in page** URL, and "The browser didn't open: …" if it didn't | **Open again**, **Cancel** |

Field and certificate prompts time out after 5 minutes (`PROMPT_TIMEOUT`), which cancels the connect (`VPN "name": cancelled`). A web sign-in has no timeout of its own: the server decides how long it may take, and the dialog closes by itself when the connect stops waiting. Only `http://` and `https://` pages are opened (`util::open_in_browser`; `MORPHGATE_BROWSER` overrides the browser).

## The VPN editor

`VpnPanel` edits one profile; the VPNs page (`VpnsPage` in `Lists.tsx`, **New VPN**) lists them with their server and status, or what uses them ("Used by 2 hosts and 1 group", "Not used by a host yet").

| Control | Does |
| --- | --- |
| **Vault** | Where a new VPN lives (`VaultField`); read-only vaults disable saving |
| **WireGuard** / **OpenVPN** / **OpenConnect** | Type of a new VPN. Phones and tablets don't offer OpenConnect |
| **Name** | The label |
| **From .conf file** / **From .ovpn file**, **Paste config** / **Paste profile** | How a new configuration arrives. Files come from **Choose file…** (WireGuard) or **Choose files…** ("The .ovpn file, and the files it refers to if they're separate"); the `.ovpn`/`.conf` among them is the profile, the rest are matched to its references by file name |
| **Replace the configuration** / **Replace the profile** | On an existing VPN, shows the import controls again |
| **Server**, **Protocol**, **Group (optional)** | openconnect only |
| **Server certificate pinned: …** with **Forget** | openconnect only; the pin is dropped on save and asked again on the next connect |
| **Username**, **Password** | OpenVPN and openconnect. A saved password shows "Saved in the vault" with **Change** and **Remove** |
| Facts | Read-only details from `VpnView.facts` (below), **Your key** (WireGuard public key, with a copy button), and **Status**: "Connected as *address*" or "Idle: starts when a host needs it" |
| **Test** | `vpn_test`; shows "Connected to *server* as *address* (*n* ms)." |
| **Delete** → **Really delete?**, **Close**, **Save** | |

Facts per kind: WireGuard **Endpoint(s)**, **Address**, **Routes** (AllowedIPs), **Peers**, **DNS**; OpenVPN **Server(s)**, **Sign-in**, **Ciphers**, **Control channel**, **Certificate**, **Key passphrase**, **One-time code**; openconnect **Server**, **Protocol**, **Group**, **Certificate** ("pinned (…)" or "trusted by the system"). While connected: **Networks** and **VPN DNS**. A profile that no longer parses shows "Stored configuration is invalid: …".

Elsewhere: the sidebar's **VPNs** entry counts tunnels that are up ("2 up"); hosts dialed through a VPN carry a **VPN** tag; the route bar above a session and the host editor's connection path show the VPN as "connected" with its address, or "comes up with the session". The group editor (`Identities.tsx`) has the same **VPN** select for a group's hosts.

## The in-app network stack

Each `Tunnel` is two tasks joined by bounded packet queues (`LINK_QUEUE`, 1024 packets each way; overflow drops, like a NIC, and TCP retransmits):

1. The **link** speaks the VPN protocol on an ordinary socket (WireGuard's UDP socket, OpenVPN's UDP or TCP socket, or openconnect's packet socket) and moves decrypted IP packets.
2. The **stack** (`netstack::Driver`) is a smoltcp interface on a virtual IP-layer device (`netstack/device.rs`), with the addresses the VPN assigned and a default route to the peer. `Tunnel::connect()` opens a smoltcp TCP socket and hands the caller one end of an in-process pipe (`VpnStream`, a tokio `DuplexStream`).

No IP packet reaches the operating system, so there is nothing to route and no interface to create: the only OS sockets are the connections to the VPN server. That is why no root or admin rights are needed, why only MorphGate's own connections use the VPN (the rest of the machine stays on its network, and the client's network doesn't see the machine), and why overlapping subnets are fine: each tunnel has its own stack and address space, and `10.0.0.5` in one never meets `10.0.0.5` in another.

| Constant | Value | Why |
| --- | --- | --- |
| `TCP_BUF` | 128 KiB per direction per socket | The receive buffer is the advertised window |
| `PIPE` | 64 KiB | App-side pipe |
| Congestion control | Cubic, Nagle off | Without it smoltcp sends its whole window at once, overflowing UDP buffers |
| TCP keep-alive | 25 s | Keeps idle sessions and middlebox state alive |
| `CONNECT_TIMEOUT` | 15 s | TCP handshake through the tunnel |
| `LOOKUP_TIMEOUT` | 12 s | DNS through the tunnel, before the system resolver is tried |
| `LINGER` | 30 s | After both sides close, how long the tail and FIN may take to be acknowledged; a socket dropped early would answer with a reset and lose the tail |
| `MAX_ROUNDS`, `MAX_PACKETS_PER_ROUND` | 64, 256 | Bounded work per poll, so one busy tunnel can't starve the runtime |

| Error (through the tunnel) | When |
| --- | --- |
| "connection refused (through VPN)" | The far host answered with a reset |
| "connection through the VPN timed out (host down or port filtered?)" | No answer in 15 s; adds "; *ip* is not in the networks the VPN announced (…)" when the server announced routes that don't cover it |
| "connection timed out: the VPN link is not up" | The link never came up or went down |
| "*ip* is outside this VPN's AllowedIPs" | WireGuard only: no peer carries that address |
| "the VPN gave this device no address for *ip*'s IP version" | An IPv6 target on an IPv4-only tunnel, or the reverse |
| "the VPN connection was lost: …" / "the VPN connection has stopped: …" | The link went down; the reason is the protocol's |

### DNS

A host name (not an IP literal) is resolved by the VPN's DNS servers through the tunnel, with smoltcp's DNS client (8 queries at once). A name without a dot tries the VPN's search domains first, then the bare name (like `ndots:1`). The stack asks for A records when the VPN gave it an IPv4 address, otherwise AAAA, and uses the first answer. When the VPN's DNS doesn't know the name or doesn't answer in 12 s, or the VPN has no DNS server, the system resolver is asked instead, and the address it returns is dialed through the tunnel; that lookup leaves the machine on the local network. Errors: "cannot resolve *host* (neither the VPN's DNS nor the system's)", or "cannot resolve *host*; the VPN profile has no DNS server". Where each protocol's DNS servers and search domains come from: [VPN protocols](vpn-protocols.md).

## Platforms

| Platform | WireGuard, OpenVPN | openconnect |
| --- | --- | --- |
| Linux, macOS | Yes | Yes, with the `openconnect` program installed (looked up in `PATH` and the usual Homebrew, MacPorts and `/usr` directories, since GUI apps on macOS don't see the shell's `PATH`) |
| Windows | Yes | No: openconnect's Windows build can't run a `--script-tun` script, and its only other way out is a TAP or Wintun adapter, which needs a driver and admin rights. The profile shows "openconnect VPNs don't work on Windows yet: …" |
| Android, iOS | Yes, in-app (no system VPN permission) | No: phones can't run another program. New VPNs don't offer it; a synced profile shows "openconnect VPNs work in the desktop app: phones and tablets can't run the openconnect program" |

## Tests

- `apps/desktop/src-tauri/src/vpn.rs`: `build()` keeps or drops the saved password and openconnect pin correctly, refuses unknown protocols, embeds the files an `.ovpn` refers to (from its folder, and picked by name), and explains a missing one.
- `apps/desktop/e2e/layout.mjs` (a new openconnect VPN saves and appears on the VPNs page) and `apps/desktop/e2e/mobile.mjs` (a WireGuard VPN added from its `.conf` file on a phone).
- The stack is exercised by the WireGuard tests in `crates/mg-vpn/src/wireguard/mod.rs` (two in-process stacks talking to each other: echo, bulk transfer with flow control, many streams, closed ports, AllowedIPs, shutdown), and every protocol has a live test that runs a real `mg-ssh` session through the tunnel. How to run the protocol and live tests: [VPN protocols](vpn-protocols.md#tests).

## Limits

- Only TCP connections go through a tunnel (SSH, SFTP, port forwards). There is no UDP or ICMP, so no `ping` through it.
- A tunnel that goes down is not restarted; the next connection starts a new one.
- openconnect: not on Windows, phones or tablets (above).
- In a view-only shared vault, an openconnect certificate the user trusts can't be pinned (the vault refuses the write; it is logged), so it is asked again on every connect.
- The VPNs page's "Used by" and the editor's "Used by:" count every host whose own or group setting names the VPN, even when a jump host means the VPN isn't used for it.
- Protocol-level refusals (TAP, static keys, proxies, hardware tokens, …): [VPN protocols](vpn-protocols.md#limits).

## Related

- [VPN protocols](vpn-protocols.md), [SSH connections](ssh-connections.md), [Architecture](../architecture.md)
