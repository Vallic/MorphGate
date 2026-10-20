# VPN protocols

What each VPN kind reads from its configuration, how it signs in, and how it behaves once up. All three end in the same in-app TCP/IP stack and are used the same way by hosts: see [Per-host VPN](vpn.md). Errors listed here reach the user prefixed with `VPN "name": `, or, for problems found when saving, as the editor's error. Code: `crates/mg-vpn/src/wireguard/` (`config.rs`, `mod.rs`), `crates/mg-vpn/src/openvpn/` (`config.rs` profile parsing, `session.rs` the protocol, `tls.rs`, `keyfile.rs`, `push.rs`, `data.rs`), `crates/mg-vpn/src/openconnect/` (`mod.rs`, `helper.rs`).

## At a glance

| | WireGuard | OpenVPN | openconnect |
| --- | --- | --- | --- |
| Implementation | boringtun, in-process | Our own client: rustls control channel, aws-lc data channel | The `openconnect` program in `--script-tun` mode |
| Configuration | wg-quick `.conf` | `.ovpn` client profile, referenced files embedded | Server, protocol, optional group |
| Sign-in | Keys | Client certificate and/or username and password; static and dynamic challenges; web sign-in | Whatever the server asks (password, one-time code, group); certificate trust; browser SSO with openconnect 9+ |
| DNS servers | `DNS` IP entries | Pushed, then the profile's own | `INTERNAL_IP4_DNS`, `INTERNAL_IP6_DNS` |
| Search domains | None | Pushed, then the profile's own | `CISCO_DEF_DOMAIN` |
| Stack MTU | `MTU`, default 1420 | Pushed or profile `tun-mtu`, at most 1400 (`STACK_MTU`) | `INTERNAL_IP4_MTU` / `INTERNAL_IP6_MTU`, default 1300 |
| Keepalive | `PersistentKeepalive` per peer | `ping`, default 10 s | openconnect's own |
| Declared down | Never (a silent peer makes connects time out) | `ping-restart` without traffic, server `RESTART`/`HALT`/`EXIT`, failed renegotiation | When the program exits |
| Platforms | All | All | Linux and macOS |

Every MTU is clamped to 576–9000. No kind restarts a tunnel that went down: the next connection starts a new one ([Per-host VPN](vpn.md#tunnel-lifetime-and-sharing)).

## WireGuard

A wg-quick file, as `wg-quick` and the WireGuard apps use. Lines are `Key = Value`, keys are case-insensitive, `#` starts a comment, and lists are comma-separated.

| Section, key | Use |
| --- | --- |
| `[Interface] PrivateKey` | Required. Stored only in the vault; the editor shows the matching public key (what `wg pubkey` prints) as **Your key** for the VPN's admin |
| `[Interface] Address` | Required; this device's addresses inside the VPN (IPv4 and/or IPv6) |
| `[Interface] DNS` | IP entries are the DNS servers. Non-IP entries (search domains) are dropped |
| `[Interface] MTU` | 576–9000, default 1420 |
| `[Interface]` anything else | Ignored on purpose: `ListenPort`, `Table`, `PostUp`/`PostDown` and other host-level settings configure nothing, since the tunnel lives in the app |
| `[Peer] PublicKey` | Required, unique per peer |
| `[Peer] PresharedKey` | Optional |
| `[Peer] Endpoint` | `host:port`, resolved once when the tunnel starts. At least one peer needs one, since MorphGate connects out; peers without one wait to be called |
| `[Peer] AllowedIPs` | Required. The networks behind this peer |
| `[Peer] PersistentKeepalive` | Seconds; `off` or `0` for none |

| Error | When |
| --- | --- |
| "[Interface] PrivateKey is missing", "[Interface] Address is missing", "the configuration has no [Peer]" | Missing pieces |
| "[Peer] PublicKey is missing", "[Peer] AllowedIPs is missing", "[Peer] Endpoint is missing" | One peer; with several, "[Peer] 2: …" and "no [Peer] has an Endpoint; MorphGate connects out, so at least one peer needs one" |
| "[Peer] 2: has the same PublicKey as an earlier peer" | Duplicate peer |
| "PrivateKey is not a WireGuard key (44 base64 characters)" | Likewise for `PublicKey`, `PresharedKey` |
| "MTU must be 576..9000", "PersistentKeepalive must be seconds", "invalid address …", "invalid prefix in …" | Bad values |
| "line N: unknown section …", "line N: setting outside a section", "line N: expected Key = Value" | Malformed file |
| "cannot resolve the VPN server *endpoint*" | At connect |
| "no WireGuard handshake with *endpoint*; check the endpoint, the keys, and that UDP isn't blocked" | No handshake within 10 s (`handshake_timeout`) |

Connecting binds one UDP socket (dual-stack when any endpoint is IPv6, 4 MiB buffers) and waits for the handshakes, so a wrong key fails at once with a clear error instead of as a connect timeout later. With several peers, the first answer is enough: the others get 2 s more (`OTHERS_GRACE`) and keep trying in the background, so one silent gateway doesn't block the rest.

Each peer has its own boringtun state, so its own handshake, rekeying and keepalives, driven every 250 ms (`WG_TICK`). Outgoing packets go to the peer whose AllowedIPs match the destination most specifically (equal prefixes: the later peer, as `wg setconf` does); a connect to an address no peer carries is refused at once. Incoming packets are accepted only when their source address routes back to the peer that sent them (cryptokey routing). Handshake MACs are checked before the costly Diffie-Hellman, and more than 10 handshakes a second (`HANDSHAKE_RATE_LIMIT`) are answered with cookies. A peer that roams is followed to its new address.

## OpenVPN

A client for OpenVPN 2.4 and later servers, Access Server, pfSense and OPNsense, over UDP or TCP, without a TUN device.

### Importing a profile

Saving embeds every file the profile refers to as an inline block (`inline_files_with()`), so the vault item stands alone and syncs: `ca`, `cert`, `key`, `extra-certs`, `tls-auth`, `tls-crypt`, `tls-crypt-v2`, `auth-user-pass`, `askpass`, `pkcs12` (base64), `secret`, `crl-verify`. `tls-auth file 1` becomes the block plus `key-direction 1`. Files are matched by name, whatever folder the profile names, against those picked with it; a missing one says "the profile refers to *file*: choose the .ovpn file and *file* together, or paste a profile with it inline" (or "…: choose it along with the profile"). The profile is then parsed and its certificates checked, so a profile that can't work fails at save. Lines are split as OpenVPN does (quotes, backslash escapes, `#` and `;` comments, optional `--` prefixes).

### Directives used

| Directive | Use |
| --- | --- |
| `remote host [port] [proto]`, `<connection>` blocks, `port`/`rport`, `proto`, `remote-random` | Servers, tried in order (shuffled with `remote-random`). Defaults: port 1194, UDP. `proto` accepts `udp`, `udp4`, `udp6`, `tcp`, `tcp4`, `tcp6`, `tcp-client` and its 4/6 forms |
| `ca`, `peer-fingerprint` | Server trust (below). One of them is required, unless a PKCS#12 bundle brings the CA |
| `cert` + `key`, `extra-certs`, `pkcs12`, `askpass` | Client certificate (below) |
| `tls-auth` + `key-direction`, `tls-crypt`, `tls-crypt-v2` | Control channel protection. With several, `tls-crypt-v2` wins, then `tls-crypt` |
| `auth` | HMAC digest for `tls-auth` and CBC: SHA1 (default), SHA256, SHA384, SHA512 |
| `data-ciphers` (`ncp-ciphers`), `data-ciphers-fallback`, `cipher` | Offered data ciphers, preferred first: AES-256-GCM, AES-128-GCM and CHACHA20-POLY1305 by default; AES-128-CBC and AES-256-CBC when listed. Unknown names are dropped; the fallback (or old `cipher`) is used when the server doesn't negotiate |
| `auth-user-pass`, `static-challenge` | Username and password sign-in (below) |
| `verify-x509-name name [subject\|name\|name-prefix]` | Required server certificate name |
| `comp-lzo`, `compress` | Compression framing (below) |
| `tun-mtu` | MTU (clamped 576–9000), capped at 1400 in the stack |
| `keepalive`, `ping`, `ping-restart` | Used when the server pushes none |
| `route`, `dhcp-option DNS`/`DNS6`/`DOMAIN`/`DOMAIN-SEARCH` | Added after what the server pushes |
| `route-nopull` | Of the pushed networks, only the VPN's own address is kept |
| `hand-window` | How long TLS and sign-in may take once the server answered: default 60 s (5–600) |
| `server-poll-timeout`, `connect-timeout` | How long to wait for each server's first answer: default 10 s (2–120) |

Everything else is ignored, including host-level options (`user`, `group`, `up`/`down` scripts, `persist-*`, `mssfix`), `reneg-sec`, `tls-cipher`, and `crl-verify` (embedded, but not checked).

### Refused directives

Each error starts with `line N: `.

| Directive | Error |
| --- | --- |
| `server`, `server-bridge`, `tls-server`, `mode server` | "this is a server configuration; import the client profile" |
| `dev tap…`, `dev-type tap` | "TAP (layer 2) VPNs are not supported, only `dev tun`" |
| `secret` | "static-key mode (`secret`) is not supported, only TLS" |
| `pkcs11-id`, `pkcs11-providers`, `cryptoapicert`, `management-external-key`, `management-external-cert` | "certificates in hardware tokens or OS stores are not supported" |
| `http-proxy`, `socks-proxy` | "connecting through a proxy is not supported yet" |
| `fragment` | "`fragment` is not supported" |
| `tls-version-max 1.0` or `1.1` | "TLS below 1.2 is not supported" |
| Unknown values | "unknown `proto`", "unsupported `auth` digest", "unknown `comp-lzo` mode", "unknown `compress` algorithm", "unknown `verify-x509-name` type", "`key-direction` must be 0 or 1", "invalid `peer-fingerprint` (SHA-256 expected)" |

Whole-profile checks: "the profile has no `remote` server", "the profile has no CA certificate (<ca>)", "the profile has both <pkcs12> and <cert> / <key>; it needs one or the other", "the profile has a client certificate without its key (or the other way round)", "none of the profile's data ciphers are supported (AES-GCM, ChaCha20-Poly1305, AES-CBC)", and for a tls-crypt-v2 server key, "this is the server's tls-crypt-v2 key; the profile needs a client key made from it (…)".

### Client certificate and key

| Form | Handling |
| --- | --- |
| `<cert>` + plain `<key>` | Used as is (PKCS#1, PKCS#8, SEC1) |
| `<key>` encrypted | PKCS#8 `ENCRYPTED PRIVATE KEY` with PBES2 (AES or 3DES), or OpenSSL's older `Proc-Type: 4,ENCRYPTED` with AES-128/192/256-CBC or DES-EDE3-CBC. Other schemes (PKCS#5 v1.5 or PKCS#12 PBE, DES-CBC) fail at save with advice to re-encrypt: `openssl pkcs8 -topk8 -v2 aes-256-cbc -in key.pem -out key-new.pem` |
| `<pkcs12>` | Certificate, key and usually the CA; its CA is trusted when the profile has no `<ca>`. A bundle with an algorithm MorphGate can't open fails with advice to convert it to `<ca>`, `<cert>` and `<key>` |
| Passphrase | From an inline `<askpass>` (first line), else an empty one for bundles, else asked: "Key passphrase" or "Bundle password". Three wrong answers (`MAX_PASSPHRASE_TRIES`) end with "wrong passphrase for the client key" (or "certificate bundle (PKCS#12)"). Decryption runs off the async runtime, since key derivation is slow on purpose |

### Username, password and challenges

For `auth-user-pass` profiles, the vault's saved username and password win over an inline `<auth-user-pass>` block (line 1 user, line 2 password); whatever is still missing is asked ("Username", "Password"). `static-challenge "text" echo [concat]` adds the challenge to the same prompt and sends the answer as `SCRV1:base64(password):base64(answer)`, or appended to the password with `concat`. A dynamic challenge (`AUTH_FAILED,CRV1:…`) is asked and answered on a new session to the same server as `CRV1::state::answer`, up to three in a row ("too many sign-in challenges"). After the first sign-in, a pushed `auth-token` (and `auth-token-user`) replaces the password on renegotiations; a renegotiation's push may refresh it.

Web sign-in: the client announces `IV_SSO=webauth,openurl`. When the server sends `WEB_AUTH` or `OPEN_URL` (with or without `INFO_PRE,`), the page opens in the browser and the connect waits for the server's verdict. Only `http(s)://` pages are accepted ("the server wants a web sign-in at "…", which is not a web page"). `AUTH_PENDING,timeout N` sets how long to wait, capped at 30 minutes (`MAX_PENDING`) or the hand window if longer; without it, the hand window applies.

### Server trust

The control channel is TLS 1.2 or 1.3 (rustls) the way OpenVPN does it: no SNI and no host name check, since OpenVPN identifies servers by CA and certificate name. The server certificate must chain to the profile's `<ca>` (or the bundle's CA) and carry the serverAuth usage when it lists usages; `verify-x509-name` then narrows it ("the server certificate is for "cn", but the profile expects "…" (verify-x509-name)"). A `peer-fingerprint` match is accepted on its own; a certificate that doesn't match is refused unless the profile also has a CA it chains to. Session resumption is off: every key state gets fresh TLS keys.

### The session

| Stage | Behavior |
| --- | --- |
| Reset and TLS | Control packets carry at most 1100 TLS bytes (`CONTROL_CHUNK`), under OpenVPN's default `tls-mtu`. tls-crypt-v2 sends the wrapped client key with the first packets, and again when a 2.6 server asks |
| Push | `PUSH_REQUEST` is repeated every 5 s (`PUSH_RETRY`) until the reply, which may span several messages (`push-continuation`). Used: `ifconfig` (with `topology subnet` or net30/p2p), `ifconfig-ipv6`, `route`, `route-ipv6`, `redirect-gateway`/`redirect-private` (everything routes through), `dhcp-option DNS`/`DNS6`/`DOMAIN`/`DOMAIN-SEARCH`/`ADAPTER_DOMAIN_SUFFIX`, the 2.6 `dns server N address …` and `dns search-domains …`, `cipher`, `peer-id`, `ping`, `ping-restart`, `tun-mtu`, `key-derivation tls-ekm` / `protocol-flags tls-ekm`, `comp-lzo`/`compress`, `auth-token`, `auth-token-user` |
| Data channel | AEAD (AES-GCM, ChaCha20-Poly1305) or AES-CBC with HMAC; keys from the TLS exporter (RFC 5705) when the server offers tls-ekm, otherwise OpenVPN's TLS 1.0 PRF; peer-id packets (`DATA_V2`) when pushed; replay window |
| Compression | Never compresses what it sends (VORACLE; SSH is encrypted anyway). Speaks the `comp-lzo` and `compress` framings (stub, stub-v2, lzo, lz4, lz4-v2, `migrate`) and decompresses LZO and LZ4 a server sends anyway, bounded to 65,535 bytes |
| Routes | Pushed networks (or only the VPN's own address with `route-nopull`) plus the profile's `route`s. They don't limit where connects go; they explain timeouts |
| Keepalive | A ping every `ping` seconds without other traffic (pushed, else the profile's, else 10 s). With `ping-restart`, silence that long takes the link down ("no traffic from the OpenVPN server for Ns") |
| Renegotiation | Started by the server; the previous key keeps decrypting for 60 s (`TRANSITION`). One that doesn't finish within the hand window takes the link down ("key renegotiation with the server failed"). MorphGate doesn't start renegotiations itself |
| Leaving | Over UDP an exit notice tells the server; over TCP the connection closes |

| Error at connect | Meaning |
| --- | --- |
| "no answer from *remote* (wrong address or port, UDP blocked, or a tls-auth / tls-crypt key mismatch)" | No reply within `server-poll-timeout`; the next server is tried. All failing: "no OpenVPN server answered: …" |
| "the OpenVPN server rejected the sign-in (wrong username or password?)", or "…: *reason*" | `AUTH_FAILED` |
| "the server's certificate was rejected: …", "the server aborted TLS: …" | Trust or TLS failure |
| "TLS handshake with the OpenVPN server timed out", "the server never confirmed the sign-in (no PUSH_REPLY)", "the sign-in in the browser wasn't finished in time", "the server's sign-in check didn't finish in time (AUTH_PENDING)" | The hand window ran out at that stage |
| "the server chose the data cipher *name*, which MorphGate doesn't support" | Pushed cipher unknown |
| "the server didn't negotiate a data cipher; add `data-ciphers-fallback` (e.g. AES-256-CBC) to the profile" | Old server, no fallback |
| "the server assigned no address to this client (no ifconfig in its push)" | |
| "the OpenVPN server ended the session: …", "the OpenVPN server is shutting down" | `RESTART`/`HALT`, `EXIT` |

## openconnect

For Cisco AnyConnect and ocserv, Palo Alto GlobalProtect, Fortinet, Pulse/Ivanti, F5, Juniper and Array servers. openconnect speaks the protocol; MorphGate keeps the packets.

| **Protocol** option | `--protocol` |
| --- | --- |
| Cisco AnyConnect / ocserv (default) | `anyconnect` |
| Palo Alto GlobalProtect | `gp` |
| Fortinet FortiGate | `fortinet` |
| Pulse / Ivanti Connect Secure | `pulse` |
| F5 BIG-IP | `f5` |
| Juniper Network Connect | `nc` |
| Array Networks | `array` |

### How it runs

`openconnect --protocol=… [--user=…] [--authgroup=…] [--servercert=pin] [--passwd-on-stdin] [--external-browser=…] --script-tun --script='<MorphGate> --mg-oc-tun' -- server`. In `--script-tun` mode openconnect configures no TUN device: it starts its "script" with a packet socket in `VPNFD` and the tunnel settings in its environment. The script is MorphGate's own binary (`main.rs` calls `tun_helper_if_requested()` first, which acts as the helper when the first argument is `--mg-oc-tun`). The helper sends the socket (`SCM_RIGHTS`) and the settings to the app over a Unix socket and stays until the app closes it.

The handoff is private: the socket lives in a fresh `mg-oc-<random>` directory with mode 0700 in the temp dir, deleted when the connect ends, and the helper must present a random 128-bit token (`MG_OC_TOKEN`) or is refused. A saved password goes in on stdin (`--passwd-on-stdin`), never on the command line. openconnect runs with `LC_ALL=C`, since prompts are recognized by their English text, and is killed if the app drops it. Stopping sends SIGTERM so openconnect logs out of the VPN session, then kills it after 5 s.

### Prompts and sign-in

A partial line on openconnect's stderr followed by 250 ms of silence (`QUIET`) is a prompt. It is shown as a field labelled with the prompt, hidden unless the label mentions a user, login, email, name, group, realm or domain, with the last three lines openconnect printed as the message. A wrong saved password makes openconnect ask again, which reaches the user. "Enter 'yes' to accept" (an untrusted server certificate) becomes the **Untrusted VPN server** dialog with openconnect's host, reason and `pin-sha256:` fingerprint; trusting it saves the pin in the profile (`server_cert`), which is passed as `--servercert` from then on. Refusing ends with "the VPN server's certificate is not trusted (*reason*)".

Browser single sign-on: when `openconnect --help` lists `--external-browser` (openconnect 9 and later; asked once per program), MorphGate writes a small 0700 script in the private directory that runs the helper with the page in `MG_OC_URL`. openconnect starts it when the server offers external-browser SSO (AnyConnect's SAML); the app opens the page through the browser prompt and waits up to 10 minutes (`WEB_SIGN_IN_TIMEOUT`) while openconnect collects the result. Older openconnect versions get no browser option.

### Settings from openconnect

| Variable | Use |
| --- | --- |
| `INTERNAL_IP4_ADDRESS` + `INTERNAL_IP4_NETMASKLEN` or `_NETMASK`, `INTERNAL_IP6_NETMASK` or `INTERNAL_IP6_ADDRESS` | This device's addresses ("openconnect connected, but the server assigned no address" without one) |
| `INTERNAL_IP4_DNS`, `INTERNAL_IP6_DNS` | DNS servers |
| `CISCO_DEF_DOMAIN` | Search domains |
| `CISCO_SPLIT_INC`, `CISCO_IPV6_SPLIT_INC` (`_n_ADDR`, `_MASKLEN`, `_MASK`) | Announced networks; none means everything goes through the VPN |
| `INTERNAL_IP4_MTU`, `INTERNAL_IP6_MTU` | MTU, default 1300 |
| `VPNGATEWAY` | Shown with the server |

Keepalives, dead-peer detection and reconnects are openconnect's own. The tunnel goes down when the program exits.

| Error | When |
| --- | --- |
| "openconnect is not installed; install it with `brew install openconnect`" / "…from your distribution (e.g. `sudo dnf install openconnect` or `sudo apt install openconnect`)" | Program not found |
| "openconnect: *its last error lines*" (sign-in failure when they say "login failed" or "authentication failed"), or "openconnect exited (*status*)" | The program gave up |
| "openconnect didn't connect within 90s (last message: …)" | `CONNECT_TIMEOUT`, which restarts after every answered prompt |

## Tests

| Where | Covers | Run |
| --- | --- | --- |
| `wireguard/config.rs`, `wireguard/mod.rs` | Parsing, public keys, longest-prefix routing; in-process tunnels: echo, bulk, streams, AllowedIPs, wrong key, two gateways, a silent peer, a gateway dialing in, forged handshakes, source checks | `cargo test -p mg-vpn` |
| `openvpn/*.rs` unit tests | Tokenizer, profiles and refusals, file embedding, static keys, protected keys and bundles, passphrase prompts, wire format and tls-auth/tls-crypt/tls-crypt-v2, every data cipher and replays, the TLS 1.0 PRF, LZO and LZ4, push replies, web sign-in and `AUTH_PENDING` | `cargo test -p mg-vpn` |
| `openvpn/live_tests.rs` | A real `openvpn` 2.6 server per test (own subnet `10.8.N.0/24`, own port): UDP tls-auth with a certificate; TCP tls-crypt with a password and ChaCha20; static challenge; CBC with the legacy PRF; LZO with net30; renegotiation with auth-token and keepalive; a wrong CA; tls-crypt-v2 over UDP and TCP; PKCS#12 and an encrypted key; web sign-in with deferred auth | The server needs a TUN device, so run inside a throwaway user and network namespace (no real root): `cargo test -p mg-vpn --no-run`, then `unshare -Urn sh -c 'ip link set lo up && MG_OVPN_LIVE=1 cargo test --offline -p mg-vpn openvpn::live -- --ignored'`. They are ignored by default and return early without `MG_OVPN_LIVE` |
| `openconnect/tests.rs` | The real `openconnect` against an in-process AnyConnect server (XML auth, CSTP over TLS) whose far end is another in-app stack with an echo service: a pinned certificate and saved password; trusting a certificate, a password and a one-time code; a wrong saved password and cancel; an unreachable server; browser SSO; the browser script; the command line | `cargo test -p mg-vpn`. openconnect runs the test binary itself as its tun script (`tun_helper_entry`); `MG_OC_HELPER=/path/to/morphgate-desktop` tests the app binary's helper mode instead. Tests that need the program skip without it |
| `ssh_session_over_wireguard`, `ssh_session_over_openconnect`, `ssh_session_over_openvpn` | A real `mg-ssh` session through each tunnel to a real sshd | Ignored by default; set `MG_TEST_SSH`, `MG_TEST_KEY` (and `MG_TEST_USER`, default `mg`) as in the header of `crates/mg-ssh/tests/live.rs`, then `--include-ignored`. The OpenVPN one also needs the namespace and `MG_OVPN_LIVE`; `MG_TEST_SSH` may be `unix:/path` to reach an sshd outside it |

CI (`.github/workflows/ci.yml`) installs `openconnect` and `openvpn`, runs the WireGuard and openconnect SSH tests against its sshd, and the OpenVPN live tests under `sudo unshare -n`.

## Limits

- WireGuard: search domains in `DNS` are dropped; endpoints are resolved once per tunnel.
- OpenVPN: no TAP, static-key mode, proxies, `fragment`, hardware tokens or OS certificate stores, or TLS below 1.2 (refused as above). CRLs (`crl-verify`) are not checked. MorphGate never starts a renegotiation, relying on the server's.
- openconnect: Linux and macOS only. Its Windows build can't run a `--script-tun` script, and its other way out, a TAP or Wintun adapter, needs a driver and admin rights ([Per-host VPN](vpn.md#platforms)).
