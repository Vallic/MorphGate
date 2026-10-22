# SSH keys and agents

A host signs in with a key from the vault or with a key held by an SSH agent. Vault keys are `ssh_key` items: generated in the app or imported, encrypted with the vault's key, synced, and used from memory, never written out as key files. A key can carry an OpenSSH user certificate, presented first, and a command that renews a short-lived certificate before it runs out. Agent keys never enter the vault: a host names the agent (1Password, Bitwarden, Secretive, Pageant, the system's, or a socket) and maybe one key's fingerprint, so the same item works on every device that runs that agent. Code: `crates/mg-ssh/src/keys.rs` (import, generation, certificates), `crates/mg-ssh/src/agent.rs` (`AgentSource`, `AgentKey`), `crates/mg-ssh/src/connection.rs` (`Auth`, signing in, agent forwarding), `crates/mg-ssh/src/authorized_keys.rs`, `apps/desktop/src-tauri/src/vault.rs` (key commands, `KeyView`), `apps/desktop/src-tauri/src/renew.rs`, `apps/desktop/src-tauri/src/agents.rs`, `apps/desktop/src/KeyPanel.tsx`, `apps/desktop/src/AgentField.tsx`, `apps/desktop/src/Lists.tsx` (`KeysPage`).

How a connection uses them, and host keys, are in [SSH connections](ssh-connections.md).

## The Keys page

**Keys** in the sidebar (the count is keys plus identities) opens a page: "SSH keys stay in the vault, encrypted, and are used from there: they are never written to disk." Its tabs are **Keys**, **Identities** ([Hosts, groups and identities](hosts-groups-identities.md)) and **Host CAs** ([SSH connections](ssh-connections.md#host-cas)). Each key shows its label, type, a **passphrase** badge when one is saved, its vault, its fingerprint, "N hosts, M identities" or "Not used yet", and its certificate's state; its name (or **Open** on the row) opens it. **New key** is at the top while the Keys tab is open.

### New SSH key (`NewKey`)

| Control | Does |
| --- | --- |
| **Vault** | Where the key goes (personal by default). A host can only use keys from its own vault |
| **Generate** / **Import** | Make a new key, or bring one in |
| **Label** | Default "MorphGate key" when generating; when importing, the file's name, else "Imported key" |
| **From file** / **Paste** | Import: a file picker ("Private key file (id_ed25519, a .pem or PuTTY's .ppk)", up to 1 MB, read in the webview so it works on phones) or a **Private key** text area |
| **Passphrase (only if the key is encrypted)** | Checked on import |
| **Cancel**, **Generate key** / **Import key** | Saves the item and opens it |

### A key (`KeyDetail`)

| Part | Shows |
| --- | --- |
| **Type**, **Fingerprint**, **Passphrase** ("Saved in the vault", only when the stored key is encrypted) | Facts |
| **Public key — add it to ~/.ssh/authorized_keys on your servers** | The `authorized_keys` line, selected on focus |
| **Certificate** | See [Certificates](#certificates) |
| **Delete** → **Really delete?**, **Close**, **Copy public key** | **Delete** and the certificate buttons are hidden in a vault you can only view. A key still in use can't be deleted: "key \"{label}\" is still used by: {hosts, identities, cloud sources}" |

## Importing and generating

`key_import` hands the text to `keys::for_vault()`:

| Input | Stored |
| --- | --- |
| OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), plain or encrypted | As given. If it is encrypted, the passphrase is saved beside it |
| PEM: PKCS#1 RSA, PKCS#8 (`BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`), legacy encrypted RSA PEM (AES-128-CBC) | As given, the same way |
| PuTTY `.ppk`, versions 2 and 3 (`PuTTY-User-Key-File-…`) | Converted to an unencrypted OpenSSH key; the passphrase is not kept, since the vault encrypts the key at rest |

Key types are those `russh` reads with its default features: Ed25519, ECDSA (P-256, P-384, P-521) and RSA. A passphrase is kept only when the stored key needs it (`KeyInfo.encrypted`). An encrypted PuTTY key without a passphrase is caught before `russh`, which would only say "encrypted".

`key_generate` makes an Ed25519 key from 32 bytes of `getrandom`, with the label as its comment, as an unencrypted OpenSSH key.

Quick connect takes a key the same two ways (**From file**, **Paste**) but keeps it out of the vault: it signs in from memory for that one connection. **Save to vault (with the key)** imports it with `key_import` first ([SSH connections](ssh-connections.md#quick-connect)).

### The `ssh_key` item

| Field | Holds |
| --- | --- |
| `label` | The name shown in lists |
| `private_key` | OpenSSH or PEM text, exactly as stored (may be encrypted) |
| `passphrase` | Only when `private_key` needs it |
| `public_key`, `algorithm`, `fingerprint` | The `authorized_keys` line, the type (`ssh-ed25519`, …), the `SHA256:` fingerprint |
| `certificate` | An OpenSSH user certificate line; apps that predate it sign in with the key alone |
| `renew` | `{command, file?}`, see [Renewal by command](#renewal-by-command) |

Views sent to the webview (`KeyView`) leave out the private key and passphrase.

## Tauri commands

| Command | Does |
| --- | --- |
| `keys_list` | Every vault's keys, by label, with certificate details or `certificateError`, `renew`, `renewAllowed` |
| `key_generate(label, vaultId?)` | New Ed25519 key |
| `key_import(input)` | `{label, vaultId?, source: {kind: "text", text} \| {kind: "file", path}, passphrase?}` |
| `key_certificate(id, source)` | Sets the certificate from text or a file, or removes it (`source` null) |
| `key_renewal(id, renewal)` | Sets `{command, file?}` or clears it (null); a command typed here is allowed on this device |
| `key_allow_renewal(id)` | Allows the key's renewal command on this device |
| `key_renew(id)` | Renews now |
| `key_delete(id)` | Deletes, unless still used |
| `agents_list(path?)` | The agents this device can have, each with where it listens, whether it answered, its keys, and why not (`custom` uses `path`) |

## Certificates

A key's certificate (`key_certificate`) is checked by `keys::certificate()`: the first non-comment line must be an OpenSSH certificate, a user certificate ("a host certificate, not one for signing in"), for this key ("the certificate is for another key (SHA256:…)"). When signing in it goes first, then the key alone ([SSH connections](ssh-connections.md#signing-in)). Validity is not checked before presenting it; the server decides.

| Control | Shows or does |
| --- | --- |
| **Validity** | "Valid until {date}", "Never expires", "Expires in N hours ({date})" under a day (warning), "Valid from {date}" (warning), "Expired {date}: get a new one from its CA" (error) |
| **Signs in as** | The principals, or "Any user the server allows" |
| **Issued by**, **Key ID** | The CA's fingerprint, the certificate's ID |
| **Add certificate** / **Replace certificate**, **Remove certificate** | **From file** ("Certificate file (id_ed25519-cert.pub, say)") or **Paste** (**Certificate**), then **Save certificate** |

A stored certificate that no longer reads shows "The certificate stored with this key can't be used: {why}."

### Renewal by command

`renew` (the **Renewal** part of the certificate section) runs a command on this device that is given the public key and returns a fresh certificate: `vault write -field=signed_key ssh/sign/<role> public_key=-`, `step ssh certificate --sign …`, `ssh-keygen -s …`.

| Control | Does |
| --- | --- |
| **Renew with a command…** / **Change renewal** | Opens the form |
| **Renew with a command** | The command. Placeholder `vault write -field=signed_key ssh/sign/deploy public_key=-` |
| **Certificate file (optional)** | Where the command leaves the certificate if it doesn't print it (`~` is the home folder) |
| **Save renewal** / **Don't renew** (empty command), **Cancel** | Saves the renewal, or removes it |
| **Allow on this device** | Shown with "This command came with the vault. It runs on this computer only once you allow it here, after reading it." |
| **Renew now** | Once allowed; says "Renewed." |

`renew::run()`:

1. Makes a folder `morphgate-renew-<ULID>` in the system's temp folder (mode 0700 on Unix), writes `key.pub` in it, and removes the folder afterwards.
2. Runs the command through `sh -c` (Unix) or `cmd /D /S /C` (Windows, no console window), with `%k` replaced by the quoted path of `key.pub` and `%%` by `%`, and the public key on stdin.
3. Waits up to 180 s (`TIMEOUT`), since the command may sign in through a browser first. A non-zero exit fails with its stderr.
4. Takes the certificate from the first stdout line containing `-cert-v01@openssh.com`, else `key-cert.pub` beside the key file (what `ssh-keygen -s` writes), else the configured file. It must pass `keys::certificate()`, and is saved to the item, so it syncs.

Before a connection, SFTP session or tunnel to a saved host, `before_connect` renews the certificate of each key on the route (jump hosts included) whose certificate is missing or runs out within 300 s (`SOON`). A renewal that fails while the current certificate is still valid is ignored, and the old one is used. Otherwise the connection stops with "renewing the certificate of key \"{label}\": {why}".

The command comes with the vault, so it runs only where this device allowed it, by its exact text, on the same list as proxy commands (`proxy.rs`, see [SSH connections](ssh-connections.md#the-per-device-allow-list)). A command saved here (new or changed) is allowed by saving it.

## SSH agents

### Which agent, and where it listens

`HostAuth::Agent { agent, path, key }` names the agent, never its location. `agents::source()` finds it on this device:

| `agent` | Name in the UI | Linux | macOS | Windows |
| --- | --- | --- | --- | --- |
| none (`system`) | System agent | `$SSH_AUTH_SOCK` | `$SSH_AUTH_SOCK` | OpenSSH's pipe `\\.\pipe\openssh-ssh-agent` |
| `1password` | 1Password | `~/.1password/agent.sock` | `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` | OpenSSH's pipe, which 1Password takes over |
| `bitwarden` | Bitwarden | The first that exists of `~/.bitwarden-ssh-agent.sock`, the Flatpak's `~/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock`, the Snap's `~/snap/bitwarden/current/.bitwarden-ssh-agent.sock` | Same | OpenSSH's pipe |
| `secretive` | Secretive | Not offered | `~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh` | Not offered |
| `pageant` | Pageant | Not offered | Not offered | PuTTY's Pageant |
| `custom` | Other socket or pipe | `path`, a Unix socket | `path` | `path`, a named pipe `\\.\pipe\…` |

KeePassXC, gpg-agent and OpenSSH's own agent are reached as the system agent. `key`, when set, is a `SHA256:` fingerprint: only that key is offered, as OpenSSH's `IdentitiesOnly`, because servers stop after a few failed keys. `path` is kept only for `custom`, and is the one device-specific value. An app that predates these fields reads the item as the system agent. Identities use the same `HostAuth`.

### Choosing the agent (`AgentField`)

In the host or identity editor, with **SSH agent**:

| Control | Does |
| --- | --- |
| **Agent** | The agents this device can have, each with "· N keys" or "· not running here"; an agent the item names that this platform lacks shows as "{name} (not on this device)" |
| **Socket or pipe**, **Look** | For **Other socket or pipe**: the path, and a fresh look at that agent |
| **Key** | **Any key it holds**, or one of its keys ("{comment} ({type}, certificate)"); a saved key the agent doesn't hold now shows "(not held here now)" |
| Hint | "{where}. Only this key is offered: the keys stay in the agent." or "Every key it holds is offered, in turn…"; for an agent that didn't answer, "Not running here: {why}. Hosts can still name it; it signs in on devices where it runs."; for a security key, "A security key: MorphGate asks you to touch it when it signs in." |

Lists describe the choice with `agentDescription()`: "SSH agent", "1Password agent", "SSH agent (own socket)", with ", one key". The **SSH agent** choice is hidden on phones unless the item already has it. Quick connect always uses the system agent with every key.

### Signing in through an agent

`connection.rs` `agent()` asks the agent for its identities, keeps the one with the saved fingerprint if there is one, and puts certificates first (what `step ssh login` and `tsh login` add beside a key), since a server that only trusts its CA takes no key alone. It then tries each in turn. Before an `sk-` key signs, the `security-key` event shows "Touch your security key to sign in to {host} ({comment})" until it has signed.

### Agent forwarding

`Host.forward_agent` (**Forward the SSH agent**, off unless set) lets programs on the host sign with the agent's keys while the session is open, as OpenSSH's `ForwardAgent`. A host whose cloud forwards nothing (`source.no_forwarding`, Vallic Cloud's) isn't offered the switch, and connecting doesn't forward the agent to it. The editor warns: "While you're connected, programs on this host can use your agent's keys to sign in elsewhere as you (git, other servers), and so can anyone with root there. Only for hosts you trust."

| Detail | Behavior |
| --- | --- |
| Which agent | The one the host signs in with, if it uses an agent; otherwise the system agent |
| Where | Terminal sessions only (`ssh_connect`), to the target only, not jump hosts, SFTP or tunnels |
| Guard | `Verifier::server_channel_open_agent_forward` refuses the server's agent channels unless forwarding was asked for on this connection, and then connects them only to the chosen agent |
| Phones | The checkbox is hidden unless already on |

## Public keys on servers

The app does not install a key on a single server: **Copy public key** and add it to `authorized_keys` yourself. `authorized_keys.rs` edits `~/.ssh/authorized_keys` over SFTP for team work: it finds keys by key material (behind options, whatever the comment), adds a line once, removes lines, keeps every other byte, and replaces the file atomically with its mode (a new file gets 0600 in a 0700 `.ssh`). It is used by:

| Command | Does |
| --- | --- |
| `offboard_scan`, `offboard_clean` | Find and remove a departing member's published keys on the organization's hosts |
| `key_replace(keyId)` | Replaces a shared key: generates a new Ed25519 key, installs it beside the old one on every host in the vault that uses the key and logs in with it, switches the item (same id, certificate dropped, renewal kept), then removes the old key. If any host fails first, it takes the new key off again: "nothing was changed; the new key couldn't be set up on every host. …" |

See [Teams](teams.md) for offboarding and the member key directory. `cloud_add_key` puts a key's public half on the signed-in Vallic Cloud account ([Cloud sources](cloud-sources.md)).

## Errors

| Text | Cause |
| --- | --- |
| "private key is encrypted; a passphrase is required" | Encrypted key, no passphrase |
| "could not load private key: {why}", "… (wrong passphrase?)" | Not a key `russh` reads, or the passphrase is wrong. Certificate problems also carry this prefix: "could not load private key: the certificate is for another key (…)" |
| "ssh agent: no agent is running here (SSH_AUTH_SOCK isn't set)" | System agent on Unix without the variable |
| "ssh agent: {socket}: {OS error}" | The socket or pipe isn't there |
| "ssh agent: the agent holds no keys" / "ssh agent: the agent doesn't hold the key {fingerprint} (unlock it, or add it to the agent)" | Nothing to offer |
| "ssh agent: Pageant runs on Windows only", "{label}: Secretive runs on macOS only" | Wrong platform |
| "{label}: no socket or pipe set for this host's agent", "{label}: this host's agent ({id}) is one this version of MorphGate doesn't know" | The host's agent setting (`{label}` is the host's) |
| "renewing the certificate of key \"{label}\": {why}" | Why: "this device hasn't allowed its renewal command: {command}. Open the key to allow it.", "renewing it runs a command on the computer: renew it from the desktop app", "it took longer than 180 s", the command's stderr or "it failed ({status})", "it gave no certificate: print it, or say which file it's left in", "the certificate it gave: …" |

## Tests

| Where | Covers |
| --- | --- |
| `crates/mg-ssh/src/keys.rs` | Generated keys round-trip and differ; fingerprints; an encrypted key needs the right passphrase; PuTTY v2 and v3 keys become OpenSSH keys; OpenSSH keys stay as given; user certificates read; certificates for another key or a host refused |
| `crates/mg-ssh/src/agent.rs` | Lists a real `ssh-agent`'s keys (skipped without OpenSSH); a missing socket says where |
| `crates/mg-ssh/src/authorized_keys.rs` | Finds keys behind options and comments; removes only those lines; adds once |
| `apps/desktop/src-tauri/src/agents.rs`, `renew.rs` | Agent names resolve per platform; `%k`; a due certificate renewed before connecting only once allowed, and not again while good; certificates printed, left beside the key, or a failure that says why |
| `crates/mg-ssh/tests/live.rs` | `key_file_auth`; `agent_sign_in_and_forwarding` (one key picked, forwarding seen by `ssh-add -l` on the server, a key the agent lacks); `authorized_keys_are_replaced_atomically` |
| `apps/desktop/e2e/appimage.mjs` | A PuTTY key imported and used; a key with only a certificate from the run's user CA signs in, from the vault and from an agent; renewal by `ssh-keygen -s`; an agent on its own socket with one key, forwarded |
| `apps/desktop/e2e/teams.mjs`, `mobile.mjs` | A published key found and removed, a shared key replaced; a key imported on the phone screens |

The unit tests that need `ssh-keygen` or `ssh-agent` return early where they aren't installed. How to run the live tests: [SSH connections](ssh-connections.md#tests).

## Not built

- Only Ed25519 keys are generated. DSA keys can't be imported (`russh` is built without its `dsa` feature).
- Security keys (`sk-`) sign in through an agent; `mg-ssh` has no FIDO2 code of its own.
- No command installs a public key on one server (as `ssh-copy-id` does).
- Certificate renewal and agents are desktop only; agent forwarding covers terminal sessions only.

## Related

- [SSH connections](ssh-connections.md), [Hosts, groups and identities](hosts-groups-identities.md), [Teams](teams.md)
- [Vault cryptography](vault-crypto.md) for how items are encrypted
