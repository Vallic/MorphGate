# Importing

People arrive with hosts in another SSH client. The desktop app reads four sources (OpenSSH's configuration, PuTTY's saved sessions, a CSV file, a Royal TS document), turns each into a plan of hosts, the key files they sign in with, their jump hosts and groups, shows it, and imports the hosts the person ticks, with the jump hosts they need. Keys are copied into the vault, so they work on every device the vault syncs to. Nothing is written to the source. Snippets come in from a CSV file the same way, on phones too. Code: `apps/desktop/src-tauri/src/host_import/mod.rs` (`import_preview`, `import_hosts`, `apply()`), `ssh_config.rs`, `putty.rs`, `csv.rs`, `royal.rs`, `crates/mg-ssh/src/ssh_config.rs` (`SshConfig`), `apps/desktop/src/ImportHosts.tsx`; `apps/desktop/src-tauri/src/snippet_import.rs`, `apps/desktop/src/ImportSnippets.tsx`.

## The page

The Hosts page's **Add from…** → **Import…** (desktop only) opens "Import hosts", which reads `~/.ssh/config` straight away.

| Control | Does |
| --- | --- |
| **OpenSSH**, **PuTTY**, **CSV**, **Royal TS** | The source; the lead text says what each brings |
| Path field (**Configuration file**, **A .reg file or PuTTY's sessions folder (empty: the sessions saved here)**, **CSV file**, **Royal TS document**) and **Read** | Reads a path on this device (`~` expanded). **Read** stays disabled for CSV and Royal TS until a path is typed |
| **Choose…** (not for OpenSSH) | Picks a file in the webview; its bytes go to Rust as base64 (`ImportSource.data`, `name`). Accepts `.reg`; `.csv`, `.tsv`, `.txt`; `.rtsz`, `.rtsx`, `.xml` |
| Warnings | What the source has that is skipped ("Match blocks are skipped: their settings aren't imported.") |
| A host row | Checkbox, label, how it signs in ("key id_work", "1Password agent, one key", "saved password"), "group …", "forwards the agent", "in the vault"; `user@host:port` and "via bastion → inner"; "Connects by running on this computer: …"; "Tags: …"; "Not imported: …" |
| **All**, **None** | Tick every host or none. Hosts the vault already has start unticked |
| **Keys** | The key files of the ticked hosts: "Copied into the vault (SHA256:…).", "The vault has this key: the hosts use that one.", "Encrypted: give its passphrase to copy it into the vault, or leave it empty for its hosts to use the SSH agent.", "Can't be read: …"; a **Passphrase** field for encrypted ones; "With its certificate: signs in as deploy, ops; …" |
| **Vault**, **Import 3 hosts** | Where the items go (default personal), then the import. The result line is "Imported 2 hosts and 1 key." (groups and certificates added when there are any), followed by the notes, and the source is read again |

| Command | Does |
| --- | --- |
| `import_preview(source)` | `ImportPreview {source, hosts, keys, warnings}`: what the source holds and how each host would sign in |
| `import_hosts(input)` | Reads the same source again and imports `input.ids`, the jump hosts they need, their keys and groups, into `input.vault_id`, with `input.passphrases` (by path as the preview showed it). Returns `ImportResult {hosts, keys, groups, certificates, notes}` |

## What every source shares

| Rule | Detail |
| --- | --- |
| Order | Keys first, then each host after its jump host (`Plan::ordered()`). A jump that loops is dropped: "app: its jump hosts go round in a loop; imported without one" |
| Jump hosts | Those the ticked hosts go through come along, ticked or not (`Plan::needed()`) |
| Hosts the vault has | Same host name (any case), port and user in the target vault: not created; the existing host is used, as a jump host too. The preview's "in the vault" looks at every vault on the device, the import only at the target |
| Keys the vault has | Same fingerprint in the target vault: that key is used. It gets the source's certificate if it has none, or the new one lasts longer |
| New keys | Labelled with the file's name. OpenSSH and PEM keys are kept as they are (an encrypted one with its passphrase beside it); PuTTY `.ppk` keys are converted to unencrypted OpenSSH keys (`mg_ssh::keys::for_vault()`), which the vault encrypts like generated ones |
| Certificates | The one that certifies the key among the host's certificate files (OpenSSH's `CertificateFile`, PuTTY's and Royal TS's detached certificate), or `<key>-cert.pub` beside the key, where ssh looks |
| A key that can't come | Unreadable, not a private key, or encrypted with no passphrase: its hosts use the system's SSH agent where there is one (always on Windows, elsewhere when `SSH_AUTH_SOCK` is set), else ask for a password. Noted: "~/.ssh/id_work: encrypted, and no passphrase given (its hosts use the SSH agent)" |
| Groups | Found by name (any case) in the target vault, or made with no defaults |
| What isn't imported | Listed per host in the preview, and added to the host's notes: "From PuTTY, not imported: X11 forwarding" (origins: `~/.ssh/config`, `PuTTY`, `the CSV file`, `Royal TS`) |
| Proxy commands | Only OpenSSH brings them. Imported from this device's own configuration and shown first, they are allowed on this device (`proxy::allow()`); other devices ask ([SSH connections](ssh-connections.md)) |
| New hosts | No VPN, theme or identity; recording and session keeping off |
| Text | UTF-8 with or without a byte order mark, or UTF-16 with one (Windows' `reg export`, some spreadsheets) |
| Addresses | `host`, `user@host`, `host:port`, `[v6]:port` and bare IPv6 are understood (`split_address()`) |

## OpenSSH

`SshConfig` reads the configuration the way `ssh` resolves it: the first value of a keyword wins, `Host` patterns take `*`, `?` and `!`, `Include` reads other files in place (globs; relative paths under `~/.ssh`; up to `MAX_DEPTH`, 16, deep), and `IdentityFile` adds up. Each `Host` line's first concrete pattern is a host; lines of only wildcards are defaults. `Match` blocks can't be evaluated and are skipped (`Match all` is read as `Host *`).

| `ssh_config` | Host |
| --- | --- |
| The alias | Label |
| `HostName` (`%h` expanded) | Host name; the alias without one |
| `Port`, `User` | Port (22), user (the local user, `USER` or `USERNAME`, without one) |
| `IdentityFile` (`~`, `%d %u %h %r %p %n`) | The first file that exists signs in. A public key there means the key lives in an agent: that agent, offering only that key. With none, `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`; then the agent; then a password |
| `IdentityAgent` | Which agent: 1Password's, Bitwarden's and Secretive's sockets by name (so the host works on each device that runs them), another socket as a custom one; `none`: no agent |
| `CertificateFile` | The key's certificate |
| `ProxyJump` | Jump hosts. A hop that is another alias (no user or port) is that alias's host, with its own jumps; `ops@inner:2222` is a host of its own, going through the hop before it in the chain |
| `ProxyCommand` (unless `ProxyJump` is set, or `none`) | Proxy command |
| `ForwardAgent` (other than `no`) | Agent forwarding |
| `LocalForward`, `RemoteForward`, `DynamicForward`, `RemoteCommand` | Not imported |

Warnings: "Match blocks are skipped: their settings aren't imported.", "Include nests too deep: stopped there.", "Include {file}: {error}".

## PuTTY

The sessions come from the registry on Windows (`reg export HKCU\Software\SimonTatham\PuTTY\Sessions` into a temporary file, removed afterwards), from `$XDG_CONFIG_HOME/putty/sessions` (default `~/.config/putty/sessions`) or `~/.putty/sessions` elsewhere, from a `.reg` file exported on Windows (typed or chosen), or from a sessions folder typed as the path. Names lose PuTTY's `%XX` escapes.

| Session value | Host |
| --- | --- |
| Session name | Label |
| `HostName` | Host name; a user and port written in it count where `UserName` and `PortNumber` are empty |
| `PortNumber`, `UserName` | Port (22), user (the local user) |
| `PublicKeyFile` | The key (`.ppk`, converted) |
| No key | Pageant where it runs (Windows) and `TryAgent` isn't 0, else a password asked for |
| `AgentFwd` = 1 | Agent forwarding |
| `ProxyMethod` 6 (SSH proxy), `ProxyHost`, `ProxyPort`, `ProxyUsername` | Jump host: the saved session of that name, else a host of its own |
| `DetachedCertificate` | The key's certificate |
| Other proxy methods (SOCKS 4 and 5, HTTP, Telnet, a local command), `PortForwardings`, `X11Forward`, `RemoteCommand` | Not imported |

"Default Settings" and sessions without a host name are skipped. Other protocols are listed: "Not SSH, so not imported: router (Telnet)." PuTTY saves no passwords. Errors: "{name} has no PuTTY sessions", "PuTTY has no saved sessions here (~/.putty/sessions); choose a .reg file exported from PuTTY on Windows", "PuTTY has no saved sessions on this computer" (Windows).

## CSV

Termius' import template (`Groups,Label,Tags,Hostname/IP,Protocol,Port,Username,Password`) and other managers' exports. Columns are found by their header in any order, compared as lowercase letters and digits (`Hostname/IP`, `hostname_ip` and a spreadsheet's byte order mark all match). The separator is whichever of comma, semicolon or tab the first line has most of; quoted values may hold separators, doubled quotes and line breaks (`csv::parse()`, which the snippet import shares).

| Value | Headers | Becomes |
| --- | --- | --- |
| Host (required) | Hostname/IP, Hostname, Host, Address, IP address, IP, URI, Server, Computer name | Host name (with user and port if written in it) |
| Label | Label, Name, Alias, Title, Display name | Label; the host name without one |
| Group | Groups, Group, Folder, Path | Group |
| Tags | Tags, Tag | Tags, split on `,` and `;` |
| Port | Port | Port; not a number: 22, and "Not a port, so 22 instead: web (22a)." |
| User | Username, User, Login, Credential username | User (the local user without one) |
| Key | Identity file, SSH key, Private key, Private key path, Key file, Key | A key file path; wins over a password |
| Passphrase | Key passphrase, Passphrase | The key's passphrase (nothing to ask) |
| Password | Password, Credential password | A saved password |
| Protocol | Protocol, Connection type, Type | Empty or `ssh…` imported; `mosh` imported as SSH and noted; others listed as "Not SSH, so not imported" |
| Notes | Notes, Description, Comment, Comments | Notes |
| Proxy | Proxy host | Not imported |

Rows without a host are skipped; hosts are picked by line ("line 4"). Errors: "{name} is empty", "the file has no column for the host (a header like Hostname/IP, Hostname, Host or Address)".

## Royal TS

Royal TS and Royal TSX documents (`.rtsz`, the older `.rtsx`): XML, as saved or compressed (gzip, or zip with the document as its first `.xml` entry). An element named `Royal…` with child elements is an object, and the children are its properties as Royal's scripting reference names them.

| Royal TS | Host |
| --- | --- |
| `RoyalSSHConnection`, or `RoyalTerminalConnection` whose `ConnectionType` is SSH (templates skipped) | A host |
| `Name` | Label (the host name without one) |
| `URI` (`ssh://` stripped), `Port` | Host name, port |
| `CredentialMode`: 1 the folder's (inherited upwards), 2 given here (`CredentialUsername`, `CredentialKeyFile`), 3 a `RoyalCredential` by `CredentialId`, 4 by `CredentialName` (its `UserName`, `PrivateKeyPath`) | User and key; a key mode of 1 leaves the key out |
| `PrivateKeyPath` on the connection | The key, over the credential's |
| The `RoyalFolder`s it is in (`ParentID`, else the element around it) | One group, "Production / Web"; the document's top "Connections" folder is left out |
| `Description` | Notes |
| `SSHAllowAgentForwarding` | Agent forwarding |
| `SSHDetachedCertificate` | The key's certificate |
| `ProxyMode`, `SSHEnableX11Forwarding` | Not imported |

Passwords stay behind: the document keeps them encrypted, and the preview says "Passwords stay in Royal TS, which keeps them encrypted: 2 hosts ask for theirs when they connect." Other connections are counted: "Not SSH, so not imported: RDS (3)." Errors: "{name} can't be read: it isn't a Royal TS document, or the whole document is encrypted (Royal TS can save it without that)", "{name} isn't a Royal TS document: {error}", "the document can't be unpacked: {error}".

## Snippets from a CSV file

The Snippets page's **Import…** (on phones, "Import from a CSV file…" under the list) opens "Import snippets": a **CSV file** picker (any file on Android, whose picker names CSV files more than one way), "Download an example" (`snippets_csv_example` saves `morphgate-snippets-example.csv` in Downloads: a command with a comma, one with quotes, one of several lines, a row without tags), then the snippets with checkboxes ("3 lines", "in the vault", the first line, "Tags: …"), **All** / **None**, **Vault** and **Import 5 snippets**.

| Column | Headers |
| --- | --- |
| Name | Name, Label, Title, Snippet name. Without one, the command's first line, cut at `NAME_CHARS` (40) with "…" |
| Command (required) | Command, Commands, Body, Script, Content, Snippet, Cmd. Line ends become `\n` (a Windows `\r\n` would send two); trailing blanks and leading empty lines go |
| Tags | Tags, Tag, Labels, split on `,` and `;` |

`snippets_read_csv(name, text)` only reads (the page reads the file's text); the page saves each ticked snippet with `snippet_save`. One named like a snippet the target vault has starts unticked and, ticked, replaces it: "Imported 5 snippets (1 replaced one the vault had)." Rows without a command are left out and said: "Line 3 has no command, so it's left out.", "Lines 2, 5 and 9 have no command, so they're left out." (past five, "… and 3 more"). Errors: "{name} is empty", "{name} has no Command column: its first line names the columns (Name, Command, Tags)".

## Tests

- `apps/desktop/src-tauri/src/host_import/`: `ssh_config.rs` (jump hosts in order, a proxy command, loops, identity files picking the sign-in, named agents), `putty.rs` (a `.reg` export, sessions to hosts, Pageant, the Linux folder), `csv.rs` (Termius' template, other exports and separators, quoted line breaks), `royal.rs` (connections to hosts, compressed documents and nested objects), `mod.rs` (ordering and loops, addresses, certificates, encodings). `snippet_import.rs` covers the example, headers in any order, names from the first line, empty rows and a missing column. `cargo test -p morphgate-desktop host_import`, `cargo test -p morphgate-desktop snippet_import`.
- `crates/mg-ssh/src/ssh_config.rs`: first value wins, tokens, includes, `Match` blocks, unsupported keywords, jump specs (`cargo test -p mg-ssh ssh_config`).
- e2e `apps/desktop/e2e/appimage.mjs`: imports two hosts and their key from a `~/.ssh/config` (the `Match` warning, a `LocalForward` not imported, the key copied) and connects through the jump host; imports a PuTTY session with a `.ppk` key (a Telnet one isn't imported), a Termius-style CSV with a group and a Royal TS document, and signs in with the PuTTY key. `mobile.mjs` imports the example snippets on the phone screens.

## Limits

- Host imports are desktop only (the button is hidden on phones and tablets).
- Not imported from any source: port forwards, remote commands, X11 forwarding, proxies other than SSH jump hosts and OpenSSH's `ProxyCommand`, Mosh; OpenSSH's `Match` blocks; Royal TS passwords. A CSV can't describe jump hosts.
- An import never changes a host the vault has: one with the same address, port and user is left as it is.
