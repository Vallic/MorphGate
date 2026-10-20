# Changelog

Each `## X.Y.Z` section becomes the notes of that release, on GitHub and in the app's update
prompt. Write them for users.

## 0.2.0

First release.

- Signing a device out from another one (Sync → Devices → Sign out) now clears it: the next time
  it connects, MorphGate removes its vaults, keys and settings there and goes back to its first
  screen, saying why. Signing in again brings everything back from the account. Disconnecting a
  device from itself asks whether to remove everything or keep a copy that no longer syncs.
- About → Open-source licenses lists the components each build includes, with their license
  texts.
- When you're no longer in a team (you left on another device, an admin removed you, or it was
  deleted), your devices say so once as its vaults leave them. Moving a host into a team's vault
  says it is the team's from then on.
- Deleting your sync account on one device (or the website) turns sync off on the others the next
  time they connect: they keep your own vault, let go of team vaults, and say why.
- If a team seat was what kept your own vault syncing and you leave the team (or it ends), your
  vault keeps syncing for a grace period; Sync shows until when. A plan's grace period shows its
  end date too.
- SSH terminals with saved hosts, keys (generated or imported) and snippets; jump hosts; local,
  remote and SOCKS port forwarding.
- Import hosts from OpenSSH's configuration (Hosts → Import…): every `Host` in `~/.ssh/config`
  (and the files it includes) becomes a host, with the private keys its `IdentityFile`s name
  copied into the vault (or the vault's copy reused) and `ProxyJump` as its jump hosts. A
  preview shows what comes in, what the vault has already, and what `ssh` does that isn't
  imported (`ProxyCommand`, forwards, `Match` blocks). The file isn't changed. `IdentityAgent`
  picks the host's agent, a public key as `IdentityFile` the one agent key it offers, and
  `ForwardAgent` turns on forwarding.
- Import from other SSH clients too (Hosts → Import…): PuTTY's saved sessions (from the registry
  on Windows, `~/.putty/sessions` elsewhere, or a `.reg` file exported from PuTTY), a CSV file
  (Termius' import template, or another manager's export: columns are found by their headers)
  and Royal TS documents (`.rtsz`, `.rtsx`). Groups, tags and notes come along; a PuTTY SSH proxy
  or a Royal TS credential's user and key too. Royal TS keeps its passwords encrypted, so those
  hosts ask for theirs.
- Snippets from a CSV file (Snippets → Import…): a Name, a Command and Tags column, in any order;
  a command of several lines stays one. "Download an example" saves one to start from. A snippet
  the vault already has by that name starts unticked; ticked, the file's replaces it.
- Importing a key or a certificate takes the file from a "Choose file…" dialog instead of a typed
  path, so it works on phones too; so does a VPN's .conf or .ovpn (with the files it refers to,
  chosen together with it).
- Sync's device list shows each device as it is now: phones as Android or iOS with their model,
  and the version each one runs, updated as it syncs rather than only when it signed in.
- Android: the keyboard no longer covers the extra-key row and the bottom of the terminal (the
  page ends where the keyboard begins), and the extra keys leave the keyboard as it is instead of
  bringing it up.
- A snippet sent right after the Esc key runs as written: the shell no longer takes its first
  characters for the key Esc modifies (`[200~df -h~`).
- Vallic Cloud (Hosts → Vallic Cloud…): sign in with your Vallic account (a code you approve in
  the browser), and its environments become hosts, one per environment, machine and worker,
  grouped by project, signing in the way `vallic ssh` does. A refresh keeps them in step: what
  the platform decides follows it, your renames, keys, schemes, tags and notes stay, and a host
  it no longer lists is marked in red, not deleted. Choose the key its hosts use and add it to
  your Vallic account from the same page. Each device signs in itself; the hosts sync like any
  other. A Vallic Cloud session is a shell in your app's container, not root on a machine, with
  no SFTP or forwarding: these hosts offer no Files, tunnels or agent forwarding. Who gets in is
  decided by Vallic accounts, so offboarding and key replacement leave these hosts to the Vallic
  console and say so.
- AWS, Google Cloud, Azure, Hetzner Cloud and DigitalOcean (Hosts → Clouds…): their virtual
  machines as hosts, kept in step like Vallic Cloud's, listed with the provider's own CLI (`aws`,
  `gcloud`, `az`, `hcloud`, `doctl`) as this
  computer has it signed in: MorphGate keeps no cloud credentials. Choose the regions, projects
  or subscriptions, public addresses or private ones through a jump host, who to log in as where a
  machine doesn't say (Azure does; a `morphgate:user` tag or `morphgate-user` label does too),
  and a tag to group by. An EC2 key pair's name picks the vault's key of that name. A stopped
  machine keeps its last address and says it's stopped. Desktop only: phones have no CLIs.
  Machines without an address can be reached through AWS Session Manager, an EC2 Instance
  Connect Endpoint or Google's IAP: the source's choice, and MorphGate runs the CLI for each
  connection. The command is built on the device from the machine's ids (checked to be ids),
  never taken from the vault.
- Phones mark hosts they can't connect to as desktop only, and their sheet says why: ones that
  connect through a command on the computer (a proxy command, or a cloud's CLI for Session
  Manager, Instance Connect or IAP), or sign in with an SSH agent (phones have none).
- Saving a VPN closes its editor, back to the list that shows it.
- Select several hosts, groups, keys and identities, snippets, tunnels or VPNs on their page
  (Select) to delete them at once, put hosts in a group, or move them to another vault. A jump
  host goes with the hosts behind it; anything something else still uses is kept, and said why.
- A host can have a login command, run with a terminal instead of the login shell (as
  `ssh -t host <command>`), and be reached through its jump host by a command the jump host runs
  (`nc %h %p`, or a platform's own), for jump hosts that hand a connection on instead of
  forwarding it. Where that command refuses, the error shows what it said.
- A host can be reached by a command on this computer (Connect via → A command on this
  computer), as ssh's `ProxyCommand`: AWS Session Manager, EC2 Instance Connect Endpoints,
  Google's IAP tunnel, `nc` through a proxy. `~/.ssh/config` imports bring `ProxyCommand` along.
  A vault syncs and is shared, so a command runs only on devices that allowed it: one typed or
  imported on a device is allowed there; one that came with the vault waits for "Allow on this
  device" in the host's editor, which shows it first. Host names and users given to a command
  (`%h`, `%r`) must be plain words.
- A key's certificate can renew itself (the key's page → Certificate → Renew with a command…):
  a command run on this computer before connecting when the certificate is missing or runs out
  within 5 minutes, and on "Renew now". It gets the public key (on its input, or as a file: `%k`)
  and prints the certificate, or leaves it in a file: `vault write -field=signed_key
  ssh/sign/<role> public_key=-`, `step ssh certificate --sign`, `ssh-keygen -s`. Like a proxy
  command, one that came with the vault runs only once this device allowed it.
- Host CAs (Keys → New host CA): hosts whose keys a certificate authority signed are trusted
  without the first-connect prompt, instead of each key being pinned: what step-ca, HashiCorp
  Vault or Teleport issue, or `ssh-keygen -h -s`. Paste the CA's key (or an `@cert-authority`
  line) and the hosts it vouches for (`*.example.com`); in a team's vault it covers every member.
  `@cert-authority` lines in `~/.ssh/known_hosts` are trusted too. A certificate that doesn't
  hold up (another CA, another host, expired) is refused; the route bar says which CA vouched.
- OpenSSH certificates: a key can have a certificate from a certificate authority (step-ca,
  HashiCorp Vault, Teleport, or your own `ssh-keygen -s`), added from its `-cert.pub` file or
  pasted. Signing in presents it, so servers that trust the CA take the key without it being in
  `authorized_keys`. The key's page shows who it signs in as, the CA, and how long it's valid,
  with a warning in its last day and once it has expired. Certificates an SSH agent holds are
  presented too (`step ssh login`, `tsh login` put one there), and imports bring a key's
  certificate along (`CertificateFile`, `<key>-cert.pub`, PuTTY's and Royal TS's detached
  certificate).
- PuTTY keys (`.ppk`, versions 2 and 3, encrypted or not) can be imported (Keys, and with PuTTY
  sessions); the vault keeps them as OpenSSH keys.
- Keys in an SSH agent, per host or identity: the system's, 1Password, Bitwarden, Secretive
  (macOS), Pageant (Windows) or any socket or pipe. The editor shows which agents run here and
  the keys they hold; pick one key so only that one is offered. The vault keeps the agent's name
  and the key's fingerprint, never a path or a secret, so a team's identity can say "the deploy
  key in 1Password". Security keys (FIDO2, `sk-`) held by an agent ask for a touch.
  Windows signs in through OpenSSH's agent pipe (where 1Password and Bitwarden also listen).
- `morphgate://` links ("Open in MorphGate" on the website and in consoles) open an invite
  ready to join, Sync, Teams or a team's page, or quick connect filled in. A link never joins or
  connects by itself, and ignores passwords; links wait while the vault is locked. See
  docs/features/deep-links.md.
- Split panes: Split (above a session) opens this host again, or another, beside or below it in
  the same tab; drag the borders to resize, close a pane from its header. Broadcast sends what
  you type, and the snippets you run, to every pane of the tab at once, outlined while it's on.
- Agent forwarding, per host and off unless turned on: programs on the host can then use your
  agent's keys while you're connected, with a warning to keep it for hosts you trust. Servers
  can't open an agent channel otherwise.
- SFTP file browser with drag and drop.
- Per-host VPNs: WireGuard and OpenVPN built in, openconnect (AnyConnect, GlobalProtect and
  others) through the `openconnect` program.
- An end-to-end encrypted vault that syncs through MorphGate's hosted service or your own
  vault-sync server. Turning sync on, or signing in on a new device, starts on morphgate.com;
  "Your own server" takes any address. It syncs every minute while you use the app, every 5
  minutes while you don't, and at once when you come back.
- A master password needs at least 10 characters and must not be easy to guess: the form says
  why one is refused ("This is similar to a commonly used password."). A few unrelated words
  make a strong one; no rule asks for a digit or a symbol.
- Unlock with the system keychain, optionally after Touch ID, Windows Hello or system
  authentication. The vault locks after 15 minutes without use; Security changes that, or turns
  it off.
- iPhone and iPad: unlock with Face ID or Touch ID (Security). The key that opens the vault stays
  in the device's keychain, which releases it only after Face ID (or Touch ID, or the passcode).
- Quick connect takes the key from a file you choose or from pasted text, on phones too, and
  can save the host to the vault with its key.
- Android: unlock with your fingerprint or face (Security). The key that opens the vault is kept
  in the phone's Keystore and released only after Android's biometric check; adding or removing
  a fingerprint or face turns it off until you unlock once with the master password. The phone
  unlock screen offers it first.
- Two-step verification for sync accounts on servers that offer it: set it up with an
  authenticator app in the Sync panel, and new devices ask for a code when they sign in.
- On servers that verify email addresses, enabling sync asks for a code mailed to you, and the
  account email can be changed from the Sync panel. The panel also shows your plan or trial.
- Teams: create an organization, invite people, and share hosts, keys, tunnels and VPNs through
  organization vaults with view, edit or manage access. Shared vaults are end-to-end encrypted
  like your own. People are confirmed by comparing fingerprints, and removing someone's access
  prompts a key rotation. Needs a sync server with sharing (the reference server has it).
- Offboarding: when someone leaves a team, the app shows what they could open, removes them and
  rotates the vault keys, finds their SSH keys on the team's servers and removes them, and can
  replace a shared SSH key on every server that uses it. Organizations show their plan, policies
  and an activity log.
- The MorphGate look: Console (dark) and Greenbar (light) app themes, or follow the system; the
  brand's typefaces (Martian Mono, Atkinson Hyperlegible Next and Mono) and the new gate mark.
- Terminal appearance: seven schemes (Console, Greenbar, Phosphor P1, Sodium P3, Bastion, Dusk and
  Production), font, size, cursor, bold in bright colors and a minimum contrast; import schemes
  from Ghostty, Alacritty, iTerm2 or Windows Terminal theme files (they sync with the vault); give
  a host its own scheme. Production hosts get a red tab with a PROD label, which a team's shared
  vault carries for everyone.
- Above each session, its route: the VPN, the jump hosts and the host, with the host key it is
  pinned to, and buttons for its files and for pasting or running a snippet. Hosts with an open
  session show it in the sidebar.
- When a host answers with a different key than the one pinned, MorphGate refuses to connect and
  shows both fingerprints, the known_hosts line holding the old one, and what to check first.
- The host editor shows the connection path and a preview in the host's terminal scheme.
- A phone layout, for the coming Android and iOS apps and for desktop windows narrower than a
  phone: hosts with open sessions on top, a sheet per host with its route, a full-screen terminal
  with Esc, Tab, Ctrl, arrows and other keys a phone keyboard lacks, a one-folder SFTP browser,
  and an unlock screen sized for thumbs.
- Session logs: turn on recording for a host, and what each session prints is saved, encrypted
  with its vault's key, and synced (to sync servers that store blobs). Play recordings back at up
  to 8× with long pauses shortened, save them as asciinema `.cast` files, or delete them. In a
  team's vault, everyone who can open the vault can play them; hosted MorphGate keeps team
  recordings on the Business plan, and a team can have the server delete them after a number of
  days.
- Item kinds from newer versions of the app sync along without breaking older ones.
- Single sign-on: when a team puts its vaults behind its identity provider, the app asks you to
  sign in to it (in your browser) and syncs them once you have. It adds to your master password;
  it never replaces it. The team's page shows the provider and this device's session.
- When a team's plan doesn't keep session logs, the host editor says so when you turn recording
  on, and recordings the server refused offer an Upgrade link; they stay on the device and upload
  with the next try.
- Device approval: when a team requires it, a new device waits until an owner or admin
  approves it, or you do from one of your devices the team already approved. The waiting device
  says so, its team vaults stay closed meanwhile, and Teams shows owners, admins and you the
  devices that wait, with Approve and Deny. Admins turn it on in the team's policies.
- Teams: when the admin who confirmed someone leaves, an owner's or admin's app certifies that
  person again by itself (or after comparing fingerprints, from the member list), so devices
  that never verified them still trust them.
- A team can ask members to publish the SSH keys they use on its servers; the app reminds those
  who haven't, and admins see who hasn't.
- Host groups: put hosts in a group and give it defaults (an identity, jump host, VPN, terminal
  scheme, keeping sessions); each host takes what it leaves empty. Groups fold in the sidebar.
- Identities: a user and how to sign in (password, key or agent), shared by any number of hosts and
  groups. Change it once and every host using it signs in the new way.
- Keep the session on the server: a host (or group) can attach to a tmux session on connect, one
  per tab, so a dropped connection, a restart or another device picks up where it was.
- Reconnect: a session whose connection was lost tries again on its own (when the network is
  back), and any ended session has a Reconnect button.
- Attachments: keep files with a host (a runbook, a certificate, up to 20 MB each), encrypted in
  its vault and synced; other devices fetch them when you save one. They go when the host goes.
- Export your vault (Security panel): a readable JSON file of your hosts, keys, snippets, tunnels,
  VPNs and themes, after your master password. Passwords, private keys and team vaults only when
  you tick them.
- Owners and admins can download a team's whole activity log as CSV or JSON lines.
- Download your data: the Sync panel saves what the sync server keeps about your account
  (devices, teams, sign-ins, activity) as a JSON file. Your vault isn't in it: the server can't
  read it.
- Delete your sync account from the Sync panel, with your master password. The server forgets
  the account, its devices and team memberships; this device keeps its vault with sync off, and
  your other devices keep what they have. Teams you own are listed first, with a way to Teams:
  transfer or delete them before the account can go.
- Teams on MorphGate's hosted sync show their plan, or "No plan" (and, where plans are enforced,
  that shared vaults can then be read but not changed). The owner's "Choose a plan" and "Manage
  plan" open that team's billing page, already signed in.
- Creating a team when you already own three without a plan says so, and offers to choose a plan.
- Where plans are enforced, a team without a plan (or whose plan ended) is locked until it has
  one: its hosts and other items open view only, and its vaults, invites, policies, keys,
  confirmations and roles can't change. Removing people, leaving, transferring and deleting the
  team still work. Buying a plan in the browser unlocks it when you come back to the app.
- Signing up on a server with terms of use and a privacy policy asks you to accept them (both
  linked); when they change, the Sync panel shows the new ones with an Accept button.
- Fixed: signing in to sync (new account, "I have an account", recovery) could sign the device
  straight back out when a sync started while it was signing in.
- Fixed: a team requiring two-step verification or single sign-on no longer removes its vaults
  from members' devices until they comply; they stay, unsynced edits included.
- WireGuard profiles with several peers: each `[Peer]` carries the traffic for its AllowedIPs
  (the most specific match wins) and keeps its own handshake and keepalives. One gateway that
  doesn't answer no longer stops the others from connecting.
- OpenVPN profiles with `tls-crypt-v2`: the client-specific control channel keys of OpenVPN 2.5
  and later, including servers that ask for the key twice (2.6, `force-cookie`).
- OpenVPN client certificates in a PKCS#12 bundle (`pkcs12`, embedded when you import the
  profile; its CA is used when the profile has none), and passphrase-protected client keys
  (PKCS#8 and the older OpenSSL format). The passphrase is asked when connecting, unless the
  profile has `<askpass>`.
- Vault export now also leaves out the passwords in OpenVPN profiles' `<askpass>` and
  `<auth-user-pass>` blocks, unless you tick passwords.
- Web sign-in (SAML, single sign-on) for VPNs: when an OpenVPN server asks you to sign in on a
  web page, or a Cisco AnyConnect server offers sign-in in an external browser (openconnect 9
  or later), MorphGate opens the page in your browser and connects once you've finished there.
  The dialog that says so closes by itself, or cancels the connect.
- On Windows, openconnect VPNs now say why they can't connect there (openconnect can only hand
  its traffic to a network adapter on Windows) as soon as you open them, not only when
  connecting.
- Pages for hosts (by group), keys and identities, snippets, tunnels and VPNs, opened from the
  top of the sidebar, which shows how many of each there are and which tunnels and VPNs are up.
  The sidebar keeps the host list for connecting. Teams and Sync are full pages too, and with no
  session open a page fills the window. Closing a page or an editor goes back to where you
  opened it: a session, or the page listing it.
- Groups have their own page too: open one to see its hosts, the tunnels through them, their
  files, and the identities, keys, jump hosts and VPNs they use. The group and identity editors
  are full screen, like the host editor.
- Move to another vault: from any editor (and a group's page), move hosts, groups, keys,
  identities, snippets, tunnels and VPNs between your personal vault and a team's. What an item
  uses comes along, a host's files and tunnels and a group's hosts ride with it, and you see the
  whole plan first. Something still used by an item that stays is copied instead, and a jump
  host, VPN or theme can be left out. Moved items keep working where they were open; session
  logs stay where they were recorded.
- A new vault offers to turn on sync right away; "Not now" leaves it for later.
- "I have an account": a device that already has a vault can sign in to the account you use
  elsewhere, from Sync or the offer after creating a vault. What its vault holds goes into the
  account (files included) and the account's hosts and keys come down; it then opens with the
  account's master password. The first screen asks up front too: a new vault, or the account you
  already have.
- Fixed: on a team's page at some window widths, a long address or the key picker ran into the
  column beside it.
- Fixed: on Android, turning on sync or signing in with an HTTPS server (morphgate.com included)
  failed: the app now checks certificates with Android's own verifier.
- Automatic updates.
