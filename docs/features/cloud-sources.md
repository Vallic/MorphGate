# Cloud sources

A cloud source keeps a set of hosts in step with a provider: Vallic Cloud's environments, the virtual machines of an AWS, Google Cloud, Azure, Hetzner Cloud or DigitalOcean account, or a feed (a JSON document of hosts and snippets that a team publishes at an address). A refresh brings what the provider decides (which machines exist, their addresses, whether they run); what the person sets stays (renames, keys, schemes, tags, notes, groups); a machine the provider no longer lists is marked gone, never deleted. The vault holds no cloud credentials: each device signs in to Vallic Cloud itself, and lists the other clouds with their own CLI as that device has it set up, so the calls go from the device to the provider and nothing reaches MorphGate's server but the encrypted items. A feed's token is the one exception ([Feeds](#feeds)). Code: `crates/mg-inventory` (`lib.rs`: `InventoryHost`, `Machine`; `vallic.rs`, `cli.rs`, `aws.rs`, `gcp.rs`, `azure.rs`, `hetzner.rs`, `digitalocean.rs`, `shape.rs`, `feed.rs`), `crates/mg-store/src/model.rs` (`CloudSource`, `HostSource`, `CloudReach`, `SnippetSource`), `apps/desktop/src-tauri/src/cloud.rs` (Tauri commands, `apply()`, `apply_snippets()`, `reach_command()`), `apps/desktop/src/CloudPage.tsx`.

## Providers

| `provider` | Lists with | Signed in by | Group (default) | User (default) | Reached by | Host's `external_id` |
| --- | --- | --- | --- | --- | --- | --- |
| `vallic` | The console's API | This device's own sign-in | Project | The platform's | Address; machines behind the front by a jump command | `env:<id>`, `env:<id>/front`, `env:<id>/<machine>`, `env:<id>/@<worker>` |
| `aws` | `aws` | The CLI's profile (SSO, MFA) | Region | `ec2-user` | Public, private through a jump host, Session Manager, Instance Connect Endpoint | `aws:<region>/<instance id>` |
| `gcp` | `gcloud` | `gcloud auth login` | Project | The OS Login user | Public, private, IAP | `gcp:<project>/<zone>/<name>` |
| `azure` | `az` | `az login` | Resource group | The VM's admin user, else `azureuser` | Public, private | `azure:<resource id, lowercase>` |
| `hetzner` | `hcloud` | The CLI's context | Location | `root` | Public, private | `hetzner:<context>/<id>` |
| `digitalocean` | `doctl` | The CLI's context | Region | `root` | Public, private | `digitalocean:<id>` |
| `feed` | `GET` of its URL | The source's token, in the vault | The feed's `group`, else none | The feed's | Address, through the feed's own jump hosts | `feed:<id>` |

## The items

A `cloud_source` item (in a personal or team vault):

| Field | Meaning |
| --- | --- |
| `label`, `provider` | "Vallic Cloud", "AWS (prod)", "Hetzner Cloud (shop)", a feed's name…; one of the seven above (else "a cloud source's provider is vallic, aws, gcp, azure, hetzner, digitalocean or feed") |
| `endpoint` | Vallic's console when not `https://console.vallic.com` |
| `account` | Who signed in when it was made (an email, an ARN, `user (subscription)`, the context) |
| `key_ref` | The `ssh_key` its new hosts sign in with; none: the SSH agent |
| `refreshed_at` | Unix seconds of the last refresh, on any device |
| `profile` | AWS profile, or the `hcloud` / `doctl` context; none: the CLI's default |
| `scopes` | AWS regions, Google Cloud projects or Azure subscription ids; empty: every enabled region, active project or enabled subscription the sign-in sees |
| `reach` | None (public addresses), `private` (with `jump_ref`: "private addresses need a jump host"), `aws-ssm`, `aws-eice` (AWS only), `gcp-iap` (Google Cloud only) |
| `jump_ref`, `user`, `group_tag` | The jump host for private addresses; who to log in as where a machine doesn't say; group by this tag's or label's value instead |
| `url`, `token` | A feed's address (`https://`, or `http://` on `localhost`, `127.0.0.1` or `[::1]`: else "a feed's address starts with https://") and the token it's read with (required: "a feed needs the token it's read with") |

A host it keeps carries `source` (`HostSource`): `source_ref`, `external_id` (what a refresh matches on), `label` (the provider's name for it: a host still called that follows renames, one renamed in MorphGate keeps its name), `gone`, `no_sftp`, `no_forwarding`, `state` (`stopped`, `VM deallocated`…), `reach`, and from a feed `host_keys` (its server's keys) and `tags` (the ones the feed gave it, among the host's). A feed's snippet carries `source` (`SnippetSource`: `source_ref`, `external_id`). Lists show "gone from AWS" ("gone from its feed") or the state as a badge, and hide **Files** for `no_sftp` ([Hosts, groups and identities](hosts-groups-identities.md)). For `no_forwarding` the tunnel editor leaves the host out, saving or starting a tunnel through it is refused ("\"{host}\" can't carry tunnels: its cloud's SSH doesn't forward ports"), and the agent isn't forwarded to it ([Port forwarding](port-forwarding.md)).

## Where credentials live

| What | Where |
| --- | --- |
| Vallic Cloud sign-in | The rotating refresh token, as a device secret: setting `secret:cloud:<source id>` in `settings`, sealed with the personal vault's key (readable only while the vault is unlocked), never synced. The access token stays in memory (15 minutes, renewed a minute early) |
| AWS, Google Cloud, Azure, Hetzner, DigitalOcean | The CLI's own configuration, untouched. MorphGate asks for no keys: keys kept in the vault would put long-lived cloud credentials in every synced copy, and each provider's single sign-on would have to be done again in MorphGate |
| The CLI's path, when it isn't found | Setting `cloud-cli:<provider>`, on this device |
| A feed's token | The `cloud_source` item's `token`, synced with the vault ([Feeds](#feeds)) |

Refresh tokens rotate and a replayed one ends the sign-in, so `CloudState` lets one cloud operation run at a time per device, and a rotated token is stored before anything else can fail. MorphGate signs in to Vallic as the public client `vallic-cli` (`CLIENT_ID`), naming the session "MorphGate on <device>".

## Adding a source

The Hosts page's **Add from…** → **Clouds…** (desktop) opens "Clouds": each source, then a **Vault** choice and **Connect Vallic Cloud** (**Connect another Vallic account** once there is one), **Add AWS**, **Add Google Cloud**, **Add Azure**, **Add Hetzner Cloud**, **Add DigitalOcean**, **Add a feed**. **Add from…** → **Feed URL…** opens it at **Add a feed**.

### Vallic Cloud

OAuth 2.0 device authorization (RFC 8628). `vallic_sign_in` gets a code; the page shows "Type this code at Vallic Cloud's sign-in page, then approve:", opens the console's page (**Open console.vallic.com/… ↗**, **Cancel**) and calls `vallic_sign_in_poll` every `interval` seconds (5 by default, 5 more after `slow_down`). "The sign-in was declined in the browser." or "The code ran out before it was used." end it. Once approved, the app reads `/me`, makes the source "Vallic Cloud" in the chosen vault (or signs this device in to an existing one: **Sign in on this device**), keeps the refresh token and refreshes.

| Console call | For |
| --- | --- |
| `POST /oauth/device_authorization` (`client_id`, `device_name`) | Starting a sign-in |
| `POST /oauth/token` (device code, then refresh token grants) | Polling; new tokens (`invalid_grant`: signed out) |
| `POST /oauth/revoke` | **Sign out on this device** |
| `GET /api/vc/v1/me`, `/projects`, `/environments`, `/environments/{id}` | Who signed in; the inventory (environments read in parallel) |
| `POST /api/vc/v1/me/ssh-keys` | **Add {key} to your Vallic account**, labelled "{key} (MorphGate)" |

The console must be `https://` (or `http://` on localhost); `MORPHGATE_VALLIC_CONSOLE` points the app at a test console. An environment becomes hosts the way `vallic ssh` reaches it (`vallic::hosts_of()`): a host "{project} · {environment}" (its login command the forced command's name where a machine carries several environments); where a plain login goes on to another machine, a "(front)" host and the environment's host behind it, carried by the jump command `<name> jump <machine>` under the host-key name `<machine>.<host>`; a host per other machine of an environment on several ("{project} · {environment} · {machine} ({role})"); and a host per worker (login command `<name> @<worker>`). A session on one of them is a shell in the customer's container (or the worker's), as the environment's own user, never root on the machine: the platform's SSH runs a forced command into the container. So all are `no_sftp` and `no_forwarding`, and none has an `authorized_keys` to edit: who gets in is decided by Vallic accounts, the keys on them included, so offboarding and key replacement leave these hosts to the Vallic console ([Offboarding](offboarding.md)). Environments without a shell for this person are reported, not made.

### CLI providers

| Control | Field |
| --- | --- |
| The check line: "Asking aws who it's signed in as…", then "aws (/usr/local/bin/aws) is signed in as …" or the CLI's error (`cloud_check`) | None. When the CLI isn't found, "Where aws is on this computer" and **Use it** store its path (`cloud_cli_path`) |
| **Profile (optional)** (AWS), **Context (optional: hcloud's active one)**, **Context (optional: doctl's default)** | `profile` |
| **Regions (optional)**, **Projects (optional)**, **Subscription ids (optional)** | `scopes` (comma separated) |
| **Reach its machines by**: "Their public address (machines without one are left out)", "Their private address, through a jump host", "AWS Session Manager (needs AWS's session-manager-plugin)", "An EC2 Instance Connect Endpoint", "IAP (Identity-Aware Proxy)" | `reach` |
| **Jump host** (for private addresses; the vault's own hosts) | `jump_ref` |
| **Log in as (where a machine doesn't say)** | `user` |
| **Group by tag (optional)** | `group_tag` |
| **Its hosts sign in with** (new sources) | `key_ref` |
| **Add and list machines** / **Save and refresh**, **Cancel** | `cloud_source_add`, or `cloud_source_settings` then `cloud_refresh` |

`cloud_source_add` makes the source only once the CLI answers who it is signed in as, then lists its machines.

| Provider | Who | Scopes | Machines |
| --- | --- | --- | --- |
| AWS (`[--profile P] --output json`) | `aws sts get-caller-identity` | `aws ec2 describe-regions` | `aws ec2 describe-instances --region R`, regions in parallel |
| Google Cloud | `gcloud auth list --format=json` | `gcloud projects list --format=json` | `gcloud compute instances list --project P --format=json`; user from `gcloud compute os-login describe-profile --format=json` |
| Azure | `az account show -o json` | `az account list -o json` | `az vm list -d --subscription S -o json`, in parallel |
| Hetzner Cloud | `hcloud context active` (or the source's context) | None | `hcloud [--context C] server list -o json` |
| DigitalOcean | `doctl [--context C] account get --output json` | None | `doctl [--context C] compute droplet list --output json` |

How a machine becomes a host (`shape::hosts()`):

| Host | From |
| --- | --- |
| Label | The name (AWS: the `Name` tag, else the instance id) |
| Host name | Public: AWS's DNS name or IP, Azure's FQDN or first public IP, Google Cloud's NAT IP (first network interface), Hetzner's IPv4, DigitalOcean's public v4. Private: the private address. Through the cloud: the instance id or name, which its host key is pinned under |
| Port | Tag `morphgate:port` (AWS) or `morphgate-port` (label or tag elsewhere; `morphgate-port:<port>` on DigitalOcean), else 22 |
| User | The machine's (tag `morphgate:user` on AWS, `morphgate-user` label or tag elsewhere, `morphgate-user:<name>` on DigitalOcean; Azure's admin user), else **Log in as**, else Google Cloud's OS Login user, else `azureuser` (Azure), `root` (Hetzner, DigitalOcean) or `ec2-user` |
| Group | The **Group by tag** value, else region, project, resource group or location |
| Sign-in (new hosts) | AWS: the vault key labelled like the instance's key pair; else the source's key; else the system's SSH agent |
| Left out | Windows machines, terminated EC2 instances; running machines without the address the source uses, and new stopped ones without any ("Without a public address: …") |

### A feed

**Add a feed**: "Hosts and snippets from a JSON document at an address, read with a token: …", the **Vault**, then:

| Control | Field |
| --- | --- |
| **Address** (placeholder `https://ops.example.com/morphgate.json`) | `url` |
| **Token** (a password field; "Kept in the vault, so every device that can open it refreshes the feed. Use a token that only reads the feed.") | `token` |
| **Name (optional)** | `label`: else what the feed calls itself (`name`), else the address's host |
| **Its hosts sign in with** | `key_ref` |
| **Add and read the feed** ("Reading…"), **Cancel** | `cloud_feed_add`: the feed is read before the source is kept, so a wrong address or token is said and nothing is made ("{host} refused the token") |

The source's card shows the address and the token's last 4 characters ("token …f3a9"; "…" for a token under 16 characters), never the rest. **Settings…** opens the same form (an empty **Token**, "Leave empty to keep it (…f3a9)", keeps it), then **Save and refresh** (`cloud_feed_settings`, then `cloud_refresh`).

## Refresh

`cloud_refresh(source_id)` runs on demand: **Refresh** on the source, or after its settings change; a feed also refreshes itself ([Feeds](#automatic-refresh)). `apply()` matches the source's hosts in its vault by `external_id`:

| What | On refresh |
| --- | --- |
| Follows the provider | Label (until renamed here), host name (a stopped machine keeps its last one), port, user, login and jump commands, the jump host (the source's for private addresses, else none; Vallic's front; a feed's `jump`), the `source` marker (a feed's host keys and state with it) |
| Stays the person's | Sign-in (key, identity), terminal scheme, VPN, tags, notes, group, agent forwarding, recording, session keeping. A feed's tags are added: the ones it gave before are replaced by the ones it gives now, the person's stay |
| A new machine | A new host, in the group of that name (made when missing; none where a feed names none) |
| No longer listed | `gone` set; listed again, it clears |

New items get ids worked out rather than drawn (`mg_store::derived_id`: SHA-256 of the vault, the source, the kind and the `external_id`, or the group's name in lowercase, as a ULID; `LocalVault::insert_in`): two devices refreshing a source at once make the same host, group or snippet under the same id, and the second gets a conflict instead of a duplicate. Copies that differ only in what the source decides (the source's `refreshed_at` too) make no "(conflict)" copy ([Sync](sync.md#conflicts)). A live item already holding the id (one that lost its `source`) leaves the new one a random id.

The page says "2 hosts added, 1 updated, 1 gone from the cloud" ("…gone from the feed"; a feed adds "1 snippet added", "1 snippet changed", "1 snippet removed"), or "Nothing changed", then what it skipped: "No shell for you (your role), or not running yet: …" (Vallic), "Without a public address: …", "Couldn't list: …" (regions, projects or subscriptions that refused, and machines whose ids aren't shaped like the cloud's), "Skipped: …" (a feed's entries). A refresh that failed on this device (an automatic one included) shows on the card until one succeeds: "The last refresh failed: …" (`CloudState`, in memory).

## Feeds

A feed is a JSON document of hosts and snippets at an address, read with a token: generated from Terraform output, a CMDB or a cron job, or served by an internal endpoint. It's how a team brings in what no cloud's API shows (an operator port, a staff user, bastions). The device reads it straight from the publisher over HTTPS, and the result becomes ordinary vault items, so MorphGate's server sees nothing new. `mg_inventory::feed` reads it (`fetch`, `parse`): data only, never something that runs on the device (no proxy or local command, no `CloudReach`).

### The request

`GET <url>` with `Authorization: Bearer <token>`, `Accept: application/json` and `User-Agent: MorphGate/<version>`. Redirects are followed (5 at most) only to `https://` or this computer. The answer is read up to 5 MiB, within 60 s.

| Answer | Message |
| --- | --- |
| 401 or 403 | "{source} refused the token: change it in the source's settings" |
| Another status | "{source} answered {status}" |
| Over 5 MiB | "{source} sent more than 5 MiB: a feed is at most that" |
| Over 60 s | "{source} took longer than 60 s to answer" |
| Not JSON, not an object, no `"version": 1`, `hosts` or `snippets` not a list | "{source} sent something this version can't read: …" |
| `version` above 1 | "{source} is a version {n} feed: update MorphGate to read it" |
| More than 5,000 hosts or 1,000 snippets | "{source} lists {n} hosts: a feed holds at most 5,000" |
| Unreachable | "can't reach {source}: …" |

A document refused whole changes nothing.

### The format (version 1)

```json
{
  "version": 1,
  "name": "Ops",
  "hosts": [
    { "id": "bastion-fsn1", "label": "Bastion FSN1", "hostname": "bastion-fsn1.example.net",
      "port": 22, "user": "ops", "group": "Bastions", "host_keys": ["ssh-ed25519 AAAAC3Nza..."] },
    { "id": "server-1234", "label": "acme-prod-1", "hostname": "10.0.12.34", "port": 2222,
      "user": "ops", "group": "Acme", "tags": ["production", "fsn1"], "jump": "bastion-fsn1",
      "key": "customers", "host_keys": ["ssh-ed25519 AAAAC3Nza..."], "state": "running" }
  ],
  "snippets": [
    { "id": "php-errors", "name": "PHP error log", "body": "podman logs --tail 200 php", "tags": ["diagnostics"] }
  ]
}
```

| Field | Rule |
| --- | --- |
| `version` | `1` |
| `name` | Optional: what the source is called when it's added without a name |
| `id` | Required, unique among the hosts (and among the snippets): 1 to 200 of `A-Z a-z 0-9 . _ : / @ -`. What a refresh matches on, as `external_id` `feed:<id>` |
| `hostname`, `user` | Required: no whitespace or control characters, no leading `-`, at most 255 bytes |
| `label` | Optional (control characters out, at most 200 characters); else the `id` |
| `port` | 1 to 65535; 22 when left out |
| `group` | Optional: the group a new host goes in (made when missing); none when left out |
| `tags` | Optional: added to the host's (at most 50, 64 characters each) |
| `jump` | Optional: another host's `id` in the same feed, kept, not itself, and not leading round in a circle |
| `key` | Optional: the label of an SSH key in the vault that a new host signs in with (as an EC2 key pair's name). No match: the source's key (**Its hosts sign in with**), else the SSH agent. Never a key itself |
| `host_keys` | Optional, at most 16: the server's OpenSSH public keys (`ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa`, `sk-…`; type and base64, a comment after them dropped). They decide the host's key at connect time instead of trust on first use; another key is refused ([SSH connections](ssh-connections.md#keys-a-feed-lists)). Left out, the first connection asks as usual |
| `state` | Optional: shown as a badge (`stopped`); `running` shows none |
| `snippets[].id`, `name`, `body`, `tags` | `id` as for hosts; `name` and `body` required; the body at most 64 KiB, with no control characters but newlines and tabs (a terminal reads escape sequences as more than text) |

Unknown fields are ignored and `null` reads as left out. An entry that breaks a rule is skipped and said ("Skipped: server-9: the port isn't 1 to 65535; …"); a host that jumps through a skipped one is skipped too.

### Snippets

A feed's snippets follow it whole: each refresh sets their name, body and tags, makes new ones and deletes the ones it no longer lists. They're read-only in the app (**Make a copy** to change one), and **Run** and **Paste** ask first when the feed changed one since this device last sent it ([Terminal and snippets](terminal-and-snippets.md#a-feeds-snippets)).

### The token

Every device of the team refreshes, so the token is in the `cloud_source` item, synced to everyone who can open the vault: an exception to the vault holding no cloud credentials, taken because a feed's token only reads a host list. Publishers should issue one that does only that. The card shows its last 4 characters at most. Offboarding lists each feed in the member's vaults under what to change: "Rotate the token for {source}" ([Offboarding](offboarding.md)).

### Automatic refresh

On desktops the app calls `cloud_auto_refresh` once the first sync since unlocking has finished (at once without sync, after 20 s at the latest), then every 15 minutes while unlocked. It refreshes, one at a time, each feed in a vault this device can write to whose `refreshed_at` (synced) is 10 minutes old or more, checking again just before (a sync may have brought another device's refresh). Members who can only view never refresh. The CLI providers and Vallic Cloud still refresh on demand only.

## Reaching machines through the cloud

A command run on this device is not something a vault may hand out: anyone who can write to a shared vault could make every teammate's MorphGate run anything. So a host reached through Session Manager, an Instance Connect Endpoint or IAP carries only `CloudReach {kind, instance, place, project}`, checked against what the cloud's ids look like (`CloudReach::check()`: `i-` and hex, lowercase regions and zones, a project of lowercase letters, digits, `-`, `.`, `:`; else "aws-ssm i-0abc; rm in eu-central-1: not an id this cloud gives"). At connect time `reach_command()` builds the command from those values, the source's profile and this device's CLI, so it needs no allowing ([SSH connections](ssh-connections.md)):

| `kind` | Command (`%p` is the host's port) |
| --- | --- |
| `aws-ssm` | `aws ssm start-session --target <id> --document-name AWS-StartSSHSession --parameters portNumber=%p --region <region> [--profile P]` |
| `aws-eice` | `aws ec2-instance-connect open-tunnel --instance-id <id> --remote-port %p --region <region> [--profile P]` |
| `gcp-iap` | `gcloud compute start-iap-tunnel <name> %p --listen-on-stdin --zone <zone> --project <project> --verbosity=warning` |

The CLI's path is quoted for the shell with `%` doubled; a profile must be letters, digits, `_`, `.` or `-` ("the AWS profile … can't be given to a command").

## Changing and removing

| Control | Command | Does |
| --- | --- | --- |
| **Its hosts sign in with** | `cloud_source_key` | Sets the source's key; its hosts that used the previous key (or the system agent, when there was none) follow, others keep theirs |
| **Settings…** (CLI sources) | `cloud_source_settings` | Changes what is listed and how; Vallic: "Vallic Cloud lists what your sign-in reaches"; a feed: "a feed's settings are its address and token" |
| **Settings…** (feeds) | `cloud_feed_settings` | Its name, address and token |
| **Sign out on this device** (Vallic) | `cloud_sign_out` | Revokes the token on the console and forgets it here; the source and hosts stay |
| **Remove…**, then **Remove it and its hosts** or **Remove it, keep the hosts** (a feed with snippets: **Remove it, its hosts and snippets**, **Remove it, keep the hosts and snippets**) | `cloud_source_delete(source_id, delete_hosts)` | Signs out, deletes the hosts (those behind a jump host first) and a feed's snippets, or makes them ordinary hosts and snippets, then the source. Groups it made stay. Deleting the item while a host or snippet still names it is refused, as for anything in use |

## Running the CLIs

`Cli::find()` looks in `MORPHGATE_CLOUD_CLI_DIR` (tests), then `PATH`, then where installers put the CLIs, since an app started from a menu or Finder doesn't get the shell's `PATH`: `~/.local/bin`, `~/google-cloud-sdk/bin`, `~/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin`, `/snap/bin`, `/opt/google-cloud-sdk/bin`, `/usr/lib/google-cloud-sdk/bin`, and on Windows `Amazon/AWSCLIV2`, `Google/Cloud SDK/google-cloud-sdk/bin` and `Microsoft SDKs/Azure/CLI2/wbin` under `ProgramFiles`, `ProgramFiles(x86)` and `LOCALAPPDATA` (`.exe` or `.cmd`). Each run has stdin closed, no pager, prompts or colors (`AWS_PAGER=`, `CLOUDSDK_CORE_DISABLE_PROMPTS=1`, `AZURE_CORE_ONLY_SHOW_ERRORS=1`, `AZURE_CORE_NO_COLOR=1`), no window on Windows, and a `TIMEOUT` of 60 s.

| Error | Text |
| --- | --- |
| Not found | "aws isn't installed on this computer, or MorphGate can't find it: install it, or give its path in the source" |
| A given path that won't run | "{path}: not a program that can be run" |
| Too slow | "`{cli} {arguments}` took longer than 60 s" |
| It failed | What it printed on stderr, as it said it (an expired session names the command to sign in again), else "`… ` failed (exit status)" |
| Unreadable output | "`…` printed something this version can't read: …" |
| Vallic | "signed out of Vallic Cloud (the sign-in ended, or was used on another device): sign in again", "this device isn't signed in to it: sign in first", "Vallic Cloud doesn't take security keys (sk-): choose another key" |

## Tauri commands

| Command | Does |
| --- | --- |
| `cloud_sources` | Sources as `SourceView`: host, gone and snippet counts, `signed_in` (Vallic: this device has a sign-in; the others: always), the CLI path set here, a feed's `url` and `token_end`, and `failed` (the last refresh here, when it failed) |
| `vallic_sign_in(endpoint)`, `vallic_sign_in_poll(endpoint, device_code, source_id, vault_id)` | The device sign-in; `Pending {slower}`, `Denied`, `Expired`, or `Done {source, refresh}` |
| `cloud_source_add(provider, vault_id, key_id, settings)`, `cloud_source_settings(source_id, settings)` | A CLI source; its settings |
| `cloud_check(provider, profile)`, `cloud_cli_path(provider, path)` | Who the CLI is signed in as; where this device runs it from |
| `cloud_feed_add(vault_id, key_id, {label, url, token})`, `cloud_feed_settings(source_id, {label, url, token})` | A feed (read first, then kept and brought in); its name, address and token (an empty token keeps it) |
| `cloud_refresh(source_id)` | `RefreshResult {added, updated, gone, without_shell, without_address, skipped, snippets_added, snippets_updated, snippets_removed}` |
| `cloud_auto_refresh` | The feeds that are due ([Automatic refresh](#automatic-refresh)); how many it refreshed. Nothing on phones |
| `cloud_source_key`, `cloud_sign_out`, `cloud_source_delete`, `cloud_add_key(source_id, key_id)` | As above |

## Platform differences

| Where | Difference |
| --- | --- |
| Phones and tablets | No **Clouds…** page and no CLIs, and feeds don't refresh themselves. The hosts sync and connect (a feed's host keys apply there too), except those reached through the cloud: "\"web-1\" connects through its cloud's CLI on the computer: connect to it from the desktop app" |
| Windows | CLIs found as `.exe` or `.cmd` |

## Tests

- `crates/mg-inventory/src/*.rs`: each provider's JSON as its CLI documents it, `shape.rs` (addresses, users, groups by tag, Session Manager), `vallic.rs` (environments as hosts), `cli.rs` (JSON read, stderr passed on, a missing CLI named). `crates/mg-store/src/model.rs`: `only_what_the_clouds_ids_look_like`. `apps/desktop/src-tauri/src/cloud.rs`: private machines and stopped ones, the reach command built here, a refresh following the platform and keeping what is the person's.
- `crates/mg-inventory/tests/console.rs`: the Vallic client against a fake console on loopback (device flow, rotation, a replayed token refused, the inventory).
- `crates/mg-inventory/src/feed.rs`: the format's example, defaults, every rule's skip and its message, documents refused whole, `https://` only. `crates/mg-inventory/tests/feed.rs`: the feed client against a fake publisher on loopback (the token and headers sent, a refused token, over 5 MiB, a redirect to plain HTTP not followed). `apps/desktop/src-tauri/src/cloud.rs`: `a_feed_keeps_hosts_and_snippets_in_step` (derived ids, jump hosts, groups, tags kept, host keys, snippets dropped). `crates/mg-store/src/sync.rs`: `refreshes_on_two_devices_make_no_copies`. `crates/mg-ssh/tests/live.rs`: `listed_host_keys_decide`.
- `crates/mg-inventory/tests/clis.rs`: the real CLIs, read only, printing counts only; ignored unless asked, e.g. `MG_TEST_AWS=1 [MG_TEST_AWS_PROFILE=…] cargo test -p mg-inventory --test clis -- --include-ignored --nocapture` (also `MG_TEST_AZ`, `MG_TEST_GCLOUD`, `MG_TEST_HCLOUD`, `MG_TEST_DOCTL`).
- e2e `apps/desktop/e2e/appimage.mjs`: Vallic Cloud through `vallic-console.mjs` (sign-in approved on the second poll, the key added to the account, no Files); AWS through the stand-in `e2e/clouds/aws` (an instance that is the test sshd, signing in with the vault key named like its key pair, a stopped one waiting, then the same source through Session Manager, which the stand-in relays with `crates/mg-ssh/tests/relay.py`); DigitalOcean through `e2e/clouds/doctl`; a feed through `e2e/host-feed.mjs` (a wrong token said, its host on 127.0.0.4 connecting with the listed key and no prompt, one listed with another key refused, an invalid entry skipped, its snippet read-only and asking before it runs once the feed changed it). `run.sh` sets `MORPHGATE_VALLIC_CONSOLE`, `MORPHGATE_CLOUD_CLI_DIR`, `E2E_CLOUD_PORT`, `E2E_CLOUD_USER`, `E2E_HOST_FEED` and `E2E_HOST_FEED_TOKEN`.

## Limits

- Refreshing is on demand only, per source, on a desktop; feeds also refresh themselves there.
- Vallic Cloud: a source brings every project the sign-in reaches, grouped by project; no SFTP; its database and cache tunnels (`vallic-tunnel`) aren't offered, and neither are ordinary tunnels or agent forwarding (`no_forwarding`).
- Not supported: Azure Bastion (`az network bastion tunnel` listens on a port and can't carry a connection on stdin), Azure's Entra ID sign-in to VMs (`az ssh cert`). Windows machines are left out.
- A jump host set by hand on a kept host is replaced at the next refresh.
- Moving a source to another vault doesn't take its hosts or snippets (they don't ride with it); its next refresh there makes new ones.
- A feed can't carry a login command or reach a host through a command (a remote login command may come later); ETags aren't sent yet, so each refresh reads the whole document.
