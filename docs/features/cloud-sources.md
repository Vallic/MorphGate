# Cloud sources

A cloud source keeps a set of hosts in step with a provider: Vallic Cloud's environments, or the virtual machines of an AWS, Google Cloud, Azure, Hetzner Cloud or DigitalOcean account. A refresh brings what the cloud decides (which machines exist, their addresses, whether they run); what the person sets stays (renames, keys, schemes, tags, notes, groups); a machine the cloud no longer lists is marked gone, never deleted. The vault holds no cloud credentials: each device signs in to Vallic Cloud itself, and lists the other clouds with their own CLI as that device has it set up, so the calls go from the device to the provider and nothing reaches MorphGate's server but the encrypted items. Code: `crates/mg-inventory` (`lib.rs`: `InventoryHost`, `Machine`; `vallic.rs`, `cli.rs`, `aws.rs`, `gcp.rs`, `azure.rs`, `hetzner.rs`, `digitalocean.rs`, `shape.rs`), `crates/mg-store/src/model.rs` (`CloudSource`, `HostSource`, `CloudReach`), `apps/desktop/src-tauri/src/cloud.rs` (Tauri commands, `apply()`, `reach_command()`), `apps/desktop/src/CloudPage.tsx`.

## Providers

| `provider` | Lists with | Signed in by | Group (default) | User (default) | Reached by | Host's `external_id` |
| --- | --- | --- | --- | --- | --- | --- |
| `vallic` | The console's API | This device's own sign-in | Project | The platform's | Address; machines behind the front by a jump command | `env:<id>`, `env:<id>/front`, `env:<id>/<machine>`, `env:<id>/@<worker>` |
| `aws` | `aws` | The CLI's profile (SSO, MFA) | Region | `ec2-user` | Public, private through a jump host, Session Manager, Instance Connect Endpoint | `aws:<region>/<instance id>` |
| `gcp` | `gcloud` | `gcloud auth login` | Project | The OS Login user | Public, private, IAP | `gcp:<project>/<zone>/<name>` |
| `azure` | `az` | `az login` | Resource group | The VM's admin user, else `azureuser` | Public, private | `azure:<resource id, lowercase>` |
| `hetzner` | `hcloud` | The CLI's context | Location | `root` | Public, private | `hetzner:<context>/<id>` |
| `digitalocean` | `doctl` | The CLI's context | Region | `root` | Public, private | `digitalocean:<id>` |

## The items

A `cloud_source` item (in a personal or team vault):

| Field | Meaning |
| --- | --- |
| `label`, `provider` | "Vallic Cloud", "AWS (prod)", "Hetzner Cloud (shop)"…; one of the six above (else "a cloud source's provider is vallic, aws, gcp, azure, hetzner or digitalocean") |
| `endpoint` | Vallic's console when not `https://console.vallic.com` |
| `account` | Who signed in when it was made (an email, an ARN, `user (subscription)`, the context) |
| `key_ref` | The `ssh_key` its new hosts sign in with; none: the SSH agent |
| `refreshed_at` | Unix seconds of the last refresh, on any device |
| `profile` | AWS profile, or the `hcloud` / `doctl` context; none: the CLI's default |
| `scopes` | AWS regions, Google Cloud projects or Azure subscription ids; empty: every enabled region, active project or enabled subscription the sign-in sees |
| `reach` | None (public addresses), `private` (with `jump_ref`: "private addresses need a jump host"), `aws-ssm`, `aws-eice` (AWS only), `gcp-iap` (Google Cloud only) |
| `jump_ref`, `user`, `group_tag` | The jump host for private addresses; who to log in as where a machine doesn't say; group by this tag's or label's value instead |

A host it keeps carries `source` (`HostSource`): `source_ref`, `external_id` (what a refresh matches on), `label` (the provider's name for it: a host still called that follows renames, one renamed in MorphGate keeps its name), `gone`, `no_sftp`, `no_forwarding`, `state` (`stopped`, `VM deallocated`…) and `reach`. Lists show "gone from AWS" or the state as a badge, and hide **Files** for `no_sftp` ([Hosts, groups and identities](hosts-groups-identities.md)). For `no_forwarding` the tunnel editor leaves the host out, saving or starting a tunnel through it is refused ("\"{host}\" can't carry tunnels: its cloud's SSH doesn't forward ports"), and the agent isn't forwarded to it ([Port forwarding](port-forwarding.md)).

## Where credentials live

| What | Where |
| --- | --- |
| Vallic Cloud sign-in | The rotating refresh token, as a device secret: setting `secret:cloud:<source id>` in `settings`, sealed with the personal vault's key (readable only while the vault is unlocked), never synced. The access token stays in memory (15 minutes, renewed a minute early) |
| AWS, Google Cloud, Azure, Hetzner, DigitalOcean | The CLI's own configuration, untouched. MorphGate asks for no keys: keys kept in the vault would put long-lived cloud credentials in every synced copy, and each provider's single sign-on would have to be done again in MorphGate |
| The CLI's path, when it isn't found | Setting `cloud-cli:<provider>`, on this device |

Refresh tokens rotate and a replayed one ends the sign-in, so `CloudState` lets one cloud operation run at a time per device, and a rotated token is stored before anything else can fail. MorphGate signs in to Vallic as the public client `vallic-cli` (`CLIENT_ID`), naming the session "MorphGate on <device>".

## Adding a source

The Hosts page's **Add from…** → **Clouds…** (desktop) opens "Clouds": each source, then a **Vault** choice and **Connect Vallic Cloud** (**Connect another Vallic account** once there is one), **Add AWS**, **Add Google Cloud**, **Add Azure**, **Add Hetzner Cloud**, **Add DigitalOcean**.

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

## Refresh

`cloud_refresh(source_id)` runs on demand: **Refresh** on the source, or after its settings change. `apply()` matches the source's hosts in its vault by `external_id`:

| What | On refresh |
| --- | --- |
| Follows the provider | Label (until renamed here), host name (a stopped machine keeps its last one), port, user, login and jump commands, the jump host (the source's for private addresses, else none; Vallic's front), the `source` marker |
| Stays the person's | Sign-in (key, identity), terminal scheme, VPN, tags, notes, group, agent forwarding, recording, session keeping |
| A new machine | A new host, in the group of that name (made when missing) |
| No longer listed | `gone` set; listed again, it clears |

The page says "2 hosts added, 1 updated, 1 gone from the cloud" (or "Nothing changed"), then what it skipped: "No shell for you (your role), or not running yet: …" (Vallic), "Without a public address: …", "Couldn't list: …" (regions, projects or subscriptions that refused, and machines whose ids aren't shaped like the cloud's).

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
| **Settings…** (CLI sources) | `cloud_source_settings` | Changes what is listed and how; Vallic: "Vallic Cloud lists what your sign-in reaches" |
| **Sign out on this device** (Vallic) | `cloud_sign_out` | Revokes the token on the console and forgets it here; the source and hosts stay |
| **Remove…**, then **Remove it and its hosts** or **Remove it, keep the hosts** | `cloud_source_delete(source_id, delete_hosts)` | Signs out, deletes the hosts (those behind a jump host first) or makes them ordinary hosts, then the source. Groups it made stay |

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
| `cloud_sources` | Sources as `SourceView`: host and gone counts, `signed_in` (Vallic: this device has a sign-in; CLI sources: always), the CLI path set here |
| `vallic_sign_in(endpoint)`, `vallic_sign_in_poll(endpoint, device_code, source_id, vault_id)` | The device sign-in; `Pending {slower}`, `Denied`, `Expired`, or `Done {source, refresh}` |
| `cloud_source_add(provider, vault_id, key_id, settings)`, `cloud_source_settings(source_id, settings)` | A CLI source; its settings |
| `cloud_check(provider, profile)`, `cloud_cli_path(provider, path)` | Who the CLI is signed in as; where this device runs it from |
| `cloud_refresh(source_id)` | `RefreshResult {added, updated, gone, without_shell, without_address, skipped}` |
| `cloud_source_key`, `cloud_sign_out`, `cloud_source_delete`, `cloud_add_key(source_id, key_id)` | As above |

## Platform differences

| Where | Difference |
| --- | --- |
| Phones and tablets | No **Clouds…** page and no CLIs. The hosts sync and connect, except those reached through the cloud: "\"web-1\" connects through its cloud's CLI on the computer: connect to it from the desktop app" |
| Windows | CLIs found as `.exe` or `.cmd` |

## Tests

- `crates/mg-inventory/src/*.rs`: each provider's JSON as its CLI documents it, `shape.rs` (addresses, users, groups by tag, Session Manager), `vallic.rs` (environments as hosts), `cli.rs` (JSON read, stderr passed on, a missing CLI named). `crates/mg-store/src/model.rs`: `only_what_the_clouds_ids_look_like`. `apps/desktop/src-tauri/src/cloud.rs`: private machines and stopped ones, the reach command built here, a refresh following the platform and keeping what is the person's.
- `crates/mg-inventory/tests/console.rs`: the Vallic client against a fake console on loopback (device flow, rotation, a replayed token refused, the inventory).
- `crates/mg-inventory/tests/clis.rs`: the real CLIs, read only, printing counts only; ignored unless asked, e.g. `MG_TEST_AWS=1 [MG_TEST_AWS_PROFILE=…] cargo test -p mg-inventory --test clis -- --include-ignored --nocapture` (also `MG_TEST_AZ`, `MG_TEST_GCLOUD`, `MG_TEST_HCLOUD`, `MG_TEST_DOCTL`).
- e2e `apps/desktop/e2e/appimage.mjs`: Vallic Cloud through `vallic-console.mjs` (sign-in approved on the second poll, the key added to the account, no Files); AWS through the stand-in `e2e/clouds/aws` (an instance that is the test sshd, signing in with the vault key named like its key pair, a stopped one waiting, then the same source through Session Manager, which the stand-in relays with `crates/mg-ssh/tests/relay.py`); DigitalOcean through `e2e/clouds/doctl`. `run.sh` sets `MORPHGATE_VALLIC_CONSOLE`, `MORPHGATE_CLOUD_CLI_DIR`, `E2E_CLOUD_PORT` and `E2E_CLOUD_USER`.

## Limits

- Refreshing is on demand only, per source, on a desktop.
- Vallic Cloud: a source brings every project the sign-in reaches, grouped by project; no SFTP; its database and cache tunnels (`vallic-tunnel`) aren't offered, and neither are ordinary tunnels or agent forwarding (`no_forwarding`).
- Not supported: Azure Bastion (`az network bastion tunnel` listens on a port and can't carry a connection on stdin), Azure's Entra ID sign-in to VMs (`az ssh cert`). Windows machines are left out.
- A jump host set by hand on a kept host is replaced at the next refresh.
- Moving a source to another vault doesn't take its hosts (they don't ride with it); its next refresh there makes new ones.
