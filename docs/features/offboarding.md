# Offboarding

When someone leaves a team, removing them stops what comes next, not what they already synced: their devices keep the copies they had. Offboarding walks an owner or admin through the rest: what the person could read, removal with key rotation, their SSH keys on the organization's hosts, and the shared secrets to change, with a shared SSH key replaced on every host that uses it. Code: `apps/desktop/src-tauri/src/offboard.rs` (Tauri commands), the `Offboard` component in `apps/desktop/src/TeamsPanel.tsx`, `crates/mg-ssh/src/authorized_keys.rs`, `Sftp::replace_file()` in `crates/mg-ssh/src/sftp.rs`. Removing and rotating are the [Teams](teams.md) commands `member_remove` and `vault_rotate`.

## Opening it

In a team's member list, **Remove…** next to a confirmed member opens the page "Remove {email}" (back: "← {team}"). Owners see it for members and admins, admins for plain members; nobody sees it for the owner or themselves. People who accepted but were never confirmed have nothing to rotate: **Remove**, then **Really remove?**, takes them off without offboarding.

## Tauri commands

| Command | Does | Talks to |
| --- | --- | --- |
| `offboard_summary` | What the member can open and what that exposes (owners and admins) | `GET /vaults/{v}/members` for each organization vault on this device |
| `offboard_scan` | Counts the member's published keys in each organization host's `authorized_keys` | Each host, over SFTP |
| `offboard_clean` | Removes those lines from the chosen hosts | Each host, over SFTP |
| `key_replace` | Replaces a vault SSH key with a new one on every host that logs in with it, then in the vault | Each host, over SFTP |

## 1. What they can open

`offboard_summary` asks the server for the member's permission on each of the organization's vaults on this device, and counts what is in them from this device's copy. Each vault shows its name, their access (**Can view**, **Can edit**, **Can manage**) and its contents; the member key directory says "Members' public SSH keys (nothing secret)". Under the list: "Whatever they synced stays on their devices: removing them stops what comes next, not what they saw."

| Item kind | Counted as | Listed in step 4 |
| --- | --- | --- |
| Host | host | "Password of {label}" when it has a saved password |
| Identity | other item | "Password of {label}" when it has a saved password |
| SSH key | SSH key | "SSH key {label}", with "used by {hosts}": hosts that log in with it, directly or through an identity or group (`effective_host()`) |
| VPN profile | VPN | "VPN profile {label}" |
| Member key | not counted | |
| Anything else | other item | |

The summary also carries their published SSH keys that verify (fingerprints), the ones step 3 looks for.

## 2. Remove and rotate

**Remove {email} and rotate keys** ("Working…") removes them once (`member_remove`), then rotates each vault from step 1 in turn (`vault_rotate`), listing "New keys: {vaults}". If a rotation fails, the error shows and the button becomes **Rotate the rest**. When all are done: "Removed; every vault they had has a new key." Rotation seals a new key to everyone who still has access and re-seals the items; see [Key rotation](teams.md#key-rotation). Their devices drop the team's vaults at their next sync and say so ([Teams](teams.md#leaving-removal-and-a-device-no-longer-in-a-team)).

## 3. Their SSH keys on your hosts

The app looks for the member's entries in the [member key directory](teams.md#member-key-directory), only those whose signature verifies with the member's pinned key. Pins outlive membership, so this still works after step 2. With none: "They published no SSH keys, so the app can't tell which lines in authorized_keys are theirs. Check the hosts by hand."

The hosts are every host item in the organization's vaults on this device (the directory aside), sorted by label. Each is reached as it is saved: its stored credentials, jump hosts, VPN and proxy, the vault's host CAs, and `known_hosts` with the usual host key prompt, within 15 seconds (`CONNECT`). A host whose login asks for a password every time is skipped: "asks for a password every time (save one to include it)".

| Control | Does |
| --- | --- |
| **Check hosts** ("Checking hosts…", then **Check again**) | `offboard_scan`: reads `.ssh/authorized_keys` (relative to where SFTP starts, the login's home) on each host; each row says "{n} of their keys found", "none of their keys", or the problem |
| **Remove from {n} host(s)** ("Removing…") | `offboard_clean` for the hosts with matches; each row then says "{n} lines removed" or the problem |

The file is edited with these safety checks (`authorized_keys.rs`, `edit_keys()`):

| Check | Detail |
| --- | --- |
| Key material decides | `line_key()` reads `type base64` with or without an options field (quoted spaces and escapes handled). The comment doesn't matter; blank and `#` lines are never matched |
| Every other byte kept | Only matching lines go; other keys, options, comments, blank lines and CRLF endings stay as they were |
| No needless write | Nothing is written when the result equals the file |
| Atomic replace | A temporary `authorized_keys.morphgate-{12 hex}` is created exclusively, synced where the server offers `fsync@openssh.com`, given the file's mode, then renamed over the file with `posix-rename@openssh.com`. Without that extension: "{path}: this server can't replace files atomically (no posix-rename@openssh.com)". The temporary file is removed on failure |
| Permissions | The file keeps its mode; a new one gets `0600`, and a missing `.ssh` is created `0700` (sshd refuses files others can write) |
| Read back | The file is read again after writing; a difference fails with "the file changed while it was being edited; check it by hand" |
| Something to look for | `offboard_clean` refuses without published keys: "they published no SSH keys to look for" |

## 4. Change what they could see

A checklist of the secrets from step 1; the ticks belong to the page and are gone when it closes. Passwords and VPN profiles are changed by hand (on the server or the VPN provider, then in the item). SSH keys have **Replace key** ("Replacing…"); a replaced key shows "replaced ({fingerprint})", and "; the old key is still on {hosts}" when removing it failed somewhere. A failure shows its message in the row.

### Replacing a shared SSH key

`key_replace` changes the key without locking anyone out:

1. Refuses a key in a vault this account can only view ("you can view this vault but not change it") or one without a readable public key ("the stored key has no readable public key").
2. Generates an Ed25519 key with the old label, and finds the hosts in the key's vault whose effective login is this key. If one of them takes its keys from a cloud account rather than `authorized_keys` (a Vallic Cloud host: a shell in the customer's container, keys on the person's Vallic account), it stops there, since the new key couldn't be installed on it and the host would lose its way in: "\"{key}\" signs in to {host} on {cloud}, which takes keys from your account there, not from the host: give its hosts another key first (Clouds), then replace this one".
3. On each host, logs in as saved (with the old key), adds the new public key, then logs in with the new key. A failure: "the new key was installed but doesn't log in: {why}".
4. If any host failed, takes the new key off every host it went onto and stops, the vault unchanged: "nothing was changed; the new key couldn't be set up on every host. {host}: {problem}; …".
5. Writes the new key into the same vault item, so every host, identity and group keeps pointing at it: new private and public key, algorithm and fingerprint, no passphrase, no certificate (it certified the old key; a key with renewal gets a new one at its next renewal). The next sync shares it.
6. Removes the old key from each host, now logging in with the new one. A failure doesn't undo anything; the host is reported with "the old key is still accepted here: {why}".

## Tests

| Where | Covers |
| --- | --- |
| `apps/desktop/e2e/teams.mjs` | Against a local sshd: Alice removes Bob and rotates every vault he had; Bob's device says he's no longer in the team; Alice finds Bob's published key on a shared host and removes it; she replaces the host's shared key and still logs in. `E2E_SKIP_BUILD=1 E2E_ONLY=teams apps/desktop/e2e/run.sh` |
| `crates/mg-ssh/src/authorized_keys.rs` tests | Keys found behind options and comments, only matching lines removed with every other byte kept, a key added once |
| `crates/mg-ssh/tests/live.rs`, `authorized_keys_are_replaced_atomically` | Read, write and remove against a real sshd; ignored unless `MG_TEST_SSH` is set (see the file's header for the command) |

`offboard.rs` itself has no unit tests.

## Limits

- Only `.ssh/authorized_keys` in the saved login's home directory is read. Other accounts on the host, `authorized_keys2`, an `AuthorizedKeysFile` elsewhere, and keys managed by configuration management are not seen.
- Hosts that let people in by their cloud account (Vallic Cloud's: a shell in the customer's container, no SFTP, no `authorized_keys`) aren't checked or cleaned: their row says "skipped: {cloud} lets people in by their account there, not by authorized_keys; remove their access there" (`account_cloud()` in `offboard.rs`).
- Only hosts saved in the team's vaults on this device are checked, one after another. Keys the member never published can't be found.
- **Replace key** reaches only the hosts in the key's vault that log in with it. A copy installed anywhere else keeps working until it is removed by hand; a key no host uses is replaced in the vault only.
- On a server that enforces plans (`billing.plans_enforced`), a team without a usable plan refuses the push of the new key, while step 6 has already removed the old key from the hosts: other members keep the old key until the push goes through.
- Step 2 skips a vault whose name matches one already rotated in this run (`rotation.includes(v.name)`). With two vaults of the same name, the second keeps its old key, though the page says every vault has a new key; its **Rotate key** stays in the team page.

## Related

- [Teams](teams.md), [SSH connections](ssh-connections.md), [SSH keys and agents](ssh-keys-and-agents.md)
- [Sharing](../sync-crypto-spec.md#sharing) in the sync and crypto spec, for what removal and rotation guarantee
