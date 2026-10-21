# Teams

A team (an organization in the code and the API) lets several accounts share vaults. The sync server decides who belongs where and stores ciphertext, certificates and sealed keys; it is never trusted about keys. The app does all the key work: it checks every account key against the organization's certificate chain, seals vault keys to members with a signed grant, and rotates a vault's key when someone loses access. Code: `crates/mg-store/src/sharing.rs` (trust, the per-round refresh, every team operation), `crates/mg-vault/src/sharing.rs` (fingerprints, certificates, grant and member key signatures), `apps/desktop/src-tauri/src/orgs.rs` (Tauri commands), `apps/desktop/src/TeamsPanel.tsx`, `apps/desktop/src/SsoSignIn.tsx`, `apps/desktop/src/ApprovalWait.tsx`.

## Before anything works

Teams go through sync. The sidebar shows **Teams** once sync is on. `sharing_status` says why teams are unavailable: no sync account ("Teams work through sync: turn on sync first (Sync in the sidebar).") or a server without `features.sharing` ("This sync server doesn't support teams.").

Every command that talks to the server runs through `with_client()`, which takes the sync lock (`SyncState.running`): a team operation never runs while a sync round does, and a rotated refresh token is saved afterwards. `orgs_list`, `vaults_list` and `member_keys` read the local database and work offline.

## Tauri commands

Paths are relative to the server's API base (`/v1`). The protocol is `spec/openapi.yaml` (tag `organizations`).

| Command | Does | Server calls |
| --- | --- | --- |
| `sharing_status` | Teams available here, this account's id and fingerprint | discovery |
| `orgs_list`, `vaults_list` | Organizations and vaults on this device | none |
| `orgs_locked` | Teams whose vaults are read-only for lack of a plan (only where `billing.plans_enforced`) | `GET /orgs/{org}` each |
| `org_create` | New organization, this account its owner and trust root | `POST /orgs`, then `POST /vaults` (directory) |
| `org_vault_create` | New shared vault | `GET /orgs/{org}`, `.../members`, `POST /vaults` |
| `org_members` | Members, each with fingerprint and `verified` | `GET /orgs/{org}`, `.../members` |
| `org_invite`, `org_invites`, `org_invite_cancel` | Invite, list pending, cancel | `POST`/`GET /orgs/{org}/invites`, `DELETE .../invites/{id}` |
| `invite_preview`, `invite_accept` | Look up an invite code, join | `GET /invites/{token}`, `POST /invites/{token}/accept` |
| `member_confirm` | Certify an accepted member and seal their vault keys | `POST /orgs/{org}/members/{id}/confirm` |
| `org_member_recertify` | Certify a confirmed member again | `PUT /orgs/{org}/members/{id}/certificate` |
| `member_role` | Make admin (with keys) or member | `PATCH /orgs/{org}/members/{id}` |
| `member_remove` | Remove someone, or leave when the id is this account | `DELETE /orgs/{org}/members/{id}` |
| `vault_access`, `vault_access_set`, `vault_access_revoke` | Who opens a vault; grant or change; take away | `GET`/`PUT`/`DELETE /vaults/{v}/members[/{id}]` |
| `vault_rotate` | New vault key for everyone who still has access | `POST /vaults/{v}/keys` |
| `org_transfer`, `org_delete` | Hand to an admin; delete (both prove the master password with the AuthKey) | `POST /orgs/{org}/transfer`, `DELETE /orgs/{org}` |
| `org_details`, `org_policies_set` | Policies, plan and what the server offers; save policies | `GET`/`PATCH /orgs/{org}` |
| `org_activity`, `org_events_export` | Audit log in the app; download as `csv` or `jsonl` | `GET /orgs/{org}/events`, `.../events/export` |
| `member_keys`, `member_key_publish`, `member_key_unpublish` | The member key directory (local; sync carries it) | none |
| `org_device_requests`, `org_device_decide` | Waiting and denied devices; approve or deny | `GET /orgs/{org}/devices`, `POST .../devices/{d}/approve` or `/deny` |
| `org_sso_status`, `org_sso_start` | Identity provider and this device's session; start a sign-in in the browser | `GET /orgs/{org}/sso`, `POST .../sso/start` |

## Fingerprints and signatures

All in `mg_vault::sharing`. Signed messages are `domain ‖ fields`, strings as `u16 length ‖ UTF-8`; the test `vectors` pins each format with values computed independently (Python `cryptography`).

| Object | Domain | Binds |
| --- | --- | --- |
| Fingerprint | `morphgate/v1/fingerprint` | Account id, encryption and signing public keys. First 20 bytes of SHA-256 (`FINGERPRINT_LEN`), shown as 8 groups of 4 Crockford base32 symbols |
| Member certificate | `morphgate/v1/member-cert` | Organization, account, both keys. Signed by an owner or admin when confirming |
| Admin certificate | `morphgate/v1/admin-cert` | Organization, account, signing key only. Signed by an owner; lets the admin sign member certificates |
| Owner certificate | `morphgate/v1/owner-cert` | Organization, account, both keys. Signed by the outgoing owner on transfer |
| Grant signature | `morphgate/v1/vault-key-grant` | Vault, key id, recipient, SHA-256 of the sealed key. Without it a server could seal a key of its own to a member and read what they write |
| Member key signature | `morphgate/v1/member-key` | Organization, account, OpenSSH public key. Only the member's own key makes it valid |

Certificates bind keys to accounts and grant nothing; access stays with the server.

## Whom the app trusts

`verify_org()` builds a `Trust` for each organization from what the server lists:

| Who | Trusted when |
| --- | --- |
| Root | Pinned in `orgs` when this device creates or joins the organization. A second device of the same account takes it from the owner chain on first sight (it never compared a fingerprint) |
| Owners | Each link of `owner_chain` verifies with the previous owner's key, starting at the pinned root ("the organization's root key isn't the one this device pinned", "the ownership chain is broken") |
| Admins | An admin certificate by a verified owner makes them a signer for member certificates; their own keys verify like a member's |
| Members | A member certificate by an owner or certified admin, or keys this device pinned earlier (`pinned_only`: their certifier has since left) |
| Vault keys | `shared_record()`: the current generation's grant must verify with a trusted member's key, or a former member's pinned key while `rotation_due` (so an admin can still rotate). An older generation that doesn't verify is left out; its items stay unreadable here |
| Vault names | The encrypted `meta` item verifies with its creator's key, or their pin after they left |

Every verified key is pinned in `pinned_keys` with the email. A known account whose keys change is a hard error, never a prompt: "the keys of {email} changed; they must be removed and invited again". Members who don't verify go to `Trust.unverified`; the member list says "Keys not verified yet" and nothing is sealed to them ("can't verify that member's keys").

## The pages

**Teams** (`TeamsPanel`) lists the teams this account is in as a table: Team, You are (its role, or "Joined" until an admin confirms it), Vaults you open, and Needs you, from what this device knows: "Turn on two-step verification", "Sign in with single sign-on", "This device waits for approval" (or "This device was denied"), "{n} devices to approve", "Publish your SSH keys", "Rotate a vault's key"; "An admin confirms you next" while waiting. **New team** is the page's primary action. Under the list: **Join with an invite** and **Your fingerprint**.

A team's page (`OrgView`) has the plan and single sign-on lines under its name, **Invite people** for owners and admins (its primary action), and **Needs you** above its tabs: members to confirm (**Confirm {name}…**) or certify again (**Verify…**), devices waiting (**Approve**, **Deny**), vaults whose key should be rotated (**Rotate key**), two-step verification the team requires, and the SSH keys it asks members to publish (**Publish a key**). Tabs: **Members** (members, then the invites not accepted yet: Role, Keys ("Verified", "To confirm", "Not verified"), SSH keys; then **Devices waiting**), **Vaults** (Items, You can, Key; **Access**, **Rotate key**), **Your SSH keys**, and for owners and admins **Settings** and **Activity**. Members see **Vaults** first. Before an admin confirms you, the page only says so, with your fingerprint and **Leave**. Lists are the tables of the other pages (`ListParts.tsx`).

## Creating a team

**New team** opens a bar: **Team name** (placeholder "Acme Ops"), **Create team**. `create_org()` picks a ULID, creates the organization, checks that the server put this account's real keys at the root of the owner chain, pins the root and creates the member key directory (if that fails, the next sync does it). A server with plans (such as morphgate.com) may refuse with `402 team_limit`, whose `limit` is how many teams an account may own without a plan. The app then says "you own {n} teams without a plan: choose a plan for one of them, or delete one, before creating another" and, on desktop, offers **Choose a plan ↗** (the account portal at `/account`); iOS and Android builds say "…, the most you can: delete one before creating another".

## Inviting

**Invite people** (owners and admins; disabled while the team is locked) opens a dialog.

| Control | Does |
| --- | --- |
| **Email addresses** (placeholder "colleague@example.com, another@example.com"), **Send invite** / **Send {n} invites** | Several at once, separated by commas, semicolons or spaces; each must be well formed (`^[^@\s]+@[^@\s]+$`, else "Not an email address: …") and at an allowed domain ("Invites go only to @…: not …"). One `org_invite` per address; those refused are named, the rest are sent |
| **Role** | Owners only ("Member: the vaults you give them", "Admin: every vault and member"); only the owner invites admins. Admin invites carry no vault grants |
| "Vaults they get once you confirm them" checkboxes | Members only; each ticked vault gets an access select, **Can edit** by default |
| "This server doesn't email invites. Send each person their code (it works once, for that address, for 7 days):", a code per address with **Copy code**, **Done** | When the server returned the tokens (`mails_invites: false`) |
| "Invite emailed to {emails}." | Otherwise |

Invites not accepted yet are rows of **Members**: "Invited · works until {date}", **Cancel invite**.

An invite page on the web opens `morphgate://invite?token=…&server=…` (or `morphgate://invite/{token}`). The app opens Teams with the code looked up, after checking that sync is on (otherwise it opens Sync, and Teams once sync is on) and that `server` is the server this device syncs with. Opened before the app has a vault, the first screen shows the invite and offers a new account with its address ([First run](vault-and-unlock.md#first-run)). A link never joins by itself. See [Deep links](deep-links.md).

## Joining

**Join with an invite**: **Invite code**, **Look up**. `preview_invite()` reads the invite and verifies its owner chain from the first link, then shows the team, the invited address, the role, the sender and the current owner's fingerprint. The person ticks **It matches the fingerprint they read to me** and chooses **Join {team}**.

`accept_invite()` reads the invite again and refuses when the owner's fingerprint is no longer the one shown ("the organization's keys changed while you were looking; check the fingerprint again") or when this device already pinned another root ("this organization's root key changed"). Then it accepts and pins the root. The member is `accepted`: the Teams list says "An admin confirms you next", and the team page shows their own fingerprint to read out, with **Leave**.

## Confirming and verifying members

An admin chooses **Confirm…** on a member marked "To confirm" (or **Confirm {name}…** in Needs you), asks them to read their fingerprint (Teams, on their device), ticks **It matches what they read to me** and chooses **Confirm {email}**. `confirm_member()`:

1. syncs the organization first (`refresh()`), then refuses a member already confirmed;
2. compares the fingerprint of the keys the server lists now with the one the admin compared ("their keys don't match the fingerprint you compared; compare again") and with any pin ("this account's keys changed");
3. seals every key generation of the granted vaults (every organization vault on this device for an admin; the invite's `pending_vaults` for a member), each with a grant signature;
4. sends the member certificate (and an admin certificate for an admin), then pins the member;
5. gives a plain member `write` on the member key directory.

On a server with plans (such as morphgate.com), when every seat of the team's plan is taken the server answers `402 seats_exceeded` and the app says "every seat of the organization's plan is taken: the owner can add seats in the account portal" (iOS and Android builds stop before the colon).

A member certificate counts only while its signer is an owner or admin. When the admin who confirmed someone leaves or is made a member, devices that never pinned that person stop trusting them. So in every sync round, an owner's or admin's device certifies again each member it trusts only through its own pin (`recertify()` with no fingerprint; the pin stands in). A server without the endpoint (404 or 405) is left alone. Confirmed members this device can't verify show **Verify…** to admins: compare the fingerprint, then **Certify {email} again** (`org_member_recertify`; "this sync server can't certify members again yet" without the endpoint).

## Roles

| Role | In the app |
| --- | --- |
| Owner | Everything below, plus the role select on members' rows, invites and confirms admins, removes admins, **Ownership** (transfer, delete), **Choose a plan ↗** / **Manage plan ↗** on desktop |
| Admin | Opens and manages every vault, invites members, confirms, removes members, policies, **Activity**, device decisions |
| Member | Opens the vaults granted, publishes SSH keys, approves their own new devices, creates vaults if the policy allows |

`set_role()` to admin verifies the member's keys, seals them every organization vault's key ring and adds an admin certificate. To member it sends no keys; the server drops access that came only with the role and flags those vaults for rotation.

**Transfer…** under **Ownership** on Settings (enabled once there is a confirmed admin; "To hand the team over, make someone an admin first.") signs an owner certificate for the chosen admin; the old owner stays an admin. **Delete team…** deletes it with all its vaults, then removes them from this device. Both ask for **Your master password**, sent as the AuthKey.

## Shared vaults and access

**New vault** (placeholder "Staging") is shown to owners and admins, and to members when `members_can_create_vaults` is on. `create_vault()` seals a new vault key to every confirmed owner and admin (each must verify: "can't verify the keys of {email}") and to the creator, and puts the name in an encrypted `meta` item signed by the creator, so the server never sees it.

| Access | Label | Can |
| --- | --- | --- |
| `read` | **Can view** | Use and read items; the sync engine never pushes |
| `write` | **Can edit** | Also add, change and delete items |
| `manage` | **Can manage** | Also see who has access, grant, revoke, rotate |

**Access** on a vault's row (Vaults tab; managers, not the directory) opens under it who has it. Owners and admins show "Can manage (owner or admin)" and can't be changed. **Give a member access…** lists confirmed plain members without access, with an access select (**Can edit** by default) and **Add**. `set_access()` only changes the permission for someone who already has the vault; a new grant verifies their keys and seals every key generation. **Remove** revokes, then explains: "They can't sync this vault anymore, but what they already had stays on their devices. Rotate the key (the button appears after the next sync) so they can't read anything added from now on, and change the passwords and keys they could see."

## Key rotation

The server sets `rotation_due` on a vault when anyone loses access to it: revoked, removed, left, or made a member again. The vault's Key column then says "Rotate" (to managers; "Rotation due" to others), Needs you says "{vault}'s key should be rotated: someone lost access since it was made.", managers get **Rotate key** ("Rotating…") there and on the row, and the sidebar shows **Teams · rotate a key**.

`rotate()` syncs the organization first, generates a vault key, seals it with a grant signature to every account the server lists as having access (each must verify), and switches with `previous_key_id` set to the current key (the server refuses a stale one with `409`). This device keeps every older generation in `vault_keys` and re-seals its own copies of the vault's items under the new key; the next sync pushes them. Any device with write access finishes what is left on its next sync, and a push under an old key (`stale_key`) is re-sealed and sent again. Rotation keeps the person who left out of what is written next; it can't take back what they synced. That is [Offboarding](offboarding.md).

## Each sync round

`refresh_with()` runs before the vaults sync (see [How sync runs](../architecture.md#how-sync-runs)):

1. Lists organizations; refetches only those whose `rev` changed (`RoundCache`; capabilities are kept for an hour, `CAPABILITIES_FOR`). Verification runs every round.
2. Verifies members and pins those that check out; owners' and admins' devices certify members again where needed.
3. Forgets organizations the account is no longer in (`orgs_gone`).
4. Lists vaults, checks each shared vault's grants and name, stores it.
5. Asks about each local shared vault missing from the list: `404` drops it; held for single sign-on or device approval, or any other answer, keeps it.
6. Owners' and admins' devices keep the member key directory (create it, grant every confirmed member `write`).
7. Reports approvals waiting, organizations asking this account for SSH keys, and per-organization errors (the rest go on).

## Leaving, removal, and a device no longer in a team

**Leave** in the member list (then **Really leave?**), or on the waiting notice of an unconfirmed member (**Really leave {team}?**), calls `member_remove` with this account's id; the device then forgets the organization and deletes its vaults and their items at once. The owner has no **Leave** (the server answers `409 sole_owner`). Removing a confirmed member goes through [Offboarding](offboarding.md); an accepted one has **Remove**, then **Really remove?**.

When a round finds the account in fewer organizations than the device knows (left on another device, removed, or the team deleted), it deletes those organizations and their vaults, and the window says once: "You're no longer in {teams}: you left on another device, an admin removed you, or the team was deleted. Its vaults left this device; your own vault is as it was." Pins stay, so a former member's grants, vault names and directory entries still verify.

## Policies

Owners and admins change them on **Settings**, grouped (Security, Members, Session logs), each with what it does and a switch or a field; **Save settings** and **Discard** appear once something changed. `org_policies_set` always sends the whole set.

| Policy | Control | Notes |
| --- | --- | --- |
| `require_totp` | **Require two-step verification** | Disabled without `features.totp` unless on ("This server doesn't offer two-step verification."). Members without it are told where they look for the vaults ([Two-step verification required](account-and-devices.md#two-step-verification-required)) |
| `members_can_create_vaults` | **Members can create vaults** | |
| `allowed_email_domains` | **Invite only these domains** (empty: any) | Split on commas and spaces, leading `@` dropped, lowercased; the invite form checks it too |
| `require_device_approval` | **Approve new devices** | Disabled unless the plan lists `device_approval` (or the server has no plans) or it is on, marked **Business plan** |
| `require_member_keys` | **Ask members to publish their SSH keys** (the app reminds those who haven't) | `Option<bool>`, sent only once set, since a server may refuse a policy it doesn't know. Only the apps act on it |
| `session_log_retention_days` | **Delete session logs after** {n} days (0 keeps them) | Only with `features.blobs`; 0 to 3650 (`min(3650)`) |
| `require_sso` | None; a **Single sign-on** row saying "Required" when on | Set on the server along with the identity provider (on the reference server, `vault-sync-server sso --require`); sent back unchanged |

The server enforces every policy but `require_member_keys`. It may check more than the app does: the reference server refuses an entry in `allowed_email_domains` that isn't a domain name ("not a domain: …"), and refuses `require_totp` with `501 not_supported`, since it has no two-step verification.

## Plans

On a server with plans (such as morphgate.com), `org_details` carries the team's plan. The team page shows what the server reports: "{Plan} trial until {date}", "{Plan} plan, renews {date}", "The {Plan} plan ended {date}. Shared vaults keep syncing until {date}." (status `grace`), or "No plan", with seats used. Where the server enforces plans (`billing.plans_enforced`) and the team has no usable plan (`trialing`, `active` or `grace`), the team is locked: invites, policies, new vaults, publishing keys, device decisions, confirming and role changes are disabled, and its vaults count as view-only everywhere in the app (`orgs_locked`, `vaultEntries()`). Removing people, leaving, transferring and deleting stay possible. Phones and iPads (`mobileOs`) show no plan buttons: the app stores don't allow pointing at purchases outside them.

## Device approval, single sign-on and activity

- **Devices waiting** (Members tab) lists pending and denied devices (everyone's for owners and admins, your own otherwise) with **Approve** and **Deny**; pending ones are in Needs you too; this device's own row says "Approve it from another of your devices". A device that waits shows **Waiting for approval · {team}** (or "{team} denied this device") in the sidebar, which opens the `ApprovalWait` dialog (**Check again** syncs now).
- With a provider configured, the team page says "Single sign-on at {host}" and either "This device is signed in until {time}" or **Sign in**. Held vaults show **Sign in to {team}** in the sidebar. `SsoSignIn` opens the provider in the browser (`org_sso_start`), polls `org_sso_status` every 2 seconds (`POLL_MS`) until a session appears, then syncs; past `expires_in` it says "The sign-in expired. Start it again." The provider's protocol (OpenID Connect or SAML) is the server's business; the app only opens the address the server gives.
- The **Activity** tab (owners and admins): `org_activity` reads every page (1000 events each, at most `ACTIVITY_PAGES` = 1000 pages) and keeps the newest `ACTIVITY_KEPT` = 5000; the panel shows 50 at a time (**Show older**). Names come from pinned emails and local vault names ("a former member", "a vault you can't open"). **Download CSV** and **Download JSON lines** save `morphgate-activity-{team}-{date}.{csv|jsonl}` in Downloads.

## Member key directory

Offboarding needs to know which `authorized_keys` lines belong to someone, so members publish the public halves of the keys they use on the team's servers. The directory is an ordinary organization vault named "Member keys" (`DIRECTORY_NAME`) whose encrypted meta says `directory: true`, so servers need nothing new. Owners' and admins' apps create it and keep every confirmed member at `write`; if two appear, the lowest id is used. On the Vaults tab it shows as "Member keys" ("Members' SSH public keys"), **Every member**.

**Your SSH keys** (until the directory reaches this device: "The organization's member key directory arrives with the next sync."): **Publish one of your keys…** lists the SSH keys of the personal vault not yet published; **Publish** (`member_key_publish`) stores a `member_key` item (`account_id`, `public_key` as OpenSSH `type base64`, `label`, `sig`) signed by this account; publishing the same key again returns the existing entry. **Unpublish** deletes the item. A reader accepts an entry only if its signature verifies with that member's own pinned key, so nobody else, the server included, can publish a key in someone's name; an entry still verifies after its author leaves. The member list's SSH keys column shows "{n} published" (verified entries only). With `require_member_keys` on, members without one show "None yet", Needs you asks them to publish one (**Publish a key**), and the sidebar shows **Teams · publish your keys**.

## Data on this device

| Table | Holds |
| --- | --- |
| `orgs` | Id, name, role, status, the pinned root (account, encryption and signing keys) |
| `pinned_keys` | Every account key this device verified, with the email; never removed |
| `vaults` | Shared vaults: `org_id`, `permission`, `name`, `rotation_due`, `directory`, the current sealed key |
| `vault_keys` | Every key generation sealed to this account; deleting a vault deletes these and its items |

Schema: [The SQLite schema](../architecture.md#the-sqlite-schema).

## Errors

| Text | When |
| --- | --- |
| "a vault key was sealed by an account this device can't verify" | A grant by someone outside the trust; the vault isn't stored ("Shared vaults: …" in the sync status) |
| "a vault key's grant signature doesn't verify" | Forged or damaged grant |
| "the server offered the personal vault as a shared one" | A server listing this account's personal vault in an organization |
| "the organization has no member key directory yet; sync first" | Publishing before the directory arrived |
| "you have no access to this vault" | Rotating a vault this account can't open |
| `{message} ({code})` | Any other API refusal, as the server worded it |

## Tests

| Where | Covers |
| --- | --- |
| `crates/mg-vault/src/sharing.rs` tests | Signature vectors, fingerprint shape, what each signature binds |
| `crates/mg-store/src/sharing.rs` tests | Owner chain, admin and member certificates, forged links, pins against swapped keys |
| `server/tests/shared_vaults.rs`, `recertify.rs`, `device_approval.rs` | The app's store and sync engine against the reference server: sharing, moving items, single sign-on holds, re-certification, the member key reminder, approvals |
| `server/tests/sharing.rs` | The protocol at the API level |
| `tools/vault-conform`, group `sharing` | Any server, with real certificates and sealed keys (`--only sharing` needs 3 accounts) |
| `apps/desktop/e2e/teams.mjs` | Two packaged apps (Alice and Bob) and a reference server: invite, fingerprints, confirm, shared edits, revoke, rotate, policies, member keys, device approval, offboarding, single sign-on. `E2E_SKIP_BUILD=1 E2E_ONLY=teams apps/desktop/e2e/run.sh` |

## Limits

- A device joined to a team on another device pins the root without a fingerprint comparison.
- The app can't turn `require_sso` on or change it; that happens on the server, with the identity provider.
- No renaming an organization or a shared vault, and no deleting a shared vault, from the app (`UpdateOrg` is sent with `name: None`).
- Only personal-vault SSH keys can be published.
- Every admin sees **Confirm…** for an invited admin, but only the owner may confirm admins: the server refuses anyone else.
- In a locked team the vaults are view-only in the panel too, so **Access** and **Rotate key** don't show, although the lock notice says taking access away and rotating still work (the server allows both). Rotating through [Offboarding](offboarding.md) does work. Device decisions are disabled too, though the protocol defines no `402` for them.

## Related

- [Offboarding](offboarding.md), [Deep links](deep-links.md), [Sync](sync.md), [Session logs](session-logs.md), [Architecture](../architecture.md#keys-in-one-picture), [Reference server](reference-server.md)
- [Sharing](../sync-crypto-spec.md#sharing) in the sync and crypto spec; the protocol in `spec/openapi.yaml`
