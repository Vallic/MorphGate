# MorphGate — Sync & Crypto Spec

Oct 16, 2026 · Valentino Međimorec

## Overview

The server is a dumb, zero-knowledge blob store behind a published OpenAPI contract ([`spec/openapi.yaml`](../spec/openapi.yaml)), so anyone can run their own and the client treats hosted and self-hosted servers identically.

**Goals**

- End-to-end encrypted sync of hosts, keys, identities, snippets, port-forward rules and known_hosts across devices.
- One open protocol (`vault-sync/v1`): the hosted service at morphgate.com is one implementation of it, and [`server/`](../server) is the reference.
- Offline-first: the client works fully without a server; sync is additive.
- Shared vaults for teams, in the open protocol behind the `sharing` capability (see Sharing).

**Non-goals (v1)**

- Server-side terminal relay or recording (session logs are recorded and sealed on the device).
- Server-side search or any feature needing plaintext.

## Threat model

A fully compromised server, ours or a self-hoster's, learns metadata only: account email, item count, sizes, timestamps and device list. It never sees hostnames, usernames, keys or passwords.

| Adversary | Can | Cannot |
| --- | --- | --- |
| Malicious / breached server | Read ciphertext and metadata, drop or replay old blobs, deny service | Decrypt items, forge items (AEAD + signatures), make a client accept a vault revision below one it has seen |
| Network attacker | Nothing beyond TLS failure | Anything: TLS required (the client refuses plain `http://` except to this computer), plus E2E |
| Stolen unlocked device | Everything in that vault | Survive revocation for future changes |
| Stolen locked device | Offline brute-force of master password | Succeed quickly (Argon2id, high cost) |
| Malicious self-host operator | Same as breached server | Same as breached server |

**Rollback defense.** Each client remembers the highest vault revision it has seen. A server answering with a lower one is flagged as an error, not silently accepted. The rollback guard covers the vault's revision, not each item's history.

**KDF bounds.** KDF parameters come from the server at prelogin, so the client enforces floors (≥ 64 MiB, ≥ 2 passes, ≥ 16-byte salt) and refuses to derive below them, and ceilings (≤ 1 GiB, ≤ 10 passes, ≤ 64-byte salt), so a server can't make a device allocate or compute without bound.

**Metadata hygiene.** Item type and size are inside the ciphertext where possible. Padding to 256-byte buckets hides exact sizes.

## Key hierarchy

The master password never leaves the device. It unlocks one account keypair, which in turn unwraps a random key per vault. That extra layer is what makes password changes cheap and team sharing possible.

A master password is set (on creating a vault, changing it, or recovering) only if it has at least 10 characters and zxcvbn estimates at least 10^10 guesses for it. With Argon2id at 256 MiB per guess, that's months of a GPU rig's time for an offline attack on a stolen device or server copy. There are no character-class rules ("one digit, one symbol"): they produce predictable passwords (`Summer2024!`) that the estimate refuses, and passphrases of unrelated words pass (NIST SP 800-63B). Passwords set earlier keep working.

```text
Master password ──Argon2id(salt)──▶ MK
MK ──HKDF──▶ AuthKey   (sent at login; server stores a slow hash)
MK ──HKDF──▶ KEK       (never stored)
KEK ─────────wraps──▶ Account keys (X25519 + Ed25519) ◀──wraps── Recovery key
Account X25519 ──sealed box──▶ Vault key (VK, one per vault)
VK ──XChaCha20-Poly1305──▶ Items
```

**Primitives (all via audited Rust crates: `argon2`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `hkdf`)**

| Key | Derived / generated | Used for | Stored on server as |
| --- | --- | --- | --- |
| Master password | User | Input to KDF | Never |
| `MK` master key | Argon2id(password, salt), m=256 MiB, t=3, p=1 | Derive `KEK` and `AuthKey` via HKDF | Never |
| `AuthKey` | HKDF(MK, "auth") | Server login proof (server stores Argon2id of it) | Hash only |
| `KEK` | HKDF(MK, "kek") | Wraps the account private keys | Never |
| Account keys | Random X25519 (encryption) + Ed25519 (signing) | Wrap vault keys; sign items | Public: plain. Private: XChaCha20-Poly1305(KEK) |
| `VK` vault key | Random 256-bit per vault | Encrypt items in that vault | Sealed box to account X25519 public key |
| `RK` recovery key | Random 256-bit, shown once as a 56-symbol code | Alternate unwrap of account private keys | Private keys wrapped under RK too |

**Item encryption.** Each item is XChaCha20-Poly1305 under `VK` with a random 192-bit nonce. Associated data = `vault_id ‖ item_id ‖ schema_version`, so blobs cannot be swapped between items or vaults.

**Password change.** Re-derive `MK`, re-wrap the account private keys, upload. No item is re-encrypted.
With sync on, the server takes the new credentials first (`PUT /account/keys` with the current
`AuthKey` as proof) and the device stores them only after that, so the two never disagree. Every
other device is signed out. It keeps opening with the old password until the user signs in again
there; that sign-in downloads the new wrapping, checks it unwraps to the device's own account keys
(same public keys), and stores it, so the local vault opens with the new password from then on.

**New recovery key.** Same `PUT /account/keys`, with the unchanged password material plus
`recovery`. The old key stops working everywhere; nobody is signed out.

**Sharing.** Each member of a shared vault gets `VK` sealed to their X25519 key, signed by whoever sealed it. The server stores one sealed `VK` per member per key generation. See Sharing.

**KDF parameters** travel with the account (`kdf: {alg, m, t, p, salt}`) so they can change per account (never below the floors above).

## Wire formats (as implemented in `crates/mg-vault`)

All HKDF is HKDF-SHA256; all info strings are prefixed `morphgate/v1/`.

| Object | Format |
| --- | --- |
| `AuthKey` | HKDF(MK, info=`auth`) |
| `KEK` | HKDF(MK, info=`kek`) |
| `wrapped_private_keys` | `nonce(24) ‖ XChaCha20-Poly1305(KEK, aad=account-keys, x25519_sk ‖ ed25519_sk)` |
| `wrapped_private_keys_rk` | same, key = HKDF(RK, info=`recovery-kek`) |
| `recovery_proof` | HKDF(RK, info=`recovery-auth`) |
| Recovery code | Crockford base32 of `RK ‖ SHA-256(recovery-check ‖ RK)[..3]`: 56 symbols, 14 groups of 4; decoding ignores case/dashes, maps I/L→1, O→0, rejects typos via the 24-bit check |
| `wrapped_vault_key` | `0x01 ‖ eph_pk(32) ‖ nonce(24) ‖ AEAD(k, aad=0x01‖eph_pk‖recipient_pk, key_id(16) ‖ VK(32))`, `k` = HKDF(X25519(eph, recipient), salt=eph_pk‖recipient_pk, info=`vault-key-seal`); low-order points rejected |
| Envelope | `0x01 ‖ key_id(16) ‖ nonce(24) ‖ ct ‖ sig(64)` |
| Blob | `0x01 ‖ key_id(16) ‖ nonce(24) ‖ XChaCha20-Poly1305(VK, aad, pad₄ₖ(plaintext))`, aad = `blob ‖ u16 len ‖ vault_id ‖ u16 len ‖ kind ‖ 0x01 ‖ key_id`; named by lowercase hex SHA-256 of the whole blob; no signature (the signed item that refers to it holds the hash) |
| Envelope AAD | `u16 len ‖ vault_id ‖ u16 len ‖ item_id ‖ u16 schema_version ‖ 0x01 ‖ key_id` |
| Envelope signature | Ed25519 over `envelope-sig ‖ u32 len(aad) ‖ aad ‖ version ‖ key_id ‖ nonce ‖ ct`; verified before decrypting |
| Padding | ISO/IEC 7816-4 (`0x80` then zeros) to a multiple of 256 bytes |
| Vault `meta` | An envelope with item id `vault-meta` (JSON `{name, directory?}`), under the vault key, signed by the vault's creator (`created_by`) |

Sharing (`crates/mg-vault/src/sharing.rs`). Strings are `u16 len ‖ UTF-8`; test vectors in the module, computed independently:

| Object | Format |
| --- | --- |
| Fingerprint | SHA-256(`fingerprint` ‖ account_id ‖ enc_pub ‖ sign_pub)[..20], as 32 Crockford base32 symbols in 8 groups of 4 |
| Member certificate | Ed25519 over `member-cert` ‖ org_id ‖ account_id ‖ enc_pub ‖ sign_pub |
| Admin certificate | Ed25519 over `admin-cert` ‖ org_id ‖ account_id ‖ sign_pub |
| Owner certificate | Ed25519 over `owner-cert` ‖ org_id ‖ account_id ‖ enc_pub ‖ sign_pub |
| Grant signature | Ed25519 over `vault-key-grant` ‖ vault_id ‖ key_id(16) ‖ recipient account_id ‖ SHA-256(wrapped_vault_key) |
| Member key signature | Ed25519 over `member-key` ‖ org_id ‖ account_id ‖ public key (OpenSSH `type base64`, no comment) |

## Data model

The server knows three things: accounts, vaults and items. Items are opaque envelopes, and everything typed lives inside the ciphertext.

**Server-visible item record**

```json
{
  "id": "01JABC…",            // ULID, client-generated
  "vault_id": "01JVLT…",
  "rev": 1842,                 // server-assigned, monotonic per vault
  "base_rev": 1790,            // rev the client edited from
  "deleted": false,            // tombstone flag
  "device_id": "01JDEV…",
  "author_id": "01JACC…",      // sharing: who pushed this revision (set by the server)
  "envelope": "base64…",       // see above
  "updated_at": "2026-10-16T10:00:00Z"
}
```

**Plaintext item types (client-only schema, `schema_version` 1)**

Serialized as JSON with a `type` tag, then sealed into an envelope.

| Type | Fields | Status |
| --- | --- | --- |
| `host` | label, hostname, port, user, auth (`password {password?}` \| `key {key_ref}` \| `agent`), jump_ref? (host to tunnel through, chains allowed, no loops, ≤ 8 deep), vpn_ref? (VPN for the first hop), theme_ref? (a `terminal_theme` in the same vault, or `builtin:<id>` for one built into the app), record_sessions?, keep_session? (attach to a tmux session on the server), group_ref? (a `host_group`), identity_ref? (an `identity`, instead of user and auth; user may then be empty), tags, notes | Implemented |
| `vpn` | label, vpn (`wireguard {config}`: wg-quick text incl. private key) | Implemented |
| `ssh_key` | label, private_key (OpenSSH/PEM, as imported), passphrase?, public_key, algorithm, fingerprint | Implemented |
| `snippet` | name, body, tags | Implemented (storage only) |
| `identity` | label, user, auth (as a host's) — shared credentials hosts refer to | Implemented |
| `host_group` | name, identity_ref?, jump_ref?, vpn_ref?, theme_ref?, keep_session? — a host takes what it leaves empty from its group (credentials only when its user is empty); deleting a group makes those values the hosts' own | Implemented |
| `attachment` | name, host_ref?, blob, size (see Blobs) | Implemented |
| `session_log` | see Blobs | Implemented |
| `port_forward` | label, host_ref, rule (`local` \| `remote` {bind_host, bind_port, target_host, target_port} \| `dynamic` {bind_host, bind_port}) | Implemented |
| `known_host` | host pattern, key type, public key | Planned (today: local known_hosts file) |
| `cloud_source` | label, provider, endpoint?, key_ref?, account — a cloud account whose machines become hosts, kept in step with it ([cloud sources](features/cloud-sources.md)) | Implemented |
| `host_ca` | label, public_key, hosts (patterns) — a CA whose signed host keys are trusted for those hosts (`@cert-authority`) | Implemented |
| `terminal_theme` | name, background, foreground, cursor, cursor_accent, selection_background, selection_foreground?, ansi (16 colors), all `#rrggbb`; imported from Ghostty, Alacritty, iTerm2 or Windows Terminal theme files | Implemented |
| `member_key` | account_id, public_key (OpenSSH `type base64`), label, sig (member key signature, hex) — only in an organization's directory vault | Implemented |

New fields are additive; readers ignore unknown fields, so `schema_version` only changes for breaking changes.

References between items (`*_ref`) are item ids. They resolve client-side only, so the server cannot see the graph.

## Local vault (`crates/mg-store`)

The client is offline-first: the vault exists on the device before any server is involved, and its rows are exactly what sync will push.

- One SQLite file in the app data dir (`vault.sqlite3`, mode 0600, `secure_delete` on).
- `account`: KDF params, public keys, `wrapped_private_keys`, `wrapped_private_keys_rk` (same values the server gets at register).
- `vaults`: id, `key_id`, `wrapped_vault_key`, `head_rev` (highest server revision seen, for the rollback guard).
- `items`: id, vault_id, envelope (NULL for tombstones), `deleted`, `rev` (server rev the copy is based on; 0 = never synced), `dirty` (unpushed local change), `updated_at`.
- Nothing typed is stored in plaintext: hostnames, users, passwords and keys exist only inside envelopes.
- Unlock = Argon2id + unwrap account keys + open vault key, all in memory. Lock drops every key and closes open sessions.
- Optional per device: a random device key in the OS keychain (`device_unlock` holds the account keys wrapped under HKDF(device key, `device-kek`)). It unlocks without the master password, survives password changes and recovery, never syncs, and is tried automatically only at app launch. The device can also require Touch ID, Windows Hello or polkit (Linux) before the key is read. That is a check made by the app: it stops someone at an unlocked computer, not malware running as the user.
- Every read verifies the envelope signature and its binding to `(vault_id, item_id)`; a tampered or swapped row fails loudly instead of being skipped.
- Shared vaults: items are keyed by `(vault_id, id)` and keep their `author_id`. `vault_keys` holds every key generation sealed to the account, `orgs` the pinned root of each organization, and `pinned_keys` every account key the device verified. Items in the personal vault verify only against the account's own key, whatever author a server names. References (`*_ref`) must stay within one vault. A vault this account lost access to is removed from the device on the next sync.
- Secrets flow one way: the UI sends passwords/keys into the Rust core, and views returned to the UI carry only `saved: true` / fingerprints.

## Sync protocol

Sync is a per-vault revision log. Pull is "give me everything after rev N". Push is a batch with optimistic concurrency per item. Conflicts resolve on the client, because only the client can read the data.

1. **Pull.** `GET /vaults/{id}/changes?since={rev}&limit=500` returns items with `rev > since` (tombstones included) plus `head_rev`. Page until `has_more = false`.
2. **Decrypt & apply.** Verify signature, decrypt, merge into local SQLite. Store `last_rev`.
3. **Push.** `POST /vaults/{id}/changes` with a batch of `{id, base_rev, deleted, envelope}`.
    - Server accepts an item if its current rev equals `base_rev`, or the item is new.
    - Otherwise it rejects that item with `conflict` in the per-item result and returns the current server copy.
    - Accepted items get a new `rev`. The batch is atomic per item, not per batch.
4. **Resolve conflicts.** The server's copy wins for that item id, and the local edit that lost is kept as a new item named "(conflict)", so nothing is silently discarded. Conflict copies are ordinary items: they stay until someone deletes them.
5. **Realtime nudge (optional).** `GET /vaults/{id}/events` via SSE sends only `{head_rev}`. Clients then pull. Self-hosters can skip this; clients fall back to polling: every 60 s while someone uses the app, every 5 minutes while nobody does (window hidden, or no input for 5 minutes), and at once on coming back. Local edits push within seconds either way.
6. **Quiet rounds are cheap.** A round lists the account's organizations (`GET /orgs`) and vaults (`GET /vaults`). A vault whose `head_rev` there equals the device's `last_rev` isn't pulled. An organization whose `rev` (optional) equals the one the device saw last isn't fetched again: its details, members, device approvals and vault members are reused, and verified again locally (the device's own pins may have changed). So a quiet round is two requests, however many organizations and vaults there are.

**Tombstones.** Deletes are items with `deleted: true` and an empty envelope. The server keeps them for at least 90 days. A client whose `last_rev` is older than the oldest retained tombstone gets `410 Gone` and does a full resync.

**Blobs and session logs.** What is too big for an item goes in a blob
(`/vaults/{id}/blobs/{hash}`, behind `features.blobs`): sealed under the vault key (Wire formats),
named by the SHA-256 of its bytes, uploaded separately, and referred to by a signed item that
carries the hash. The server checks the name, the size and the owner's quota, never the content;
`kind` is `session_log` or `attachment` (a server may keep them apart, e.g. for retention). Clients
upload a blob before the item that names it, keep refused uploads (`402`, `413`) for later rather
than failing the sync, delete the blobs of items they delete, and drop local copies no live item
refers to. A blob that comes back from the server is checked against its hash before it is
opened.

A **session log** item (`type: session_log`) records one terminal session of a host with
`record_sessions`: `host_ref`, `title`, `address`, `started_at`/`ended_at` (Unix ms), `cols`,
`rows`, `output_bytes`, the recording `device`, and `chunks` (`{hash, size}` in order). Each
chunk's plaintext is a raw DEFLATE (RFC 1951) stream; inflated and concatenated in order, the
chunks are an asciicast v2 file (a header line, then `[time, "o", output]` and
`[time, "r", "COLSxROWS"]` events). Recorders seal a chunk every 512 KiB of asciicast or 60 s and
update the item each time, so a crash loses little. An organization's
`session_log_retention_days` makes the server delete older session log blobs; a log whose
chunks are gone says so instead of playing.

An **attachment** item (`type: attachment`) keeps one file with a host: `name`, `host_ref`, `blob`
(the hash) and `size` (plaintext bytes), the file sealed whole into one `attachment` blob (up to
20 MiB, so it stays under servers' 25 MiB blob limit). Deleting the host deletes its attachments.

**Limits.** Max envelope 64 KiB, max 500 items per push. Servers advertise their own limits in capabilities.

## Auth & devices

Login proves knowledge of `AuthKey` and returns short-lived tokens. The client never sends the master password, and the server can't derive `KEK` from what it stores.

1. `POST /auth/prelogin {email}` returns `kdf` params and salt. For unknown emails it returns deterministic fake params to avoid user enumeration.
2. The client validates the params against the floors, derives `MK`, then `AuthKey`.
3. `POST /auth/login {email, auth_key, device}` returns `access_token` (15 min, opaque), `refresh_token` (rotating, 90 days; replaying a used one revokes the device), and the wrapped account keys.
4. The client unwraps the private keys with `KEK`. If the user opts in, a device key in the OS keychain can unlock them later (see Local vault).

**Devices.** Each login registers a device (`name`, `platform`, public Ed25519 key). `GET /devices` lists them and `DELETE /devices/{id}` signs one out: its tokens stop working, and its next refresh gets `401 device_revoked` (servers keep answering that for the refresh token's lifetime), on which the app erases what it keeps (vaults, keys, settings, pinned host keys, its keychain entry) and returns to first run with a note saying why. Only that code erases. `401 account_deleted` (the account was deleted from another device or a website) turns sync off as *Disconnect → Keep a copy* does: the personal vault stays, now the only copy, and team vaults go. Every other 401 (an expired session, a reused refresh token, a password changed on another device) means "sign in again", and the data stays. A device that never connects again keeps what it has, encrypted under the master password, so the UI says signing out takes effect when the device next connects. A device's own *Disconnect* asks whether to erase it too or keep a copy that no longer syncs.

**2FA.** TOTP on the account, checked at `/auth/login`; set up and turned off through
`/account/totp…`, and turned off by recovery. WebAuthn isn't supported yet. Email-verified sign-up,
email changes and an account portal are optional features of the API spec
([`spec/openapi.yaml`](../spec/openapi.yaml)).

**Recovery.** Lost password with a recovery key: `POST /account/recover` with `recovery_proof` returns `wrapped_private_keys_rk` and a single-use, access-only token. The client unwraps with `RK` (on a device that has the vault, the keys must be its own), wraps them under a new password, and sends that with the token to `PUT /account/keys`. Every session ends, so the device then signs in with the new password; this works on a fresh device too. Lost both: the account can be reset, but the data is unrecoverable by design, and no server operator can help: the app says so when it shows the recovery key, once, at sign-up.

**Self-hosted auth.** The same flow is mandatory in the spec.

**Single sign-on** (`features.sso`) is per organization and layered on top of the `AuthKey`
proof, never instead of it, since key unwrapping still needs the master password. An organization
with an identity provider (OIDC or SAML, set up on the server's website) and `require_sso` gets
`403 sso_required` (with `org_id`) on its vaults until this device has signed in there: the app
calls `POST /orgs/{id}/sso/start`, opens the returned URL in a browser, and retries once the user
is back. Sessions are per device and expire; a member removed from the organization, or a
provider removed, ends them. Personal vaults are never affected.

**Device approval** (`policies.require_device_approval`) adds a check after that one: a device
the organization hasn't approved gets `403 device_approval_required` (with `org_id`, `device_id`
and `status`, `pending` or `denied`) on its vaults, so a stolen master password isn't enough on
someone else's machine. The first refusal files a request; listing vaults files it too, and
leaves those vaults out, so a new device learns it waits from its own entry in
`GET /orgs/{id}/devices`. Owners and admins approve or deny anyone's devices, members their own
other devices (`POST /orgs/{id}/members/{account}/devices/{device}/approve` or `/deny`), always
from a device the organization approved. Turning the policy on approves the signed-in devices of
confirmed members, confirming a member approves theirs, and signing a device out forgets its
approvals. Like single sign-on, it gates access to ciphertext only: keys never depend on it.

## Sharing

An organization owns shared vaults, and each member gets `read`, `write` or `manage` on each vault. Owners and admins open every organization vault. Personal vaults stay personal. This section is the protocol as implemented; paths and schemas are in `spec/openapi.yaml` (tag `organizations`).

**What the server stores.** Organizations (plaintext name, policies, the ownership chain), members (role, `accepted` or `confirmed`, certificates), invites (token hashed, single use, 7 days, bound to the address), vault grants, and a key ring per vault: one sealed key per account per generation, each with its grant signature. Items gain `author_id`. Vault names stay inside the encrypted `meta`.

**Joining.**

1. An admin invites an address, optionally with vault grants. A server that mails invites sends the link; otherwise the admin gets the token to pass on.
2. The invitee's app reads `GET /invites/{token}`: the organization's name and its ownership chain. It pins the chain's first link (the creator), checks the chain to the current owner, and shows that owner's fingerprint to compare out of band.
3. The invitee accepts (`accepted`): the server shows their keys to admins.
4. An admin's app compares the member's fingerprint with them out of band, signs a member certificate and seals each granted vault's keys to them, with grant signatures (`confirmed`).

**Whom an app trusts.** Nothing the server says about keys is taken as is:

- **Owners:** the pinned root, then each later link of `owner_chain`, verified with the previous owner's signing key (owner certificate). The creator pins themself.
- **Admins:** an admin certificate by a verified owner.
- **Members:** a member certificate by a verified owner or admin (`signer_id`).
- **Vault keys:** a sealed key is used only if its grant signature verifies with a verified member's signing key. It matters because a sealed box doesn't say who sealed it, so without it a server could seal a key of its own to a member and read what they write. Grants by someone who has since left still count when this device verified them while they were a member (their pinned key), for older generations, and for the current one only while a rotation is due (so an admin can rotate). An older generation that can't be verified is left out; the current one must verify.
- **Items:** each envelope is verified with its author's verified signing key (`author_id`); a personal vault's items with the account's own.
- **Pins:** every verified account key is pinned. A different key for a known account is a hard error, not a prompt.

Certificates grant nothing; the server decides membership and permissions. It is trusted for that: it could keep serving a removed member, or accept pushes from a `read` member, but it can't read or forge items, slip in a key, or give anyone a vault key.

**Key generations.** Envelopes carry `key_id`, so a vault can have several generations. `GET /vaults` returns the caller's copy of each (`keys`), and `key_id`/`wrapped_vault_key` stay the current one for older clients. Removing anyone sets `rotation_due`. An app with `manage` then:

1. Generates a new key, seals it to every account with access (owners and admins included), and switches with `POST /vaults/{id}/keys`. The server requires every account (`incomplete_rotation`) and the current generation as `previous_key_id` (`409`).
2. Re-encrypts every live item under the new key in ordinary pushes. A push under an older generation is refused per item with `stale_key`; any app with `write` finishes the job. `items_on_old_keys` counts what's left.

Rotation keeps a removed member from reading anything written afterwards. It doesn't un-share what they already synced: changing those secrets is the offboarding job.

**Member key directory.** Offboarding has to find a removed member's SSH keys on shared hosts, so members publish the public halves of the keys they use there. Each organization has a directory vault: an ordinary organization vault whose meta says `directory: true`, so servers need nothing new.

- Owners' and admins' apps create it when the organization has none, and keep every confirmed member at `write` on it. When two appear, apps use the one with the lowest id.
- A member's app publishes `member_key` items in it, each signed by the member over the organization, their account id and the key.
- Readers accept an entry only if that signature verifies with the member's verified (or pinned) signing key. The envelope's author doesn't decide it: rotations re-encrypt every item under the rotating admin's signature, and entries must still verify after the member is gone.
- Any member with `write` can delete another member's entry, but can't forge one.

**What the server enforces.** Push needs `write` (`403 not_permitted`); grants and rotation need `manage`; confirming an admin, inviting admins, promotions and ownership transfer are the owner's. Organization vaults are created with keys for every owner and admin (`incomplete_keys`), and members create them only when the `members_can_create_vaults` policy allows. The owner can't leave or delete their account (`409 sole_owner`); `DELETE /account` (the AuthKey proves the password) removes anyone else's account, leaving its organizations, and the app then turns sync off on that device. The server keeps an audit log of what it sees (`GET /orgs/{org}/events`).

## Self-hosting contract

We publish `vault-sync/v1` as an OpenAPI 3.1 document plus a conformance test suite. Any server passing the suite is a supported backend, and the client has no hosted-only code paths.

**What we publish**

| Artifact | License | Purpose |
| --- | --- | --- |
| `spec/openapi.yaml` (vault-sync/v1) | CC0-1.0 | The contract; generate servers in any language |
| [`tools/vault-conform`](../tools/vault-conform) (runs against a URL) | Apache-2.0 OR MIT | Pass/fail per endpoint, with throwaway accounts: auth, devices, sync (conflicts, 410, pagination), sharing, blobs |
| Reference server ([`server/`](../server), Rust + SQLite, single binary, Dockerfile) | AGPL-3.0 | So self-hosting is `docker run`, not "implement the spec" |

**Capability discovery.** `GET /.well-known/vault-sync`, which needs no session (like the sign-up and sign-in steps), returns the spec version, limits, and optional features (`Capabilities` in the spec: `registration_open`, `terms`, `email_verification`, `sse`, `totp`, `blobs`, `sso`, `sharing`, `billing`). The client adapts its UI from that response; for example, it shows no plans when `billing` is absent.

**Versioning.** The path prefix is `/v1`. Additive changes are minor and must be ignored by older clients. Breaking changes go to `/v2`, and the client supports N and N-1.

## Plans (optional)

A server may sell plans; how is outside `vault-sync/v1`, and self-hosted servers usually have
none. A server with plans says so in `features.billing` (`plans_enforced`), and reports each
account's and organization's `Entitlement` (`plan`, `status`, `expires_at`, `grace_ends_at`, …;
see the spec). Where plans are enforced:

| State | Pull | Push |
| --- | --- | --- |
| Active or on a trial | Yes | Yes |
| Ended, within its grace period (`grace_ends_at`) | Yes | Yes, with a notice |
| Ended after grace | Yes (always: it's their data) | `402 payment_required`, with a `reason` and a `billing_url` |

Users can always pull and export, even after a plan ends. The app shows what the server reports;
it sells nothing itself.

## Licensing

Each component's license is in [CONTRIBUTING.md](../CONTRIBUTING.md#licenses): the apps and
the client crates MPL-2.0, the crypto and protocol crates Apache-2.0 OR MIT, the reference server
AGPL-3.0, the spec CC0. Contributions are signed off under the Developer Certificate of Origin.
