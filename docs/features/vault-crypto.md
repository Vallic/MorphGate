# Vault cryptography

Everything the app stores or syncs is encrypted on the device by `mg-vault`, a small crate with no I/O that implements the key hierarchy and wire formats of `vault-sync/v1`. The master password never leaves the device: it unlocks one account key pair, which unwraps a random key per vault, which encrypts and verifies each item. That middle layer makes a password change cheap (no item is re-encrypted) and lets a team vault's key be sealed to every member. The normative description is [`docs/sync-crypto-spec.md`](../sync-crypto-spec.md); this page follows the code and lists where the two differ. Code: `crates/mg-vault/src/kdf.rs`, `aead.rs`, `account.rs`, `recovery_code.rs`, `vault.rs`, `envelope.rs`, `blob.rs`, `sharing.rs`; how the store uses them in `crates/mg-store/src/vault.rs`, `device.rs`, `sync.rs` (rollback guard) and `sync_http.rs` (`kdf_from_wire`).

## Key hierarchy

```
master password ──Argon2id(salt)──▶ MasterKey ──HKDF "auth"──▶ AuthKey  (sent at sign-in; the server stores a slow hash)
                                              └─HKDF "kek"───▶ KEK      (never stored, never sent)
KEK  /  HKDF(RecoveryKey, "recovery-kek")  /  HKDF(DeviceKey, "device-kek")
        ──XChaCha20-Poly1305──▶ AccountKeys (X25519 secret ‖ Ed25519 seed)
AccountKeys.X25519 ──sealed box──▶ VaultKey (one per vault, per key generation)
VaultKey ──XChaCha20-Poly1305 + author's Ed25519 signature──▶ item envelopes
VaultKey ──XChaCha20-Poly1305──▶ blobs (attachments, session-log chunks)
```

| Key | Type | Made from | Used for | Kept |
| --- | --- | --- | --- | --- |
| Master key | `MasterKey` | Argon2id(password, `KdfParams`), 32 bytes | Deriving `AuthKey` and the KEK | Memory only, zeroized on drop |
| `AuthKey` | `AuthKey` | HKDF-SHA256(MK, no salt, `morphgate/v1/auth`) | Proof of the password at `/auth/login` and for account changes | Sent to the server, which stores only a slow hash; `Debug` prints `AuthKey(<redacted>)` |
| KEK | crate-private | HKDF(MK, `morphgate/v1/kek`) | Wraps the account private keys | Memory only |
| Account keys | `AccountKeys` | 32 random bytes each for X25519 (`enc`) and Ed25519 (`sign`) | Opening sealed vault keys; signing items, certificates and grants | Public halves (`PublicKeys`) in the clear; private halves only wrapped |
| Recovery key | `RecoveryKey` | 32 random bytes | Second wrapping of the account keys; `recovery_proof` | Shown once as a code, never stored |
| Device key | `DeviceKey` | 32 random bytes | Third wrapping of the account keys, for keychain or biometric unlock | OS keychain (or Android Keystore-sealed); never syncs. See [Keychain and biometric unlock](device-unlock.md) |
| Vault key | `VaultKey` | 16-byte random id + 32-byte random key | Encrypting a vault's items and blobs | Sealed to each member's X25519 key |

Randomness comes from the OS (`getrandom`); a failure is `Error::Rng`. Secrets are `ZeroizeOnDrop` or `Zeroizing`.

## Primitives

| Primitive | Crate | Notes |
| --- | --- | --- |
| Argon2id v1.3 | `argon2` 0.6 | 32-byte output |
| HKDF-SHA256 | `hkdf` 0.13, `sha2` 0.11 | Always 32-byte output (`aead::hkdf32`) |
| XChaCha20-Poly1305 | `chacha20poly1305` 0.11 | 24-byte random nonce per seal, 16-byte tag |
| X25519 | `x25519-dalek` 3 | Non-contributory (low-order) results refused |
| Ed25519 | `ed25519-dalek` 3 | Verified with `verify_strict` |

Every label is domain-separated with a `morphgate/v1/` prefix:

| Label | Kind | Where |
| --- | --- | --- |
| `auth`, `kek` | HKDF info | `kdf.rs` |
| `recovery-kek`, `recovery-auth`, `device-kek` | HKDF info | `account.rs` |
| `account-keys` | AEAD associated data | All three wrappings of the account keys |
| `vault-key-seal` | HKDF info | Sealed vault keys |
| `envelope-sig` | Signature prefix | Item envelopes |
| `blob` | AAD prefix | Blobs |
| `recovery-check` | SHA-256 prefix | Recovery code checksum |
| `fingerprint`, `member-cert`, `admin-cert`, `owner-cert`, `vault-key-grant`, `member-key` | Hash and signature prefixes | `sharing.rs` |

## From the master password

`KdfParams { m_kib, t, p, salt }` travel with the account (the server returns them at `prelogin`), so they can be raised later. `KdfParams::recommended()` gives 256 MiB, 3 passes, 1 lane and a fresh 16-byte salt; Argon2id at that cost takes about a second (`VaultState::blocking` runs it off the async runtime). Every new password (creating the vault, changing the password, recovery) gets `recommended()` with a new salt (`LocalVault::new_kdf`), so a password change also moves an older account to the current defaults. Unlocking uses the parameters stored with the account.

### The minimums the client enforces

`MasterKey::derive` calls `KdfParams::validate()` before every derivation, whether the parameters came from the server or from the local `account` row:

| Rule | Constant | Error |
| --- | --- | --- |
| Memory at least 64 MiB | `KdfParams::MIN_M_KIB` = 65536 | `KDF parameters rejected: memory cost below 64 MiB` |
| At least 2 passes | `KdfParams::MIN_T` = 2 | `KDF parameters rejected: fewer than 2 passes` |
| Parallelism 1 to 16 | (literal) | `KDF parameters rejected: parallelism must be 1..=16` |
| Salt at least 16 bytes | `KdfParams::MIN_SALT_LEN` = 16 | `KDF parameters rejected: salt shorter than 16 bytes` |
| Algorithm Argon2id | `kdf_from_wire` (`mg-store`) | `unsupported KDF <alg>` |

Why: the server supplies the parameters before sign-in, and it receives the `AuthKey` at sign-in. A malicious server that handed out cheap parameters could brute-force the password from the `AuthKey` offline, then derive the KEK and open everything it stores. The floors keep each guess at least 64 MiB of memory-hard work. There is no upper bound: a server can make derivation slower, not weaker.

## Account keys

The 64-byte secret (`x25519_sk ‖ ed25519_seed`) is wrapped with `aead::seal`: `nonce(24) ‖ ciphertext(64) ‖ tag(16)`, 104 bytes, associated data `morphgate/v1/account-keys`.

| Wrapping | KEK | Stored as |
| --- | --- | --- |
| `AccountKeys::wrap` | KEK from the master key | `wrapped_private_keys` (server and `account` table) |
| `wrap_with_recovery` | HKDF(RK, `recovery-kek`) | `wrapped_private_keys_rk` (server and `account` table) |
| `wrap_with_device` | HKDF(device key, `device-kek`) | `device_unlock.wrapped`, this device only |

The three KEKs differ by HKDF label, so the same 32 bytes used as a recovery key and as a device key open different things (`device_key_wrap_is_its_own_domain`). A failed unwrap is `Error::Decrypt`, which the store reports as "wrong master password", "that recovery key does not match this vault" or "the system keychain holds a different key for this vault". After any unwrap the store checks that the keys match the public halves in the `account` row ("account keys do not match their public halves"), and refuses new credentials for other keys ("the new credentials are for different account keys", "the sync server's account keys are not this vault's"), so a server cannot swap in another account's keys.

## Recovery key and code

The code is Crockford base32 of `RK(32) ‖ SHA-256("morphgate/v1/recovery-check" ‖ RK)[..3]`: 35 bytes, 56 symbols from `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, in 14 groups of 4 joined by dashes. Decoding ignores case, dashes, spaces, tabs and line breaks, and reads I and L as 1 and O as 0. The 24-bit check catches typos before any cryptography runs:

| Input | Error (the user sees it with a `malformed data: ` prefix) |
| --- | --- |
| A symbol outside the alphabet | `invalid character in recovery code` |
| More than 56 symbols | `recovery code is too long` |
| Fewer than 56 symbols | `recovery code is too short` |
| Checksum mismatch | `recovery code has a typo (checksum mismatch)` |

`RecoveryKey::proof()` is HKDF(RK, `recovery-auth`): the server stores a hash of it and accepts it at `POST /account/recover`. The device keeps `wrapped_private_keys_rk` and `recovery_proof`, never the key or the code.

## Vault keys

A `VaultKey` has a 16-byte id, which names its generation and travels in every envelope so shared vaults can rotate keys. `VaultKey::seal_to(recipient_enc_pub)` makes `wrapped_vault_key`, 121 bytes:

`0x01 ‖ eph_pk(32) ‖ nonce(24) ‖ XChaCha20-Poly1305(k, aad, key_id(16) ‖ key(32)) ‖ tag(16)`

with a fresh ephemeral X25519 key per seal, `k` = HKDF(X25519(eph, recipient), salt = `eph_pk ‖ recipient_pk`, info `vault-key-seal`) and `aad` = `0x01 ‖ eph_pk ‖ recipient_pk`. A low-order recipient key is refused when sealing ("low-order recipient public key") and fails as `Decrypt` when opening.

The personal vault has one key (`vaults.wrapped_vault_key`, id in `vaults.key_id`, checked on unlock: "vault key id does not match"). A shared vault keeps every generation sealed to this account in `vault_keys`, and its current key must be among them ("the current key of vault … is missing"). Who sealed a shared key is checked by grant signature; see [Teams](teams.md).

## Item envelopes

| Bytes | Field |
| --- | --- |
| 1 | Version, `0x01` (`envelope::VERSION`) |
| 16 | Vault key id |
| 24 | Random nonce |
| n + 16 | XChaCha20-Poly1305 ciphertext of the padded plaintext, with tag |
| 64 | Ed25519 signature of the author |

- **Associated data**: `u16 len ‖ vault_id ‖ u16 len ‖ item_id ‖ u16 schema_version ‖ version ‖ key_id`. The server cannot move an envelope to another item, vault or schema version (`moved_to_another_item_fails`). The store uses `schema_version` 1 (`model::SCHEMA_VERSION`).
- **Signature**: over `morphgate/v1/envelope-sig ‖ u32 len(aad) ‖ aad ‖ every byte before the signature`. In a shared vault every member holds the vault key, so the AEAD tag alone would let any member write as another; the signature names the author. The store picks the signing key: this account's for the personal vault whatever author the server names, a verified (pinned) member's key otherwise (`UnverifiedAuthor` if none).
- **Order on open**: length, version (`unsupported format version N`), signature (`signature verification failed`), key id (`envelope was encrypted with a different vault key`), decryption (`decryption failed (wrong key or tampered data)`), padding. Tampered bytes never reach the decryptor.
- **Padding**: ISO/IEC 7816-4 (`0x80`, then zeros) to a multiple of `PAD_BUCKET` = 256 bytes. 0 to 255 bytes of JSON become one bucket, 256 become two.
- **Size**: the whole envelope is at most `MAX_ENVELOPE_LEN` = 64 KiB (the default `capabilities.limits.max_envelope_bytes`), so at most 65,279 bytes of plaintext; larger is `plaintext too large (N bytes)`.

The store seals a few things that are not items with contexts of their own, so none can pass for an item: the sync refresh token (personal vault, item id `sync:refresh-token`, never a valid ULID), device-local secrets such as cloud sign-ins (vault id `this-device`, item id `secret` name, kept hex-encoded in `settings`), and a shared vault's name (item id `vault-meta`, signed by the vault's creator).

## Blobs

What is too big for an item (attachments, session-log chunks) is a blob: `0x01 ‖ key_id(16) ‖ nonce(24) ‖ ciphertext`, associated data `morphgate/v1/blob ‖ u16 len ‖ vault_id ‖ u16 len ‖ kind ‖ version ‖ key_id`, where `kind` is `attachment` or `session_log` (`BlobKind`). Plaintext is padded to 4 KiB (`blob::PAD_BUCKET`), and a blob is at most `MAX_BLOB_LEN` = 25 MiB. A blob has no signature: the signed item that refers to it carries its name, the lowercase hex SHA-256 of the whole blob (`blob::hash`), and the client checks the hash before opening a blob from the server. `blob::key_id` reads the generation that opens it. Attachments are capped lower by the store, at 20 MiB (`MAX_ATTACHMENT_BYTES`: "attachments are up to 20 MB").

## Sharing signatures

`sharing.rs` signs and checks what makes shared vaults safe against the server; all strings are `u16 len ‖ UTF-8`:

| Object | Signed or hashed |
| --- | --- |
| Fingerprint | SHA-256(`fingerprint` ‖ account_id ‖ enc_pub ‖ sign_pub), first 20 bytes, 32 symbols in 8 groups of 4 |
| Member, owner certificate | `member-cert` / `owner-cert` ‖ org_id ‖ account_id ‖ enc_pub ‖ sign_pub |
| Admin certificate | `admin-cert` ‖ org_id ‖ account_id ‖ sign_pub |
| Grant | `vault-key-grant` ‖ vault_id ‖ key_id ‖ recipient account_id ‖ SHA-256(wrapped_vault_key) |
| Member SSH key | `member-key` ‖ org_id ‖ account_id ‖ OpenSSH public key without comment |

How they are used: [Teams](teams.md) and the spec's [Sharing](../sync-crypto-spec.md#sharing).

## Rollback guard

The revision memory lives in `mg-store`: `vaults.head_rev` is the highest server revision this device has applied for each vault, advanced as pull pages apply (`sync_vault` in `crates/mg-store/src/sync.rs`).

| Check | What happens |
| --- | --- |
| A pull answers with `head_rev` below the device's | `SyncError::Rollback`: "the sync server sent older data (revision R) than this device already has (L); refusing to roll back". Nothing from that answer is applied |
| A pulled item whose `rev` is not newer than the local copy's | Skipped (`apply_remote`) |
| `410 Gone` (the history was purged) | The cursor resets to 0 and the vault is pulled in full; the `head_rev` check is off for that pass, the per-item check stays. Synced, unchanged items the server no longer lists are dropped (`drop_unseen`) |
| Sync turned off | `head_rev` back to 0 for every vault: another server is another history |

How a round pages and resolves conflicts: [Sync](sync.md).

## Where code and spec differ

| Topic | `docs/sync-crypto-spec.md` | Code |
| --- | --- | --- |
| KDF floors | Memory, passes, salt | Also parallelism 1 to 16, and only `argon2id` (`kdf_from_wire`) |
| Password strength | "at least 10 characters and zxcvbn ≥ 10^10" | `mg-store` enforces only the length (`MIN_PASSWORD_CHARS`); the zxcvbn check is the desktop app's (`apps/desktop/src-tauri/src/password.rs`), and it is not applied on the fresh-device recovery path (`sync_recover_sign_in`) |
| Device unlock check | Touch ID, Windows Hello or polkit, "a check made by the app" | Still true on desktops; on Android the device key is sealed by a Keystore key a biometric check releases, and on iOS it is a keychain item iOS releases only after Face ID, Touch ID or the passcode |
| Local `account` table | KDF params, public keys, both wrappings | Also `recovery_proof`, in the clear, so sync can be turned on later |
| "Nothing typed is stored in plaintext" | | Team vault names (`vaults.name`, decrypted from `vault-meta`), organization names, pinned members' emails and the sync email are in the clear in SQLite. No host data or secrets are |
| Erasing a signed-out device | Removes "pinned host keys" too | `LocalVault::erase` empties every table and the keychain entry goes; the `known_hosts` file in the data folder is not touched |
| Rollback defense | A lower revision is an error | Except during a `410 Gone` full resync, when only the per-item check applies (above) |

## Tests

| Where | Covers |
| --- | --- |
| `mg-vault` unit tests, one module each | Derivation determinism and domain separation, weak parameters refused (`kdf.rs`); wrap, wrong password, recovery and device domains, truncated blobs (`account.rs`); code shape, forgiving input, typos (`recovery_code.rs`); seal, other account, tampering, low-order keys (`vault.rs`); bucket sizes, trailing zeros, moved items, bit flips, wrong author, wrong key, oversize (`envelope.rs`); binding to vault and kind, SHA-256 vector, size limit (`blob.rs`); fixed vectors computed independently (`sharing.rs`) |
| `mg-store` `vault.rs` tests | `persists_and_stores_only_ciphertext` (no hostname, password or key bytes in the file), `tampered_or_swapped_envelopes_are_rejected`, `another_accounts_keys_are_refused` |
| `mg-store` `sync.rs` tests | `rollback_is_refused` |

`cargo test -p mg-vault -p mg-store`. Tests derive at the floor parameters (`fast_params()`, `LocalVault::with_kdf_cost(MIN_M_KIB, MIN_T, 1)`), 64 MiB each. CI runs `cargo test --workspace --all-features` on Linux and these crates on macOS and Windows.

## Limits

- One format version (`0x01`) for envelopes, sealed keys and blobs; anything else is refused.
- The personal vault has one key and no rotation; only shared vaults rotate.
- Envelopes up to 64 KiB, blobs up to 25 MiB, attachments up to 20 MiB.
- What a server still sees: ids, revisions, timestamps, key ids, sizes in 256-byte (items) or 4 KiB (blobs) steps, blob kinds, and KDF parameters. See [Sync](sync.md).
