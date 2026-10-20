# Reference server

`vault-sync-server` is the self-hostable implementation of `vault-sync/v1`: one Rust binary with one SQLite file, under AGPL-3.0. People run it to sync without morphgate.com, and the app's own tests, its e2e suite and `vault-conform` run against it. It is zero-knowledge: it stores ciphertext envelopes, wrapped keys, public keys and a slow hash of each account's `AuthKey`, and never receives a master password, a host name or a private key. It covers the base protocol, teams, blobs, device approval, OpenID Connect single sign-on and SCIM; it leaves out what needs mail, money or an operator (verification codes, two-step verification, plans, rate limits). Code: `server/src/main.rs` (flags, the `sso` and `scim` commands), `server/src/api.rs` (router, discovery, accounts, devices, vaults), `server/src/sharing.rs`, `server/src/blobs.rs`, `server/src/approvals.rs`, `server/src/sso.rs`, `server/src/scim.rs`, `server/src/events.rs`, `server/src/export.rs`, `server/src/auth.rs`, `server/src/db.rs`; the contract is `spec/openapi.yaml`, and `server/README.md` has the essentials for running it.

## Running it

From a checkout of the repository:

```sh
cargo run -p vault-sync-server                 # 127.0.0.1:8443, ./vault-sync.sqlite3
cargo run --release -p vault-sync-server -- --listen 127.0.0.1:8443 --db /var/lib/vault-sync/db.sqlite3
```

In the app: **Sync** → **Your own server** → `http://127.0.0.1:8443` → **Check** (it answers "vault-sync-reference … — accepts new accounts") → **Enable sync**. The server speaks plain HTTP. That is fine on this computer; anywhere else put it behind a TLS reverse proxy (Caddy: `sync.example.com { reverse_proxy 127.0.0.1:8443 }`) and set `--public-url`. The app warns about a plain `http://` address that isn't this computer ("Plain http:// sends tokens unencrypted over the network. Use https://."), and `morphgate://invite` links accept `http://` only for this computer ([Deep links](deep-links.md)).

Docker, from the repository root: `docker build -f server/Dockerfile -t vault-sync-server .`, then `docker run -d -p 127.0.0.1:8443:8443 -v vault-sync:/data vault-sync-server`. The image builds on `rust:1-bookworm`, runs on `debian:bookworm-slim` as the user `vault-sync`, listens on `0.0.0.0:8443` and keeps `/data/vault-sync.sqlite3` in the volume.

Register the accounts first, then restart with `--registration closed`. A closed server accepts no sign-ups at all, invited people included. Logs go to stderr through `tracing`; `RUST_LOG` sets the filter (default `info`).

## Configuration

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--listen` | `VAULT_SYNC_LISTEN` | `127.0.0.1:8443` | Address and port |
| `--db` | `VAULT_SYNC_DB` | `vault-sync.sqlite3` | The SQLite file, created when missing |
| `--registration open\|closed` | `VAULT_SYNC_REGISTRATION` | `open` | `closed` refuses `POST /auth/register` with `403 registration_closed` ("this server does not accept new accounts") |
| `--blob-quota-mb` | `VAULT_SYNC_BLOB_QUOTA_MB` | `1024` | Blob storage per owner: an account's personal vaults, or one organization's vaults |
| `--public-url` | `VAULT_SYNC_PUBLIC_URL` | `http://` + the listen address | Where browsers reach the server; single sign-on's redirect URI is `<public URL>/sso/callback` |

Flags win over the environment. A wrong flag prints the error and exits with 2 (`--help` prints the usage); a database that can't be opened or an address that can't be bound exits with 1.

Organizations' identity providers and SCIM tokens are set up from the command line, against the database, not over the API:

| Command | Does |
| --- | --- |
| `vault-sync-server sso --db PATH --org ID\|NAME --issuer URL --client-id ID --client-secret SECRET [--session-hours 12] [--require]` | Puts the organization behind its OpenID Connect provider; `--require` also turns `require_sso` on. `--session-hours` is 1 to 720. The client secret is stored as given |
| `vault-sync-server sso --db PATH --org ID\|NAME --remove` | Removes the provider and its sessions; `require_sso` goes off |
| `vault-sync-server scim --db PATH --org ID\|NAME [--public-url URL]` | A new SCIM token, printed once with the base URL `<public URL>/scim/v2/<org id>`; it replaces the old one and is stored as a hash |
| `vault-sync-server scim --db PATH --org ID\|NAME --revoke` | Provisioning stops |

`--org` takes the organization's id or its name; a name that several organizations share must be given as an id.

## Limits and lifetimes

| What | Value | Constant |
| --- | --- | --- |
| Item envelope | 64 KiB | `MAX_ENVELOPE` |
| Items per push | 500 | `MAX_PUSH` |
| Changes per page | 500 by default, 1000 at most | `DEFAULT_PAGE`, `MAX_PAGE` |
| Request body | 48 MiB | `DefaultBodyLimit` in `router()` |
| One blob | 25 MiB | `Config::max_blob_bytes` |
| Blob storage | 1 GiB per owner by default | `--blob-quota-mb` |
| Items per vault, vaults, members, devices | No limit (`max_items_per_vault` absent, `max_members_per_org` and `max_vaults_per_org` 0) | |
| Access token | 15 minutes | `ACCESS_TTL` |
| Refresh token | 90 days, rotated on every use; reusing an old one signs the device out | `REFRESH_TTL` |
| Invite | 7 days | `INVITE_TTL` |
| A started single sign-on | 10 minutes | `LOGIN_SECS` |
| Organization names | 1 to 100 characters ("an organization name has 1 to 100 characters") | `MAX_NAME` |
| Session log retention policy | 0 to 3650 days | `update_org` |
| KDF parameters accepted | Argon2id, at least 64 MiB and 2 passes, 1 to 16 lanes, a salt of 16 bytes or more | `check_kdf()` |

Tokens are 32 random bytes, stored as SHA-256 hashes. The `AuthKey` and the recovery proof are stored as Argon2 hashes (PHC strings). A prelogin for an unknown address answers stable, plausible parameters (a salt from an HMAC of the address under a per-server secret kept in `meta`), and a login for one spends the same Argon2 time, so neither tells whether an account exists.

## What it implements

`GET /.well-known/vault-sync` advertises `server.name` `vault-sync-reference` and:

| Feature | Value |
| --- | --- |
| `registration_open` | From `--registration` |
| `email_verification`, `totp`, `sse` | `false` |
| `terms`, `billing` | Absent |
| `sharing` | No member or vault limits; `mails_invites: false` (creating an invite returns its token) |
| `blobs` | `max_blob_bytes`, `quota_bytes`, kinds `attachment` and `session_log` |
| `sso` | `protocols: ["oidc"]` |
| `limits.tombstone_retention_days` | 90 |

| Area | Endpoints (under `/v1` unless noted) |
| --- | --- |
| Accounts | `POST /auth/prelogin`, `/auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`; `GET` and `DELETE /account`; `GET /account/export`; `PUT /account/keys` (password change, and the second half of recovery); `POST /account/recover` |
| Devices | `GET /devices`; `PATCH /devices/{id}` (a device updates only itself); `DELETE /devices/{id}` |
| Vaults and sync | `GET`, `POST /vaults`; `GET`, `DELETE /vaults/{id}`; `GET`, `POST /vaults/{id}/changes` |
| Sharing | `/vaults/{id}/members[/{account}]`, `POST /vaults/{id}/keys`; `/orgs`, `/orgs/{org}`, members, `…/confirm`, `…/certificate`, invites, `POST /orgs/{org}/transfer`; `GET /invites/{token}`, `POST /invites/{token}/accept` |
| Audit log | `GET /orgs/{org}/events`; `GET /orgs/{org}/events/export` (CSV by default, or JSON lines; columns `seq`, `at`, `kind`, `actor_id`, `actor_email`, `target_id`, `target_email`, `vault_id`, `detail`) |
| Device approval | `GET /orgs/{org}/devices`; `POST /orgs/{org}/members/{member}/devices/{device}/approve` and `/deny` |
| Single sign-on | `GET /orgs/{org}/sso`, `POST /orgs/{org}/sso/start`; `GET /sso/callback` (outside `/v1`) |
| Blobs | `GET /vaults/{id}/blobs`; `GET`, `PUT`, `DELETE /vaults/{id}/blobs/{hash}` |
| SCIM 2.0 | `/scim/v2/{org}/…`, users only (outside `vault-sync/v1`) |

Not implemented, though the spec defines them: `POST /auth/register/start`, `PUT /account/terms`, `POST /account/email/start`, `PUT /account/email`, `POST /account/totp/start`, `POST /account/totp/enable`, `DELETE /account/totp`, `POST /account/web-session`, and `GET /vaults/{id}/events` (server-sent events). The policy `require_totp` is refused with `501 not_supported` ("this server has no two-step verification to require").

Behavior the app relies on:

- Deleting an account needs the `AuthKey` again, and an owner must transfer or delete their organizations first (`409 sole_owner`). The account's other devices then get `401 account_deleted` on their next refresh, and devices signed out before get `device_revoked`: `deleted_tokens` keeps those answers for as long as the tokens would have lasted.
- Recovery issues an access token alone, scoped `recover`, usable only to set new keys.
- An organization vault belongs to the organization's current owner in the `vaults` table; only owners and admins delete organization vaults.
- Because no mail is sent, a SCIM-provisioned person can't join alone: the invite waits in the organization's invites until an admin invites the address again, which returns a token to pass on.
- Turning `require_device_approval` on approves the devices members have at that moment, so nobody is locked out.

## Storage

Everything is in the one SQLite file, opened with WAL and foreign keys on, behind a single connection and a mutex (plenty for a self-hosted server). Argon2 work runs on blocking threads.

| Tables | Hold |
| --- | --- |
| `meta` | The per-server secret for fake prelogin salts |
| `accounts`, `devices`, `tokens`, `deleted_tokens` | Accounts (KDF parameters, `auth_hash`, public keys, private keys wrapped under the password and under the recovery key, `recovery_hash`), devices, token hashes |
| `vaults`, `items` | Vaults and their envelopes, revisions and tombstones |
| `orgs`, `owner_chain`, `members`, `invites`, `vault_members`, `vault_keys`, `events` | Organizations, the signed owner chain, membership, invites (token hashes), access, sealed vault keys per generation, the audit log |
| `blobs` | Encrypted blobs, in the database |
| `org_sso`, `sso_logins`, `sso_sessions` | Identity providers (the client secret in clear), sign-ins in progress, device sessions |
| `device_approvals` | Requests and decisions per device |
| `scim_tokens`, `scim_users` | SCIM token hashes and the users the provider manages |

`db::init()` creates the base schema, then applies the ordered SQL in `MIGRATIONS`, each in a transaction; `PRAGMA user_version` counts the ones applied (7 today). A database from before sharing is upgraded in place (`upgrades_a_pre_sharing_database`). Back the file up like any SQLite database (with `sqlite3 … .backup`, which includes the WAL), and keep backups private: they hold the hashes and the single sign-on secrets.

## What it leaves out

What needs mail, payment or an operator is left out. Where discovery has a field for it, the field says so:

| Area | On the reference server |
| --- | --- |
| Sign-up | Open or closed (`--registration`); no email verification (`email_verification: false`) and no terms to accept (`terms` absent) |
| Two-step verification, email change | Not implemented (`totp: false`); the `require_totp` policy is refused with `501 not_supported` |
| Account portal | None: no `billing` in discovery, no `POST /account/web-session` |
| Plans | None: nothing is refused for payment, and no request answers `402` |
| Limits | Only the fixed ones above |
| Rate limits | None |
| Tombstones | Kept forever, so no cursor gets `410 gone`, although discovery advertises `tombstone_retention_days: 90` |
| Mail | None: creating an invite returns its token to the admin (`mails_invites: false`), and nothing is mailed about security or device approval |
| Single sign-on | OpenID Connect only (`sso.protocols: ["oidc"]`), set up with `vault-sync-server sso`; no SAML |
| SCIM | A token from `vault-sync-server scim` |
| Server-sent events | None (`sse: false`) |

The app reads `/.well-known/vault-sync` and shows only what a server offers, so the same build hides plans, two-step verification and email change against the reference server.

## Tests

| Test (`server/tests/`) | Covers | Against another server |
| --- | --- | --- |
| `protocol.rs` | `mg_sync::SyncClient` through the whole base protocol | Yes |
| `e2e.rs` | Two real local vaults syncing | Yes |
| `account.rs` | Password change, recovery, a new recovery key, signing in again after a change elsewhere, device sign-out, two-step verification where offered | Yes |
| `sharing.rs` | Organizations with real certificates, sealed keys and grant signatures | Yes, where `sharing` is offered and invites aren't mailed |
| `shared_vaults.rs` | Shared vaults end to end with real local vaults and the sync engine | Same |
| `blobs.rs` | Blobs sealed as apps seal them | Yes, where `blobs` is offered |
| `device_approval.rs`, `recertify.rs`, `scim.rs`, `sso.rs` | Device approval; certificates outliving their admin and the member key policy; SCIM; single sign-on against an in-process OpenID provider | No (in-process only) |

Each test starts its own in-process server with an in-memory database (`tests/common/mod.rs`). With `VAULT_SYNC_URL` set, the tests marked above run against that server instead, which makes them a conformance suite; `tools/vault-conform` checks a server endpoint by endpoint, and `cargo test -p vault-conform` runs it against the reference server, where nothing may fail. Unit tests in `db.rs` cover the schema upgrade. See [Development](../development.md#conformance-suite).

## Limits

- No email verification, two-step verification, email change, terms, account portal, server-sent events, SAML, rate limiting or tombstone purging ([What it leaves out](#what-it-leaves-out)).
- One SQLite connection: meant for a person or a team, not a large service.
- Single sign-on and SCIM are set up from the command line only.
- No mail of any kind.
