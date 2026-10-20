# vault-sync-server

Reference implementation of [`vault-sync/v1`](../spec/openapi.yaml): a single binary with SQLite.
It stores only ciphertext envelopes, wrapped keys, public keys and a slow hash of each account's
`AuthKey`; it never sees a master password, hostname or private key.

```sh
cargo run --release -p vault-sync-server -- --listen 127.0.0.1:8443 --db /var/lib/vault-sync/db.sqlite3
```

| Flag | Env | Default |
| --- | --- | --- |
| `--listen` | `VAULT_SYNC_LISTEN` | `127.0.0.1:8443` |
| `--db` | `VAULT_SYNC_DB` | `vault-sync.sqlite3` |
| `--registration open\|closed` | `VAULT_SYNC_REGISTRATION` | `open` |
| `--blob-quota-mb` | `VAULT_SYNC_BLOB_QUOTA_MB` | `1024` (per account's personal vaults, and per organization) |
| `--public-url` | `VAULT_SYNC_PUBLIC_URL` | `http://` + the listen address; set it to the HTTPS address behind your proxy for single sign-on |

Register your account(s), then restart with `--registration closed`.

It speaks plain HTTP. Put it behind a TLS reverse proxy, e.g. Caddy:

```
sync.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

Docker:

```sh
docker build -f server/Dockerfile -t vault-sync-server .
docker run -d -p 127.0.0.1:8443:8443 -v vault-sync:/data vault-sync-server
```

Sharing (organizations, invites, shared vaults, key rotation; `features.sharing`) is supported.
This server sends no mail, so creating an invite returns its token for the admin to pass on.

Blobs (`features.blobs`: encrypted session logs and attachments) are stored in the database, up
to 25 MiB each. An organization's `session_log_retention_days` deletes its older session logs.

### Single sign-on

An organization can put its vaults behind its OpenID Connect provider (`features.sso`): with
`require_sso`, its vaults answer `403 sso_required` until the device has signed in there, from
the app. It adds to the master password; it never replaces it. Register
`<public URL>/sso/callback` as the redirect URI at the provider, then:

```sh
vault-sync-server sso --db /var/lib/vault-sync/db.sqlite3 --org "Acme Ops" \
  --issuer https://login.example.com --client-id morphgate --client-secret … --require
vault-sync-server sso --db /var/lib/vault-sync/db.sqlite3 --org "Acme Ops" --remove
```

`--org` takes the organization's id or name; `--session-hours` (default 12) is how long a
device's sign-in lasts. The client secret is stored in the database as given, so protect it like
the rest of it.

### SCIM provisioning

An organization's identity provider (Okta, Microsoft Entra ID, …) can decide who is on the team
over SCIM 2.0 (users only). Make a token, then give the provider the base URL
`<public URL>/scim/v2/{org id}`, the token as a bearer token, and map `userName` to the
person's email address:

```sh
vault-sync-server scim --db /var/lib/vault-sync/db.sqlite3 --org "Acme Ops" --public-url https://sync.example.com
vault-sync-server scim --db /var/lib/vault-sync/db.sqlite3 --org "Acme Ops" --revoke
```

The token is printed once and stored as a hash; running the command again replaces it.

- Creating an active user invites the address as a member (nothing changes if it is one already,
  or has an open invite). An admin's app still confirms them and gives them vaults.
- Deactivating (`active: false`) or deleting a user removes the membership, takes their vault
  access, flags those vaults for a new key, and cancels invites to the address. Reactivating
  invites them again. The owner can't be deprovisioned (`409`).
- The organization's activity log shows these changes without an actor.

This server sends no mail and keeps no invite token, so a provisioned person can't join on their
own: the invite shows in the organization's invites (Teams in the app), and an admin invites the
address again there. That replaces the provisioned invite and returns a token to pass on, as for
any invite (and can offer vault access).

Not implemented yet (advertised as off in `/.well-known/vault-sync`): TOTP, email
verification, SSE change notifications, SAML, rate limiting. Tombstones are never purged: the
90 days discovery advertises is the least the protocol asks for.

## Testing another server

`vault-conform` ([`tools/vault-conform`](../tools/vault-conform)) checks any `vault-sync/v1`
server endpoint by endpoint and says what passed, what failed (with the server's answer) and what
it skipped and why:

```sh
cargo run --release -p vault-conform -- https://sync.example.com
```

The tests in `tests/` drive the real client code: the sync engine, password change, recovery and
device sign-out. By default they start this server in-process. With `VAULT_SYNC_URL` they run
against any `vault-sync/v1` server, which makes them a conformance suite:

```sh
VAULT_SYNC_URL=https://sync.example.com \
  cargo test -p vault-sync-server --test protocol --test e2e --test account --test sharing --test blobs
```

The server must accept new accounts without email verification (the codes go to a mailbox
the tests can't read). Each run registers up to 23 accounts with unique `@example.com`
addresses, so raise any per-IP rate limits on a test instance. The closed-registration test
only runs in-process. Tests for optional features run only where the server advertises them:
two-step verification (`totp`), the refusals of `email_verification` (run that one
with verification turned on), and organizations and shared vaults (`sharing`, on servers that
hand invite tokens back instead of mailing them).

Licensed under [AGPL-3.0](LICENSE).
