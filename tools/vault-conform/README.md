# vault-conform

Checks a [`vault-sync/v1`](../../spec/openapi.yaml) server against the spec, endpoint by
endpoint, with throwaway accounts: the reference server, the hosted backend, or your own.

```sh
cargo run --release -p vault-conform -- https://sync.example.com
```

```
auth
  PASS  POST /auth/prelogin        answers unknown addresses with stable, distinct parameters
  PASS  POST /auth/register        creates an account and returns its session
  ...
sharing
  PASS  POST /orgs/{org_id}/members/{account_id}/confirm   confirms a member; their grant opens the vault
  ...
75 passed, 0 failed, 14 skipped
```

Every check names the endpoint it exercises. A failure shows what the server answered; a skip
says why it didn't run (a feature the server doesn't advertise, or something the run needs, such
as a SCIM token). It exits 1 when anything failed, so it fits CI; `--json` gives the report as
JSON.

| Group | What it checks |
| --- | --- |
| discovery | The capabilities document (always runs) |
| auth | Prelogin, registration (and the refusals of email verification), sign-in, refresh-token rotation and reuse detection, logout, devices, account deletion |
| account | The account, password changes and new recovery keys, recovery, two-step verification (`features.totp`), the portal link (`features.billing`) |
| vaults | Create, list, push, pull, conflicts, tombstones, paging, per-item refusals, privacy, deletion, `410` after a purge (`--purge-command`), change notifications (`features.sse`) |
| blobs | Upload (201, then 200), hash and size refusals, download, `HEAD`, listing, deletion, privacy (`features.blobs`) |
| sharing | Organizations, invites, confirmation, vault access, key rotation, roles, re-certification, the audit log and its export, device approval, the member key policy, single sign-on status, ownership transfer, removal, deletion (`features.sharing`) |
| exports | `GET /account/export` (optional) |
| scim | SCIM 2.0 provisioning, with `--scim ORG_ID:TOKEN` |

Most checks use placeholder key material (servers check sizes and shapes, never the
cryptography); the sharing checks use the app's own store and sync engine, so certificates,
sealed keys and grants are real.

## What the server must allow

- New accounts. Servers that mail sign-up codes or invites need `--mailpit URL` (a
  [Mailpit](https://mailpit.axllent.org/) that receives their mail):
  the run reads codes and invite links from there, and checks email changes end to end.
- A full run registers 8 accounts (with email verification, each also asks for a code) and signs
  in about 15 times from one address. A server that limits registrations or code requests per
  address needs its limits raised on a test instance, or the groups run apart (`--only sharing`
  needs 3 accounts).
- The `410` check needs a way to purge tombstones on demand: `--purge-command "…"` runs a shell
  command that does.

## Options

```
--only GROUP[,GROUP…]    run only these groups (discovery always runs)
--email-domain DOMAIN    domain of the throwaway addresses (default example.com)
--purge-command CMD      makes the server purge tombstones now, to check 410 Gone
--scim ORG_ID:TOKEN      an organization's SCIM token, to check provisioning
--mailpit URL            a Mailpit that receives the server's mail, to read codes and invites
--json                   the report as JSON
--no-color               plain text
```

`cargo test -p vault-conform` runs it against an in-process reference server: nothing may fail.
