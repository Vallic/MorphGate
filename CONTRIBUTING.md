# Contributing to MorphGate

Thanks for helping. Bug reports, fixes and features are all welcome; for anything larger than a
small fix, open an issue first so we can agree on the approach before you write it.

## Branches and pull requests

- **`develop`** is where work goes: branch from it and open your pull request **against
  `develop`**. **`main`** only takes releases (a maintainer merges `develop` into it), so a pull
  request against `main` will be retargeted.
- One topic per pull request. Keep it up to date by rebasing on `develop`, and squash fix-ups
  ("fix typo", "address review") into the commits they fix before it's merged.
- Say what changes for the person using the app, and how you tested it (screenshots for UI
  changes help).
- CI runs on every pull request: lint, unit and integration tests, the end-to-end tests of the
  packaged Linux app, and the Android build. A first-time contributor's run waits for a
  maintainer to approve it.

## Commits

- Every commit is signed off ([Developer Certificate of Origin](https://developercertificate.org/)):

  ```sh
  git commit -s -m "Fix resize on tab switch"
  ```

  This adds `Signed-off-by: Your Name <you@example.com>`: you certify that you may submit the
  change under the license of the component it touches.
- A short summary line in the imperative ("Fix …", "Add …"), then a body that says why: what was
  wrong or missing, and what the change does about it.
- No secrets, tokens or real hosts in commits, tests or screenshots. Test keys and certificates
  are made for the tests, and [`.gitleaks.toml`](.gitleaks.toml) tells
  [gitleaks](https://github.com/gitleaks/gitleaks) about them (`gitleaks git .` should find
  nothing).

## Licenses

By contributing you agree your contribution is licensed under the license of the component you
change:

| Path | License |
| --- | --- |
| `apps/`, `crates/mg-ssh`, `crates/mg-store`, `crates/mg-vpn`, `crates/mg-presence` | [MPL-2.0](LICENSE) |
| `crates/mg-vault`, `crates/mg-sync`, `crates/mg-inventory` | [Apache-2.0](crates/mg-vault/LICENSE-APACHE) OR [MIT](crates/mg-vault/LICENSE-MIT) |
| `server/` | [AGPL-3.0](server/LICENSE) |
| `spec/` | [CC0-1.0](spec/LICENSE) |

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd apps/desktop && npm run typecheck)
```

- **The app's screens:** run the end-to-end tests that cover what you changed
  ([apps/desktop/e2e/README.md](apps/desktop/e2e/README.md)); they drive the Linux build
  (WebKitGTK). Android and Windows render with Chromium, which lays some CSS out differently:
  check layout changes there too, at a phone's width as well as a window's.
- **User-visible changes:** add a line to [CHANGELOG.md](CHANGELOG.md) under the next version,
  written for people using the app, and update the feature's page in [docs/](docs/README.md),
  which describes the app as the code has it.
- **The vault, encryption or wire formats** (anything in `crates/mg-vault`, what's stored or
  sent): update [docs/sync-crypto-spec.md](docs/sync-crypto-spec.md) to match, with tests that
  pin the format.
- **The sync API:** change [spec/openapi.yaml](spec/openapi.yaml), the reference server
  (`server/`) and a check in `tools/vault-conform` together, and keep older servers working (a
  client treats a missing endpoint as "not offered").
- Match the code around you: its naming, idiom and comments (they say why, not what). Leave no
  `TODO` comments: open an issue instead.

## Security

Please don't report vulnerabilities in public issues: [SECURITY.md](SECURITY.md) says how to
report them privately.
