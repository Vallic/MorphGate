#!/bin/sh
# Sets the version of the workspace (all crates, the app) and the desktop frontend:
#   scripts/bump-version.sh 0.2.0
# Then add a "## 0.2.0" section to CHANGELOG.md, commit, and tag v0.2.0 (RELEASING.md).
set -eu

version=${1:?usage: $0 X.Y.Z}
case $version in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "not a version: $version" >&2; exit 1 ;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)

# The first `version = ` in Cargo.toml is [workspace.package].
awk -v v="$version" '!done && /^version = "/ { $0 = "version = \"" v "\""; done = 1 } 1' \
  "$root/Cargo.toml" > "$root/Cargo.toml.new"
mv "$root/Cargo.toml.new" "$root/Cargo.toml"
(cd "$root" && cargo update --workspace --offline --quiet)
(cd "$root/apps/desktop" && npm version "$version" --no-git-tag-version --allow-same-version >/dev/null)

# Android's version code: Google Play takes each one once, so X.Y.Z gets X·1000000 + Y·10000 +
# Z·100, leaving 99 more for uploading the same version again (raise it by one in the file).
code=$(echo "$version" | awk -F. '{ print $1 * 1000000 + $2 * 10000 + $3 * 100 }')
node -e '
  const fs = require("fs"), [file, code] = process.argv.slice(1);
  const conf = JSON.parse(fs.readFileSync(file, "utf8"));
  conf.bundle.android.versionCode = Number(code);
  fs.writeFileSync(file, JSON.stringify(conf, null, 2) + "\n");
' "$root/apps/desktop/src-tauri/tauri.android.conf.json" "$code"

grep -q "^## $version\$" "$root/CHANGELOG.md" || echo "Remember: CHANGELOG.md has no '## $version' section yet."
echo "Version is now $version (Android version code $code)."
