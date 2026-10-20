#!/usr/bin/env bash
# Installs the Ubuntu packages named that aren't installed yet (what GitHub's runner image
# lacks), and nothing when all are.
#
# `a|b` is a package with another name in another release (webkitgtk-webdriver on 26.04,
# webkit2gtk-driver on 24.04): either one installed will do, else the first apt has.
#
#   .github/scripts/need-packages.sh <package>[|<package>…]…
set -euo pipefail
installed() {
  local p
  IFS='|' read -ra names <<<"$1"
  for p in "${names[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 && return 0
  done
  return 1
}
missing=()
for spec in "$@"; do
  installed "$spec" || missing+=("$spec")
done
[ ${#missing[@]} -eq 0 ] && exit 0
apt="sudo apt-get -o DPkg::Lock::Timeout=600"
$apt update -q
install=()
for spec in "${missing[@]}"; do
  IFS='|' read -ra names <<<"$spec"
  pick=${names[0]}
  for p in "${names[@]}"; do
    if apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [^(]'; then
      pick=$p
      break
    fi
  done
  install+=("$pick")
done
echo "Installing: ${install[*]}"
$apt install -yq --no-install-recommends "${install[@]}"
