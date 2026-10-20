#!/bin/sh
# End-to-end test of the packaged Linux app; see README.md next to this file.
#
#   apps/desktop/e2e/run.sh                     build test packages, then run every scenario
#   E2E_SKIP_BUILD=1 apps/desktop/e2e/run.sh    reuse the packages from the last build
#   E2E_ONLY="teams" apps/desktop/e2e/run.sh     only these scenarios (appimage, rpm, deb, teams, layout, mobile)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
desktop="$root/apps/desktop"
target=$(cargo metadata --format-version 1 --no-deps --manifest-path "$root/Cargo.toml" |
  node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).target_directory)')
out=${E2E_OUT:-"$target/e2e"}
artifacts=${E2E_ARTIFACTS:-"$out/packages"}
# Wayland sockets go in XDG_RUNTIME_DIR, which a CI runner started as a service has none of.
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
  XDG_RUNTIME_DIR=$(mktemp -d)
  chmod 700 "$XDG_RUNTIME_DIR"
  export XDG_RUNTIME_DIR
fi

# Free ports unless given: several runs can share a machine.
free=$(node "$here/free-ports.mjs" 5)
read -r free_feed free_ssh free_sync free_idp free_vallic <<EOF
$free
EOF
feed_port=${E2E_FEED_PORT:-$free_feed}
ssh_port=${E2E_SSH_PORT:-$free_ssh}
sync_port=${E2E_SYNC_PORT:-$free_sync}
idp_port=${E2E_IDP_PORT:-$free_idp}
vallic_port=${E2E_VALLIC_PORT:-$free_vallic}
export TAURI_DRIVER=${TAURI_DRIVER:-tauri-driver}

want() {
  [ -z "${E2E_ONLY:-}" ] && return 0
  case " $E2E_ONLY " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "e2e: needs $1 ($2)" >&2; exit 2; }
}
need node "Node 22"
need mutter "headless Wayland compositor"
need dbus-run-session "dbus"
need WebKitWebDriver "Fedora: webkitgtk6.0, Debian/Ubuntu: webkit2gtk-driver"
need "$TAURI_DRIVER" "cargo install tauri-driver --locked"
need ssh-keygen "openssh"
need rpm2cpio "rpm"
need cpio "cpio"
need ar "binutils"
sshd=$(command -v sshd || echo /usr/sbin/sshd)
[ -x "$sshd" ] || { echo "e2e: needs sshd (openssh-server)" >&2; exit 2; }

case $(uname -m) in
  x86_64) deb_arch=amd64 rpm_arch=x86_64 appimage_arch=amd64 feed_arch=x86_64 ;;
  aarch64) deb_arch=arm64 rpm_arch=aarch64 appimage_arch=aarch64 feed_arch=aarch64 ;;
  *) echo "e2e: unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
next=$(echo "$version" | awk -F. '{ print $1 "." $2 "." ($3 + 1) }')
appimage="morphgate_${version}_${appimage_arch}.AppImage"
next_appimage="morphgate_${next}_${appimage_arch}.AppImage"
deb="morphgate_${version}_${deb_arch}.deb"
rpm="morphgate-${version}-1.${rpm_arch}.rpm"

# Test packages: signed with a throwaway update key (its public half replaces the real one), and
# allowed to fetch updates over plain HTTP from the local feed. Never release these.
if [ "${E2E_SKIP_BUILD:-}" != 1 ]; then
  mkdir -p "$artifacts"
  rm -f "$artifacts/update-key" "$artifacts/update-key.pub"
  (cd "$desktop" && npx tauri signer generate --ci -w "$artifacts/update-key" >/dev/null)
  pubkey=$(cat "$artifacts/update-key.pub")
  config="\"plugins\":{\"updater\":{\"pubkey\":\"$pubkey\",\"dangerousInsecureTransportProtocol\":true}}"
  bundle="$target/release/bundle"
  export TAURI_SIGNING_PRIVATE_KEY="$(cat "$artifacts/update-key")" TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
  echo "e2e: building $version (AppImage, deb, rpm)"
  (cd "$desktop" && npx tauri build --config "{$config}")
  # Moved, not copied: test packages must not be left where release packages go.
  mv "$bundle/appimage/$appimage" "$bundle/appimage/$appimage.sig" "$bundle/deb/$deb" "$bundle/rpm/$rpm" "$artifacts/"
  rm -f "$bundle/deb/$deb.sig" "$bundle/rpm/$rpm.sig"
  echo "e2e: building $next (AppImage), the update"
  (cd "$desktop" && npx tauri build --bundles appimage --config "{\"version\":\"$next\",$config}")
  mv "$bundle/appimage/$next_appimage" "$bundle/appimage/$next_appimage.sig" "$artifacts/"
fi
for f in "$appimage" "$next_appimage" "$next_appimage.sig" "$deb" "$rpm"; do
  [ -f "$artifacts/$f" ] || { echo "e2e: missing $artifacts/$f (run without E2E_SKIP_BUILD)" >&2; exit 2; }
done

run="$out/run-$(date +%Y%m%d-%H%M%S)"
# A Unix socket's path has room for about 100 characters, which a CI runner's work folder can use
# up: the kept sessions' tmux socket goes in a short folder.
tmux_dir=$(mktemp -d /tmp/mg-tmux.XXXXXX)
mkdir -p "$run/sshd" "$run/feed" "$run/sync" "$run/appimage/shots" "$run/deb/shots" "$run/rpm/shots" "$run/teams/shots" "$run/layout/shots" "$run/mobile/shots"
pids=""
cleanup() {
  [ -n "$pids" ] && kill $pids 2>/dev/null
  # The kept sessions' tmux server (its own socket directory, never yours).
  TMUX_TMPDIR="$tmux_dir" tmux kill-server 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$tmux_dir"
  # The AppImages unpacked to run (APPIMAGE_EXTRACT_AND_RUN): a few hundred MB per launch of a
  # new build, otherwise left behind in /tmp by every run.
  rm -rf "$run/appimage/tmp"
}
trap cleanup EXIT INT TERM

# A throwaway sshd on loopback, key login for the current user only. SFTP sessions start in
# $run/sshd/home, whose .ssh/authorized_keys is the one sshd reads: what the app edits there
# (teams offboarding) never touches your real home.
ssh-keygen -q -t ed25519 -N '' -f "$run/sshd/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$run/sshd/client_key"
# A user CA: keys it certifies for the user sign in without being in authorized_keys.
ssh-keygen -q -t ed25519 -N '' -C "e2e user CA" -f "$run/sshd/user_ca"
# A host CA: the host key's certificate names 127.0.0.3, an address nothing has pinned.
ssh-keygen -q -t ed25519 -N '' -C "e2e host CA" -f "$run/sshd/host_ca"
ssh-keygen -q -s "$run/sshd/host_ca" -I e2e-host -h -n 127.0.0.3 "$run/sshd/host_key.pub"
mkdir -p "$run/sshd/home/.ssh"
chmod 700 "$run/sshd/home/.ssh"
cp "$run/sshd/client_key.pub" "$run/sshd/home/.ssh/authorized_keys"
cat >"$run/sshd/sshd_config" <<CONFIG
Port $ssh_port
ListenAddress 127.0.0.1
# A second address (all of 127/8 is loopback on Linux): hosts imported from other clients are
# new to the vault there.
ListenAddress 127.0.0.2
# The host certificate's address (a client that trusts the host CA asks for it there).
ListenAddress 127.0.0.3
HostKey $run/sshd/host_key
HostCertificate $run/sshd/host_key-cert.pub
PidFile $run/sshd/sshd.pid
AuthorizedKeysFile $run/sshd/home/.ssh/authorized_keys
TrustedUserCAKeys $run/sshd/user_ca.pub
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
AllowUsers $(id -un)
Subsystem sftp internal-sftp -d $run/sshd/home
# Kept sessions get their own tmux server.
SetEnv TMUX_TMPDIR=$tmux_dir
CONFIG
"$sshd" -D -e -f "$run/sshd/sshd_config" >"$run/sshd/sshd.log" 2>&1 &
pids="$pids $!"

node "$here/feed.mjs" "$run/feed" "$feed_port" "$artifacts/$next_appimage" "$next" "linux-$feed_arch" >"$run/feed.log" 2>&1 &
pids="$pids $!"
for _ in $(seq 1 50); do
  curl -s "http://127.0.0.1:$feed_port/latest.json" >/dev/null 2>&1 && break
  sleep 0.2
done

export MORPHGATE_UPDATE_ENDPOINT="http://127.0.0.1:$feed_port/latest.json"

# A stand-in for Vallic Cloud's console, whose production environment is the sshd above.
node "$here/vallic-console.mjs" "$vallic_port" 127.0.0.2 "$ssh_port" "$(id -un)" >"$run/vallic.log" 2>&1 &
pids="$pids $!"
for _ in $(seq 1 50); do
  curl -s "http://127.0.0.1:$vallic_port/e2e/keys" >/dev/null 2>&1 && break
  sleep 0.2
done
export MORPHGATE_VALLIC_CONSOLE="http://127.0.0.1:$vallic_port"

# A stand-in aws CLI (clouds/aws), whose running instance is the sshd above.
export MORPHGATE_CLOUD_CLI_DIR="$here/clouds" E2E_CLOUD_PORT="$ssh_port" E2E_CLOUD_USER="$(id -un)"

# The reference sync server (open registration, invite codes instead of mail), for teams and layout.
if want teams || want layout; then
  cargo build --release --quiet -p vault-sync-server --manifest-path "$root/Cargo.toml"
  "$target/release/vault-sync-server" --listen "127.0.0.1:$sync_port" --db "$run/sync/vault-sync.sqlite3" \
    --registration open >"$run/sync/server.log" 2>&1 &
  pids="$pids $!"
  # An identity provider for the team's single sign-on.
  node "$here/idp.mjs" "$idp_port" morphgate s3cret >"$run/sync/idp.log" 2>&1 &
  pids="$pids $!"
  for _ in $(seq 1 50); do
    curl -s "http://127.0.0.1:$sync_port/.well-known/vault-sync" >/dev/null 2>&1 && break
    sleep 0.2
  done
fi

if want appimage; then
  echo "e2e: AppImage"
  cp "$artifacts/$appimage" "$run/appimage/"
  # APPIMAGELAUNCHER_DISABLE: where AppImageLauncher is installed, it takes over every AppImage
  # launch (binfmt), the app's own relaunch after an update included. TMPDIR: where an AppImage
  # unpacks to run, in the run's folder rather than /tmp, removed when the run ends.
  mkdir -p "$run/appimage/tmp"
  APPIMAGE_EXTRACT_AND_RUN=1 APPIMAGELAUNCHER_DISABLE=1 TMPDIR="$run/appimage/tmp" MORPHGATE_BROWSER="$here/browser.sh" \
    dbus-run-session -- "$here/session.sh" "$run/appimage" \
    node "$here/appimage.mjs" "$run/appimage/$appimage" "$run/appimage/shots" "$run/feed" \
    "$run/sshd/client_key" "$ssh_port" "$(id -un)" "$version" "$next" 2>"$run/appimage/stderr.log"
fi

if want rpm; then
  echo "e2e: rpm"
  mkdir -p "$run/rpm/root"
  (cd "$run/rpm/root" && rpm2cpio "$artifacts/$rpm" | cpio -idm --quiet)
  dbus-run-session -- "$here/session.sh" "$run/rpm" \
    node "$here/package.mjs" "$run/rpm/root/usr/bin/morphgate" "$run/rpm/shots" "RPM package" "$version" "$next" 2>"$run/rpm/stderr.log"
fi

if want deb; then
  echo "e2e: deb"
  mkdir -p "$run/deb/root"
  (cd "$run/deb/root" && ar x "$artifacts/$deb" && tar -xzf data.tar.gz)
  dbus-run-session -- "$here/session.sh" "$run/deb" \
    node "$here/package.mjs" "$run/deb/root/usr/bin/morphgate" "$run/deb/shots" "Debian package" "$version" "$next" 2>"$run/deb/stderr.log"
fi

if want teams; then
  echo "e2e: teams (two apps, one sync server)"
  mkdir -p "$run/teams/root"
  (cd "$run/teams/root" && rpm2cpio "$artifacts/$rpm" | cpio -idm --quiet)
  MORPHGATE_BROWSER="$here/browser.sh" E2E_PEOPLE="alice bob carol" dbus-run-session -- "$here/session.sh" "$run/teams" \
    node "$here/teams.mjs" "$run/teams/root/usr/bin/morphgate" "$run/teams/shots" "http://127.0.0.1:$sync_port" \
    "$run/sshd/client_key" "$ssh_port" "$(id -un)" "$run/sshd/home/.ssh/authorized_keys" \
    "$target/release/vault-sync-server" "$run/sync/vault-sync.sqlite3" "http://127.0.0.1:$idp_port" \
    2>"$run/teams/stderr.log"
fi

if want layout; then
  echo "e2e: layout (every page at four window widths)"
  mkdir -p "$run/layout/root"
  (cd "$run/layout/root" && rpm2cpio "$artifacts/$rpm" | cpio -idm --quiet)
  dbus-run-session -- "$here/session.sh" "$run/layout" \
    node "$here/layout.mjs" "$run/layout/root/usr/bin/morphgate" "$run/layout/shots" "http://127.0.0.1:$sync_port" \
    2>"$run/layout/stderr.log"
fi

if want mobile; then
  echo "e2e: mobile (the phone layout, in a phone-sized window)"
  mkdir -p "$run/mobile/root"
  (cd "$run/mobile/root" && rpm2cpio "$artifacts/$rpm" | cpio -idm --quiet)
  # Its own key: teams replaces the keys it shared on the test host.
  ssh-keygen -q -t ed25519 -N '' -f "$run/mobile/key"
  cat "$run/mobile/key.pub" >>"$run/sshd/home/.ssh/authorized_keys"
  dbus-run-session -- "$here/session.sh" "$run/mobile" \
    node "$here/mobile.mjs" "$run/mobile/root/usr/bin/morphgate" "$run/mobile/shots" \
    "$run/mobile/key" "$ssh_port" "$(id -un)" 2>"$run/mobile/stderr.log"
fi

echo "e2e: all scenarios passed; screenshots and logs in $run"
