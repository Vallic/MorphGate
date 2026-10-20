#!/bin/sh
# Runs one scenario: a headless mutter, tauri-driver, then the given command. Meant to run under
# dbus-run-session (a private session bus), with HOME and the XDG dirs moved to <dir>/home so the
# app never sees real data or the real desktop.
#
#   dbus-run-session -- session.sh <dir> <command…>
#
# With E2E_PEOPLE="alice bob", each person gets their own tauri-driver and HOME
# (<dir>/<person>/home), so several apps run side by side; the command finds each driver in
# WD_URL_ALICE, WD_URL_BOB, …. Drivers listen on free ports (E2E_DRIVER_PORT: from that one up,
# two per driver).
set -u
dir=$1
shift
display=mg-e2e-$$
here=$(dirname "$0")

# A screen wide enough for every app side by side: WebKitGTK can't screenshot a window another
# one covers completely (without a GPU, as on CI runners, the screenshot never returns). And
# well larger than the app's window, which mutter otherwise maximizes (it then ignores resizes).
people=$(echo ${E2E_PEOPLE:-one} | wc -w)
if [ -n "${E2E_DRIVER_PORT:-}" ]; then
  ports=$(seq "$E2E_DRIVER_PORT" "$((E2E_DRIVER_PORT + 2 * people - 1))")
else
  ports=$(node "$here/free-ports.mjs" "$((2 * people))")
fi
# The next driver's port and native port, from $ports.
take() {
  set -- $ports
  port=$1 native=$2
  shift 2
  ports="$*"
}
mutter --headless --no-x11 --wayland-display="$display" --virtual-monitor "$((1920 * people))x1080" >"$dir/mutter.log" 2>&1 &
pids=$!
for _ in $(seq 1 50); do
  [ -S "$XDG_RUNTIME_DIR/$display" ] && break
  sleep 0.2
done

export WAYLAND_DISPLAY=$display GDK_BACKEND=wayland
unset DISPLAY

# tauri-driver on `port` (WebKitWebDriver on `native`) for an app whose HOME is `home`.
driver() {
  (
    export HOME="$1"
    export XDG_DATA_HOME="$HOME/.local/share" XDG_CONFIG_HOME="$HOME/.config" XDG_CACHE_HOME="$HOME/.cache"
    mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
    exec "${TAURI_DRIVER:-tauri-driver}" --port "$2" --native-port "$4"
  ) >"$3" 2>&1 &
  pids="$pids $!"
  for _ in $(seq 1 50); do
    curl -s "http://127.0.0.1:$2/status" >/dev/null 2>&1 && break
    sleep 0.2
  done
}

if [ -z "${E2E_PEOPLE:-}" ]; then
  take
  driver "$dir/home" "$port" "$dir/tauri-driver.log" "$native"
  export WD_URL="http://127.0.0.1:$port" HOME="$dir/home"
  export XDG_DATA_HOME="$HOME/.local/share" XDG_CONFIG_HOME="$HOME/.config" XDG_CACHE_HOME="$HOME/.cache"
else
  for person in $E2E_PEOPLE; do
    mkdir -p "$dir/$person"
    take
    driver "$dir/$person/home" "$port" "$dir/$person/tauri-driver.log" "$native"
    export "WD_URL_$(echo "$person" | tr '[:lower:]' '[:upper:]')=http://127.0.0.1:$port"
  done
fi

"$@"
status=$?
kill $pids 2>/dev/null
wait 2>/dev/null
exit $status
