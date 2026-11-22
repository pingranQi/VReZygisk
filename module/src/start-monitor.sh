#!/system/bin/sh
# Shared monitor bootstrap for normal boot and KernelSU late-load.

set -u

MODDIR=/data/adb/modules/rezygisk
TMP_PATH=/data/adb/rezygisk
MODE=${1:-boot}

[ -d "$MODDIR" ] || exit 0
[ ! -f "$MODDIR/disable" ] || exit 0
[ ! -f "$MODDIR/remove" ] || exit 0

cd "$MODDIR" || exit 1

# Serialize concurrent post-fs-data / late-load invocations.
LOCK=/data/adb/rezygisk-monitor.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  owner=""
  [ -r "$LOCK/pid" ] && owner="$(cat "$LOCK/pid" 2>/dev/null)"
  if [ -n "$owner" ] && [ -d "/proc/$owner" ]; then
    exit 0
  fi
  rm -rf "$LOCK"
  mkdir "$LOCK" 2>/dev/null || exit 0
fi
echo $$ > "$LOCK/pid"
trap 'rm -rf "$LOCK"' EXIT

# Do not start a second monitor. TracerPid catches the interval before the
# monitor has exec'd under its final process name.
init_tracer="$(awk '/^TracerPid:/{print $2; exit}' /proc/1/status 2>/dev/null || true)"
if [ -n "$init_tracer" ] && [ "$init_tracer" != "0" ]; then
  exit 0
fi
if pidof zygisk-ptrace64 >/dev/null 2>&1; then
  exit 0
fi

if [ "$MODE" = "boot" ]; then
  rm -rf "$TMP_PATH"
fi
mkdir -p "$TMP_PATH"
chmod 555 "$TMP_PATH" 2>/dev/null || true
chcon u:object_r:system_file:s0 "$TMP_PATH" 2>/dev/null || true
export TMP_PATH

# The monitor binds this endpoint. Remove only its stale socket; daemon
# sockets may still belong to a live daemon during soft reboot.
rm -f "$TMP_PATH/init_monitor"

# This package contains only the arm64 monitor and daemon.
MONITOR="$MODDIR/bin/zygisk-ptrace64"
if [ ! -x "$MONITOR" ]; then
  echo "ReZygisk: arm64 monitor binary is missing" >&2
  exit 1
fi

if [ "$MODE" = "boot" ] && [ -f "$MODDIR/module.prop.bak" ]; then
  cp "$MODDIR/module.prop.bak" "$MODDIR/module.prop"
fi

"$MONITOR" monitor &
exit 0
