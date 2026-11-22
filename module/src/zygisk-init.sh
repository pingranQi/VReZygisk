#!/system/bin/sh

set -u

MODDIR=${0%/*}
MODE=${1:-normal}
TMP_PATH=/data/adb/rezygisk

if [ -n "${ZYGISK_ENABLED:-}" ]; then
  exit 0
fi

# Reuse the existing monitor if the late-load hook is replayed.
if ! pidof zygisk-ptrace64 >/dev/null 2>&1; then
  mkdir -p "$TMP_PATH"
  chmod 0755 "$TMP_PATH"
  chcon u:object_r:system_file:s0 "$TMP_PATH" 2>/dev/null || true

  # Restore a clean module.prop before the monitor starts composing status.
  if [ -f "$MODDIR/module.prop.bak" ]; then
    cp "$MODDIR/module.prop.bak" "$MODDIR/module.prop"
  fi

  cd "$MODDIR" || exit 1
  ./bin/zygisk-ptrace64 monitor &
fi

if [ "$MODE" = "late-load" ]; then
  # Wait until the monitor has claimed init and created its control socket.
  tries=0
  while [ "$tries" -lt 50 ]; do
    [ -S "$TMP_PATH/init_monitor" ] && break
    sleep 0.1
    tries=$((tries + 1))
  done

  if [ ! -S "$TMP_PATH/init_monitor" ]; then
    log -p e -t ReZygisk "Late-load monitor did not create init_monitor socket"
    exit 1
  fi

  # The monitor only sees future fork/exec events. Restarting zygote makes
  # init create a fresh app_process instance that can be traced and injected.
  setprop ctl.restart zygote
  setprop ctl.restart zygote_secondary
fi

exit 0
