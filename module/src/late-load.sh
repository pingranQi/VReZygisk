#!/system/bin/sh
# KernelSU late-load stage entry. Installed in /data/adb/late-load.d/.
# Existing Zygote has already passed __libc_init, the only supported injection
# point in the current ptracer. Restarting the init zygote service after the
# monitor seizes init makes it exec again and gives ReZygisk a real injection
# point. This is a framework soft restart: running apps/system_server will stop.

set -u

MODDIR=/data/adb/modules/rezygisk
[ ! -f "$MODDIR/disable" ] || exit 0
[ ! -f "$MODDIR/remove" ] || exit 0
[ -x "$MODDIR/start-monitor.sh" ] || exit 0

# A monitor that survived a soft reboot already observed the reboot-driven
# Zygote restart. Do not trigger a second framework restart on stage replay.
existing_tracer="$(awk '/^TracerPid:/{print $2; exit}' /proc/1/status 2>/dev/null || true)"
if { [ -n "$existing_tracer" ] && [ "$existing_tracer" != "0" ]; } ||
   pidof zygisk-ptrace64 >/dev/null 2>&1 ||
   pidof zygisk-ptrace32 >/dev/null 2>&1; then
  "$MODDIR/start-monitor.sh" late
  exit 0
fi

"$MODDIR/start-monitor.sh" late

# Wait for monitor to seize init before restarting Zygote. A bounded wait
# avoids restarting the framework when monitor startup failed.
attempt=0
while [ "$attempt" -lt 20 ]; do
  tracer="$(awk '/^TracerPid:/{print $2; exit}' /proc/1/status 2>/dev/null || true)"
  [ -n "$tracer" ] && [ "$tracer" != "0" ] && break
  attempt=$((attempt + 1))
  sleep 0.25
done

if [ -z "${tracer:-}" ] || [ "$tracer" = "0" ]; then
  echo "ReZygisk: monitor did not seize init; leaving Zygote untouched" >&2
  exit 1
fi

# Ensure the tracer survived socket/event-loop initialization, not just a
# transient TracerPid update while a failed monitor is exiting.
sleep 0.5
tracer_check="$(awk '/^TracerPid:/{print $2; exit}' /proc/1/status 2>/dev/null || true)"
if [ -z "$tracer_check" ] || [ "$tracer_check" = "0" ] ||
   { ! pidof zygisk-ptrace64 >/dev/null 2>&1 && ! pidof zygisk-ptrace32 >/dev/null 2>&1; }; then
  echo "ReZygisk: monitor failed to stay alive; leaving Zygote untouched" >&2
  exit 1
fi

# Re-exec Zygote so injection runs at its supported early startup point.
if [ "$(getprop init.svc.zygote)" = "running" ]; then
  log -p i -t ReZygisk "Late-load: restarting zygote for first injection"
  setprop ctl.restart zygote
fi

if [ "$(getprop init.svc.zygote_secondary)" = "running" ]; then
  log -p i -t ReZygisk "Late-load: restarting secondary zygote"
  setprop ctl.restart zygote_secondary
fi

exit 0
