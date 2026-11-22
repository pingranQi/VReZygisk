#!/system/bin/sh
# KernelSU late-load stage entry. Installed in /data/adb/late-load.d/.
set -u
MODDIR=/data/adb/modules/rezygisk
[ -x "$MODDIR/start-monitor.sh" ] || exit 0
exec "$MODDIR/start-monitor.sh" late
