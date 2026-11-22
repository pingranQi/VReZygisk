#!/system/bin/sh

set -e

export TMP_PATH=/data/adb/rezygisk
rm -rf "$TMP_PATH"

rm -f /data/adb/service.d/rezygisk.sh
rm -f /data/adb/late-load.d/rezygisk.sh
rmdir /data/adb/service.d 2>/dev/null || true
rmdir /data/adb/late-load.d 2>/dev/null || true

exit 0
