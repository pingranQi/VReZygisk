#!/system/bin/sh
MODDIR=${0%/*}
exec sh "$MODDIR/zygisk-init.sh" late-load
