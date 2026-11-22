#!/system/bin/sh
# Refresh the root-manager module card with runtime state and active Zygisk modules.

MODDIR=/data/adb/modules/rezygisk
PROP="$MODDIR/module.prop"
[ -f "$PROP" ] || exit 0

if [ "${1:-}" = "disabled" ]; then
  status="[❌ Disable Magisk's built-in Zygisk]"
else
  tracer="$(awk '/^TracerPid:/{print $2; exit}' /proc/1/status 2>/dev/null)"
  if pidof zygisk-ptrace64 >/dev/null 2>&1 || { [ -n "$tracer" ] && [ "$tracer" != "0" ]; }; then
    status="[Monitor: ✓, ReZygisk 64-bit: ✓]"
  else
    status="[Monitor: ✗, ReZygisk 64-bit: ✗]"
  fi
fi

modules=""
for dir in /data/adb/modules/*; do
  [ -d "$dir" ] || continue
  [ -f "$dir/disable" ] && continue
  [ -f "$dir/remove" ] && continue

  id=${dir##*/}
  [ "$id" = "rezygisk" ] && continue

  standard=false
  next=false
  [ -f "$dir/zygisk/arm64-v8a.so" ] && standard=true
  [ -f "$dir/zn_modules.txt" ] && next=true
  [ "$standard" = true ] || [ "$next" = true ] || continue

  name="$(sed -n 's/^name=//p' "$dir/module.prop" 2>/dev/null | head -n 1)"
  [ -n "$name" ] || name="$id"

  # A module providing both interfaces is listed once, marked as Next.
  [ "$next" = true ] && name="$name (Next)"

  if [ -n "$modules" ]; then
    modules="$modules, $name"
  else
    modules="$name"
  fi
done

[ -n "$modules" ] || modules="none"
modules="$(printf '%s' "$modules" | cut -c 1-180)"
description="$status Modules: $modules"

# Keep module.prop updates atomic so the manager never reads a partial line.
tmp="$PROP.tmp"
awk '!/^description=/' "$PROP" > "$tmp"
printf 'description=%s\n' "$description" >> "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$PROP"
exit 0
