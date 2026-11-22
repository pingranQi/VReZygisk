# shellcheck disable=SC2034
SKIPUNZIP=1

DEBUG=@DEBUG@
MIN_KSU_VERSION=@MIN_KSU_VERSION@
MIN_KSUD_VERSION=@MIN_KSUD_VERSION@
MIN_MAGISK_VERSION=@MIN_MAGISK_VERSION@
MIN_APATCH_VERSION=@MIN_APATCH_VERSION@

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if ! [ "$KSU_KERNEL_VER_CODE" ] || [ "$KSU_KERNEL_VER_CODE" -lt "$MIN_KSU_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! KernelSU version is too old!"
    ui_print "! Please update KernelSU to latest version"
    abort    "*********************************************************"
  fi
  if ! [ "$KSU_VER_CODE" ] || [ "$KSU_VER_CODE" -lt "$MIN_KSUD_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! ksud version is too old!"
    ui_print "! Please update KernelSU Manager to latest version"
    abort    "*********************************************************"
  fi
  if [ "$(which magisk)" ]; then
    ui_print "*********************************************************"
    ui_print "! Multiple root implementation is NOT supported!"
    ui_print "! Please uninstall Magisk before installing ReZygisk"
    abort    "*********************************************************"
  fi
  elif [ "$BOOTMODE" ] && [ "$APATCH" ]; then
    ui_print "- Installing from APatch app"
    if ! [ "$APATCH_VER_CODE" ] || [ "$APATCH_VER_CODE" -lt "$MIN_APATCH_VERSION" ]; then
      ui_print "*********************************************************"
      ui_print "! APatch version is too old!"
      ui_print "! Please update APatch to latest version"
      abort    "*********************************************************"
    fi
elif [ "$BOOTMODE" ] && [ "$MAGISK_VER_CODE" ]; then
  ui_print "- Installing from Magisk app"
  if [ "$MAGISK_VER_CODE" -lt "$MIN_MAGISK_VERSION" ]; then
    ui_print "*********************************************************"
    ui_print "! Magisk version is too old!"
    ui_print "! Please update Magisk to latest version"
    abort    "*********************************************************"
  fi
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from KernelSU or Magisk app"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing ReZygisk $VERSION"

# check android
if [ "$API" -lt 25 ]; then
  ui_print "! Unsupported sdk: $API"
  abort "! Minimal supported sdk is 25 (Android 7.1)"
else
  ui_print "- Device sdk: $API"
fi

# This build targets arm64 only. Reject 32-bit and x86 devices explicitly.
if [ "$ARCH" != "arm64" ]; then
  abort "! ReZygisk supports arm64 devices only"
fi

CPU_ABIS="$(getprop ro.product.cpu.abilist64)"
case ",$CPU_ABIS," in
  *,arm64-v8a,*) ;;
  *) abort "! This device does not expose the arm64-v8a ABI" ;;
esac

ui_print "- Device ABI: arm64-v8a"

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'      "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh'  "$MODPATH"
extract "$ZIPFILE" 'service.sh'       "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'     "$MODPATH"
extract "$ZIPFILE" 'start-monitor.sh' "$MODPATH"
extract "$ZIPFILE" 'late-load.sh'     "$MODPATH"
extract "$ZIPFILE" 'update-description.sh' "$MODPATH"
extract "$ZIPFILE" 'rezygisk.sh' "/data/adb/service.d/"

# KernelSU executes scripts in /data/adb/late-load.d after ksud late-load.
if [ "$KSU" ]; then
  mkdir -p /data/adb/late-load.d
  cp "$MODPATH/late-load.sh" /data/adb/late-load.d/rezygisk.sh
  chmod 0755 /data/adb/late-load.d/rezygisk.sh
fi

cp "$MODPATH/module.prop" "$MODPATH/module.prop.bak"

chmod +x "$MODPATH/uninstall.sh"
chmod +x "$MODPATH/start-monitor.sh"
chmod +x "$MODPATH/late-load.sh"
chmod +x "$MODPATH/update-description.sh"
chmod +x "/data/adb/service.d/rezygisk.sh"

mv "$TMPDIR/sepolicy.rule" "$MODPATH"

mkdir "$MODPATH/bin" "$MODPATH/lib64"

ui_print "- Extracting arm64-v8a libraries"
extract "$ZIPFILE" 'bin/arm64-v8a/zygiskd' "$MODPATH/bin" true
mv "$MODPATH/bin/zygiskd" "$MODPATH/bin/zygiskd64"
extract "$ZIPFILE" 'lib/arm64-v8a/libzygisk.so' "$MODPATH/lib64" true
extract "$ZIPFILE" 'lib/arm64-v8a/libzygisk_ptrace.so' "$MODPATH/bin" true
mv "$MODPATH/bin/libzygisk_ptrace.so" "$MODPATH/bin/zygisk-ptrace64"

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/lib64" 0 0 0755 0644 u:object_r:system_lib_file:s0

# If Huawei's Maple is enabled, system_server is created with a special way which is out of Zygisk's control
HUAWEI_MAPLE_ENABLED=$(grep_prop ro.maple.enable)
if [ "$HUAWEI_MAPLE_ENABLED" == "1" ]; then
  ui_print "- Add ro.maple.enable=0"
  echo "ro.maple.enable=0" >>"$MODPATH/system.prop"
fi
