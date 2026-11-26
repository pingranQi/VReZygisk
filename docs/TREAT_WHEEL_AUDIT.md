# Treat Wheel high-value porting audit

Source: https://github.com/PerformanC/Treat-Wheel-Zygisk
Audited revision: `bed0c0a973503b1aef5f9324ec13dceabc0a8262`
Target base: `519b3f4eb93410f60f9f569be844ac487ed3eee5`

## Port status

P3, P4, and P5 are now implemented independently in:
- `loader/src/injector/treat_wheel_port.c`
- `loader/src/injector/treat_wheel_port.h`
- `loader/src/injector/hook.c`
- `loader/Makefile`

The implementation does not reuse Treat Wheel's companion protocol, daemon operation enums, or module ABI. All three features are fail-open and disabled by default.

| Feature | Runtime scope | Enable switch | Behavior |
|---|---|---|---|
| P3 Frida linker-entry cleanup | Denylisted app processes | `/data/adb/rezygisk/enable-frida-trace-cleanup` | Runtime-probes linker symbols and soinfo layout; removes only exact known Frida agent memfd entries. Unknown linker layouts are skipped. |
| P4 mntent buffer scrub | Denylisted app processes | `/data/adb/rezygisk/enable-mntent-buffer-scrub` | Clears the process-local last Bionic `getmntent` line buffer. Does not alter the mount table or call setns/umount. |
| P5 ReVanced mount detach | Non-denylisted, non-manager app processes | `/data/adb/rezygisk/enable-revanced-mount-umount` | Requires at least one enabled module with `tw_config` containing `module_type=revanced` and `allow_umount=true`. Parses current `/proc/self/mountinfo`, checks the candidate count against opted-in modules, preserves the current app package mount, and calls `umount2(MNT_DETACH)` only in the current process mount namespace. |

## Enable / disable

All features are off unless their marker file exists. To enable:

```sh
su -c 'mkdir -p /data/adb/rezygisk'
su -c 'touch /data/adb/rezygisk/enable-frida-trace-cleanup'
su -c 'touch /data/adb/rezygisk/enable-mntent-buffer-scrub'
su -c 'touch /data/adb/rezygisk/enable-revanced-mount-umount'
```

P5 also requires the opted-in ReVanced module configuration. Example:

```ini
module_type=revanced
allow_umount=true
```

Place that content in `/data/adb/modules/<module_id>/tw_config`. Remove any marker file to disable its corresponding feature. Reboot or restart the affected app processes after changing switches.

## Safety and implementation notes

- P3 depends on private Android linker symbols and internal `soinfo` layout. Symbol presence and candidate offsets are checked at runtime, but this is not a stable Android ABI. It remains opt-in and requires device/API testing before general enablement.
- P3 only recognizes the two exact upstream memfd names. It does not claim to hide all Frida versions, Gum mappings, threads, sockets, file descriptors, or other instrumentation artifacts.
- P4 only clears the last line buffer returned by Bionic `getmntent`; it does not hide entries from a fresh read of `/proc/self/mounts` or `/proc/self/mountinfo`.
- P5 deliberately avoids Treat Wheel's cross-process `setns(pid)` companion protocol. It acts only on the current process namespace, only after ReZygisk has completed its own namespace selection, and skips when the number of candidate `/data/app/~~...` mounts does not match the number of opted-in modules.
- P5 uses lazy detach. It can affect other processes sharing the same mount namespace. The current package's mount is preserved, but app/WebView/file-picker regression testing is mandatory.
- Any failure in P3/P4/P5 is logged and does not abort app specialization.
- Treat Wheel's upstream source is AGPL-3.0; this port is a separate implementation based on behavior analysis. No upstream source file or function body was copied verbatim. This note is attribution, not a legal determination about derivative-work status.

## Compatibility and build

Current target repository constraints from `common.mk`:
- Android API minimum: 25 (`API_LEVEL=25`).
- ABI: `arm64-v8a` only. The current Rust target is `aarch64-linux-android`.
- NDK: `30.0.16248370`.
- Existing root-manager minimums: Magisk 26402, KernelSU 10940 / ksud 11425, APatch 10655.
- The feature code uses runtime linker-symbol capability checks rather than inventing a linker-symbol-to-Android-version mapping.

## CI

Branch: `port/treat-wheel-high-value`
Commit: `1942fa98f882ac225e4edc3fd9bc9c641a97c1d1`
Workflow run: https://github.com/pingranQi/VReZygisk/actions/runs/45843830408

- Mountinfo host unit tests: passed.
- Android build: passed.
- Release artifact: `ReZygisk-v1.0.0-706-457afdd-release.zip`
  - SHA-256: `9fb4fc3208337a29ca131e40025cee2ffe22e5f5145c714763ac5e562a289947`
- Debug artifact: `ReZygisk-v1.0.0-706-457afdd-debug.zip`
  - SHA-256: `eb33d727db19878b878fd70b7ae525ce26d743c0e79ffda074d398c2570cf32e`
- CI did not sign the artifacts because no private/public signing keys were configured.

## Device validation still required

Before enabling any switch on a daily-use device, test:
- Android API 25, 29, 30, 34, and current platform releases where available.
- Magisk, KernelSU, and APatch installations supported by the repository.
- App launch, current app APK/resource loading, WebView provider initialization, file picker, DocumentsUI, Download, and app-private file access.
- Soft reboot followed by a full reboot.
- `logcat` for `TreatWheel P3/P4/P5` and ReZygisk tags; inspect AVC denials and compare `/proc/<pid>/mountinfo` before/after P5.

Do not enable P5 globally if the device has additional app-specific bind mounts that are not represented by opted-in ReVanced module configurations.
