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

The implementation does not reuse Treat Wheel's companion protocol, daemon operation enums, or module ABI. P3/P4/P5 are enabled by default, fail-open, and can each be disabled with a marker file. P5 retains an explicit per-module opt-in gate.

| Feature | Runtime scope | Default | Disable switch | Behavior |
|---|---|---|---|---|
| P3 Frida linker-entry cleanup | Denylisted app processes | Enabled | `/data/adb/rezygisk/disable-frida-trace-cleanup` | Runtime-probes linker symbols and soinfo layout; removes only exact known Frida agent memfd entries. Unknown linker layouts are skipped. |
| P4 mntent buffer scrub | Denylisted app processes | Enabled | `/data/adb/rezygisk/disable-mntent-buffer-scrub` | Clears the process-local last Bionic `getmntent` line buffer. Does not alter the mount table or call setns/umount. |
| P5 ReVanced mount detach | Non-denylisted, non-manager app processes | Enabled when at least one module explicitly opts in | `/data/adb/rezygisk/disable-revanced-mount-umount` | Requires an enabled module with `tw_config` containing `module_type=revanced` and `allow_umount=true`. Parses current `/proc/self/mountinfo`, checks candidate count against opted-in modules, preserves current app package mount, and calls `umount2(MNT_DETACH)` only in the current process mount namespace. |

## Enable / disable

P3 and P4 run by default for their documented process scopes. P5 runs by default only when at least one enabled ReVanced module has explicitly opted in. No enable marker files are required.

To disable individual features:

```sh
su -c 'mkdir -p /data/adb/rezygisk'
su -c 'touch /data/adb/rezygisk/disable-frida-trace-cleanup'
su -c 'touch /data/adb/rezygisk/disable-mntent-buffer-scrub'
su -c 'touch /data/adb/rezygisk/disable-revanced-mount-umount'
```

P5 requires the opted-in ReVanced module configuration. Example:

```ini
module_type=revanced
allow_umount=true
```

Place that content in `/data/adb/modules/<module_id>/tw_config`. Remove the corresponding `disable-*` file to re-enable a feature. Restart affected app processes after changing switches.
## Safety and implementation notes

- P3 is enabled by default for Denylisted processes and depends on private Android linker symbols and internal `soinfo` layout. Symbol presence and candidate offsets are checked at runtime, but this is not a stable Android ABI. Unknown layouts are skipped; disable it with the documented `disable-frida-trace-cleanup` marker if device testing exposes regressions.
- P3 only recognizes the two exact upstream memfd names. It does not claim to hide all Frida versions, Gum mappings, threads, sockets, file descriptors, or other instrumentation artifacts.
- P4 only clears the last line buffer returned by Bionic `getmntent`; it does not hide entries from a fresh read of `/proc/self/mounts` or `/proc/self/mountinfo`.
- P5's global code path is enabled by default, but actual detach remains explicitly opt-in per ReVanced module through `tw_config`. It deliberately avoids Treat Wheel's cross-process `setns(pid)` companion protocol. It acts only on the current process namespace, only after ReZygisk has completed its own namespace selection, and skips when the number of candidate `/data/app/~~...` mounts does not match the number of opted-in modules.
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

Because P3/P4 now run by default and P5 can run when a module opts in, test before daily use:
- Android API 25, 29, 30, 34, and current platform releases where available.
- Magisk, KernelSU, and APatch installations supported by the repository.
- App launch, current app APK/resource loading, WebView provider initialization, file picker, DocumentsUI, Download, and app-private file access.
- Soft reboot followed by a full reboot.
- `logcat` for `TreatWheel P3/P4/P5` and ReZygisk tags; inspect AVC denials and compare `/proc/<pid>/mountinfo` before/after P5.

Do not add `allow_umount=true` to a ReVanced module unless its mount behavior has been validated on that device. P5 can affect other processes sharing the current mount namespace.
