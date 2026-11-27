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

The implementation does not reuse Treat Wheel's companion protocol, daemon operation enums, or module ABI. P3 and P4 are enabled by default at the user's request, with independent global disable markers because they touch private linker state and Bionic process-local buffers. P5 remains guarded by explicit per-module opt-in. All three features also have global disable markers.

| Feature | Runtime scope | Default | Disable switch | Behavior |
|---|---|---|---|---|
| P3 Frida linker-entry cleanup | Denylisted app processes | Enabled by default; global opt-out | `/data/adb/rezygisk/disable-frida-trace-cleanup` | Runtime-probes linker symbols and soinfo layout; removes only exact known Frida agent memfd entries. Unknown linker layouts are skipped. |
| P4 mntent buffer scrub | Denylisted app processes | Enabled by default; global opt-out | `/data/adb/rezygisk/disable-mntent-buffer-scrub` | Clears the process-local last Bionic `getmntent` line buffer. Does not alter the mount table or call setns/umount. |
| P5 ReVanced mount detach | Non-denylisted, non-manager app processes | Enabled when at least one module explicitly opts in | `/data/adb/rezygisk/disable-revanced-mount-umount` | Requires an enabled module with `tw_config` containing `module_type=revanced` and `allow_umount=true`. Parses current `/proc/self/mountinfo`, checks candidate count against opted-in modules, preserves current app package mount, and calls `umount2(MNT_DETACH)` only in the current process mount namespace. |

## Enable / disable

P3 and P4 run by default unless their respective disable marker exists. P5's code path is considered only for enabled ReVanced modules with explicit opt-in configuration.

P3/P4 are enabled by default; no enable marker is required.

A corresponding `disable-*` marker always takes precedence. To disable individual features:

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

- P3 is enabled by default and depends on private Android linker symbols and internal `soinfo` layout. This is not a stable Android ABI. Unknown layouts are skipped; create `/data/adb/rezygisk/disable-frida-trace-cleanup` to disable it if the exact device build has not been validated.
- P3 only recognizes the two exact upstream memfd names. It does not claim to hide all Frida versions, Gum mappings, threads, sockets, file descriptors, or other instrumentation artifacts.
- P4 is enabled by default and uses Bionic `getmntent()`'s process-local static line buffer, clearing the last `mnt_fsname`. It only runs on the process main thread (the pre-specialize call site is expected to be before app threads start); it does not hide entries from a fresh read of `/proc/self/mounts` or `/proc/self/mountinfo`. Because `getmntent()` is non-reentrant, disable it with `/data/adb/rezygisk/disable-mntent-buffer-scrub` if the call timing/thread assumption is not valid for a target ROM.
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
- Current packaging emits per-file SHA-256 sidecars for accidental-corruption detection only. It does not provide artifact authenticity; the legacy Ed25519 files had no consumer and were removed.

## Device validation still required

P3/P4 are enabled unless disabled by their respective marker files; P5 can run only when a module opts in. Test before enabling any of them:
- Android API 25, 29, 30, 34, and current platform releases where available.
- Magisk, KernelSU, and APatch installations supported by the repository.
- App launch, current app APK/resource loading, WebView provider initialization, file picker, DocumentsUI, Download, and app-private file access.
- Soft reboot followed by a full reboot.
- `logcat` for `TreatWheel P3/P4/P5` and ReZygisk tags; inspect AVC denials and compare `/proc/<pid>/mountinfo` before/after P5.

Do not add `allow_umount=true` to a ReVanced module unless its mount behavior has been validated on that device. P5 can affect other processes sharing the current mount namespace.
