# Treat Wheel high-value porting audit

Source: https://github.com/PerformanC/Treat-Wheel-Zygisk
Audited revision: `bed0c0a973503b1aef5f9324ec13dceabc0a8262`
Target base: `519b3f4eb93410f60f9f569be844ac487ed3eee5`

## Decision

Do not merge Treat Wheel wholesale into ReZygisk. Treat Wheel is a separate Zygisk module and depends on ReZygisk-specific companion behavior. P1 has been independently implemented as a parser only. P3/P4/P5 remain excluded: they conceal instrumentation or mount traces from app-side inspection, which is not an appropriate core feature to add. P2 remains a separate opt-in compatibility candidate.

## Candidate ranking

| Priority | Source area | Value | Integration risk | Decision |
|---|---|---|---|---|
| P1 | `src/lib/utils.c`: mountinfo tokenization and octal escape decoding | Robust parsing of mountinfo paths containing escaped whitespace, tabs, newlines, and backslashes | Medium; ReZygisk currently has no direct consumer for a new parser | Implemented independently as a reusable parser with strict token validation, octal escape decoding, allocation cleanup, and host unit tests; not wired into runtime behavior yet |
| P2 | `src/lib/hiding.c`: GSI environment cleanup | Removes PHH_STEP1/2/3 environment traces in target app processes | Low; behavior is narrow and should be scoped to selected processes | Not implemented in this pass; could be considered later as a transparent compatibility option |
| P3 | `src/lib/hiding.c`: Frida trace handling | Potentially reduces known linker/runtime traces | Very high; depends on private linker symbols and ABI/layout details | Do not port without API-level symbol validation and device tests |
| P4 | `src/lib/hiding.c`: zygote mountinfo buffer modification | Hides one mountinfo-related trace | High; mutates Bionic-owned parser storage and uses pointer data over IPC | Reject for core integration |
| P5 | `src/lib/hiding.c`: ReVanced mount unmount (RVU) | Removes selected module mounts from target process namespaces | Very high; changes mount visibility and can break APK/resource/file access | Reject for now; requires explicit allow-list, namespace isolation tests, and rollback |
| P6 | `src/lib/hiding.c`: maps hiding | Attempts to replace file-backed mappings with anonymous copies | High; source has a known issue report that its filter condition can make the feature a no-op | Do not copy; current ReZygisk `loader/src/injector/hiding.c` already uses a more defensive snapshot/preflight flow |

## Important compatibility and safety notes

- Treat Wheel README requires ReZygisk 508+ and Android API 25+. Its module ABI and companion protocol are not a drop-in ReZygisk core API.
- Do not transplant `zygisk_companion_entry`, daemon operation enums, or module state structures: they belong to Treat Wheel's own companion protocol.
- Do not transplant private linker symbol lookups from `do_frida_hiding` without runtime branches and symbol validation per Android release.
- Avoid RVU and mountinfo mutation in this porting pass. Mount namespace changes can affect `/data/app`, WebView providers, DocumentsUI, and app data visibility.
- Target repository metadata identifies GPL-3.0, while Treat Wheel declares AGPL-3.0. Do not copy its implementation verbatim into this repository without resolving licensing compatibility or obtaining permission. This audit records behavior and integration decisions; it does not copy Treat Wheel source code.

## Recommended implementation order

1. P1 parser is implemented in `loader/src/common/mountinfo.c` and exposed by `loader/src/include/mountinfo.h`; `make -C loader test-mountinfo` runs host unit tests. It is not yet wired into a runtime consumer.
2. P2 can be evaluated separately as a transparent, opt-in GSI compatibility feature; it is not part of this change.
3. P3/P4/P5 are intentionally not ported. If the underlying goal is compatibility debugging, add non-concealing diagnostics for linker symbols, mountinfo contents, and per-process mount namespace differences instead.

## Validation gate

Any runtime change must pass:
- Build for supported Android ABIs and the repository's existing NDK/toolchain.
- Android API 25, 29, 30, 34, and current platform coverage where available.
- Magisk, KernelSU, and APatch runtime checks.
- App launch, WebView provider initialization, file picker, DocumentsUI, Download, and app-private file access.
- Soft reboot followed by a full reboot regression.
- Logcat and AVC review; no new mount namespace or SELinux failures.
