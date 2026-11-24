# Linker overhaul audit

> Scope: ARM64-only VReZygisk. This document records the initial source audit before implementation.
> Reference projects: YukiZygisk/YukiLinker and Zygisk Next (ZN Linker).
> This is an engineering plan, not a claim that the listed features are implemented.

## Existing architecture

VReZygisk currently has two distinct loading paths:

1. **In-process module loader**: `loader/src/injector/hook.c` calls the pinned CSOLoader submodule first and can fall back to Bionic `dlopen`. CSOLoader is pinned at `0d29278cf60a3c38850dde3eaf07b0ffc3241f03`.
2. **Ptracer bootstrap mapper**: `loader/src/ptracer/remote_csoloader.c` maps the initial ELF into the target process, resolves its dynamic dependencies and relocations, and resolves the entry point. This is a separate implementation; improvements to CSOLoader do not automatically improve this path.

Keep these paths separate in the design and test plans. They have different address spaces, dependency resolution constraints, and rollback requirements.

## Findings

### P0 — correctness and memory-safety gates

- The remote mapper explicitly rejects `PT_TLS`, `DT_RELR`, Android packed relocations, and `STT_GNU_IFUNC`. These are honest fail-closed checks and must remain until complete implementations and tests exist.
- The remote mapper supports a deliberately small relocation set. On AArch64 its RELA path handles RELATIVE, GLOB_DAT, JUMP_SLOT and ABS64; unsupported types fail. TLS, IRELATIVE and other architecture-specific cases are not handled there.
- Segment bookkeeping uses a fixed 64-entry array. The parser must reject excess PT_LOAD entries before mapping; silent truncation would leave permissions incomplete.
- All dynamic pointers and relocation targets must be proven to fall inside validated PT_LOAD/file-backed ranges before reads, writes or arithmetic. Keep file offsets distinct from target virtual addresses.
- Failure after remote mapping begins must restore target registers and release every remote fd/mapping. Cleanup errors need to be preserved separately from the original failure.
- In-process CSOLoader's ELF parser is section-header-oriented in several paths. Runtime loading must not depend on section headers being present; PT_DYNAMIC and dynamic tags are the authoritative runtime metadata.
- CSOLoader's TLS implementation is a pthread-key based emulation with a fixed 128-module table. It is not equivalent to Bionic's native TLS ABI. Audit thread-exit, unload/reuse, fork, concurrent registration and TLSDESC semantics before expanding its support claims.

### P1 — ABI and linker compatibility

- Add bounded, explicit support and tests for Android packed REL/RELA and RELR only after parser and relocation transaction design is complete.
- Add GNU symbol versioning (`DT_VERSYM`, `DT_VERDEF`, `DT_VERNEED`) to symbol lookup; plain name matching is insufficient for versioned dependencies.
- Audit symbol scope and precedence: main image, ordered DT_NEEDED dependencies, global/weak symbols, visibility, symbol type, version, and duplicate names.
- Audit IFUNC and IRELATIVE as executable resolver operations. They require a defined execution context, ordering, error handling and rollback; never substitute resolver `st_value` for the resolved address.
- Audit dependency recursion, cycles, duplicate SONAMEs, maximum dependency count, path provenance and missing dependency behavior.
- Audit constructor/destructor order, `DT_INIT`/`DT_INIT_ARRAY`, `DT_FINI_ARRAY`/`DT_FINI`, partial constructor failure, and one-time finalization.

### P2 — lifecycle, observability and maintainability

- Define an explicit image state machine: parsed -> reserved -> mapped -> relocated -> protected -> initialized -> active -> finalizing -> unmapped. Every transition needs rollback semantics.
- Make load/unload and shared dependency ownership safe under concurrent requests. Existing CSOLoader global TLS/linker state and active-linker tracking require a concurrency audit.
- Validate W^X and PT_GNU_RELRO final permissions, page overlap, BSS tails, segment alignment and cache maintenance.
- Add structured diagnostics identifying stage, ELF object, dynamic tag/relocation, symbol, target address, errno and cleanup status.
- Add host-side ELF fixtures and Android device tests for API levels, Bionic variants, concurrent load/unload, fork, TLS, C++ exceptions/unwind and module callbacks.

## Reference-derived design points

- **YukiLinker** demonstrates a separate loader runtime with explicit library ownership, execution leases, retained failed operations, private-image tracking and controlled Bionic fallback. The transferable lesson is lifecycle discipline and backend boundaries, not copying its kernel/runtime integration.
- **ZN Linker** documents a staged feature set: packed relocations, RELR, TLS relocation, symbol lookup and lifecycle-related compatibility. Treat each feature as an independently testable capability, not a single "custom linker enabled" switch.
- VReZygisk should retain Bionic fallback for unsupported images. A custom backend must report a precise failure and fully roll back before fallback; never fall back after constructors or other image code may have executed unless the state is proven safe.

## Implementation sequence

1. Freeze the existing submodule pin and record baseline build/test behavior.
2. Harden the remote ELF parser and mapping transaction without expanding supported relocation types.
3. Add a dedicated ELF/dynamic-table validation layer and regression fixtures.
4. Improve in-process CSOLoader integration and lifecycle/error contracts; upstream reusable fixes where practical.
5. Add relocation and symbol features incrementally: RELR, Android packed relocations, GNU symbol versions, then IFUNC/IRELATIVE only with a safe resolver execution model.
6. Rework TLS only after deciding whether the supported ABI is emulated TLS or true Bionic-compatible TLS. Do not advertise the former as the latter.
7. Add stress, fork, unload, Android API matrix and device validation; update documentation only after evidence exists.

## Non-goals for this branch

- No blind source-code or binary copying from reference projects.
- No bypass claims or guarantees against third-party detection.
- No weakening of ELF validation or fail-closed behavior to make more modules appear to load.
- No change to the main branch until the branch passes review and CI.
