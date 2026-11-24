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
- In-process CSOLoader supports a pthread-key based emulated TLS implementation (128 module slots), including AArch64 DTPMOD/DTPREL/TPREL and TLSDESC paths. This is not Bionic's native static-TLS ABI; ordinary modules with PT_TLS are therefore routed to Bionic by the VReZygisk integration until the emulation has dedicated device tests.
- CSOLoader's symbol parser is section-header-oriented and does not implement GNU symbol version selection. VReZygisk now detects GNU version tags in PT_DYNAMIC and routes those images to Bionic rather than silently performing unversioned lookup.
- CSOLoader does not consume Android packed relocation or RELR dynamic tables. The integration now detects these tags and routes such images to Bionic.
- CSOLoader has process-global active-linker and TLS registries. VReZygisk serializes its public load, lookup, unload, abandon and deinit calls with a process mutex; the module entry point and specialization callbacks are deliberately invoked outside that mutex.

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

1. Freeze the existing CSOLoader submodule pin and record baseline build/test behavior.
2. Serialize access to CSOLoader's process-global registries and keep callbacks outside the lock.
3. Add a bounded PT_DYNAMIC feature probe; route PT_TLS, GNU symbol versioning, Android packed relocations and RELR to Bionic until native custom support is implemented and tested.
4. Harden the remote ELF parser and mapping transaction without expanding supported relocation types.
5. Implement missing remote relocation and resolver features only with a target-thread execution model, rollback and regression fixtures.
6. Add symbol scope/versioning and TLS ABI support to the custom backend only when the pinned dependency can be safely patched and validated.
7. Add stress, fork, unload, Android API matrix and device validation; update support claims only after evidence exists.

## Non-goals for this branch

- No blind source-code or binary copying from reference projects.
- No bypass claims or guarantees against third-party detection.
- No weakening of ELF validation or fail-closed behavior to make more modules appear to load.
- No change to the main branch until the branch passes review and CI.
