# Linker overhaul audit

> Scope: ARM64-only VReZygisk. This document records the initial source audit before implementation.
> Reference projects: YukiZygisk/YukiLinker and Zygisk Next (ZN Linker).
> This is an engineering plan, not a claim that the listed features are implemented.

## Existing architecture

VReZygisk currently has two distinct loading paths:

1. **In-process module loader**: `loader/src/injector/hook.c` calls the pinned CSOLoader submodule first and can fall back to Bionic `dlopen`. CSOLoader is pinned at `0d29278cf60a3c38850dde3eaf07b0ffc3241f03`.
2. **Ptracer bootstrap mapper**: `loader/src/ptracer/remote_csoloader.c` maps the initial ELF into the target process, resolves its dynamic dependencies and relocations, and resolves the entry point. This is a separate implementation; improvements to CSOLoader do not automatically improve this path.

Keep these paths separate in the design and test plans. They have different address spaces, dependency resolution constraints, and rollback requirements.

## Implemented in this branch

- Serialized CSOLoader lifecycle and symbol operations, active-image accounting, partial-load cleanup, and pre-constructor path allocation.
- Bounded ELF64/AArch64 PT_DYNAMIC inspection; Bionic routing for PT_TLS and GNU symbol-versioned images.
- Build-time hardening of CSOLoader TLS key creation, TLS allocation metadata, per-thread module generations, module-ID reuse and registration failure propagation.
- Fail-closed remote bootstrap handling for unsupported standard/Android RELR, Android packed relocation, GNU versioning, PT_TLS and IFUNC metadata; defined-symbol bounds and SHN_ABS handling.

### Remaining findings

### P0 — correctness and memory-safety gates

- The remote mapper explicitly rejects `PT_TLS`, `DT_RELR`, Android packed relocations, GNU symbol-version tags and `STT_GNU_IFUNC`. These are honest fail-closed checks and must remain until complete implementations and tests exist.
- The remote mapper supports a deliberately small relocation set. On AArch64 its RELA path handles RELATIVE, GLOB_DAT, JUMP_SLOT and ABS64; unsupported types fail. TLS, IRELATIVE and other architecture-specific cases are not handled there.
- Segment bookkeeping uses a fixed 64-entry array. The parser must reject excess PT_LOAD entries before mapping; silent truncation would leave permissions incomplete.
- All dynamic pointers and relocation targets must be proven to fall inside validated PT_LOAD/file-backed ranges before reads, writes or arithmetic. Keep file offsets distinct from target virtual addresses.
- Failure after remote mapping begins must restore target registers and release every remote fd/mapping. Cleanup errors need to be preserved separately from the original failure.
- The remote bootstrap resolver currently searches the image's direct DT_NEEDED libraries only. It does not yet construct the complete ordered transitive/global lookup scope; keep unresolved symbols fail-closed rather than searching arbitrary resident mappings.
- In-process CSOLoader supports a pthread-key based emulated TLS implementation (128 module slots), including AArch64 DTPMOD/DTPREL/TPREL and TLSDESC paths. This is not Bionic's native static-TLS ABI; ordinary modules with PT_TLS are therefore routed to Bionic by the VReZygisk integration until the emulation has dedicated device tests.
- CSOLoader's symbol parser is section-header-oriented and does not implement GNU symbol version selection. VReZygisk detects GNU version tags in PT_DYNAMIC and routes those images to Bionic rather than silently performing unversioned lookup.
- The pinned CSOLoader contains Android packed relocation, RELR, IFUNC and IRELATIVE handling. Those implementations still require dedicated regression tests; the separate ptracer bootstrap mapper deliberately rejects the unsupported formats.
- CSOLoader has process-global active-linker and TLS registries. VReZygisk serializes its public load, lookup, unload, abandon and deinit calls with a recursive process mutex; the module entry point and specialization callbacks are deliberately invoked outside that mutex.
- A build-time patch hardens TLS key creation and registration failures, per-thread TLS block generation tracking (including module-ID reuse), alignment and offset validation, and TLS registry failure propagation.

### P1 — ABI and linker compatibility

- If the remote bootstrap mapper needs these formats, add bounded Android packed REL/RELA and RELR decoding with transactional rollback; until then its fail-closed rejection is intentional.
- Add GNU symbol version selection to the custom backend only if Bionic fallback is no longer sufficient; the current in-process policy routes versioned images to Bionic.
- Audit symbol scope and precedence: main image, ordered DT_NEEDED dependencies, global/weak symbols, visibility, symbol type, version, and duplicate names.
- Audit the in-process IFUNC/IRELATIVE implementation with regression fixtures. The remote bootstrap mapper must continue rejecting these until it can execute resolvers in the target process with defined ordering and rollback.
- Audit dependency recursion, cycles, duplicate SONAMEs, maximum dependency count, path provenance and missing dependency behavior.
- Audit constructor/destructor order, `DT_INIT`/`DT_INIT_ARRAY`, `DT_FINI_ARRAY`/`DT_FINI`, partial constructor failure, and one-time finalization.

### P2 — lifecycle, observability and maintainability

- Define an explicit image state machine: parsed -> reserved -> mapped -> relocated -> protected -> initialized -> active -> finalizing -> unmapped. Every transition needs rollback semantics.
- Make load/unload and shared dependency ownership safe under concurrent requests. Existing CSOLoader global TLS/linker state and active-linker tracking require a concurrency audit.
- Validate W^X and PT_GNU_RELRO final permissions, page overlap, BSS tails, segment alignment and cache maintenance.
- Add structured diagnostics identifying stage, ELF object, dynamic tag/relocation, symbol, target address, errno and cleanup status.
- Preallocate CSOLoader path bookkeeping before constructors so custom-loader failure cannot fall back to Bionic after module code has executed.
- Add host-side ELF fixtures and Android device tests for API levels, Bionic variants, concurrent load/unload, fork, TLS, C++ exceptions/unwind and module callbacks.

## Reference-derived design points

- **YukiLinker** demonstrates a separate loader runtime with explicit library ownership, execution leases, retained failed operations, private-image tracking and controlled Bionic fallback. The transferable lesson is lifecycle discipline and backend boundaries, not copying its kernel/runtime integration.
- **ZN Linker** documents a staged feature set: packed relocations, RELR, TLS relocation, symbol lookup and lifecycle-related compatibility. Treat each feature as an independently testable capability, not a single "custom linker enabled" switch.
- VReZygisk should retain Bionic fallback for unsupported images. A custom backend must report a precise failure and fully roll back before fallback; never fall back after constructors or other image code may have executed unless the state is proven safe.

## Implementation sequence

1. Freeze the existing CSOLoader submodule pin and record baseline build/test behavior.
2. Serialize access to CSOLoader's process-global registries and keep callbacks outside the lock.
3. Harden CSOLoader's emulated TLS registry against key-creation failure, TLS module-ID reuse, invalid offsets and incomplete registration.
4. Add a bounded PT_DYNAMIC feature probe; route PT_TLS and GNU symbol versioning to Bionic, while keeping CSOLoader's existing Android packed relocation and RELR support behind its custom backend.
5. Harden the remote ELF parser and mapping transaction without expanding supported relocation types.
6. Implement missing remote relocation and resolver features only with a target-thread execution model, rollback and regression fixtures.
7. Add GNU symbol version selection to the custom backend only when the dependency can be safely extended; until then Bionic handles versioned images.
8. Add stress, fork, unload, Android API matrix and device validation; update support claims only after evidence exists.

## Non-goals for this branch

- No blind source-code or binary copying from reference projects.
- No bypass claims or guarantees against third-party detection.
- No weakening of ELF validation or fail-closed behavior to make more modules appear to load.
- No change to the main branch until the branch passes review and CI.
