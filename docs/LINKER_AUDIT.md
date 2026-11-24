# Linker overhaul audit

> Scope: ARM64-only VReZygisk. This document records implemented behavior and remaining compatibility boundaries.
> Reference projects: YukiZygisk/YukiLinker and Zygisk Next (ZN Linker).

## Architecture

VReZygisk has two independent loading paths:

1. **In-process module loader**: `loader/src/injector/hook.c` uses the pinned CSOLoader submodule or Bionic `dlopen`. CSOLoader is pinned at `0d29278cf60a3c38850dde3eaf07b0ffc3241f03`.
2. **Ptracer bootstrap mapper**: `loader/src/ptracer/remote_csoloader.c` maps the bootstrap ELF into the target process, builds its dependency scope, applies relocations, and resolves the entry point. It must not confuse injector addresses with target addresses.

## Implemented in this branch

### GNU symbol versioning

- Parses `DT_VERSYM`, `DT_VERNEED`, `DT_VERNEEDNUM`, `DT_VERDEF`, and `DT_VERDEFNUM` with file-backed PT_LOAD range checks.
- Validates the complete `DT_VERSYM` table against the dynamic symbol count and validates GNU version-definition chains.
- For undefined symbols with a version requirement, resolves the exact provider SONAME and version through the local Bionic `dlvsym()`, then translates the provider-relative offset to the corresponding target mapping.
- If local Bionic cannot resolve the provider/version, bootstrap fails closed.
- The in-process CSOLoader feature probe still routes versioned images to Bionic; its section-oriented symbol parser has not been extended with a complete GNU version resolver.

### Dependency graph and symbol scope

- Builds the remote dependency search scope breadth-first: all direct `DT_NEEDED` entries first, followed by their transitive dependencies in discovery order.
- De-duplicates by SONAME/basename, which terminates cycles and avoids duplicate entries caused by path aliases.
- Rejects missing direct dependencies, unreadable dependency metadata, and missing non-alias transitive dependencies rather than continuing with an incomplete scope.
- Symbol resolution checks the main image first, then the ordered dependency scope; weak undefined symbols resolve to zero only after the scope is exhausted.
- This is a dependency-local scope, not a complete Bionic global namespace implementation. It does not enumerate arbitrary `RTLD_GLOBAL` objects, model namespace isolation, or fully implement all `RTLD_LOCAL`/symbolic lookup rules. SONAME matching currently uses the mapped filename basename; unusual SONAME/path arrangements need device fixtures.

### Relocations and remote resolvers

- Supports standard `DT_RELR` and Android `DT_ANDROID_RELR` tables, including optional `DT_ANDROID_RELRCOUNT` validation.
- Supports Android APS2 packed **RELA** decoding with bounded SLEB128 parsing and the AArch64 RELATIVE, IRELATIVE, GLOB_DAT, JUMP_SLOT and ABS64 relocation subset.
- Executes AArch64 IFUNC and IRELATIVE resolver functions in the stopped target process, using a temporary target mapping and restoring the saved register state afterward.
- Unsupported Android packed REL, TLS relocation families, and unsupported AArch64 relocation types remain fail-closed.
- The in-process pinned CSOLoader already contains Android packed relocation, RELR, IFUNC and IRELATIVE implementations.

### Lifecycle and concurrency

- CSOLoader load, symbol lookup, unload, abandon and deinit are serialized through a recursive process mutex. Module entry points and specialization callbacks run outside that mutex.
- Active custom-image accounting prevents global CSOLoader deinit while a tracked image remains active. A failed custom load is eligible for Bionic fallback only before module code has executed and after cleanup.
- Module callbacks acquire execution leases. Unload closes the lease gate, waits for active callbacks to leave, then releases the backend-specific handle. A failed release pins the image and prevents unmapping the containing runtime.
- Module lifecycle states cover new, loading, image-loaded, entry-running, registered, active, closing, retained, failed/unloaded bookkeeping.
- The build-time CSOLoader patch adds per-image constructor/destructor state. Constructors are called once; destructors run once and only for images whose constructors completed. Dependency finalization follows reverse load/constructor order.
- Dependency ownership is currently per CSOLoader instance. There is no process-wide shared dependency reference-count registry across independent CSOLoader instances; concurrent public operations are serialized, but duplicate dependency mappings across separate module linkers are still possible.

### TLS policy

- The pinned CSOLoader contains pthread-key based emulated TLS. The build-time patch checks TLS key creation and thread registration, validates allocation alignment and offsets, and tracks per-thread module generations to prevent stale TLS block reuse after module-ID recycling.
- Emulated TLS is not claimed to be equivalent to Bionic's native static-TLS ABI. In-process images with `PT_TLS` are routed to Bionic.
- The ptracer bootstrap mapper rejects `PT_TLS` and TLS symbols/relocations.

## Remaining correctness gates

1. **Global symbol scope**: implement only with explicit namespace and visibility semantics. Do not resolve from arbitrary resident mappings as a shortcut.
2. **Dependency identity**: parse and honor `DT_SONAME` rather than relying solely on basename matching; add fixtures for aliases and duplicate SONAMEs.
3. **Shared dependency ownership**: a process-wide image registry/refcount is not implemented across separate CSOLoader instances. Until that exists, do not claim shared-object de-duplication across independent module loads.
4. **GNU versioning**: remote undefined-symbol version lookup relies on the local Bionic `dlvsym` implementation and a matching local provider mapping. Full custom-linker version lookup, versioned symbol export selection, version inheritance and namespace-specific provider resolution are not implemented.
5. **Remote resolver ABI**: IFUNC/IRELATIVE execution needs device validation for resolver calling convention, target auxv/HWCAP handling, stack alignment, signal-stop verification, resolver reentrancy and cleanup after abnormal termination.
6. **Relocation coverage**: Android packed REL and TLS relocation families remain unsupported; other relocation types fail closed.
7. **Constructor failure semantics**: ELF constructors have no standard error return. State tracking prevents duplicate finalization, but cannot roll back arbitrary side effects performed by a constructor that terminates the process or faults.
8. **Real-device matrix**: no claim of Android runtime correctness until tested across supported API levels, Bionic revisions, fork behavior, thread exit, C++ unwind, constructor/destructor order, and concurrent load/unload stress.

## Validation status

The GitHub Actions build verifies pinned submodules, idempotent build-time patching, Android NDK Debug/Release compilation, and artifact packaging. CI success is not a substitute for on-device runtime tests. The feature branch remains separate from `main` and the pull request remains a review candidate.

## Reference-derived design points

- YukiLinker demonstrates explicit image ownership, execution leases, retained failed operations and controlled Bionic fallback. The transferable lesson is lifecycle discipline and backend boundaries.
- ZN Linker demonstrates staged support for packed relocations, RELR, TLS and symbol lookup. Each capability needs independent tests rather than one broad "custom linker supported" claim.
- A custom backend must report precise failure and fully roll back before Bionic fallback. Never fall back after constructors or other image code may have executed unless execution state proves that doing so is safe.
