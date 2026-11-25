# Linker overhaul audit

> Scope: ARM64 VReZygisk. This document records implemented behavior and the remaining compatibility boundaries.
> Reference projects: YukiZygisk/YukiLinker and Zygisk Next (ZN Linker).

## Architecture

VReZygisk has two independent loading paths:

1. **In-process module loader**: `loader/src/injector/hook.c` uses the pinned CSOLoader submodule or Bionic `dlopen`. CSOLoader is pinned at `0d29278cf60a3c38850dde3eaf07b0ffc3241f03`.
2. **Ptracer bootstrap mapper**: `loader/src/ptracer/remote_csoloader.c` maps the bootstrap ELF into the target process, builds its dependency scope, applies relocations, and resolves the entry point. Injector addresses are translated to target addresses by module-relative offsets; target IFUNC resolvers execute in the target process.

## Implemented in this branch

### GNU symbol versioning

- `loader/src/common/elf_version.c` parses ELF64/AArch64 dynamic metadata, including `DT_SYMTAB`, `DT_STRTAB`, `DT_STRSZ`, `DT_SYMENT`, `DT_HASH`/`DT_GNU_HASH`, `DT_VERSYM`, `DT_VERDEF`, and `DT_VERNEED`.
- Version metadata validation checks file-backed `PT_LOAD` ranges, bounded linked-list traversal, string termination, version indexes, and System V version-name hashes.
- Versioned lookup distinguishes explicit-version lookup from unversioned/default-version lookup. It filters symbol binding/visibility, checks symbol addresses against load segments, and reports symbol type so IFUNC resolvers are not mistaken for final function addresses.
- The ptracer resolves requester `DT_VERSYM`/`DT_VERNEED` requirements against the named provider's actual `DT_SONAME`, performs exact version lookup in the local provider mapping, and translates the provider-relative offset to the target mapping. Weak version requirements may fall back to an unversioned/default lookup in the same provider.
- Versioned provider IFUNC symbols return the resolver address and are executed in the target process. The resolver ABI is selected by Android API level.
- The in-process pinned CSOLoader is patched to use the same bounded ELF64/AArch64 version parser. For non-TLS relocations it reads the requester's `DT_VERSYM`/`DT_VERNEED`, checks the provider `DT_SONAME`, and matches the provider's `DT_VERDEF` version name/hash. Unversioned references use default-version selection; IFUNC results are passed to the existing CSOLoader resolver. Versioned TLS relocations remain fail-closed. Main images with `PT_TLS` still route to Bionic.

### Dependency graph and symbol scope

- The ptracer builds a breadth-first dependency scope: all direct `DT_NEEDED` entries first, then transitive dependencies in discovery order.
- Remote dependency lookup and de-duplication use actual `DT_SONAME` when present. Basename is only a fallback for objects without `DT_SONAME`. Cycles terminate through object-identity/SONAME de-duplication.
- Missing direct dependencies, unreadable dependency metadata, invalid dynamic tables, and missing non-alias transitive dependencies fail closed.
- CSOLoader uses actual `DT_SONAME` for in-linker de-duplication, dynamically grows its dependency array up to a bounded maximum, skips the Bionic-internal `ld-android.so` alias, and fails on unresolved required `DT_NEEDED` entries.
- The in-process symbol scope searches the requester/main image and then the ordered dependency list. This is a dependency-local scope, not a complete Bionic global namespace implementation. It does not model arbitrary `RTLD_GLOBAL` objects, all namespace isolation rules, or every symbolic lookup corner case.
- Separate CSOLoader instances do not share one process-wide dependency-object pool. Two independent module linkers can still map separate copies of the same private dependency.

### Relocations and remote resolvers

- The ptracer supports standard `DT_RELR` and Android `DT_ANDROID_RELR` tables, including `DT_ANDROID_RELRCOUNT` validation.
- The ptracer supports Android APS2 packed RELA decoding with bounded SLEB128 parsing and the supported AArch64 relocation subset.
- AArch64 IFUNC and IRELATIVE resolvers execute in the stopped target process using a temporary target mapping. The code saves/restores the target register state and selects the Bionic resolver argument ABI by runtime Android API level.
- The pinned in-process CSOLoader already contains RELR, Android packed relocation, IFUNC, and IRELATIVE support.
- The ptracer still rejects Android packed REL, `PT_TLS`, TLS relocation families, and unsupported relocation types rather than silently applying an incorrect relocation.

### Lifecycle and concurrency

- CSOLoader load, symbol lookup, unload, abandon, and deinit are serialized through a recursive process mutex. The custom linker registry has its own recursive mutex; the injector's at-fork handlers acquire the CSOLoader mutex first and the registry mutex second, then release them in reverse order in parent/child.
- Custom `dlopen`/`dlsym`/`dlclose` hooks are enabled. Custom image handles carry per-image reference counts, and `dlsym`/`dlclose` locate the owning linker globally rather than assuming the caller owns the handle.
- Module callbacks acquire execution leases. The lease gate is closed and active callbacks are drained before either unload or abandon. Callback synchronization state is destroyed only after the gate is closed.
- Modules can create tracked workers through `rz_module_pthread_create()`. The wrapper acquires a lease before `pthread_create` and releases it through a pthread cleanup handler, including normal return, `pthread_exit`, and cancellation. Closing the module lease gate waits for these workers. Direct `pthread_create`, `clone`, raw syscalls, and threads created by third-party runtimes are not intercepted; modules must use the wrapper for every worker that can execute module code.
- Per-image constructor/destructor state prevents duplicate initialization/finalization. Main-image and dependency destructors run once in reverse initialization order.
- Unload runs finalizers, then refuses to unmap if custom `dlopen` references remain. The image is retained/pinned rather than invalidating a live handle. A later handle close decrements the reference count, but automatic deferred unmapping is not implemented; a retained image can therefore remain mapped until process exit.
- Handle accounting covers custom linker handles, not arbitrary detached threads executing module code without a tracked handle. Modules must synchronize such threads themselves.
- Dependency ownership/reference counting is per CSOLoader instance for its dependency graph. There is no process-wide shared dependency reference-count registry across independent CSOLoader instances.

### TLS policy

- The pinned CSOLoader contains pthread-key based emulated TLS. The build-time patch checks TLS key creation and thread registration, validates allocation alignment and offsets, and tracks per-thread module generations to prevent stale TLS block reuse after module-ID recycling.
- Emulated TLS is not claimed to be equivalent to Bionic's native static-TLS ABI. In-process images with `PT_TLS` are routed to Bionic.
- The ptracer bootstrap mapper rejects `PT_TLS` and TLS symbols/relocations.

## Remaining correctness gates

1. **Global symbol scope**: implement only with explicit namespace and visibility semantics; do not resolve from arbitrary resident mappings as a shortcut.
2. **Cross-linker shared dependency ownership**: separate CSOLoader instances can still map duplicate copies of the same private dependency. A process-wide shared image registry and deferred release protocol remain future work.
3. **GNU versioning edge cases**: ordinary versioned relocations are now resolved natively by CSOLoader, but versioned TLS relocations, weak-version corner cases, nonstandard symbol namespaces, and full Bionic lookup parity remain unsupported or unverified.
4. **Remote resolver ABI**: IFUNC/IRELATIVE execution needs device validation for target auxv/HWCAP, API-specific resolver calling convention, stack alignment, signal-stop verification, resolver reentrancy, and abnormal termination cleanup.
5. **Relocation coverage**: Android packed REL and TLS relocation families remain unsupported in the ptracer; unsupported relocation types fail closed.
6. **Constructor failure semantics**: ELF constructors have no standard error return. State tracking prevents duplicate finalization, but cannot roll back arbitrary side effects from a constructor that faults or terminates the process.
7. **Real-device matrix**: validate supported Android API levels, Bionic revisions, fork behavior, thread exit, C++ unwind, constructor/destructor order, and concurrent load/unload stress.

## Validation status

GitHub Actions verifies pinned submodules, idempotent build-time patching, Android NDK ARM64 Debug and Release compilation, and artifact packaging. The latest tested commit is recorded by the branch/PR checks. CI success is not a substitute for on-device runtime tests. This feature branch remains separate from `main` and the pull request remains a review candidate.

## Reference-derived design points

- YukiLinker demonstrates explicit image ownership, execution leases, retained failed operations, and controlled Bionic fallback. The transferable lesson is lifecycle discipline and backend boundaries.
- ZN Linker demonstrates staged support for packed relocations, RELR, TLS, and symbol lookup. Each capability needs independent tests rather than one broad "custom linker supported" claim.
- A custom backend must report precise failure and fully roll back before Bionic fallback. Never fall back after constructors or other image code may have executed unless execution state proves that doing so is safe.
