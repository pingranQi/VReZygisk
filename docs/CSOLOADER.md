# CSOLoader maintenance

CSOLoader is tracked as a Git submodule at `loader/src/external/csoloader`.
The superproject commit therefore pins the exact source revision used by every
build; builds must not fetch a moving upstream branch.

- Upstream: https://github.com/ThePedroo/CSOLoader
- License: AGPL-3.0 (retain the upstream license and copyright notices)
- Public API: `include/csoloader.h`
- Integration: `loader/src/injector/hook.c` and `module.h`

## Loader backend behavior

There are two separate loading paths and they must not be conflated:

- Modules loaded inside the injected `libzygisk.so` process use a bounded
  ELF feature probe before CSOLoader. Images with `PT_TLS` are routed directly
  to Bionic. Non-TLS GNU symbol-versioned images use the patched CSOLoader
  resolver, which matches requester version requirements against provider
  `DT_SONAME` and `DT_VERDEF` metadata. Versioned TLS relocations fail closed.
  CSOLoader's pinned implementation already processes Android packed
  relocations, RELR, IFUNC and IRELATIVE; these remain on the custom path when
  the dependency closure is compatible. Other images try CSOLoader first and
  fall back to Bionic only after a clean pre-execution failure. The probe
  validates ELF64/AArch64 identity, program-header bounds, the file-backed
  `PT_DYNAMIC` mapping and its `DT_NULL` terminator.
- The build-time patch adds actual `DT_SONAME` matching, a growable bounded
  dependency array, fail-closed handling for missing required `DT_NEEDED`
  entries, and per-image constructor/destructor states. Custom
  `dlopen`/`dlsym`/`dlclose` hooks are enabled; image handles carry reference
  counts and can be resolved/released by modules other than the original
  caller. If custom handles remain when unload is requested, CSOLoader marks
  the linker closing and defers finalizers and unmapping. The final custom
  `dlclose` notifies every closing linker whose handle references have drained.
- CSOLoader operations use a recursive process mutex. Its active-linker
  registry has a separate recursive mutex, coordinated with the injector's
  at-fork handlers in the same lock order. Module callbacks use execution
  leases; the lease gate is closed and active callbacks drained before unload.
  A detached reaper waits for tracked module execution leases across the
  process to drain, retries teardown, releases shared dependency references,
  and deinitializes CSOLoader when safe. The Zygisk runtime stays resident while
  deferred images are pending. ReZygisk API v6 exposes a tracked
  `pthread_create` callback, backed by `rz_module_pthread_create()`; it holds
  an execution lease until worker cleanup. Direct `pthread_create`, `clone`,
  raw syscalls, and third-party thread pools remain outside automatic tracking.
- The ptracer's bootstrap ELF mapper is a separate implementation. It supports
  standard and Android RELR, Android APS2 packed RELA, GNU versioned undefined
  symbol lookup, and target-process AArch64 IFUNC/IRELATIVE execution. It still
  rejects `PT_TLS`, TLS relocation families, Android packed REL, and
  unsupported architecture relocation types. The resolver ABI is selected by
  runtime Android API level, but target auxv/HWCAP, stack alignment, signal-stop
  handling, reentrancy and abnormal cleanup still require device validation.
- A process-wide shared dependency pool covers dependencies Bionic can
  load that do not contain `PT_TLS`. It is keyed by SONAME, owns one Bionic
  `dlopen` reference and one shared `csoloader_elf` metadata wrapper, and is
  reference-counted across independent CSOLoader instances. Bionic owns mapping,
  relocations, constructors, unwind registration, and final unload for these
  objects. `PT_TLS` dependencies use per-linker Bionic handles when available;
  dependencies Bionic cannot load still use the manual CSOLoader mapper and
  are not cross-Linker shared.

Do not claim complete TLS support for the ptracer mapper. IFUNC/IRELATIVE
support is implemented using target-process execution, but must be validated
on-device for target auxv/HWCAP, stack ABI, signal-stop verification,
reentrancy and abnormal resolver termination.

## Updating the dependency

Initialize the pinned revision:

```sh
git submodule update --init --recursive loader/src/external/csoloader
```

Python 3 is required for the build-time patch pipeline. The loader Makefile
applies `scripts/patch-csoloader.py`, then the process-shared dependency pool
and deferred-unload patches before compiling the pinned submodule. The pipeline
validates TLS registration/allocation, preallocates path bookkeeping before
constructors, adds per-image lifecycle state, shares Bionic-owned dependency
objects across Linker instances where supported, and defers final teardown
until custom handles and tracked execution leases have drained. The patches are
idempotent and target the pinned upstream revision; do not commit the modified
submodule worktree as a new upstream revision.

Inspect the current pin:

```sh
sh scripts/update-csoloader.sh status
```

To evaluate a newer upstream revision, fetch and detach the submodule at that
revision:

```sh
sh scripts/update-csoloader.sh update <tag-or-commit>
git diff --submodule=log -- .gitmodules loader/src/external/csoloader
```

Review the diff, run the Android build and device tests, then commit the
superproject gitlink update. Do not use an unpinned `git submodule update
--remote` in CI or release builds.

## Local changes

Prefer fixes in upstream CSOLoader and submit them upstream. If a VReZygisk
specific patch is required, keep it as a separately reviewable commit in the
submodule checkout and record its upstream base and rationale in the commit
message. Do not silently edit generated build artifacts or replace the
submodule with a floating archive.

## Required loader validation

Before advancing the pinned revision, validate at least:

- ELF class, machine, endianness, program-header bounds, PT_LOAD alignment,
  PT_DYNAMIC termination, and all dynamic-table ranges.
- REL/RELA and PLT relocation tables, symbol bounds, weak/undefined symbols,
  Android relocation variants, and architecture-specific relocation types.
- GNU IFUNC and IRELATIVE resolver execution order, API-specific resolver ABI,
  target register restoration, signal-stop verification and resolver failure paths.
- TLS module allocation, per-thread block initialization, thread-exit cleanup,
  module-id reuse/generation handling, and deinit after all images are gone
  (PT_TLS is currently rejected by the ptracer bootstrap mapper).
- Constructor/destructor ordering, partial-load rollback, unload failure, and
  abandon semantics.
- Android API-level and ABI matrix on real bionic runtimes.

The pinned CSOLoader implements emulated TLS, RELR, Android packed relocation,
IFUNC and IRELATIVE handling. The build applies
`scripts/patch-csoloader.py` to harden TLS key creation, per-thread registration,
module-ID reuse generations, alignment and offset validation, TLS registration
failure propagation, per-image constructor/destructor state, and native GNU
versioned symbol resolution for non-TLS relocations. Its emulated TLS is not a
substitute for Bionic's native TLS ABI, so VReZygisk routes PT_TLS images to
Bionic for now. Versioned TLS relocations remain unsupported and fail closed. The ptracer bootstrap path has a separate
version-aware undefined-symbol resolver based on `DT_VERSYM`/`DT_VERNEED`,
actual provider `DT_SONAME`, and mapped-provider version metadata. It is not a
complete replacement for Bionic's global namespace and version lookup rules. A failed custom load is allowed to fall back to Bionic only when cleanup
is complete and module code has not started; a successful custom load must
always be released with `csoloader_unload()`, never `dlclose()`.
