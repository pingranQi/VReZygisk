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
  ELF feature probe before CSOLoader. Main images with `PT_TLS` or GNU
  symbol-version tags are routed directly to Bionic. The patched CSOLoader
  also detects GNU version tags in manually loaded dependencies and fails
  closed so the injector can retry the complete dependency closure with
  Bionic. CSOLoader's pinned implementation already processes Android packed
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
  caller. Destruction runs finalizers once and refuses to unmap an image while
  tracked handles remain open.
- CSOLoader operations use a recursive process mutex. Its active-linker
  registry has a separate recursive mutex, coordinated with the injector's
  at-fork handlers in the same lock order. Module callbacks use execution
  leases; the lease gate is closed and active callbacks drained before both
  unload and abandon. A retained image is pinned if callbacks or custom
  handles prevent safe teardown. The callback lease does not track arbitrary
  detached threads that execute module code without a tracked custom handle.
- The ptracer's bootstrap ELF mapper is a separate implementation. It supports
  standard and Android RELR, Android APS2 packed RELA, GNU versioned undefined
  symbol lookup, and target-process AArch64 IFUNC/IRELATIVE execution. It still
  rejects `PT_TLS`, TLS relocation families, Android packed REL, and
  unsupported architecture relocation types. The resolver ABI is selected by
  runtime Android API level, but target auxv/HWCAP, stack alignment, signal-stop
  handling, reentrancy and abnormal cleanup still require device validation.
- Dependency de-duplication is within each CSOLoader instance. Separate
  CSOLoader instances do not share a process-wide dependency-object registry,
  so duplicate private dependency mappings across independent module linkers
  remain possible.

Do not claim complete TLS support for the ptracer mapper. IFUNC/IRELATIVE
support is implemented using target-process execution, but must be validated
on-device for target auxv/HWCAP, stack ABI, signal-stop verification,
reentrancy and abnormal resolver termination.

## Updating the dependency

Initialize the pinned revision:

```sh
git submodule update --init --recursive loader/src/external/csoloader
```

Python 3 is required for the build-time patch step. The loader Makefile applies the tracked TLS/lifecycle hardening patch before
compiling the submodule. It validates TLS registration and allocation,
preallocates path bookkeeping before constructors, and adds per-image
constructor/destructor state to prevent duplicate initialization/finalization.
The patch is idempotent and is based on the pinned upstream revision; do not
commit the modified submodule worktree as a new upstream revision.

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
failure propagation, and per-image constructor/destructor state. Its emulated
TLS is not a substitute for Bionic's native TLS ABI, so VReZygisk routes PT_TLS
images to Bionic for now. GNU symbol versioning in the in-process CSOLoader is
likewise delegated to Bionic. The ptracer bootstrap path has a separate
version-aware undefined-symbol resolver based on `DT_VERSYM`/`DT_VERNEED`,
actual provider `DT_SONAME`, and mapped-provider version metadata. It is not a
complete replacement for Bionic's global namespace and version lookup rules. A failed custom load is allowed to fall back to Bionic only when cleanup
is complete and module code has not started; a successful custom load must
always be released with `csoloader_unload()`, never `dlclose()`.
