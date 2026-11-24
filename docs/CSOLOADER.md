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
  ELF feature probe before CSOLoader. Images with `PT_TLS` or GNU symbol-version
  tags are routed directly to Bionic. CSOLoader's pinned implementation already
  processes Android packed relocations, RELR, IFUNC and IRELATIVE; these remain
  on the custom path. Other images try CSOLoader first and fall back to Bionic
  on a clean pre-execution failure. The probe validates ELF64/AArch64 identity,
  program-header bounds, the file-backed `PT_DYNAMIC` mapping and its
  `DT_NULL` terminator. The matching release operation is `csoloader_unload()` for
  CSOLoader images and `dlclose()` for Bionic handles.
- CSOLoader public lifecycle operations are serialized by a recursive
  process-wide mutex because the pinned dependency maintains global linker
  and TLS registries. A successful-image counter prevents global deinit while
  another custom image remains loaded; failed partial loads are cleaned up
  when no image is active. The lock is not held across module entry points or
  specialization callbacks.
- GNU symbol versioning is not implemented by the pinned CSOLoader, so the
  integration detects its dynamic tags and delegates those images to Bionic.
- The ptracer's bootstrap ELF mapper is a separate implementation. It currently
  rejects PT_TLS images and GNU IFUNC symbols rather than pretending that
  `st_value` is the resolved IFUNC address. IRELATIVE and TLS relocation
  families are not implemented there. Such images cannot be made safe merely
  by the in-process `dlopen()` fallback because the bootstrap mapper runs
  before that loader exists in the target.

Do not claim complete TLS/IFUNC support for the ptracer mapper. Extending it
requires correct target-thread TLS setup and execution of resolver functions
inside the target process, with rollback and constructor ordering tested.

## Updating the dependency

Initialize the pinned revision:

```sh
git submodule update --init --recursive loader/src/external/csoloader
```

The loader Makefile applies the tracked TLS hardening patch before compiling
the submodule. The patch is idempotent and is based on the pinned upstream
revision; do not commit the modified submodule worktree as a new upstream
revision.

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
- GNU IFUNC and IRELATIVE resolver execution order and resolver failure paths
  (currently unsupported by the ptracer bootstrap mapper and must be rejected).
- TLS module allocation, per-thread block initialization, thread-exit cleanup,
  module-id reuse/generation handling, and deinit after all images are gone
  (PT_TLS is currently rejected by the ptracer bootstrap mapper).
- Constructor/destructor ordering, partial-load rollback, unload failure, and
  abandon semantics.
- Android API-level and ABI matrix on real bionic runtimes.

The pinned CSOLoader implements emulated TLS, RELR, Android packed relocation,
IFUNC and IRELATIVE handling. The build applies
`scripts/patch-csoloader.py` to harden TLS key creation, per-thread registration,
module-ID reuse generations, alignment and offset validation, and TLS
registration failure propagation. Its emulated TLS is not a substitute for
Bionic's native TLS ABI, so VReZygisk routes PT_TLS images to Bionic for now.
GNU symbol versioning is likewise delegated to Bionic. A failed custom load is allowed to fall back to Bionic only when cleanup
is complete and module code has not started; a successful custom load must
always be released with `csoloader_unload()`, never `dlclose()`.
