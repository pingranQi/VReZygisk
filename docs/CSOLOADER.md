# CSOLoader maintenance

CSOLoader is tracked as a Git submodule at `loader/src/external/csoloader`.
The superproject commit therefore pins the exact source revision used by every
build; builds must not fetch a moving upstream branch.

- Upstream: https://github.com/ThePedroo/CSOLoader
- License: AGPL-3.0 (retain the upstream license and copyright notices)
- Public API: `include/csoloader.h`
- Integration: `loader/src/injector/hook.c` and `module.h`

## Updating the dependency

Initialize the pinned revision:

```sh
git submodule update --init --recursive loader/src/external/csoloader
```

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
- GNU IFUNC and IRELATIVE resolver execution order and resolver failure paths.
- TLS module allocation, per-thread block initialization, thread-exit cleanup,
  module-id reuse/generation handling, and deinit after all images are gone.
- Constructor/destructor ordering, partial-load rollback, unload failure, and
  abandon semantics.
- Android API-level and ABI matrix on real bionic runtimes.

The upstream implementation documents TLS and IFUNC support, but those feature
claims are not a substitute for this project's regression tests. A failed
custom load is allowed to fall back to bionic; a successful custom load must
always be released with `csoloader_unload()`, never `dlclose()`.
