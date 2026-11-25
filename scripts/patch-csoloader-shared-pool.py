#!/usr/bin/env python3
"""Install the process-wide shared dependency pool on the pinned CSOLoader.

The pool delegates mapping, relocations, TLS, constructors, unwind registration,
and final unmapping to Bionic. CSOLoader keeps one shared image wrapper and one
Bionic dlopen reference per SONAME across all linker instances. PT_TLS images
are deliberately excluded because CSOLoader's custom relocation ABI cannot
safely mix Bionic static TLS with its emulated TLS implementation.
"""
from pathlib import Path
import sys

MARKER = "/* VREZYGISK_PROCESS_SHARED_DEPENDENCY_POOL */"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source anchor, found {count}")
    return source.replace(old, new, 1)


def patch(header_path: Path, linker_path: Path) -> None:
    header = header_path.read_text()
    if "struct shared_dep_object *shared_object;" not in header:
        header = replace_once(
            header,
            "  size_t handle_refs;\n  bool is_manual_load;",
            "  size_t handle_refs;\n  struct shared_dep_object *shared_object;\n  bool is_manual_load;",
            "shared dependency reference in loaded_dep",
        )
        header = replace_once(
            header,
            "struct loaded_dep {",
            "struct shared_dep_object;\n\nstruct loaded_dep {",
            "shared dependency forward declaration",
        )
        header_path.write_text(header)

    source = linker_path.read_text()
    if MARKER in source:
        return

    pool = r"""
/* A process-wide pool of Bionic-owned dependency images. Each entry owns one
 * dlopen reference and one csoloader_elf metadata wrapper. Linker instances
 * hold references to the entry, never to an independently owned mapping. */
struct shared_dep_object {
  char *key;
  void *bionic_handle;
  struct csoloader_elf *img;
  size_t refs;
  size_t handle_refs;
  struct shared_dep_object *next;
};

static struct shared_dep_object *g_shared_dep_objects;

static struct shared_dep_object *_linker_shared_dep_acquire(const char *soname) {
  if (!soname || !*soname || !_linker_registry_lock()) return NULL;

  for (struct shared_dep_object *it = g_shared_dep_objects; it; it = it->next) {
    if (strcmp(it->key, soname) != 0) continue;
    if (it->refs == SIZE_MAX) {
      _linker_registry_unlock();
      return NULL;
    }
    ++it->refs;
    _linker_registry_unlock();
    return it;
  }
  _linker_registry_unlock();

  /* dlopen is intentionally performed outside the registry lock. Bionic
   * serializes its own namespace/object graph and may run constructors. */
  void *handle = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
  if (!handle) return NULL;

  struct csoloader_elf *img = csoloader_elf_create(soname, NULL);
  if (!img || !img->base || !img->header || img->tls_segment) {
    if (img) csoloader_elf_destroy(img);
    (void)dlclose(handle);
    return NULL;
  }

  struct shared_dep_object *created = calloc(1, sizeof(*created));
  if (!created) {
    csoloader_elf_destroy(img);
    (void)dlclose(handle);
    return NULL;
  }
  created->key = strdup(soname);
  if (!created->key) {
    free(created);
    csoloader_elf_destroy(img);
    (void)dlclose(handle);
    return NULL;
  }
  created->bionic_handle = handle;
  created->img = img;
  created->refs = 1;

  if (!_linker_registry_lock()) {
    free(created->key);
    free(created);
    csoloader_elf_destroy(img);
    (void)dlclose(handle);
    return NULL;
  }

  /* Another linker may have populated the entry while dlopen was running. */
  for (struct shared_dep_object *it = g_shared_dep_objects; it; it = it->next) {
    if (strcmp(it->key, soname) != 0) continue;
    if (it->refs == SIZE_MAX) {
      _linker_registry_unlock();
      free(created->key);
      free(created);
      csoloader_elf_destroy(img);
      (void)dlclose(handle);
      return NULL;
    }
    ++it->refs;
    _linker_registry_unlock();
    free(created->key);
    free(created);
    csoloader_elf_destroy(img);
    (void)dlclose(handle);
    return it;
  }

  created->next = g_shared_dep_objects;
  g_shared_dep_objects = created;
  _linker_registry_unlock();
  return created;
}

static void _linker_shared_dep_release(struct shared_dep_object *object) {
  if (!object || !_linker_registry_lock()) return;

  if (object->refs == 0) {
    LOGE("Shared dependency reference underflow for %s", object->key);
    _linker_registry_unlock();
    return;
  }
  if (--object->refs != 0) {
    _linker_registry_unlock();
    return;
  }

  struct shared_dep_object **cursor = &g_shared_dep_objects;
  while (*cursor && *cursor != object) cursor = &(*cursor)->next;
  if (*cursor == object) *cursor = object->next;
  _linker_registry_unlock();

  /* No CSOLoader linker can still reference this image. Bionic performs the
   * finalizer/TLS/unwind/mapping teardown when its final handle is closed. */
  csoloader_elf_destroy(object->img);
  (void)dlclose(object->bionic_handle);
  free(object->key);
  free(object);
}

/* VREZYGISK_PROCESS_SHARED_DEPENDENCY_POOL */
"""
    source = replace_once(
        source,
        "/* VREZYGISK_ELF_SONAME_IDENTITY */",
        "/* VREZYGISK_ELF_SONAME_IDENTITY */\n" + pool,
        "insert process shared dependency pool",
    )

    source = replace_once(
        source,
        """          refs = &linker->dependencies[i].handle_refs;""",
        """          refs = linker->dependencies[i].shared_object
              ? &linker->dependencies[i].shared_object->handle_refs
              : &linker->dependencies[i].handle_refs;""",
        "global shared-object handle references",
    )

    source = replace_once(
        source,
        """  for (int i = 0; i < linker->dep_count; ++i)
    if (linker->dependencies[i].handle_refs != 0) return true;""",
        """  for (int i = 0; i < linker->dep_count; ++i) {
    if (linker->dependencies[i].handle_refs != 0) return true;
    if (linker->dependencies[i].shared_object &&
        linker->dependencies[i].shared_object->handle_refs != 0) return true;
  }""",
        "check process-wide shared-object handles before teardown",
    )
    source = replace_once(
        source,
        """static void _linker_release_dependency(struct linker *linker, int index, bool unload) {
  struct loaded_dep *dep = &linker->dependencies[index];
  if (!dep->img) return;

  void *dep_base = dep->img->base;""",
        """static void _linker_release_dependency(struct linker *linker, int index, bool unload) {
  struct loaded_dep *dep = &linker->dependencies[index];
  if (!dep->img) return;

  if (dep->shared_object) {
    _linker_shared_dep_release(dep->shared_object);
    dep->shared_object = NULL;
    dep->img = NULL;
    dep->map_size = 0;
    return;
  }

  void *dep_base = dep->img->base;""",
        "release shared dependency references",
    )

    # System-loaded objects must contribute their DT_NEEDED closure to this
    # linker's symbol scope as well. Bionic has mapped them, but the custom
    # main image still needs the same dependency search order.
    source = replace_once(
        source,
        "if (current_dep->is_manual_load && current_dep->img->header->e_phoff > 0 && current_dep->img->header->e_phnum > 0) {",
        "if (current_dep->img->header->e_phoff > 0 && current_dep->img->header->e_phnum > 0) {",
        "walk transitive dependencies for shared images",
    )

    linker_path.write_text(source)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <CSOLoader/src/linker.c>", file=sys.stderr)
        return 2
    linker_path = Path(sys.argv[1])
    header_path = linker_path.parent.parent / "include" / "linker.h"
    patch(header_path, linker_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
