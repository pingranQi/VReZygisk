#!/usr/bin/env python3
"""Share manually mapped CSOLoader dependency closures across Linker instances.

A closure is reusable only when its ordered symbol scope is identical and none
of its manual dependencies resolved an external symbol from the main image.
The entire manual subset is adopted/published atomically. The shared record owns
the mapping, relocation result, TLS module and TLSDESC bookkeeping, unwind
registration, and constructor/destructor state.
"""
from pathlib import Path
import sys

MARKER = "/* VREZYGISK_MANUAL_DEPENDENCY_OBJECT_POOL */"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source anchor, found {count}")
    return source.replace(old, new, 1)


def patch(header_path: Path, linker_path: Path) -> None:
    header = header_path.read_text()
    if "bool pool_uses_main;" not in header:
        header = replace_once(
            header,
            "  struct shared_dep_object *shared_object;\n  void *system_handle;",
            "  struct shared_dep_object *shared_object;\n  bool pool_uses_main;\n  void *system_handle;",
            "manual dependency main-scope marker",
        )
        header_path.write_text(header)

    source = linker_path.read_text()
    if MARKER in source:
        required = [
            "static bool _linker_shared_manual_adopt(struct linker *linker)",
            "static void _linker_shared_manual_publish(struct linker *linker)",
            "it->manual && it->scope_key &&",
        ]
        for item in required:
            if item not in source:
                raise RuntimeError(f"manual dependency pool is incomplete: {item}")
        return

    source = replace_once(
        source,
        "struct shared_dep_object {",
        "static void _linker_unregister_tls_segment(struct loaded_dep *dep);\n\n"
        "struct shared_dep_object {",
        "forward-declare TLS teardown for pooled manual images",
    )

    source = replace_once(
        source,
        "struct shared_dep_object {\n  char *key;\n  void *bionic_handle;\n  struct csoloader_elf *img;\n  size_t refs;\n  size_t handle_refs;\n  struct shared_dep_object *next;\n};",
        """struct shared_dep_object {
  char *key;
  char *scope_key;
  void *bionic_handle;
  struct csoloader_elf *img;
  void *map_base;
  size_t map_size;
  struct tls_indices_data tls_indices;
  enum linker_image_state lifecycle_state;
  size_t refs;
  size_t handle_refs;
  bool manual;
  bool pinned;
  struct shared_dep_object *next;
};""",
        "extend shared object record for manual mappings",
    )

    # The Bionic-backed pool and the manual pool share one registry, but their
    # lookup domains must remain disjoint.
    source = source.replace(
        "if (strcmp(it->key, soname) != 0) continue;",
        "if (it->manual || strcmp(it->key, soname) != 0) continue;",
    )
    source = replace_once(
        source,
        "  created->refs = 1;\n\n  if (!_linker_registry_lock()) {",
        "  created->refs = 1;\n  created->manual = false;\n\n  if (!_linker_registry_lock()) {",
        "mark Bionic pool records",
    )

    source = replace_once(
        source,
        "static void _linker_shared_dep_release(struct shared_dep_object *object) {",
        "static void _linker_shared_dep_release(struct shared_dep_object *object, bool unload) {",
        "pass unload intent to shared object release",
    )
    source = replace_once(
        source,
        """  if (--object->refs != 0) {
    _linker_registry_unlock();
    return;
  }

  struct shared_dep_object **cursor = &g_shared_dep_objects;""",
        """  if (--object->refs != 0) {
    _linker_registry_unlock();
    return;
  }
  if (!unload) {
    /* linker_abandon() intentionally leaves executable mappings resident. */
    object->refs = 1;
    object->pinned = true;
    _linker_registry_unlock();
    return;
  }

  struct shared_dep_object **cursor = &g_shared_dep_objects;""",
        "pin shared object on linker abandon",
    )
    source = replace_once(
        source,
        """  csoloader_elf_destroy(object->img);
  (void)dlclose(object->bionic_handle);
  free(object->key);
  free(object);""",
        """  if (object->manual) {
    _linker_call_destructors(object->img, &object->lifecycle_state);
    unregister_eh_frame_for_library(object->img);
    unregister_custom_library_for_backtrace(object->img);

    struct loaded_dep tls_owner = {
      .img = object->img,
      .tls_indices = object->tls_indices,
    };
    _linker_unregister_tls_segment(&tls_owner);
    csoloader_elf_destroy(object->img);
    if (object->map_base && object->map_size)
      munmap(object->map_base, object->map_size);
    free(object->scope_key);
  } else {
    csoloader_elf_destroy(object->img);
    if (object->bionic_handle) (void)dlclose(object->bionic_handle);
  }
  free(object->key);
  free(object);""",
        "final shared object teardown by ownership type",
    )
    source = replace_once(
        source,
        """    _linker_shared_dep_release(dep->shared_object);
    dep->shared_object = NULL;""",
        """    _linker_shared_dep_release(dep->shared_object, unload);
    dep->shared_object = NULL;""",
        "release shared dependency with unload mode",
    )

    source = replace_once(
        source,
        """  if (dep->system_handle) {
    csoloader_elf_destroy(dep->img);
    dep->img = NULL;
    (void)dlclose(dep->system_handle);
    dep->system_handle = NULL;
    dep->map_size = 0;
    return;
  }""",
        """  if (dep->system_handle) {
    csoloader_elf_destroy(dep->img);
    dep->img = NULL;
    /* linker_abandon() deliberately pins Bionic mappings as well. */
    if (unload) (void)dlclose(dep->system_handle);
    dep->system_handle = NULL;
    dep->map_size = 0;
    return;
  }""",
        "preserve Bionic TLS dependency on linker abandon",
    )

    # The TLS descriptor index array belongs to the provider image. A pooled
    # provider must therefore return the shared array, not the Linker-local
    # embedded array.
    source = replace_once(
        source,
        ".tls_indices = &linker->dependencies[i].tls_indices",
        ".tls_indices = linker->dependencies[i].shared_object\n"
        "              ? &linker->dependencies[i].shared_object->tls_indices\n"
        "              : &linker->dependencies[i].tls_indices",
        "shared TLS indices for requester dependency",
    )
    source = replace_once(
        source,
        ".tls_indices = &candidate->tls_indices",
        ".tls_indices = candidate->shared_object\n"
        "        ? &candidate->shared_object->tls_indices : &candidate->tls_indices",
        "shared TLS indices for provider dependency",
    )

    # Do not run a pooled dependency's finalizer once per Linker. The shared
    # record runs it exactly once when its final reference is released.
    source = replace_once(
        source,
        "if (!dep->img || !dep->is_manual_load) return;",
        "if (!dep->img || !dep->is_manual_load || dep->shared_object) return;",
        "defer shared dependency finalizer",
    )

    source = source.replace(
        "if (!dep->is_manual_load) continue;",
        "if (!dep->is_manual_load || dep->shared_object) continue;",
    )
    source = source.replace(
        "if (i >= 0 && !linker->dependencies[i].is_manual_load) continue;",
        "if (i >= 0 && (!linker->dependencies[i].is_manual_load || "
        "linker->dependencies[i].shared_object)) continue;",
    )
    source = source.replace(
        "if (!dep->is_manual_load || !dep->img) continue;",
        "if (!dep->is_manual_load || !dep->img || dep->shared_object) continue;",
    )

    helpers = r"""
static bool _linker_scope_append_image(char *buffer, size_t capacity,
                                       size_t *used,
                                       const struct csoloader_elf *img,
                                       bool manual) {
  if (!buffer || !used || !img || !img->elf || *used >= capacity) return false;
  struct stat st;
  int written;
  if (stat(img->elf, &st) == 0) {
    written = snprintf(buffer + *used, capacity - *used,
        "%c:%s:%llu:%llu:%llu:%lld:%u:%u;",
        manual ? 'M' : 'B', img->elf,
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        (unsigned long long)st.st_size, (long long)st.st_mtime,
        (unsigned)img->header->e_machine, (unsigned)img->header->e_type);
  } else {
    /* Bionic images may be represented by a SONAME rather than a path.
     * Their process-wide mapping address is stable while the dlopen ref lives. */
    written = snprintf(buffer + *used, capacity - *used,
        "%c:%s:%p:%u:%u;",
        manual ? 'M' : 'B', img->elf, img->base,
        (unsigned)img->header->e_machine, (unsigned)img->header->e_type);
  }
  if (written < 0 || (size_t)written >= capacity - *used) return false;
  *used += (size_t)written;
  return true;
}

static char *_linker_shared_manual_scope_key(struct linker *linker,
                                              int requester_index) {
  if (!linker || requester_index < 0 || requester_index >= linker->dep_count)
    return NULL;
  size_t capacity = ((size_t)linker->dep_count + 1) * (PATH_MAX + 256u) + 128u;
  if (capacity < PATH_MAX || capacity > SIZE_MAX / 2) return NULL;
  char *key = calloc(1, capacity);
  if (!key) return NULL;
  size_t used = 0;
  if (!_linker_scope_append_image(key, capacity, &used, linker->img, false))
    goto fail;
  for (int i = 0; i < linker->dep_count; ++i) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!_linker_scope_append_image(key, capacity, &used, dep->img,
                                    dep->is_manual_load))
      goto fail;
  }
  int written = snprintf(key + used, capacity - used, "#requester=%d",
                         requester_index);
  if (written < 0 || (size_t)written >= capacity - used) goto fail;
  return key;
fail:
  free(key);
  return NULL;
}

/* Adopt the complete manual subset or none of it. A partial adoption could
 * leave relocations in a shared image pointing at a private provider mapping. */
static bool _linker_shared_manual_adopt(struct linker *linker) {
  if (!linker || linker->dep_count <= 0) return true;
  size_t manual_count = 0;
  for (int i = 0; i < linker->dep_count; ++i)
    if (linker->dependencies[i].is_manual_load &&
        !linker->dependencies[i].shared_object)
      ++manual_count;
  if (!manual_count) return true;

  char **keys = calloc((size_t)linker->dep_count, sizeof(*keys));
  struct shared_dep_object **matches =
      calloc((size_t)linker->dep_count, sizeof(*matches));
  if (!keys || !matches) {
    free(keys);
    free(matches);
    return false;
  }

  bool complete = true;
  for (int i = 0; i < linker->dep_count; ++i) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load || dep->shared_object) continue;
    keys[i] = _linker_shared_manual_scope_key(linker, i);
    if (!keys[i]) {
      complete = false;
      break;
    }
  }

  if (complete && _linker_registry_lock()) {
    for (int i = 0; i < linker->dep_count; ++i) {
      if (!keys[i]) continue;
      for (struct shared_dep_object *it = g_shared_dep_objects; it; it = it->next) {
        if (it->manual && it->scope_key &&
            strcmp(it->scope_key, keys[i]) == 0) {
          matches[i] = it;
          break;
        }
      }
      if (!matches[i] || matches[i]->refs == SIZE_MAX) {
        complete = false;
        break;
      }
    }
    if (complete) {
      for (int i = 0; i < linker->dep_count; ++i)
        if (matches[i]) ++matches[i]->refs;
    }
    _linker_registry_unlock();
  } else {
    complete = false;
  }

  if (complete) {
    for (int i = 0; i < linker->dep_count; ++i) {
      struct shared_dep_object *shared = matches[i];
      if (!shared) continue;
      struct loaded_dep *dep = &linker->dependencies[i];
      void *old_base = dep->map_base ? dep->map_base : dep->img->base;
      size_t old_size = dep->map_size;
      csoloader_elf_destroy(dep->img);
      if (old_base && old_size) munmap(old_base, old_size);
      dep->img = shared->img;
      dep->shared_object = shared;
      dep->map_base = NULL;
      dep->map_size = 0;
      dep->load_bias = 0;
      dep->lifecycle_state = shared->lifecycle_state;
      memset(&dep->tls_indices, 0, sizeof(dep->tls_indices));
    }
  }

  for (int i = 0; i < linker->dep_count; ++i) free(keys[i]);
  free(keys);
  free(matches);
  return true;
}

/* Publish only after relocation, unwind registration and constructors have
 * succeeded. Allocation and insertion are all-or-none for this dependency
 * closure, so another Linker can never adopt only a subset of its providers. */
static void _linker_shared_manual_publish(struct linker *linker) {
  if (!linker || linker->dep_count <= 0) return;
  size_t count = 0;
  for (int i = 0; i < linker->dep_count; ++i) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (dep->is_manual_load && !dep->shared_object) {
      if (dep->pool_uses_main) return;
      ++count;
    }
  }
  if (!count) return;

  struct shared_dep_object **objects =
      calloc((size_t)linker->dep_count, sizeof(*objects));
  if (!objects) return;
  bool allocated = true;
  for (int i = 0; i < linker->dep_count; ++i) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load || dep->shared_object) continue;
    struct shared_dep_object *object = calloc(1, sizeof(*object));
    char *scope_key = _linker_shared_manual_scope_key(linker, i);
    if (!object || !scope_key || !dep->map_size) {
      free(object);
      free(scope_key);
      allocated = false;
      break;
    }
    object->key = strdup(dep->img->elf ? dep->img->elf : "<manual>");
    if (!object->key) {
      free(scope_key);
      free(object);
      allocated = false;
      break;
    }
    object->scope_key = scope_key;
    object->img = dep->img;
    object->map_base = dep->map_base ? dep->map_base : dep->img->base;
    object->map_size = dep->map_size;
    object->tls_indices = dep->tls_indices;
    object->lifecycle_state = dep->lifecycle_state;
    object->refs = 1;
    object->manual = true;
    objects[i] = object;
  }
  if (!allocated) {
    for (int i = 0; i < linker->dep_count; ++i) {
      if (!objects[i]) continue;
      free(objects[i]->key);
      free(objects[i]->scope_key);
      free(objects[i]);
    }
    free(objects);
    return;
  }

  if (!_linker_registry_lock()) {
    for (int i = 0; i < linker->dep_count; ++i) {
      if (!objects[i]) continue;
      free(objects[i]->key);
      free(objects[i]->scope_key);
      free(objects[i]);
    }
    free(objects);
    return;
  }

  /* A concurrent linker may have published an identical scope. Keep this
   * just-linked closure private rather than replacing a live relocated image. */
  for (int i = 0; i < linker->dep_count && allocated; ++i) {
    if (!objects[i]) continue;
    for (struct shared_dep_object *it = g_shared_dep_objects; it; it = it->next) {
      if (it->manual && it->scope_key &&
          strcmp(it->scope_key, objects[i]->scope_key) == 0) {
        allocated = false;
        break;
      }
    }
  }
  if (allocated) {
    for (int i = 0; i < linker->dep_count; ++i) {
      struct shared_dep_object *object = objects[i];
      if (!object) continue;
      object->next = g_shared_dep_objects;
      g_shared_dep_objects = object;
      struct loaded_dep *dep = &linker->dependencies[i];
      dep->shared_object = object;
      dep->map_base = NULL;
      dep->map_size = 0;
      memset(&dep->tls_indices, 0, sizeof(dep->tls_indices));
      objects[i] = NULL;
    }
  }
  _linker_registry_unlock();

  for (int i = 0; i < linker->dep_count; ++i) {
    if (!objects[i]) continue;
    free(objects[i]->key);
    free(objects[i]->scope_key);
    free(objects[i]);
  }
  free(objects);
}

/* VREZYGISK_MANUAL_DEPENDENCY_OBJECT_POOL */
"""

    source = replace_once(
        source,
        "/* VREZYGISK_PROCESS_SHARED_DEPENDENCY_POOL */",
        "/* VREZYGISK_PROCESS_SHARED_DEPENDENCY_POOL */\n" + helpers,
        "insert manual dependency pool helpers",
    )

    source = replace_once(
        source,
        '#include "linker.h"',
        '#include "linker.h"\n#include <sys/stat.h>',
        "include stat for manual dependency identity",
    )

    # Mark main-image bindings from dependency relocations. The generated
    # version-aware resolver still contains this stable diagnostic anchor.
    source = replace_once(
        source,
        "    if (addr) {\n      LOGD(\"Found exported symbol '%s' in main image:",
        "    if (addr) {\n      if (requester != linker->img) {\n"
        "        for (int scope_i = 0; scope_i < linker->dep_count; ++scope_i) {\n"
        "          if (linker->dependencies[scope_i].img == requester)\n"
        "            linker->dependencies[scope_i].pool_uses_main = true;\n"
        "        }\n"
        "      }\n"
        "      LOGD(\"Found exported symbol '%s' in main image:",
        "mark main-image relocation bindings",
    )

    # All-or-none adoption happens after the full ordered dependency graph is
    # known but before any TLS registration or relocation is performed.
    source = replace_once(
        source,
        """  carray_destroy(loaded_libs);

  LOGD("Registering TLS segments for main library and dependencies.");""",
        """  carray_destroy(loaded_libs);

  if (!_linker_shared_manual_adopt(linker)) {
    LOGE("Unable to allocate shared dependency adoption state");
    return false;
  }

  LOGD("Registering TLS segments for main library and dependencies.");""",
        "adopt shared manual closure before TLS and relocation",
    )

    source = replace_once(
        source,
        """  linker->is_linked = true;

  return true;""",
        """  linker->is_linked = true;
  _linker_shared_manual_publish(linker);

  return true;""",
        "publish relocated manual dependency closure",
    )

    # Verify that every relocation/registration path skips an already-linked
    # shared image, while its TLS indices remain visible through the scope.
    if source.count("linker->dependencies[i].shared_object)) continue;") < 4:
        raise RuntimeError("not all dependency relocation/unwind loops skip pooled images")
    if "candidate->shared_object->tls_indices" not in source:
        raise RuntimeError("shared provider TLS index ownership is not wired")

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
