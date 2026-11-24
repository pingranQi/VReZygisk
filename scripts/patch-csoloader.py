#!/usr/bin/env python3
"""Apply the VReZygisk TLS hardening delta to the pinned CSOLoader submodule.

The upstream dependency remains pinned. This script is idempotent and is run
before compiling CSOLoader, so CI and local builds use the same reviewed patch.
"""
from pathlib import Path
import sys

MARKER = "/* VREZYGISK_TLS_GENERATION_GUARD */"
REGISTRATION_MARKER = "/* VREZYGISK_TLS_REGISTRATION_FAILURE_GUARD */"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source anchor, found {count}")
    return source.replace(old, new, 1)



def patch_csoloader_api(path: Path) -> None:
    marker = "/* VREZYGISK_PREALLOCATE_LIBRARY_PATH */"
    source = path.read_text()
    if marker in source:
        return

    source = replace_once(
        source,
        """bool csoloader_load(struct csoloader *lib, const char *lib_path) {
  struct loaded_dep dep_info = { 0 };
  void *map_start = linker_load_library_manually(lib_path, &dep_info);
  if (!map_start) {
    LOGE("Failed to load library: %s", lib_path);

    return false;
  }

  struct csoloader_elf *elf_image = csoloader_elf_create(lib_path, map_start);
  if (!elf_image) {
    LOGE("Failed to create ELF image for %s", lib_path);

    if (dep_info.map_size > 0)
      munmap(map_start, dep_info.map_size);

    return false;
  }

  if (!linker_init(&lib->linker, elf_image)) {
    LOGE("Failed to initialize linker for %s", lib_path);

    csoloader_elf_destroy(elf_image);
    if (dep_info.map_size > 0)
      munmap(map_start, dep_info.map_size);

    return false;
  }

  lib->linker.main_map_size = dep_info.map_size;

  if (!linker_link(&lib->linker)) {
    LOGE("Linker failed to link %s", lib_path);

    linker_destroy(&lib->linker);

    return false;
  }

  lib->img = elf_image;
  lib->lib_path = strdup(lib_path);
  if (!lib->lib_path) {
    LOGE("Failed to duplicate library path string");

    linker_destroy(&lib->linker);

    return false;
  }

  return true;
}""",
        """bool csoloader_load(struct csoloader *lib, const char *lib_path) {
  if (!lib || !lib_path || lib->img || lib->lib_path) return false;

  /* Allocate all bookkeeping before mapping or executing module code. This
   * ensures an allocation failure cannot trigger Bionic fallback after the
   * custom loader has already run constructors. */
  char *path_copy = strdup(lib_path);
  if (!path_copy) {
    LOGE("Failed to duplicate library path string");
    return false;
  }

  struct loaded_dep dep_info = { 0 };
  void *map_start = linker_load_library_manually(lib_path, &dep_info);
  if (!map_start) {
    LOGE("Failed to load library: %s", lib_path);
    free(path_copy);
    return false;
  }

  struct csoloader_elf *elf_image = csoloader_elf_create(lib_path, map_start);
  if (!elf_image) {
    LOGE("Failed to create ELF image for %s", lib_path);
    if (dep_info.map_size > 0) munmap(map_start, dep_info.map_size);
    free(path_copy);
    return false;
  }

  if (!linker_init(&lib->linker, elf_image)) {
    LOGE("Failed to initialize linker for %s", lib_path);
    csoloader_elf_destroy(elf_image);
    if (dep_info.map_size > 0) munmap(map_start, dep_info.map_size);
    free(path_copy);
    return false;
  }

  lib->linker.main_map_size = dep_info.map_size;
  if (!linker_link(&lib->linker)) {
    LOGE("Linker failed to link %s", lib_path);
    linker_destroy(&lib->linker);
    free(path_copy);
    return false;
  }

  lib->img = elf_image;
  lib->lib_path = path_copy;
  return true;
}

/* VREZYGISK_PREALLOCATE_LIBRARY_PATH */""",
        "preallocate CSOLoader path before constructors",
    )
    path.write_text(source)



def patch_csoloader_lifecycle(linker_path: Path) -> None:
    header_path = linker_path.parent.parent / "include" / "linker.h"
    header = header_path.read_text()
    header_marker = "/* VREZYGISK_IMAGE_LIFECYCLE */"
    if header_marker not in header:
        header = replace_once(
            header,
            """struct loaded_dep {
  /* INFO: DO NOT change this 2 members from order. Keep consistent with linker structure */
  struct csoloader_elf *img;
  struct tls_indices_data tls_indices;

  bool is_manual_load;""",
            """enum linker_image_state {
  LINKER_IMAGE_UNINITIALIZED = 0,
  LINKER_IMAGE_CONSTRUCTING,
  LINKER_IMAGE_CONSTRUCTED,
  LINKER_IMAGE_FINALIZING,
  LINKER_IMAGE_FINALIZED
};

/* VREZYGISK_IMAGE_LIFECYCLE */
struct loaded_dep {
  /* INFO: DO NOT change this 2 members from order. Keep consistent with linker structure */
  struct csoloader_elf *img;
  struct tls_indices_data tls_indices;

  enum linker_image_state lifecycle_state;
  bool is_manual_load;""",
            "dependency constructor/destructor state",
        )
        header = replace_once(
            header,
            """  size_t main_map_size;
  bool is_linked;""",
            """  size_t main_map_size;
  bool is_linked;
  enum linker_image_state main_lifecycle_state;""",
            "main image constructor/destructor state",
        )
        header_path.write_text(header)

    source = linker_path.read_text()
    source_marker = "/* VREZYGISK_CONSTRUCTOR_STATE_MACHINE */"
    if source_marker not in source:
        source = replace_once(
            source,
            """static void _linker_call_constructors(struct csoloader_elf *img) {
  if (img->init_func) {""",
            """static void _linker_call_constructors(struct csoloader_elf *img,
                                       enum linker_image_state *state) {
  if (!img || !state || *state != LINKER_IMAGE_UNINITIALIZED) return;
  *state = LINKER_IMAGE_CONSTRUCTING;

  if (img->init_func) {""",
            "constructor state entry",
        )
        source = replace_once(
            source,
            """  }
}

static void _linker_call_destructors(struct csoloader_elf *img) {
  if (img->fini_array) {""",
            """  }

  *state = LINKER_IMAGE_CONSTRUCTED;
}

static void _linker_call_destructors(struct csoloader_elf *img,
                                     enum linker_image_state *state) {
  if (!img || !state || *state != LINKER_IMAGE_CONSTRUCTED) return;
  *state = LINKER_IMAGE_FINALIZING;

  if (img->fini_array) {""",
            "constructor/destructor state transition",
        )
        source = replace_once(
            source,
            """    img->fini_func();
  }
}

static const char *_path_basename""",
            """    img->fini_func();
  }

  *state = LINKER_IMAGE_FINALIZED;
}

/* VREZYGISK_CONSTRUCTOR_STATE_MACHINE */
static const char *_path_basename""",
            "destructor finalization state",
        )

        source = source.replace(
            "_linker_call_destructors(dep->img);",
            "_linker_call_destructors(dep->img, &dep->lifecycle_state);",
        )
        source = source.replace(
            "_linker_call_destructors(linker->img);",
            "_linker_call_destructors(linker->img, &linker->main_lifecycle_state);",
        )
        source = source.replace(
            "_linker_call_constructors(dep->img);",
            "_linker_call_constructors(dep->img, &dep->lifecycle_state);",
        )
        source = source.replace(
            "_linker_call_constructors(linker->img);",
            "_linker_call_constructors(linker->img, &linker->main_lifecycle_state);",
        )
        source = replace_once(
            source,
            """  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->dep_count = 0;""",
            """  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->main_lifecycle_state = LINKER_IMAGE_UNINITIALIZED;
  linker->dep_count = 0;""",
            "initialize main image lifecycle",
        )
        source = replace_once(
            source,
            """static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (strstr(linker->img->elf, lib_name)) return true;

  for (int i = 0; i < linker->dep_count; i++) {
    if (strstr(linker->dependencies[i].img->elf, lib_name)) return true;
  }

  return false;
}""",
            """static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (!linker || !lib_name) return false;
  const char *requested = _path_basename(lib_name);
  if (linker->img && strcmp(_path_basename(linker->img->elf), requested) == 0)
    return true;

  for (int i = 0; i < linker->dep_count; i++) {
    struct csoloader_elf *loaded = linker->dependencies[i].img;
    if (loaded && strcmp(_path_basename(loaded->elf), requested) == 0)
      return true;
  }

  return false;
}""",
            "exact SONAME/path dependency de-duplication",
        )
        linker_path.write_text(source)

def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <CSOLoader/src/linker.c>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    csoloader_path = path.with_name("csoloader.c")
    source = path.read_text()
    if MARKER in source:
        patch_csoloader_api(csoloader_path)
        patch_csoloader_lifecycle(path)
        if REGISTRATION_MARKER not in source:
            source = replace_once(
                source,
                """  LOGD("Registering TLS segments for main library and dependencies.");
  _linker_register_tls_segment(linker->img);
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    _linker_register_tls_segment(dep->img);
  }""",
                """  LOGD("Registering TLS segments for main library and dependencies.");
  if (!_linker_register_tls_segment(linker->img)) {
    LOGE("Failed to register TLS segment for main image %s", linker->img->elf);
    return false;
  }
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    if (!_linker_register_tls_segment(dep->img)) {
      LOGE("Failed to register TLS segment for dependency %s", dep->img->elf);
      return false;
    }
  }
  /* VREZYGISK_TLS_REGISTRATION_FAILURE_GUARD */""",
                "TLS registration failure propagation",
            )
            path.write_text(source)
            print(f"Applied CSOLoader TLS registration failure checks to {path}")
        else:
            print("CSOLoader TLS hardening already applied")
        return 0

    source = replace_once(
        source,
        """struct tls_module {
  size_t module_id;
  size_t align;""",
        """struct tls_module {
  size_t module_id;
  size_t generation;
  size_t align;""",
        "TLS module generation field",
    )
    source = replace_once(
        source,
        """  /* INFO: Per-module TLS block pointers */
  void *modules[MAX_TLS_MODULES];""",
        """  /* INFO: Per-module TLS block pointers and allocation generations */
  void *modules[MAX_TLS_MODULES];
  size_t module_generations[MAX_TLS_MODULES];""",
        "per-thread TLS generation fields",
    )
    source = replace_once(
        source,
        """static pthread_key_t g_tls_key;
static bool g_tls_key_initialized = false;
static pthread_once_t g_tls_key_once = PTHREAD_ONCE_INIT;""",
        """static pthread_key_t g_tls_key;
static bool g_tls_key_initialized = false;
static int g_tls_key_error = 0;
static pthread_once_t g_tls_key_once = PTHREAD_ONCE_INIT;

/* VREZYGISK_TLS_GENERATION_GUARD */
static size_t _linker_bump_tls_generation(void) {
  if (++g_tls_generation == 0) ++g_tls_generation;
  return g_tls_generation;
}""",
        "TLS key and generation state",
    )
    source = replace_once(
        source,
        """static void _linker_alloc_tls_key_once(void) {
  pthread_key_create(&g_tls_key, _linker_destroy_thread_tls);
}""",
        """static void _linker_alloc_tls_key_once(void) {
  g_tls_key_error = pthread_key_create(&g_tls_key, _linker_destroy_thread_tls);
  g_tls_key_initialized = (g_tls_key_error == 0);
}""",
        "TLS key creation error handling",
    )
    source = replace_once(
        source,
        """  size_t align = mod->align;
  /* INFO: posix_memalign requires alignment >= sizeof(void *) and power of 2 */
  if (align < sizeof(void *)) align = sizeof(void *);
  if (system_page_size > 0 && align > system_page_size) align = system_page_size;""",
        """  size_t align = mod->align;
  /* posix_memalign requires power-of-two alignment and must honor p_align. */
  if (align < sizeof(void *)) align = sizeof(void *);
  if ((align & (align - 1)) != 0 || mod->filesz > mod->memsz ||
      (mod->filesz > 0 && !mod->init_image)) {
    LOGE("Invalid TLS image metadata for module %zu", mod->module_id);
    return NULL;
  }""",
        "TLS alignment and image bounds",
    )
    source = replace_once(
        source,
        """static struct thread_tls *_linker_get_thread_tls(void) {
  pthread_once(&g_tls_key_once, _linker_alloc_tls_key_once);
  g_tls_key_initialized = true;

  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (!ttls) {
    ttls = (struct thread_tls *)calloc(1, sizeof(struct thread_tls));
    if (!ttls) {
      LOGE("Failed to allocate thread TLS state");

      return NULL;
    }

    ttls->generation = 0;

    pthread_setspecific(g_tls_key, ttls);
  }

  return ttls;
}""",
        """static struct thread_tls *_linker_get_thread_tls(void) {
  int once_error = pthread_once(&g_tls_key_once, _linker_alloc_tls_key_once);
  if (once_error != 0 || g_tls_key_error != 0 || !g_tls_key_initialized) {
    LOGE("Failed to initialize TLS key: once=%d key=%d",
         once_error, g_tls_key_error);
    return NULL;
  }

  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (!ttls) {
    ttls = (struct thread_tls *)calloc(1, sizeof(struct thread_tls));
    if (!ttls) {
      LOGE("Failed to allocate thread TLS state");
      return NULL;
    }

    ttls->generation = 0;
    int set_error = pthread_setspecific(g_tls_key, ttls);
    if (set_error != 0) {
      LOGE("Failed to attach thread TLS state: %d", set_error);
      free(ttls);
      return NULL;
    }
  }

  return ttls;
}""",
        "TLS key initialization and per-thread registration",
    )
    source = replace_once(
        source,
        """static void _linker_sync_thread_tls(struct thread_tls *ttls) {
  pthread_mutex_lock(&g_tls_mutex);
  size_t current_gen = g_tls_generation;
  pthread_mutex_unlock(&g_tls_mutex);

  if (ttls->generation >= current_gen) return;

  for (size_t i = 1; i < MAX_TLS_MODULES; i++) {
    struct tls_module *mod = &g_tls_modules[i];
    if (mod->module_id != 0 || !ttls->modules[i]) continue;

    free(ttls->modules[i]);
    ttls->modules[i] = NULL;
  }

  ttls->generation = current_gen;
}""",
        """static void _linker_sync_thread_tls(struct thread_tls *ttls) {
  if (!ttls) return;

  pthread_mutex_lock(&g_tls_mutex);
  size_t current_gen = g_tls_generation;
  if (ttls->generation == current_gen) {
    pthread_mutex_unlock(&g_tls_mutex);
    return;
  }

  /* A module ID can be reused after unload. Compare per-slot generations,
   * not only the current module_id, or a stale TLS block can be reused. */
  for (size_t i = 1; i < MAX_TLS_MODULES; i++) {
    size_t module_generation = g_tls_modules[i].generation;
    if (ttls->module_generations[i] == module_generation) continue;

    free(ttls->modules[i]);
    ttls->modules[i] = NULL;
    ttls->module_generations[i] = module_generation;
  }

  ttls->generation = current_gen;
  pthread_mutex_unlock(&g_tls_mutex);
}""",
        "generation-safe per-thread TLS synchronization",
    )
    source = replace_once(
        source,
        """  mod->init_image = (const void *)((uintptr_t)img->base + img->tls_segment->p_vaddr - img->bias);
  mod->owner      = img;

  img->tls_mod_id = mod_id;
  g_tls_generation++;""",
        """  mod->init_image = (const void *)((uintptr_t)img->base + img->tls_segment->p_vaddr - img->bias);
  mod->owner      = img;
  mod->generation = _linker_bump_tls_generation();

  img->tls_mod_id = mod_id;""",
        "TLS registration generation assignment",
    )
    source = replace_once(
        source,
        """void *__tls_get_addr(struct tls_index *ti) {
  LOGD("__tls_get_addr called: ti=%p, module=%zu, offset=%zu", ti, (size_t)ti->module, (size_t)ti->offset);

  size_t mod_id = ti->module;""",
        """void *__tls_get_addr(struct tls_index *ti) {
  if (!ti) {
    LOGE("__tls_get_addr called with a null TLS index");
    return NULL;
  }
  LOGD("__tls_get_addr called: ti=%p, module=%zu, offset=%zu", ti, (size_t)ti->module, (size_t)ti->offset);

  size_t mod_id = ti->module;""",
        "TLS index validation",
    )
    source = replace_once(
        source,
        """  if (!ttls->modules[mod_id]) {
    ttls->modules[mod_id] = _linker_allocate_module_tls(mod);
    if (!ttls->modules[mod_id]) {""",
        """  if (ti->offset >= mod->memsz) {
    pthread_mutex_unlock(&g_tls_mutex);
    LOGE("TLS offset %zu exceeds module %zu size %zu",
         (size_t)ti->offset, mod_id, mod->memsz);
    return NULL;
  }

  /* Re-check under the registry lock in case a module ID was recycled after
   * the thread's initial generation synchronization. */
  if (ttls->module_generations[mod_id] != mod->generation) {
    free(ttls->modules[mod_id]);
    ttls->modules[mod_id] = NULL;
    ttls->module_generations[mod_id] = mod->generation;
  }

  if (!ttls->modules[mod_id]) {
    ttls->modules[mod_id] = _linker_allocate_module_tls(mod);
    if (!ttls->modules[mod_id]) {""",
        "TLS offset and module ID reuse validation",
    )
    source = replace_once(
        source,
        """void linker_deinit(void) {
  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (ttls) _linker_destroy_thread_tls(ttls);
  pthread_setspecific(g_tls_key, NULL);

  pthread_key_delete(g_tls_key);
  g_tls_key_initialized = false;
  g_tls_key_once = PTHREAD_ONCE_INIT;""",
        """void linker_deinit(void) {
  if (g_tls_key_initialized) {
    struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
    int clear_error = pthread_setspecific(g_tls_key, NULL);
    if (clear_error == 0) {
      if (ttls) _linker_destroy_thread_tls(ttls);
    } else {
      LOGE("Failed to clear current thread TLS state during deinit: %d",
           clear_error);
    }

    int delete_error = pthread_key_delete(g_tls_key);
    if (delete_error != 0)
      LOGE("Failed to delete TLS key during deinit: %d", delete_error);
  }
  g_tls_key_initialized = false;
  g_tls_key_error = 0;
  g_tls_key_once = PTHREAD_ONCE_INIT;""",
        "safe TLS key deinitialization",
    )

    source = replace_once(
        source,
        """  LOGD("Registering TLS segments for main library and dependencies.");
  _linker_register_tls_segment(linker->img);
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    _linker_register_tls_segment(dep->img);
  }""",
        """  LOGD("Registering TLS segments for main library and dependencies.");
  if (!_linker_register_tls_segment(linker->img)) {
    LOGE("Failed to register TLS segment for main image %s", linker->img->elf);
    return false;
  }
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    if (!_linker_register_tls_segment(dep->img)) {
      LOGE("Failed to register TLS segment for dependency %s", dep->img->elf);
      return false;
    }
  }
  /* VREZYGISK_TLS_REGISTRATION_FAILURE_GUARD */""",
        "TLS registration failure propagation",
    )

    patch_csoloader_api(csoloader_path)
    path.write_text(source)
    patch_csoloader_lifecycle(path)
    print(f"Applied VReZygisk linker/TLS hardening to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
