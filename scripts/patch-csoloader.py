#!/usr/bin/env python3
"""Apply the VReZygisk TLS hardening delta to the pinned CSOLoader submodule.

The upstream dependency remains pinned. This script is idempotent and is run
before compiling CSOLoader, so CI and local builds use the same reviewed patch.
"""
from pathlib import Path
import sys

MARKER = "/* VREZYGISK_TLS_GENERATION_GUARD */"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source anchor, found {count}")
    return source.replace(old, new, 1)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <CSOLoader/src/linker.c>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    source = path.read_text()
    if MARKER in source:
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

    path.write_text(source)
    print(f"Applied VReZygisk TLS hardening to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
