#define LOG_TAG "zygisk-zn-hook"

#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "logging.h"
#include "zn_hook.h"
#include "shadowhook.h"

struct zn_inline_hook_record {
  void *target;
  void *handler;
  void *stub;
  void *owner_base;
  void **original_out;
  void *internal_original;
  struct zn_inline_hook_record *next;
};

static pthread_mutex_t g_hook_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_hook_once = PTHREAD_ONCE_INIT;
static struct zn_inline_hook_record *g_hook_records;
static int g_hook_init_result = -1;

static void hook_atfork_prepare(void) {
  pthread_mutex_lock(&g_hook_mutex);
}

static void hook_atfork_parent(void) {
  pthread_mutex_unlock(&g_hook_mutex);
}

static void hook_atfork_child(void) {
  /* The forking thread owns the prepare lock in both parent and child. */
  pthread_mutex_unlock(&g_hook_mutex);
}

static void hook_initialize_once(void) {
  int result = shadowhook_init(SHADOWHOOK_MODE_MULTI, false);
  if (result != 0) {
    LOGE("ShadowHook initialization failed: %d (%s)", result,
         shadowhook_to_errmsg(result));
    g_hook_init_result = result;
    return;
  }

  result = pthread_atfork(hook_atfork_prepare, hook_atfork_parent,
                          hook_atfork_child);
  if (result != 0) {
    LOGE("Failed registering ShadowHook fork coordinator: %d", result);
    g_hook_init_result = result;
    return;
  }

  g_hook_init_result = 0;
  LOGI("ShadowHook %s initialized (multi mode)",
       shadowhook_get_version());
}

bool zn_hook_init(void) {
  int result = pthread_once(&g_hook_once, hook_initialize_once);
  if (result != 0) {
    LOGE("pthread_once for ShadowHook failed: %d", result);
    return false;
  }
  return g_hook_init_result == 0;
}

static void *image_base_for_address(void *address) {
  if (!address) return NULL;
  Dl_info info = {0};
  if (dladdr(address, &info) == 0) return NULL;
  return info.dli_fbase;
}

int zn_inline_hook(void *target, void *handler, void **original,
                   void *caller_address) {
  if (!target || !handler || !zn_hook_init()) return ZN_FAILED;

  void *owner_base = image_base_for_address(caller_address);
  if (!owner_base) owner_base = image_base_for_address(handler);
  if (!owner_base) {
    LOGE("Cannot identify owner image for ZN inline hook %p", handler);
    return ZN_FAILED;
  }

  struct zn_inline_hook_record *record = calloc(1, sizeof(*record));
  if (!record) {
    LOGE("Out of memory allocating ZN inline hook record");
    return ZN_FAILED;
  }

  record->target = target;
  record->handler = handler;
  record->owner_base = owner_base;
  record->original_out = original;

  pthread_mutex_lock(&g_hook_mutex);
  void **original_slot = original ? original : &record->internal_original;
  record->stub = shadowhook_hook_func_addr_2(
      target, handler, original_slot, SHADOWHOOK_HOOK_WITH_MULTI_MODE);
  if (!record->stub) {
    int error = shadowhook_get_errno();
    LOGE("ShadowHook inline hook failed target=%p handler=%p: %d (%s)",
         target, handler, error, shadowhook_to_errmsg(error));
    pthread_mutex_unlock(&g_hook_mutex);
    free(record);
    return ZN_FAILED;
  }

  record->next = g_hook_records;
  g_hook_records = record;
  LOGI("ZN inline hook installed target=%p handler=%p owner=%p stub=%p",
       target, handler, owner_base, record->stub);
  pthread_mutex_unlock(&g_hook_mutex);
  return ZN_SUCCESS;
}

int zn_inline_unhook(void *target, void *caller_address) {
  if (!target || !zn_hook_init()) return ZN_FAILED;

  void *owner_base = image_base_for_address(caller_address);
  pthread_mutex_lock(&g_hook_mutex);

  struct zn_inline_hook_record **selected = NULL;
  for (struct zn_inline_hook_record **it = &g_hook_records; *it;
       it = &(*it)->next) {
    if ((*it)->target != target) continue;
    if (owner_base && (*it)->owner_base != owner_base) continue;
    selected = it;
    break; /* Newest hook from this module is removed first. */
  }

  if (!selected) {
    pthread_mutex_unlock(&g_hook_mutex);
    LOGW("No ZN inline hook owned by caller for target=%p", target);
    return ZN_FAILED;
  }

  struct zn_inline_hook_record *record = *selected;
  int result = shadowhook_unhook(record->stub);
  if (result != 0) {
    int error = shadowhook_get_errno();
    LOGE("ShadowHook inline unhook failed target=%p stub=%p: %d (%s)",
         target, record->stub, error, shadowhook_to_errmsg(error));
    pthread_mutex_unlock(&g_hook_mutex);
    return ZN_FAILED;
  }

  *selected = record->next;
  LOGI("ZN inline hook removed target=%p handler=%p owner=%p",
       target, record->handler, record->owner_base);
  free(record);
  pthread_mutex_unlock(&g_hook_mutex);
  return ZN_SUCCESS;
}
