#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "hiding.h"
#include "logging.h"
#include "misc.h"

/*
 * Anonymous mapping replacement for Zygisk-owned libraries.
 *
 * The loaded-object table is collected before any VMA is replaced. This is
 * important: mremap can split/merge VMAs, so reading /proc/self/maps while
 * modifying it would make later ranges stale.
 *
 * The target list comes from get_loaded_libraries() in hook.c. It contains
 * ReZygisk's own image and the CSOLoader images that remain loaded after
 * postAppSpecialize. Only private mappings belonging to /data/adb-backed
 * objects are eligible; shared mappings and unrelated app/system mappings
 * are never touched.
 *
 * The replacement is prepared completely at a scratch address first. The
 * source mapping is changed only after the copy has its final permissions.
 * Any failed preflight leaves the original mapping intact.
 */

#define ADB_PREFIX "/data/adb/"
#define DISABLE_ANON_MEMORY_PATH "/data/adb/rezygisk/disable-anonymous-memory"

#ifndef PR_SET_VMA
  #define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
  #define PR_SET_VMA_ANON_NAME 0
#endif

struct hide_target {
  uintptr_t start;
  uintptr_t end;
  int perms;
  const char *path;
};

static bool is_adb_library(const char *path) {
  if (path == NULL) return false;

  static const char deleted_suffix[] = " (deleted)";
  size_t len = strlen(path);
  const size_t suffix_len = sizeof(deleted_suffix) - 1;

  if (len > suffix_len &&
      memcmp(path + len - suffix_len, deleted_suffix, suffix_len) == 0) {
    len -= suffix_len;
  }

  return len >= sizeof(ADB_PREFIX) - 1 &&
         memcmp(path, ADB_PREFIX, sizeof(ADB_PREFIX) - 1) == 0;
}

static const char *find_owner(const struct map_entry *map,
                              const struct maps_info *libraries) {
  for (size_t i = 0; i < libraries->length; i++) {
    const struct map_entry *library = &libraries->maps[i];

    if (!is_adb_library(library->path)) continue;
    if (map->start < library->start || map->end > library->end) continue;

    return library->path;
  }

  return NULL;
}

static bool hide_one_mapping(const struct hide_target *target) {
  const size_t size = (size_t)(target->end - target->start);
  void *address = (void *)target->start;
  bool source_made_readable = false;

  if (size == 0 || target->end <= target->start) return false;

  void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (copy == MAP_FAILED) {
    PLOGE("anonymous-memory: allocate copy for [%s]", target->path);
    return false;
  }

  if ((target->perms & PROT_READ) == 0) {
    if (mprotect(address, size, target->perms | PROT_READ) == -1) {
      PLOGE("anonymous-memory: make source readable for [%s]", target->path);
      munmap(copy, size);
      return false;
    }

    source_made_readable = true;
  }

  memcpy(copy, address, size);

  if (source_made_readable && mprotect(address, size, target->perms) == -1) {
    PLOGE("anonymous-memory: restore source permissions for [%s]", target->path);
    munmap(copy, size);
    return false;
  }

  /*
   * Preflight the exact final protection before replacing the live mapping.
   * This is particularly important for executable mappings on devices whose
   * SELinux policy denies anonymous executable memory.
   */
  if (mprotect(copy, size, target->perms) == -1) {
    PLOGE("anonymous-memory: executable/protection policy rejected [%s]", target->path);
    munmap(copy, size);
    return false;
  }

  if (target->perms & PROT_EXEC) {
    __builtin___clear_cache((char *)copy, (char *)copy + size);
  }

  if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, address) == MAP_FAILED) {
    PLOGE("anonymous-memory: replace mapping for [%s]", target->path);
    munmap(copy, size);
    return false;
  }

  /* The replacement is already at the original address and has final perms. */
  (void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, address, size, NULL);

  if (target->perms & PROT_EXEC) {
    __builtin___clear_cache((char *)address, (char *)address + size);
  }

  LOGD("anonymous-memory: replaced [%s] %p-%p (%zu bytes)",
       target->path, address, (void *)target->end, size);

  return true;
}

struct hide_state {
  const struct maps_info *libraries;
  struct hide_target *targets;
  size_t count;
  size_t capacity;
};

static bool collect_hide_target(const struct map_entry *map, void *userdata) {
  struct hide_state *state = userdata;

  if (!map->is_private || map->end <= map->start) return true;

  const char *owner = find_owner(map, state->libraries);
  if (owner == NULL) return true;

  if (state->count == state->capacity) {
    size_t capacity = state->capacity == 0 ? 8 : state->capacity * 2;
    struct hide_target *targets = realloc(state->targets, capacity * sizeof(*targets));
    if (targets == NULL) {
      PLOGE("anonymous-memory: grow target list");
      return false;
    }

    state->targets = targets;
    state->capacity = capacity;
  }

  state->targets[state->count++] = (struct hide_target) {
    .start = map->start,
    .end = map->end,
    .perms = map->perms,
    .path = owner
  };

  return true;
}

bool hide_module_maps(const struct maps_info *libraries) {
  if (libraries == NULL || libraries->length == 0) return false;

  if (access(DISABLE_ANON_MEMORY_PATH, F_OK) == 0) {
    LOGD("anonymous-memory: disabled by %s", DISABLE_ANON_MEMORY_PATH);
    return true;
  }

  struct hide_state state = { .libraries = libraries };

  /*
   * The child opens /proc/self/maps and passes the fd to us. Collection is
   * completed before any mremap, so no live maps reader races VMA replacement.
   */
  if (!scan_maps_safe("self", collect_hide_target, &state)) {
    LOGE("anonymous-memory: failed to snapshot /proc/self/maps");
    free(state.targets);
    return false;
  }

  size_t hidden = 0;
  for (size_t i = 0; i < state.count; i++) {
    if (hide_one_mapping(&state.targets[i])) hidden++;
  }

  LOGD("anonymous-memory: replaced %zu/%zu eligible mappings",
       hidden, state.count);

  free(state.targets);

  return hidden > 0 || state.count == 0;
}
