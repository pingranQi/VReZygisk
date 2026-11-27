#include <errno.h>
#include <pthread.h>
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
 * The target list comes from get_loaded_libraries() in hook.c. Only private
 * mappings belonging to /data/adb-backed objects are eligible; shared
 * mappings and unrelated app/system mappings are never touched.
 *
 * Each replacement is prepared at a scratch address first. The source VMA is
 * changed only after the copy has the final permissions. A failed preflight
 * leaves the original mapping in place.
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

struct hide_state {
  const struct maps_info *libraries;
  struct hide_target *targets;
  size_t count;
  size_t capacity;
};

/*
 * hide_module_maps() is normally called once during app specialization.
 * Serialize callers nevertheless: two concurrent snapshots must not attempt
 * to replace the same virtual address at the same time.
 */
static pthread_mutex_t g_hide_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool is_adb_library(const char *path) {
  if (path == NULL) return false;

  static const char deleted_suffix[] = " (deleted)";
  const size_t len = strlen(path);
  const size_t suffix_len = sizeof(deleted_suffix) - 1;

  if (len >= suffix_len &&
      memcmp(path + len - suffix_len, deleted_suffix, suffix_len) == 0) {
    return len - suffix_len >= sizeof(ADB_PREFIX) - 1 &&
           memcmp(path, ADB_PREFIX, sizeof(ADB_PREFIX) - 1) == 0;
  }

  return len >= sizeof(ADB_PREFIX) - 1 &&
         memcmp(path, ADB_PREFIX, sizeof(ADB_PREFIX) - 1) == 0;
}

static const char *find_owner(const struct map_entry *map,
                              const struct maps_info *libraries) {
  if (map == NULL || libraries == NULL || libraries->maps == NULL) return NULL;

  for (size_t i = 0; i < libraries->length; i++) {
    const struct map_entry *library = &libraries->maps[i];

    if (!is_adb_library(library->path)) continue;
    if (library->end <= library->start) continue;
    if (map->start < library->start || map->end > library->end) continue;

    return library->path;
  }

  return NULL;
}

/*
 * /proc/self/maps ranges should be page-aligned. Validate this before passing
 * the range to mmap/mprotect/mremap, and reject malformed or overflowing
 * ranges rather than allowing a wrapped size to reach a syscall.
 */
static bool get_mapping_size(const struct hide_target *target,
                             size_t page_size, size_t *size_out) {
  if (target == NULL || size_out == NULL || page_size == 0 ||
      target->end <= target->start) {
    return false;
  }

  const uintptr_t span = target->end - target->start;
  const size_t size = (size_t)span;
  if ((uintptr_t)size != span) return false;
  if (size == 0 || (target->start % page_size) != 0 ||
      (size % page_size) != 0) {
    return false;
  }

  *size_out = size;
  return true;
}

static bool hide_one_mapping(const struct hide_target *target,
                             size_t page_size) {
  size_t size = 0;
  if (target == NULL) {
    LOGW("Skip a null mapping target");
    return false;
  }
  if (!get_mapping_size(target, page_size, &size)) {
    LOGW("Skip invalid mapping range %p-%p",
         (void *)target->start, (void *)target->end);
    return false;
  }

  void *address = (void *)target->start;
  const char *path = target->path ? target->path : "(unknown)";
  bool source_needs_restore = false;

  void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (copy == MAP_FAILED) {
    PLOGE("allocate a copy of [%s]", path);
    return false;
  }

  /*
   * Some ELF segments are execute-only or PROT_NONE. Temporarily add read
   * permission only for the copy. If restoring it fails, still try the
   * prepared replacement: a successful mremap installs the original final
   * permissions atomically at the target address.
   */
  if ((target->perms & PROT_READ) == 0) {
    if (mprotect(address, size, target->perms | PROT_READ) == -1) {
      PLOGE("make [%s] readable", path);
      munmap(copy, size);
      return false;
    }

    source_needs_restore = true;
  }

  memcpy(copy, address, size);

  if (source_needs_restore) {
    if (mprotect(address, size, target->perms) == 0) {
      source_needs_restore = false;
    } else {
      PLOGE("restore the permissions of [%s]", path);
    }
  }

  /*
   * Preflight the exact final protection before replacing the live mapping.
   * This is particularly important for executable mappings on devices whose
   * SELinux policy denies anonymous executable memory.
   */
  if (mprotect(copy, size, target->perms) == -1) {
    const int protect_error = errno;

    if (source_needs_restore &&
        mprotect(address, size, target->perms) == -1) {
      PLOGE("restore the permissions of [%s] after preflight failure", path);
    }

    errno = protect_error;
    PLOGE("set the permissions of the copy of [%s]", path);
    munmap(copy, size);
    return false;
  }

  if (target->perms & PROT_EXEC) {
    __builtin___clear_cache((char *)copy, (char *)copy + size);
  }

  if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, address) == MAP_FAILED) {
    const int remap_error = errno;

    if (source_needs_restore &&
        mprotect(address, size, target->perms) == -1) {
      PLOGE("restore the permissions of [%s] after replacement failure", path);
    }

    errno = remap_error;
    PLOGE("move the copy of [%s] over the original", path);
    munmap(copy, size);
    return false;
  }

  /* The replacement is already at the original address and has final perms. */
  (void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, address, size, NULL);

  if (target->perms & PROT_EXEC) {
    __builtin___clear_cache((char *)address, (char *)address + size);
  }

  LOGD("Hid [%s]", path);

  return true;
}

static bool collect_hide_target(const struct map_entry *map, void *userdata) {
  struct hide_state *state = (struct hide_state *)userdata;
  if (map == NULL || state == NULL || state->libraries == NULL) return false;

  if (!map->is_private || map->end <= map->start) return true;

  const char *owner = find_owner(map, state->libraries);
  if (owner == NULL) return true;

  if (state->count == SIZE_MAX) {
    LOGE("The hide list count overflowed");
    return false;
  }

  if (state->count == state->capacity) {
    size_t capacity;

    if (state->capacity == 0) {
      capacity = 8;
    } else {
      if (state->capacity > SIZE_MAX / 2) {
        LOGE("The hide list capacity overflowed");
        return false;
      }
      capacity = state->capacity * 2;
    }

    if (capacity > SIZE_MAX / sizeof(*state->targets)) {
      LOGE("The hide list allocation size overflowed");
      return false;
    }

    struct hide_target *targets =
        realloc(state->targets, capacity * sizeof(*state->targets));
    if (targets == NULL) {
      PLOGE("allocate the hide list");
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
  if (gettid() != getpid()) {
    LOGW("Skip anonymous-memory replacement outside the app main thread");
    return false;
  }
  if (libraries == NULL || libraries->length == 0) return false;
  if (libraries->maps == NULL) {
    LOGE("Invalid loaded-library table");
    return false;
  }

  const int lock_error = pthread_mutex_lock(&g_hide_mutex);
  if (lock_error != 0) {
    LOGE("Unable to acquire the hide lock: %s", strerror(lock_error));
    return false;
  }

  bool result = false;
  struct hide_state state = {
    .libraries = libraries,
    .targets = NULL,
    .count = 0,
    .capacity = 0
  };

  if (access(DISABLE_ANON_MEMORY_PATH, F_OK) == 0) {
    LOGD("Anonymous-memory hiding is disabled");
    result = true;
    goto cleanup;
  }

  const long raw_page_size = sysconf(_SC_PAGESIZE);
  if (raw_page_size <= 0) {
    LOGE("Failed to determine the page size");
    goto cleanup;
  }

  /*
   * The child opens /proc/self/maps and passes the fd to us. Collection is
   * completed before any mremap, so no live maps reader races VMA replacement.
   */
  if (!scan_maps_safe("self", collect_hide_target, &state)) {
    LOGE("Failed to read the maps of this process");
    goto cleanup;
  }

  size_t hidden = 0;
  for (size_t i = 0; i < state.count; i++) {
    if (hide_one_mapping(&state.targets[i], (size_t)raw_page_size)) {
      hidden++;
    }
  }

  LOGD("Hid %zu/%zu module map(s)", hidden, state.count);

  result = hidden > 0 || state.count == 0;

cleanup:
  free(state.targets);

  const int unlock_error = pthread_mutex_unlock(&g_hide_mutex);
  if (unlock_error != 0) {
    LOGE("Unable to release the hide lock: %s", strerror(unlock_error));
    return false;
  }

  return result;
}
