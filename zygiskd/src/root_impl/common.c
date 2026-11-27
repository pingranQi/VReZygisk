#include "common.h"

#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>

#include "../utils.h"
#include "apatch.h"
#include "kernelsu.h"
#include "magisk.h"

static struct root_impl impl;

/* The daemon serves requests serially; a bounded TTL cache avoids spawning
 * Magisk CLI subprocesses for every app specialization. */
enum decision_kind { DECISION_MANAGER, DECISION_ROOT, DECISION_UMOUNT };
struct decision_entry {
  bool valid;
  enum decision_kind kind;
  uid_t uid;
  char process[PROCESS_NAME_MAX_LEN];
  bool result;
  uint64_t expires_ms;
};
#define DECISION_CACHE_SIZE 128
#define DECISION_CACHE_TTL_MS 5000
static struct decision_entry decision_cache[DECISION_CACHE_SIZE];
static size_t decision_cache_next;

static uint64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static bool decision_cache_get(enum decision_kind kind, uid_t uid,
                               const char *process, bool *result) {
  uint64_t now = monotonic_ms();
  if (now == 0) return false;
  const char *key = process ? process : "";
  for (size_t i = 0; i < DECISION_CACHE_SIZE; ++i) {
    struct decision_entry *entry = &decision_cache[i];
    if (!entry->valid || entry->expires_ms <= now || entry->kind != kind || entry->uid != uid) continue;
    if (strncmp(entry->process, key, sizeof(entry->process)) != 0) continue;
    *result = entry->result;
    return true;
  }
  return false;
}

static void decision_cache_put(enum decision_kind kind, uid_t uid,
                               const char *process, bool result) {
  uint64_t now = monotonic_ms();
  if (now == 0) return;
  struct decision_entry *entry = &decision_cache[decision_cache_next++ % DECISION_CACHE_SIZE];
  memset(entry, 0, sizeof(*entry));
  entry->valid = true;
  entry->kind = kind;
  entry->uid = uid;
  if (process) snprintf(entry->process, sizeof(entry->process), "%s", process);
  entry->result = result;
  entry->expires_ms = now + DECISION_CACHE_TTL_MS;
}

void root_impls_setup(void) {
  struct root_impl_state state_ksu;
  ksu_get_existence(&state_ksu);

  struct root_impl_state state_apatch;
  apatch_get_existence(&state_apatch);

  struct root_impl_state state_magisk;
  magisk_get_existence(&state_magisk);

  /* INFO: Check if it's only one supported, if not, it's multile and that's bad.
            Remember that true here is equal to the integer 1. */
  if ((state_ksu.state == Supported ? 1 : 0) + (state_apatch.state == Supported ? 1 : 0) + (state_magisk.state == Supported ? 1 : 0) >= 2) {
    impl.impl = Multiple;
  } else if (state_ksu.state == Supported) {
    impl.impl = KernelSU;
    impl.variant = state_ksu.variant;
  } else if (state_apatch.state == Supported) {
    impl.impl = APatch;
  } else if (state_magisk.state == Supported) {
    impl.impl = Magisk;
    impl.variant = state_magisk.variant;
  } else {
    impl.impl = None;
  }

  switch (impl.impl) {
    case None: {
      LOGI("No root implementation found.\n");

      break;
    }
    case Multiple: {
      LOGI("Multiple root implementations found.\n");

      break;
    }
    case KernelSU: {
      LOGI("KernelSU root implementation found.\n");

      break;
    }
    case APatch: {
      LOGI("APatch root implementation found.\n");

      break;
    }
    case Magisk: {
      LOGI("Magisk root implementation found.\n");

      break;
    }
  }
}

void get_impl(struct root_impl *uimpl) {
  *uimpl = impl;
}

bool uid_granted_root(uid_t uid) {
  bool cached = false;
  if (decision_cache_get(DECISION_ROOT, uid, NULL, &cached)) return cached;
  bool result = false;
  switch (impl.impl) {
    case KernelSU: result = ksu_uid_granted_root(uid); break;
    case APatch: result = apatch_uid_granted_root(uid); break;
    case Magisk: result = magisk_uid_granted_root(uid); break;
    default: result = false; break;
  }
  decision_cache_put(DECISION_ROOT, uid, NULL, result);
  return result;
}

bool uid_should_umount(uid_t uid, const char *const process) {
  bool cached = false;
  if (decision_cache_get(DECISION_UMOUNT, uid, process, &cached)) return cached;
  bool result = false;
  switch (impl.impl) {
    case KernelSU: result = ksu_uid_should_umount(uid); break;
    case APatch: result = apatch_uid_should_umount(uid, process); break;
    case Magisk: result = magisk_uid_should_umount(process); break;
    default: result = false; break;
  }
  decision_cache_put(DECISION_UMOUNT, uid, process, result);
  return result;
}

uid_t uid_from_pkg(const char *restrict pkg) {
  DIR *dir = opendir("/data/user");
  if (!dir) {
    LOGE("Failed to opendir /data/user: %s", strerror(errno));

    /* INFO: In Android system, an app cannot have UID 0, hence it's safe to utilize it as a fail signal.

      SOURCES:
       - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java#2100
    */
    return 0;
  }

  struct dirent *entry;
  struct stat st;
  memset(&st, 0, sizeof(st));
  bool found = false;
  while ((entry = readdir(dir)) != NULL) {
    /* INFO: Skip "." and ".." */
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        continue;

    char stat_path[PATH_MAX];
    snprintf(stat_path, sizeof(stat_path), "/data/user_de/%s/%s", entry->d_name, pkg);

    if (stat(stat_path, &st) != 0) {
      if (errno != ENOENT) {
        LOGE("Failed to stat manager path %s with %s", stat_path, strerror(errno));
      }

      continue;
    }

    found = true;
    break;
  }

  closedir(dir);
  if (!found) return 0;

  return APP_ID(st.st_uid);
}

bool uid_is_manager(uid_t uid) {
  bool cached = false;
  if (decision_cache_get(DECISION_MANAGER, uid, NULL, &cached)) return cached;
  bool result = false;
  switch (impl.impl) {
    case KernelSU: result = ksu_uid_is_manager(uid); break;
    case APatch: result = apatch_uid_is_manager(uid); break;
    case Magisk: result = magisk_uid_is_manager(uid); break;
    default: result = false; break;
  }
  decision_cache_put(DECISION_MANAGER, uid, NULL, result);
  return result;
}

void root_impl_cleanup(void) {
  if (impl.impl == KernelSU) ksu_cleanup();
}
