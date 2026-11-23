#ifndef ROOT_MOUNTS_H
#define ROOT_MOUNTS_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define ROOT_MODULES_DIR "/data/adb/modules"
#define ROOT_MODULES_ROOT "/adb/modules"
#define MOUNT_FIELD_MAX 4096
#define MOUNT_TYPE_MAX 128

struct mount_entry {
  unsigned int id;
  char *root;
  char *target;
  char *source;
};

static inline bool mount_entry_split(char *line, unsigned int *id,
                                     char *root, char *target,
                                     char *type, char *source) {
  char *separator = strstr(line, " - ");
  if (separator == NULL) return false;
  *separator = '\0';
  if (sscanf(line, "%u %*u %*u:%*u %4095s %4095s", id, root, target) != 3) return false;
  if (sscanf(separator + 3, "%127s %4095s", type, source) != 2) return false;
  return true;
}

static inline bool mount_path_at_or_under(const char *path, const char *prefix) {
  size_t len = strlen(prefix);
  if (strncmp(path, prefix, len) != 0) return false;
  return path[len] == '\0' || path[len] == '/';
}

static inline bool mount_is_module_loop_source(const char *target, const char *source) {
  return strcmp(target, ROOT_MODULES_DIR) == 0 &&
         strncmp(source, MOUNT_SOURCE_LOOP, strlen(MOUNT_SOURCE_LOOP)) == 0;
}

static inline const char *mount_find_loop_source(const struct mount_entry *entries, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (mount_is_module_loop_source(entries[i].target, entries[i].source)) return entries[i].source;
  }
  return NULL;
}

static const char *const kRootSources[] = {
  "APatch", "kpatch", "KSU", "magisk", "YukiSU", "YukiZygisk"
};
#define ROOT_SOURCE_COUNT (sizeof(kRootSources) / sizeof(kRootSources[0]))

static inline bool mount_carries_root_trace(const char *root, const char *target,
                                            const char *source, const char *loop_source) {
  if (mount_path_at_or_under(root, ROOT_MODULES_ROOT)) return true;
  if (mount_path_at_or_under(target, ROOT_MODULES_DIR)) return true;
  for (size_t i = 0; i < ROOT_SOURCE_COUNT; i++) {
    if (strcmp(source, kRootSources[i]) == 0) return true;
  }
  return loop_source != NULL && strcmp(source, loop_source) == 0;
}

#endif
