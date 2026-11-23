#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>

#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "mount_revert.h"
#include "logging.h"

#define MAX_REVERT_MOUNTS 128

struct mount_entry {
  char root[PATH_MAX];
  char target[PATH_MAX];
  char fs_type[64];
  char source[PATH_MAX];
  bool module_overlay;
};

static void decode_mount_field(char *field) {
  char *readp = field;
  char *writep = field;

  while (*readp) {
    if (readp[0] == '\\' && readp[1] >= '0' && readp[1] <= '7' &&
        readp[2] >= '0' && readp[2] <= '7' &&
        readp[3] >= '0' && readp[3] <= '7') {
      *writep++ = (char)(((readp[1] - '0') << 6) |
                         ((readp[2] - '0') << 3) |
                         (readp[3] - '0'));
      readp += 4;
    } else {
      *writep++ = *readp++;
    }
  }

  *writep = '\0';
}

static bool path_is_or_below(const char *path, const char *prefix) {
  size_t len = strlen(prefix);
  return strncmp(path, prefix, len) == 0 &&
         (path[len] == '\0' || path[len] == '/');
}

static bool is_root_source(const char *source) {
  return strcasecmp(source, "magisk") == 0 ||
         strcasecmp(source, "worker") == 0 ||
         strcasecmp(source, "KSU") == 0 ||
         strcasecmp(source, "KernelSU") == 0 ||
         strcasecmp(source, "KernelSU Next") == 0 ||
         strcasecmp(source, "APatch") == 0;
}

static bool is_root_mount(const struct mount_entry *entry) {
  if (is_root_source(entry->source)) return true;

  if (path_is_or_below(entry->target, "/data/adb/modules") ||
      path_is_or_below(entry->target, "/debug_ramdisk") ||
      path_is_or_below(entry->target, "/sbin/.magisk"))
    return true;

  if (path_is_or_below(entry->root, "/adb/modules") ||
      path_is_or_below(entry->root, "/adb/ksu") ||
      path_is_or_below(entry->root, "/adb/ap"))
    return true;

  /* Metamodule overlays commonly report a generic "overlay" source. */
  if (entry->module_overlay) return true;

  if (strcmp(entry->fs_type, "overlay") == 0 &&
      (strstr(entry->root, "/adb/modules/") != NULL ||
       strstr(entry->source, "/data/adb/") != NULL))
    return true;

  return false;
}

static bool is_protected_resource_target(const char *target) {
  static const char *const protected_paths[] = {
    "/system/fonts", "/system/framework",
    "/system_ext/fonts", "/system_ext/framework",
    "/product/fonts", "/product/framework",
    "/vendor/etc/fonts", "/apex/com.android.art"
  };

  if (path_is_or_below(target, "/product")) return true;

  for (size_t i = 0; i < sizeof(protected_paths) / sizeof(protected_paths[0]); i++) {
    if (path_is_or_below(target, protected_paths[i])) return true;
  }

  return false;
}

static bool read_mount_entry(char *line, struct mount_entry *entry) {
  unsigned int id, parent;
  char device[64], options[256];
  char root[PATH_MAX], target[PATH_MAX];
  char *separator = strstr(line, " - ");

  if (!separator) return false;

  entry->module_overlay =
      strstr(line, "/data/adb/modules") != NULL ||
      strstr(line, "/debug_ramdisk") != NULL;
  *separator = '\0';
  if (sscanf(line, "%u %u %63s %4095s %4095s %255s",
             &id, &parent, device, root, target, options) != 6)
    return false;

  if (sscanf(separator + 3, "%63s %4095s",
             entry->fs_type, entry->source) != 2)
    return false;

  if (strlen(root) >= sizeof(entry->root) ||
      strlen(target) >= sizeof(entry->target))
    return false;

  strcpy(entry->root, root);
  strcpy(entry->target, target);
  decode_mount_field(entry->root);
  decode_mount_field(entry->target);
  decode_mount_field(entry->source);
  return true;
}

/* 1 = candidate found, 0 = none, -1 = mountinfo is unsafe to act on. */
static int find_deepest_candidate(struct mount_entry *selected,
                                  bool *protected_resource) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp) {
    PLOGE("open /proc/self/mountinfo");
    return -1;
  }

  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  size_t deepest = 0;
  bool found = false;
  *protected_resource = false;

  while ((length = getline(&line, &capacity, fp)) != -1) {
    (void)length;
    struct mount_entry current = {0};
    if (!read_mount_entry(line, &current)) {
      LOGE("Malformed mountinfo entry; refusing direct mount revert");
      free(line);
      fclose(fp);
      return -1;
    }

    /* A generic overlay source may still expose its module lowerdir only
       through mount options, not through the source field. */
    if (strcmp(current.fs_type, "overlay") == 0 &&
        is_protected_resource_target(current.target)) {
      *protected_resource = true;
      continue;
    }

    if (!is_root_mount(&current)) continue;

    if (is_protected_resource_target(current.target)) {
      *protected_resource = true;
      continue;
    }

    size_t depth = strlen(current.target);
    if (!found || depth > deepest) {
      *selected = current;
      deepest = depth;
      found = true;
    }
  }

  free(line);
  if (ferror(fp)) {
    LOGE("Failed while reading /proc/self/mountinfo");
    fclose(fp);
    return -1;
  }
  fclose(fp);

  if (*protected_resource) return -1;
  return found ? 1 : 0;
}

bool revert_root_mounts(void) {
  struct mount_entry selected = {0};
  bool protected_resource = false;
  int state = find_deepest_candidate(&selected, &protected_resource);

  if (state == 0) {
    LOGD("No root/module mounts to revert");
    return true;
  }

  if (state < 0 || protected_resource) {
    LOGW("Protected or unreadable mount table; use cached clean namespace");
    return false;
  }

  /* Private copy prevents detach operations propagating to Zygote or siblings. */
  if (unshare(CLONE_NEWNS) == -1) {
    PLOGE("unshare mount namespace");
    return false;
  }

  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
    PLOGE("make mount propagation private");
    return false;
  }

  for (size_t count = 0; count < MAX_REVERT_MOUNTS; count++) {
    state = find_deepest_candidate(&selected, &protected_resource);
    if (state == 0) {
      LOGI("Root/module mounts detached from private process namespace");
      return true;
    }

    if (state < 0 || protected_resource) {
      LOGW("Encountered protected or unreadable mount during revert");
      return false;
    }

    if (umount2(selected.target, MNT_DETACH) == -1) {
      PLOGE("detach root/module mount");
      return false;
    }

    LOGD("Detached root/module mount at %s", selected.target);
  }

  LOGW("Mount revert exceeded safety limit (%u)", MAX_REVERT_MOUNTS);
  return false;
}
