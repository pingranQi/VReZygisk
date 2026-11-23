#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "mount_revert.h"
#include "logging.h"

#define MAX_REVERT_MOUNTS 128

struct mount_entry {
  unsigned int id;
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

  entry->id = id;

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

 
static bool is_mountinfo_fd_path(const char *path) {
  if (strncmp(path, "/proc/", 6) != 0) return false;
  size_t len = strlen(path);
  return (len >= 10 && strcmp(path + len - 10, "/mountinfo") == 0) ||
         (len >= 7 && strcmp(path + len - 7, "/mounts") == 0);
}

static bool is_root_artifact_fd_path(const char *path) {
  return path_is_or_below(path, "/data/adb") ||
         path_is_or_below(path, "/debug_ramdisk") ||
         path_is_or_below(path, "/sbin/.magisk") ||
         strstr(path, "/data/adb/modules/") != NULL;
}

static bool read_fd_mount_id(int fd, unsigned int *mount_id) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
  FILE *fp = fopen(path, "r");
  if (!fp) return false;

  bool found = false;
  while (fgets(line, sizeof(line), fp)) {
    unsigned int value;
    if (strncmp(line, "mnt_id:", 7) == 0 &&
        sscanf(line + 7, "%u", &value) == 1) {
      *mount_id = value;
      found = true;
      break;
    }
  }

  fclose(fp);
  return found;
}

/*
 * Examine descriptors against the exact mount ID, not merely their pathname.
 * Close only descriptors whose resolved path unambiguously names root storage.
 * An unknown descriptor pinned to the candidate mount forces namespace fallback.
 */
static bool inspect_mount_fds(const struct mount_entry *mount) {
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("open /proc/self/fd for mount FD inspection");
    return false;
  }

  int dirfd_value = dirfd(dir);
  struct dirent *entry;
  bool safe = true;

  while ((entry = readdir(dir))) {
    char *end = NULL;
    long value = strtol(entry->d_name, &end, 10);
    if (!entry->d_name[0] || !end || *end || value < 0 ||
        value > INT_MAX || value == dirfd_value)
      continue;

    int fd = (int)value;
    char target[PATH_MAX];
    ssize_t length = readlinkat(dirfd_value, entry->d_name,
                                target, sizeof(target) - 1);
    if (length < 0) continue;
    target[length] = 0;

    /* readlink(2) appends this marker for an unlinked but still-open file. */
    char *deleted = strstr(target, " (deleted)");
    if (deleted) *deleted = 0;

    if (is_root_artifact_fd_path(target)) {
      if (close(fd) == -1) {
        PLOGE("close root artifact FD");
        safe = false;
      } else {
        LOGW("Closed root artifact FD %d -> %s", fd, target);
      }
      continue;
    }

    unsigned int fd_mount_id = 0;
    if (!read_fd_mount_id(fd, &fd_mount_id)) {
      /* If fdinfo is unavailable, a pathname under the candidate mount is
         enough to classify the descriptor as an unresolved reference. */
      if (path_is_or_below(target, mount->target)) {
        LOGW("Cannot read mount ID for FD %d under candidate mount %s",
             fd, mount->target);
        safe = false;
      }
      continue;
    }
    if (fd_mount_id != mount->id) continue;

    LOGW("FD %d (%s) pins candidate mount id %u at %s",
         fd, target, mount->id, mount->target);
    safe = false;
  }

  closedir(dir);
  return safe;
}

/*
 * Bionic does not maintain a global libc mountinfo cache. The stale state of
 * concern is an inherited open procfs descriptor. Close those descriptors and
 * force a fresh open/read after mount namespace changes.
 */
void refresh_mountinfo_fds(bool webview_zygote) {
  DIR *dir = opendir("/proc/self/fd");
  if (dir) {
    int dirfd_value = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir))) {
      char *end = NULL;
      long value = strtol(entry->d_name, &end, 10);
      if (!entry->d_name[0] || !end || *end || value < 0 ||
          value > INT_MAX || value == dirfd_value)
        continue;

      char target[PATH_MAX];
      ssize_t length = readlinkat(dirfd_value, entry->d_name,
                                  target, sizeof(target) - 1);
      if (length < 0) continue;
      target[length] = 0;
      if (is_mountinfo_fd_path(target)) {
        LOGD("Closing inherited proc mount descriptor %d -> %s",
             (int)value, target);
        close((int)value);
      }
    }
    closedir(dir);
  } else {
    PLOGE("open /proc/self/fd while refreshing mountinfo");
  }

  int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    char buffer[4096];
    (void)read(fd, buffer, sizeof(buffer));
    close(fd);
  } else {
    PLOGE("reopen /proc/self/mountinfo after namespace change");
  }

  if (webview_zygote) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
      PLOGE("open WebView Zygote maps");
      return;
    }

    char line[PATH_MAX + 256];
    while (fgets(line, sizeof(line), maps)) {
      if (strstr(line, "/data/adb/") ||
          strstr(line, "/debug_ramdisk/") ||
          strstr(line, "/sbin/.magisk/")) {
        /*
         * Do not munmap inherited mappings here: ART, linker and WebView may
         * still hold relocations/function pointers into them. Report the
         * mapping for explicit review instead of risking a Zygote crash.
         */
        LOGW("WebView Zygote retains root-backed mapping: %s", line);
      }
    }
    fclose(maps);
  }
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
      refresh_mountinfo_fds(false);
      return true;
    }

    if (state < 0 || protected_resource) {
      LOGW("Encountered protected or unreadable mount during revert");
      return false;
    }

    if (!inspect_mount_fds(&selected)) {
      LOGW("Candidate mount has unknown or unclosable FD references; use clean namespace fallback");
      return false;
    }

    if (umount2(selected.target, MNT_DETACH) == -1) {
      PLOGE("detach root/module mount");
      return false;
    }

    LOGD("Detached root/module mount at %s", selected.target);
  }

  LOGW("Mount revert exceeded safety limit (%u)", (unsigned int)MAX_REVERT_MOUNTS);
  return false;
}
