#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
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
  unsigned int parent;
  unsigned int shared;
  unsigned int master;
  unsigned int propagate_from;
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

  /* Never detach the namespace root or the system root mount itself. */
  if (strcmp(target, "/") == 0 || strcmp(target, "/system") == 0 ||
      strcmp(target, "/system_ext") == 0 || strcmp(target, "/vendor") == 0)
    return true;

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
  int optional_start = 0;

  if (!separator) return false;

  entry->module_overlay =
      strstr(line, "/data/adb/modules") != NULL ||
      strstr(line, "/debug_ramdisk") != NULL;
  *separator = '\0';
  if (sscanf(line, "%u %u %63s %4095s %4095s %255s %n",
             &id, &parent, device, root, target, options,
             &optional_start) != 6)
    return false;

  entry->id = id;
  entry->parent = parent;
  entry->shared = 0;
  entry->master = 0;
  entry->propagate_from = 0;

  /* Parse mountinfo optional fields. These IDs describe propagation peer
     groups and slave relationships; they must disappear after MS_PRIVATE. */
  char *saveptr = NULL;
  for (char *token = strtok_r(line + optional_start, " \t\r\n", &saveptr);
       token != NULL;
       token = strtok_r(NULL, " \t\r\n", &saveptr)) {
    unsigned int value;
    if (sscanf(token, "shared:%u", &value) == 1)
      entry->shared = value;
    else if (sscanf(token, "master:%u", &value) == 1)
      entry->master = value;
    else if (sscanf(token, "propagate_from:%u", &value) == 1)
      entry->propagate_from = value;
  }

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
    if (length < 0) {
      /* A concurrently closed FD is harmless; any other unresolved FD is
         ambiguous and must not be ignored during a destructive detach. */
      if (errno != ENOENT && errno != EBADF) {
        unsigned int unresolved_mount_id = 0;
        if (!read_fd_mount_id(fd, &unresolved_mount_id) ||
            unresolved_mount_id == mount->id) {
          LOGW("Cannot resolve FD %d while checking mount %u",
               fd, mount->id);
          safe = false;
        }
      }
      continue;
    }
    if ((size_t)length >= sizeof(target) - 1) {
      LOGW("FD %d target was truncated while checking mount %u",
           fd, mount->id);
      safe = false;
      continue;
    }
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
 * Return 1 when mount[index] is below ancestor_id in the mount parent graph,
 * 0 when it is outside that subtree, and -1 when the graph contains a cycle.
 * A bounded walk prevents malformed parent chains from becoming unbounded.
 */
static int mount_descends_from(const struct mount_entry *mounts, size_t count,
                               size_t index, unsigned int ancestor_id) {
  unsigned int parent = mounts[index].parent;

  for (size_t depth = 0; depth < count; depth++) {
    if (parent == ancestor_id) return 1;

    size_t parent_index = count;
    for (size_t i = 0; i < count; i++) {
      if (mounts[i].id == parent) {
        parent_index = i;
        break;
      }
    }

    /* Parent may be outside this namespace's visible mount table. */
    if (parent_index == count) return 0;
    parent = mounts[parent_index].parent;
  }

  return -1;
}

/*
 * A detach at a mountpoint also detaches its mounted descendants. Only allow
 * that when every descendant is itself a recognized root/module mount.
 * Stacked mounts at the same target are ambiguous for umount2(path), so they
 * deliberately force the namespace fallback.
 */
static bool validate_mount_subtree(const struct mount_entry *selected) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp) {
    PLOGE("open mountinfo for subtree validation");
    return false;
  }

  struct mount_entry *mounts = NULL;
  size_t count = 0;
  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  bool safe = true;
  size_t selected_index = SIZE_MAX;

  while ((length = getline(&line, &capacity, fp)) != -1) {
    (void)length;
    struct mount_entry current = {0};
    if (!read_mount_entry(line, &current)) {
      LOGE("Malformed mountinfo while validating mount subtree");
      safe = false;
      break;
    }

    for (size_t i = 0; i < count; i++) {
      if (mounts[i].id == current.id) {
        LOGE("Duplicate mount ID %u; refusing detach", current.id);
        safe = false;
        break;
      }
    }
    if (!safe) break;

    struct mount_entry *grown =
        realloc(mounts, (count + 1) * sizeof(*mounts));
    if (!grown) {
      LOGE("Out of memory validating mount subtree");
      safe = false;
      break;
    }
    mounts = grown;
    mounts[count] = current;

    if (current.id == selected->id) {
      if (strcmp(current.target, selected->target) != 0) {
        LOGE("Mount ID %u changed target during validation", current.id);
        safe = false;
        break;
      }
      selected_index = count;
    }
    count++;
  }

  if (ferror(fp)) {
    LOGE("Failed reading mountinfo during subtree validation");
    safe = false;
  }
  free(line);
  fclose(fp);

  if (!safe || selected_index == SIZE_MAX) {
    if (selected_index == SIZE_MAX)
      LOGW("Candidate mount ID %u disappeared before detach", selected->id);
    free(mounts);
    return false;
  }

  for (size_t i = 0; i < count && safe; i++) {
    if (i == selected_index) continue;

    if (strcmp(mounts[i].target, selected->target) == 0) {
      LOGW("Stacked mounts share target %s; refusing path-based detach",
           selected->target);
      safe = false;
      break;
    }

    int descendant = mount_descends_from(mounts, count, i, selected->id);
    if (descendant < 0) {
      LOGW("Mount parent graph is cyclic or malformed near mount ID %u",
           mounts[i].id);
      safe = false;
      break;
    }

    bool target_is_nested =
        path_is_or_below(mounts[i].target, selected->target);
    if ((descendant == 1 && !target_is_nested) ||
        (descendant == 0 && target_is_nested)) {
      LOGW("Mount path/parent chain disagreement: candidate=%s child=%s parent_id=%u",
           selected->target, mounts[i].target, mounts[i].parent);
      safe = false;
      break;
    }
    if (descendant == 0) continue;

    if (is_protected_resource_target(mounts[i].target) ||
        !is_root_mount(&mounts[i])) {
      LOGW("Candidate %s has non-root/protected descendant %s (id=%u)",
           selected->target, mounts[i].target, mounts[i].id);
      safe = false;
      break;
    }
  }

  /* Check every mount in the subtree for open descriptors, not just its root. */
  for (size_t i = 0; i < count && safe; i++) {
    bool in_subtree = (i == selected_index);
    if (!in_subtree) {
      int descendant = mount_descends_from(mounts, count, i, selected->id);
      in_subtree = descendant == 1;
    }

    if (in_subtree && !inspect_mount_fds(&mounts[i])) {
      LOGW("Open or unresolved FD pins mount %u at %s",
           mounts[i].id, mounts[i].target);
      safe = false;
    }
  }

  free(mounts);
  return safe;
}

/*
 * Verify the recursive MS_PRIVATE transition actually removed all shared and
 * slave peer-group metadata. If any propagation relationship remains, do not
 * detach anything: an unmount could otherwise affect a peer or master tree.
 */
static bool validate_private_propagation(void) {
  FILE *fp = fopen("/proc/self/mountinfo", "r");
  if (!fp) {
    PLOGE("open mountinfo for propagation validation");
    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  bool private_tree = true;

  while ((length = getline(&line, &capacity, fp)) != -1) {
    (void)length;
    struct mount_entry current = {0};
    if (!read_mount_entry(line, &current)) {
      LOGE("Malformed mountinfo during propagation validation");
      private_tree = false;
      break;
    }

    if (current.shared || current.master || current.propagate_from) {
      LOGW("Mount propagation remains: id=%u target=%s shared=%u master=%u propagate_from=%u",
           current.id, current.target, current.shared, current.master,
           current.propagate_from);
      private_tree = false;
      break;
    }
  }

  if (ferror(fp)) {
    LOGE("Failed reading mountinfo during propagation validation");
    private_tree = false;
  }
  free(line);
  fclose(fp);
  return private_tree;
}

static bool restore_original_mount_namespace(int original_ns_fd) {
  if (setns(original_ns_fd, CLONE_NEWNS) == -1) {
    PLOGE("restore original mount namespace after failed revert");
    return false;
  }

  LOGW("Restored original mount namespace after incomplete revert");
  return true;
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
  bool saw_mount = false;
  *protected_resource = false;

  while ((length = getline(&line, &capacity, fp)) != -1) {
    saw_mount = true;
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
  if (ferror(fp) || !saw_mount) {
    LOGE("Failed to read a complete /proc/self/mountinfo table");
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

  /*
   * Keep a handle to the caller's original namespace. Any failure after
   * unshare() must roll back to this namespace before the clean-namespace
   * fallback runs; never leave the caller in a partially detached tree.
   */
  int original_ns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (original_ns_fd == -1) {
    PLOGE("open original mount namespace");
    return false;
  }

  if (unshare(CLONE_NEWNS) == -1) {
    PLOGE("unshare mount namespace");
    close(original_ns_fd);
    return false;
  }

  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
    PLOGE("make mount propagation private");
    goto rollback;
  }

  if (!validate_private_propagation()) {
    LOGW("Mount namespace still contains shared/slave peer groups");
    goto rollback;
  }

  for (size_t count = 0; count < MAX_REVERT_MOUNTS; count++) {
    state = find_deepest_candidate(&selected, &protected_resource);
    if (state == 0) {
      LOGI("Root/module mounts detached from private process namespace");
      refresh_mountinfo_fds(false);
      close(original_ns_fd);
      return true;
    }

    if (state < 0 || protected_resource) {
      LOGW("Encountered protected or unreadable mount during revert");
      goto rollback;
    }

    /*
     * Validate the complete mount-parent subtree and all FDs pinned to it.
     * A path-only MNT_DETACH is unsafe when a non-root child mount is nested
     * below the candidate or when stacked mount IDs make the target ambiguous.
     */
    if (!validate_mount_subtree(&selected)) {
      LOGW("Mount chain or FD topology is unsafe; use clean namespace fallback");
      goto rollback;
    }

    if (!validate_private_propagation()) {
      LOGW("Peer-group metadata reappeared during mount revert");
      goto rollback;
    }

    if (umount2(selected.target, MNT_DETACH) == -1) {
      PLOGE("detach root/module mount");
      goto rollback;
    }

    LOGD("Detached root/module mount id=%u at %s",
         selected.id, selected.target);
  }

  LOGW("Mount revert exceeded safety limit (%u)", (unsigned int)MAX_REVERT_MOUNTS);

rollback:
  (void)restore_original_mount_namespace(original_ns_fd);
  close(original_ns_fd);
  return false;
}
