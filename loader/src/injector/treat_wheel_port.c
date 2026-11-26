/* ReZygisk Treat Wheel compatibility port: guarded, fail-open helpers. */
#include "treat_wheel_port.h"

#include <dirent.h>
#include <errno.h>
#include <link.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elf_util.h"
#include "logging.h"
#include "mountinfo.h"

#define TW_ENABLE_FRIDA_FILE "/data/adb/rezygisk/enable-frida-trace-cleanup"
#define TW_ENABLE_MNTENT_FILE "/data/adb/rezygisk/enable-mntent-buffer-scrub"
#define TW_ENABLE_RVU_FILE "/data/adb/rezygisk/enable-revanced-mount-umount"
#define TW_MODULES_DIR "/data/adb/modules"
#define TW_MNTENT_SCAN_LIMIT 1024U
#define TW_MAX_LINKER_OBJECTS 4096U

typedef void SoInfo;
typedef const char *(*get_realpath_fn)(void *);
typedef void (*soinfo_unload_fn)(SoInfo *);
typedef void (*linker_guard_fn)(void);

struct linker_path_context {
  char path[PATH_MAX];
};

static int find_linker_path(struct dl_phdr_info *info, size_t size, void *opaque) {
  (void)size;
  struct linker_path_context *ctx = (struct linker_path_context *)opaque;
  if (ctx == NULL || info == NULL || info->dlpi_name == NULL ||
      info->dlpi_name[0] == '\0') {
    return 0;
  }

  const char *base = strrchr(info->dlpi_name, '/');
  base = base ? base + 1 : info->dlpi_name;
  if (strncmp(base, "linker", 6) != 0) return 0;

  const int written = snprintf(ctx->path, sizeof(ctx->path), "%s", info->dlpi_name);
  return written > 0 && (size_t)written < sizeof(ctx->path) ? 1 : 0;
}

static bool is_frida_agent_path(const char *path) {
  if (path == NULL) return false;
  return strcmp(path, "/memfd:frida-agent-64.so") == 0 ||
         strcmp(path, "/memfd:frida-agent-32.so") == 0 ||
         strcmp(path, "memfd:frida-agent-64.so") == 0 ||
         strcmp(path, "memfd:frida-agent-32.so") == 0;
}

/*
 * P3: best-effort removal of known Frida memfd soinfo entries.
 * Private linker layout is not a stable Android ABI. Every required symbol
 * and discovered offset is checked; unsupported layouts are skipped.
 */
bool treat_wheel_hide_frida_traces(void) {
  if (access(TW_ENABLE_FRIDA_FILE, F_OK) != 0) {
    LOGD("TreatWheel P3 disabled; create %s to enable", TW_ENABLE_FRIDA_FILE);
    return true;
  }

  struct linker_path_context path_ctx = { 0 };
  dl_iterate_phdr(find_linker_path, &path_ctx);
  if (path_ctx.path[0] == '\0') {
    LOGW("TreatWheel P3: dynamic linker path not found; skipping");
    return true;
  }

  ElfImg *linker = ElfImg_create(path_ctx.path, NULL);
  if (linker == NULL) {
    LOGW("TreatWheel P3: unable to inspect linker %s; skipping", path_ctx.path);
    return true;
  }

  linker_guard_fn guard_enter = (linker_guard_fn)getSymbAddress(
      linker, "__dl__ZN18ProtectedDataGuardC2Ev");
  if (guard_enter == NULL) {
    guard_enter = (linker_guard_fn)getSymbAddress(
        linker, "__dl__ZN18ProtectedDataGuardC1Ev");
  }

  linker_guard_fn guard_leave = (linker_guard_fn)getSymbAddress(
      linker, "__dl__ZN18ProtectedDataGuardD2Ev");
  if (guard_leave == NULL) {
    guard_leave = (linker_guard_fn)getSymbAddress(
        linker, "__dl__ZN18ProtectedDataGuardD1Ev");
  }

  get_realpath_fn get_realpath = (get_realpath_fn)getSymbAddress(
      linker, "__dl__ZNK6soinfo12get_realpathEv");
  soinfo_unload_fn soinfo_unload = (soinfo_unload_fn)getSymbAddressByPrefix(
      linker, "__dl__ZL13soinfo_unloadP6soinfo");

  SoInfo *(*solist_get_head)(void) =
      (SoInfo *(*)(void))getSymbAddress(linker, "__dl__Z15solist_get_headv");
  SoInfo *(*solist_get_vdso)(void) =
      (SoInfo *(*)(void))getSymbAddress(linker, "__dl__Z15solist_get_vdsov");
  SoInfo *somain = (SoInfo *)getSymbValueByPrefix(linker, "__dl__ZL6somain");
  SoInfo *solinker = (SoInfo *)getSymbValueByPrefix(linker, "__dl__ZL8solinker");

  if (guard_enter == NULL || guard_leave == NULL || get_realpath == NULL ||
      soinfo_unload == NULL || solist_get_head == NULL || somain == NULL ||
      solinker == NULL) {
    LOGW("TreatWheel P3: linker symbols unavailable on %s; skipping",
         path_ctx.path);
    ElfImg_destroy(linker);
    return true;
  }

  SoInfo *head = solist_get_head();
  SoInfo *vdso = solist_get_vdso ? solist_get_vdso() : NULL;
  if (head == NULL) {
    LOGW("TreatWheel P3: linker soinfo list is empty; skipping");
    ElfImg_destroy(linker);
    return true;
  }

  const char *solinker_path = get_realpath(solinker);
  if (solinker_path == NULL) {
    LOGW("TreatWheel P3: linker realpath unavailable; skipping");
    ElfImg_destroy(linker);
    return true;
  }

  ptrdiff_t next_offset = -1;
  ptrdiff_t size_offset = -1;
  ptrdiff_t constructors_offset = -1;

  for (size_t i = 0; i < 1024U / sizeof(void *); i++) {
    const uintptr_t slot = (uintptr_t)head + i * sizeof(void *);
    SoInfo *possible_next = NULL;
    memcpy(&possible_next, (const void *)slot, sizeof(possible_next));

    if (next_offset < 0 &&
        (possible_next == somain || possible_next == solinker ||
         (vdso != NULL && possible_next == vdso))) {
      next_offset = (ptrdiff_t)(i * sizeof(void *));
    }

    size_t possible_size = 0;
    memcpy(&possible_size,
           (const void *)((uintptr_t)somain + i * sizeof(void *)),
           sizeof(possible_size));
    if (size_offset < 0 && possible_size > 0x100U &&
        possible_size < 0x100000U) {
      size_offset = (ptrdiff_t)(i * sizeof(void *));
    }

    if (constructors_offset < 0) {
      const uintptr_t candidate_address =
          (uintptr_t)solinker + i * sizeof(void *);
      struct link_map candidate_map;
      memcpy(&candidate_map, (const void *)candidate_address,
             sizeof(candidate_map));

      const size_t map_slots =
          (sizeof(struct link_map) + sizeof(void *) - 1U) / sizeof(void *);
      const uintptr_t bool_address =
          candidate_address + map_slots * sizeof(void *);
      bool constructors_called = false;
      memcpy(&constructors_called, (const void *)bool_address,
             sizeof(constructors_called));

      if (constructors_called && candidate_map.l_name == solinker_path) {
        constructors_offset = (ptrdiff_t)(bool_address - (uintptr_t)solinker);
      }
    }

    if (next_offset >= 0 && size_offset >= 0 && constructors_offset >= 0)
      break;
  }

  if (next_offset < 0 || size_offset < 0 || constructors_offset < 0) {
    LOGW("TreatWheel P3: linker layout not recognized on %s; skipping",
         path_ctx.path);
    ElfImg_destroy(linker);
    return true;
  }

  SoInfo *visited[TW_MAX_LINKER_OBJECTS];
  size_t visited_count = 0;
  bool found = false;

  for (SoInfo *so = head; so != NULL && visited_count < TW_MAX_LINKER_OBJECTS;) {
    bool cycle = false;
    for (size_t i = 0; i < visited_count; i++) {
      if (visited[i] == so) {
        cycle = true;
        break;
      }
    }
    if (cycle) {
      LOGW("TreatWheel P3: detected a cycle in linker soinfo list");
      break;
    }

    visited[visited_count++] = so;
    const char *realpath = get_realpath(so);
    if (is_frida_agent_path(realpath)) {
      LOGI("TreatWheel P3: found known Frida agent mapping; unlinking linker entry");

      guard_enter();
      size_t zero_size = 0;
      bool constructors_not_called = false;
      memcpy((void *)((uintptr_t)so + size_offset), &zero_size,
             sizeof(zero_size));
      memcpy((void *)((uintptr_t)so + constructors_offset),
             &constructors_not_called, sizeof(constructors_not_called));
      soinfo_unload(so);
      guard_leave();
      found = true;
      break;
    }

    SoInfo *next = NULL;
    memcpy(&next, (const void *)((uintptr_t)so + next_offset), sizeof(next));
    if (next == so) break;
    so = next;
  }

  if (visited_count == TW_MAX_LINKER_OBJECTS) {
    LOGW("TreatWheel P3: linker object traversal limit reached");
  }

  if (found) {
    size_t *load_counter = (size_t *)getSymbAddress(
        linker, "__dl__ZL21g_module_load_counter");
    size_t *unload_counter = (size_t *)getSymbAddress(
        linker, "__dl__ZL23g_module_unload_counter");
    if (load_counter != NULL && *load_counter > 0) (*load_counter)--;
    if (unload_counter != NULL && *unload_counter > 0) (*unload_counter)--;
    LOGI("TreatWheel P3: Frida linker entry removed");
  } else {
    LOGD("TreatWheel P3: no known Frida agent entry found");
  }

  ElfImg_destroy(linker);
  return true;
}

/*
 * P4: scrub the process-local Bionic getmntent line buffer.
 * This does not alter mount tables or the active mount namespace.
 */
bool treat_wheel_scrub_mntent_buffer(void) {
  if (access(TW_ENABLE_MNTENT_FILE, F_OK) != 0) {
    LOGD("TreatWheel P4 disabled; create %s to enable", TW_ENABLE_MNTENT_FILE);
    return true;
  }

  FILE *mounts = setmntent("/proc/self/mounts", "r");
  if (mounts == NULL) {
    LOGW("TreatWheel P4: unable to open /proc/self/mounts: %s",
         strerror(errno));
    return true;
  }

  char *line_buffer = NULL;
  struct mntent *entry = NULL;
  while ((entry = getmntent(mounts)) != NULL) {
    if (entry->mnt_fsname != NULL) line_buffer = entry->mnt_fsname;
  }

  if (line_buffer == NULL) {
    LOGW("TreatWheel P4: getmntent returned no line buffer");
    endmntent(mounts);
    return true;
  }

  const size_t length = strnlen(line_buffer, TW_MNTENT_SCAN_LIMIT);
  if (length == TW_MNTENT_SCAN_LIMIT) {
    LOGW("TreatWheel P4: mount line is not terminated within scan limit");
    endmntent(mounts);
    return true;
  }

  memset(line_buffer, 0, length + 1U);
  endmntent(mounts);
  LOGD("TreatWheel P4: cleared %zu bytes from the process-local mntent buffer",
       length + 1U);
  return true;
}

static bool module_allows_revanced_umount(const char *module_name) {
  char disabled_path[PATH_MAX];
  char config_path[PATH_MAX];

  int n = snprintf(disabled_path, sizeof(disabled_path),
                   TW_MODULES_DIR "/%s/disable", module_name);
  if (n < 0 || (size_t)n >= sizeof(disabled_path)) return false;
  if (access(disabled_path, F_OK) == 0) return false;

  n = snprintf(config_path, sizeof(config_path),
               TW_MODULES_DIR "/%s/tw_config", module_name);
  if (n < 0 || (size_t)n >= sizeof(config_path)) return false;

  FILE *config = fopen(config_path, "r");
  if (config == NULL) return false;

  bool revanced = false;
  bool allow_umount = false;
  char line[256];

  while (fgets(line, sizeof(line), config) != NULL) {
    size_t length = strlen(line);
    while (length > 0 &&
           (line[length - 1] == '\n' || line[length - 1] == '\r' ||
            line[length - 1] == ' ' || line[length - 1] == '\t')) {
      line[--length] = '\0';
    }

    if (strcmp(line, "module_type=revanced") == 0) {
      revanced = true;
    } else if (strcmp(line, "allow_umount=true") == 0) {
      allow_umount = true;
    }
  }

  fclose(config);
  return revanced && allow_umount;
}

static size_t count_revanced_umount_modules(void) {
  DIR *modules = opendir(TW_MODULES_DIR);
  if (modules == NULL) {
    LOGW("TreatWheel P5: cannot open %s: %s", TW_MODULES_DIR,
         strerror(errno));
    return 0;
  }

  size_t count = 0;
  struct dirent *entry;
  while ((entry = readdir(modules)) != NULL) {
    if (entry->d_name[0] == '.' &&
        (entry->d_name[1] == '\0' ||
         (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) {
      continue;
    }

    char module_path[PATH_MAX];
    struct stat st;
    int n = snprintf(module_path, sizeof(module_path),
                     TW_MODULES_DIR "/%s", entry->d_name);
    if (n < 0 || (size_t)n >= sizeof(module_path) ||
        stat(module_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
      continue;
    }

    if (module_allows_revanced_umount(entry->d_name)) count++;
  }

  closedir(modules);
  return count;
}

static bool is_re_vanced_app_mount(const char *mount_point) {
  static const char prefix[] = "/data/app/~~";
  if (mount_point == NULL ||
      strncmp(mount_point, prefix, sizeof(prefix) - 1U) != 0) {
    return false;
  }

  const char *package_start = strchr(mount_point + sizeof(prefix) - 1U, '/');
  if (package_start == NULL || package_start[1] == '\0') return false;

  package_start++;
  if (strchr(package_start, '/') != NULL) return false;

  const char *suffix = strchr(package_start, '-');
  return suffix != NULL && suffix != package_start && suffix[1] != '\0';
}

static bool mount_belongs_to_process(const char *mount_point,
                                     const char *process_name) {
  if (!is_re_vanced_app_mount(mount_point) ||
      process_name == NULL || process_name[0] == '\0') {
    return false;
  }

  const char *package_start = strrchr(mount_point, '/') + 1;
  const char *suffix = strchr(package_start, '-');
  if (suffix == NULL) return false;

  const char *process_end = strchr(process_name, ':');
  const size_t process_length = process_end
      ? (size_t)(process_end - process_name)
      : strlen(process_name);
  const size_t package_length = (size_t)(suffix - package_start);

  return process_length == package_length &&
         memcmp(package_start, process_name, package_length) == 0;
}

static int compare_mount_paths_desc(const void *left, const void *right) {
  const char *const *a = (const char *const *)left;
  const char *const *b = (const char *const *)right;
  const size_t a_len = strlen(*a);
  const size_t b_len = strlen(*b);
  if (a_len < b_len) return 1;
  if (a_len > b_len) return -1;
  return strcmp(*a, *b);
}

/*
 * P5: detach opted-in ReVanced app mounts from this process's current mount
 * namespace, preserving the mount belonging to the current app package.
 * No cross-process setns() and no daemon pointer protocol are used.
 */
bool treat_wheel_umount_revanced_mounts(const char *process_name) {
  if (access(TW_ENABLE_RVU_FILE, F_OK) != 0) {
    LOGD("TreatWheel P5 disabled; create %s to enable", TW_ENABLE_RVU_FILE);
    return true;
  }

  if (getuid() != 0) {
    LOGW("TreatWheel P5: specialize hook is no longer privileged; skipping");
    return true;
  }

  const size_t opted_in_modules = count_revanced_umount_modules();
  if (opted_in_modules == 0) {
    LOGD("TreatWheel P5: no enabled ReVanced module opted into unmounting");
    return true;
  }

  struct mountinfo_table *table = NULL;
  size_t error_line = 0;
  if (mountinfo_parse_file("/proc/self/mountinfo", &table, &error_line) != 0) {
    LOGW("TreatWheel P5: mountinfo parse failed at line %zu: %s",
         error_line, strerror(errno));
    return true;
  }

  char **paths = NULL;
  size_t path_count = 0;
  for (size_t i = 0; i < table->count; i++) {
    const char *mount_point = table->entries[i].mount_point;
    if (!is_re_vanced_app_mount(mount_point)) continue;

    char **new_paths = realloc(paths, (path_count + 1U) * sizeof(*paths));
    if (new_paths == NULL) {
      LOGW("TreatWheel P5: cannot allocate mount path list");
      for (size_t j = 0; j < path_count; j++) free(paths[j]);
      free(paths);
      mountinfo_free(table);
      return true;
    }
    paths = new_paths;
    paths[path_count] = strdup(mount_point);
    if (paths[path_count] == NULL) {
      LOGW("TreatWheel P5: cannot duplicate mount path");
      for (size_t j = 0; j < path_count; j++) free(paths[j]);
      free(paths);
      mountinfo_free(table);
      return true;
    }
    path_count++;
  }

  mountinfo_free(table);

  /*
   * The upstream module uses this count as its readiness check. Keep the
   * same conservative gate: do not unmount a partial/ambiguous mount set.
   */
  if (path_count != opted_in_modules) {
    LOGW("TreatWheel P5: expected %zu ReVanced mount(s), found %zu; skipping",
         opted_in_modules, path_count);
    for (size_t i = 0; i < path_count; i++) free(paths[i]);
    free(paths);
    return true;
  }

  qsort(paths, path_count, sizeof(*paths), compare_mount_paths_desc);

  size_t unmounted = 0;
  for (size_t i = 0; i < path_count; i++) {
    if (mount_belongs_to_process(paths[i], process_name)) {
      LOGD("TreatWheel P5: preserving current app mount %s", paths[i]);
      free(paths[i]);
      continue;
    }

    if (umount2(paths[i], MNT_DETACH) == 0) {
      LOGI("TreatWheel P5: detached %s from current mount namespace",
           paths[i]);
      unmounted++;
    } else if (errno == EINVAL || errno == ENOENT) {
      LOGD("TreatWheel P5: mount already absent: %s", paths[i]);
    } else {
      LOGW("TreatWheel P5: unable to detach %s: %s",
           paths[i], strerror(errno));
    }

    free(paths[i]);
  }

  free(paths);
  LOGI("TreatWheel P5: detached %zu/%zu ReVanced app mount(s)",
       unmounted, path_count);
  return true;
}
