#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#include "magisk.h"

#include "../utils.h"
#include "common.h"

#define SBIN_MAGISK LP_SELECT("/sbin/magisk32", "/sbin/magisk64")
#define BITLESS_SBIN_MAGISK "/sbin/magisk"
#define DEBUG_RAMDISK_MAGISK LP_SELECT("/debug_ramdisk/magisk32", "/debug_ramdisk/magisk64")
#define BITLESS_DEBUG_RAMDISK_MAGISK "/debug_ramdisk/magisk"

/* INFO: Longest path */
static char path_to_magisk[sizeof(DEBUG_RAMDISK_MAGISK)] = { 0 };

void magisk_get_existence(struct root_impl_state *state) {
  const char *magisk_files[] = {
    SBIN_MAGISK,
    BITLESS_SBIN_MAGISK,
    DEBUG_RAMDISK_MAGISK,
    BITLESS_DEBUG_RAMDISK_MAGISK
  };

  for (size_t i = 0; i < sizeof(magisk_files) / sizeof(magisk_files[0]); i++) {
    if (access(magisk_files[i], F_OK) != 0) continue;

    strcpy(path_to_magisk, magisk_files[i]);

    break;
  }

  if (path_to_magisk[0] == '\0') {
    state->state = Inexistent;

    return;
  }

  const char *argv[] = { "magisk", "-V", NULL };

  char magisk_version[32];
  if (!exec_command(magisk_version, sizeof(magisk_version), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    state->state = Abnormal;

    return;
  }

  if (atoi(magisk_version) >= MIN_MAGISK_VERSION) state->state = Supported;
  else state->state = TooOld;
}

bool magisk_uid_granted_root(uid_t uid) {
  char sqlite_cmd[256];
  snprintf(sqlite_cmd, sizeof(sqlite_cmd), "select 1 from policies where uid=%u and policy=2 limit 1", (unsigned int)uid);

  const char *const argv[] = { "magisk", "--sqlite", sqlite_cmd, NULL };

  char result[32];
  if (!exec_command(result, sizeof(result), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    return false;
  }

  return result[0] != '\0';
}

bool magisk_uid_should_umount(const char *const process) {
  /* Escape SQLite quoted-identifier delimiters before interpolation. */
  if (process == NULL) return false;
  size_t process_len = strnlen(process, PROCESS_NAME_MAX_LEN);
  if (process_len == 0 || process_len >= PROCESS_NAME_MAX_LEN) return false;
  char escaped_process[2 * PROCESS_NAME_MAX_LEN];
  size_t out = 0;
  for (size_t i = 0; i < process_len; ++i) {
    if (process[i] == '"') escaped_process[out++] = '"';
    escaped_process[out++] = process[i];
  }
  escaped_process[out] = '\0';

  char sqlite_cmd[96 + sizeof(escaped_process)];
  /* INFO: Find if process string starts with any data in "process" column. */
  int written = snprintf(sqlite_cmd, sizeof(sqlite_cmd),
      "SELECT 1 FROM denylist WHERE \"%s\" LIKE process || '%%' LIMIT 1", escaped_process);
  if (written < 0 || (size_t)written >= sizeof(sqlite_cmd)) return false;

  const char *const argv[] = { "magisk", "--sqlite", sqlite_cmd, NULL };

  char result[sizeof("1=1")];
  if (!exec_command(result, sizeof(result), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    return false;
  }

  return result[0] != '\0';
}

bool magisk_uid_is_manager(uid_t uid) {
  const char *const argv[] = { "magisk", "--sqlite", "select value from strings where key=\"requester\" limit 1", NULL };

  char output[128];
  if (!exec_command(output, sizeof(output), (const char *)path_to_magisk, argv)) {
    LOGE("Failed to execute magisk binary: %s", strerror(errno));

    return false;
  }

  char pkg[NAME_MAX + 1] = "com.topjohnwu.magisk";
  if (output[0] != '\0')
    snprintf(pkg, sizeof(pkg), "%s", output + strlen("value="));

  uid_t manager_uid = uid_from_pkg(pkg);
  if (!manager_uid) {
    LOGE("Failed to retrieve uid for %s", pkg);

    return false;
  }

  return manager_uid == APP_ID(uid);
}
