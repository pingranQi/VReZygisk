#include <stddef.h>
#include <string.h>

#include "misc.h"

/* Classify procfs map names without conflating memfd and pseudo entries. */
enum map_backing_kind classify_map_backing(const char *path) {
  if (path == NULL || path[0] == '\0') return MAP_BACKING_ANONYMOUS;
  if (path[0] == '[' || strncmp(path, "anon_inode:", 11) == 0)
    return MAP_BACKING_SPECIAL;
  if (strncmp(path, "/memfd:", 7) == 0 || strncmp(path, "memfd:", 6) == 0)
    return MAP_BACKING_MEMFD;

  static const char deleted_suffix[] = " (deleted)";
  size_t len = strlen(path);
  size_t suffix_len = sizeof(deleted_suffix) - 1;
  if (len >= suffix_len &&
      memcmp(path + len - suffix_len, deleted_suffix, suffix_len) == 0)
    return MAP_BACKING_DELETED_FILE;

  return MAP_BACKING_FILE;
}
