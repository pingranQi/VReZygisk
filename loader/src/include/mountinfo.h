/* /data/adb/modules/rezygisk/loader/src/include/mountinfo.h */
#ifndef MOUNTINFO_H
#define MOUNTINFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct mountinfo_entry {
  uint32_t id;
  uint32_t parent_id;
  dev_t device;
  char *root;
  char *mount_point;
  char *mount_options;
  char **optional_fields;
  size_t optional_count;
  uint32_t shared_id;
  uint32_t master_id;
  uint32_t propagate_from_id;
  bool has_shared_id;
  bool has_master_id;
  bool has_propagate_from_id;
  bool unbindable;
  char *filesystem_type;
  char *mount_source;
  char *super_options;
};

struct mountinfo_table {
  struct mountinfo_entry *entries;
  size_t count;
};

/*
 * Parse Linux /proc/<pid>/mountinfo.
 * Returns 0 on success, -1 on error and sets errno.
 * On failure, *out_table remains NULL. error_line is optional and is
 * populated for malformed input or I/O failure.
 */
int mountinfo_parse_file(const char *path,
                         struct mountinfo_table **out_table,
                         size_t *error_line);

void mountinfo_free(struct mountinfo_table *table);

#endif /* MOUNTINFO_H */
