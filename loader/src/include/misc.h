#ifndef MISC_H
#define MISC_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __LP64__
  #define LP_SELECT(lp32, lp64) lp64
#else
  #define LP_SELECT(lp32, lp64) lp32
#endif

#define APP_ID(uid) uid % 100000

#define IS_ISOLATED_SERVICE(uid)      \
  ((APP_ID(uid)) >= 90000)

struct kernel_version {
  uint8_t major;
  unsigned int minor;
  unsigned int patch;
};

struct map_entry {
  uintptr_t start;
  uintptr_t end;
  int perms;
  bool is_private;
  uintptr_t offset;
  dev_t dev;
  ino_t inode;
  char *path;
};

struct maps_info {
  struct map_entry *maps;
  size_t length;
};

typedef bool (*maps_visitor)(const struct map_entry *map, void *userdata);

int parse_int(const char *str);

struct kernel_version parse_kversion();

struct maps_info *parse_maps(const char *pid);

bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata);

void free_maps(struct maps_info *maps);

#endif /* MISC_H */
