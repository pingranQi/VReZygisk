#ifndef ZN_MODULES_H
#define ZN_MODULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define ZN_TARGET_NAME 1u
#define ZN_TARGET_PATH 2u

struct zn_module_entry {
  char *module_id;
  char *target;
  char *library;
  uint8_t target_type;
  uint8_t companion;
  int companion_fd; /* daemon-owned stream to the ZN companion process */
  int companion_broker_fd; /* inherited SOCK_DGRAM broker from hyos_spawner */
  pthread_t companion_broker_thread;
  bool companion_broker_running;
};

struct zn_module_list {
  struct zn_module_entry *items;
  size_t count;
};

bool zn_modules_load(const char *modules_root, struct zn_module_list *out);
void zn_modules_free(struct zn_module_list *list);

#endif
