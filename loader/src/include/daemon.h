#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

enum rezygiskd_actions {
  ZygoteInjected,
  GetProcessFlags,
  GetInfo,
  ReadModules,
  RequestCompanionSocket,
  GetModuleDir,
  ZygoteRestart,
  UpdateMountNamespace,
  RemoveModule,
  ReadZnModules,
  RequestZnCompanionSocket,
  GetZnModuleFd
};

struct zygisk_modules {
  char **modules;
  size_t modules_count;
};

#define ZN_TARGET_NAME 1u
#define ZN_TARGET_PATH 2u

struct zn_module_info {
  char *module_id;
  char *target;
  char *library;
  uint8_t target_type;
  bool companion;
};

struct zn_module_list {
  struct zn_module_info *items;
  size_t count;
};

enum root_impl {
  ROOT_IMPL_NONE,
  ROOT_IMPL_APATCH,
  ROOT_IMPL_KERNELSU,
  ROOT_IMPL_MAGISK
};

struct rezygisk_info {
  struct zygisk_modules modules;
  enum root_impl root_impl;
  pid_t pid;
  bool running;
};

enum mount_namespace_state {
  Clean,
  Mounted
};

#define TMP_PATH "/data/adb/rezygisk"

static inline const char *rezygiskd_get_path(void) {
  return TMP_PATH;
}

bool rezygiskd_zygote_injected(void);
uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process);
void rezygiskd_get_info(struct rezygisk_info *info);
void free_rezygisk_info(struct rezygisk_info *info);
bool rezygiskd_read_modules(struct zygisk_modules *modules);
void free_modules(struct zygisk_modules *modules);
bool rezygiskd_read_zn_modules(struct zn_module_list *modules);
void rezygiskd_free_zn_modules(struct zn_module_list *modules);
int rezygiskd_connect_companion(size_t index);
int rezygiskd_connect_zn_companion(size_t index);
int rezygiskd_get_zn_module_fd(size_t index);
int rezygiskd_get_module_dir(size_t index);
void rezygiskd_zygote_restart(void);
bool rezygiskd_update_mns(enum mount_namespace_state nms_state, uid_t uid,
                          const char *process, char *buf, size_t buf_size);
bool rezygiskd_remove_module(size_t index);

#endif /* DAEMON_H */
