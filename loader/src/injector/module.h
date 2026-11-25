#ifndef MODULE_H
#define MODULE_H

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

#include <sys/types.h>

#include <jni.h>

#include <csoloader.h>

#include "logging.h"

#define REZYGISK_API_VERSION 7

enum rezygiskd_flags : uint32_t {
  PROCESS_GRANTED_ROOT = (1u << 0),
  PROCESS_ON_DENYLIST = (1u << 1),

  PROCESS_IS_MANAGER = (1u << 27),
  PROCESS_ROOT_IS_APATCH = (1u << 28),
  PROCESS_ROOT_IS_KSU = (1u << 29),
  PROCESS_ROOT_IS_MAGISK = (1u << 30),
  PROCESS_IS_FIRST_STARTED = (1u << 31),

  PRIVATE_MASK = PROCESS_IS_FIRST_STARTED
};

struct app_specialize_args_v1 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jint *mount_external;
  jstring *se_info;
  jstring *nice_name;
  jstring *instruction_set;
  jstring *app_data_dir;

  jboolean *is_child_zygote;
  jboolean *is_top_app;
  jobjectArray *pkg_data_info_list;
  jobjectArray *whitelisted_data_info_list;
  jboolean *mount_data_dirs;
  jboolean *mount_storage_dirs;
};

struct app_specialize_args_v4 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jobjectArray *rlimits;
  jint *mount_external;
  jstring *se_info;
  jstring *nice_name;
  jstring *instruction_set;
  jstring *app_data_dir;

  jintArray *fds_to_ignore;
  jboolean *is_child_zygote;
  jboolean *is_top_app;
  jobjectArray *pkg_data_info_list;
  jobjectArray *whitelisted_data_info_list;
  jboolean *mount_data_dirs;
  jboolean *mount_storage_dirs;
};

struct app_specialize_args_v5 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jobjectArray *rlimits;
  jint *mount_external;
  jstring *se_info;
  jstring *nice_name;
  jstring *instruction_set;
  jstring *app_data_dir;

  jintArray *fds_to_ignore;
  jboolean *is_child_zygote;
  jboolean *is_top_app;
  jobjectArray *pkg_data_info_list;
  jobjectArray *whitelisted_data_info_list;
  jboolean *mount_data_dirs;
  jboolean *mount_storage_dirs;

  jboolean *mount_sysprop_overrides;
};

struct server_specialize_args_v1 {
  jint *uid;
  jint *gid;
  jintArray *gids;
  jint *runtime_flags;
  jlong *permitted_capabilities;
  jlong *effective_capabilities;
};

enum rezygisk_options {
  /* INFO: Force ReZygisk to umount the root related mounts on this process. This option
             will only take effect if set in pre...Specialize, as ReZygisk umounts at
             that point.

           ReZygisk Umount System will not umount all root related mounts, read ReZygiskd
             umount_root function in utils.c file to understand how it selects the ones
             to umount.
  */
  FORCE_DENYLIST_UNMOUNT = 0,

  /* INFO: Once set, ReZygisk unloads the module after post...Specialize.
             CSOLoader-backed images use csoloader_unload(); system-linker-backed
             images use dlclose(). The handle is never passed across backends.
             Do not use this option if hooks or other process references can still
             execute code from the module. */
  DLCLOSE_MODULE_LIBRARY = 1
};

struct rezygisk_abi {
  long api_version;
  void *impl;

  void (*pre_app_specialize)(void *, void *);
  void (*post_app_specialize)(void *, const void *);
  void (*pre_server_specialize)(void *, void *);
  void (*post_server_specialize)(void *, const void *);
};

struct rezygisk_api {
  void *impl;
  bool (*register_module)(struct rezygisk_api *, struct rezygisk_abi const *);

  void (*hook_jni_native_methods)(JNIEnv *, const char *, JNINativeMethod *, int);
  union {
    void (*plt_hook_register)(const char *, const char *, void *, void **);    /* INFO: v3 and below */
    void (*plt_hook_register_v4)(dev_t, ino_t, const char *, void *, void **); /* INFO: v4 */
  };
  union {
    void (*plt_hook_exclude)(const char *, const char *); /* INFO: v3 and below */
    void (*exempt_fd)(int);                               /* INFO: v4 */
  };

  bool (*plt_hook_commit)();
  int (*connect_companion)(void *);
  void (*set_option)(void *, enum rezygisk_options opt);
  int (*get_module_dir)(void *);
  uint32_t (*get_flags)();

  /* API v6: tracked module-owned worker creation. */
  int (*pthread_create)(struct rezygisk_api *, pthread_t *,
                        const pthread_attr_t *, void *(*)(void *), void *);

  /* API v7: leases for work submitted to arbitrary thread pools/runtimes.
   * Acquire before publishing/scheduling work; release exactly once when the
   * task can no longer execute module code. The lease may be released by a
   * different thread from the one that acquired it. */
  void *(*acquire_execution_lease)(struct rezygisk_api *);
  /* Run the leased module entry on this host-side trampoline. The lease is
   * consumed after entry returns, pthread_exit() or cancellation. */
  void *(*run_with_execution_lease)(struct rezygisk_api *, void *lease,
                                    void *(*entry)(void *), void *arg);
  /* Cancel a task that will never run. If called from module code, the caller
   * must itself still hold another execution lease until it returns. */
  void (*cancel_execution_lease)(struct rezygisk_api *, void *lease);
};

enum module_loader_backend {
  MODULE_LOADER_NONE = 0,
  MODULE_LOADER_CSO,
  MODULE_LOADER_SYSTEM
};

enum module_lifecycle_state {
  MODULE_STATE_NEW = 0,
  MODULE_STATE_LOADING,
  MODULE_STATE_IMAGE_LOADED,
  MODULE_STATE_ENTRY_RUNNING,
  MODULE_STATE_REGISTERED,
  MODULE_STATE_ACTIVE,
  MODULE_STATE_CLOSING,
  MODULE_STATE_RETAINED,
  MODULE_STATE_UNLOADED,
  MODULE_STATE_FAILED
};

struct rezygisk_module {
  struct rezygisk_abi abi;
  struct rezygisk_api api;

  /* Exactly one loader owns the image; never pass a system handle to CSOLoader. */
  struct csoloader lib;
  void *system_handle;
  enum module_loader_backend loader_backend;

  dev_t dev;
  ino_t ino;
  void (*zygisk_module_entry)(void *, void *);

  bool unload;
  enum module_lifecycle_state lifecycle_state;

  /* Host-side execution lease: unload waits until all module callbacks return. */
  pthread_mutex_t call_mutex;
  pthread_cond_t call_cond;
  size_t active_calls;
  bool call_closing;
  bool call_sync_initialized;
};

static inline bool rz_module_sync_init(struct rezygisk_module *m) {
  if (!m) return false;
  int error = pthread_mutex_init(&m->call_mutex, NULL);
  if (error != 0) return false;
  error = pthread_cond_init(&m->call_cond, NULL);
  if (error != 0) {
    pthread_mutex_destroy(&m->call_mutex);
    return false;
  }
  m->active_calls = 0;
  m->call_closing = false;
  m->lifecycle_state = MODULE_STATE_NEW;
  m->call_sync_initialized = true;
  return true;
}

static inline bool rz_module_call_enter(struct rezygisk_module *m) {
  if (!m || !m->call_sync_initialized) return false;
  if (pthread_mutex_lock(&m->call_mutex) != 0) return false;
  bool allowed = !m->call_closing &&
      m->lifecycle_state != MODULE_STATE_UNLOADED &&
      m->lifecycle_state != MODULE_STATE_FAILED;
  if (allowed) m->active_calls++;
  pthread_mutex_unlock(&m->call_mutex);
  return allowed;
}

static inline void rz_module_call_leave(struct rezygisk_module *m) {
  if (!m || !m->call_sync_initialized) return;
  pthread_mutex_lock(&m->call_mutex);
  if (m->active_calls > 0) m->active_calls--;
  if (m->call_closing && m->active_calls == 0)
    pthread_cond_broadcast(&m->call_cond);
  pthread_mutex_unlock(&m->call_mutex);
}

/* VREZYGISK_TRACKED_MODULE_THREADS
 * Modules that create persistent workers must use this wrapper. The lease is
 * acquired before pthread_create and released by a cleanup handler, including
 * when the worker calls pthread_exit or is cancelled.
 */
struct rz_module_thread_start {
  struct rezygisk_module *module;
  void *(*entry)(void *);
  void *arg;
};

static inline void rz_module_thread_release(void *opaque) {
  struct rz_module_thread_start *start =
      (struct rz_module_thread_start *)opaque;
  if (!start) return;
  rz_module_call_leave(start->module);
  free(start);
}

static inline void *rz_module_thread_trampoline(void *opaque) {
  struct rz_module_thread_start *start =
      (struct rz_module_thread_start *)opaque;
  void *(*entry)(void *) = start->entry;
  void *arg = start->arg;

  void *result = NULL;
  pthread_cleanup_push(rz_module_thread_release, start);
  result = entry(arg);
  pthread_cleanup_pop(1);
  return result;
}

/*
 * Create a module-owned worker with an execution lease. Unload closes the
 * lease gate and waits for all workers created through this API to finish.
 * Direct pthread_create/clone/syscall use is not intercepted.
 */
static inline int rz_module_pthread_create(
    struct rezygisk_module *m, pthread_t *thread,
    const pthread_attr_t *attr, void *(*entry)(void *), void *arg) {
  if (!m || !thread || !entry || !rz_module_call_enter(m)) return EBUSY;

  struct rz_module_thread_start *start =
      (struct rz_module_thread_start *)calloc(1, sizeof(*start));
  if (!start) {
    rz_module_call_leave(m);
    return ENOMEM;
  }

  start->module = m;
  start->entry = entry;
  start->arg = arg;

  int error = pthread_create(thread, attr, rz_module_thread_trampoline, start);
  if (error != 0) {
    free(start);
    rz_module_call_leave(m);
  }
  return error;
}
/* VREZYGISK_TRACKED_MODULE_THREADS */

static inline bool rz_module_sync_close_and_wait(struct rezygisk_module *m) {
  if (!m || !m->call_sync_initialized) return false;
  if (pthread_mutex_lock(&m->call_mutex) != 0) return false;
  m->call_closing = true;
  m->lifecycle_state = MODULE_STATE_CLOSING;
  while (m->active_calls != 0) {
    int error = pthread_cond_wait(&m->call_cond, &m->call_mutex);
    if (error != 0) {
      pthread_mutex_unlock(&m->call_mutex);
      return false;
    }
  }
  pthread_mutex_unlock(&m->call_mutex);
  return true;
}

static inline void rz_module_sync_destroy(struct rezygisk_module *m) {
  if (!m || !m->call_sync_initialized) return;
  (void)rz_module_sync_close_and_wait(m);
  pthread_cond_destroy(&m->call_cond);
  pthread_mutex_destroy(&m->call_mutex);
  m->lifecycle_state = MODULE_STATE_UNLOADED;
  m->call_sync_initialized = false;
}

/*
    INFO: What follows are function definitions to be included wherever necessary.
            As a reminder for best C practices, a function body should not be in a header
            since they lead to ODR violations, resulting in UB since the compiled code *can* have duplicate defintions.
            Therefore, we have only ONE of two choices:
              1. Put the function declarations here and their respective definitions in a separate .c file;
              2. Inline these function definitions in the header so as to allow multiple definitions.
          Doing otherwise, clang-tidy throws 'definitions-in-headers' warning.

    SOURCES:
     - https://clang.llvm.org/extra/clang-tidy/checks/misc/definitions-in-headers.html
*/
static inline bool rz_module_set_state(struct rezygisk_module *m,
                                       enum module_lifecycle_state state) {
  if (!m || !m->call_sync_initialized ||
      pthread_mutex_lock(&m->call_mutex) != 0) return false;
  bool allowed = state == MODULE_STATE_RETAINED ||
      state == MODULE_STATE_UNLOADED ||
      (!m->call_closing && state != MODULE_STATE_CLOSING);
  if (allowed) m->lifecycle_state = state;
  pthread_mutex_unlock(&m->call_mutex);
  return allowed;
}

static inline bool rz_module_request_unload(struct rezygisk_module *m) {
  if (!m || !m->call_sync_initialized ||
      pthread_mutex_lock(&m->call_mutex) != 0) return false;
  bool allowed = !m->call_closing &&
      m->lifecycle_state != MODULE_STATE_UNLOADED;
  if (allowed) m->unload = true;
  pthread_mutex_unlock(&m->call_mutex);
  return allowed;
}

static inline bool rz_module_unload_requested(struct rezygisk_module *m) {
  if (!m || !m->call_sync_initialized ||
      pthread_mutex_lock(&m->call_mutex) != 0) return false;
  bool requested = m->unload;
  pthread_mutex_unlock(&m->call_mutex);
  return requested;
}

static inline void rz_module_call_on_load(struct rezygisk_module *m, void *env) {
  if (!m->zygisk_module_entry || !rz_module_call_enter(m)) return;
  m->zygisk_module_entry((void *)&m->api, env);
  rz_module_call_leave(m);
}

static inline void rz_module_call_pre_app_specialize(struct rezygisk_module *m, struct app_specialize_args_v5 *args) {
  if (!m->abi.pre_app_specialize) {
    /* NOTE: Original Zygisk API expects all modules to have all specialize functions. Not
               doing so will cause a null pointer deference in Magisk's Zygisk. */
    LOGW("Module [%s] doesn't have pre_app_specialize. Skipping it.", (m->lib.img ? m->lib.img->elf : "system-linker module"));

    return;
  }

  switch (m->abi.api_version) {
    case 1:
    case 2: {
      struct app_specialize_args_v1 versioned_args = {
        .uid = args->uid,
        .gid = args->gid,
        .gids = args->gids,
        .runtime_flags = args->runtime_flags,
        .mount_external = args->mount_external,
        .se_info = args->se_info,
        .nice_name = args->nice_name,
        .instruction_set = args->instruction_set,
        .app_data_dir = args->app_data_dir,
        .is_child_zygote = args->is_child_zygote,
        .is_top_app = args->is_top_app,
        .pkg_data_info_list = args->pkg_data_info_list,
        .whitelisted_data_info_list = args->whitelisted_data_info_list,
        .mount_data_dirs = args->mount_data_dirs,
        .mount_storage_dirs = args->mount_storage_dirs
      };

      if (rz_module_call_enter(m)) { m->abi.pre_app_specialize(m->abi.impl, &versioned_args); rz_module_call_leave(m); }

      break;
    }
    case 3:
    case 4: {
      struct app_specialize_args_v4 versioned_args;
      memcpy(&versioned_args, args, sizeof(struct app_specialize_args_v4));

      if (rz_module_call_enter(m)) { m->abi.pre_app_specialize(m->abi.impl, &versioned_args); rz_module_call_leave(m); }

      break;
    }
    case 5: {
      if (rz_module_call_enter(m)) { m->abi.pre_app_specialize(m->abi.impl, args); rz_module_call_leave(m); }

      break;
    }
  }
}

static inline void rz_module_call_post_app_specialize(struct rezygisk_module *m, const struct app_specialize_args_v5 *args) {
  if (!m->abi.post_app_specialize) {
    /* NOTE: Original Zygisk API expects all modules to have all specialize functions. Not
               doing so will cause a null pointer deference in Magisk's Zygisk. */
    LOGW("Module [%s] doesn't have post_app_specialize. Skipping it.", (m->lib.img ? m->lib.img->elf : "system-linker module"));

    return;
  }

  switch (m->abi.api_version) {
    case 1:
    case 2: {
      struct app_specialize_args_v1 versioned_args = {
        .uid = args->uid,
        .gid = args->gid,
        .gids = args->gids,
        .runtime_flags = args->runtime_flags,
        .mount_external = args->mount_external,
        .se_info = args->se_info,
        .nice_name = args->nice_name,
        .instruction_set = args->instruction_set,
        .app_data_dir = args->app_data_dir,
        .is_child_zygote = args->is_child_zygote,
        .is_top_app = args->is_top_app,
        .pkg_data_info_list = args->pkg_data_info_list,
        .whitelisted_data_info_list = args->whitelisted_data_info_list,
        .mount_data_dirs = args->mount_data_dirs,
        .mount_storage_dirs = args->mount_storage_dirs
      };

      if (rz_module_call_enter(m)) { m->abi.post_app_specialize(m->abi.impl, &versioned_args); rz_module_call_leave(m); }

      break;
    }
    case 3:
    case 4: {
      struct app_specialize_args_v4 versioned_args;
      memcpy(&versioned_args, args, sizeof(struct app_specialize_args_v4));

      if (rz_module_call_enter(m)) { m->abi.post_app_specialize(m->abi.impl, &versioned_args); rz_module_call_leave(m); }

      break;
    }
    case 5: {
      if (rz_module_call_enter(m)) { m->abi.post_app_specialize(m->abi.impl, args); rz_module_call_leave(m); }

      break;
    }
  }
}

static inline void rz_module_call_pre_server_specialize(struct rezygisk_module *m, struct server_specialize_args_v1 *args) {
  if (!m->abi.pre_server_specialize) {
    /* NOTE: Original Zygisk API expects all modules to have all specialize functions. Not
               doing so will cause a null pointer deference in Magisk's Zygisk. */
    LOGW("Module [%s] doesn't have pre_server_specialize. Skipping it.", (m->lib.img ? m->lib.img->elf : "system-linker module"));

    return;
  }

  if (rz_module_call_enter(m)) { m->abi.pre_server_specialize(m->abi.impl, args); rz_module_call_leave(m); }
}

static inline void rz_module_call_post_server_specialize(struct rezygisk_module *m, const struct server_specialize_args_v1 *args) {
  if (!m->abi.post_server_specialize) {
    /* NOTE: Original Zygisk API expects all modules to have all specialize functions. Not
               doing so will cause a null pointer deference in Magisk's Zygisk. */
    LOGW("Module [%s] doesn't have post_server_specialize. Skipping it.", (m->lib.img ? m->lib.img->elf : "system-linker module"));

    return;
  }

  if (rz_module_call_enter(m)) { m->abi.post_server_specialize(m->abi.impl, args); rz_module_call_leave(m); }
}

#endif /* MODULE_H */
