#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <dlfcn.h>
#include <link.h>
#include <regex.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <csoloader.h>
#include <plti.h>

#include "daemon.h"
#include "hook.h"
#include "hiding.h"
#include "misc.h"
#include "module.h"

#include "art_method.h"
#include "cpp_strings.h"
#include "registers.h"

void *start_addr = NULL;
size_t block_size = 0;

dev_t self_dev;
ino_t self_ino;

/* INFO: Flag indices */
enum {
  POST_SPECIALIZE,
  APP_FORK_AND_SPECIALIZE,
  APP_SPECIALIZE,
  SERVER_FORK_AND_SPECIALIZE,
  DO_REVERT_UNMOUNT,
  SKIP_FD_SANITIZATION,

  FLAG_MAX
};

#define MAX_FD_SIZE 1024
#define MAX_REGISTER_INFO 64
#define MAX_IGNORE_INFO 64
#define MAX_EXEMPTED_FDS 128

struct register_info {
  regex_t regex;
  char *symbol;
  void *callback;
  void **backup;
};

struct ignore_info {
  regex_t regex;
  char *symbol;
};

struct zygisk_context {
  JNIEnv *env;
  union {
    void *ptr;
    struct app_specialize_args_v5 *app;
    struct server_specialize_args_v1 *server;
  } args;

  const char *process;

  int pid;
  uint32_t flags;
  uint32_t info_flags;
  uint8_t allowed_fds[MAX_FD_SIZE];
  int exempted_fds[MAX_EXEMPTED_FDS];
  size_t exempted_fds_count;

  pthread_mutex_t hook_info_lock;
  struct register_info register_info[MAX_REGISTER_INFO];
  size_t register_info_count;
  struct ignore_info ignore_info[MAX_IGNORE_INFO];
  size_t ignore_info_count;
};

/* INFO: Current context */
static struct zygisk_context *g_ctx = NULL;

/* INFO: Helper macros for flags */
#define FLAG_SET(ctx, f) ((ctx)->flags |= (1u << (f)))
#define FLAG_GET(ctx, f) (((ctx)->flags & (1u << (f))) != 0)

#define DCL_PRE_POST(name)                                   \
  static void rz_## name ##_pre(struct zygisk_context *ctx); \
  static void rz_## name ##_post(struct zygisk_context *ctx)

/* INFO: Early declarations */
static void rz_init(struct zygisk_context *ctx, JNIEnv *env, void *args);
static void rz_cleanup(struct zygisk_context *ctx);

DCL_PRE_POST(run_modules);
DCL_PRE_POST(fork);
DCL_PRE_POST(app_specialize);
DCL_PRE_POST(nativeForkAndSpecialize);
DCL_PRE_POST(nativeSpecializeAppProcess);
DCL_PRE_POST(nativeForkSystemServer);

#undef DCL_PRE_POST

static inline bool is_zygote_child(struct zygisk_context *ctx) {
  return ctx->pid <= 0;
}

struct plt_hook_entry {
  const char *lib_path;
  const char *symbol;
  void *new_func;
  void **backup;
};

struct jni_hook_entry {
  char *class_name;
  JNINativeMethod *methods;
  size_t methods_count;
};

struct plti plti_ctx;

static struct plt_hook_entry *plt_hook_list = NULL;
static size_t plt_hook_list_count = 0;

static struct jni_hook_entry *jni_hook_list = NULL;
static size_t jni_hook_list_count = 0;

struct rezygisk_module *zygisk_modules = NULL;
size_t zygisk_module_length = 0;

static bool should_unmap_zygisk = false;
static bool enable_unloader = false;

/* Process-wide CSOLoader state must outlive every abandoned custom image. */
static bool csoloader_initialized = false;
static bool csoloader_pinned = false;
static size_t csoloader_active_images = 0;

/*
 * CSOLoader keeps process-global linker/TLS registries. Serialize its public
 * lifecycle API so simultaneous module load/unload requests cannot race those
 * registries. Do not hold this lock while invoking a module entry point or
 * specialization callback.
 */
static pthread_mutex_t g_csoloader_mutex;
static pthread_once_t g_csoloader_mutex_once = PTHREAD_ONCE_INIT;
static int g_csoloader_mutex_init_error;

/* The zygote forks while process-global linker state is live. Serialize fork
 * against every CSOLoader API call and leave the recursive mutex owned by the
 * forking thread so it can be released independently in parent and child. */
static void csoloader_atfork_prepare(void) {
  (void)pthread_mutex_lock(&g_csoloader_mutex);
  csoloader_fork_prepare();
}

static void csoloader_atfork_parent(void) {
  csoloader_fork_parent();
  (void)pthread_mutex_unlock(&g_csoloader_mutex);
}

static void csoloader_atfork_child(void) {
  csoloader_fork_child();
  (void)pthread_mutex_unlock(&g_csoloader_mutex);
}

static void csoloader_mutex_init_once(void) {
  pthread_mutexattr_t attr;
  int error = pthread_mutexattr_init(&attr);
  if (error != 0) {
    g_csoloader_mutex_init_error = error;
    return;
  }

  error = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  if (error == 0) error = pthread_mutex_init(&g_csoloader_mutex, &attr);
  pthread_mutexattr_destroy(&attr);
  if (error == 0) {
    error = pthread_atfork(csoloader_atfork_prepare,
                           csoloader_atfork_parent,
                           csoloader_atfork_child);
    if (error != 0) (void)pthread_mutex_destroy(&g_csoloader_mutex);
  }
  g_csoloader_mutex_init_error = error;
}

static bool csoloader_lock(void) {
  int error = pthread_once(&g_csoloader_mutex_once, csoloader_mutex_init_once);
  if (error == 0) error = g_csoloader_mutex_init_error;
  if (error == 0) error = pthread_mutex_lock(&g_csoloader_mutex);
  if (error != 0) {
    LOGE("Failed to lock CSOLoader state: %d", error);
    return false;
  }
  return true;
}

static void csoloader_unlock(void) {
  int error = pthread_mutex_unlock(&g_csoloader_mutex);
  if (error != 0) LOGE("Failed to unlock CSOLoader state: %d", error);
}

static void csoloader_pin(void) {
  if (!csoloader_lock()) return;
  csoloader_pinned = true;
  csoloader_unlock();
}


#define MAX_DEFERRED_CSO_UNLOADS 128
static pthread_mutex_t g_deferred_unload_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_deferred_unload_cond = PTHREAD_COND_INITIALIZER;
static struct csoloader *g_deferred_unloads[MAX_DEFERRED_CSO_UNLOADS];
static size_t g_deferred_unload_count;
static pthread_once_t g_deferred_worker_once = PTHREAD_ONCE_INIT;
static int g_deferred_worker_error;

static struct rezygisk_module *find_module_by_csoloader(struct csoloader *lib) {
  if (!lib || !zygisk_modules) return NULL;
  for (size_t i = 0; i < zygisk_module_length; ++i) {
    if (&zygisk_modules[i].lib == lib) return &zygisk_modules[i];
  }
  return NULL;
}

static bool any_module_execution_active(void) {
  for (size_t i = 0; i < zygisk_module_length; ++i) {
    struct rezygisk_module *m = &zygisk_modules[i];
    if (!m->call_sync_initialized) continue;
    if (pthread_mutex_lock(&m->call_mutex) != 0) return true;
    bool active = m->active_calls != 0;
    pthread_mutex_unlock(&m->call_mutex);
    if (active) return true;
  }
  return false;
}

static void *deferred_unload_worker(void *unused) {
  (void)unused;
  for (;;) {
    pthread_mutex_lock(&g_deferred_unload_mutex);
    while (g_deferred_unload_count == 0)
      pthread_cond_wait(&g_deferred_unload_cond, &g_deferred_unload_mutex);
    struct csoloader *lib = g_deferred_unloads[0];
    memmove(&g_deferred_unloads[0], &g_deferred_unloads[1],
            (--g_deferred_unload_count) * sizeof(g_deferred_unloads[0]));
    pthread_mutex_unlock(&g_deferred_unload_mutex);

    struct rezygisk_module *m = find_module_by_csoloader(lib);
    if (!m) continue;

    /* The notification can race the caller marking the image RETAINED.
     * Wait until the first unload attempt has returned and all tracked module
     * code in the process has left its execution lease. */
    bool ready = false;
    while (!ready) {
      if (!m->call_sync_initialized) break;
      if (pthread_mutex_lock(&m->call_mutex) != 0) break;
      ready = m->call_closing &&
              m->lifecycle_state == MODULE_STATE_RETAINED &&
              m->active_calls == 0;
      pthread_mutex_unlock(&m->call_mutex);
      if (!ready) usleep(1000);
    }
    if (!ready) continue;

    while (any_module_execution_active()) usleep(1000);

    if (!csoloader_unload_serialized(lib)) {
      LOGW("Deferred CSOLoader unload is still blocked; image remains resident");
      continue;
    }

    m->loader_backend = MODULE_LOADER_NONE;
    rz_module_sync_destroy(m);
    memset(m, 0, sizeof(*m));
    LOGI("Deferred CSOLoader image unload completed");
    csoloader_deinit_if_safe();
  }
  return NULL;
}

static void deferred_unload_worker_start(void) {
  pthread_t thread;
  g_deferred_worker_error =
      pthread_create(&thread, NULL, deferred_unload_worker, NULL);
  if (g_deferred_worker_error == 0) {
    g_deferred_worker_error = pthread_detach(thread);
  }
}

static void csoloader_deferred_unload_notify(void *owner) {
  struct csoloader *lib = (struct csoloader *)owner;
  if (!lib) return;
  int once_error = pthread_once(&g_deferred_worker_once,
                                deferred_unload_worker_start);
  if (once_error != 0 || g_deferred_worker_error != 0) {
    LOGE("Unable to start deferred unload worker: once=%d create=%d",
         once_error, g_deferred_worker_error);
    return;
  }

  pthread_mutex_lock(&g_deferred_unload_mutex);
  for (size_t i = 0; i < g_deferred_unload_count; ++i) {
    if (g_deferred_unloads[i] == lib) {
      pthread_cond_signal(&g_deferred_unload_cond);
      pthread_mutex_unlock(&g_deferred_unload_mutex);
      return;
    }
  }
  if (g_deferred_unload_count == MAX_DEFERRED_CSO_UNLOADS) {
    LOGE("Deferred unload queue is full; retaining image %p", (void *)lib);
    pthread_mutex_unlock(&g_deferred_unload_mutex);
    return;
  }
  g_deferred_unloads[g_deferred_unload_count++] = lib;
  pthread_cond_signal(&g_deferred_unload_cond);
  pthread_mutex_unlock(&g_deferred_unload_mutex);
}

static bool csoloader_unload_serialized(struct csoloader *lib);
static void csoloader_deinit_if_safe(void);

static bool csoloader_load_serialized(struct csoloader *lib, const char *path) {
  if (!csoloader_lock()) return false;
  csoloader_set_deferred_unload_callback(csoloader_deferred_unload_notify);

  /* A failed load can still have initialized process-global TLS/linker state.
   * Mark the runtime initialized before entering CSOLoader so that partial
   * failures are always eligible for cleanup. */
  csoloader_initialized = true;
  bool loaded = csoloader_load(lib, path);
  if (loaded) {
    csoloader_active_images++;
  } else if (csoloader_active_images == 0 && !csoloader_pinned) {
    csoloader_deinit();
    csoloader_initialized = false;
  }

  csoloader_unlock();
  return loaded;
}

static bool csoloader_unload_serialized(struct csoloader *lib) {
  if (!csoloader_lock()) return false;
  bool unloaded = csoloader_unload(lib);
  if (unloaded && csoloader_active_images > 0) csoloader_active_images--;
  csoloader_unlock();
  return unloaded;
}

static bool csoloader_abandon_serialized(struct csoloader *lib) {
  if (!csoloader_lock()) return false;
  bool abandoned = csoloader_abandon(lib);
  if (abandoned) csoloader_pinned = true;
  csoloader_unlock();
  return abandoned;
}

static void *csoloader_get_symbol_serialized(struct csoloader *lib, const char *name) {
  if (!csoloader_lock()) return NULL;
  void *symbol = csoloader_get_symbol(lib, name);
  csoloader_unlock();
  return symbol;
}

static void csoloader_deinit_if_safe(void) {
  if (!csoloader_lock()) return;
  if (csoloader_initialized && csoloader_active_images == 0 && !csoloader_pinned) {
    csoloader_deinit();
    csoloader_initialized = false;
    LOGD("CSOLoader global state deinitialized");
  }
  csoloader_unlock();
}

/* Read-only ELF feature probe. Unsupported metadata is routed to Bionic rather
 * than allowing the section-oriented CSOLoader parser to mis-link the image. */
struct linker_elf_features {
  bool has_gnu_versions;
  bool has_pt_tls;
};

static bool file_range_valid(uint64_t offset, uint64_t length, uint64_t file_size) {
  return offset <= file_size && length <= file_size - offset;
}

static bool pread_fully(int fd, void *buffer, size_t size, off_t offset) {
  unsigned char *out = (unsigned char *)buffer;
  size_t done = 0;
  while (done < size) {
    ssize_t n = pread(fd, out + done, size - done, offset + (off_t)done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    done += (size_t)n;
  }
  return true;
}

static bool inspect_linker_elf(const char *path, struct linker_elf_features *features) {
  if (!path || !features) return false;
  memset(features, 0, sizeof(*features));

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;

  struct stat st;
  Elf64_Ehdr eh;
  bool valid = fstat(fd, &st) == 0 && st.st_size >= (off_t)sizeof(eh) &&
      pread_fully(fd, &eh, sizeof(eh), 0) &&
      memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0 &&
      eh.e_ident[EI_CLASS] == ELFCLASS64 &&
      eh.e_ident[EI_DATA] == ELFDATA2LSB &&
      eh.e_ident[EI_VERSION] == EV_CURRENT &&
      eh.e_machine == EM_AARCH64 && eh.e_type == ET_DYN &&
      eh.e_ehsize == sizeof(eh) && eh.e_phentsize == sizeof(Elf64_Phdr) &&
      eh.e_phnum > 0 &&
      file_range_valid(eh.e_phoff, (uint64_t)eh.e_phnum * sizeof(Elf64_Phdr),
                       (uint64_t)st.st_size);

  Elf64_Phdr *phdr = NULL;
  if (valid) {
    size_t bytes = (size_t)eh.e_phnum * sizeof(Elf64_Phdr);
    phdr = (Elf64_Phdr *)malloc(bytes);
    valid = phdr && pread_fully(fd, phdr, bytes, (off_t)eh.e_phoff);
  }

  bool dynamic_found = false;
  if (valid) {
    for (Elf64_Half i = 0; i < eh.e_phnum; ++i) {
      const Elf64_Phdr *p = &phdr[i];
      if (p->p_type == PT_TLS) features->has_pt_tls = true;
      if (p->p_type != PT_DYNAMIC) continue;
      if (dynamic_found || p->p_filesz == 0 || p->p_filesz > p->p_memsz ||
          p->p_filesz % sizeof(Elf64_Dyn) != 0 ||
          !file_range_valid(p->p_offset, p->p_filesz, (uint64_t)st.st_size)) {
        valid = false;
        break;
      }
      /* PT_DYNAMIC must be backed by the matching file bytes of a PT_LOAD. */
      bool dynamic_in_load = false;
      for (Elf64_Half k = 0; k < eh.e_phnum; ++k) {
        const Elf64_Phdr *load = &phdr[k];
        if (load->p_type != PT_LOAD || p->p_vaddr < load->p_vaddr) continue;
        uint64_t delta = p->p_vaddr - load->p_vaddr;
        if (delta <= load->p_filesz && p->p_filesz <= load->p_filesz - delta &&
            load->p_offset <= UINT64_MAX - delta &&
            load->p_offset + delta == p->p_offset) {
          dynamic_in_load = true;
          break;
        }
      }
      if (!dynamic_in_load) {
        valid = false;
        break;
      }

      dynamic_found = true;
      bool dynamic_terminated = false;
      size_t count = (size_t)(p->p_filesz / sizeof(Elf64_Dyn));
      for (size_t n = 0; n < count; ++n) {
        Elf64_Dyn dyn;
        if (!pread_fully(fd, &dyn, sizeof(dyn),
                         (off_t)(p->p_offset + n * sizeof(dyn)))) {
          valid = false;
          break;
        }
        if (dyn.d_tag == DT_NULL) {
          dynamic_terminated = true;
          break;
        }
        switch ((uint64_t)dyn.d_tag) {
          case 0x6ffffff0ULL: /* DT_VERSYM */
          case 0x6ffffffcULL: /* DT_VERDEF */
          case 0x6ffffffdULL: /* DT_VERDEFNUM */
          case 0x6ffffffeULL: /* DT_VERNEED */
          case 0x6fffffffULL: /* DT_VERNEEDNUM */
            features->has_gnu_versions = true;
            break;
          default:
            break;
        }
      }
      if (!dynamic_terminated) valid = false;
      break;
    }
    if (!dynamic_found) valid = false;
  }

  free(phdr);
  close(fd);
  return valid;
}

static bool requires_system_linker(const char *path) {
  struct linker_elf_features features;
  if (!inspect_linker_elf(path, &features)) {
    LOGW("Unable to validate ELF metadata for [%s]; using Bionic linker", path);
    return true;
  }
  if (features.has_pt_tls) {
    LOGI("Using Bionic linker for [%s]: PT_TLS=%d GNU versions=%d",
         path, features.has_pt_tls, features.has_gnu_versions);
    return true;
  }
  if (features.has_gnu_versions)
    LOGI("Using CSOLoader native GNU version resolver for [%s]", path);
  return false;
}

/* INFO: Helper function to add to PLT hook list */
static bool plt_hook_list_add(const char *lib_path, const char *symbol, void *new_func, void **backup) {
  struct plt_hook_entry *new_plt_hook_list = realloc(plt_hook_list, (plt_hook_list_count + 1) * sizeof(struct plt_hook_entry));
  if (!new_plt_hook_list) {
    LOGE("Failed to reallocate buffer for PLT hook list");

    return false;
  }
  plt_hook_list = new_plt_hook_list;

  plt_hook_list[plt_hook_list_count].lib_path = lib_path;
  plt_hook_list[plt_hook_list_count].symbol = symbol;
  plt_hook_list[plt_hook_list_count].new_func = new_func;
  plt_hook_list[plt_hook_list_count].backup = backup;
  plt_hook_list_count++;

  return true;
}

/* INFO: Helper function to add to JNI hook list */
static void jni_hook_list_add(const char *class_name, JNINativeMethod *methods, size_t count) {
  struct jni_hook_entry *new_jni_hook_list = realloc(jni_hook_list, (jni_hook_list_count + 1) * sizeof(struct jni_hook_entry));
  if (!new_jni_hook_list) {
    LOGE("Failed to reallocate buffer for JNI hook list");

    return;
  }
  jni_hook_list = new_jni_hook_list;

  jni_hook_list[jni_hook_list_count].class_name = strdup(class_name);
  if (!jni_hook_list[jni_hook_list_count].class_name) {
    LOGE("Failed to duplicate class name for hook list");

    return;
  }

  jni_hook_list[jni_hook_list_count].methods = malloc(count * sizeof(JNINativeMethod));
  if (!jni_hook_list[jni_hook_list_count].methods) {
    LOGE("Failed to allocate memory for methods in hook list");

    free(jni_hook_list[jni_hook_list_count].class_name);

    return;
  }

  memcpy(jni_hook_list[jni_hook_list_count].methods, methods, count * sizeof(JNINativeMethod));

  jni_hook_list[jni_hook_list_count].methods_count = count;
  jni_hook_list_count++;
}

static bool update_mnt_ns(enum mount_namespace_state mns_state, uid_t uid,
                             const char *process, bool dry_run) {
  char ns_path[PATH_MAX];
  if (!rezygiskd_update_mns(mns_state, uid, process, ns_path, sizeof(ns_path))) {
    PLOGE("Failed to update mount namespace");

    return false;
  }

  /* Empty path means the daemon deliberately preserved the target namespace. */
  if (ns_path[0] == '\0') {
    LOGD("Keeping original mount namespace for [%s]", process ? process : "(unknown)");
    return true;
  }

  if (dry_run) return true;

  int updated_ns = open(ns_path, O_RDONLY);
  if (updated_ns == -1) {
    PLOGE("Failed to open mount namespace [%s]", ns_path);

    return false;
  }

  char *mns_state_str = "unknown";
  if (mns_state == Clean) mns_state_str = "clean";
  if (mns_state == Mounted) mns_state_str = "mounted";

  LOGD("set mount namespace to [%s] fd=[%d]: %s", ns_path, updated_ns, mns_state_str);

  if (setns(updated_ns, CLONE_NEWNS) == -1) {
    PLOGE("Failed to set mount namespace [%s]", ns_path);

    close(updated_ns);

    return false;
  }

  close(updated_ns);

  return true;
}

/* INFO: Hook function declarations */
#define DCL_HOOK_FUNC(ret, func, ...) \
  ret (*old_##func)(__VA_ARGS__);     \
  ret new_##func(__VA_ARGS__)

/* INFO: ReZygisk already performs a fork in zygisk_context::fork_pre, because of that,
           we avoid duplicate fork in nativeForkAndSpecialize and nativeForkSystemServer
           by caching the pid in fork_pre function and only performing fork if the pid
           is non-0, or in other words, if we (libzygisk.so) already forked.
*/
DCL_HOOK_FUNC(int, fork) {
  return (g_ctx && g_ctx->pid >= 0) ? g_ctx->pid : old_fork();
}

/* INFO: file_path is a std::string in the actual class. We represent it as opaque bytes. */
#ifdef __LP64__
  #define STD_STRING_SIZE 24
#else
  #define STD_STRING_SIZE 12
#endif

struct FileDescriptorInfo {
  const int fd;
  const struct stat stat;
  /* INFO: std::string, actually */
  char file_path_storage[STD_STRING_SIZE];
  const int open_flags;
  const int fd_flags;
  const int fs_flags;
  const off_t offset;
  const bool is_sock;
};

/* INFO: This hook avoids that umounted overlays made by root modules lead to Zygote
           to Abort its operation as it cannot open anymore.

   SOURCES:
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/fd_utils.cpp#346
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/fd_utils.cpp#544
     - https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#2329
*/
DCL_HOOK_FUNC(void, _ZNK18FileDescriptorInfo14ReopenOrDetach, void *_this, void *fail_fn) {
  const int fd = *(const int *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, fd));
  const void *file_path_std_string = (const void *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, file_path_storage));
  const char *file_path = read_std_string(file_path_std_string);
  const bool is_sock = *(const bool *)((uintptr_t)_this + offsetof(struct FileDescriptorInfo, is_sock));

  if (is_sock)
    goto bypass_fd_check;

  if (strncmp(file_path, "/memfd:/boot-image-methods.art", strlen("/memfd:/boot-image-methods.art")) == 0)
    goto bypass_fd_check;

  if (access(file_path, F_OK) == -1) {
    LOGD("Failed to open file %s, detaching it", file_path);

    close(fd);

    return;
  }

  bypass_fd_check:
    old__ZNK18FileDescriptorInfo14ReopenOrDetach(_this, fail_fn);
}

static void unhook_functions(void);
/* INFO: Self-unloading is not a direct task, it requires the utilization of tail
           optimization, which requires the signature to be the same as munmap, or
           else munmap will be executed and will try to reach our code, leading to
           a segmentation fault.

         To counter that, we hook pthread_attr_setstacksize, which is called around
           when the VM daemon starts, to allow this to happen before the app can
           execute code.
*/
DCL_HOOK_FUNC(int, pthread_attr_setstacksize, void *target, size_t size) {
  int res = old_pthread_attr_setstacksize((pthread_attr_t *)target, size);
  LOGV("Call pthread_attr_setstacksize in [tid, pid]: %d, %d", gettid(), getpid());

  if (!enable_unloader) return res;

  /* INFO: Only perform unloading on the main thread */
  if (gettid() != getpid()) return res;

  if (should_unmap_zygisk) {
    unhook_functions();

    csoloader_deinit_if_safe();

    if (!should_unmap_zygisk) {
      LOGW("Failed to unmap libzygisk.so, skipping munmap");

      enable_unloader = false;

      free(zygisk_modules);
      zygisk_modules = NULL;

      plti_deinit(&plti_ctx);

      return res;
    }

    /* INFO: Modules might use libzygisk.so after postAppSpecialize. We can only
               free it when we are really before our unmap. */
    free(zygisk_modules);
    zygisk_modules = NULL;

    plti_deinit(&plti_ctx);

    LOGD("unmap libzygisk.so loaded at %p with size %zu", start_addr, block_size);

    [[clang::musttail]] return munmap(start_addr, block_size);
  }

  return res;
}

static void initialize_jni_hook(void);

DCL_HOOK_FUNC(char *, strdup, const char *str) {
  if (strcmp(str, "com.android.internal.os.ZygoteInit") == 0) {
    LOGV("strdup %s", str);

    initialize_jni_hook();
  }

  return old_strdup(str);
}

static void hook_unloader(void);
/*
  INFO: Our goal is to get called after libart.so is loaded, but before ART actually starts running.
          If we are too early, we won't find libart.so in maps, and if we are too late, we could make other
          threads crash if they try to use the PLT while we are in the process of hooking it.
          For this task, hooking property_get was chosen as there are lots of calls to this, so it's
          relatively unlikely to break.

        After we succeed in getting called at a point where libart.so is already loaded, we will ignore
          the rest of the property_get calls.
  SOURCES:
   - https://github.com/aosp-mirror/platform_frameworks_base/blob/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/jni/AndroidRuntime.cpp#L1266
   - https://github.com/aosp-mirror/platform_frameworks_base/blob/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/jni/AndroidRuntime.cpp#L791
*/
DCL_HOOK_FUNC(int, property_get, const char *key, char *value, const char *default_value) {
  hook_unloader();

  return old_property_get(key, value, default_value);
}

#undef DCL_HOOK_FUNC

static bool can_hook_jni = false;
static jint MODIFIER_NATIVE = 0;
static jmethodID member_getModifiers = NULL;

void hook_jni_methods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods) {
  if (!can_hook_jni) return;

  jclass clazz = (*env)->FindClass(env, clz);
  if (!clazz) {
    (*env)->ExceptionClear(env);

    memset(methods, 0, numMethods * sizeof(JNINativeMethod));

    return;
  }

  JNINativeMethod hooks[32];
  size_t hooks_count = 0;

  for (int i = 0; i < numMethods; i++) {
    bool is_static = false;

    JNINativeMethod *nm = &methods[i];
    jmethodID mid = (*env)->GetMethodID(env, clazz, nm->name, nm->signature);
    if (!mid) {
      (*env)->ExceptionClear(env);
      mid = (*env)->GetStaticMethodID(env, clazz, nm->name, nm->signature);
      is_static = true;
    }

    if (!mid) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      continue;
    }

    jobject method = (*env)->ToReflectedMethod(env, clazz, mid, is_static);
    jint modifier = (*env)->CallIntMethod(env, method, member_getModifiers);
    if ((*env)->ExceptionCheck(env) || (modifier & MODIFIER_NATIVE) == 0) {
      (*env)->ExceptionClear(env);
      nm->fnPtr = NULL;

      (*env)->DeleteLocalRef(env, method);

      continue;
    }

    void *art_method = amethod_from_reflected_method(env, method);
    if (hooks_count < 32)
      hooks[hooks_count++] = *nm;

    void *orig = amethod_get_data((uintptr_t)art_method);
    nm->fnPtr = orig;

    LOGV("replaced %s %s orig %p: %s", clz, nm->name, orig, nm->signature);

    (*env)->DeleteLocalRef(env, method);
  }

  if (hooks_count == 0) {
    (*env)->DeleteLocalRef(env, clazz);

    return;
  }

  (*env)->RegisterNatives(env, clazz, hooks, (jint)hooks_count);
  (*env)->DeleteLocalRef(env, clazz);
}

/* INFO: JNI method hook definitions */
#include "jni_hooks.h"

/* INFO: Collect candidate libraries across Bionic, ReZygisk, and loaded modules without procfs */
static int collect_dl_libs(struct dl_phdr_info *info, size_t size, void *data) {
  (void) size;

  struct maps_info *maps = (struct maps_info *)data;
  if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

  for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type != PT_LOAD || phdr->p_offset != 0 || !(phdr->p_flags & PF_R)) continue;

    struct map_entry *new_maps = realloc(maps->maps, (maps->length + 1) * sizeof(struct map_entry));
    if (!new_maps) {
      LOGE("Failed to reallocate memory for maps");

      return 0;
    }

    /* INFO: The device and inode belong to the container when the library lives
               inside of an APK (e.g. /data/app/.../base.apk!/lib/arm64-v8a/x.so). */
    struct stat st;
    dev_t dev = 0;
    ino_t ino = 0;
    char *zip = strstr(info->dlpi_name, "!/");
    if (zip) {
      char *container = strndup(info->dlpi_name, (size_t)(zip - info->dlpi_name));
      if (container) {
        if (stat(container, &st) == 0) {
          dev = st.st_dev;
          ino = st.st_ino;
        }

        free(container);
      }
    } else if (stat(info->dlpi_name, &st) == 0) {
      dev = st.st_dev;
      ino = st.st_ino;
    }

    maps->maps = new_maps;
    maps->maps[maps->length++] = (struct map_entry){
      .start = (uintptr_t)info->dlpi_addr + phdr->p_vaddr,
      .end = (uintptr_t)info->dlpi_addr + phdr->p_vaddr + phdr->p_memsz,
      .offset = 0,
      .dev = dev,
      .inode = ino,
      .perms = PROT_READ,
      .is_private = true,
      .path = strdup(info->dlpi_name)
    };
    if (!maps->maps[maps->length - 1].path) {
      LOGE("Failed to duplicate path for %s", info->dlpi_name);

      return 0;
    }

    break;
  }

  return 0;
}

static struct maps_info *get_loaded_libraries(void) {
  struct maps_info *maps = calloc(1, sizeof(struct maps_info));
  if (!maps) return NULL;

  /* INFO: 1.: Libraries loaded by system linker */
  dl_iterate_phdr(collect_dl_libs, maps);

  /* INFO: 2.: ReZygisk itself (loaded via RCSOLoader) */
  if (start_addr && block_size > 0 && self_dev) {
    struct map_entry *new_maps = realloc(maps->maps, (maps->length + 1) * sizeof(struct map_entry));
    if (!new_maps) {
      LOGE("Failed to reallocate memory for maps");

      free_maps(maps);

      return NULL;
    }

    maps->maps = new_maps;
    maps->maps[maps->length++] = (struct map_entry) {
      .start = (uintptr_t)start_addr,
      .end = (uintptr_t)start_addr + block_size,
      .offset = 0,
      .dev = self_dev,
      .inode = self_ino,
      .perms = PROT_READ,
      .is_private = true,
      .path = strdup("/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so")
    };
    if (!maps->maps[maps->length - 1].path) {
      LOGE("Failed to duplicate path for ReZygisk");

      free_maps(maps);

      return NULL;
    }
  }

  /* INFO: 3.: Zygisk modules loaded via CSOLoader */
  for (size_t i = 0; i < zygisk_module_length; i++) {
    struct rezygisk_module *map = &zygisk_modules[i];
    if (!map->lib.lib_path || !map->lib.img || !map->lib.img->header) continue;

    struct map_entry *new_maps = realloc(maps->maps, (maps->length + 1) * sizeof(struct map_entry));
    if (!new_maps) {
      LOGE("Failed to reallocate memory for maps");

      continue;
    }

    maps->maps = new_maps;
    maps->maps[maps->length++] = (struct map_entry) {
      .start = (uintptr_t)map->lib.img->header,
      .end = (uintptr_t)map->lib.img->header + map->lib.img->size,
      .offset = 0,
      .dev = map->dev,
      .inode = map->ino,
      .perms = PROT_READ,
      .is_private = true,
      .path = strdup(map->lib.lib_path)
    };
  }

  if (maps->length == 0) {
    LOGE("Failed to find any loaded library");

    free_maps(maps);

    return NULL;
  }

  return maps;
}

static void initialize_jni_hook(void) {
  jint (*get_created_java_vms)(JavaVM **, jsize, jsize *) = (jint (*)(JavaVM **, jsize, jsize *))dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
  if (!get_created_java_vms) {
    struct maps_info *maps = get_loaded_libraries();
    if (!maps) {
      LOGE("Failed to get loaded libraries for plt_hook_register_v4");

      return;
    }

    for (size_t i = 0; i < maps->length; i++) {
      struct map_entry *map = &maps->maps[i];
      if (map->path && !strstr(map->path, "/libnativehelper.so")) continue;

      /* TODO: Add RTLD_NOLOAD? */
      void *handle = dlopen(map->path, RTLD_LAZY);
      if (!handle) {
        LOGE("Failed to dlopen %s: %s", map->path, dlerror());

        break;
      }

      get_created_java_vms = (jint (*)(JavaVM **, jsize, jsize *))dlsym(handle, "JNI_GetCreatedJavaVMs");
      dlclose(handle);

      break;
    }

    free_maps(maps);

    if (!get_created_java_vms) {
      LOGE("Failed to find JNI_GetCreatedJavaVMs");

      return;
    }
  }

  JavaVM *vm = NULL;
  jsize num = 0;
  jint res = get_created_java_vms(&vm, 1, &num);
  if (res != JNI_OK || !vm) return;

  JNIEnv *env = NULL;
  res = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
  if (res != JNI_OK || !env) return;

  jclass classMember = (*env)->FindClass(env, "java/lang/reflect/Member");
  if (classMember) member_getModifiers = (*env)->GetMethodID(env, classMember, "getModifiers", "()I");

  jclass classModifier = (*env)->FindClass(env, "java/lang/reflect/Modifier");
  if (classModifier) {
    jfieldID fieldId = (*env)->GetStaticFieldID(env, classModifier, "NATIVE", "I");
    if (fieldId) MODIFIER_NATIVE = (*env)->GetStaticIntField(env, classModifier, fieldId);
  }

  (*env)->DeleteLocalRef(env, classMember);
  (*env)->DeleteLocalRef(env, classModifier);

  if (!member_getModifiers || MODIFIER_NATIVE == 0) return;

  if (!amethod_init(env)) {
    LOGE("failed to init amethod");

    return;
  }

  can_hook_jni = true;
  do_hook_zygote(env);

  /* INFO: ART leaks through libc strings from ReZygisk. We immediately
             clear them here. */
  registers_clear();
}

/* INFO: Module registration and API functions */
static void api_plt_hook_register(const char *regex, const char *symbol, void *fn, void **backup) {
  if (!g_ctx || !regex || !symbol || !fn || g_ctx->register_info_count >= MAX_REGISTER_INFO) return;

  regex_t re;
  if (regcomp(&re, regex, REG_NOSUB) != 0) return;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  g_ctx->register_info[g_ctx->register_info_count].regex = re;
  g_ctx->register_info[g_ctx->register_info_count].symbol = strdup(symbol);
  g_ctx->register_info[g_ctx->register_info_count].callback = fn;
  g_ctx->register_info[g_ctx->register_info_count].backup = backup;
  g_ctx->register_info_count++;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);
}

static void api_plt_hook_exclude(const char *regex, const char *symbol) {
  if (!g_ctx || !regex || g_ctx->ignore_info_count >= MAX_IGNORE_INFO) return;

  regex_t re;
  if (regcomp(&re, regex, REG_NOSUB) != 0) return;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  g_ctx->ignore_info[g_ctx->ignore_info_count].regex = re;
  g_ctx->ignore_info[g_ctx->ignore_info_count].symbol = symbol ? strdup(symbol) : NULL;
  g_ctx->ignore_info_count++;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);
}

static bool api_plt_hook_commit(void) {
  if (!g_ctx || g_ctx->register_info_count == 0) return false;

  pthread_mutex_lock(&g_ctx->hook_info_lock);

  struct maps_info *map_infos = get_loaded_libraries();
  if (!map_infos) {
    LOGE("Failed to scan maps for self");

    pthread_mutex_unlock(&g_ctx->hook_info_lock);

    return false;
  }

  bool any_failed = false;
  for (size_t i = 0; i < map_infos->length; i++) {
    struct map_entry *map = &map_infos->maps[i];
    if (map->offset != 0 || !map->is_private || !(map->perms & PROT_READ)) continue;

    for (size_t r = 0; r < g_ctx->register_info_count; r++) {
      struct register_info *reg = &g_ctx->register_info[r];
      if (regexec(&reg->regex, map->path, 0, NULL, 0) != 0) continue;

      bool ignored = false;
      for (size_t ig = 0; ig < g_ctx->ignore_info_count; ig++) {
        struct ignore_info *ign = &g_ctx->ignore_info[ig];
        if (regexec(&ign->regex, map->path, 0, NULL, 0) != 0) continue;
        if (ign->symbol && strcmp(ign->symbol, reg->symbol) != 0) continue;

        ignored = true;

        break;
      }

      if (!ignored && !plti_add_hook(&plti_ctx, map->path, reg->symbol, reg->callback, reg->backup)) {
        LOGE("Failed to register PLT hook for %s in %s", reg->symbol, map->path);

        any_failed = true;
      }
    }
  }

  free_maps(map_infos);

  /* INFO: Clear register_info and ignore_info */
  for (size_t i = 0; i < g_ctx->register_info_count; i++) {
    regfree(&g_ctx->register_info[i].regex);
    free(g_ctx->register_info[i].symbol);
  }
  g_ctx->register_info_count = 0;

  for (size_t i = 0; i < g_ctx->ignore_info_count; i++) {
    regfree(&g_ctx->ignore_info[i].regex);
    free(g_ctx->ignore_info[i].symbol);
  }
  g_ctx->ignore_info_count = 0;

  pthread_mutex_unlock(&g_ctx->hook_info_lock);

  return !any_failed;
}

static void api_plt_hook_register_v4(dev_t dev, ino_t inode, const char *symbol, void *fn, void **backup) {
  if (!g_ctx || !symbol || !fn) return;

  struct maps_info *maps = get_loaded_libraries();
  if (!maps) {
    LOGE("Failed to scan maps for plt_hook_register_v4");

    return;
  }

  uintptr_t lib_start = 0;
  const char *lib_path = NULL;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];
    if (entry->dev != dev || entry->inode != inode) continue;

    lib_start = entry->start;
    lib_path = entry->path;

    break;
  }

  if (!lib_path) {
    LOGE("Failed to find library with dev %zu and inode %zu for hook %s", (size_t)dev, (size_t)inode, symbol);

    free_maps(maps);

    return;
  }

  char *lib_path_copy = strdup(lib_path);
  if (!lib_path_copy) {
    LOGE("Failed to duplicate library path for hook %s: %s", symbol, lib_path);

    free_maps(maps);

    return;
  }

  free_maps(maps);

  if (!plti_add_manual_lib(&plti_ctx, lib_path_copy, lib_start)) {
    LOGE("Failed to add manual library for hook %s: %s", symbol, lib_path_copy);

    free(lib_path_copy);

    return;
  }

  char *symbol_copy = strdup(symbol);
  if (!symbol_copy) {
    LOGE("Failed to duplicate symbol name for hook %s in %s", symbol, lib_path_copy);

    free(lib_path_copy);

    return;
  }

  if (!plt_hook_list_add(lib_path_copy, symbol_copy, fn, backup)) {
    LOGE("Failed to add plt_hook entry for %s in %s", symbol, lib_path_copy);

    free(lib_path_copy);
    free(symbol_copy);

    return;
  }
}

static void api_exempt_fd(int fd) {
  if (!g_ctx) return;

  if (FLAG_GET(g_ctx, POST_SPECIALIZE) || FLAG_GET(g_ctx, SKIP_FD_SANITIZATION)) return;
  if (!FLAG_GET(g_ctx, APP_FORK_AND_SPECIALIZE)) return;
  if (g_ctx->exempted_fds_count >= MAX_EXEMPTED_FDS) return;

  g_ctx->exempted_fds[g_ctx->exempted_fds_count++] = fd;

  return;
}

static bool api_plt_hook_commit_v4(void) {
  if (!g_ctx) return false;

  bool any_failed = false;
  for (size_t i = 0; i < plt_hook_list_count; i++) {
    struct plt_hook_entry *entry = &plt_hook_list[i];
    if (!plti_add_hook(&plti_ctx, entry->lib_path, entry->symbol, entry->new_func, entry->backup)) {
      LOGE("Failed to register plt_hook \"%s\" in %s with PLTI", entry->symbol, entry->lib_path);

      any_failed = true;
    }
  }

  if (plt_hook_list) {
    for (size_t i = 0; i < plt_hook_list_count; i++) {
      free((void *)plt_hook_list[i].lib_path);
      free((void *)plt_hook_list[i].symbol);
    }

    free(plt_hook_list);
    plt_hook_list = NULL;
    plt_hook_list_count = 0;
  }

  return !any_failed;
}

/* INFO: Avoid common mistakes of not utilizing implementation member (impl) when calling
           any Zygisk API functions by logging that error. */
#define RZID_MAGIC ('R' + 'Z' + 'I' + 'D')
#define ENCODE_ID(id) ((void *)((size_t)(id) + RZID_MAGIC))
#define DECODE_ID(ptr) ((size_t)(ptr) - RZID_MAGIC)

static int api_connect_companion(void *id) {
  if (!g_ctx) return -1;

  if ((size_t)id < RZID_MAGIC || (size_t)id >= RZID_MAGIC + zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return -1;
  }

  return rezygiskd_connect_companion(DECODE_ID(id));
}

static void api_set_option(void *id, enum rezygisk_options opt) {
  if (!g_ctx) return;

  if ((size_t)id < RZID_MAGIC || (size_t)id >= RZID_MAGIC + zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return;
  }

  switch (opt) {
    case FORCE_DENYLIST_UNMOUNT: {
      FLAG_SET(g_ctx, DO_REVERT_UNMOUNT);

      break;
    }
    case DLCLOSE_MODULE_LIBRARY: {
      struct rezygisk_module *m_lib = &zygisk_modules[DECODE_ID(id)];
      if (!rz_module_request_unload(m_lib))
        LOGW("Ignoring unload request for module in a closing/invalid state");

      break;
    }
  }
}

static int api_get_module_dir(void *id) {
  if (!g_ctx) return -1;

  if ((size_t)id < RZID_MAGIC || (size_t)id >= RZID_MAGIC + zygisk_module_length) {
    LOGE("Invalid (encoded) module id %zu", (size_t)id);

    return -1;
  }

  return rezygiskd_get_module_dir(DECODE_ID(id));
}

static uint32_t api_get_flags(void) {
  if (!g_ctx) return 0;

  return (g_ctx->info_flags & ~PRIVATE_MASK);
}

bool rezygisk_module_register(struct rezygisk_api *api, struct rezygisk_abi const *target_module) {
  if (!g_ctx || !api || !target_module || target_module->api_version > REZYGISK_API_VERSION) return false;

  LOGD("Registering module with API version %ld", target_module->api_version);

  struct rezygisk_module *m = &zygisk_modules[DECODE_ID(api->impl)];
  m->abi = *target_module;
  m->api = *api;
  (void)rz_module_set_state(m, MODULE_STATE_REGISTERED);

  api->hook_jni_native_methods = hook_jni_methods;
  if (target_module->api_version >= 4) {
    api->plt_hook_register_v4 = api_plt_hook_register_v4;
    api->exempt_fd = api_exempt_fd;
    api->plt_hook_commit = api_plt_hook_commit_v4;
  } else {
    api->plt_hook_register = api_plt_hook_register;
    api->plt_hook_exclude = api_plt_hook_exclude;
    api->plt_hook_commit = api_plt_hook_commit;
  }

  api->connect_companion = api_connect_companion;
  api->set_option = api_set_option;

  if (target_module->api_version >= 2) {
    api->get_module_dir = api_get_module_dir;
    api->get_flags = api_get_flags;
  }

  return true;
}

/* INFO: Signal mask helper */
static int sigmask(int how, int signum) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signum);

  return sigprocmask(how, &set, NULL);
}

static bool load_modules_only(void);

static void rz_fork_pre(struct zygisk_context *ctx) {
  /* INFO: Do our own fork before loading any 3rd party code.
              First block SIGCHLD, unblock after original fork is done.
  */
  sigmask(SIG_BLOCK, SIGCHLD);
  ctx->pid = old_fork();
  if (ctx->pid != 0 || FLAG_GET(ctx, SKIP_FD_SANITIZATION)) return;

  /* INFO: Record all open fds */
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("Failed to open /proc/self/fd");

    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir))) {
    int fd = parse_int(entry->d_name);
    if (fd == -1) continue;

    if (fd >= MAX_FD_SIZE) {
      close(fd);

      continue;
    }

    ctx->allowed_fds[fd] = 1;
  }

  /* INFO: The dirfd should not be allowed */
  int dfd = dirfd(dir);
  if (dfd >= 0 && dfd < MAX_FD_SIZE) ctx->allowed_fds[dfd] = 0;

  closedir(dir);
}

static void mark_fds_allowed(struct zygisk_context *ctx, JNIEnv *env, jintArray fdsArray) {
  if (!fdsArray) return;

  jint *arr = (*env)->GetIntArrayElements(env, fdsArray, NULL);
  jint len = (*env)->GetArrayLength(env, fdsArray);

  for (jint i = 0; i < len; ++i) {
    int fd = arr[i];
    if (fd >= 0 && fd < MAX_FD_SIZE) ctx->allowed_fds[fd] = 1;
  }

  (*env)->ReleaseIntArrayElements(env, fdsArray, arr, JNI_ABORT);
}

static void rz_sanitize_fds(struct zygisk_context *ctx) {
  if (FLAG_GET(ctx, SKIP_FD_SANITIZATION)) return;

  if (FLAG_GET(ctx, APP_FORK_AND_SPECIALIZE)) {
    jintArray fdsToIgnore = ctx->args.app->fds_to_ignore ? *ctx->args.app->fds_to_ignore : NULL;
    mark_fds_allowed(ctx, ctx->env, fdsToIgnore);

    if (ctx->exempted_fds_count > 0) {
      jint len = fdsToIgnore ? (*ctx->env)->GetArrayLength(ctx->env, fdsToIgnore) : 0;
      jintArray newArray = (*ctx->env)->NewIntArray(ctx->env, (jsize)(len + ctx->exempted_fds_count));
      if (newArray) {
        if (fdsToIgnore && len > 0) {
          jint *arr = (*ctx->env)->GetIntArrayElements(ctx->env, fdsToIgnore, NULL);
          (*ctx->env)->SetIntArrayRegion(ctx->env, newArray, 0, len, arr);
          (*ctx->env)->ReleaseIntArrayElements(ctx->env, fdsToIgnore, arr, JNI_ABORT);
          (*ctx->env)->DeleteLocalRef(ctx->env, fdsToIgnore);
        }

        (*ctx->env)->SetIntArrayRegion(ctx->env, newArray, len, (jsize)ctx->exempted_fds_count, ctx->exempted_fds);
        for (size_t i = 0; i < ctx->exempted_fds_count; i++) {
          int fd = ctx->exempted_fds[i];
          if (fd >= 0 && fd < MAX_FD_SIZE) ctx->allowed_fds[fd] = 1;
        }

        *ctx->args.app->fds_to_ignore = newArray;
        FLAG_SET(ctx, SKIP_FD_SANITIZATION);
      }
    }
  }

  if (ctx->pid != 0) return;

  /* INFO: Close all forbidden fds to prevent crashing */
  DIR *dir = opendir("/proc/self/fd");
  if (!dir) {
    PLOGE("Failed to open /proc/self/fd");

    return;
  }

  int dfd = dirfd(dir);
  struct dirent *entry;
  while ((entry = readdir(dir))) {
    int fd = parse_int(entry->d_name);
    if (fd < 0 || fd >= MAX_FD_SIZE || fd == dfd || ctx->allowed_fds[fd]) continue;

    close(fd);

    LOGW("Closed leaked fd: %d", fd);
  }

  closedir(dir);
}

static void rz_fork_post(struct zygisk_context *ctx __attribute__((unused))) {
  sigmask(SIG_UNBLOCK, SIGCHLD);
  g_ctx = NULL;
}

static void release_unregistered_module(struct rezygisk_module *module, const char *lib_path) {
  bool released = true;

  if (module->loader_backend == MODULE_LOADER_CSO) {
    released = csoloader_unload_serialized(&module->lib);
    if (!released) {
      csoloader_pin();
      LOGE("Retaining failed CSOLoader image for [%s]", lib_path);
    }
  } else if (module->loader_backend == MODULE_LOADER_SYSTEM) {
    if (!module->system_handle || dlclose(module->system_handle) != 0) {
      const char *error = dlerror();
      LOGE("Failed to close system-loaded module [%s]: %s", lib_path,
           error ? error : "invalid handle");
      released = false;
    }
  }

  if (!released) {
    /* The image/handle must remain resident; libzygisk must not be unmapped. */
    should_unmap_zygisk = false;
    return;
  }

  rz_module_sync_destroy(module);
  memset(module, 0, sizeof(*module));
}

static bool load_modules_only(void) {
  struct zygisk_modules ms;
  if (!rezygiskd_read_modules(&ms)) {
    LOGE("Failed to read modules from ReZygiskd");

    return false;
  }

  if (ms.modules_count == 0) {
    free_modules(&ms);
    return true;
  }

  zygisk_modules = (struct rezygisk_module *)calloc(ms.modules_count, sizeof(struct rezygisk_module));
  if (!zygisk_modules) {
    LOGE("Failed to allocate memory for modules");

    free_modules(&ms);

    return false;
  }

  for (size_t i = 0; i < ms.modules_count; i++) {
    const char *lib_path = ms.modules[i];
    struct rezygisk_module *module = &zygisk_modules[zygisk_module_length];
    memset(module, 0, sizeof(*module));
    if (!rz_module_sync_init(module)) {
      LOGE("Failed to initialize module execution lease for [%s]", lib_path);
      rezygiskd_remove_module(i);
      continue;
    }

    (void)rz_module_set_state(module, MODULE_STATE_LOADING);

    /*
     * Prefer CSOLoader, but do not make a module unavailable solely because
     * the custom linker cannot handle a device-/module-specific ELF feature.
     * A system handle is never stored in struct csoloader.
     */
    bool force_system_linker = requires_system_linker(lib_path);
    if (!force_system_linker && csoloader_load_serialized(&module->lib, lib_path)) {
      module->loader_backend = MODULE_LOADER_CSO;
    } else {
      if (force_system_linker)
        LOGI("Routing [%s] directly to Bionic linker by ELF compatibility policy", lib_path);
      else
        LOGW("CSOLoader rejected [%s]; retrying with the system linker", lib_path);
      dlerror();
      module->system_handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
      if (!module->system_handle) {
        const char *error = dlerror();
        LOGE("Both loaders failed for [%s]; system linker: %s",
             lib_path, error ? error : "unknown dlopen error");

        rezygiskd_remove_module(i);
        rz_module_sync_destroy(module);
        memset(module, 0, sizeof(*module));
        continue;
      }
      module->loader_backend = MODULE_LOADER_SYSTEM;
    }

    (void)rz_module_set_state(module, MODULE_STATE_IMAGE_LOADED);

    struct stat st;
    if (stat(lib_path, &st) != 0) {
      PLOGE("Failed to stat module [%s]", lib_path);
      release_unregistered_module(module, lib_path);
      rezygiskd_remove_module(i);
      continue;
    }

    module->dev = st.st_dev;
    module->ino = st.st_ino;

    void *entry = NULL;
    if (module->loader_backend == MODULE_LOADER_CSO) {
      entry = csoloader_get_symbol_serialized(&module->lib, "zygisk_module_entry");
    } else {
      dlerror();
      entry = dlsym(module->system_handle, "zygisk_module_entry");
      const char *error = dlerror();
      if (error) {
        LOGE("Failed to resolve zygisk_module_entry in [%s]: %s", lib_path, error);
        entry = NULL;
      }
    }

    if (!entry) {
      LOGE("Failed to find entry point in module [%s]", lib_path);
      release_unregistered_module(module, lib_path);
      rezygiskd_remove_module(i);
      continue;
    }

    module->api.register_module = rezygisk_module_register;
    module->api.impl = ENCODE_ID((void *)zygisk_module_length);
    module->zygisk_module_entry = (void (*)(void *, void *))entry;
    (void)rz_module_set_state(module, MODULE_STATE_ENTRY_RUNNING);

    LOGD("Loaded module [%s] using %s linker. Entry: %p", lib_path,
         module->loader_backend == MODULE_LOADER_CSO ? "CSO" : "system", entry);

    module->unload = false;
    (void)rz_module_set_state(module, MODULE_STATE_ACTIVE);
    zygisk_module_length++;
  }

  free_modules(&ms);

  return true;
}

static void rz_run_modules_pre(struct zygisk_context *ctx) {
  for (size_t i = 0; i < zygisk_module_length; i++) {
    rz_module_call_on_load(&zygisk_modules[i], ctx->env);

    if (FLAG_GET(ctx, APP_SPECIALIZE)) rz_module_call_pre_app_specialize(&zygisk_modules[i], ctx->args.app);
    else if (FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE)) rz_module_call_pre_server_specialize(&zygisk_modules[i], ctx->args.server);
  }
}

static void rz_run_modules_post(struct zygisk_context *ctx) {
  FLAG_SET(ctx, POST_SPECIALIZE);

  size_t modules_unloaded = 0;
  bool all_cso_modules_unloaded = true;
  bool had_cso_module = false;

  for (size_t i = 0; i < zygisk_module_length; i++) {
    struct rezygisk_module *m = &zygisk_modules[i];

    if (FLAG_GET(ctx, APP_SPECIALIZE)) rz_module_call_post_app_specialize(m, ctx->args.app);
    else if (FLAG_GET(ctx, SERVER_FORK_AND_SPECIALIZE)) rz_module_call_post_server_specialize(m, ctx->args.server);

    /*
     * No module callback may outlive loader metadata teardown. This applies
     * to intentional residency/abandon as well as explicit unload.
     */
    if (!rz_module_sync_close_and_wait(m)) {
      LOGE("Module [%s] still has active callbacks; retaining image",
           m->lib.lib_path ? m->lib.lib_path : "system-linker module");
      (void)rz_module_set_state(m, MODULE_STATE_RETAINED);
      if (m->loader_backend == MODULE_LOADER_CSO) {
        csoloader_pin();
        all_cso_modules_unloaded = false;
      }
      should_unmap_zygisk = false;
      continue;
    }

    if (m->loader_backend == MODULE_LOADER_CSO) {
      had_cso_module = true;
      if (!rz_module_unload_requested(m)) {
        LOGD("Abandoning CSOLoader image at %p", m->lib.img ? m->lib.img->header : NULL);
        csoloader_pin();
        all_cso_modules_unloaded = false;
        if (!csoloader_abandon_serialized(&m->lib)) {
          LOGE("Failed to abandon CSOLoader module safely");
          should_unmap_zygisk = false;
        }
        rz_module_sync_destroy(m);
        continue;
      }

      if (!csoloader_unload_serialized(&m->lib)) {
        LOGI("Deferring CSOLoader unload for [%s] until its final custom handle closes",
             m->lib.lib_path ? m->lib.lib_path : "(unknown)");
        all_cso_modules_unloaded = false;
        should_unmap_zygisk = false;
        (void)rz_module_set_state(m, MODULE_STATE_RETAINED);
        /* Keep the closed lease synchronization alive until the reaper
         * completes teardown. The final dlclose queues the image here. */
        continue;
      }
    } else if (m->loader_backend == MODULE_LOADER_SYSTEM) {
      if (!rz_module_unload_requested(m)) {
        /* Intentional residency: keep the dlopen reference and its handle alive. */
        LOGD("Keeping system-linker module resident: %p", m->system_handle);
        rz_module_sync_destroy(m);
        continue;
      }

      if (!m->system_handle || dlclose(m->system_handle) != 0) {
        const char *error = dlerror();
        LOGE("Failed to dlclose system-linker module: %s",
             error ? error : "invalid handle");
        should_unmap_zygisk = false;
        rz_module_sync_destroy(m);
        continue;
      }
      m->system_handle = NULL;
    }

    m->loader_backend = MODULE_LOADER_NONE;
    rz_module_sync_destroy(m);
    modules_unloaded++;
  }

  if (zygisk_module_length > 0)
    LOGD("Modules unloaded: %zu/%zu", modules_unloaded, zygisk_module_length);

  if (had_cso_module && all_cso_modules_unloaded)
    csoloader_deinit_if_safe();
}

static void rz_app_specialize_pre(struct zygisk_context *ctx) {
  FLAG_SET(ctx, APP_SPECIALIZE);

  /* INFO: Isolated services have different UIDs than the main apps. Because
              numerous root implementations base themselves in the UID of the
              app, we need to ensure that the UID sent to ReZygiskd to search
              is the app's and not the isolated service, or else it will be
              able to bypass DenyList.

           All apps, and isolated processes, of *third-party* applications will
             have their app_data_dir set. The system applications might not have
             one, however it is unlikely they will create an isolated process,
             and even if so, it should not impact in detections, performance or
             any area.
  */
  uid_t target_uid = *ctx->args.app->uid;
  uid_t uid = target_uid;
  if (IS_ISOLATED_SERVICE(uid) && ctx->args.app->app_data_dir) {
    /* INFO: If the app is an isolated service, we use the UID of the
               app's process data directory, which is the UID of the
               app itself, which root implementations actually use.
    */
    const char *data_dir = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, NULL);
    if (!data_dir) {
      LOGE("Failed to get app data directory");

      return;
    }

    struct stat st;
    if (stat(data_dir, &st) == -1) {
      PLOGE("Failed to stat app data directory [%s]", data_dir);

      (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, data_dir);

      return;
    }

    uid = st.st_uid;
    LOGD("Isolated service being related to UID %d, app data dir: %s", uid, data_dir);

    (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->app_data_dir, data_dir);
  }

  ctx->info_flags = rezygiskd_get_process_flags(uid, ctx->process);
  /* INFO: To ensure we are really using a clean mount namespace, we use
              the first process it as reference for clean mount namespace,
              before it even does something, so that it will be clean yet
              with expected mounts.

           To avoid duplication, we will bypass this update_mnt_ns if we
             are going to execute it later, as the app will be in the
             denylist.
  */
  if ((ctx->info_flags & PROCESS_IS_FIRST_STARTED) == PROCESS_IS_FIRST_STARTED &&
      (ctx->info_flags & PROCESS_ON_DENYLIST) == 0 &&
      (ctx->info_flags & PROCESS_IS_MANAGER) == 0
  ) {
    update_mnt_ns(Clean, target_uid, ctx->process, true);
  }

  if ((ctx->info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
    LOGD("Manager process detected. Notifying that Zygisk has been enabled.");


    /* INFO: This environment variable is related to Magisk Zygisk/Manager. It
               it used by Magisk's Zygisk to communicate to Magisk Manager whether
               Zygisk is working or not, allowing Zygisk modules to both work properly
               and for the manager to mark Zygisk as enabled.

             However, to enhance capabilities of root managers, it is also set for
               any other supported manager, so that, if they wish, they can recognize
               if Zygisk is enabled.
    */
    setenv("ZYGISK_ENABLED", "1", 1);
  }

  /* INFO: Modules only have two "start off" points from Zygisk, preSpecialize and
             postSpecialize. In preSpecialize, the process still has privileged
             permissions, and therefore can execute mount/umount/setns functions.
             If we update the mount namespace AFTER executing them, any mounts made
             will be lost, and the process will not have access to them anymore.

           In postSpecialize, while still could have its mounts modified with the
             assistance of a Zygisk companion, it will already have the mount
             namespace switched by then, so there won't be issues.

           Knowing this, we update the mns before execution, so that they can still
             make changes to mounts in DenyListed processes without being reverted.
  */
  bool in_denylist = (ctx->info_flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST;
  if (in_denylist) {
    FLAG_SET(ctx, DO_REVERT_UNMOUNT);
    update_mnt_ns(Clean, target_uid, ctx->process, false);
  }

  /* INFO: Executed after setns to ensure a module can update the mounts of an
              application without worrying about it being overwritten by setns.
  */
  rz_run_modules_pre(ctx);

  /* INFO: The modules may request that although the process is NOT in
              the DenyList, it has its mount namespace switched to the clean
              one.

              So to ensure this behavior happens, we must also check after the
              modules are loaded and executed, so that the modules can have
              the chance to request it.
  */
  if (!in_denylist && FLAG_GET(ctx, DO_REVERT_UNMOUNT))
    update_mnt_ns(Clean, target_uid, ctx->process, false);
}

static void rz_app_specialize_post(struct zygisk_context *ctx) {
  rz_run_modules_post(ctx);

  /*
   * Module callbacks have finished, so the retained module images are now
   * known. Anonymize only for processes whose mount traces are being reverted.
   */
  if (FLAG_GET(ctx, DO_REVERT_UNMOUNT)) {
    struct maps_info *libraries = get_loaded_libraries();
    if (libraries != NULL) {
      hide_module_maps(libraries);
      free_maps(libraries);
    } else {
      LOGW("anonymous-memory: unable to enumerate loaded libraries");
    }
  }

  /* INFO: Allow the process name string to be released */
  (*ctx->env)->ReleaseStringUTFChars(ctx->env, *ctx->args.app->nice_name, ctx->process);
  g_ctx = NULL;
}

static void rz_nativeSpecializeAppProcess_pre(struct zygisk_context *ctx) {
  ctx->process = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->nice_name, NULL);
  LOGV("pre specialize [%s]", ctx->process);

  FLAG_SET(ctx, SKIP_FD_SANITIZATION);
  rz_app_specialize_pre(ctx);
}

static void rz_nativeSpecializeAppProcess_post(struct zygisk_context *ctx) {
  LOGV("post specialize [%s]", ctx->process);
  rz_app_specialize_post(ctx);
}

static void rz_nativeForkSystemServer_pre(struct zygisk_context *ctx) {
  LOGV("pre forkSystemServer");
  FLAG_SET(ctx, SERVER_FORK_AND_SPECIALIZE);

  rz_fork_pre(ctx);
  if (!is_zygote_child(ctx)) return;

  rz_run_modules_pre(ctx);

  rz_sanitize_fds(ctx);
}

static void rz_nativeForkSystemServer_post(struct zygisk_context *ctx) {
  if (ctx->pid == 0) {
    LOGV("post forkSystemServer");

    rz_run_modules_post(ctx);
  }

  rz_fork_post(ctx);
}

static void rz_nativeForkAndSpecialize_pre(struct zygisk_context *ctx) {
  ctx->process = (*ctx->env)->GetStringUTFChars(ctx->env, *ctx->args.app->nice_name, NULL);
  LOGV("pre forkAndSpecialize [%s]", ctx->process);
  FLAG_SET(ctx, APP_FORK_AND_SPECIALIZE);

  rz_fork_pre(ctx);
  if (!is_zygote_child(ctx)) return;

  rz_app_specialize_pre(ctx);
  rz_sanitize_fds(ctx);
}

static void rz_nativeForkAndSpecialize_post(struct zygisk_context *ctx) {
  if (ctx->pid == 0) {
    LOGV("post forkAndSpecialize [%s]", ctx->process);
    rz_app_specialize_post(ctx);
  }

  rz_fork_post(ctx);
}

static void rz_init(struct zygisk_context *ctx, JNIEnv *env, void *args) {
  memset(ctx, 0, sizeof(struct zygisk_context));

  ctx->env = env;
  ctx->args.ptr = args;
  ctx->pid = -1;
  pthread_mutex_init(&ctx->hook_info_lock, NULL);

  g_ctx = ctx;
}

static void rz_cleanup(struct zygisk_context *ctx) {
  g_ctx = NULL;

  if (!is_zygote_child(ctx)) return;

  should_unmap_zygisk = true;

  /* INFO: Unhook JNI methods */
  for (size_t i = 0; i < jni_hook_list_count; i++) {
    struct jni_hook_entry *entry = &jni_hook_list[i];
    jclass jc = (*ctx->env)->FindClass(ctx->env, entry->class_name);
    if (jc) {
      if (entry->methods_count > 0 && (*ctx->env)->RegisterNatives(ctx->env, jc, entry->methods, (jint)entry->methods_count) != 0) {
        LOGE("Failed to restore JNI hook of class [%s]", entry->class_name);

        should_unmap_zygisk = false;
      }

      (*ctx->env)->DeleteLocalRef(ctx->env, jc);
    }

    free(entry->class_name);
    free(entry->methods);
  }

  free(jni_hook_list);
  jni_hook_list = NULL;
  jni_hook_list_count = 0;

  for (size_t i = 0; i < ctx->register_info_count; i++) {
    regfree(&ctx->register_info[i].regex);
    free(ctx->register_info[i].symbol);
  }
  ctx->register_info_count = 0;

  for (size_t i = 0; i < ctx->ignore_info_count; i++) {
    regfree(&ctx->ignore_info[i].regex);
    free(ctx->ignore_info[i].symbol);
  }
  ctx->ignore_info_count = 0;

  if (plt_hook_list) {
    for (size_t i = 0; i < plt_hook_list_count; i++) {
      free((void *)plt_hook_list[i].lib_path);
      free((void *)plt_hook_list[i].symbol);
    }

    free(plt_hook_list);
    plt_hook_list = NULL;
    plt_hook_list_count = 0;
  }

  /* Retained CSOLoader images may still have outstanding custom handles.
   * Their closed lease state and owner records must survive until the deferred
   * unload worker observes the final dlclose. */
  for (size_t i = 0; i < zygisk_module_length; i++) {
    struct rezygisk_module *m = &zygisk_modules[i];
    if (m->lifecycle_state == MODULE_STATE_RETAINED) {
      should_unmap_zygisk = false;
      continue;
    }
    rz_module_sync_destroy(m);
    memset(m, 0, sizeof(*m));
  }

  enable_unloader = true;
  pthread_mutex_destroy(&ctx->hook_info_lock);
}

/* INFO: PLT hook commit helper */

static bool hook_register(const char *lib_name, const char *symbol, bool is_prefix, void *new_func, void **backup) {
  if (!(is_prefix ? plti_add_hook_by_prefix : plti_add_hook)(&plti_ctx, lib_name, symbol, new_func, backup)) {
    LOGE("Failed to register plt_hook \"%s\" with PLTI", symbol);

    return false;
  }

  LOGD("Registered plt_hook for symbol \"%s\" in library \"%s\"", symbol, lib_name);

  return true;
}

static bool hook_unregister(const char *lib_name, const char *symbol, bool is_prefix, void **backup) {
  if (!(is_prefix ? plti_remove_hook_by_prefix : plti_remove_hook)(&plti_ctx, lib_name, symbol, backup)) {
    LOGE("Failed to unregister plt_hook \"%s\" with PLTI", symbol);

    should_unmap_zygisk = false;

    return false;
  }

  LOGD("Unregistered plt_hook for symbol \"%s\" in library \"%s\"", symbol, lib_name);

  return true;
}

#define PLT_HOOK_REGISTER_SYM(LIB, SYM, NAME, IS_PREFIX)                       \
  hook_register(LIB, SYM, IS_PREFIX, (void *)new_##NAME, (void **)&old_##NAME)

#define PLT_HOOK_REGISTER(LIB, SYM, IS_PREFIX)     \
  PLT_HOOK_REGISTER_SYM(LIB, #SYM, SYM, IS_PREFIX)

#define PLT_HOOK_UNREGISTER_SYM(LIB, SYM, NAME, IS_PREFIX)   \
  hook_unregister(LIB, SYM, IS_PREFIX, (void **)&old_##NAME)

#define PLT_HOOK_UNREGISTER(LIB, SYM, IS_PREFIX)     \
  PLT_HOOK_UNREGISTER_SYM(LIB, #SYM, SYM, IS_PREFIX)

void hook_functions(void) {
  plti_init(&plti_ctx);

  plti_add_lib(&plti_ctx, "libandroid_runtime.so");

  PLT_HOOK_REGISTER("libandroid_runtime.so", fork, false);
  PLT_HOOK_REGISTER("libandroid_runtime.so", strdup, false);
  PLT_HOOK_REGISTER("libandroid_runtime.so", property_get, false);
  PLT_HOOK_REGISTER_SYM("libandroid_runtime.so", "_ZNK18FileDescriptorInfo14ReopenOrDetach", _ZNK18FileDescriptorInfo14ReopenOrDetach, true);
}

static void hook_unloader(void) {
  if (!plti_add_lib(&plti_ctx, "libart.so")) {
    LOGE("Failed to add libart.so to PLTI");

    return;
  }

  PLT_HOOK_REGISTER("libart.so", pthread_attr_setstacksize, false);

  PLT_HOOK_UNREGISTER("libandroid_runtime.so", property_get, false);

  /* INFO: Load modules early on (before system server fork) to spread through all Zygotes */
  if (!load_modules_only()) {
    LOGE("Failed to load modules in hook_unloader");
  }

  LOGD("ReZygisk unloader hooked successfully");
}

static void unhook_functions(void) {
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", fork, false);
  PLT_HOOK_UNREGISTER("libandroid_runtime.so", strdup, false);
  PLT_HOOK_UNREGISTER_SYM("libandroid_runtime.so", "_ZNK18FileDescriptorInfo14ReopenOrDetach", _ZNK18FileDescriptorInfo14ReopenOrDetach, true);
  PLT_HOOK_UNREGISTER("libart.so", pthread_attr_setstacksize, false);
}
