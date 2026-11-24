#define LOG_TAG "zygisk-zn-api"

#include <dlfcn.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <plti.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"
#include "logging.h"
#include "socket_utils.h"
#include "zygisk_next_api.h"

struct ZnSymbolResolver {
  uintptr_t base;
  uintptr_t image_start;
  uintptr_t image_end;
  const Elf64_Sym *symtab;
  const char *strtab;
  size_t strsz;
  size_t symbol_count;
};

struct zn_module_handle {
  size_t manifest_index;
  int target_api_version;
  bool companion;
  void *dl_handle;
  char *module_id;
  char *library;
  int companion_broker_fd;
};

static struct zn_module_handle **g_zn_handles;
static size_t g_zn_handle_count;

static struct plti g_zn_plti;
static bool g_zn_plti_initialized;
static char g_main_executable_path[PATH_MAX];
static pthread_mutex_t g_zn_plti_mutex = PTHREAD_MUTEX_INITIALIZER;

struct plti_target_lookup {
  uintptr_t requested_base;
  const char *path;
  uintptr_t elf_header;
  bool found;
};

static int find_plti_target(struct dl_phdr_info *info, size_t size,
                            void *opaque) {
  (void)size;
  struct plti_target_lookup *lookup = opaque;
  uintptr_t header = (uintptr_t)info->dlpi_addr;
  for (Elf64_Half i = 0; i < info->dlpi_phnum; ++i) {
    const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
      header += (uintptr_t)phdr->p_vaddr;
      break;
    }
  }
  if ((uintptr_t)info->dlpi_addr != lookup->requested_base &&
      header != lookup->requested_base) return 0;
  if (!info->dlpi_name || !*info->dlpi_name) {
    ssize_t n = readlink("/proc/self/exe", g_main_executable_path,
                         sizeof(g_main_executable_path) - 1);
    if (n <= 0 || (size_t)n >= sizeof(g_main_executable_path)) return 0;
    g_main_executable_path[n] = '\0';
    lookup->path = g_main_executable_path;
  } else {
    lookup->path = info->dlpi_name;
  }
  lookup->elf_header = header;
  lookup->found = true;
  return 1;
}

static int api_plt_hook(void *base_addr, const char *symbol,
                        void *hook_handler, void **original) {
  if (!base_addr || !symbol || !*symbol || !hook_handler) return ZN_FAILED;

  struct plti_target_lookup lookup = {
    .requested_base = (uintptr_t)base_addr,
    .path = NULL,
    .elf_header = 0,
    .found = false
  };
  dl_iterate_phdr(find_plti_target, &lookup);
  if (!lookup.found || !lookup.path) {
    LOGW("ZN pltHook could not resolve library base %p", base_addr);
    return ZN_FAILED;
  }

  pthread_mutex_lock(&g_zn_plti_mutex);
  if (!g_zn_plti_initialized) {
    g_zn_plti_initialized = plti_init(&g_zn_plti);
  }

  bool ok = g_zn_plti_initialized &&
            plti_add_manual_lib(&g_zn_plti, lookup.path, lookup.elf_header);
  if (ok && original && *original && hook_handler == *original) {
    ok = plti_remove_hook(&g_zn_plti, lookup.path, symbol, original);
  } else if (ok) {
    ok = plti_add_hook(&g_zn_plti, lookup.path, symbol,
                       hook_handler, original);
  }
  pthread_mutex_unlock(&g_zn_plti_mutex);

  if (!ok) LOGW("ZN pltHook failed for %s in %s", symbol, lookup.path);
  return ok ? ZN_SUCCESS : ZN_FAILED;
}

static int api_unsupported_inline_hook(void *target, void *handler,
                                       void **original) {
  (void)target; (void)handler; (void)original;
  LOGW("ZN inlineHook backend is not initialized");
  return ZN_FAILED;
}

static int api_unsupported_inline_unhook(void *target) {
  (void)target;
  LOGW("ZN inlineUnhook backend is not initialized");
  return ZN_FAILED;
}

static bool hyos_in_child(void);
static bool is_hyos_spawner(void);

static int connect_zn_companion_via_broker(int broker_fd) {
  if (broker_fd < 0) return -1;
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    PLOGE("create ZN companion client socketpair");
    return -1;
  }

  struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
  (void)setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout));
  if (write_fd(broker_fd, sockets[1]) != 1) {
    LOGE("Failed sending ZN companion client FD through broker");
    close(sockets[0]);
    close(sockets[1]);
    return -1;
  }
  close(sockets[1]);

  uint8_t ack = 0;
  if (read_uint8_t(sockets[0], &ack) != sizeof(ack) || ack != 1) {
    LOGE("ZN companion broker did not acknowledge the connection");
    close(sockets[0]);
    return -1;
  }

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  (void)setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout));
  return sockets[0];
}

static int create_zn_companion_broker(const char *library) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    PLOGE("create ZN companion broker socketpair");
    return -1;
  }

  struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
  (void)setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   sizeof(timeout));
  if (!rezygiskd_register_zn_companion_broker(library, sockets[1])) {
    LOGW("Failed to register ZN companion broker for %s", library);
    close(sockets[0]);
    close(sockets[1]);
    return -1;
  }
  close(sockets[1]);
  LOGI("Registered inherited ZN companion broker for %s", library);
  return sockets[0];
}

static int api_connect_companion(void *opaque) {
  const struct zn_module_handle *handle = opaque;
  if (!handle || !handle->companion || handle->target_api_version < 3)
    return -1;
  if (hyos_in_child() && is_hyos_spawner()) {
    if (handle->companion_broker_fd >= 0)
      return connect_zn_companion_via_broker(handle->companion_broker_fd);
    LOGW("HyperOS child has no inherited ZN companion broker");
    return -1;
  }
  return rezygiskd_connect_zn_companion(handle->manifest_index);
}

#define ZN_MAX_HYOS_MODULES 16

typedef int (*hyos_setcontext_fn)(uid_t uid, int is_system_server,
                                  const char *se_info, const char *package_name);
typedef int (*hyos_setname_fn)(pthread_t thread, const char *name);

static struct ZygiskNextHyosModule g_hyos_modules[ZN_MAX_HYOS_MODULES];
static size_t g_hyos_module_count;
static bool g_hyos_runtime_enabled;
static bool g_hyos_fired;
static bool g_hyos_atfork_registered;
static pid_t g_hyos_spawner_pid;
static char g_hyos_captured_name[256];
static bool g_hyos_has_captured_name;
static hyos_setcontext_fn g_hyos_orig_setcontext;
static hyos_setname_fn g_hyos_orig_setname;

static pid_t raw_getpid(void) {
  return (pid_t)syscall(SYS_getpid);
}

static bool hyos_in_child(void) {
  return g_hyos_spawner_pid > 0 && raw_getpid() != g_hyos_spawner_pid;
}

static bool is_hyos_spawner(void) {
  char path[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (n <= 0 || (size_t)n >= sizeof(path)) return false;
  path[n] = '\0';

  static const char deleted_suffix[] = " (deleted)";
  size_t length = strlen(path);
  const size_t suffix_length = sizeof(deleted_suffix) - 1;
  if (length >= suffix_length &&
      strcmp(path + length - suffix_length, deleted_suffix) == 0)
    path[length - suffix_length] = '\0', length -= suffix_length;

  const char *suffix = "/hyos_spawner";
  size_t suffix_len = sizeof(suffix) - 1;
  return length >= suffix_len &&
         strcmp(path + length - suffix_len, suffix) == 0;
}

static bool read_process_cmdline(char *out, size_t capacity) {
  if (!out || capacity < 2) return false;
  int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t n;
  do {
    n = read(fd, out, capacity - 1);
  } while (n < 0 && errno == EINTR);
  close(fd);
  if (n <= 0) return false;
  size_t length = strnlen(out, (size_t)n);
  out[length] = '\0';
  return length != 0;
}

static bool is_spawner_cmdline(const char *name) {
  return !name || !*name || strcmp(name, "usap64") == 0 ||
         strcmp(name, "usap32") == 0 || strcmp(name, "hyos_spawner") == 0;
}

static void hyos_deliver_app_specialized(const char *package_name,
                                         const char *se_info) {
  if (!hyos_in_child() || g_hyos_fired || g_hyos_module_count == 0) return;
  g_hyos_fired = true;

  char process_name[256] = {0};
  char package_copy[256] = {0};
  char se_info_copy[512] = {0};
  if (package_name) snprintf(package_copy, sizeof(package_copy), "%s", package_name);
  if (se_info) snprintf(se_info_copy, sizeof(se_info_copy), "%s", se_info);

  char cmdline[256] = {0};
  if (read_process_cmdline(cmdline, sizeof(cmdline)) &&
      !is_spawner_cmdline(cmdline)) {
    snprintf(process_name, sizeof(process_name), "%s", cmdline);
  } else if (g_hyos_has_captured_name && g_hyos_captured_name[0]) {
    size_t captured_len = strlen(g_hyos_captured_name);
    size_t package_len = strlen(package_copy);
    if (captured_len == 15 && package_len > captured_len &&
        strcmp(package_copy + package_len - captured_len,
               g_hyos_captured_name) == 0) {
      snprintf(process_name, sizeof(process_name), "%s", package_copy);
    } else {
      snprintf(process_name, sizeof(process_name), "%s",
               g_hyos_captured_name);
    }
  } else if (prctl(PR_GET_NAME, process_name, 0, 0, 0) != 0 ||
             process_name[0] == '\0' || is_spawner_cmdline(process_name)) {
    snprintf(process_name, sizeof(process_name), "%s",
             package_copy[0] ? package_copy : "hyos_app");
  }

  const struct ZnHyosAppSpecializeArgs args = {
    .process_name = process_name,
    .package_name = package_copy,
    .se_info = se_info_copy
  };
  LOGI("HyperOS app specialized: process=%s package=%s se_info=%s",
       process_name, package_copy, se_info_copy);

  for (size_t i = 0; i < g_hyos_module_count; ++i) {
    if (g_hyos_modules[i].onAppSpecialized)
      g_hyos_modules[i].onAppSpecialized(&args);
  }
}

static int hyos_setcontext_hook(uid_t uid, int is_system_server,
                                const char *se_info,
                                const char *package_name) {
  int result = g_hyos_orig_setcontext
                   ? g_hyos_orig_setcontext(uid, is_system_server, se_info,
                                            package_name)
                   : -1;
  if (result == 0) hyos_deliver_app_specialized(package_name, se_info);
  else if (hyos_in_child() && !g_hyos_fired)
    LOGW("HyperOS selinux_android_setcontext failed: %d", result);
  return result;
}

static int hyos_setname_hook(pthread_t thread, const char *name) {
  int result = g_hyos_orig_setname
                   ? g_hyos_orig_setname(thread, name)
                   : -1;
  if (result == 0 && name && name[0] && hyos_in_child() &&
      !g_hyos_fired && !g_hyos_has_captured_name &&
      pthread_equal(thread, pthread_self())) {
    snprintf(g_hyos_captured_name, sizeof(g_hyos_captured_name), "%s", name);
    g_hyos_has_captured_name = true;
    LOGD("HyperOS captured process name: %s", g_hyos_captured_name);
  }
  return result;
}

static void hyos_atfork_child(void) {
  g_hyos_fired = false;
  g_hyos_has_captured_name = false;
  g_hyos_captured_name[0] = '\0';
}

struct hyos_main_base_lookup {
  uintptr_t base;
};

static int hyos_find_main_base(struct dl_phdr_info *info, size_t size,
                               void *opaque) {
  (void)size;
  struct hyos_main_base_lookup *lookup = opaque;
  if (info->dlpi_name && info->dlpi_name[0]) return 0;
  lookup->base = (uintptr_t)info->dlpi_addr;
  return 1;
}

static void hyos_install_hooks(void) {
  if (!g_hyos_spawner_pid || !g_hyos_module_count) return;

  /* Hook only the hyos_spawner executable's PLT callers. */
  struct hyos_main_base_lookup lookup = {0};
  dl_iterate_phdr(hyos_find_main_base, &lookup);
  uintptr_t base = lookup.base;
  if (!base) {
    LOGW("HyperOS could not locate hyos_spawner load bias");
    return;
  }

  if (!g_hyos_orig_setcontext) {
    void *original = NULL;
    if (api_plt_hook((void *)base, "selinux_android_setcontext",
                     (void *)hyos_setcontext_hook, &original) == ZN_SUCCESS) {
      g_hyos_orig_setcontext = (hyos_setcontext_fn)original;
      LOGI("HyperOS PLT hooked selinux_android_setcontext");
    } else {
      LOGW("HyperOS PLT hook failed for selinux_android_setcontext");
    }
  }

  if (!g_hyos_orig_setname) {
    void *original = NULL;
    if (api_plt_hook((void *)base, "pthread_setname_np",
                     (void *)hyos_setname_hook, &original) == ZN_SUCCESS) {
      g_hyos_orig_setname = (hyos_setname_fn)original;
      LOGI("HyperOS PLT hooked pthread_setname_np");
    } else {
      LOGW("HyperOS PLT hook failed for pthread_setname_np");
    }
  }
}

static int api_hyos_register_module(const void *opaque) {
  if (!opaque || !g_hyos_runtime_enabled || !g_hyos_spawner_pid ||
      raw_getpid() != g_hyos_spawner_pid) return ZN_FAILED;
  const struct ZygiskNextHyosModule *module = opaque;
  if (module->target_api_version < 1 ||
      module->target_api_version > ZYGISK_NEXT_HYOS_API_VERSION ||
      !module->onAppSpecialized ||
      g_hyos_module_count >= ZN_MAX_HYOS_MODULES) {
    LOGW("Rejecting invalid or unsupported HyperOS Runtime module");
    return ZN_FAILED;
  }

  g_hyos_modules[g_hyos_module_count++] = *module;
  if (!g_hyos_atfork_registered) {
    if (pthread_atfork(NULL, NULL, hyos_atfork_child) == 0)
      g_hyos_atfork_registered = true;
  }
  hyos_install_hooks();
  if (!g_hyos_orig_setcontext) {
    --g_hyos_module_count;
    LOGW("HyperOS Runtime registration failed: specialization hook unavailable");
    return ZN_FAILED;
  }
  LOGI("Registered HyperOS Runtime module (%zu)", g_hyos_module_count);
  return ZN_SUCCESS;
}

static const struct ZygiskNextRuntime g_hyos_runtime = {
  .type = ZN_RUNTIME_HYOS,
  .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
  .registerModule = api_hyos_register_module
};

static const struct ZygiskNextRuntime *api_get_runtime(void) {
  if (!is_hyos_spawner()) return NULL;
  if (!g_hyos_runtime_enabled) {
    g_hyos_spawner_pid = raw_getpid();
    g_hyos_runtime_enabled = true;
    LOGI("Detected HyperOS Rust Runtime spawner pid=%d", g_hyos_spawner_pid);
  }
  return &g_hyos_runtime;
}

static bool address_in_image(uintptr_t start, uintptr_t end,
                             const void *address, size_t size) {
  uintptr_t p = (uintptr_t)address;
  return p >= start && p <= end && size <= end - p;
}

struct resolver_lookup {
  const char *path;
  uintptr_t requested_base;
  struct ZnSymbolResolver *resolver;
  bool found;
};

static uintptr_t dynamic_pointer(uintptr_t base, uintptr_t start,
                                 uintptr_t end, Elf64_Addr value) {
  uintptr_t p = (uintptr_t)value;
  if (p >= start && p < end) return p;
  if (value <= UINTPTR_MAX - base) {
    p = base + (uintptr_t)value;
    if (p >= start && p < end) return p;
  }
  return 0;
}

static bool resolve_symbol_count(struct ZnSymbolResolver *resolver,
                                 const uint32_t *sysv_hash,
                                 const uint32_t *gnu_hash) {
  if (sysv_hash &&
      address_in_image(resolver->image_start, resolver->image_end,
                       sysv_hash, 2 * sizeof(uint32_t))) {
    resolver->symbol_count = sysv_hash[1];
    return resolver->symbol_count <= 1u << 20;
  }

  if (!gnu_hash ||
      !address_in_image(resolver->image_start, resolver->image_end,
                        gnu_hash, 4 * sizeof(uint32_t))) return false;

  const uint32_t bucket_count = gnu_hash[0];
  const uint32_t symbol_offset = gnu_hash[1];
  const uint32_t bloom_count = gnu_hash[2];
  if (!bucket_count || !bloom_count || bucket_count > (1u << 20) ||
      bloom_count > (1u << 20) || symbol_offset > (1u << 20)) return false;

  const uintptr_t bloom_addr = (uintptr_t)(gnu_hash + 4);
  const size_t bloom_bytes = (size_t)bloom_count * sizeof(Elf64_Xword);
  if (!address_in_image(resolver->image_start, resolver->image_end,
                        (void *)bloom_addr, bloom_bytes)) return false;
  const uint32_t *buckets =
      (const uint32_t *)(bloom_addr + bloom_bytes);
  const size_t bucket_bytes = (size_t)bucket_count * sizeof(uint32_t);
  if (!address_in_image(resolver->image_start, resolver->image_end,
                        buckets, bucket_bytes)) return false;

  const uint32_t *chains = buckets + bucket_count;
  size_t max_symbols = symbol_offset;
  for (uint32_t i = 0; i < bucket_count; ++i) {
    uint32_t index = buckets[i];
    if (index < symbol_offset) continue;
    if (index - symbol_offset > (1u << 20)) return false;

    for (size_t steps = 0; steps < (1u << 20); ++steps, ++index) {
      const size_t chain_index = (size_t)(index - symbol_offset);
      if (!address_in_image(resolver->image_start, resolver->image_end,
                            chains + chain_index, sizeof(uint32_t)))
        return false;
      uint32_t chain = chains[chain_index];
      if ((size_t)index + 1 > max_symbols) max_symbols = (size_t)index + 1;
      if (chain & 1u) break;
      if (steps == (1u << 20) - 1) return false;
    }
  }
  resolver->symbol_count = max_symbols;
  return max_symbols > symbol_offset && max_symbols <= (1u << 20);
}

static int resolver_find_image(struct dl_phdr_info *info, size_t size,
                               void *opaque) {
  (void)size;
  struct resolver_lookup *lookup = opaque;
  if (lookup->requested_base && info->dlpi_addr != lookup->requested_base)
    return 0;

  const char *loaded_path = info->dlpi_name ? info->dlpi_name : "";
  const char *loaded_base = strrchr(loaded_path, '/');
  loaded_base = loaded_base ? loaded_base + 1 : loaded_path;
  const char *requested_base = strrchr(lookup->path, '/');
  requested_base = requested_base ? requested_base + 1 : lookup->path;

  if (!lookup->requested_base &&
      strcmp(loaded_path, lookup->path) != 0 &&
      strcmp(loaded_base, requested_base) != 0) return 0;

  uintptr_t image_start = UINTPTR_MAX;
  uintptr_t image_end = 0;
  Elf64_Dyn *dynamic = NULL;
  for (Elf64_Half i = 0; i < info->dlpi_phnum; ++i) {
    const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type == PT_LOAD) {
      uintptr_t start = (uintptr_t)info->dlpi_addr + phdr->p_vaddr;
      uintptr_t end = start + phdr->p_memsz;
      if (start < image_start) image_start = start;
      if (end > image_end) image_end = end;
    } else if (phdr->p_type == PT_DYNAMIC) {
      dynamic = (Elf64_Dyn *)((uintptr_t)info->dlpi_addr + phdr->p_vaddr);
    }
  }
  if (!dynamic || image_start >= image_end ||
      !address_in_image(image_start, image_end, dynamic, sizeof(Elf64_Dyn)))
    return 0;

  Elf64_Addr symtab_value = 0, strtab_value = 0;
  Elf64_Addr hash_value = 0, gnu_hash_value = 0;
  size_t strsz = 0, syment = 0;
  for (Elf64_Dyn *d = dynamic;
       address_in_image(image_start, image_end, d, sizeof(*d)) &&
       d->d_tag != DT_NULL; ++d) {
    switch (d->d_tag) {
      case DT_SYMTAB: symtab_value = d->d_un.d_ptr; break;
      case DT_STRTAB: strtab_value = d->d_un.d_ptr; break;
      case DT_STRSZ: strsz = (size_t)d->d_un.d_val; break;
      case DT_SYMENT: syment = (size_t)d->d_un.d_val; break;
      case DT_HASH: hash_value = d->d_un.d_ptr; break;
#ifdef DT_GNU_HASH
      case DT_GNU_HASH: gnu_hash_value = d->d_un.d_ptr; break;
#endif
      default: break;
    }
  }

  uintptr_t symtab_addr = dynamic_pointer(info->dlpi_addr, image_start,
                                          image_end, symtab_value);
  uintptr_t strtab_addr = dynamic_pointer(info->dlpi_addr, image_start,
                                          image_end, strtab_value);
  uintptr_t hash_addr = dynamic_pointer(info->dlpi_addr, image_start,
                                        image_end, hash_value);
  uintptr_t gnu_hash_addr = dynamic_pointer(info->dlpi_addr, image_start,
                                             image_end, gnu_hash_value);
  if (!symtab_addr || !strtab_addr || !strsz || syment != sizeof(Elf64_Sym) ||
      !address_in_image(image_start, image_end, (void *)strtab_addr, strsz))
    return 0;

  struct ZnSymbolResolver *resolver = calloc(1, sizeof(*resolver));
  if (!resolver) return 0;
  resolver->base = (uintptr_t)info->dlpi_addr;
  resolver->image_start = image_start;
  resolver->image_end = image_end;
  resolver->symtab = (const Elf64_Sym *)symtab_addr;
  resolver->strtab = (const char *)strtab_addr;
  resolver->strsz = strsz;

  if (!resolve_symbol_count(resolver, (const uint32_t *)hash_addr,
                            (const uint32_t *)gnu_hash_addr) ||
      !address_in_image(image_start, image_end, resolver->symtab,
                        resolver->symbol_count * sizeof(Elf64_Sym))) {
    free(resolver);
    return 0;
  }

  lookup->resolver = resolver;
  lookup->found = true;
  return 1;
}

static struct ZnSymbolResolver *api_new_symbol_resolver(const char *path,
                                                         void *base_addr) {
  if (!path && !base_addr) return NULL;
  struct resolver_lookup lookup = {
    .path = path ? path : "",
    .requested_base = (uintptr_t)base_addr,
    .resolver = NULL,
    .found = false
  };
  dl_iterate_phdr(resolver_find_image, &lookup);
  return lookup.found ? lookup.resolver : NULL;
}

static void api_free_symbol_resolver(struct ZnSymbolResolver *resolver) {
  free(resolver);
}

static void *api_get_base_address(struct ZnSymbolResolver *resolver) {
  return resolver ? (void *)resolver->base : NULL;
}

static void *api_symbol_lookup(struct ZnSymbolResolver *resolver,
                               const char *name, bool prefix, size_t *size) {
  if (!resolver || !name) return NULL;
  const size_t name_len = strlen(name);
  for (size_t i = 0; i < resolver->symbol_count; ++i) {
    const Elf64_Sym *symbol = &resolver->symtab[i];
    if (symbol->st_name >= resolver->strsz ||
        symbol->st_shndx == SHN_UNDEF) continue;
    const char *symbol_name = resolver->strtab + symbol->st_name;
    size_t remaining = resolver->strsz - symbol->st_name;
    if (!memchr(symbol_name, '\0', remaining)) continue;
    bool matched = prefix ? strncmp(symbol_name, name, name_len) == 0
                          : strcmp(symbol_name, name) == 0;
    if (!matched) continue;
    if (size) *size = (size_t)symbol->st_size;
    uintptr_t address = symbol->st_shndx == SHN_ABS
                            ? (uintptr_t)symbol->st_value
                            : resolver->base + (uintptr_t)symbol->st_value;
    return (void *)address;
  }
  return NULL;
}

static void api_for_each_symbols(
    struct ZnSymbolResolver *resolver,
    bool (*callback)(const char *name, void *addr, size_t size, void *data),
    void *data) {
  if (!resolver || !callback) return;
  for (size_t i = 0; i < resolver->symbol_count; ++i) {
    const Elf64_Sym *symbol = &resolver->symtab[i];
    if (symbol->st_name >= resolver->strsz ||
        symbol->st_shndx == SHN_UNDEF) continue;
    const char *name = resolver->strtab + symbol->st_name;
    if (!*name || !memchr(name, '\0', resolver->strsz - symbol->st_name))
      continue;
    uintptr_t address = symbol->st_shndx == SHN_ABS
                            ? (uintptr_t)symbol->st_value
                            : resolver->base + (uintptr_t)symbol->st_value;
    if (!callback(name, (void *)address, (size_t)symbol->st_size, data))
      break;
  }
}

static const struct ZygiskNextAPI g_zn_api = {
  .pltHook = api_plt_hook,
  .inlineHook = api_unsupported_inline_hook,
  .inlineUnhook = api_unsupported_inline_unhook,
  .newSymbolResolver = api_new_symbol_resolver,
  .freeSymbolResolver = api_free_symbol_resolver,
  .getBaseAddress = api_get_base_address,
  .symbolLookup = api_symbol_lookup,
  .forEachSymbols = api_for_each_symbols,
  .connectCompanion = api_connect_companion,
  .getRuntime = api_get_runtime
};

static bool target_matches(const struct zn_module_info *entry,
                           const char *exe_path) {
  if (entry->target_type == ZN_TARGET_PATH)
    return strcmp(entry->target, exe_path) == 0;
  const char *base = strrchr(exe_path, '/');
  base = base ? base + 1 : exe_path;
  return entry->target_type == ZN_TARGET_NAME &&
         strcmp(entry->target, base) == 0;
}

static bool already_loaded(const char *module_id, const char *library) {
  for (size_t i = 0; i < g_zn_handle_count; ++i) {
    const struct zn_module_handle *loaded = g_zn_handles[i];
    if (strcmp(loaded->module_id, module_id) == 0 &&
        strcmp(loaded->library, library) == 0) return true;
  }
  return false;
}

bool zn_modules_load_for_current_process(void) {
  if (is_hyos_spawner() && !g_hyos_spawner_pid) {
    g_hyos_spawner_pid = raw_getpid();
    g_hyos_runtime_enabled = true;
    LOGI("Detected HyperOS Rust Runtime spawner pid=%d", g_hyos_spawner_pid);
  }

  char exe_path[PATH_MAX];
  ssize_t path_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (path_len <= 0 || (size_t)path_len >= sizeof(exe_path)) {
    PLOGE("readlink /proc/self/exe");
    return false;
  }
  exe_path[path_len] = '\0';
  static const char deleted_suffix[] = " (deleted)";
  size_t exe_len = strlen(exe_path);
  size_t suffix_len = sizeof(deleted_suffix) - 1;
  if (exe_len >= suffix_len &&
      strcmp(exe_path + exe_len - suffix_len, deleted_suffix) == 0)
    exe_path[exe_len - suffix_len] = '\0';

  struct zn_module_list modules = {0};
  if (!rezygiskd_read_zn_modules(&modules)) {
    LOGE("Failed to read ZN module manifest inventory");
    return false;
  }

  bool loaded_any = false;
  for (size_t i = 0; i < modules.count; ++i) {
    struct zn_module_info *entry = &modules.items[i];
    if (!target_matches(entry, exe_path) ||
        already_loaded(entry->module_id, entry->library)) continue;

    int image_fd = rezygiskd_get_zn_module_fd(i);
    if (image_fd < 0) {
      LOGE("Failed to obtain module image for %s", entry->module_id);
      continue;
    }

    (void)fcntl(image_fd, F_SETFD, FD_CLOEXEC);
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", image_fd);
    void *handle = dlopen(fd_path, RTLD_NOW | RTLD_LOCAL);
    close(image_fd);
    if (!handle) {
      LOGE("dlopen ZN module %s failed: %s", entry->module_id, dlerror());
      continue;
    }

    struct ZygiskNextModule *module =
        (struct ZygiskNextModule *)dlsym(handle, "zn_module");
    if (!module || !module->onModuleLoaded ||
        (module->target_api_version != 3 &&
         module->target_api_version != ZYGISK_NEXT_API_VERSION)) {
      LOGW("Rejecting ZN module %s: invalid entry or unsupported API version",
           entry->module_id);
      dlclose(handle);
      continue;
    }

    struct zn_module_handle *self = calloc(1, sizeof(*self));
    if (!self) {
      PLOGE("allocate ZN module handle");
      dlclose(handle);
      continue;
    }
    self->manifest_index = i;
    self->target_api_version = module->target_api_version;
    self->companion = entry->companion;
    self->dl_handle = handle;
    self->module_id = strdup(entry->module_id);
    self->library = strdup(entry->library);
    self->companion_broker_fd = -1;
    if (!self->module_id || !self->library ||
        g_zn_handle_count >= SIZE_MAX / sizeof(*g_zn_handles)) {
      LOGE("Failed to retain ZN module identity for %s", entry->module_id);
      free(self->module_id);
      free(self->library);
      free(self);
      dlclose(handle);
      continue;
    }

    struct zn_module_handle **new_handles =
        realloc(g_zn_handles,
                (g_zn_handle_count + 1) * sizeof(*g_zn_handles));
    if (!new_handles) {
      PLOGE("grow ZN module handle list");
      free(self->module_id);
      free(self->library);
      free(self);
      dlclose(handle);
      continue;
    }
    g_zn_handles = new_handles;
    g_zn_handles[g_zn_handle_count++] = self;

    if (entry->companion && module->target_api_version >= 3 &&
        is_hyos_spawner()) {
      self->companion_broker_fd = create_zn_companion_broker(entry->library);
    }

    LOGI("Loading ZN module %s (API v%d) for %s",
         entry->module_id, module->target_api_version, exe_path);
    module->onModuleLoaded(self, &g_zn_api);
    loaded_any = true;
  }

  rezygiskd_free_zn_modules(&modules);
  return loaded_any;
}
