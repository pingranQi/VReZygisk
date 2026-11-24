#define LOG_TAG "zygisk-zn-api"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
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
  void *dl_handle;
};

static struct zn_module_handle **g_zn_handles;
static size_t g_zn_handle_count;

static int api_unsupported_plt_hook(void *base, const char *symbol,
                                    void *handler, void **original) {
  (void)base; (void)symbol; (void)handler; (void)original;
  LOGW("ZN pltHook backend is not initialized");
  return ZN_FAILED;
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

static int api_connect_companion(void *opaque) {
  const struct zn_module_handle *handle = opaque;
  if (!handle) return -1;
  return rezygiskd_connect_zn_companion(handle->manifest_index);
}

static const struct ZygiskNextRuntime *api_get_runtime(void) {
  /* HyperOS Runtime is registered in a later integration stage. */
  return NULL;
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
  .pltHook = api_unsupported_plt_hook,
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
  (void)module_id;
  (void)library;
  /* dlopen() reference-counts the same memfd path; keep one callback per
   * manifest row for now because each row has its own companion handle. */
  return false;
}

bool zn_modules_load_for_current_process(void) {
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
    self->dl_handle = handle;

    struct zn_module_handle **new_handles =
        realloc(g_zn_handles,
                (g_zn_handle_count + 1) * sizeof(*g_zn_handles));
    if (!new_handles) {
      PLOGE("grow ZN module handle list");
      free(self);
      dlclose(handle);
      continue;
    }
    g_zn_handles = new_handles;
    g_zn_handles[g_zn_handle_count++] = self;

    LOGI("Loading ZN module %s (API v%d) for %s",
         entry->module_id, module->target_api_version, exe_path);
    module->onModuleLoaded(self, &g_zn_api);
    loaded_any = true;
  }

  rezygiskd_free_zn_modules(&modules);
  return loaded_any;
}
