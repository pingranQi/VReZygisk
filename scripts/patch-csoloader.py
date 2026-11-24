#!/usr/bin/env python3
"""Apply the VReZygisk TLS hardening delta to the pinned CSOLoader submodule.

The upstream dependency remains pinned. This script is idempotent and is run
before compiling CSOLoader, so CI and local builds use the same reviewed patch.
"""
from pathlib import Path
import sys

MARKER = "/* VREZYGISK_TLS_GENERATION_GUARD */"
REGISTRATION_MARKER = "/* VREZYGISK_TLS_REGISTRATION_FAILURE_GUARD */"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source anchor, found {count}")
    return source.replace(old, new, 1)



def patch_csoloader_api(path: Path) -> None:
    marker = "/* VREZYGISK_PREALLOCATE_LIBRARY_PATH */"
    source = path.read_text()
    if marker in source:
        return

    source = replace_once(
        source,
        """bool csoloader_load(struct csoloader *lib, const char *lib_path) {
  struct loaded_dep dep_info = { 0 };
  void *map_start = linker_load_library_manually(lib_path, &dep_info);
  if (!map_start) {
    LOGE("Failed to load library: %s", lib_path);

    return false;
  }

  struct csoloader_elf *elf_image = csoloader_elf_create(lib_path, map_start);
  if (!elf_image) {
    LOGE("Failed to create ELF image for %s", lib_path);

    if (dep_info.map_size > 0)
      munmap(map_start, dep_info.map_size);

    return false;
  }

  if (!linker_init(&lib->linker, elf_image)) {
    LOGE("Failed to initialize linker for %s", lib_path);

    csoloader_elf_destroy(elf_image);
    if (dep_info.map_size > 0)
      munmap(map_start, dep_info.map_size);

    return false;
  }

  lib->linker.main_map_size = dep_info.map_size;

  if (!linker_link(&lib->linker)) {
    LOGE("Linker failed to link %s", lib_path);

    linker_destroy(&lib->linker);

    return false;
  }

  lib->img = elf_image;
  lib->lib_path = strdup(lib_path);
  if (!lib->lib_path) {
    LOGE("Failed to duplicate library path string");

    linker_destroy(&lib->linker);

    return false;
  }

  return true;
}""",
        """bool csoloader_load(struct csoloader *lib, const char *lib_path) {
  if (!lib || !lib_path || lib->img || lib->lib_path) return false;

  /* Allocate all bookkeeping before mapping or executing module code. This
   * ensures an allocation failure cannot trigger Bionic fallback after the
   * custom loader has already run constructors. */
  char *path_copy = strdup(lib_path);
  if (!path_copy) {
    LOGE("Failed to duplicate library path string");
    return false;
  }

  struct loaded_dep dep_info = { 0 };
  void *map_start = linker_load_library_manually(lib_path, &dep_info);
  if (!map_start) {
    LOGE("Failed to load library: %s", lib_path);
    free(path_copy);
    return false;
  }

  struct csoloader_elf *elf_image = csoloader_elf_create(lib_path, map_start);
  if (!elf_image) {
    LOGE("Failed to create ELF image for %s", lib_path);
    if (dep_info.map_size > 0) munmap(map_start, dep_info.map_size);
    free(path_copy);
    return false;
  }

  if (!linker_init(&lib->linker, elf_image)) {
    LOGE("Failed to initialize linker for %s", lib_path);
    csoloader_elf_destroy(elf_image);
    if (dep_info.map_size > 0) munmap(map_start, dep_info.map_size);
    free(path_copy);
    return false;
  }

  lib->linker.main_map_size = dep_info.map_size;
  if (!linker_link(&lib->linker)) {
    LOGE("Linker failed to link %s", lib_path);
    linker_destroy(&lib->linker);
    free(path_copy);
    return false;
  }

  lib->img = elf_image;
  lib->lib_path = path_copy;
  return true;
}

/* VREZYGISK_PREALLOCATE_LIBRARY_PATH */""",
        "preallocate CSOLoader path before constructors",
    )
    path.write_text(source)



def patch_csoloader_lifecycle(linker_path: Path) -> None:
    header_path = linker_path.parent.parent / "include" / "linker.h"
    header = header_path.read_text()
    header_marker = "/* VREZYGISK_IMAGE_LIFECYCLE */"
    if header_marker not in header:
        header = replace_once(
            header,
            """struct loaded_dep {
  /* INFO: DO NOT change this 2 members from order. Keep consistent with linker structure */
  struct csoloader_elf *img;
  struct tls_indices_data tls_indices;

  bool is_manual_load;""",
            """enum linker_image_state {
  LINKER_IMAGE_UNINITIALIZED = 0,
  LINKER_IMAGE_CONSTRUCTING,
  LINKER_IMAGE_CONSTRUCTED,
  LINKER_IMAGE_FINALIZING,
  LINKER_IMAGE_FINALIZED
};

/* VREZYGISK_IMAGE_LIFECYCLE */
struct loaded_dep {
  /* INFO: DO NOT change this 2 members from order. Keep consistent with linker structure */
  struct csoloader_elf *img;
  struct tls_indices_data tls_indices;

  enum linker_image_state lifecycle_state;
  bool is_manual_load;""",
            "dependency constructor/destructor state",
        )
        header = replace_once(
            header,
            """  size_t main_map_size;
  bool is_linked;""",
            """  size_t main_map_size;
  bool is_linked;
  enum linker_image_state main_lifecycle_state;""",
            "main image constructor/destructor state",
        )
        header_path.write_text(header)

    source = linker_path.read_text()
    source_marker = "/* VREZYGISK_CONSTRUCTOR_STATE_MACHINE */"
    if source_marker not in source:
        source = replace_once(
            source,
            """static void _linker_call_constructors(struct csoloader_elf *img) {
  if (img->init_func) {""",
            """static void _linker_call_constructors(struct csoloader_elf *img,
                                       enum linker_image_state *state) {
  if (!img || !state || *state != LINKER_IMAGE_UNINITIALIZED) return;
  *state = LINKER_IMAGE_CONSTRUCTING;

  if (img->init_func) {""",
            "constructor state entry",
        )
        source = replace_once(
            source,
            """  }
}

static void _linker_call_destructors(struct csoloader_elf *img) {
  if (img->fini_array) {""",
            """  }

  *state = LINKER_IMAGE_CONSTRUCTED;
}

static void _linker_call_destructors(struct csoloader_elf *img,
                                     enum linker_image_state *state) {
  if (!img || !state || *state != LINKER_IMAGE_CONSTRUCTED) return;
  *state = LINKER_IMAGE_FINALIZING;

  if (img->fini_array) {""",
            "constructor/destructor state transition",
        )
        source = replace_once(
            source,
            """    img->fini_func();
  }
}

static const char *_path_basename""",
            """    img->fini_func();
  }

  *state = LINKER_IMAGE_FINALIZED;
}

/* VREZYGISK_CONSTRUCTOR_STATE_MACHINE */
static const char *_path_basename""",
            "destructor finalization state",
        )

        source = source.replace(
            "_linker_call_destructors(dep->img);",
            "_linker_call_destructors(dep->img, &dep->lifecycle_state);",
        )
        source = source.replace(
            "_linker_call_destructors(linker->img);",
            "_linker_call_destructors(linker->img, &linker->main_lifecycle_state);",
        )
        source = source.replace(
            "_linker_call_constructors(dep->img);",
            "_linker_call_constructors(dep->img, &dep->lifecycle_state);",
        )
        source = source.replace(
            "_linker_call_constructors(linker->img);",
            "_linker_call_constructors(linker->img, &linker->main_lifecycle_state);",
        )
        source = replace_once(
            source,
            """  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->dep_count = 0;""",
            """  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->main_lifecycle_state = LINKER_IMAGE_UNINITIALIZED;
  linker->dep_count = 0;""",
            "initialize main image lifecycle",
        )
        source = replace_once(
            source,
            """static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (strstr(linker->img->elf, lib_name)) return true;

  for (int i = 0; i < linker->dep_count; i++) {
    if (strstr(linker->dependencies[i].img->elf, lib_name)) return true;
  }

  return false;
}""",
            """static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (!linker || !lib_name) return false;
  const char *requested = _path_basename(lib_name);
  if (linker->img && strcmp(_path_basename(linker->img->elf), requested) == 0)
    return true;

  for (int i = 0; i < linker->dep_count; i++) {
    struct csoloader_elf *loaded = linker->dependencies[i].img;
    if (loaded && strcmp(_path_basename(loaded->elf), requested) == 0)
      return true;
  }

  return false;
}""",
            "exact SONAME/path dependency de-duplication",
        )
        linker_path.write_text(source)


def patch_csoloader_linker_lifetime(linker_path: Path) -> None:
    """Patch SONAME identity, dynamic dependency storage and custom dlopen refs."""
    header_path = linker_path.parent.parent / "include" / "linker.h"
    header = header_path.read_text()
    header_marker = "/* VREZYGISK_LINKER_OBJECT_REFS */"
    if header_marker not in header:
        header = replace_once(
            header,
            """  enum linker_image_state lifecycle_state;
  bool is_manual_load;""",
            """  enum linker_image_state lifecycle_state;
  size_t handle_refs;
  bool is_manual_load;""",
            "dependency handle reference count",
        )
        header = replace_once(
            header,
            """  struct loaded_dep dependencies[MAX_DEPS];
  int dep_count;

  size_t main_map_size;
  bool is_linked;
  enum linker_image_state main_lifecycle_state;""",
            """  struct loaded_dep *dependencies;
  size_t dep_capacity;
  int dep_count;

  size_t main_map_size;
  bool is_linked;
  size_t main_handle_refs;
  enum linker_image_state main_lifecycle_state;
  /* VREZYGISK_LINKER_OBJECT_REFS */""",
            "growable dependency storage and main image references",
        )
        header = replace_once(
            header,
            "void linker_destroy(struct linker *linker);",
            "bool linker_destroy(struct linker *linker);",
            "report unload refusal while handles remain open",
        )
        header = replace_once(
            header,
            "void linker_abandon(struct linker *linker);",
            "bool linker_abandon(struct linker *linker);",
            "report abandon refusal while handles remain open",
        )
        header_path.write_text(header)

    source = linker_path.read_text()
    soname_marker = "/* VREZYGISK_ELF_SONAME_IDENTITY */"
    if soname_marker not in source:
        basename = """static const char *_path_basename(const char *path) {
  if (!path) return "";

  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}"""
        helper = r"""static const char *_linker_image_soname(const struct csoloader_elf *img) {
  if (!img || !img->header || img->size < sizeof(ElfW(Ehdr))) return NULL;
  const ElfW(Ehdr) *eh = img->header;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_phentsize != sizeof(ElfW(Phdr)) || eh->e_phnum == 0 ||
      eh->e_phnum > 1024 || eh->e_phoff > img->size ||
      (size_t)eh->e_phnum > SIZE_MAX / sizeof(ElfW(Phdr)) ||
      (size_t)eh->e_phnum * sizeof(ElfW(Phdr)) >
          img->size - (size_t)eh->e_phoff) return NULL;

  const ElfW(Phdr) *phdr =
      (const ElfW(Phdr) *)((const uint8_t *)img->header + eh->e_phoff);
  const ElfW(Phdr) *dynamic_phdr = NULL;
  for (size_t i = 0; i < eh->e_phnum; ++i) {
    if (phdr[i].p_type == PT_DYNAMIC) {
      dynamic_phdr = &phdr[i];
      break;
    }
  }
  if (!dynamic_phdr || dynamic_phdr->p_filesz < sizeof(ElfW(Dyn)) ||
      dynamic_phdr->p_offset > img->size ||
      dynamic_phdr->p_filesz > img->size - (size_t)dynamic_phdr->p_offset ||
      dynamic_phdr->p_filesz % sizeof(ElfW(Dyn)) != 0) return NULL;

  const ElfW(Dyn) *dyn =
      (const ElfW(Dyn) *)((const uint8_t *)img->header + dynamic_phdr->p_offset);
  size_t dyn_count = (size_t)dynamic_phdr->p_filesz / sizeof(ElfW(Dyn));
  ElfW(Addr) strtab_vaddr = 0;
  size_t strsz = 0;
  size_t soname_offset = SIZE_MAX;
  bool terminated = false;
  for (size_t i = 0; i < dyn_count; ++i) {
    if (dyn[i].d_tag == DT_NULL) {
      terminated = true;
      break;
    }
    switch (dyn[i].d_tag) {
      case DT_STRTAB: strtab_vaddr = dyn[i].d_un.d_ptr; break;
      case DT_STRSZ: strsz = (size_t)dyn[i].d_un.d_val; break;
      case DT_SONAME: soname_offset = (size_t)dyn[i].d_un.d_val; break;
      default: break;
    }
  }
  if (!terminated || !strtab_vaddr || !strsz || soname_offset >= strsz)
    return NULL;

  for (size_t i = 0; i < eh->e_phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD || strtab_vaddr < phdr[i].p_vaddr)
      continue;
    ElfW(Addr) delta = strtab_vaddr - phdr[i].p_vaddr;
    if (delta > phdr[i].p_filesz || strsz > phdr[i].p_filesz - delta ||
        phdr[i].p_offset > img->size ||
        delta > img->size - (size_t)phdr[i].p_offset) continue;
    size_t strtab_offset = (size_t)phdr[i].p_offset + (size_t)delta;
    if (strtab_offset > img->size || strsz > img->size - strtab_offset)
      continue;
    const char *strtab = (const char *)img->header + strtab_offset;
    const char *soname = strtab + soname_offset;
    if (soname[0] == '\0' ||
        !memchr(soname, '\0', strsz - soname_offset)) return NULL;
    return soname;
  }
  return NULL;
}

static bool _linker_image_has_gnu_versions(const struct csoloader_elf *img,
                                           bool *out_has_versions) {
  if (!img || !img->header || !out_has_versions ||
      img->size < sizeof(ElfW(Ehdr))) return false;
  *out_has_versions = false;
  const ElfW(Ehdr) *eh = img->header;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_phentsize != sizeof(ElfW(Phdr)) || eh->e_phnum == 0 ||
      eh->e_phoff > img->size ||
      (size_t)eh->e_phnum > SIZE_MAX / sizeof(ElfW(Phdr)) ||
      (size_t)eh->e_phnum * sizeof(ElfW(Phdr)) >
          img->size - (size_t)eh->e_phoff) return false;

  const ElfW(Phdr) *phdr =
      (const ElfW(Phdr) *)((const uint8_t *)img->header + eh->e_phoff);
  for (size_t i = 0; i < eh->e_phnum; ++i) {
    if (phdr[i].p_type != PT_DYNAMIC) continue;
    if (phdr[i].p_offset > img->size ||
        phdr[i].p_filesz > img->size - (size_t)phdr[i].p_offset ||
        phdr[i].p_filesz < sizeof(ElfW(Dyn)) ||
        phdr[i].p_filesz % sizeof(ElfW(Dyn)) != 0) return false;
    const ElfW(Dyn) *dyn =
        (const ElfW(Dyn) *)((const uint8_t *)img->header + phdr[i].p_offset);
    size_t count = (size_t)phdr[i].p_filesz / sizeof(ElfW(Dyn));
    for (size_t j = 0; j < count; ++j) {
      if (dyn[j].d_tag == DT_NULL) return true;
      if (dyn[j].d_tag == (ElfW(Sxword))0x6ffffff0 ||
          dyn[j].d_tag == (ElfW(Sxword))0x6ffffffc ||
          dyn[j].d_tag == (ElfW(Sxword))0x6ffffffe)
        *out_has_versions = true;
    }
    return false;
  }
  return false;
}

static bool _linker_image_matches_name(const struct csoloader_elf *img,
                                       const char *name) {
  if (!img || !img->elf || !name || !*name) return false;
  if (strcmp(img->elf, name) == 0) return true;
  const char *soname = _linker_image_soname(img);
  if (soname) return strcmp(soname, name) == 0;
  return strcmp(_path_basename(img->elf), _path_basename(name)) == 0;
}

/* VREZYGISK_ELF_SONAME_IDENTITY */"""
        source = replace_once(source, basename, basename + "\n\n" + helper,
                              "ELF DT_SONAME identity helper")

        source = replace_once(
            source,
            """static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (!linker || !lib_name) return false;
  const char *requested = _path_basename(lib_name);
  if (linker->img && strcmp(_path_basename(linker->img->elf), requested) == 0)
    return true;

  for (int i = 0; i < linker->dep_count; i++) {
    struct csoloader_elf *loaded = linker->dependencies[i].img;
    if (loaded && strcmp(_path_basename(loaded->elf), requested) == 0)
      return true;
  }

  return false;
}""",
            """static bool _linker_is_library_loaded(struct linker *linker, const char *lib_name) {
  if (!linker || !lib_name) return false;
  if (_linker_image_matches_name(linker->img, lib_name)) return true;
  for (int i = 0; i < linker->dep_count; i++) {
    if (_linker_image_matches_name(linker->dependencies[i].img, lib_name))
      return true;
  }
  return false;
}""",
            "DT_SONAME-based dependency de-duplication",
        )
        source = replace_once(
            source,
            """  static struct csoloader_elf *_linker_find_loaded_image(struct linker *linker, const char *name) {
    const char *base_name = _path_basename(name);
    if (linker->img && (strcmp(linker->img->elf, name) == 0 || strcmp(_path_basename(linker->img->elf), base_name) == 0))
      return linker->img;

    for (int i = 0; i < linker->dep_count; i++) {
      struct loaded_dep *dep = &linker->dependencies[i];
      if (!dep->img || !dep->is_manual_load) continue;

      if (strcmp(dep->img->elf, name) == 0 || strcmp(_path_basename(dep->img->elf), base_name) == 0)
        return dep->img;
    }

    return NULL;
  }""",
            """  static struct csoloader_elf *_linker_find_loaded_image(struct linker *linker, const char *name) {
    if (!linker || !name) return NULL;
    if (_linker_image_matches_name(linker->img, name)) return linker->img;
    for (int i = 0; i < linker->dep_count; i++) {
      struct loaded_dep *dep = &linker->dependencies[i];
      if (!dep->img) continue;
      if (_linker_image_matches_name(dep->img, name)) return dep->img;
    }
    return NULL;
  }""",
            "dlopen lookup by SONAME",
        )
        image_from_handle = """  static struct csoloader_elf *_linker_image_from_handle(struct linker *linker, void *handle) {
    if (!linker || !handle || handle == RTLD_DEFAULT || handle == RTLD_NEXT) return NULL;
    if (handle == linker->img) return linker->img;

    for (int i = 0; i < linker->dep_count; i++) {
      if (handle != linker->dependencies[i].img) continue;

      return linker->dependencies[i].img;
    }

    return NULL;
  }"""
        ref_helper = r"""  static bool _linker_adjust_handle_ref(struct linker *linker,
                                       struct csoloader_elf *img,
                                       bool acquire) {
    if (!linker || !img) return false;
    size_t *refs = NULL;
    if (img == linker->img) {
      refs = &linker->main_handle_refs;
    } else {
      for (int i = 0; i < linker->dep_count; ++i) {
        if (linker->dependencies[i].img == img) {
          refs = &linker->dependencies[i].handle_refs;
          break;
        }
      }
    }
    if (!refs) return false;
    if (acquire) {
      if (*refs == SIZE_MAX) return false;
      ++*refs;
      return true;
    }
    if (*refs == 0) return false;
    --*refs;
    return true;
  }

"""
        image_start = source.index("static struct csoloader_elf *_linker_image_from_handle(")
        image_end = source.index("\n  }", image_start) + len("\n  }")
        image_chunk = source[image_start:image_end]
        if "_linker_adjust_handle_ref" not in source:
            source = source[:image_end] + "\n\n" + ref_helper.rstrip() + source[image_end:]
        dlopen_start = source.index("static void *custom_dlopen(")
        dlopen_end = source.index("static void *custom_dlsym(", dlopen_start)
        dlopen_chunk = source[dlopen_start:dlopen_end]
        if "if (img) return img;" in dlopen_chunk:
            dlopen_chunk = dlopen_chunk.replace(
                "if (img) return img;",
                "if (img && _linker_adjust_handle_ref(linker, img, true)) return img;",
                1,
            )
        elif "_linker_adjust_handle_ref(linker, img, true)" not in dlopen_chunk:
            raise RuntimeError("custom dlopen handle acquisition anchor missing")
        source = source[:dlopen_start] + dlopen_chunk + source[dlopen_end:]
        source = replace_once(
            source,
            """  /* INFO: If a handle is shared between modules, this will not be able to find it.*/
  static int custom_dlclose(void *handle) {
    int (*original_dlclose)(void *) = (int (*)(void *))_linker_get_original_libdl_symbol("dlclose");

    struct linker *linker = _linker_find_by_caller_address(__builtin_return_address(0));
    if (linker && _linker_image_from_handle(linker, handle)) return 0;

    return original_dlclose ? original_dlclose(handle) : -1;
  }""",
            """  static int custom_dlclose(void *handle) {
    int (*original_dlclose)(void *) = (int (*)(void *))_linker_get_original_libdl_symbol("dlclose");
    struct linker *linker = _linker_find_by_caller_address(__builtin_return_address(0));
    if (linker && _linker_image_from_handle(linker, handle))
      return _linker_adjust_handle_ref(linker, handle, false) ? 0 : -1;
    return original_dlclose ? original_dlclose(handle) : -1;
  }""",
            "release custom dlopen handle",
        )
        source = replace_once(
            source,
            "if (_linker_is_library_loaded(linker, lib_full_path)) {",
            "if (_linker_is_library_loaded(linker, lib_name)) {",
            "dependency lookup by DT_NEEDED SONAME",
        )

    open_handles_marker = "/* VREZYGISK_OPEN_HANDLE_GUARD */"
    if open_handles_marker not in source:
        source = replace_once(
            source,
            "/* INFO: Internal functions END */",
            """static bool _linker_has_open_handles(const struct linker *linker) {
  if (!linker || linker->main_handle_refs != 0) return true;
  for (int i = 0; i < linker->dep_count; ++i)
    if (linker->dependencies[i].handle_refs != 0) return true;
  return false;
}

/* VREZYGISK_OPEN_HANDLE_GUARD */

/* INFO: Internal functions END */""",
            "unconditional linker open-handle guard",
        )

    abandon_marker = "/* VREZYGISK_REFCOUNTED_LINKER_ABANDON */"
    if abandon_marker not in source:
        source = source.replace(
            "void linker_abandon(struct linker *linker) {",
            "bool linker_abandon(struct linker *linker) {",
            1,
        )
        abandon_start = source.index("bool linker_abandon(struct linker *linker) {")
        abandon_end = source.index("\nstatic size_t phdr_get_load_size", abandon_start)
        abandon_chunk = source[abandon_start:abandon_end]
        old_head = """bool linker_abandon(struct linker *linker) {
  _linker_release_dependencies(linker, false, false);"""
        new_head = """bool linker_abandon(struct linker *linker) {
  if (!linker || !linker->img || _linker_has_open_handles(linker))
    return false;
  _linker_release_dependencies(linker, false, false);"""
        if old_head not in abandon_chunk:
            raise RuntimeError("linker abandon guard anchor missing")
        abandon_chunk = abandon_chunk.replace(old_head, new_head, 1)
        old_tail = """  linker->dep_count = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
}"""
        new_tail = """  free(linker->dependencies);
  linker->dependencies = NULL;
  linker->dep_capacity = 0;
  linker->dep_count = 0;
  linker->main_handle_refs = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
  return true;
}"""
        if old_tail not in abandon_chunk:
            raise RuntimeError("linker abandon cleanup anchor missing")
        abandon_chunk = abandon_chunk.replace(old_tail, new_tail, 1)
        source = source[:abandon_start] + abandon_chunk + source[abandon_end:]
        source = source.replace(
            "/* INFO: Internal functions END */",
            "/* VREZYGISK_REFCOUNTED_LINKER_ABANDON */\n\n/* INFO: Internal functions END */",
            1,
        )

    deps_marker = "/* VREZYGISK_GROWABLE_LINKER_DEPENDENCIES */"
    if deps_marker not in source:
        source = replace_once(
            source,
            """bool linker_init(struct linker *linker, struct csoloader_elf *img) {
  _linker_internal_init();

  linker->img = img;
  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->main_lifecycle_state = LINKER_IMAGE_UNINITIALIZED;
  linker->dep_count = 0;
  memset(&linker->tls_indices, 0, sizeof(linker->tls_indices));

  memset(linker->dependencies, 0, sizeof(linker->dependencies));

  _linker_register(linker);

  return true;
}""",
            """bool linker_init(struct linker *linker, struct csoloader_elf *img) {
  if (!linker || !img) return false;
  _linker_internal_init();

  struct loaded_dep *dependencies = calloc(16, sizeof(*dependencies));
  if (!dependencies) return false;

  linker->img = img;
  linker->is_linked = false;
  linker->main_map_size = 0;
  linker->main_lifecycle_state = LINKER_IMAGE_UNINITIALIZED;
  linker->main_handle_refs = 0;
  linker->dep_count = 0;
  linker->dep_capacity = 16;
  linker->dependencies = dependencies;
  memset(&linker->tls_indices, 0, sizeof(linker->tls_indices));

  _linker_register(linker);
  return true;
}

/* VREZYGISK_GROWABLE_LINKER_DEPENDENCIES */
static bool _linker_reserve_dependencies(struct linker *linker, size_t required) {
  if (!linker || required > 4096) return false;
  if (required <= linker->dep_capacity) return true;
  size_t capacity = linker->dep_capacity ? linker->dep_capacity : 16;
  while (capacity < required) {
    if (capacity > 2048) {
      capacity = 4096;
      break;
    }
    capacity *= 2;
  }
  if (capacity < required || capacity > SIZE_MAX / sizeof(*linker->dependencies))
    return false;
  struct loaded_dep *grown =
      realloc(linker->dependencies, capacity * sizeof(*linker->dependencies));
  if (!grown) return false;
  memset(grown + linker->dep_capacity, 0,
         (capacity - linker->dep_capacity) * sizeof(*linker->dependencies));
  linker->dependencies = grown;
  linker->dep_capacity = capacity;
  return true;
}""",
            "growable dependency allocation",
        )
        source = replace_once(
            source,
            """    if (linker->dep_count >= MAX_DEPS) {
      LOGE("Maximum dependency count (%d) exceeded while loading: %s", MAX_DEPS, lib_full_path);

      carray_destroy(loaded_libs);

      return false;
    }

    struct loaded_dep *current_dep = &linker->dependencies[linker->dep_count];""",
            """    if (!_linker_reserve_dependencies(linker,
                                      (size_t)linker->dep_count + 1)) {
      LOGE("Dependency graph limit/allocation failure while loading: %s",
           lib_full_path);
      carray_destroy(loaded_libs);
      return false;
    }

    struct loaded_dep *current_dep = &linker->dependencies[linker->dep_count];""",
            "dynamic dependency graph growth",
        )
        source = replace_once(
            source,
            """    linker->dep_count++;

    if (current_dep->is_manual_load && current_dep->img->header->e_phoff > 0 && current_dep->img->header->e_phnum > 0) {""",
            """    linker->dep_count++;

    if (current_dep->is_manual_load) {
      bool dependency_has_versions = false;
      if (!_linker_image_has_gnu_versions(current_dep->img,
                                          &dependency_has_versions)) {
        LOGE("Malformed dynamic metadata in dependency %s",
             current_dep->img->elf);
        carray_destroy(loaded_libs);
        return false;
      }
      if (dependency_has_versions) {
        LOGE("Manual dependency %s requires GNU symbol versioning; "
             "request Bionic fallback for the complete dependency closure",
             current_dep->img->elf);
        carray_destroy(loaded_libs);
        return false;
      }
    }

    if (current_dep->is_manual_load && current_dep->img->header->e_phoff > 0 && current_dep->img->header->e_phnum > 0) {""",
            "fail closed on versioned manual dependencies",
        )
        source = replace_once(
            source,
            """    char lib_full_path[PATH_MAX];
    if (!_linker_find_library_path(lib_name, lib_full_path, sizeof(lib_full_path))) {
      LOGW("Could not find required library: %s", lib_name);

      /* INFO: Rather than failing, just skip missing libraries.
                 This allows loading libraries with optional dependencies. */
      carray_remove(loaded_libs, lib_name);
      i--;

      continue;
    }

    if (_linker_is_library_loaded(linker, lib_name)) {
      LOGD("Library already loaded: %s", lib_full_path);

      continue;
    }""",
            """    if (_linker_is_library_loaded(linker, lib_name)) {
      LOGD("Dependency already present by DT_SONAME: %s", lib_name);
      continue;
    }

    char lib_full_path[PATH_MAX];
    if (!_linker_find_library_path(lib_name, lib_full_path, sizeof(lib_full_path))) {
      LOGE("Required DT_NEEDED dependency cannot be located: %s", lib_name);
      carray_destroy(loaded_libs);
      return false;
    }""",
            "fail closed on missing DT_NEEDED and de-duplicate before path lookup",
        )
        source = source.replace(
            "void linker_destroy(struct linker *linker) {",
            "bool linker_destroy(struct linker *linker) {",
            1,
        )
        destroy_start = source.index("bool linker_destroy(struct linker *linker) {")
        destroy_end = source.index("\n/* INFO: Free resources related to the library without unloading it */",
                                  destroy_start)
        source = source[:destroy_start] + r"""bool linker_destroy(struct linker *linker) {
  if (!linker || !linker->img) return false;
  if (_linker_has_open_handles(linker)) {
    LOGE("Refusing to unload %s while custom dlopen handles remain open",
         linker->img->elf);
    return false;
  }

  void *main_base = linker->img->base;
  size_t main_map_size = linker->main_map_size;
  if (linker->is_linked) {
    _linker_call_destructors(linker->img, &linker->main_lifecycle_state);
    unregister_eh_frame_for_library(linker->img);
    unregister_custom_library_for_backtrace(linker->img);
  }

  _linker_release_dependencies(linker, true, linker->is_linked);
  _linker_unregister(linker);
  _linker_unregister_tls_segment((struct loaded_dep *)linker);
  csoloader_elf_destroy(linker->img);
  linker->img = NULL;
  if (main_base && main_map_size > 0) munmap(main_base, main_map_size);

  free(linker->dependencies);
  linker->dependencies = NULL;
  linker->dep_capacity = 0;
  linker->dep_count = 0;
  linker->main_handle_refs = 0;
  linker->is_linked = false;
  linker->main_map_size = 0;
  return true;
}
""" + source[destroy_end:]

    linker_path.write_text(source)

    csoloader_path = linker_path.with_name("csoloader.c")
    csoloader = csoloader_path.read_text()
    unload_marker = "/* VREZYGISK_REFCOUNTED_CSOLOADER_UNLOAD */"
    if unload_marker not in csoloader:
        csoloader = replace_once(
            csoloader,
            """bool csoloader_unload(struct csoloader *lib) {
  linker_destroy(&lib->linker);

  free(lib->lib_path);""",
            """bool csoloader_unload(struct csoloader *lib) {
  if (!lib || !linker_destroy(&lib->linker)) return false;

  free(lib->lib_path);""",
            "propagate linker unload refusal",
        )
        csoloader = csoloader.replace(
            "  return true;\n}\n\n/* INFO: Free resources related to the library without unloading it */",
            "  return true;\n}\n\n/* VREZYGISK_REFCOUNTED_CSOLOADER_UNLOAD */\n\n/* INFO: Free resources related to the library without unloading it */",
            1,
        )
        csoloader_path.write_text(csoloader)

    abandon_api_marker = "/* VREZYGISK_REFCOUNTED_CSOLOADER_ABANDON */"
    if abandon_api_marker not in csoloader:
        csoloader = replace_once(
            csoloader,
            """bool csoloader_abandon(struct csoloader *lib) {
  linker_abandon(&lib->linker);

  free(lib->lib_path);""",
            """bool csoloader_abandon(struct csoloader *lib) {
  if (!lib || !linker_abandon(&lib->linker)) return false;

  free(lib->lib_path);""",
            "propagate linker abandon refusal",
        )
        csoloader = csoloader.replace(
            "  return true;\n}\n\nvoid *csoloader_get_symbol",
            "  return true;\n}\n\n/* VREZYGISK_REFCOUNTED_CSOLOADER_ABANDON */\n\nvoid *csoloader_get_symbol",
            1,
        )
        csoloader_path.write_text(csoloader)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <CSOLoader/src/linker.c>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    csoloader_path = path.with_name("csoloader.c")
    source = path.read_text()
    if MARKER in source:
        patch_csoloader_api(csoloader_path)
        patch_csoloader_lifecycle(path)
        patch_csoloader_linker_lifetime(path)
        if REGISTRATION_MARKER not in source:
            source = replace_once(
                source,
                """  LOGD("Registering TLS segments for main library and dependencies.");
  _linker_register_tls_segment(linker->img);
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    _linker_register_tls_segment(dep->img);
  }""",
                """  LOGD("Registering TLS segments for main library and dependencies.");
  if (!_linker_register_tls_segment(linker->img)) {
    LOGE("Failed to register TLS segment for main image %s", linker->img->elf);
    return false;
  }
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    if (!_linker_register_tls_segment(dep->img)) {
      LOGE("Failed to register TLS segment for dependency %s", dep->img->elf);
      return false;
    }
  }
  /* VREZYGISK_TLS_REGISTRATION_FAILURE_GUARD */""",
                "TLS registration failure propagation",
            )
            path.write_text(source)
            print(f"Applied CSOLoader TLS registration failure checks to {path}")
        else:
            print("CSOLoader TLS hardening already applied")
        return 0

    source = replace_once(
        source,
        """struct tls_module {
  size_t module_id;
  size_t align;""",
        """struct tls_module {
  size_t module_id;
  size_t generation;
  size_t align;""",
        "TLS module generation field",
    )
    source = replace_once(
        source,
        """  /* INFO: Per-module TLS block pointers */
  void *modules[MAX_TLS_MODULES];""",
        """  /* INFO: Per-module TLS block pointers and allocation generations */
  void *modules[MAX_TLS_MODULES];
  size_t module_generations[MAX_TLS_MODULES];""",
        "per-thread TLS generation fields",
    )
    source = replace_once(
        source,
        """static pthread_key_t g_tls_key;
static bool g_tls_key_initialized = false;
static pthread_once_t g_tls_key_once = PTHREAD_ONCE_INIT;""",
        """static pthread_key_t g_tls_key;
static bool g_tls_key_initialized = false;
static int g_tls_key_error = 0;
static pthread_once_t g_tls_key_once = PTHREAD_ONCE_INIT;

/* VREZYGISK_TLS_GENERATION_GUARD */
static size_t _linker_bump_tls_generation(void) {
  if (++g_tls_generation == 0) ++g_tls_generation;
  return g_tls_generation;
}""",
        "TLS key and generation state",
    )
    source = replace_once(
        source,
        """static void _linker_alloc_tls_key_once(void) {
  pthread_key_create(&g_tls_key, _linker_destroy_thread_tls);
}""",
        """static void _linker_alloc_tls_key_once(void) {
  g_tls_key_error = pthread_key_create(&g_tls_key, _linker_destroy_thread_tls);
  g_tls_key_initialized = (g_tls_key_error == 0);
}""",
        "TLS key creation error handling",
    )
    source = replace_once(
        source,
        """  size_t align = mod->align;
  /* INFO: posix_memalign requires alignment >= sizeof(void *) and power of 2 */
  if (align < sizeof(void *)) align = sizeof(void *);
  if (system_page_size > 0 && align > system_page_size) align = system_page_size;""",
        """  size_t align = mod->align;
  /* posix_memalign requires power-of-two alignment and must honor p_align. */
  if (align < sizeof(void *)) align = sizeof(void *);
  if ((align & (align - 1)) != 0 || mod->filesz > mod->memsz ||
      (mod->filesz > 0 && !mod->init_image)) {
    LOGE("Invalid TLS image metadata for module %zu", mod->module_id);
    return NULL;
  }""",
        "TLS alignment and image bounds",
    )
    source = replace_once(
        source,
        """static struct thread_tls *_linker_get_thread_tls(void) {
  pthread_once(&g_tls_key_once, _linker_alloc_tls_key_once);
  g_tls_key_initialized = true;

  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (!ttls) {
    ttls = (struct thread_tls *)calloc(1, sizeof(struct thread_tls));
    if (!ttls) {
      LOGE("Failed to allocate thread TLS state");

      return NULL;
    }

    ttls->generation = 0;

    pthread_setspecific(g_tls_key, ttls);
  }

  return ttls;
}""",
        """static struct thread_tls *_linker_get_thread_tls(void) {
  int once_error = pthread_once(&g_tls_key_once, _linker_alloc_tls_key_once);
  if (once_error != 0 || g_tls_key_error != 0 || !g_tls_key_initialized) {
    LOGE("Failed to initialize TLS key: once=%d key=%d",
         once_error, g_tls_key_error);
    return NULL;
  }

  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (!ttls) {
    ttls = (struct thread_tls *)calloc(1, sizeof(struct thread_tls));
    if (!ttls) {
      LOGE("Failed to allocate thread TLS state");
      return NULL;
    }

    ttls->generation = 0;
    int set_error = pthread_setspecific(g_tls_key, ttls);
    if (set_error != 0) {
      LOGE("Failed to attach thread TLS state: %d", set_error);
      free(ttls);
      return NULL;
    }
  }

  return ttls;
}""",
        "TLS key initialization and per-thread registration",
    )
    source = replace_once(
        source,
        """static void _linker_sync_thread_tls(struct thread_tls *ttls) {
  pthread_mutex_lock(&g_tls_mutex);
  size_t current_gen = g_tls_generation;
  pthread_mutex_unlock(&g_tls_mutex);

  if (ttls->generation >= current_gen) return;

  for (size_t i = 1; i < MAX_TLS_MODULES; i++) {
    struct tls_module *mod = &g_tls_modules[i];
    if (mod->module_id != 0 || !ttls->modules[i]) continue;

    free(ttls->modules[i]);
    ttls->modules[i] = NULL;
  }

  ttls->generation = current_gen;
}""",
        """static void _linker_sync_thread_tls(struct thread_tls *ttls) {
  if (!ttls) return;

  pthread_mutex_lock(&g_tls_mutex);
  size_t current_gen = g_tls_generation;
  if (ttls->generation == current_gen) {
    pthread_mutex_unlock(&g_tls_mutex);
    return;
  }

  /* A module ID can be reused after unload. Compare per-slot generations,
   * not only the current module_id, or a stale TLS block can be reused. */
  for (size_t i = 1; i < MAX_TLS_MODULES; i++) {
    size_t module_generation = g_tls_modules[i].generation;
    if (ttls->module_generations[i] == module_generation) continue;

    free(ttls->modules[i]);
    ttls->modules[i] = NULL;
    ttls->module_generations[i] = module_generation;
  }

  ttls->generation = current_gen;
  pthread_mutex_unlock(&g_tls_mutex);
}""",
        "generation-safe per-thread TLS synchronization",
    )
    source = replace_once(
        source,
        """  mod->init_image = (const void *)((uintptr_t)img->base + img->tls_segment->p_vaddr - img->bias);
  mod->owner      = img;

  img->tls_mod_id = mod_id;
  g_tls_generation++;""",
        """  mod->init_image = (const void *)((uintptr_t)img->base + img->tls_segment->p_vaddr - img->bias);
  mod->owner      = img;
  mod->generation = _linker_bump_tls_generation();

  img->tls_mod_id = mod_id;""",
        "TLS registration generation assignment",
    )
    source = replace_once(
        source,
        """void *__tls_get_addr(struct tls_index *ti) {
  LOGD("__tls_get_addr called: ti=%p, module=%zu, offset=%zu", ti, (size_t)ti->module, (size_t)ti->offset);

  size_t mod_id = ti->module;""",
        """void *__tls_get_addr(struct tls_index *ti) {
  if (!ti) {
    LOGE("__tls_get_addr called with a null TLS index");
    return NULL;
  }
  LOGD("__tls_get_addr called: ti=%p, module=%zu, offset=%zu", ti, (size_t)ti->module, (size_t)ti->offset);

  size_t mod_id = ti->module;""",
        "TLS index validation",
    )
    source = replace_once(
        source,
        """  if (!ttls->modules[mod_id]) {
    ttls->modules[mod_id] = _linker_allocate_module_tls(mod);
    if (!ttls->modules[mod_id]) {""",
        """  if (ti->offset >= mod->memsz) {
    pthread_mutex_unlock(&g_tls_mutex);
    LOGE("TLS offset %zu exceeds module %zu size %zu",
         (size_t)ti->offset, mod_id, mod->memsz);
    return NULL;
  }

  /* Re-check under the registry lock in case a module ID was recycled after
   * the thread's initial generation synchronization. */
  if (ttls->module_generations[mod_id] != mod->generation) {
    free(ttls->modules[mod_id]);
    ttls->modules[mod_id] = NULL;
    ttls->module_generations[mod_id] = mod->generation;
  }

  if (!ttls->modules[mod_id]) {
    ttls->modules[mod_id] = _linker_allocate_module_tls(mod);
    if (!ttls->modules[mod_id]) {""",
        "TLS offset and module ID reuse validation",
    )
    source = replace_once(
        source,
        """void linker_deinit(void) {
  struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
  if (ttls) _linker_destroy_thread_tls(ttls);
  pthread_setspecific(g_tls_key, NULL);

  pthread_key_delete(g_tls_key);
  g_tls_key_initialized = false;
  g_tls_key_once = PTHREAD_ONCE_INIT;""",
        """void linker_deinit(void) {
  if (g_tls_key_initialized) {
    struct thread_tls *ttls = (struct thread_tls *)pthread_getspecific(g_tls_key);
    int clear_error = pthread_setspecific(g_tls_key, NULL);
    if (clear_error == 0) {
      if (ttls) _linker_destroy_thread_tls(ttls);
    } else {
      LOGE("Failed to clear current thread TLS state during deinit: %d",
           clear_error);
    }

    int delete_error = pthread_key_delete(g_tls_key);
    if (delete_error != 0)
      LOGE("Failed to delete TLS key during deinit: %d", delete_error);
  }
  g_tls_key_initialized = false;
  g_tls_key_error = 0;
  g_tls_key_once = PTHREAD_ONCE_INIT;""",
        "safe TLS key deinitialization",
    )

    source = replace_once(
        source,
        """  LOGD("Registering TLS segments for main library and dependencies.");
  _linker_register_tls_segment(linker->img);
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    _linker_register_tls_segment(dep->img);
  }""",
        """  LOGD("Registering TLS segments for main library and dependencies.");
  if (!_linker_register_tls_segment(linker->img)) {
    LOGE("Failed to register TLS segment for main image %s", linker->img->elf);
    return false;
  }
  for (int i = 0; i < linker->dep_count; i++) {
    struct loaded_dep *dep = &linker->dependencies[i];
    if (!dep->is_manual_load) continue;

    LOGD("Registering TLS segment for dependency: %s", dep->img->elf);

    if (!_linker_register_tls_segment(dep->img)) {
      LOGE("Failed to register TLS segment for dependency %s", dep->img->elf);
      return false;
    }
  }
  /* VREZYGISK_TLS_REGISTRATION_FAILURE_GUARD */""",
        "TLS registration failure propagation",
    )

    patch_csoloader_api(csoloader_path)
    path.write_text(source)
    patch_csoloader_lifecycle(path)
    patch_csoloader_linker_lifetime(path)
    print(f"Applied VReZygisk linker/TLS hardening to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
