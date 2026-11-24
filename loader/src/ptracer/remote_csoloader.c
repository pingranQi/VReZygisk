/* INFO: Remote CSOLoader, part of CSOLoader. Follows the same licensing
           as the original one (CSOLoader project).
*/

#include "remote_csoloader.h"

#if !defined(__aarch64__)
#error "ReZygisk remote CSOLoader supports AArch64 only"
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <elf.h>
#include <link.h>
#include <sys/syscall.h>
#include <sys/auxv.h>

#undef SYS_mmap
#define SYS_mmap LP_SELECT(__NR_mmap2, __NR_mmap)

#include "socket_utils.h"

#ifndef STT_GNU_IFUNC
  #define STT_GNU_IFUNC 10
#endif

#ifndef ALIGN_DOWN
  #define ALIGN_DOWN(x, a) ((x) & ~((a)-1))
#endif
#ifndef ALIGN_UP
  #define ALIGN_UP(x, a) (((x) + ((a)-1)) & ~((a)-1))
#endif

static uintptr_t page_start(uintptr_t addr, size_t page_size) {
  return ALIGN_DOWN(addr, page_size);
}

static uintptr_t page_end(uintptr_t addr, size_t page_size) {
  if (page_size == 0 || addr > UINTPTR_MAX - (page_size - 1)) return 0;
  return ALIGN_DOWN(addr + page_size - 1, page_size);
}

static bool remote_syscall_failed(long result) {
  /* Linux raw syscalls return -errno in the range [-4095, -1]. */
  return result < 0 && result >= -4095;
}

static long remote_mmap_offset_arg(off_t file_offset, size_t page_size) {
  /* INFO: mmap2 needs the offset in page units, unlike mmap */
  #ifdef __LP64__
    (void) page_size;

    return file_offset;
  #else
    return (long)(file_offset / (off_t)page_size);
  #endif
}

/* INFO: Parse ELF headers and compute the total mapping size for PT_LOAD segments. */
static bool compute_load_layout(int fd, size_t page_size, ElfW(Ehdr) *eh,
                                ElfW(Phdr) **out_phdr, ElfW(Addr) *out_min_vaddr,
                                size_t *out_map_size) {
  struct stat st;
  if (!eh || !out_phdr || !out_min_vaddr || !out_map_size ||
      page_size == 0 || (page_size & (page_size - 1)) != 0 ||
      fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(*eh)) {
    LOGE("Invalid ELF input or page size");
    return false;
  }

  *out_phdr = NULL;
  *out_min_vaddr = 0;
  *out_map_size = 0;

  if (!read_loop_offset(fd, eh, sizeof(*eh), 0)) {
    LOGE("Failed to read ELF header");
    return false;
  }

  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_ident[EI_VERSION] != EV_CURRENT ||
#ifdef __LP64__
      eh->e_ident[EI_CLASS] != ELFCLASS64 ||
#else
      eh->e_ident[EI_CLASS] != ELFCLASS32 ||
#endif
      eh->e_version != EV_CURRENT ||
      eh->e_ident[EI_DATA] != ELFDATA2LSB ||
      eh->e_ehsize != sizeof(*eh) ||
      eh->e_phentsize != sizeof(ElfW(Phdr)) ||
      eh->e_phnum == 0 || eh->e_type != ET_DYN) {
    LOGE("Unsupported or malformed ELF header");
    return false;
  }

#if defined(__aarch64__)
  if (eh->e_machine != EM_AARCH64) return false;
#elif defined(__arm__)
  if (eh->e_machine != EM_ARM) return false;
#elif defined(__x86_64__)
  if (eh->e_machine != EM_X86_64) return false;
#elif defined(__i386__)
  if (eh->e_machine != EM_386) return false;
#endif

  size_t phdr_sz = (size_t)eh->e_phnum * sizeof(ElfW(Phdr));
  if (eh->e_phoff > (ElfW(Off))st.st_size ||
      phdr_sz > (size_t)((ElfW(Off))st.st_size - eh->e_phoff)) {
    LOGE("Program header table exceeds file bounds");
    return false;
  }

  ElfW(Phdr) *phdr = (ElfW(Phdr) *)calloc(eh->e_phnum, sizeof(ElfW(Phdr)));
  if (!phdr) {
    LOGE("Failed to allocate memory for program headers");
    return false;
  }

  if (!read_loop_offset(fd, phdr, phdr_sz, (off_t)eh->e_phoff)) {
    LOGE("Failed to read program headers");
    free(phdr);
    return false;
  }

  ElfW(Addr) lo = (ElfW(Addr))UINTPTR_MAX;
  ElfW(Addr) hi = 0;
  size_t load_count = 0;

  for (int i = 0; i < eh->e_phnum; i++) {
    if (phdr[i].p_type == PT_TLS) {
      LOGE("Remote CSOLoader does not implement ELF TLS; rejecting image");
      free(phdr);
      return false;
    }
    if (phdr[i].p_type != PT_LOAD) continue;

    load_count++;
    if (phdr[i].p_filesz > phdr[i].p_memsz ||
        phdr[i].p_offset > (ElfW(Off))st.st_size ||
        phdr[i].p_filesz > (ElfW(Xword))((ElfW(Off))st.st_size - phdr[i].p_offset) ||
        phdr[i].p_vaddr > UINTPTR_MAX - phdr[i].p_memsz ||
        (phdr[i].p_align > 1 &&
         ((phdr[i].p_align & (phdr[i].p_align - 1)) != 0 ||
          (phdr[i].p_vaddr % phdr[i].p_align) != (phdr[i].p_offset % phdr[i].p_align))) ||
        ((phdr[i].p_vaddr - phdr[i].p_offset) & (page_size - 1)) != 0) {
      LOGE("Invalid PT_LOAD segment %d", i);
      free(phdr);
      return false;
    }

    if (phdr[i].p_memsz == 0) continue;
    if (phdr[i].p_vaddr < lo) lo = phdr[i].p_vaddr;

    ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_memsz;
    if (end > hi) hi = end;
  }

  /* The fixed-size protection table below must never silently drop segments. */
  if (load_count == 0 || load_count > 64 || hi <= lo) {
    LOGE("Invalid PT_LOAD layout (count=%zu)", load_count);
    free(phdr);
    return false;
  }

  lo = (ElfW(Addr))page_start((uintptr_t)lo, page_size);
  uintptr_t aligned_hi = page_end((uintptr_t)hi, page_size);
  if (aligned_hi == 0 || aligned_hi <= lo) {
    LOGE("PT_LOAD mapping size overflow");
    free(phdr);
    return false;
  }

  *out_min_vaddr = lo;
  *out_map_size = (size_t)(aligned_hi - lo);
  *out_phdr = phdr;
  return true;
}

/* INFO: Convert a virtual address to file offset using PT_LOAD segment mapping. */
static bool vaddr_range_in_load_segment(const ElfW(Phdr) *phdr, int phnum,
                                          ElfW(Addr) vaddr, size_t length,
                                          bool require_write) {
  if (!phdr || length == 0 || (uintmax_t)length > UINTPTR_MAX ||
      (uintptr_t)vaddr > UINTPTR_MAX - length)
    return false;

  uintptr_t end = (uintptr_t)vaddr + length;
  for (int i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;
    if (require_write && !(phdr[i].p_flags & PF_W)) continue;
    if ((uintptr_t)phdr[i].p_vaddr > UINTPTR_MAX - (uintptr_t)phdr[i].p_memsz) continue;

    uintptr_t seg_start = (uintptr_t)phdr[i].p_vaddr;
    uintptr_t seg_end = seg_start + (uintptr_t)phdr[i].p_memsz;
    if ((uintptr_t)vaddr >= seg_start && end <= seg_end) return true;
  }
  return false;
}

/* Validate the complete requested range, not only its first byte. */
static bool vaddr_to_offset(const ElfW(Phdr) *phdr, int phnum, ElfW(Addr) vaddr,
                            size_t length, off_t *out_off) {
  if (!phdr || !out_off || length == 0) return false;

  for (int i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    ElfW(Addr) seg_start = phdr[i].p_vaddr;
    if (phdr[i].p_vaddr > UINTPTR_MAX - phdr[i].p_filesz) continue;
    ElfW(Addr) seg_end = phdr[i].p_vaddr + phdr[i].p_filesz;

    if (vaddr < seg_start || vaddr >= seg_end) continue;
    ElfW(Addr) delta = vaddr - seg_start;
    if ((uintmax_t)length > (uintmax_t)(seg_end - vaddr) ||
        phdr[i].p_offset > (ElfW(Off))INT64_MAX ||
        delta > (ElfW(Addr))(INT64_MAX - (int64_t)phdr[i].p_offset))
      return false;

    ElfW(Off) file_off = phdr[i].p_offset + delta;
    if ((uintmax_t)length > (uintmax_t)(INT64_MAX - (int64_t)file_off))
      return false;

    *out_off = (off_t)file_off;
    return true;
  }

  LOGE("Failed to map full vaddr range: 0x%" PRIxPTR " + %zu", (uintptr_t)vaddr, length);
  return false;
}

/* INFO: Find the full path of a loaded module by its soname in remote maps. */
static const char *find_remote_module_path(struct maps_info *remote_map, const char *soname) {
  for (size_t i = 0; i < remote_map->length; i++) {
    const struct map_entry *m = &remote_map->maps[i];

    if (!m->path) continue;
    if (m->offset != 0) continue;

    const char *filename = position_after(m->path, '/');
    if (!filename) filename = m->path;

    if (strcmp(filename, soname) == 0) return m->path;
  }

  return NULL;
}

struct elf_dyn_info {
  off_t dyn_off;
  size_t dyn_sz;

  off_t symtab_off;
  off_t strtab_off;
  off_t rel_off;
  size_t rel_sz;
  off_t rela_off;
  size_t rela_sz;
  off_t jmprel_off;
  size_t jmprel_sz;
  off_t relr_off;
  size_t relr_sz;
  off_t android_relr_off;
  size_t android_relr_sz;
  size_t android_relr_count;
  bool has_android_relr_count;
  off_t android_rela_off;
  size_t android_rela_sz;
  off_t versym_off;
  bool has_versym;
  ElfW(Addr) verneed_vaddr;
  size_t verneed_num;
  ElfW(Addr) verdef_vaddr;
  size_t verdef_num;
  int pltrel_type;

  size_t syment;
  size_t strsz;
  size_t nsyms;

  char *strtab;
  size_t needed_count;
  size_t *needed_str_offsets;
};

static void elf_dyn_info_destroy(struct elf_dyn_info *info) {
  if (!info) return;

  free(info->strtab);
  free(info->needed_str_offsets);
  memset(info, 0, sizeof(*info));
}

/* INFO: Parse PT_DYNAMIC and extract relocation/symbol table info. */
static bool elf_load_dyn_info(int fd, const ElfW(Ehdr) *eh, const ElfW(Phdr) *phdr, struct elf_dyn_info *out) {
  if (!eh || !phdr || !out) return false;

  memset(out, 0, sizeof(*out));
  out->pltrel_type = 0;

  ElfW(Dyn) *dyn = NULL;
  size_t *needed_str_offsets = NULL;
  bool success = false;

  /* INFO: Find PT_DYNAMIC segment */
  const ElfW(Phdr) *dyn_phdr = NULL;
  for (int i = 0; i < eh->e_phnum; i++) {
    if (phdr[i].p_type != PT_DYNAMIC) continue;

    dyn_phdr = &phdr[i];

    break;
  }

  struct stat st;
  off_t checked_dyn_off = 0;
  if (!dyn_phdr || dyn_phdr->p_filesz == 0 ||
      dyn_phdr->p_filesz > SIZE_MAX ||
      dyn_phdr->p_filesz % sizeof(ElfW(Dyn)) != 0 ||
      fstat(fd, &st) != 0 ||
      dyn_phdr->p_offset > (ElfW(Off))st.st_size ||
      dyn_phdr->p_filesz > (ElfW(Xword))((ElfW(Off))st.st_size - dyn_phdr->p_offset) ||
      !vaddr_to_offset(phdr, eh->e_phnum, dyn_phdr->p_vaddr,
                       (size_t)dyn_phdr->p_filesz, &checked_dyn_off) ||
      checked_dyn_off != (off_t)dyn_phdr->p_offset) {
    LOGE("Missing or out-of-bounds PT_DYNAMIC");
    return false;
  }

  out->dyn_off = (off_t)dyn_phdr->p_offset;
  out->dyn_sz = (size_t)dyn_phdr->p_filesz;

  size_t dyn_count = out->dyn_sz / sizeof(ElfW(Dyn));
  if (dyn_count == 0) return false;

  dyn = (ElfW(Dyn) *)calloc(dyn_count, sizeof(ElfW(Dyn)));
  if (!dyn) {
    LOGE("Failed to allocate memory for dynamic entries");

    return false;
  }

  if (!read_loop_offset(fd, dyn, dyn_count * sizeof(ElfW(Dyn)), out->dyn_off)) {
    LOGE("Failed to read dynamic entries");

    goto cleanup;
  }

  ElfW(Addr) symtab_vaddr = 0;
  ElfW(Addr) strtab_vaddr = 0;
  ElfW(Addr) gnu_hash_vaddr = 0;
  ElfW(Addr) sysv_hash_vaddr = 0;
  ElfW(Addr) rel_vaddr = 0;
  ElfW(Addr) rela_vaddr = 0;
  ElfW(Addr) jmprel_vaddr = 0;
  ElfW(Addr) relr_vaddr = 0;
  ElfW(Addr) android_relr_vaddr = 0;
  size_t rel_sz = 0;
  size_t rela_sz = 0;
  size_t jmprel_sz = 0;
  size_t relr_sz = 0;
  size_t relrent = 0;
  size_t android_relr_sz = 0;
  size_t android_relrent = 0;
  size_t android_relr_count = 0;
  bool has_android_relr_count = false;
  ElfW(Addr) android_rela_vaddr = 0;
  size_t android_rela_sz = 0;
  ElfW(Addr) versym_vaddr = 0;
  ElfW(Addr) verneed_vaddr = 0;
  size_t verneed_num = 0;
  ElfW(Addr) verdef_vaddr = 0;
  size_t verdef_num = 0;
  size_t strsz = 0;
  size_t syment = 0;

  size_t needed_count = 0;
  bool has_dt_null = false;
  for (size_t i = 0; i < dyn_count; i++) {
    if (dyn[i].d_tag == DT_NEEDED) needed_count++;
    if (dyn[i].d_tag == DT_NULL) {
      has_dt_null = true;
      break;
    }
  }
  if (!has_dt_null) {
    LOGE("PT_DYNAMIC has no DT_NULL terminator");
    goto cleanup;
  }

  if (needed_count) {
    needed_str_offsets = (size_t *)calloc(needed_count, sizeof(size_t));
    if (!needed_str_offsets) {
      LOGE("Failed to allocate memory for DT_NEEDED offsets");

      goto cleanup;
    }
  }

  size_t needed_i = 0;
  for (size_t i = 0; i < dyn_count; i++) {
    uintptr_t tag = (uintptr_t)dyn[i].d_tag;
    switch (tag) {
      case DT_SYMTAB:    symtab_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_STRTAB:    strtab_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_STRSZ:     strsz = (size_t)dyn[i].d_un.d_val; break;
      case DT_SYMENT:    syment = (size_t)dyn[i].d_un.d_val; break;
      case DT_REL:       rel_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_RELSZ:     rel_sz = (size_t)dyn[i].d_un.d_val; break;
      case DT_RELA:      rela_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_RELASZ:    rela_sz = (size_t)dyn[i].d_un.d_val; break;
      case DT_JMPREL:    jmprel_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_PLTRELSZ:  jmprel_sz = (size_t)dyn[i].d_un.d_val; break;
      /* Reject unsupported dynamic metadata by ABI tag value, independent
       * of whether the platform elf.h exposes the corresponding macro. */
      case 35: /* DT_RELRSZ */ relr_sz = (size_t)dyn[i].d_un.d_val; break;
      case 36: /* DT_RELR */ relr_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case 37: /* DT_RELRENT */ relrent = (size_t)dyn[i].d_un.d_val; break;
      case 0x60000011: /* DT_ANDROID_RELA */
        android_rela_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr;
        break;
      case 0x60000012: /* DT_ANDROID_RELASZ */
        android_rela_sz = (size_t)dyn[i].d_un.d_val;
        break;
      case 0x6000000f: /* DT_ANDROID_REL */
      case 0x60000010: /* DT_ANDROID_RELSZ */
        LOGE("Android REL packed relocations are not supported on AArch64");
        goto cleanup;
      case 0x6fffe000: /* DT_ANDROID_RELR */
        android_relr_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr;
        break;
      case 0x6fffe001: /* DT_ANDROID_RELRSZ */
        android_relr_sz = (size_t)dyn[i].d_un.d_val;
        break;
      case 0x6fffe003: /* DT_ANDROID_RELRENT */
        android_relrent = (size_t)dyn[i].d_un.d_val;
        break;
      case 0x6fffe005: /* DT_ANDROID_RELRCOUNT */
        android_relr_count = (size_t)dyn[i].d_un.d_val;
        has_android_relr_count = true;
        break;
      case 0x6ffffff0: /* DT_VERSYM */
        versym_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr;
        break;
      case 0x6ffffffc: /* DT_VERDEF */
        verdef_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr;
        break;
      case 0x6ffffffd: /* DT_VERDEFNUM */
        verdef_num = (size_t)dyn[i].d_un.d_val;
        break;
      case 0x6ffffffe: /* DT_VERNEED */
        verneed_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr;
        break;
      case 0x6fffffff: /* DT_VERNEEDNUM */
        verneed_num = (size_t)dyn[i].d_un.d_val;
        break;
      case DT_PLTREL:    out->pltrel_type = (int)dyn[i].d_un.d_val; break;
      case DT_GNU_HASH:  gnu_hash_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_HASH:      sysv_hash_vaddr = (ElfW(Addr))dyn[i].d_un.d_ptr; break;
      case DT_NEEDED: {
        if (needed_str_offsets && needed_i < needed_count)
          needed_str_offsets[needed_i++] = (size_t)dyn[i].d_un.d_val;

        break;
      }
      case DT_NULL: i = dyn_count; break;
    }
  }

  /* Reject partial or unsupported dynamic relocation descriptions. */
  if ((rel_vaddr == 0) != (rel_sz == 0) ||
      (rela_vaddr == 0) != (rela_sz == 0) ||
      (jmprel_vaddr == 0) != (jmprel_sz == 0) ||
      (relr_vaddr == 0) != (relr_sz == 0) ||
      (android_relr_vaddr == 0) != (android_relr_sz == 0) ||
      (android_relr_sz && android_relrent != sizeof(ElfW(Addr))) ||
      (!android_relr_sz && android_relrent != 0) ||
      (has_android_relr_count && !android_relr_sz) ||
      (android_relr_count > 10000000) ||
      (android_rela_vaddr == 0) != (android_rela_sz == 0) ||
      ((verneed_vaddr == 0) != (verneed_num == 0)) ||
      ((verdef_vaddr == 0) != (verdef_num == 0)) ||
      ((verneed_num || verdef_num) && versym_vaddr == 0) ||
      (verneed_num > 4096) || (verdef_num > 4096) ||
      (relr_sz && relrent != sizeof(ElfW(Addr))) ||
      (!relr_sz && relrent != 0) ||
      (jmprel_sz && out->pltrel_type != DT_REL && out->pltrel_type != DT_RELA)) {
    LOGE("Inconsistent dynamic relocation metadata");
    goto cleanup;
  }

  /* INFO: Validate required entries */
  if (!syment) syment = sizeof(ElfW(Sym));

  if (!symtab_vaddr || !strtab_vaddr || !strsz) {
    LOGE("Missing DT_SYMTAB/DT_STRTAB/DT_STRSZ");

    goto cleanup;
  }

  /* INFO: Convert virtual addresses to file offsets */
  if (!vaddr_to_offset(phdr, eh->e_phnum, symtab_vaddr, sizeof(ElfW(Sym)), &out->symtab_off) ||
      !vaddr_to_offset(phdr, eh->e_phnum, strtab_vaddr, strsz, &out->strtab_off)) {
    LOGE("Failed vaddr_to_offset for symtab/strtab");

    goto cleanup;
  }

  /* INFO: Convert relocation table virtual addresses to file offsets */
  if (rel_vaddr && rel_sz) {
    if (!vaddr_to_offset(phdr, eh->e_phnum, rel_vaddr, rel_sz, &out->rel_off)) {
      LOGE("Failed vaddr_to_offset for DT_REL");

      goto cleanup;
    }
    out->rel_sz = rel_sz;
  }

  if (rela_vaddr && rela_sz) {
    if (!vaddr_to_offset(phdr, eh->e_phnum, rela_vaddr, rela_sz, &out->rela_off)) {
      LOGE("Failed vaddr_to_offset for DT_RELA");

      goto cleanup;
    }
    out->rela_sz = rela_sz;
  }

  if (jmprel_vaddr && jmprel_sz) {
    if (!vaddr_to_offset(phdr, eh->e_phnum, jmprel_vaddr, jmprel_sz, &out->jmprel_off)) {
      LOGE("Failed vaddr_to_offset for DT_JMPREL");
      goto cleanup;
    }
    out->jmprel_sz = jmprel_sz;
  }

  if (relr_vaddr && relr_sz) {
    if (relr_sz % sizeof(ElfW(Addr)) != 0 ||
        !vaddr_to_offset(phdr, eh->e_phnum, relr_vaddr, relr_sz, &out->relr_off)) {
      LOGE("Invalid or out-of-bounds DT_RELR table");
      goto cleanup;
    }
    out->relr_sz = relr_sz;
  }
  if (android_relr_vaddr && android_relr_sz) {
    if (android_relr_sz % sizeof(ElfW(Addr)) != 0 ||
        !vaddr_to_offset(phdr, eh->e_phnum, android_relr_vaddr,
                         android_relr_sz, &out->android_relr_off)) {
      LOGE("Invalid or out-of-bounds DT_ANDROID_RELR table");
      goto cleanup;
    }
    out->android_relr_sz = android_relr_sz;
    out->android_relr_count = android_relr_count;
    out->has_android_relr_count = has_android_relr_count;
  }

  if (android_rela_vaddr && android_rela_sz) {
    if (!vaddr_to_offset(phdr, eh->e_phnum, android_rela_vaddr,
                         android_rela_sz, &out->android_rela_off)) {
      LOGE("Invalid or out-of-bounds DT_ANDROID_RELA table");
      goto cleanup;
    }
    out->android_rela_sz = android_rela_sz;
  }
  if (versym_vaddr) {
    if (!vaddr_to_offset(phdr, eh->e_phnum, versym_vaddr,
                         sizeof(uint16_t), &out->versym_off)) {
      LOGE("Invalid DT_VERSYM address");
      goto cleanup;
    }
    out->has_versym = true;
  }
  out->verneed_vaddr = verneed_vaddr;
  out->verneed_num = verneed_num;
  out->verdef_vaddr = verdef_vaddr;
  out->verdef_num = verdef_num;

  /* INFO: Read string table into memory */
  if (strsz == 0 || strsz == SIZE_MAX) {
    LOGE("Invalid DT_STRSZ");
    goto cleanup;
  }

  out->strtab = (char *)malloc(strsz + 1);
  if (!out->strtab) {
    LOGE("Failed to allocate memory for string table");

    goto cleanup;
  }

  if (!read_loop_offset(fd, out->strtab, strsz, out->strtab_off)) {
    LOGE("Failed to read string table");

    free(out->strtab);
    out->strtab = NULL;

    goto cleanup;
  }
  out->strtab[strsz] = '\0';

  for (size_t i = 0; i < needed_count; i++) {
    size_t off = needed_str_offsets[i];
    if (off >= strsz || !memchr(out->strtab + off, '\0', strsz - off)) {
      LOGE("Invalid or unterminated DT_NEEDED string offset");
      goto cleanup;
    }
  }

  if (syment != sizeof(ElfW(Sym)) ||
      (rel_sz && rel_sz % sizeof(ElfW(Rel)) != 0) ||
      (rela_sz && rela_sz % sizeof(ElfW(Rela)) != 0) ||
      (jmprel_sz && out->pltrel_type == DT_REL && jmprel_sz % sizeof(ElfW(Rel)) != 0) ||
      (jmprel_sz && out->pltrel_type == DT_RELA && jmprel_sz % sizeof(ElfW(Rela)) != 0)) {
    LOGE("Invalid dynamic symbol or relocation table size");
    goto cleanup;
  }

  out->syment = syment;
  out->strsz = strsz;
  out->needed_count = needed_count;
  out->needed_str_offsets = needed_str_offsets;

  out->nsyms = 0;

  if (sysv_hash_vaddr) {
    off_t hash_off = 0;
    uint32_t hash_header[2];
    if (vaddr_to_offset(phdr, eh->e_phnum, sysv_hash_vaddr, sizeof(uint32_t) * 2, &hash_off) &&
        read_loop_offset(fd, hash_header, sizeof(hash_header), hash_off) &&
        hash_header[1] > 0) {
      out->nsyms = hash_header[1];
    }
  }

  if (gnu_hash_vaddr) {
    off_t gnu_hash_off = 0;

    if (vaddr_to_offset(phdr, eh->e_phnum, gnu_hash_vaddr, sizeof(uint32_t) * 4, &gnu_hash_off)) {
      uint32_t header[4];

      if (read_loop_offset(fd, header, sizeof(header), gnu_hash_off)) {
        uint32_t nbuckets = header[0];
        uint32_t symoffset = header[1];
        uint32_t bloom_size = header[2];

        /* INFO: Calculate offset to buckets array (after bloom filter) */
        size_t bloom_words = bloom_size * sizeof(ElfW(Addr));
        off_t buckets_off = gnu_hash_off + 16 + (off_t)bloom_words;

        /* INFO: Find max bucket value to determine highest symbol index */
        uint32_t max_bucket = 0;

        for (uint32_t b = 0; b < nbuckets; b++) {
          uint32_t bucket_val;

          if (!read_loop_offset(fd, &bucket_val, sizeof(bucket_val), buckets_off + (off_t)(b * 4)))
            break;

          if (bucket_val > max_bucket) max_bucket = bucket_val;
        }

        if (max_bucket >= symoffset) {
          /* INFO: Walk chain from max_bucket to find last symbol */
          off_t chains_off = buckets_off + (off_t)(nbuckets * 4);
          uint32_t chain_idx = max_bucket - symoffset;
          uint32_t chain_val;

          while (read_loop_offset(fd, &chain_val, sizeof(chain_val), chains_off + (off_t)(chain_idx * 4))) {
            if (chain_val & 1) {
              out->nsyms = max_bucket + 1;

              break;
            }

            max_bucket++;
            chain_idx++;
          }

          if (!out->nsyms) out->nsyms = max_bucket + 1;
        } else {
          out->nsyms = symoffset;
        }
      }
    }
  }

  /* Validate the entire dynamic symbol table after deriving its bound from DT_HASH/GNU_HASH. */
  off_t checked_symtab_off = 0;
  if (out->nsyms == 0 || out->nsyms > SIZE_MAX / sizeof(ElfW(Sym)) ||
      !vaddr_to_offset(phdr, eh->e_phnum, symtab_vaddr,
                       out->nsyms * sizeof(ElfW(Sym)), &checked_symtab_off) ||
      checked_symtab_off != out->symtab_off) {
    LOGE("Invalid or unbounded dynamic symbol table");
    goto cleanup;
  }

  if (versym_vaddr) {
    off_t checked_versym = 0;
    if (out->nsyms > SIZE_MAX / sizeof(uint16_t) ||
        !vaddr_to_offset(phdr, eh->e_phnum, versym_vaddr,
                         out->nsyms * sizeof(uint16_t), &checked_versym) ||
        checked_versym != out->versym_off) {
      LOGE("Invalid or truncated DT_VERSYM table");
      goto cleanup;
    }
  }

  success = true;

cleanup:
  free(dyn);
  if (!success) {
    free(out->strtab);
    out->strtab = NULL;
    free(needed_str_offsets);
  }

  return success;
}

static const char *remote_soname(const char *path) {
  if (!path) return NULL;
  const char *base = position_after(path, '/');
  return base ? base : path;
}

static bool same_remote_soname(const char *left, const char *right) {
  const char *a = remote_soname(left);
  const char *b = remote_soname(right);
  return a && b && strcmp(a, b) == 0;
}

static void free_symbol_scope(char **paths, size_t count) {
  if (!paths) return;
  for (size_t i = 0; i < count; ++i) free(paths[i]);
  free(paths);
}

static bool read_dependency_dynamic_info(const char *path, int *out_fd,
                                         ElfW(Ehdr) *out_eh,
                                         ElfW(Phdr) **out_phdr,
                                         struct elf_dyn_info *out_info) {
  if (!path || !out_fd || !out_eh || !out_phdr || !out_info) return false;
  *out_fd = -1;
  *out_phdr = NULL;
  memset(out_info, 0, sizeof(*out_info));

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st;
  ElfW(Ehdr) eh;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(eh) ||
      !read_loop_offset(fd, &eh, sizeof(eh), 0) ||
      memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 ||
      eh.e_ident[EI_DATA] != ELFDATA2LSB ||
      eh.e_machine != EM_AARCH64 || eh.e_type != ET_DYN ||
      eh.e_phentsize != sizeof(ElfW(Phdr)) || eh.e_phnum == 0 ||
      eh.e_phoff > (ElfW(Off))st.st_size ||
      (size_t)eh.e_phnum > SIZE_MAX / sizeof(ElfW(Phdr)) ||
      (size_t)eh.e_phnum * sizeof(ElfW(Phdr)) >
          (size_t)((ElfW(Off))st.st_size - eh.e_phoff)) {
    close(fd);
    return false;
  }

  size_t phdr_size = (size_t)eh.e_phnum * sizeof(ElfW(Phdr));
  ElfW(Phdr) *phdr = (ElfW(Phdr) *)calloc(1, phdr_size);
  if (!phdr || !read_loop_offset(fd, phdr, phdr_size, (off_t)eh.e_phoff)) {
    free(phdr);
    close(fd);
    return false;
  }

  for (int i = 0; i < eh.e_phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD) continue;
    if (phdr[i].p_filesz > phdr[i].p_memsz ||
        phdr[i].p_offset > (ElfW(Off))st.st_size ||
        phdr[i].p_filesz > (ElfW(Xword))((ElfW(Off))st.st_size - phdr[i].p_offset) ||
        phdr[i].p_vaddr > UINTPTR_MAX - phdr[i].p_memsz) {
      free(phdr);
      close(fd);
      return false;
    }
  }

  if (!elf_load_dyn_info(fd, &eh, phdr, out_info)) {
    free(phdr);
    close(fd);
    return false;
  }
  *out_fd = fd;
  *out_eh = eh;
  *out_phdr = phdr;
  return true;
}

/*
 * Build the ordered breadth-first DT_NEEDED scope. Bionic's global lookup
 * scope places all direct dependencies before their transitive dependencies.
 * Path de-duplication also terminates dependency cycles.
 */
static char **build_remote_symbol_scope(struct maps_info *remote_map,
                                        const char *const *direct_paths,
                                        size_t direct_count,
                                        size_t *out_count) {
  if (!remote_map || !out_count || direct_count > 256) return NULL;
  *out_count = 0;
  size_t capacity = 256;
  char **paths = (char **)calloc(capacity, sizeof(char *));
  if (!paths) return NULL;

  for (size_t i = 0; i < direct_count; ++i) {
    /* A missing direct DT_NEEDED object makes the bootstrap dependency graph
     * incomplete. Do not silently continue with a partially linked image. */
    if (!direct_paths || !direct_paths[i]) goto fail;
    bool duplicate = false;
    for (size_t j = 0; j < *out_count; ++j)
      if (same_remote_soname(paths[j], direct_paths[i])) { duplicate = true; break; }
    if (duplicate) continue;
    if (*out_count == capacity) goto fail;
    paths[*out_count] = strdup(direct_paths[i]);
    if (!paths[*out_count]) goto fail;
    (*out_count)++;
  }

  for (size_t i = 0; i < *out_count; ++i) {
    int fd = -1;
    ElfW(Ehdr) eh;
    ElfW(Phdr) *phdr = NULL;
    struct elf_dyn_info dep_info;
    if (!read_dependency_dynamic_info(paths[i], &fd, &eh, &phdr, &dep_info)) {
      LOGE("Unable to inspect transitive dependency metadata: %s", paths[i]);
      goto fail;
    }

    for (size_t n = 0; n < dep_info.needed_count; ++n) {
      size_t off = dep_info.needed_str_offsets[n];
      if (off >= dep_info.strsz) continue;
      const char *soname = dep_info.strtab + off;
      if (!memchr(soname, '\0', dep_info.strsz - off)) continue;
      const char *dep_path = find_remote_module_path(remote_map, soname);
      if (!dep_path) {
        /* Android's libdl and private linker sonames can be linker aliases
         * rather than independently mapped ELF objects. Other missing
         * dependencies make the ordered lookup scope incomplete. */
        if (strcmp(soname, "libdl.so") == 0 ||
            strcmp(soname, "ld-android.so") == 0)
          continue;
        LOGE("Missing mapped transitive dependency %s required by %s",
             soname, paths[i]);
        elf_dyn_info_destroy(&dep_info);
        free(phdr);
        close(fd);
        goto fail;
      }

      bool duplicate = false;
      for (size_t j = 0; j < *out_count; ++j) {
        /* DT_NEEDED names identify a loaded object by SONAME; use that key
         * rather than path strings so aliases/symlinks cannot duplicate it. */
        if (same_remote_soname(paths[j], dep_path)) { duplicate = true; break; }
      }
      if (duplicate) continue;
      if (*out_count == capacity) {
        elf_dyn_info_destroy(&dep_info);
        free(phdr);
        close(fd);
        goto fail;
      }
      paths[*out_count] = strdup(dep_path);
      if (!paths[*out_count]) {
        elf_dyn_info_destroy(&dep_info);
        free(phdr);
        close(fd);
        goto fail;
      }
      (*out_count)++;
    }

    elf_dyn_info_destroy(&dep_info);
    free(phdr);
    close(fd);
  }
  return paths;

fail:
  free_symbol_scope(paths, *out_count);
  *out_count = 0;
  return NULL;
}

/* INFO: Look up a symbol by name in the dynamic symbol table. */
static bool find_dynsym_value(int fd, const struct elf_dyn_info *info, const char *sym_name, ElfW(Addr) *out_value) {
  if (!info || !sym_name || !out_value || info->syment != sizeof(ElfW(Sym))) return false;

  for (size_t i = 0; i < info->nsyms; i++) {
    ElfW(Sym) sym;
    if (i > (size_t)INT64_MAX / info->syment ||
        !read_loop_offset(fd, &sym, sizeof(sym), info->symtab_off + (off_t)(i * info->syment)))
      break;

    if (sym.st_name == 0 || sym.st_name >= info->strsz) continue;

    const char *name = &info->strtab[sym.st_name];
    if (!memchr(name, '\0', info->strsz - sym.st_name) ||
        strcmp(name, sym_name) != 0 || sym.st_shndx == SHN_UNDEF || sym.st_value == 0)
      continue;

    *out_value = sym.st_value;
    return true;
  }

  LOGE("Symbol not found in dynsym: %s", sym_name);

  return false;
}

#ifdef __LP64__
  #define ELF_R_TYPE ELF64_R_TYPE
  #define ELF_R_SYM ELF64_R_SYM
#else
  #define ELF_R_TYPE ELF32_R_TYPE
  #define ELF_R_SYM ELF32_R_SYM
#endif

struct gnu_verneed {
  uint16_t vn_version;
  uint16_t vn_cnt;
  uint32_t vn_file;
  uint32_t vn_aux;
  uint32_t vn_next;
};
struct gnu_vernaux {
  uint32_t vna_hash;
  uint16_t vna_flags;
  uint16_t vna_other;
  uint32_t vna_name;
  uint32_t vna_next;
};
struct gnu_verdef {
  uint16_t vd_version;
  uint16_t vd_flags;
  uint16_t vd_ndx;
  uint16_t vd_cnt;
  uint32_t vd_hash;
  uint32_t vd_aux;
  uint32_t vd_next;
};
struct gnu_verdaux {
  uint32_t vda_name;
  uint32_t vda_next;
};

static bool get_symbol_version_requirement(int fd,
                                           const struct elf_dyn_info *info,
                                           const ElfW(Phdr) *phdr, int phnum,
                                           size_t sym_idx,
                                           char *version, size_t version_size,
                                           char *provider, size_t provider_size) {
  if (!version || version_size == 0 || !provider || provider_size == 0)
    return false;
  version[0] = '\0';
  provider[0] = '\0';
  if (!info || !info->has_versym) return true;

  uint16_t versym = 0;
  if (sym_idx > (size_t)INT64_MAX / sizeof(versym) ||
      !read_loop_offset(fd, &versym, sizeof(versym),
                        info->versym_off + (off_t)(sym_idx * sizeof(versym))))
    return false;
  uint16_t wanted = versym & 0x7fff;
  if (wanted <= 1) return true;
  if (!info->verneed_vaddr || info->verneed_num == 0) return false;

  ElfW(Addr) need_addr = info->verneed_vaddr;
  for (size_t i = 0; i < info->verneed_num; ++i) {
    off_t need_off = 0;
    struct gnu_verneed need;
    if (!vaddr_to_offset(phdr, phnum, need_addr, sizeof(need), &need_off) ||
        !read_loop_offset(fd, &need, sizeof(need), need_off) ||
        need.vn_version != 1 || need.vn_cnt == 0 || need.vn_cnt > 4096 ||
        need.vn_file >= info->strsz ||
        !memchr(info->strtab + need.vn_file, '\0', info->strsz - need.vn_file))
      return false;

    if (need.vn_aux == 0 || need_addr > UINTPTR_MAX - need.vn_aux)
      return false;
    ElfW(Addr) aux_addr = need_addr + need.vn_aux;
    for (size_t j = 0; j < need.vn_cnt; ++j) {
      off_t aux_off = 0;
      struct gnu_vernaux aux;
      if (!vaddr_to_offset(phdr, phnum, aux_addr, sizeof(aux), &aux_off) ||
          !read_loop_offset(fd, &aux, sizeof(aux), aux_off))
        return false;
      if ((aux.vna_other & 0x7fff) == wanted) {
        if (aux.vna_name >= info->strsz ||
            !memchr(info->strtab + aux.vna_name, '\0',
                    info->strsz - aux.vna_name))
          return false;
        if (strlen(info->strtab + aux.vna_name) >= version_size ||
            strlen(info->strtab + need.vn_file) >= provider_size)
          return false;
        strcpy(version, info->strtab + aux.vna_name);
        strcpy(provider, info->strtab + need.vn_file);
        return true;
      }
      if (j + 1 < need.vn_cnt) {
        if (aux.vna_next == 0 || aux_addr > UINTPTR_MAX - aux.vna_next)
          return false;
        aux_addr += aux.vna_next;
      }
    }

    if (i + 1 < info->verneed_num) {
      if (need.vn_next == 0 || need_addr > UINTPTR_MAX - need.vn_next)
        return false;
      need_addr += need.vn_next;
    }
  }
  return false;
}

static bool validate_verdef_table(int fd, const struct elf_dyn_info *info,
                                  const ElfW(Phdr) *phdr, int phnum) {
  if (!info || info->verdef_num == 0) return true;
  ElfW(Addr) def_addr = info->verdef_vaddr;
  for (size_t i = 0; i < info->verdef_num; ++i) {
    off_t def_off = 0;
    struct gnu_verdef def;
    if (!vaddr_to_offset(phdr, phnum, def_addr, sizeof(def), &def_off) ||
        !read_loop_offset(fd, &def, sizeof(def), def_off) ||
        def.vd_version != 1 || def.vd_cnt == 0 || def.vd_cnt > 4096)
      return false;
    if (def.vd_aux == 0 || def_addr > UINTPTR_MAX - def.vd_aux)
      return false;
    ElfW(Addr) aux_addr = def_addr + def.vd_aux;
    for (size_t j = 0; j < def.vd_cnt; ++j) {
      off_t aux_off = 0;
      struct gnu_verdaux aux;
      if (!vaddr_to_offset(phdr, phnum, aux_addr, sizeof(aux), &aux_off) ||
          !read_loop_offset(fd, &aux, sizeof(aux), aux_off) ||
          aux.vda_name >= info->strsz ||
          !memchr(info->strtab + aux.vda_name, '\0',
                  info->strsz - aux.vda_name))
        return false;
      if (j + 1 < def.vd_cnt) {
        if (aux.vda_next == 0 || aux_addr > UINTPTR_MAX - aux.vda_next)
          return false;
        aux_addr += aux.vda_next;
      }
    }
    if (i + 1 < info->verdef_num) {
      if (def.vd_next == 0 || def_addr > UINTPTR_MAX - def.vd_next)
        return false;
      def_addr += def.vd_next;
    }
  }
  return true;
}

static bool validate_verneed_table(int fd, const struct elf_dyn_info *info,
                                    const ElfW(Phdr) *phdr, int phnum) {
  if (!info || info->verneed_num == 0) return true;
  ElfW(Addr) need_addr = info->verneed_vaddr;
  for (size_t i = 0; i < info->verneed_num; ++i) {
    off_t need_off = 0;
    struct gnu_verneed need;
    if (!vaddr_to_offset(phdr, phnum, need_addr, sizeof(need), &need_off) ||
        !read_loop_offset(fd, &need, sizeof(need), need_off) ||
        need.vn_version != 1 || need.vn_cnt == 0 || need.vn_cnt > 4096 ||
        need.vn_file >= info->strsz ||
        !memchr(info->strtab + need.vn_file, '\0',
                info->strsz - need.vn_file) ||
        need.vn_aux == 0 || need_addr > UINTPTR_MAX - need.vn_aux)
      return false;

    ElfW(Addr) aux_addr = need_addr + need.vn_aux;
    for (size_t j = 0; j < need.vn_cnt; ++j) {
      off_t aux_off = 0;
      struct gnu_vernaux aux;
      if (!vaddr_to_offset(phdr, phnum, aux_addr, sizeof(aux), &aux_off) ||
          !read_loop_offset(fd, &aux, sizeof(aux), aux_off) ||
          aux.vna_name >= info->strsz ||
          !memchr(info->strtab + aux.vna_name, '\0',
                  info->strsz - aux.vna_name) ||
          (aux.vna_other & 0x7fff) <= 1)
        return false;
      if (j + 1 < need.vn_cnt) {
        if (aux.vna_next == 0 || aux_addr > UINTPTR_MAX - aux.vna_next)
          return false;
        aux_addr += aux.vna_next;
      }
    }
    if (i + 1 < info->verneed_num) {
      if (need.vn_next == 0 || need_addr > UINTPTR_MAX - need.vn_next)
        return false;
      need_addr += need.vn_next;
    }
  }
  return true;
}

struct remote_ifunc_args {
  unsigned long size;
  unsigned long hwcap;
  unsigned long hwcap2;
};

/*
 * Execute an AArch64 IFUNC resolver inside the target process. A private
 * scratch mapping supplies an isolated stack and resolver argument block.
 * The resolver returns through address zero, producing the expected SIGSEGV
 * stop; remote_call verifies the stop PC before accepting x0 as the result.
 */
static bool run_remote_ifunc_resolver(int pid, struct user_regs_struct *regs,
                                      struct maps_info *remote_map,
                                      uintptr_t resolver,
                                      uintptr_t *out_address) {
#if !defined(__aarch64__)
  (void)pid; (void)regs; (void)remote_map; (void)resolver; (void)out_address;
  return false;
#else
  if (pid <= 0 || !regs || !remote_map || !resolver || !out_address)
    return false;

  long page_long = sysconf(_SC_PAGESIZE);
  if (page_long <= 0) return false;
  size_t page_size = (size_t)page_long;
  uintptr_t gadget = find_syscall_gadget(pid, remote_map);
  if (!gadget) return false;

  long mmap_args[6] = {
    0, (long)page_size, PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
  };
  long mapped = remote_syscall(pid, regs, gadget, SYS_mmap, mmap_args, 6);
  if (remote_syscall_failed(mapped)) {
    LOGE("Failed to allocate remote IFUNC scratch stack: %ld", mapped);
    return false;
  }
  uintptr_t scratch = (uintptr_t)mapped;
  uintptr_t args_address = scratch + page_size / 2;
  struct remote_ifunc_args ifunc_args = {
    .size = sizeof(struct remote_ifunc_args),
    .hwcap = getauxval(AT_HWCAP),
    .hwcap2 = getauxval(AT_HWCAP2)
  };
  bool success = false;
  struct user_regs_struct saved = *regs;

  if (write_proc(pid, args_address, &ifunc_args, sizeof(ifunc_args)) !=
      (ssize_t)sizeof(ifunc_args)) {
    LOGE("Failed to write remote IFUNC argument block");
    goto cleanup;
  }

  regs->REG_SP = (scratch + page_size - 16) & ~(uintptr_t)0xf;
  long call_args[2] = {
    (long)(ifunc_args.hwcap | (1ULL << 62)),
    (long)args_address
  };
  uintptr_t resolved = remote_call(pid, regs, resolver, 0, call_args, 2);
  if (resolved == 0) {
    LOGE("Remote IFUNC resolver failed or returned a null address");
    goto restore;
  }
  *out_address = resolved;
  success = true;

restore:
  *regs = saved;
  if (!set_regs(pid, regs)) {
    LOGE("Failed to restore target registers after IFUNC resolver");
    success = false;
  }

cleanup: {
    long unmap_args[2] = { (long)scratch, (long)page_size };
    long unmap_result = remote_syscall(pid, regs, gadget, SYS_munmap,
                                       unmap_args, 2);
    if (unmap_result != 0) {
      LOGE("Failed to release remote IFUNC scratch mapping: %ld", unmap_result);
      success = false;
    }
  }
  return success;
#endif
}

/* INFO: Resolve a symbol address - either local or from DT_NEEDED libraries. */
static bool resolve_symbol_addr(int pid, struct user_regs_struct *regs, int fd,
                                const struct elf_dyn_info *info,
                                struct maps_info *local_map, struct maps_info *remote_map,
                                const char *const *needed_paths, const ElfW(Phdr) *phdr,
                                int phnum, uintptr_t load_bias, size_t sym_idx,
                                uintptr_t *out_addr) {
  ElfW(Sym) sym;

  if (!info || !out_addr || info->syment != sizeof(ElfW(Sym)) ||
      info->nsyms == 0 || sym_idx >= info->nsyms ||
      sym_idx > (size_t)INT64_MAX / info->syment ||
      !read_loop_offset(fd, &sym, sizeof(sym), info->symtab_off + (off_t)(sym_idx * info->syment)))
    return false;

  /* TLS symbols require target-thread TLS setup, which this bootstrap
   * mapper deliberately does not provide. */
  if (ELF_ST_TYPE(sym.st_info) == STT_TLS) {
    LOGE("TLS symbol relocation is unsupported by remote CSOLoader");
    return false;
  }

  /* Absolute symbols are not relative to the image load bias. */
  if (sym.st_shndx == SHN_ABS) {
    *out_addr = (uintptr_t)sym.st_value;
    return true;
  }

  /* Reject reserved section indices and validate the full symbol extent. */
  if (sym.st_shndx != SHN_UNDEF) {
    size_t symbol_size = sym.st_size ? (size_t)sym.st_size : 1;
    if (sym.st_shndx >= SHN_LORESERVE ||
        (uintptr_t)sym.st_value > UINTPTR_MAX - load_bias ||
        !vaddr_range_in_load_segment(phdr, phnum, sym.st_value,
                                     symbol_size, false)) {
      LOGE("Defined symbol is outside a valid PT_LOAD range");
      return false;
    }
    uintptr_t symbol_address = (uintptr_t)load_bias + (uintptr_t)sym.st_value;
    if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
      LOGD("Executing target-process IFUNC resolver at %p", (void *)symbol_address);
      return run_remote_ifunc_resolver(pid, regs, remote_map,
                                       symbol_address, out_addr);
    }
    *out_addr = symbol_address;
    return true;
  }

  /* INFO: Undefined symbol - resolve from external libraries */
  if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;

  const char *name = &info->strtab[sym.st_name];
  if (!*name || !memchr(name, '\0', info->strsz - sym.st_name)) return false;

  char required_version[256];
  char required_provider[256];
  if (!get_symbol_version_requirement(fd, info, phdr, phnum, sym_idx,
                                      required_version, sizeof(required_version),
                                      required_provider, sizeof(required_provider))) {
    LOGE("Malformed or unresolved GNU version requirement for %s", name);
    return false;
  }

  /* TODO: In CSOLoader, they're optional. Since it's broken to solve those *ATM*, just bypass. */
  if (strcmp(name, "__register_frame") == 0 || strcmp(name, "__deregister_frame") == 0) {
    LOGW("Bypassing resolution of EH frame function: %s", name);

    *out_addr = 0;

    return true;
  }

  /* INFO: Search in DT_NEEDED libraries */
  for (size_t i = 0; i < info->needed_count; i++) {
    const char *mod_path = needed_paths ? needed_paths[i] : NULL;
    if (!mod_path) continue;
    if (required_provider[0]) {
      const char *base = position_after(mod_path, '/');
      if (!base) base = mod_path;
      if (strcmp(base, required_provider) != 0) continue;
    }

    void *addr = required_version[0]
        ? find_func_addr_version(local_map, remote_map, mod_path, name, required_version)
        : find_func_addr(local_map, remote_map, mod_path, name);
    if (addr) {
      *out_addr = (uintptr_t)addr;

      return true;
    }
  }

  if (strcmp(name, "dlopen") == 0 || strcmp(name, "dlsym") == 0 || strcmp(name, "dlerror") == 0 || strcmp(name, "dl_iterate_phdr") == 0 || strcmp(name, "dlclose") == 0) {
    const char *linker_dl_symbol = "__dl_dlopen";
    if (strcmp(name, "dlsym") == 0) linker_dl_symbol = "__dl_dlsym";
    else if (strcmp(name, "dlerror") == 0) linker_dl_symbol = "__dl_dlerror";
    else if (strcmp(name, "dl_iterate_phdr") == 0) linker_dl_symbol = "__dl_dl_iterate_phdr";
    else if (strcmp(name, "dlclose") == 0) linker_dl_symbol = "__dl_dlclose";

    LOGD("Trying to resolve %s from main executable as: %s", name, linker_dl_symbol);

    /* INFO: Special-case dlsym since some old devices don't have libdl.so loaded to resolve it from. */
    void *addr = find_func_addr(local_map, remote_map, "/system/bin/" LP_SELECT("linker", "linker64"), linker_dl_symbol);
    if (addr) {
      *out_addr = (uintptr_t)addr;

      return true;
    }
  }

  if (ELF_ST_BIND(sym.st_info) == STB_WEAK) {
    LOGD("Unresolved weak symbol %s; using zero", name);
    *out_addr = 0;
    return true;
  }

  LOGE("Failed to resolve external symbol %s", name);
  return false;
}

static bool write_remote_addr(int pid, uintptr_t addr, ElfW(Addr) value) {
  return write_proc(pid, addr, &value, sizeof(value)) == (ssize_t)sizeof(value);
}

static bool read_remote_addr(int pid, uintptr_t addr, ElfW(Addr) *out) {
  return read_proc(pid, addr, out, sizeof(*out)) == (ssize_t)sizeof(*out);
}

/* INFO: Process RELA-format relocations from a given offset/size. */
static bool apply_rela_section(int pid, struct user_regs_struct *regs, int fd,
                               const struct elf_dyn_info *info,
                               struct maps_info *local_map, struct maps_info *remote_map,
                               const char *const *needed_paths, const ElfW(Phdr) *phdr, int phnum, uintptr_t load_bias,
                               off_t rela_off, size_t rela_sz) {
  if (rela_sz % sizeof(ElfW(Rela)) != 0) {
    LOGE("Malformed RELA table size");
    return false;
  }
  size_t count = rela_sz / sizeof(ElfW(Rela));

  for (size_t i = 0; i < count; i++) {
    ElfW(Rela) r;
    if (!read_loop_offset(fd, &r, sizeof(r), rela_off + (off_t)(i * sizeof(r)))) return false;

    unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
    unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
#if defined(__aarch64__)
    if (type == R_AARCH64_NONE) continue;
#endif
    if ((uintptr_t)r.r_offset > UINTPTR_MAX - load_bias ||
        !vaddr_range_in_load_segment(phdr, phnum, r.r_offset, sizeof(ElfW(Addr)), true)) {
      LOGE("RELA target is outside a writable PT_LOAD segment");
      return false;
    }
    uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
    ElfW(Addr) value = 0;

    #if defined(__aarch64__)
      if (type == R_AARCH64_RELATIVE) {
        value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
      } else if (type == R_AARCH64_IRELATIVE) {
        uintptr_t resolver = 0;
        if (sym != 0 || (uintptr_t)r.r_addend > UINTPTR_MAX - load_bias)
          return false;
        resolver = load_bias + (uintptr_t)r.r_addend;
        if (!run_remote_ifunc_resolver(pid, regs, remote_map, resolver,
                                       (uintptr_t *)&value))
          return false;
      } else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_ABS64) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(pid, regs, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, sym, &sym_addr))
          return false;

        value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
      } else {
        LOGE("Unsupported AArch64 RELA type %u", type);

        return false;
      }
    #elif defined(__x86_64__)
      if (type == R_X86_64_RELATIVE) {
        value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
      } else if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT || type == R_X86_64_64) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, sym, &sym_addr))
          return false;

        value = sym_addr ? (ElfW(Addr))sym_addr + (ElfW(Addr))r.r_addend : 0;
      } else {
        LOGE("Unsupported x86_64 RELA type %u", type);
        return false;
      }
    #else
      (void) info; (void) local_map; (void) remote_map; (void) sym; (void) type; (void) needed_paths;

      if (type == 0) value = (ElfW(Addr))load_bias + (ElfW(Addr))r.r_addend;
      else {
        LOGE("Unsupported RELA type %u", type);

        return false;
      }
    #endif

    if (!write_remote_addr(pid, target, value)) return false;
  }

  return true;
}

/* INFO: Process REL-format relocations from a given offset/size. */
static bool apply_rel_section(int pid, int fd, const struct elf_dyn_info *info,
                              struct maps_info *local_map, struct maps_info *remote_map,
                              const char *const *needed_paths, const ElfW(Phdr) *phdr, int phnum, uintptr_t load_bias,
                              off_t rel_off, size_t rel_sz) {
  size_t count = rel_sz / sizeof(ElfW(Rel));

  for (size_t i = 0; i < count; i++) {
    ElfW(Rel) r;
    if (!read_loop_offset(fd, &r, sizeof(r), rel_off + (off_t)(i * sizeof(r)))) return false;

    unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
    unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
    if ((uintptr_t)r.r_offset > UINTPTR_MAX - load_bias ||
        !vaddr_range_in_load_segment(phdr, phnum, r.r_offset, sizeof(ElfW(Addr)), true)) {
      LOGE("REL target is outside a writable PT_LOAD segment");
      return false;
    }
    uintptr_t target = (uintptr_t)load_bias + (uintptr_t)r.r_offset;
    ElfW(Addr) addend = 0;
    ElfW(Addr) value = 0;

    #if defined(__arm__)
      if (type == R_ARM_RELATIVE) {
        if (!read_remote_addr(pid, target, &addend)) return false;

        value = (ElfW(Addr))load_bias + addend;
      } else if (type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT || type == R_ARM_ABS32) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, sym, &sym_addr))
          return false;

        if (sym_addr == 0) value = 0;
        else if (type == R_ARM_ABS32) {
          if (!read_remote_addr(pid, target, &addend)) return false;

          value = (ElfW(Addr))sym_addr + addend;
        } else {
          value = (ElfW(Addr))sym_addr;
        }
      } else {
        LOGE("Unsupported ARM REL type %u", type);

        return false;
      }
    #elif defined(__i386__)
      if (type == R_386_RELATIVE) {
        if (!read_remote_addr(pid, target, &addend)) return false;

        value = (ElfW(Addr))load_bias + addend;
      } else if (type == R_386_GLOB_DAT || type == R_386_JMP_SLOT || type == R_386_32) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, sym, &sym_addr))
          return false;

        if (sym_addr == 0) value = 0;
        else if (type == R_386_32) {
          if (!read_remote_addr(pid, target, &addend)) return false;

          value = (ElfW(Addr))sym_addr + addend;
        } else {
          value = (ElfW(Addr))sym_addr;
        }
      } else {
        LOGE("Unsupported i386 REL type %u", type);

        return false;
      }
    #else
      (void) info; (void) local_map; (void) remote_map; (void) sym; (void) type; (void) needed_paths; (void) addend; (void) read_remote_addr; (void) target;

      LOGE("Unsupported REL relocation on this arch");

      return false;
    #endif

    if (!write_remote_addr(pid, target, value)) return false;
  }

  return true;
}

/* Apply ELF RELR relative relocations using the ABI direct/bitmap encoding. */
static bool apply_relr_table(int pid, int fd, off_t table_off, size_t table_sz,
                             bool check_count, size_t expected_count,
                             const ElfW(Phdr) *phdr, int phnum,
                             uintptr_t load_bias) {
  if (table_sz == 0) return true;
  if (table_sz % sizeof(ElfW(Addr)) != 0) return false;

  const size_t word_bits = sizeof(ElfW(Addr)) * 8;
  uintptr_t where = 0;
  size_t count = table_sz / sizeof(ElfW(Addr));
  size_t relocated_count = 0;
  for (size_t i = 0; i < count; ++i) {
    ElfW(Addr) entry = 0;
    if (i > (size_t)INT64_MAX / sizeof(entry) ||
        !read_loop_offset(fd, &entry, sizeof(entry),
                          table_off + (off_t)(i * sizeof(entry))))
      return false;

    if ((entry & 1) == 0) {
      if ((uintptr_t)entry > UINTPTR_MAX - load_bias) return false;
      where = (uintptr_t)entry;
      uintptr_t target = load_bias + where;
      ElfW(Addr) addend = 0;
      if (!vaddr_range_in_load_segment(phdr, phnum, (ElfW(Addr))where,
                                       sizeof(addend), true) ||
          !read_remote_addr(pid, target, &addend) ||
          !write_remote_addr(pid, target, (ElfW(Addr))(load_bias + addend)))
        return false;
      if (relocated_count == SIZE_MAX ||
          where > UINTPTR_MAX - sizeof(ElfW(Addr))) return false;
      relocated_count++;
      where += sizeof(ElfW(Addr));
      continue;
    }

    ElfW(Addr) bitmap = entry >> 1;
    for (size_t bit = 0; bit < word_bits - 1; ++bit) {
      if (bitmap & ((ElfW(Addr))1 << bit)) {
        if (where > UINTPTR_MAX - load_bias) return false;
        uintptr_t target = load_bias + where;
        ElfW(Addr) addend = 0;
        if (!vaddr_range_in_load_segment(phdr, phnum, (ElfW(Addr))where,
                                         sizeof(addend), true) ||
            !read_remote_addr(pid, target, &addend) ||
            !write_remote_addr(pid, target, (ElfW(Addr))(load_bias + addend)))
          return false;
        if (relocated_count == SIZE_MAX) return false;
        relocated_count++;
      }
      if (where > UINTPTR_MAX - sizeof(ElfW(Addr))) return false;
      where += sizeof(ElfW(Addr));
    }
  }

  if (check_count && relocated_count != expected_count) {
    LOGE("Android RELR count mismatch: decoded=%zu expected=%zu",
         relocated_count, expected_count);
    return false;
  }
  return true;
}

static bool apply_relr_section(int pid, int fd,
                               const struct elf_dyn_info *info,
                               const ElfW(Phdr) *phdr, int phnum,
                               uintptr_t load_bias) {
  return !info || apply_relr_table(pid, fd, info->relr_off, info->relr_sz,
                                   false, 0, phdr, phnum, load_bias);
}

static bool apply_android_relr_section(int pid, int fd,
                                       const struct elf_dyn_info *info,
                                       const ElfW(Phdr) *phdr, int phnum,
                                       uintptr_t load_bias) {
  if (!info) return true;
  return apply_relr_table(pid, fd, info->android_relr_off,
                          info->android_relr_sz,
                          info->has_android_relr_count,
                          info->android_relr_count,
                          phdr, phnum, load_bias);
}

static bool decode_sleb128(const uint8_t **cursor, const uint8_t *end,
                           int64_t *out) {
  if (!cursor || !*cursor || !out) return false;
  uint64_t value = 0;
  unsigned shift = 0;
  uint8_t byte = 0;

  for (;;) {
    if (*cursor >= end || shift > 63) return false;
    byte = *(*cursor)++;
    uint8_t payload = byte & 0x7f;

    if (shift == 63) {
      /* The tenth SLEB128 byte may only carry the sign-extension bit. */
      if (payload != 0x00 && payload != 0x7f) return false;
      value |= (uint64_t)(payload & 1) << 63;
    } else {
      value |= (uint64_t)payload << shift;
    }

    if (!(byte & 0x80)) break;
    shift += 7;
  }

  shift += 7;
  if (shift < 64 && (byte & 0x40))
    value |= (~UINT64_C(0)) << shift;

  *out = (int64_t)value;
  return true;
}

static bool apply_android_rela_section(int pid, struct user_regs_struct *regs, int fd,
                                       const struct elf_dyn_info *info,
                                       struct maps_info *local_map,
                                       struct maps_info *remote_map,
                                       const char *const *needed_paths,
                                       const ElfW(Phdr) *phdr, int phnum,
                                       uintptr_t load_bias) {
#if !defined(__aarch64__)
  (void)pid; (void)fd; (void)info; (void)local_map; (void)remote_map;
  (void)needed_paths; (void)phdr; (void)phnum; (void)load_bias;
  return true;
#else
  if (!info || !info->android_rela_sz) return true;
  if (info->android_rela_sz < 4 || info->android_rela_sz > 64U * 1024U * 1024U)
    return false;

  uint8_t *buffer = (uint8_t *)malloc(info->android_rela_sz);
  if (!buffer) return false;
  bool ok = false;
  if (!read_loop_offset(fd, buffer, info->android_rela_sz,
                        info->android_rela_off)) goto done;

  const uint8_t *cursor = buffer;
  const uint8_t *end = buffer + info->android_rela_sz;
  if ((size_t)(end - cursor) < 4 || memcmp(cursor, "APS2", 4) != 0) {
    LOGE("Invalid Android packed relocation magic");
    goto done;
  }
  cursor += 4;

  int64_t reloc_count_signed = 0, relocation_offset_signed = 0;
  if (!decode_sleb128(&cursor, end, &reloc_count_signed) ||
      !decode_sleb128(&cursor, end, &relocation_offset_signed) ||
      reloc_count_signed < 0 || reloc_count_signed > 1000000 ||
      relocation_offset_signed < 0) {
    LOGE("Invalid Android packed relocation header");
    goto done;
  }

  uint64_t reloc_offset = (uint64_t)relocation_offset_signed;
  int64_t addend = 0;
  uint64_t processed = 0;
  enum {
    GROUPED_BY_INFO = 1,
    GROUPED_BY_OFFSET_DELTA = 2,
    GROUPED_BY_ADDEND = 4,
    GROUP_HAS_ADDEND = 8
  };

  while (processed < (uint64_t)reloc_count_signed) {
    int64_t group_size_signed = 0, flags_signed = 0;
    if (!decode_sleb128(&cursor, end, &group_size_signed) ||
        !decode_sleb128(&cursor, end, &flags_signed) ||
        group_size_signed <= 0 ||
        (uint64_t)group_size_signed > (uint64_t)reloc_count_signed - processed ||
        flags_signed < 0 || (flags_signed & ~15) != 0) {
      LOGE("Invalid Android packed relocation group");
      goto done;
    }

    uint64_t group_size = (uint64_t)group_size_signed;
    unsigned flags = (unsigned)flags_signed;
    if (!(flags & GROUP_HAS_ADDEND)) {
      LOGE("AArch64 Android RELA group is missing addends");
      goto done;
    }

    int64_t offset_delta_group = 0;
    uint64_t info_group = 0;
    if ((flags & GROUPED_BY_OFFSET_DELTA) &&
        !decode_sleb128(&cursor, end, &offset_delta_group)) goto done;
    if ((flags & GROUPED_BY_INFO)) {
      int64_t encoded_info = 0;
      if (!decode_sleb128(&cursor, end, &encoded_info) || encoded_info < 0)
        goto done;
      info_group = (uint64_t)encoded_info;
    }
    if ((flags & GROUPED_BY_ADDEND) &&
        !decode_sleb128(&cursor, end, &addend)) goto done;

    for (uint64_t i = 0; i < group_size; ++i) {
      int64_t delta = offset_delta_group;
      if (!(flags & GROUPED_BY_OFFSET_DELTA) &&
          !decode_sleb128(&cursor, end, &delta)) goto done;
      if (delta < 0 || reloc_offset > UINT64_MAX - (uint64_t)delta)
        goto done;
      reloc_offset += (uint64_t)delta;

      uint64_t r_info = info_group;
      if (!(flags & GROUPED_BY_INFO)) {
        int64_t encoded_info = 0;
        if (!decode_sleb128(&cursor, end, &encoded_info) || encoded_info < 0)
          goto done;
        r_info = (uint64_t)encoded_info;
      }

      if (!(flags & GROUPED_BY_ADDEND)) {
        int64_t addend_delta = 0;
        if (!decode_sleb128(&cursor, end, &addend_delta) ||
            __builtin_add_overflow(addend, addend_delta, &addend))
          goto done;
      }

      unsigned type = (unsigned)ELF_R_TYPE(r_info);
      unsigned sym = (unsigned)ELF_R_SYM(r_info);
      processed++;
      if (type == R_AARCH64_NONE) continue;
      if (reloc_offset > UINTPTR_MAX - load_bias ||
          !vaddr_range_in_load_segment(phdr, phnum, (ElfW(Addr))reloc_offset,
                                       sizeof(ElfW(Addr)), true)) {
        LOGE("Android packed relocation target is outside writable PT_LOAD");
        goto done;
      }

      uintptr_t target = load_bias + (uintptr_t)reloc_offset;
      ElfW(Addr) value = 0;
      if (type == R_AARCH64_RELATIVE) {
        if (sym != 0) goto done;
        value = (ElfW(Addr))(load_bias + (uintptr_t)addend);
      } else if (type == R_AARCH64_IRELATIVE) {
        if (sym != 0) goto done;
        uintptr_t resolver = load_bias + (uintptr_t)addend;
        if (!run_remote_ifunc_resolver(pid, regs, remote_map, resolver,
                                       (uintptr_t *)&value)) goto done;
      } else if (type == R_AARCH64_GLOB_DAT ||
                 type == R_AARCH64_JUMP_SLOT ||
                 type == R_AARCH64_ABS64) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(pid, regs, fd, info, local_map, remote_map,
                                 needed_paths, phdr, phnum, load_bias,
                                 sym, &sym_addr)) goto done;
        value = sym_addr ? (ElfW(Addr))(sym_addr + (uintptr_t)addend) : 0;
      } else {
        LOGE("Unsupported AArch64 Android packed relocation type %u", type);
        goto done;
      }

      if (!write_remote_addr(pid, target, value)) goto done;
    }
  }

  if (cursor != end) {
    /* Padding is not part of APS2; trailing bytes usually indicate corruption. */
    LOGE("Trailing bytes in Android packed relocation stream");
    goto done;
  }
  ok = true;

done:
  free(buffer);
  return ok;
#endif
}

static bool apply_relocations(int pid, struct user_regs_struct *regs, int fd,
                              const struct elf_dyn_info *info,
                              struct maps_info *local_map, struct maps_info *remote_map,
                              const char *const *needed_paths, const ElfW(Phdr) *phdr,
                              int phnum, uintptr_t load_bias) {
  /* Relative relocations must be applied before symbol relocations. */
  if (!apply_relr_section(pid, fd, info, phdr, phnum, load_bias)) {
    LOGE("Failed to apply DT_RELR relocations");
    return false;
  }
  if (!apply_android_relr_section(pid, fd, info, phdr, phnum, load_bias)) {
    LOGE("Failed to apply DT_ANDROID_RELR relocations");
    return false;
  }
  if (!apply_android_rela_section(pid, regs, fd, info, local_map, remote_map,
                                  needed_paths, phdr, phnum, load_bias)) {
    LOGE("Failed to apply Android packed RELA relocations");
    return false;
  }

  /* INFO: Process RELA section */
  if (info->rela_sz && info->rela_off) {
    if (!apply_rela_section(pid, regs, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, info->rela_off, info->rela_sz))
      return false;
  }

  /* INFO: Process REL section */
  if (info->rel_sz && info->rel_off) {
    if (!apply_rel_section(pid, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, info->rel_off, info->rel_sz))
      return false;
  }

  /* INFO: Process JMPREL section (PLT relocations) - uses same format as RELA/REL */
  if (info->jmprel_sz && info->jmprel_off) {
    if (info->pltrel_type == DT_RELA) {
      if (!apply_rela_section(pid, regs, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, info->jmprel_off, info->jmprel_sz))
        return false;
    } else if (info->pltrel_type == DT_REL) {
      if (!apply_rel_section(pid, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, info->jmprel_off, info->jmprel_sz))
        return false;
    } else {
      LOGE("Unknown DT_PLTREL type %d", info->pltrel_type);

      return false;
    }
  }

  return true;
}

bool remote_csoloader_load_and_resolve_entry(int pid, struct user_regs_struct *regs,
                                             struct maps_info *remote_map, struct maps_info *local_map,
                                             const char *lib_path, uintptr_t *out_base,
                                             size_t *out_total_size, uintptr_t *out_entry) {
  if (pid <= 0 || !regs || !remote_map || !local_map || !lib_path ||
      !out_base || !out_total_size || !out_entry) {
    LOGE("Invalid arguments to remote CSOLoader");
    return false;
  }

  *out_base = 0;
  *out_total_size = 0;
  *out_entry = 0;

  struct user_regs_struct regs_saved = *regs;

  long page_size_long = sysconf(_SC_PAGESIZE);
  if (page_size_long <= 0) {
    LOGE("sysconf(_SC_PAGESIZE) failed");

    return false;
  }

  size_t page_size = (size_t)page_size_long;

  int fd = open(lib_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    PLOGE("open %s", lib_path);

    return false;
  }

  /* INFO: Parse ELF headers and compute mapping size */
  ElfW(Ehdr) eh;
  ElfW(Phdr) *phdr = NULL;
  ElfW(Addr) min_vaddr = 0;
  size_t map_size = 0;

  if (!compute_load_layout(fd, page_size, &eh, &phdr, &min_vaddr, &map_size)) {
    LOGE("Failed to parse ELF phdrs for %s", lib_path);
    close(fd);

    return false;
  }

  /* INFO: It's better to go raw syscall. It is problematic for new Android versions,
             which seems to be related to IBT (Indirect Branch Tracking) and GCS
             (Guarded Control Stack) enforcement, which interfers when trying
             to use libc's functions.
  */
  uintptr_t syscall_gadget = find_syscall_gadget(pid, remote_map);
  if (!syscall_gadget) {
    LOGE("Failed to find syscall gadget");

    free(phdr);
    close(fd);

    return false;
  }

  size_t path_len = strlen(lib_path) + 1;
  uintptr_t remote_path = regs_saved.REG_SP - ALIGN_UP(path_len, 16);
  if (write_proc(pid, remote_path, lib_path, path_len) != (ssize_t)path_len) {
    LOGE("Failed to write remote path string to stack");

    free(phdr);
    close(fd);

    return false;
  }

  /* INFO: Ensure remote_call's own stack usage stays below our string */
  regs->REG_SP = remote_path;

  long args[6];
  args[0] = AT_FDCWD;
  args[1] = (long)remote_path;
  args[2] = O_RDONLY | O_CLOEXEC;
  args[3] = 0;

  long remote_fd = remote_syscall(pid, regs, syscall_gadget, SYS_openat, args, 4);
  if (remote_fd < 0) {
    LOGE("Failed to open remote file: %s (%ld)", lib_path, remote_fd);

    free(phdr);
    close(fd);

    return false;
  }

  void *remote_path_zerod = calloc(1, ALIGN_UP(path_len, 16));
  if (!remote_path_zerod) {
    LOGE("Failed to allocate memory for zeroed path");

    args[0] = remote_fd;
    remote_syscall(pid, regs, syscall_gadget, SYS_close, args, 1);

    free(phdr);
    close(fd);

    return false;
  }

  if (write_proc(pid, remote_path, remote_path_zerod, ALIGN_UP(path_len, 16)) != (ssize_t)ALIGN_UP(path_len, 16)) {
    LOGE("Failed to zero remote path string on stack");

    free(remote_path_zerod);

    args[0] = remote_fd;
    remote_syscall(pid, regs, syscall_gadget, SYS_close, args, 1);

    free(phdr);
    close(fd);

    return false;
  }

  free(remote_path_zerod);

  /* INFO: Request an LP64 base 4GiB+ so the mapping starts high and stays
             farther from the areas where the target process is more likely to
             create VMAs later. */
  uintptr_t min_addr = sizeof(void *) == 8 ? 0x100000000ULL : (uintptr_t)0;
  args[0] = (long)min_addr;
  args[1] = (long)map_size;
  args[2] = PROT_NONE;
  args[3] = MAP_PRIVATE | MAP_ANONYMOUS;
  args[4] = -1;
  args[5] = 0;

  long remote_base_result = remote_syscall(pid, regs, syscall_gadget, SYS_mmap, args, 6);
  if (remote_syscall_failed(remote_base_result)) {
    LOGE("remote mmap reserve failed: %ld", remote_base_result);


    args[0] = remote_fd;
    remote_syscall(pid, regs, syscall_gadget, SYS_close, args, 1);

    free(phdr);
    close(fd);

    return false;
  }
  uintptr_t remote_base = (uintptr_t)remote_base_result;
  bool remote_mapping_active = true;

#define REMOTE_CLEANUP_MAPPING() do {                                      \
  if (remote_fd >= 0) {                                                    \
    args[0] = remote_fd;                                                   \
    remote_syscall(pid, regs, syscall_gadget, SYS_close, args, 1);         \
    remote_fd = -1;                                                        \
  }                                                                        \
  if (remote_mapping_active) {                                             \
    args[0] = (long)remote_base;                                           \
    args[1] = (long)map_size;                                              \
    remote_syscall(pid, regs, syscall_gadget, SYS_munmap, args, 2);        \
    remote_mapping_active = false;                                         \
  }                                                                        \
} while (0)

#ifdef __LP64__
  if (remote_base < min_addr) {
    LOGE("remote mmap reserve returned low base %p (< %p)", (void *)remote_base, (void *)min_addr);


    REMOTE_CLEANUP_MAPPING();

    free(phdr);
    close(fd);

    return false;
  }
 #endif

  if (remote_base < (uintptr_t)min_vaddr ||
      map_size > UINTPTR_MAX - remote_base) {
    LOGE("Remote image address range overflow");
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);
    return false;
  }

  uintptr_t load_bias = remote_base - (uintptr_t)min_vaddr;

  /* INFO: Track segments for later protection finalization */
  struct {
    uintptr_t addr;
    size_t len;
    int final_prot;
  } segs[64];

  size_t segs_count = 0;

  /* INFO: Map non-writable PT_LOAD from file */
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD) continue;

    if ((uintptr_t)phdr[i].p_vaddr > UINTPTR_MAX - load_bias ||
        (uintptr_t)phdr[i].p_memsz > UINTPTR_MAX - ((uintptr_t)phdr[i].p_vaddr + load_bias)) {
      LOGE("PT_LOAD address overflow for phdr %d", i);
      REMOTE_CLEANUP_MAPPING();
      free(phdr);
      close(fd);
      return false;
    }

    uintptr_t seg_start = (uintptr_t)phdr[i].p_vaddr + load_bias;
    uintptr_t seg_page = page_start(seg_start, page_size);
    uintptr_t seg_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_memsz + load_bias;
    uintptr_t seg_page_end = page_end(seg_end, page_size);
    if (seg_page_end == 0 || seg_page_end <= seg_page) {
      LOGE("Invalid PT_LOAD page range for phdr %d", i);
      REMOTE_CLEANUP_MAPPING();
      free(phdr);
      close(fd);
      return false;
    }
    size_t seg_page_len = (size_t)(seg_page_end - seg_page);

    bool is_writable = (phdr[i].p_flags & PF_W) != 0;

    if (is_writable) {
      off_t seg_offset = (off_t)phdr[i].p_offset;
      off_t file_page_offset = (off_t)page_start((uintptr_t)seg_offset, page_size);
      uintptr_t file_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_filesz + load_bias;
      uintptr_t file_page_end = page_end(file_end, page_size);

      if (phdr[i].p_filesz > 0) {

        size_t file_map_len = (size_t)(file_page_end - seg_page);
        args[0] = (long)seg_page;
        args[1] = (long)file_map_len;
        args[2] = PROT_READ | PROT_WRITE;
        args[3] = MAP_FIXED | MAP_PRIVATE;
        args[4] = remote_fd;
        args[5] = remote_mmap_offset_arg(file_page_offset, page_size);

        long seg_map_result = remote_syscall(pid, regs, syscall_gadget, SYS_mmap, args, 6);
        if (remote_syscall_failed(seg_map_result)) {
          LOGE("remote mmap writable file-backed segment failed for phdr %d", i);


          REMOTE_CLEANUP_MAPPING();
          free(phdr);
          close(fd);

          return false;
        }

        /* INFO: Zero-fill the tail of the last page (p_memsz - p_filesz within page). */
        if (file_page_end > file_end) {
          size_t tail_len = (size_t)(file_page_end - file_end);
          char *zeros = (char *)calloc(1, tail_len);
          if (!zeros || write_proc(pid, file_end, zeros, tail_len) != (ssize_t)tail_len) {
            LOGE("Failed to zero tail for phdr %d", i);

            if (zeros) free(zeros);
            REMOTE_CLEANUP_MAPPING();
            free(phdr);
            close(fd);

            return false;
          }

          free(zeros);
        }
      }

      if (seg_page_end > file_page_end) {

        args[0] = (long)file_page_end;
        args[1] = (long)(seg_page_end - file_page_end);
        args[2] = PROT_READ | PROT_WRITE;
        args[3] = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
        args[4] = -1;
        args[5] = 0;

        long bss_map_result = remote_syscall(pid, regs, syscall_gadget, SYS_mmap, args, 6);
        if (remote_syscall_failed(bss_map_result)) {
          LOGE("remote mmap bss segment failed for phdr %d", i);


          REMOTE_CLEANUP_MAPPING();
          free(phdr);
          close(fd);

          return false;
        }
      }
    } else {
      off_t seg_offset = (off_t)phdr[i].p_offset;
      off_t file_page_offset = (off_t)page_start((uintptr_t)seg_offset, page_size);
      uintptr_t file_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_filesz + load_bias;
      uintptr_t file_page_end = page_end(file_end, page_size);

      if (phdr[i].p_filesz > 0) {

        size_t file_map_len = (size_t)(file_page_end - seg_page);
        args[0] = (long)seg_page;
        args[1] = (long)file_map_len;
        args[2] = PROT_READ | PROT_WRITE;
        args[3] = MAP_FIXED | MAP_PRIVATE;
        args[4] = remote_fd;
        args[5] = remote_mmap_offset_arg(file_page_offset, page_size);

        long seg_map_result = remote_syscall(pid, regs, syscall_gadget, SYS_mmap, args, 6);
        if (remote_syscall_failed(seg_map_result)) {
          LOGE("remote mmap file-backed segment failed for phdr %d", i);


          REMOTE_CLEANUP_MAPPING();
          free(phdr);
          close(fd);

          return false;
        }
      }

      if (seg_page_end > file_page_end) {

        args[0] = (long)file_page_end;
        args[1] = (long)(seg_page_end - file_page_end);
        args[2] = PROT_READ | PROT_WRITE;
        args[3] = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
        args[4] = -1;
        args[5] = 0;

        long bss_map_result = remote_syscall(pid, regs, syscall_gadget, SYS_mmap, args, 6);
        if (remote_syscall_failed(bss_map_result)) {
          LOGE("remote mmap bss segment failed for phdr %d", i);


          REMOTE_CLEANUP_MAPPING();
          free(phdr);
          close(fd);

          return false;
        }
      }
    }

    /* INFO: Record segment info for later protection finalization */
    int prot = 0;

    if (phdr[i].p_flags & PF_R) prot |= PROT_READ;
    if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC;

    if (segs_count < (sizeof(segs) / sizeof(segs[0]))) {
      segs[segs_count].addr = seg_page;
      segs[segs_count].len = seg_page_len;
      segs[segs_count].final_prot = prot;
      segs_count++;
    }
  }


  args[0] = remote_fd;
  remote_syscall(pid, regs, syscall_gadget, SYS_close, args, 1);
  remote_fd = -1;

  struct elf_dyn_info dinfo;
  if (!elf_load_dyn_info(fd, &eh, phdr, &dinfo) ||
      !validate_verneed_table(fd, &dinfo, phdr, eh.e_phnum) ||
      !validate_verdef_table(fd, &dinfo, phdr, eh.e_phnum)) {
    LOGE("Failed to load or validate ELF dynamic/version metadata");

    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);

    return false;
  }

  const char **direct_needed_paths = NULL;
  if (dinfo.needed_count) {
    direct_needed_paths = (const char **)calloc(dinfo.needed_count, sizeof(char *));
    if (!direct_needed_paths) {
      LOGE("Failed to allocate memory for direct dependency paths");
      elf_dyn_info_destroy(&dinfo);
      REMOTE_CLEANUP_MAPPING();
      free(phdr);
      close(fd);
      return false;
    }

    for (size_t i = 0; i < dinfo.needed_count; i++) {
      size_t off = dinfo.needed_str_offsets[i];
      if (off >= dinfo.strsz) continue;
      const char *soname = &dinfo.strtab[off];
      size_t remaining = dinfo.strsz - off;
      if (!memchr(soname, '\0', remaining)) {
        LOGE("DT_NEEDED string is not terminated within DT_STRSZ");
        continue;
      }
      direct_needed_paths[i] = find_remote_module_path(remote_map, soname);
    }
  }

  size_t symbol_scope_count = 0;
  char **needed_paths = build_remote_symbol_scope(remote_map, direct_needed_paths,
                                                   dinfo.needed_count,
                                                   &symbol_scope_count);
  free((void *)direct_needed_paths);
  if (!needed_paths && dinfo.needed_count != 0) {
    LOGE("Failed to construct ordered transitive dependency scope");
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);
    return false;
  }
  /* The resolver consumes the expanded BFS scope from this point onward. */
  dinfo.needed_count = symbol_scope_count;

  /* INFO: Apply all relocations */
  if (!apply_relocations(pid, regs, fd, &dinfo, local_map, remote_map, (const char *const *)needed_paths, phdr, eh.e_phnum, load_bias)) {
    LOGE("Failed to apply relocations");

    free_symbol_scope(needed_paths, symbol_scope_count);
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);

    return false;
  }

  /* INFO: Finalize segment protections after relocations */
  for (size_t i = 0; i < segs_count; i++) {

    args[0] = (long)segs[i].addr;
    args[1] = (long)segs[i].len;
    args[2] = segs[i].final_prot;

    long mp_ret = remote_syscall(pid, regs, syscall_gadget, SYS_mprotect, args, 3);
    if (mp_ret < 0) {
      LOGE("Failed to set final protections for segment at %p: %ld", (void *)segs[i].addr, mp_ret);


      REMOTE_CLEANUP_MAPPING();

      free_symbol_scope(needed_paths, symbol_scope_count);
      elf_dyn_info_destroy(&dinfo);
      free(phdr);
      close(fd);

      return false;
    }
  }

  ElfW(Addr) entry_value = 0;
  if (!find_dynsym_value(fd, &dinfo, "entry", &entry_value)) {
    LOGE("Failed to resolve entry from ELF dynsym");

    free_symbol_scope(needed_paths, symbol_scope_count);
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);

    return false;
  }

  if ((uintptr_t)entry_value > UINTPTR_MAX - load_bias) {
    LOGE("Entry point address overflow");
    free_symbol_scope(needed_paths, symbol_scope_count);
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);
    return false;
  }

  uintptr_t remote_entry = (uintptr_t)load_bias + (uintptr_t)entry_value;
  bool entry_is_executable = false;
  for (int i = 0; i < eh.e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || !(phdr[i].p_flags & PF_X)) continue;
    uintptr_t start = (uintptr_t)phdr[i].p_vaddr;
    uintptr_t end = start + (uintptr_t)phdr[i].p_memsz;
    if ((uintptr_t)entry_value >= start && (uintptr_t)entry_value < end) {
      entry_is_executable = true;
      break;
    }
  }
  if (!entry_is_executable) {
    LOGE("Resolved entry point is outside executable PT_LOAD segments");
    free_symbol_scope(needed_paths, symbol_scope_count);
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);
    return false;
  }

  free_symbol_scope(needed_paths, symbol_scope_count);
  elf_dyn_info_destroy(&dinfo);
  free(phdr);
  close(fd);

  *out_base = remote_base;
  *out_total_size = map_size;
  *out_entry = remote_entry;

#undef REMOTE_CLEANUP_MAPPING

  LOGI("remote mapped %s at %p (size %zu), entry %p", lib_path, (void *)remote_base, map_size, (void *)remote_entry);

  return true;
}


/* Release a bootstrap image when its remote entry point fails. */
bool remote_csoloader_unmap(int pid, struct user_regs_struct *regs,
                            struct maps_info *remote_map, uintptr_t base, size_t size) {
  if (pid <= 0 || !regs || !remote_map || base == 0 || size == 0) return false;

  uintptr_t syscall_gadget = find_syscall_gadget(pid, remote_map);
  if (!syscall_gadget) {
    LOGE("Cannot locate a syscall gadget to release remote bootstrap image");
    return false;
  }

  long args[2] = { (long)base, (long)size };
  long result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, args, 2);
  if (result != 0) {
    LOGE("Remote munmap failed for bootstrap image %p (%zu): %ld", (void *)base, size, result);
    return false;
  }
  return true;
}
