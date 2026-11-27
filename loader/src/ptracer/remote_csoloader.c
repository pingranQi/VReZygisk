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

/* Close a tracee fd once; close(EINTR) must not be blindly retried. */
static void remote_close_fd(int pid, struct user_regs_struct *regs,
                            uintptr_t syscall_gadget, long *remote_fd) {
  if (!remote_fd || *remote_fd < 0) return;
  long args[1] = { *remote_fd };
  long result = remote_syscall(pid, regs, syscall_gadget, SYS_close, args, 1);
  if (result != 0) LOGE("Remote close(%ld) failed: %ld", *remote_fd, result);
  *remote_fd = -1;
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

/* Return the file-backed bytes remaining in the PT_LOAD containing vaddr. */
static bool vaddr_file_bytes_remaining(const ElfW(Phdr) *phdr, int phnum,
                                       ElfW(Addr) vaddr, off_t *out_off,
                                       size_t *out_remaining) {
  if (!phdr || !out_off || !out_remaining) return false;
  for (int i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || vaddr < phdr[i].p_vaddr) continue;
    if (phdr[i].p_vaddr > UINTPTR_MAX - phdr[i].p_filesz) continue;
    ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_filesz;
    if (vaddr >= end) continue;
    ElfW(Addr) delta = vaddr - phdr[i].p_vaddr;
    if (phdr[i].p_offset > (ElfW(Off))INT64_MAX ||
        delta > (ElfW(Addr))(INT64_MAX - (int64_t)phdr[i].p_offset)) return false;
    ElfW(Off) file_off = phdr[i].p_offset + delta;
    ElfW(Addr) remaining = end - vaddr;
    if (remaining > SIZE_MAX) return false;
    *out_off = (off_t)file_off;
    *out_remaining = (size_t)remaining;
    return true;
  }
  return false;
}

static bool sysv_hash_symbol_count(int fd, const ElfW(Phdr) *phdr, int phnum,
                                   ElfW(Addr) vaddr, size_t max_symbols,
                                   size_t *out_count) {
  uint32_t header[2];
  off_t off = 0;
  if (!out_count || !vaddr_to_offset(phdr, phnum, vaddr, sizeof(header), &off) ||
      !read_loop_offset(fd, header, sizeof(header), off) ||
      header[0] == 0 || header[1] == 0) return false;
  uint64_t words = UINT64_C(2) + (uint64_t)header[0] + (uint64_t)header[1];
  if (words > SIZE_MAX / sizeof(uint32_t)) return false;
  size_t bytes = (size_t)words * sizeof(uint32_t);
  off_t checked_off = 0;
  if (!vaddr_to_offset(phdr, phnum, vaddr, bytes, &checked_off) || checked_off != off)
    return false;
  if ((size_t)header[1] > max_symbols) return false;
  *out_count = (size_t)header[1];
  return true;
}

/* Validate every GNU hash bucket chain and derive the exclusive dynsym bound. */
static bool gnu_hash_symbol_count(int fd, const ElfW(Phdr) *phdr, int phnum,
                                  ElfW(Addr) vaddr, size_t max_symbols,
                                  size_t *out_count) {
  uint32_t header[4];
  off_t hash_off = 0;
  size_t available = 0;
  if (!out_count ||
      !vaddr_file_bytes_remaining(phdr, phnum, vaddr, &hash_off, &available) ||
      available < sizeof(header) ||
      !read_loop_offset(fd, header, sizeof(header), hash_off)) return false;
  const uint32_t nbuckets = header[0], symoffset = header[1], bloom_size = header[2];
  if (nbuckets == 0 || bloom_size == 0 ||
      (uint64_t)bloom_size > SIZE_MAX / sizeof(ElfW(Addr)) ||
      (uint64_t)nbuckets > SIZE_MAX / sizeof(uint32_t)) return false;
  size_t bloom_bytes = (size_t)bloom_size * sizeof(ElfW(Addr));
  size_t bucket_bytes = (size_t)nbuckets * sizeof(uint32_t);
  if (bloom_bytes > SIZE_MAX - sizeof(header) ||
      bucket_bytes > SIZE_MAX - sizeof(header) - bloom_bytes) return false;
  size_t prefix_bytes = sizeof(header) + bloom_bytes + bucket_bytes;
  if (prefix_bytes > available) return false;
  off_t buckets_off = hash_off + (off_t)sizeof(header) + (off_t)bloom_bytes;
  off_t chains_off = buckets_off + (off_t)bucket_bytes;
  size_t chain_words = (available - prefix_bytes) / sizeof(uint32_t);
  if ((size_t)symoffset > max_symbols) return false;
  size_t max_chain_words = max_symbols - (size_t)symoffset;
  if (chain_words > max_chain_words) chain_words = max_chain_words;
  size_t symbol_count = symoffset;
  for (uint32_t b = 0; b < nbuckets; b++) {
    uint32_t bucket = 0;
    off_t bucket_off = buckets_off + (off_t)((size_t)b * sizeof(uint32_t));
    if (!read_loop_offset(fd, &bucket, sizeof(bucket), bucket_off)) return false;
    if (bucket == 0) continue;
    if (bucket < symoffset) return false;
    size_t chain_index = (size_t)(bucket - symoffset);
    size_t symbol_index = (size_t)bucket;
    bool terminated = false;
    while (chain_index < chain_words) {
      uint32_t chain = 0;
      off_t chain_off = chains_off + (off_t)(chain_index * sizeof(uint32_t));
      if (!read_loop_offset(fd, &chain, sizeof(chain), chain_off)) return false;
      if (symbol_index == SIZE_MAX) return false;
      if (symbol_index + 1 > symbol_count) symbol_count = symbol_index + 1;
      if (chain & 1U) { terminated = true; break; }
      if (chain_index == SIZE_MAX || symbol_index == SIZE_MAX) return false;
      chain_index++;
      symbol_index++;
    }
    if (!terminated) return false;
  }
  if (symbol_count == 0) return false;
  *out_count = symbol_count;
  return true;
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
  size_t rel_sz = 0;
  size_t rela_sz = 0;
  size_t jmprel_sz = 0;
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
#if defined(DT_RELR) && defined(DT_RELRSZ) && defined(DT_RELRENT)
       case DT_RELR:
       case DT_RELRSZ:
       case DT_RELRENT:
         LOGE("DT_RELR relocations are not supported by remote CSOLoader");
         goto cleanup;
#endif
#if defined(DT_ANDROID_REL) && defined(DT_ANDROID_RELSZ) && defined(DT_ANDROID_RELA) && defined(DT_ANDROID_RELASZ)
       case DT_ANDROID_REL:
       case DT_ANDROID_RELSZ:
       case DT_ANDROID_RELA:
       case DT_ANDROID_RELASZ:
         LOGE("Android packed relocations are not supported by remote CSOLoader");
         goto cleanup;
#endif
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
  needed_str_offsets = NULL; /* Ownership transferred to out. */

  out->nsyms = 0;
  off_t symtab_bound_off = 0;
  size_t symtab_file_remaining = 0;
  if (!vaddr_file_bytes_remaining(phdr, eh->e_phnum, symtab_vaddr,
                                  &symtab_bound_off, &symtab_file_remaining) ||
      symtab_bound_off != out->symtab_off) {
    LOGE("Dynamic symbol table is not contained in a file-backed PT_LOAD");
    goto cleanup;
  }
  size_t max_symbols = symtab_file_remaining / sizeof(ElfW(Sym));
  size_t sysv_count = 0;
  size_t gnu_count = 0;
  if (max_symbols == 0) {
    LOGE("Dynamic symbol table has no file-backed entries");
    goto cleanup;
  }
  if (sysv_hash_vaddr &&
      !sysv_hash_symbol_count(fd, phdr, eh->e_phnum, sysv_hash_vaddr, max_symbols, &sysv_count)) {
    LOGE("Malformed or out-of-bounds DT_HASH");
    goto cleanup;
  }
  if (gnu_hash_vaddr &&
      !gnu_hash_symbol_count(fd, phdr, eh->e_phnum, gnu_hash_vaddr, max_symbols, &gnu_count)) {
    LOGE("Malformed or out-of-bounds DT_GNU_HASH");
    goto cleanup;
  }
  if (!sysv_hash_vaddr && !gnu_hash_vaddr) {
    LOGE("ELF has no supported dynamic symbol hash table");
    goto cleanup;
  }
  if (sysv_count && gnu_count && gnu_count > sysv_count) {
    LOGE("DT_GNU_HASH symbol bound exceeds DT_HASH nchain");
    goto cleanup;
  }
  out->nsyms = sysv_count ? sysv_count : gnu_count;

  /* Validate the entire dynamic symbol table after deriving its bound from DT_HASH/GNU_HASH. */
  off_t checked_symtab_off = 0;
  if (out->nsyms == 0 || out->nsyms > SIZE_MAX / sizeof(ElfW(Sym)) ||
      !vaddr_to_offset(phdr, eh->e_phnum, symtab_vaddr,
                       out->nsyms * sizeof(ElfW(Sym)), &checked_symtab_off) ||
      checked_symtab_off != out->symtab_off) {
    LOGE("Invalid or unbounded dynamic symbol table");
    goto cleanup;
  }

  success = true;

cleanup:
  free(dyn);
  free(needed_str_offsets);
  if (!success) {
    /* Destroy every partially initialized field on all failure edges. */
    elf_dyn_info_destroy(out);
  }

  return success;
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

/* INFO: Resolve a symbol address - either local or from DT_NEEDED libraries. */
static bool resolve_symbol_addr(int fd, const struct elf_dyn_info *info,
                                struct maps_info *local_map, struct maps_info *remote_map,
                                const char *const *needed_paths, uintptr_t load_bias,
                                size_t sym_idx, uintptr_t *out_addr) {
  ElfW(Sym) sym;

  if (!info || !out_addr || info->syment != sizeof(ElfW(Sym)) ||
      info->nsyms == 0 || sym_idx >= info->nsyms ||
      sym_idx > (size_t)INT64_MAX / info->syment ||
      !read_loop_offset(fd, &sym, sizeof(sym), info->symtab_off + (off_t)(sym_idx * info->syment)))
    return false;

  /* IFUNC symbols require executing their resolver; never treat st_value as final. */
if (ELF_ST_TYPE(sym.st_info) == STT_GNU_IFUNC) {
    LOGE("Remote CSOLoader does not implement GNU IFUNC resolvers");
    return false;
  }

  /* INFO: Defined symbol - use load_bias + value */
  if (sym.st_shndx != SHN_UNDEF) {
    *out_addr = (uintptr_t)load_bias + (uintptr_t)sym.st_value;

    return true;
  }

  /* INFO: Undefined symbol - resolve from external libraries */
  if (sym.st_name == 0 || sym.st_name >= info->strsz) return false;

  const char *name = &info->strtab[sym.st_name];
  if (!*name || !memchr(name, '\0', info->strsz - sym.st_name)) return false;

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

    void *addr = find_func_addr(local_map, remote_map, mod_path, name);
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
static bool apply_rela_section(int pid, int fd, const struct elf_dyn_info *info,
                               struct maps_info *local_map, struct maps_info *remote_map,
                               const char *const *needed_paths, const ElfW(Phdr) *phdr, int phnum, uintptr_t load_bias,
                               off_t rela_off, size_t rela_sz) {
  size_t count = rela_sz / sizeof(ElfW(Rela));

  for (size_t i = 0; i < count; i++) {
    ElfW(Rela) r;
    if (!read_loop_offset(fd, &r, sizeof(r), rela_off + (off_t)(i * sizeof(r)))) return false;

    unsigned type = (unsigned)ELF_R_TYPE(r.r_info);
    unsigned sym = (unsigned)ELF_R_SYM(r.r_info);
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
      } else if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_ABS64) {
        uintptr_t sym_addr = 0;
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr))
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
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr))
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
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr))
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
        if (!resolve_symbol_addr(fd, info, local_map, remote_map, needed_paths, load_bias, sym, &sym_addr))
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

static bool apply_relocations(int pid, int fd, const struct elf_dyn_info *info,
                              struct maps_info *local_map, struct maps_info *remote_map,
                              const char *const *needed_paths, const ElfW(Phdr) *phdr,
                              int phnum, uintptr_t load_bias) {
  /* INFO: Process RELA section */
  if (info->rela_sz && info->rela_off) {
    if (!apply_rela_section(pid, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, info->rela_off, info->rela_sz))
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
      if (!apply_rela_section(pid, fd, info, local_map, remote_map, needed_paths, phdr, phnum, load_bias, info->jmprel_off, info->jmprel_sz))
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
    remote_close_fd(pid, regs, syscall_gadget, &remote_fd);

    free(phdr);
    close(fd);

    return false;
  }

  if (write_proc(pid, remote_path, remote_path_zerod, ALIGN_UP(path_len, 16)) != (ssize_t)ALIGN_UP(path_len, 16)) {
    LOGE("Failed to zero remote path string on stack");

    free(remote_path_zerod);

    args[0] = remote_fd;
    remote_close_fd(pid, regs, syscall_gadget, &remote_fd);

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
    remote_close_fd(pid, regs, syscall_gadget, &remote_fd);

    free(phdr);
    close(fd);

    return false;
  }
  uintptr_t remote_base = (uintptr_t)remote_base_result;
  bool remote_mapping_active = true;

#define REMOTE_CLEANUP_MAPPING() do {                                      \
  if (remote_fd >= 0) {                                                    \
    args[0] = remote_fd;                                                   \
    remote_close_fd(pid, regs, syscall_gadget, &remote_fd);         \
    remote_fd = -1;                                                        \
  }                                                                        \
  if (remote_mapping_active) {                                             \
    args[0] = (long)remote_base;                                           \
    args[1] = (long)map_size;                                              \
    long unmap_result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, args, 2); \
    if (unmap_result == 0) {                                               \
      remote_mapping_active = false;                                       \
    } else {                                                               \
      LOGE("Remote cleanup munmap failed for %p (%zu): %ld",               \
           (void *)remote_base, map_size, unmap_result);                   \
      *out_base = remote_base;                                             \
      *out_total_size = map_size;                                          \
    }                                                                      \
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
        if (remote_syscall_failed(seg_map_result) || (uintptr_t)seg_map_result != seg_page) {
          LOGE("remote MAP_FIXED writable segment mismatch for phdr %d: expected %p got %ld",
               i, (void *)seg_page, seg_map_result);
          if (!remote_syscall_failed(seg_map_result)) {
            long cleanup_args[2] = { seg_map_result, (long)file_map_len };
            long cleanup_result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, cleanup_args, 2);
            if (cleanup_result != 0) LOGE("Failed to unmap unexpected writable segment: %ld", cleanup_result);
          }


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
        if (remote_syscall_failed(bss_map_result) || (uintptr_t)bss_map_result != file_page_end) {
          LOGE("remote MAP_FIXED BSS mismatch for phdr %d: expected %p got %ld",
               i, (void *)file_page_end, bss_map_result);
          if (!remote_syscall_failed(bss_map_result)) {
            long cleanup_args[2] = { bss_map_result, (long)(seg_page_end - file_page_end) };
            long cleanup_result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, cleanup_args, 2);
            if (cleanup_result != 0) LOGE("Failed to unmap unexpected BSS mapping: %ld", cleanup_result);
          }


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
        if (remote_syscall_failed(seg_map_result) || (uintptr_t)seg_map_result != seg_page) {
          LOGE("remote MAP_FIXED file-backed mismatch for phdr %d: expected %p got %ld",
               i, (void *)seg_page, seg_map_result);
          if (!remote_syscall_failed(seg_map_result)) {
            long cleanup_args[2] = { seg_map_result, (long)file_map_len };
            long cleanup_result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, cleanup_args, 2);
            if (cleanup_result != 0) LOGE("Failed to unmap unexpected file mapping: %ld", cleanup_result);
          }


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
        if (remote_syscall_failed(bss_map_result) || (uintptr_t)bss_map_result != file_page_end) {
          LOGE("remote MAP_FIXED BSS mismatch for phdr %d: expected %p got %ld",
               i, (void *)file_page_end, bss_map_result);
          if (!remote_syscall_failed(bss_map_result)) {
            long cleanup_args[2] = { bss_map_result, (long)(seg_page_end - file_page_end) };
            long cleanup_result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, cleanup_args, 2);
            if (cleanup_result != 0) LOGE("Failed to unmap unexpected BSS mapping: %ld", cleanup_result);
          }


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

    if (segs_count >= (sizeof(segs) / sizeof(segs[0]))) {
      LOGE("ELF has more PT_LOAD segments than the CSOLoader limit (%zu)",
           sizeof(segs) / sizeof(segs[0]));
      REMOTE_CLEANUP_MAPPING();
      free(phdr);
      close(fd);
      return false;
    }
    segs[segs_count].addr = seg_page;
    segs[segs_count].len = seg_page_len;
    segs[segs_count].final_prot = prot;
    segs_count++;
  }


  args[0] = remote_fd;
  remote_close_fd(pid, regs, syscall_gadget, &remote_fd);
  remote_fd = -1;

  struct elf_dyn_info dinfo;
  if (!elf_load_dyn_info(fd, &eh, phdr, &dinfo)) {
    LOGE("Failed to load ELF dynamic info");

    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);

    return false;
  }

  const char **needed_paths = NULL;
  if (dinfo.needed_count) {
    needed_paths = (const char **)calloc(dinfo.needed_count, sizeof(char *));
    if (!needed_paths) {
      LOGE("Failed to allocate memory for needed paths");

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

      needed_paths[i] = find_remote_module_path(remote_map, soname);
    }
  }

  /* INFO: Apply all relocations */
  if (!apply_relocations(pid, fd, &dinfo, local_map, remote_map, needed_paths, phdr, eh.e_phnum, load_bias)) {
    LOGE("Failed to apply relocations");

    free((void *)needed_paths);
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

      free((void *)needed_paths);
      elf_dyn_info_destroy(&dinfo);
      free(phdr);
      close(fd);

      return false;
    }
  }

  ElfW(Addr) entry_value = 0;
  if (!find_dynsym_value(fd, &dinfo, "entry", &entry_value)) {
    LOGE("Failed to resolve entry from ELF dynsym");

    free((void *)needed_paths);
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);

    return false;
  }

  if ((uintptr_t)entry_value > UINTPTR_MAX - load_bias) {
    LOGE("Entry point address overflow");
    free((void *)needed_paths);
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
    free((void *)needed_paths);
    elf_dyn_info_destroy(&dinfo);
    REMOTE_CLEANUP_MAPPING();
    free(phdr);
    close(fd);
    return false;
  }

  free((void *)needed_paths);
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
  for (unsigned attempt = 1; attempt <= 3; attempt++) {
    long result = remote_syscall(pid, regs, syscall_gadget, SYS_munmap, args, 2);
    if (result == 0) return true;
    LOGE("Remote munmap attempt %u/3 failed for bootstrap image %p (%zu): %ld",
         attempt, (void *)base, size, result);
  }
  return false;
}
