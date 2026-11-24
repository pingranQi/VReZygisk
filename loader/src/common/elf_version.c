#include "elf_version.h"

#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif
#ifndef DT_VERSYM
#define DT_VERSYM 0x6ffffff0
#endif
#ifndef DT_VERDEF
#define DT_VERDEF 0x6ffffffc
#endif
#ifndef DT_VERDEFNUM
#define DT_VERDEFNUM 0x6ffffffd
#endif
#ifndef DT_VERNEED
#define DT_VERNEED 0x6ffffffe
#endif
#ifndef DT_VERNEEDNUM
#define DT_VERNEEDNUM 0x6fffffff
#endif
#ifndef STT_GNU_IFUNC
#define STT_GNU_IFUNC 10
#endif
#ifndef VER_DEF_CURRENT
#define VER_DEF_CURRENT 1
#endif
#ifndef VER_NDX_GLOBAL
#define VER_NDX_GLOBAL 1
#endif
#ifndef VER_NEED_CURRENT
#define VER_NEED_CURRENT 1
#endif

#define VER_NDX_MASK 0x7fffU
#define VER_FLG_HIDDEN 0x8000U
#define MAX_DYNAMIC_ENTRIES 4096U
#define MAX_VERSION_ENTRIES 4096U

struct image_view {
  uintptr_t begin;
  uintptr_t end;
  uintptr_t bias;
};

struct dynamic_info {
  const Elf64_Sym *symtab;
  const char *strtab;
  const Elf64_Half *versym;
  const Elf64_Verdef *verdef;
  size_t verdef_count;
  const Elf64_Verneed *verneed;
  size_t verneed_count;
  size_t soname_offset;
  size_t strsz;
  size_t syment;
  size_t symbol_count;
  bool has_soname;
};

static bool range_ok(const struct image_view *v, uintptr_t p, size_t n) {
  return p >= v->begin && p <= v->end && n <= v->end - p;
}

static bool add_overflow_uintptr(uintptr_t a, uintptr_t b, uintptr_t *out) {
  if (a > UINTPTR_MAX - b) return true;
  *out = a + b;
  return false;
}

static uintptr_t dynamic_pointer(const struct image_view *v, Elf64_Addr value) {
  uintptr_t p = (uintptr_t)value;
  if (p >= v->begin && p < v->end) return p;
  if (add_overflow_uintptr(v->bias, p, &p)) return 0;
  return p;
}

/* System V ELF hash, also used by Verdef.vd_hash. */
static uint32_t elf_name_hash(const char *name) {
  uint32_t h = 0;
  while (*name) {
    h = (h << 4) + (uint8_t)*name++;
    uint32_t g = h & 0xf0000000U;
    if (g) h ^= g >> 24;
    h &= ~g;
  }
  return h;
}

static bool image_bounds(void *base, struct image_view *v,
                         const Elf64_Ehdr **eh_out,
                         const Elf64_Phdr **phdr_out) {
  if (!base || !v || !eh_out || !phdr_out) return false;
  uintptr_t b = (uintptr_t)base;
  const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
      eh->e_ident[EI_CLASS] != ELFCLASS64 ||
      eh->e_ident[EI_DATA] != ELFDATA2LSB ||
      eh->e_ident[EI_VERSION] != EV_CURRENT ||
      eh->e_machine != EM_AARCH64 ||
      eh->e_type != ET_DYN ||
      eh->e_phentsize != sizeof(Elf64_Phdr) ||
      eh->e_phnum == 0 || eh->e_phnum > 1024) return false;

  uintptr_t phdr_addr;
  size_t phdr_bytes = (size_t)eh->e_phnum * sizeof(Elf64_Phdr);
  if (eh->e_phoff > UINTPTR_MAX - b) return false;
  phdr_addr = b + (uintptr_t)eh->e_phoff;

  uintptr_t lo = UINTPTR_MAX, hi = 0;
  const Elf64_Phdr *phdr = (const Elf64_Phdr *)phdr_addr;
  for (size_t i = 0; i < eh->e_phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) continue;
    if (phdr[i].p_vaddr > UINTPTR_MAX - phdr[i].p_memsz) return false;
    if (phdr[i].p_vaddr < lo) lo = (uintptr_t)phdr[i].p_vaddr;
    uintptr_t seg_end = (uintptr_t)phdr[i].p_vaddr + (uintptr_t)phdr[i].p_memsz;
    if (seg_end > hi) hi = seg_end;
  }
  if (lo != 0 || hi <= lo || hi - lo > SIZE_MAX) return false;

  /* VReZygisk's offset-zero map lookup requires the conventional vaddr=0 image. */
  uintptr_t bias = b;
  uintptr_t image_end;
  if (add_overflow_uintptr(bias, hi, &image_end) || image_end <= b) return false;

  v->begin = b;
  v->end = image_end;
  v->bias = bias;
  if (!range_ok(v, phdr_addr, phdr_bytes)) return false;
  *eh_out = eh;
  *phdr_out = phdr;
  return true;
}

static size_t gnu_hash_symbol_count(const struct image_view *v,
                                    const uint32_t *gh) {
  if (!range_ok(v, (uintptr_t)gh, 4 * sizeof(uint32_t))) return 0;
  uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2];
  if (!nbuckets || !bloom_size || nbuckets > 1U << 20 ||
      bloom_size > 1U << 20 || symoffset > 1U << 24) return 0;

  uintptr_t p = (uintptr_t)(gh + 4);
  size_t bloom_bytes = (size_t)bloom_size * sizeof(Elf64_Xword);
  if (!range_ok(v, p, bloom_bytes)) return 0;
  p += bloom_bytes;
  size_t bucket_bytes = (size_t)nbuckets * sizeof(uint32_t);
  if (!range_ok(v, p, bucket_bytes)) return 0;
  const uint32_t *buckets = (const uint32_t *)p;
  p += bucket_bytes;
  if (p > v->end) return 0;
  const uint32_t *chains = (const uint32_t *)p;
  size_t chain_capacity = (v->end - p) / sizeof(uint32_t);
  size_t max_symbol = symoffset;

  for (uint32_t i = 0; i < nbuckets; ++i) {
    uint32_t idx = buckets[i];
    if (idx < symoffset) continue;
    size_t steps = 0;
    while (idx >= symoffset) {
      size_t ci = (size_t)(idx - symoffset);
      if (ci >= chain_capacity || ++steps > chain_capacity) return 0;
      uint32_t hash = chains[ci];
      if ((size_t)idx + 1 > max_symbol) max_symbol = (size_t)idx + 1;
      if (hash & 1U) break;
      if (idx == UINT32_MAX) return 0;
      ++idx;
    }
  }
  return max_symbol;
}

static bool parse_dynamic(const struct image_view *v,
                          const Elf64_Ehdr *eh, const Elf64_Phdr *phdr,
                          struct dynamic_info *di) {
  uintptr_t dyn_addr = 0;
  size_t dyn_size = 0;
  for (size_t i = 0; i < eh->e_phnum; ++i) {
    if (phdr[i].p_type == PT_DYNAMIC) {
      dyn_addr = dynamic_pointer(v, phdr[i].p_vaddr);
      dyn_size = (size_t)phdr[i].p_memsz;
      break;
    }
  }
  if (!dyn_addr || dyn_size < sizeof(Elf64_Dyn) ||
      !range_ok(v, dyn_addr, dyn_size)) return false;

  const Elf64_Dyn *dyn = (const Elf64_Dyn *)dyn_addr;
  size_t count = dyn_size / sizeof(*dyn);
  if (count > MAX_DYNAMIC_ENTRIES) count = MAX_DYNAMIC_ENTRIES;
  bool terminated = false;

  uintptr_t hash_addr = 0, gnu_hash_addr = 0;
  bool have_strsz = false, have_syment = false;
  for (size_t i = 0; i < count; ++i) {
    if (dyn[i].d_tag == DT_NULL) { terminated = true; break; }
    uintptr_t p = dynamic_pointer(v, dyn[i].d_un.d_ptr);
    switch (dyn[i].d_tag) {
      case DT_SYMTAB: di->symtab = (const Elf64_Sym *)p; break;
      case DT_STRTAB: di->strtab = (const char *)p; break;
      case DT_STRSZ:
        di->strsz = (size_t)dyn[i].d_un.d_val;
        have_strsz = true;
        break;
      case DT_SYMENT:
        di->syment = (size_t)dyn[i].d_un.d_val;
        have_syment = true;
        break;
      case DT_HASH: hash_addr = p; break;
      case DT_GNU_HASH: gnu_hash_addr = p; break;
      case DT_VERSYM: di->versym = (const Elf64_Half *)p; break;
      case DT_VERDEF: di->verdef = (const Elf64_Verdef *)p; break;
      case DT_VERDEFNUM: di->verdef_count = (size_t)dyn[i].d_un.d_val; break;
      case DT_VERNEED: di->verneed = (const Elf64_Verneed *)p; break;
      case DT_VERNEEDNUM: di->verneed_count = (size_t)dyn[i].d_un.d_val; break;
      case DT_SONAME:
        di->soname_offset = (size_t)dyn[i].d_un.d_val;
        di->has_soname = true;
        break;
      default: break;
    }
  }
  if (!terminated || !di->symtab || !di->strtab ||
      !have_strsz || !have_syment || di->syment != sizeof(Elf64_Sym) ||
      di->strsz == 0) return false;
  if (hash_addr) {
    const uint32_t *h = (const uint32_t *)hash_addr;
    if (!range_ok(v, hash_addr, 2 * sizeof(uint32_t))) return false;
    if (h[0] == 0 || h[0] > (1U << 20) || h[1] == 0 ||
        h[1] > (1U << 24)) return false;
    size_t hash_words = 2U + (size_t)h[0] + (size_t)h[1];
    if (hash_words > SIZE_MAX / sizeof(uint32_t) ||
        !range_ok(v, hash_addr, hash_words * sizeof(uint32_t))) return false;
    di->symbol_count = h[1];
  } else if (gnu_hash_addr) {
    di->symbol_count = gnu_hash_symbol_count(v, (const uint32_t *)gnu_hash_addr);
  }
  if (!di->symbol_count || di->symbol_count > (v->end - v->begin) / sizeof(Elf64_Sym))
    return false;
  if (!range_ok(v, (uintptr_t)di->symtab,
                di->symbol_count * sizeof(Elf64_Sym))) return false;
  if (di->versym &&
      !range_ok(v, (uintptr_t)di->versym,
                di->symbol_count * sizeof(Elf64_Half))) return false;
  if (!range_ok(v, (uintptr_t)di->strtab, di->strsz)) return false;
  if (di->verdef_count > MAX_VERSION_ENTRIES ||
      di->verneed_count > MAX_VERSION_ENTRIES) return false;
  if (di->verdef_count && (!di->verdef ||
      !range_ok(v, (uintptr_t)di->verdef, sizeof(Elf64_Verdef)))) return false;
  if (di->verneed_count && (!di->verneed ||
      !range_ok(v, (uintptr_t)di->verneed, sizeof(Elf64_Verneed)))) return false;
  if (di->has_soname &&
      (di->soname_offset >= di->strsz ||
       !memchr(di->strtab + di->soname_offset, '\0',
               di->strsz - di->soname_offset))) return false;
  return true;
}

static bool version_name_for_index(const struct image_view *v,
                                   const struct dynamic_info *di,
                                   uint16_t wanted_index,
                                   const char **out_name,
                                   uint32_t *out_hash) {
  if (!di->verdef || !di->verdef_count || wanted_index <= VER_NDX_GLOBAL)
    return false;
  uintptr_t cur = (uintptr_t)di->verdef;
  for (size_t i = 0; i < di->verdef_count; ++i) {
    if (!range_ok(v, cur, sizeof(Elf64_Verdef))) return false;
    const Elf64_Verdef *vd = (const Elf64_Verdef *)cur;
    if (vd->vd_version != VER_DEF_CURRENT || vd->vd_cnt == 0 ||
        vd->vd_cnt > 64 || vd->vd_aux == 0) return false;

    uintptr_t aux_addr;
    if (add_overflow_uintptr(cur, vd->vd_aux, &aux_addr) ||
        !range_ok(v, aux_addr, sizeof(Elf64_Verdaux))) return false;
    const Elf64_Verdaux *aux = (const Elf64_Verdaux *)aux_addr;
    if ((vd->vd_ndx & VER_NDX_MASK) == wanted_index) {
      size_t maxstr = di->strsz;
      if (aux->vda_name >= maxstr) return false;
      const char *name = di->strtab + aux->vda_name;
      if (!memchr(name, '\0', maxstr - aux->vda_name)) return false;
      *out_name = name;
      *out_hash = vd->vd_hash;
      return true;
    }
    if (!vd->vd_next) break;
    uintptr_t next;
    if (add_overflow_uintptr(cur, vd->vd_next, &next) || next <= cur) return false;
    cur = next;
  }
  return false;
}

uintptr_t elf_find_versioned_symbol(void *image_base,
                                    const char *symbol_name,
                                    const char *version_name) {
  if (!image_base || !symbol_name || !*symbol_name ||
      !version_name || !*version_name) return 0;

  struct image_view view = {0};
  const Elf64_Ehdr *eh = NULL;
  const Elf64_Phdr *phdr = NULL;
  if (!image_bounds(image_base, &view, &eh, &phdr)) return 0;

  struct dynamic_info di = {0};
  if (!parse_dynamic(&view, eh, phdr, &di) || !di.versym ||
      !di.verdef || !di.verdef_count) return 0;

  uint32_t wanted_hash = elf_name_hash(version_name);
  for (size_t i = 0; i < di.symbol_count; ++i) {
    const Elf64_Sym *sym = &di.symtab[i];
    if (sym->st_name == 0 || sym->st_shndx == SHN_UNDEF ||
        sym->st_name >= di.strsz) continue;

    unsigned bind = ELF64_ST_BIND(sym->st_info);
    unsigned type = ELF64_ST_TYPE(sym->st_info);
    unsigned visibility = sym->st_other & 0x3U;
    if ((bind != STB_GLOBAL && bind != STB_WEAK
#ifdef STB_GNU_UNIQUE
         && bind != STB_GNU_UNIQUE
#endif
        ) || (visibility != STV_DEFAULT && visibility != STV_PROTECTED) ||
        type == STT_TLS || type == STT_GNU_IFUNC) continue;

    const char *name = di.strtab + sym->st_name;
    size_t maxstr = di.strsz;
    if (!memchr(name, '\0', maxstr - sym->st_name) ||
        strcmp(name, symbol_name) != 0) continue;

    uint16_t vi = di.versym[i] & VER_NDX_MASK;
    const char *candidate_version = NULL;
    uint32_t candidate_hash = 0;
    if (!version_name_for_index(&view, &di, vi,
                                &candidate_version, &candidate_hash)) continue;
    if (candidate_hash != wanted_hash ||
        strcmp(candidate_version, version_name) != 0) continue;

    uintptr_t result;
    if (add_overflow_uintptr(view.bias, (uintptr_t)sym->st_value, &result))
      return 0;
    if (result < view.begin || result >= view.end) return 0;
    return result;
  }
  return 0;
}


uintptr_t elf_resolve_versioned_symbol(void *provider_base,
                                       void *requester_base,
                                       size_t requester_symbol_index,
                                       const char *symbol_name) {
  if (!provider_base || !requester_base || !symbol_name || !*symbol_name)
    return 0;

  struct image_view requester_view = {0};
  const Elf64_Ehdr *requester_eh = NULL;
  const Elf64_Phdr *requester_phdr = NULL;
  if (!image_bounds(requester_base, &requester_view,
                    &requester_eh, &requester_phdr)) return 0;

  struct dynamic_info request = {0};
  if (!parse_dynamic(&requester_view, requester_eh, requester_phdr, &request) ||
      !request.versym || !request.verneed || !request.verneed_count ||
      requester_symbol_index >= request.symbol_count) return 0;

  uint16_t wanted = request.versym[requester_symbol_index] & VER_NDX_MASK;
  if (wanted <= VER_NDX_GLOBAL) return 0;

  uintptr_t need_addr = (uintptr_t)request.verneed;
  for (size_t i = 0; i < request.verneed_count; ++i) {
    if (!range_ok(&requester_view, need_addr, sizeof(Elf64_Verneed))) return 0;
    const Elf64_Verneed *need = (const Elf64_Verneed *)need_addr;
    if (need->vn_version != VER_NEED_CURRENT || !need->vn_aux) return 0;

    uintptr_t aux_addr;
    if (add_overflow_uintptr(need_addr, need->vn_aux, &aux_addr)) return 0;
    for (size_t j = 0; j < need->vn_cnt; ++j) {
      if (!range_ok(&requester_view, aux_addr, sizeof(Elf64_Vernaux))) return 0;
      const Elf64_Vernaux *aux = (const Elf64_Vernaux *)aux_addr;
      if ((aux->vna_other & VER_NDX_MASK) == wanted) {
        size_t str_size = request.strsz;
        if (aux->vna_name >= str_size || need->vn_file >= str_size) return 0;
        const char *required_version = request.strtab + aux->vna_name;
        const char *required_provider = request.strtab + need->vn_file;
        if (!memchr(required_version, '\0', str_size - aux->vna_name) ||
            !memchr(required_provider, '\\0', str_size - need->vn_file) ||
            aux->vna_hash != elf_name_hash(required_version)) return 0;

        struct image_view provider_view = {0};
        const Elf64_Ehdr *provider_eh = NULL;
        const Elf64_Phdr *provider_phdr = NULL;
        if (!image_bounds(provider_base, &provider_view,
                          &provider_eh, &provider_phdr)) return 0;
        struct dynamic_info provider = {0};
        if (!parse_dynamic(&provider_view, provider_eh, provider_phdr, &provider))
          return 0;

        /* If the provider advertises DT_SONAME, enforce the VERNEED owner. */
        if (provider.has_soname) {
          size_t provider_str_size = provider.strsz;
          if (provider.soname_offset >= provider_str_size) return 0;
          const char *soname = provider.strtab + provider.soname_offset;
          if (!memchr(soname, '\\0', provider_str_size - provider.soname_offset) ||
              strcmp(soname, required_provider) != 0) return 0;
        }
        return elf_find_versioned_symbol(provider_base, symbol_name,
                                         required_version);
      }
      if (!aux->vna_next) break;
      uintptr_t next;
      if (add_overflow_uintptr(aux_addr, aux->vna_next, &next) ||
          next <= aux_addr) return 0;
      aux_addr = next;
    }
    if (!need->vn_next) break;
    uintptr_t next;
    if (add_overflow_uintptr(need_addr, need->vn_next, &next) ||
        next <= need_addr) return 0;
    need_addr = next;
  }
  return 0;
}
