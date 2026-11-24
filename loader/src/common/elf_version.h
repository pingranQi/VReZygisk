#ifndef VREZYGISK_ELF_VERSION_H
#define VREZYGISK_ELF_VERSION_H

#include <stdint.h>

/*
 * Resolve an explicitly versioned, defined ELF64 symbol in an already mapped
 * AArch64 ET_DYN image. image_base must point at the ELF header mapping whose
 * file offset is zero. Returns the runtime symbol address or 0.
 *
 * This routine does not invoke IFUNC resolvers; callers must handle STT_GNU_IFUNC
 * using the target process' execution backend.
 */
uintptr_t elf_find_versioned_symbol(void *image_base,
                                    const char *symbol_name,
                                    const char *version_name);

/*
 * Resolve a relocation's version requirement: requester_symbol_index selects
 * the requester's .dynsym/.gnu.version entry and DT_VERNEED metadata; the
 * provider is searched by the required version name/hash and DT_VERDEF.
 */
uintptr_t elf_resolve_versioned_symbol(void *provider_base,
                                       void *requester_base,
                                       size_t requester_symbol_index,
                                       const char *symbol_name);

#endif
