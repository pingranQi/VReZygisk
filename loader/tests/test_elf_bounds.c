#include <stdio.h>
#include <stdlib.h>
#include "elf_util.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <elf> [elf...]", argv[0]);
    return 2;
  }

  for (int i = 1; i < argc; ++i) {
    ElfImg *img = ElfImg_create(argv[i], (void *)(uintptr_t)0x100000);
    if (img != NULL) {
      (void)getSymbOffset(img, "__libc_start_main", NULL);
      (void)getSymbOffset(img, "symbol_that_does_not_exist_for_bounds_test", NULL);
      ElfImg_destroy(img);
    }
  }
  return 0;
}
