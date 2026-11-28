#include "misc.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
  assert(classify_map_backing(NULL) == MAP_BACKING_ANONYMOUS);
  assert(classify_map_backing("") == MAP_BACKING_ANONYMOUS);
  assert(classify_map_backing("[heap]") == MAP_BACKING_SPECIAL);
  assert(classify_map_backing("[vdso]") == MAP_BACKING_SPECIAL);
  assert(classify_map_backing("anon_inode:[eventfd]") == MAP_BACKING_SPECIAL);
  assert(classify_map_backing("/memfd:jit-cache (deleted)") == MAP_BACKING_MEMFD);
  assert(classify_map_backing("memfd:jit-cache") == MAP_BACKING_MEMFD);
  assert(classify_map_backing("/data/app/example.apk") == MAP_BACKING_FILE);
  assert(classify_map_backing("/data/app/example.apk (deleted)") == MAP_BACKING_DELETED_FILE);
  puts("maps backing classification tests: PASS");
  return 0;
}
