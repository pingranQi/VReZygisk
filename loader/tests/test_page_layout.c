#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "page_layout.h"

static void test_page_size(size_t page) {
  uintptr_t start = 0, end = 0;
  assert(rz_page_align_down((uintptr_t)page + 17, page, &start));
  assert(start == page);
  assert(rz_page_align_up((uintptr_t)page + 17, page, &end));
  assert(end == page * 2);

  assert(rz_page_range((uintptr_t)page + 3, (uintptr_t)page * 2 + 1,
                       page, &start, &end));
  assert(start == page);
  assert(end == page * 3);

  assert(!rz_page_range(100, 100, page, &start, &end));
}

int main(void) {
  test_page_size(4096);
  test_page_size(16384);

  uintptr_t out = 0;
  assert(!rz_page_align_up(UINTPTR_MAX - 7, 4096, &out));
  assert(!rz_page_align_down(123, 3000, &out));
  assert(!rz_page_align_down(123, 0, &out));

  puts("page layout tests (4 KiB / 16 KiB): PASS");
  return 0;
}
