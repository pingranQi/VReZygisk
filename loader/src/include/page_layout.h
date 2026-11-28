#ifndef PAGE_LAYOUT_H
#define PAGE_LAYOUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Android supports both 4 KiB and 16 KiB runtime pages. */
static inline bool rz_page_size_valid(size_t page_size) {
  return page_size >= 4096 && (page_size & (page_size - 1)) == 0;
}

static inline bool rz_page_align_down(uintptr_t value, size_t page_size,
                                      uintptr_t *out) {
  if (!out || !rz_page_size_valid(page_size)) return false;
  *out = value & ~((uintptr_t)page_size - 1u);
  return true;
}

static inline bool rz_page_align_up(uintptr_t value, size_t page_size,
                                    uintptr_t *out) {
  if (!out || !rz_page_size_valid(page_size) ||
      value > UINTPTR_MAX - (page_size - 1u)) return false;
  *out = (value + page_size - 1u) & ~((uintptr_t)page_size - 1u);
  return true;
}

static inline bool rz_page_range(uintptr_t start, uintptr_t end,
                                 size_t page_size, uintptr_t *out_start,
                                 uintptr_t *out_end) {
  if (!out_start || !out_end || end <= start ||
      !rz_page_align_down(start, page_size, out_start) ||
      !rz_page_align_up(end, page_size, out_end) ||
      *out_end <= *out_start) return false;
  return true;
}

#endif
