#ifndef HIDING_H
#define HIDING_H

#include <stdbool.h>

#include "misc.h"

/*
 * Replaces private VMAs belonging to ReZygisk and its retained modules with
 * anonymous copies at the same virtual addresses.
 *
 * Create /data/adb/rezygisk/disable-anonymous-memory to disable this pass.
 */
bool hide_module_maps(const struct maps_info *libraries);

#endif /* HIDING_H */
