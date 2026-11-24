#ifndef ZN_HOOK_H
#define ZN_HOOK_H

#include <stdbool.h>

bool zn_hook_init(void);
int zn_inline_hook(void *target, void *handler, void **original,
                   void *caller_address);
int zn_inline_unhook(void *target, void *caller_address);

#endif
