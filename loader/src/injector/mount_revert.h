#ifndef REZYGISK_MOUNT_REVERT_H
#define REZYGISK_MOUNT_REVERT_H

#include <stdbool.h>

/* Detach root/module mounts from a private copy of the calling process'
 * mount namespace. False means use the cached clean namespace fallback. */
bool revert_root_mounts(void);

/* Close inherited proc mount descriptors and refresh the current mountinfo view. */
void refresh_mountinfo_fds(bool webview_zygote);

#endif
