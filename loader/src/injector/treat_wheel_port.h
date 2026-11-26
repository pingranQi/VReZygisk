/* ReZygisk Treat Wheel compatibility port declarations. */
#ifndef TREAT_WHEEL_PORT_H
#define TREAT_WHEEL_PORT_H

#include <stdbool.h>

bool treat_wheel_hide_frida_traces(void);
bool treat_wheel_scrub_mntent_buffer(void);
bool treat_wheel_umount_revanced_mounts(const char *process_name);

#endif /* TREAT_WHEEL_PORT_H */
