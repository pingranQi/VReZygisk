#include "daemon.h"
#include "logging.h"
#include "misc.h"

#include <sys/stat.h>

#include "hook.h"
#include "ptrace_clear.h"
#include "zn_api.h"

__attribute__((visibility("default")))
int entry(void *addr, size_t size, int tango_flag) {
  LOGD("ReZygisk%s library injected, version %s", tango_flag ? " [TANGO]" : "", ZKSU_VERSION);

  start_addr = addr;
  block_size = size;

  struct stat self_stat;
  if (stat("/data/adb/modules/rezygisk/lib" LP_SELECT("", "64") "/libzygisk.so", &self_stat) != 0) {
    PLOGE("Failed to stat self library");

    return -1;
  }

  self_dev = self_stat.st_dev;
  self_ino = self_stat.st_ino;

  if (!rezygiskd_zygote_injected()) {
    LOGE("ReZygiskd is not running; refusing to install hooks");

    return -2;
  }

  LOGD("start plt hooking");
  hook_functions();

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    LOGD("Supported kernel version %d.%d.%d, sending seccomp event", version.major, version.minor, version.patch);

    perform_ptrace_message_clear();
  }

  LOGD("Zygisk library execution done, addr: %p, size: %zu", addr, size);
  return 0;
}

/* Separate entry point for init-exec ZN targets. It deliberately does not
 * install the ART/Zygisk hooks used by the ordinary app_process entry. */
__attribute__((visibility("default")))
int zn_entry(void *addr, size_t size, int unused) {
  (void)unused;
  LOGI("ZN loader injected, version %s", ZKSU_VERSION);
  start_addr = addr;
  block_size = size;

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8))
    perform_ptrace_message_clear();

  if (!zn_modules_load_for_current_process()) {
    LOGW("No ZN module was loaded for the current executable");
    return 1;
  }
  return 0;
}
