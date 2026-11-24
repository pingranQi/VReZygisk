#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daemon.h"
#include "monitor.h"

int main(int argc, char **argv) {
  printf("The ReZygisk Tracer %s\n\n", ZKSU_VERSION);

  if (argc >= 2 && strcmp(argv[1], "monitor") == 0) {
    init_monitor();

    return 0;
  } else if (argc >= 3 && strcmp(argv[1], "trace-zn") == 0) {
      long pid = strtol(argv[2], 0, 0);
      if (!trace_zn_target((int)pid)) {
        printf("[ReZygisk] ZN target injection failed for pid %ld; target resumed\n", pid);
        return 1;
      }
      return 0;
  } else if (argc >= 3 && strcmp(argv[1], "trace") == 0) {
      bool do_restart = false;

      for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--restart") == 0) do_restart = true;
      }

      if (do_restart) rezygiskd_zygote_restart();

      long pid = strtol(argv[2], 0, 0);
      if (!trace_zygote(pid)) {
        kill(pid, SIGKILL);
        return 1;
      }

      return 0;
  } else if (argc >= 2 && strcmp(argv[1], "ctl") == 0) {
    enum rezygiskd_command command;

    if (strcmp(argv[2], "start") == 0) command = START;
    else if (strcmp(argv[2], "stop") == 0) command = STOP;
    else if (strcmp(argv[2], "exit") == 0) command = EXIT;
    else {
      printf("[ReZygisk]: Usage: %s ctl <start|stop|exit>\n", argv[0]);

      return 1;
    }

    if (send_control_command(command) == -1) {
      printf("[ReZygisk]: Failed to send the command, is the daemon running?\n");

      return 1;
    }

    printf("[ReZygisk]: command sent\n");

    return 0;
  } else if (argc >= 2 && strcmp(argv[1], "version") == 0) {
    /* INFO: Noop*/

    return 0;
  } else if (argc >= 2 && strcmp(argv[1], "info") == 0) {
    struct rezygisk_info info;
    rezygiskd_get_info(&info);

    printf("Daemon process PID: %d\n", info.pid);

    switch (info.root_impl) {
      case ROOT_IMPL_NONE: {
        printf("Root implementation: none\n");

        break;
      }
      case ROOT_IMPL_APATCH: {
        printf("Root implementation: APatch\n");

        break;
      }
      case ROOT_IMPL_KERNELSU: {
        printf("Root implementation: KernelSU\n");

        break;
      }
      case ROOT_IMPL_MAGISK: {
        printf("Root implementation: Magisk\n");

        break;
      }
    }

    struct zn_module_list zn_modules = {0};
    bool zn_available = rezygiskd_read_zn_modules(&zn_modules);

    printf("Zygisk modules: %zu\n", info.modules.modules_count);
    for (size_t i = 0; i < info.modules.modules_count; i++) {
      bool hybrid = false;
      for (size_t j = 0; zn_available && j < zn_modules.count; j++) {
        if (strcmp(info.modules.modules[i], zn_modules.items[j].module_id) == 0) {
          hybrid = true;
          break;
        }
      }
      printf(" - %s%s\n", info.modules.modules[i], hybrid ? " [Hybrid]" : "");
    }

    if (zn_available) {
      printf("ZN targets: %zu\n", zn_modules.count);
      for (size_t i = 0; i < zn_modules.count; i++) {
        const struct zn_module_info *entry = &zn_modules.items[i];
        bool hybrid = false;
        for (size_t j = 0; j < info.modules.modules_count; j++) {
          if (strcmp(info.modules.modules[j], entry->module_id) == 0) {
            hybrid = true;
            break;
          }
        }
        printf(" - %s%s -> %s (%s, library=%s, companion=%s)\n",
               entry->module_id, hybrid ? " [Hybrid]" : "", entry->target,
               entry->target_type == ZN_TARGET_PATH ? "path" : "name",
               entry->library, entry->companion ? "yes" : "no");
      }
    } else {
      printf("ZN targets: unavailable (daemon not ready)\n");
    }

    rezygiskd_free_zn_modules(&zn_modules);
    free_rezygisk_info(&info);

    return 0;
  } else {
    printf(
      "Available commands:\n"
      " - monitor\n"
      " - trace <pid> [--restart]\n"
      " - trace-zn <pid>\n"
      " - ctl <start|stop|exit>\n"
      " - version: Shows the version of ReZygisk.\n"
      " - info: Shows information about the created daemon/injection.\n"
      "\n"
      "<...>: Obligatory\n"
      "[...]: Optional\n");

    return 1;
  }
}
