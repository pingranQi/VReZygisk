#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dlfcn.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/limits.h>
#include <pthread.h>
#include <unistd.h>

#define LOG_TAG "zygiskd-companion" LP_SELECT("32", "64")

#include "utils.h"

typedef void (*zygisk_companion_entry)(int);

struct companion_module_thread_args {
  int fd;
  zygisk_companion_entry entry;
};

zygisk_companion_entry load_module(int fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

  void *handle = dlopen(path, RTLD_NOW);
  if (!handle) {
    LOGE("Failed to dlopen module: %s", dlerror());

    return NULL;
  }

  void *entry = dlsym(handle, "zygisk_companion_entry");
  if (!entry) {
    LOGE("Failed to dlsym zygisk_companion_entry: %s", dlerror());

    dlclose(handle);

    return NULL;
  }

  return (zygisk_companion_entry)entry;
}

/* WARNING: Dynamic memory based */
void *entry_thread(void *arg) {
  struct companion_module_thread_args *args = (struct companion_module_thread_args *)arg;

  int fd = args->fd;
  zygisk_companion_entry module_entry = args->entry;

  struct stat st0 = { 0 };
  if (fstat(fd, &st0) == -1) {
    LOGE(" - Failed to get initial client fd stats: %s", strerror(errno));

    free(args);

    return NULL;
  }

  module_entry(fd);

  /* INFO: Only attempt to close the client fd if it appears to be the same file
             and if we can successfully stat it again. This prevents double closes
             if the module companion already closed the fd.
  */
  struct stat st1;
  if (fstat(fd, &st1) != -1 && st0.st_ino == st1.st_ino) {
    LOGI(" - Client fd changed after module entry");

    close(fd);
  }

  free(args);

  return NULL;
}

/* WARNING: Dynamic memory based */
void companion_entry(int fd) {
  LOGI("New companion entry.\n - Client fd: %d\n", fd);

  char name[256 + 1];
  ssize_t ret = read_string(fd, name, sizeof(name));
  if (ret == -1) {
    LOGE("Failed to read module name");

    goto cleanup;
  }

  LOGI(" - Module name: \"%s\"", name);

  int library_fd = read_fd(fd);
  if (library_fd == -1) {
    LOGE("Failed to receive library fd");

    goto cleanup;
  }

  LOGI(" - Library fd: %d", library_fd);

  zygisk_companion_entry module_entry = load_module(library_fd);
  close(library_fd);

  if (module_entry == NULL) {
    LOGE(" - No companion module entry for module: %s", name);

    ret = write_uint8_t(fd, 0);
    ASSURE_SIZE_WRITE("ZygiskdCompanion", "module_entry", ret, sizeof(uint8_t), goto cleanup);

    goto cleanup;
  } else {
    LOGI(" - Module entry found");

    ret = write_uint8_t(fd, 1);
    ASSURE_SIZE_WRITE("ZygiskdCompanion", "module_entry", ret, sizeof(uint8_t), goto cleanup);
  }

  struct sigaction sa = { .sa_handler = SIG_IGN };
  sigaction(SIGPIPE, &sa, NULL);

  while (1) {
    if (!check_unix_socket(fd, true)) {
      LOGE("Something went wrong in companion. Bye!");

      break;
    }

    int client_fd = read_fd(fd);
    if (client_fd == -1) {
      LOGE("Failed to receive client fd");

      break;
    }

    struct companion_module_thread_args *args = malloc(sizeof(struct companion_module_thread_args));
    if (args == NULL) {
      LOGE("Failed to allocate memory for thread args");

      close(client_fd);

      break;
    }

    args->fd = client_fd;
    args->entry = module_entry;

    LOGI("New companion request.\n - Module name: %s\n - Client fd: %d\n", name, client_fd);

    ret = write_uint8_t(client_fd, 1);
    if (ret != sizeof(uint8_t)) {
      LOGE("Failed to send client_fd in ZygiskdCompanion: Expected %zu, got %zd", sizeof(uint8_t), ret);

      free(args);
      close(client_fd);

      break;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, entry_thread, (void *)args) != 0) {
      LOGE(" - Failed to create thread for companion module");

      close(client_fd);
      free(args);

      break;
    }

    pthread_detach(thread);
  }

  cleanup:
    close(fd);
    LOGE("Companion thread exited");

    exit(0);
}

/*
 * Zygisk Next companion ABI is intentionally separate from the ordinary
 * zygisk_companion_entry(int) ABI. Keep the callbacks copied out of the
 * library's exported structure so the dispatcher does not depend on its
 * layout after initialization.
 */
struct zn_companion_module_abi {
  int target_api_version;
  void (*on_companion_loaded)(void);
  void (*on_module_connected)(int fd);
};

struct zn_companion_callbacks {
  void (*on_companion_loaded)(void);
  void (*on_module_connected)(int fd);
};

struct zn_companion_thread_args {
  int fd;
  void (*callback)(int fd);
};

static void *zn_companion_client_thread(void *opaque) {
  struct zn_companion_thread_args *args = opaque;
  int client_fd = args->fd;
  void (*callback)(int) = args->callback;
  free(args);

  if (callback) callback(client_fd);
  else close(client_fd);
  return NULL;
}

static bool load_zn_companion_module(int library_fd,
                                     struct zn_companion_callbacks *callbacks) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", library_fd);
  void *handle = dlopen(path, RTLD_NOW);
  if (!handle) {
    LOGE("ZN companion dlopen failed: %s", dlerror());
    return false;
  }

  struct zn_companion_module_abi *module =
      (struct zn_companion_module_abi *)dlsym(handle, "zn_companion_module");
  if (!module) {
    LOGE("ZN companion symbol zn_companion_module not found: %s", dlerror());
    dlclose(handle);
    return false;
  }
  if (module->target_api_version < 1 || module->target_api_version > 4) {
    LOGE("ZN companion API version %d is unsupported",
         module->target_api_version);
    dlclose(handle);
    return false;
  }

  callbacks->on_companion_loaded = module->on_companion_loaded;
  callbacks->on_module_connected = module->on_module_connected;
  /* Keep handle resident: callbacks point into this image for process life. */
  return true;
}

/* Daemon child entry for the ZN companion ABI. */
void zn_companion_entry(int fd) {
  char module_id[256];
  if (read_string(fd, module_id, sizeof(module_id)) < 0) {
    LOGE("ZN companion failed to read module id");
    close(fd);
    _exit(1);
  }

  int library_fd = read_fd(fd);
  if (library_fd < 0) {
    LOGE("ZN companion failed to receive library fd");
    close(fd);
    _exit(1);
  }

  struct zn_companion_callbacks callbacks = {0};
  bool loaded = load_zn_companion_module(library_fd, &callbacks);
  close(library_fd);

  uint8_t response = loaded ? 1 : 0;
  if (write_uint8_t(fd, response) != sizeof(response) || !loaded) {
    LOGE("ZN companion initialization failed for %s", module_id);
    close(fd);
    _exit(loaded ? 1 : 0);
  }

  LOGI("ZN companion ready for module %s", module_id);
  if (callbacks.on_companion_loaded) callbacks.on_companion_loaded();

  struct sigaction sa = { .sa_handler = SIG_IGN };
  sigaction(SIGPIPE, &sa, NULL);

  while (check_unix_socket(fd, true)) {
    int client_fd = read_fd(fd);
    if (client_fd < 0) {
      LOGE("ZN companion failed to receive client fd");
      break;
    }

    uint8_t ack = 1;
    if (write_uint8_t(client_fd, ack) != sizeof(ack)) {
      LOGE("ZN companion failed to acknowledge client fd");
      close(client_fd);
      continue;
    }

    struct zn_companion_thread_args *args = malloc(sizeof(*args));
    if (!args) {
      PLOGE("allocate ZN companion thread args");
      close(client_fd);
      continue;
    }
    args->fd = client_fd;
    args->callback = callbacks.on_module_connected;

    pthread_t thread;
    if (pthread_create(&thread, NULL, zn_companion_client_thread, args) != 0) {
      LOGE("Failed to create ZN companion client thread");
      close(client_fd);
      free(args);
      continue;
    }
    pthread_detach(thread);
  }

  close(fd);
  LOGI("ZN companion for %s exited", module_id);
  _exit(0);
}
