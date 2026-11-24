#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>

#include <linux/limits.h>
#include <linux/memfd.h>
#include <unistd.h>

#include "constants.h"
#include "root_impl/common.h"
#include "utils.h"
#include "zn_modules.h"

extern char **environ;

struct Module {
  char *name;
  int lib_fd;
  int companion;
};

struct Context {
  struct Module *modules;
  size_t len;
  struct zn_module_list zn_modules;
  pthread_mutex_t zn_mutex;
};

struct rzd_msg_header {
  uint8_t cmd;
  uint32_t len;
  char data[0];
} __attribute__((packed));

struct rzd_info_payload {
  char impl[LONGEST_ROOT_IMPL_NAME];
  uint32_t modules_count;
  char data[0];
} __attribute__((packed));

#define PATH_MODULES_DIR "/data/adb/modules"
#define TMP_PATH "/data/adb/rezygisk"
#define CONTROLLER_SOCKET TMP_PATH "/init_monitor"
#define PATH_CP_NAME TMP_PATH "/" LP_SELECT("cp32.sock", "cp64.sock")
#define ZYGISKD_FILE PATH_MODULES_DIR "/rezygisk/bin/zygiskd" LP_SELECT("32", "64")
#define ZYGISKD_PATH "/data/adb/modules/rezygisk/bin/zygiskd" LP_SELECT("32", "64")

#ifdef __aarch64__
  #define ARCH_STR "arm64-v8a"
#elif __arm__
  #define ARCH_STR "armeabi-v7a"
#elif __x86_64__
  #define ARCH_STR "x86_64"
#elif __i386__
  #define ARCH_STR "x86"
#else
  #error "Unsupported architecture"
  #define ARCH_STR "unknown"
#endif

/* WARNING: Dynamic memory based */
static void load_modules(struct Context *restrict context) {
  context->len = 0;
  context->modules = NULL;

  DIR *dir = opendir(PATH_MODULES_DIR);
  if (dir == NULL) {
    LOGE("Failed opening modules directory: %s.", PATH_MODULES_DIR);

    return;
  }

  LOGI("Loading modules for architecture: " ARCH_STR);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_DIR) continue; /* INFO: Only directories */
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    char *name = entry->d_name;
    char so_path[PATH_MAX];
    snprintf(so_path, PATH_MAX, "/data/adb/modules/%s/zygisk/" ARCH_STR ".so", name);

    if (access(so_path, R_OK) == -1) continue;

    char disabled[PATH_MAX];
    snprintf(disabled, PATH_MAX, "/data/adb/modules/%s/disable", name);

    if (access(disabled, F_OK) == 0) continue;

    int lib_fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (lib_fd == -1) {
      LOGE("Failed loading module \"%s\"", name);

      continue;
    }

    struct Module *tmp_modules = realloc(context->modules, (context->len + 1) * sizeof(struct Module));
    if (tmp_modules == NULL) {
      LOGE("Failed reallocating memory for modules.");

      close(lib_fd);

      for (size_t i = 0; i < context->len; i++) {
        free(context->modules[i].name);
        if (context->modules[i].companion >= 0) close(context->modules[i].companion);
        if (context->modules[i].lib_fd >= 0) close(context->modules[i].lib_fd);
      }

      free(context->modules);
      context->modules = NULL;
      context->len = 0;

      closedir(dir);

      return;
    }
    context->modules = tmp_modules;

    context->modules[context->len].name = strdup(name);
    if (context->modules[context->len].name == NULL) {
      LOGE("Failed to strdup for the module \"%s\": %s", name, strerror(errno));

      close(lib_fd);

      for (size_t i = 0; i < context->len; i++) {
        free(context->modules[i].name);
        if (context->modules[i].companion >= 0) close(context->modules[i].companion);
        if (context->modules[i].lib_fd >= 0) close(context->modules[i].lib_fd);
      }

      free(context->modules);
      context->modules = NULL;
      context->len = 0;

      closedir(dir);

      return;
    }

    context->modules[context->len].lib_fd = lib_fd;
    context->modules[context->len].companion = -1;
    context->len++;
  }

  closedir(dir);
}

static void free_modules(struct Context *restrict context) {
  zn_modules_free(&context->zn_modules);
  for (size_t i = 0; i < context->len; i++) {
    free(context->modules[i].name);
    if (context->modules[i].companion >= 0) close(context->modules[i].companion);
    if (context->modules[i].lib_fd >= 0) close(context->modules[i].lib_fd);
  }

  free(context->modules);
}

static int create_daemon_socket(void) {
  set_socket_create_context("u:r:zygote:s0");

  return unix_listener_from_path(PATH_CP_NAME);
}

static int spawn_companion(char *restrict argv[], char *restrict name, int lib_fd) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    LOGE("Failed creating socket pair.");

    return -1;
  }

  int daemon_fd = sockets[0];
  int companion_fd = sockets[1];

  pid_t pid = fork();
  if (pid < 0) {
    LOGE("Failed forking companion: %s", strerror(errno));

    close(companion_fd);
    close(daemon_fd);

    return -1;
  }

  if (pid > 0) {
    close(companion_fd);

    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      LOGE("Exited with status %d", status);

      close(daemon_fd);

      return -1;
    }

    if (write_string(daemon_fd, name) == -1) {
      LOGE("Failed writing module name.");

      close(daemon_fd);

      return -1;
    }

    if (write_fd(daemon_fd, lib_fd) == -1) {
      LOGE("Failed sending library fd.");

      close(daemon_fd);

      return -1;
    }

    uint8_t response = 0;
    ssize_t ret = read_uint8_t(daemon_fd, &response);
    if (ret <= 0) {
      LOGE("Failed reading companion response.");

      close(daemon_fd);

      return -1;
    }

    switch (response) {
      /* INFO: Even without any entry, we should still just deal with it */
      case 0: {
        close(daemon_fd);

        return -2;
      }
      case 1: { return daemon_fd; }
      /* TODO: Should we be closing daemon socket here? (in non-0-and-1 case) */
      default: {
        close(daemon_fd);

        return -1;
      }
    }
  /* INFO: if pid == 0: */
  }

  close(daemon_fd);

  /* INFO: There is no case where this will fail with a valid fd. */
  /* INFO: Remove FD_CLOEXEC flag to avoid closing upon exec */
  if (fcntl(companion_fd, F_SETFD, 0) == -1) {
    LOGE("Failed removing FD_CLOEXEC flag: %s", strerror(errno));

    close(companion_fd);

    exit(1);
  }

  char *process = argv[0];
  char nice_name[256];
  char *last = strrchr(process, '/');
  if (last == NULL) {
    snprintf(nice_name, sizeof(nice_name), "%s", process);
  } else {
    snprintf(nice_name, sizeof(nice_name), "%s", last + 1);
  }

  char process_name[256];
  snprintf(process_name, sizeof(process_name), "%s-%s", nice_name, name);

  char companion_fd_str[32];
  snprintf(companion_fd_str, sizeof(companion_fd_str), "%d", companion_fd);

  char companion[] = "companion";
  char *eargv[] = { process_name, companion, companion_fd_str, NULL };
  if (non_blocking_execv(ZYGISKD_PATH, eargv) == -1) {
    LOGE("Failed executing companion: %s", strerror(errno));

    close(companion_fd);

    exit(1);
  }

  exit(0);
}

/*
 * Copy a root-readable module image into an anonymous sealed file before
 * passing it to an app-domain process. This avoids requiring the receiver to
 * traverse /data/adb/modules and avoids exposing the original module path.
 */
static int create_zn_module_memfd(const char *path) {
#ifdef SYS_memfd_create
  int source = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (source < 0) {
    LOGE("Failed opening ZN module image %s: %s", path, strerror(errno));
    return -1;
  }

  struct stat st;
  if (fstat(source, &st) != 0 || !S_ISREG(st.st_mode) ||
      st.st_size <= 0 || (uint64_t)st.st_size > (256ULL * 1024 * 1024)) {
    LOGE("Rejecting invalid ZN module image size/type: %s", path);
    close(source);
    return -1;
  }

  int image = (int)syscall(SYS_memfd_create, "zn_module",
                           MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (image < 0) {
    LOGE("memfd_create for %s failed: %s", path, strerror(errno));
    close(source);
    return -1;
  }

  char buffer[16384];
  bool ok = true;
  for (;;) {
    ssize_t n = read(source, buffer, sizeof(buffer));
    if (n == 0) break;
    if (n < 0) {
      if (errno == EINTR) continue;
      ok = false;
      break;
    }

    ssize_t offset = 0;
    while (offset < n) {
      ssize_t written = write(image, buffer + offset, (size_t)(n - offset));
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) {
        ok = false;
        break;
      }
      offset += written;
    }
    if (!ok) break;
  }

  close(source);
  if (!ok || lseek(image, 0, SEEK_SET) < 0) {
    LOGE("Failed copying ZN module image %s: %s", path, strerror(errno));
    close(image);
    return -1;
  }

  if (fcntl(image, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
    LOGE("Failed sealing ZN module image %s: %s", path, strerror(errno));
    close(image);
    return -1;
  }
  return image;
#else
  (void)path;
  errno = ENOSYS;
  LOGE("memfd_create is unavailable in this build");
  return -1;
#endif
}

static int spawn_zn_companion(char *restrict argv[],
                                struct zn_module_entry *module) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == -1) {
    LOGE("Failed creating ZN companion socket pair: %s", strerror(errno));
    return -1;
  }

  int daemon_fd = sockets[0];
  int companion_fd = sockets[1];
  int child_fd = 198;
  while (child_fd == daemon_fd || child_fd == companion_fd) ++child_fd;

  const char *process = argv[0];
  const char *last = strrchr(process, '/');
  char process_name[256];
  snprintf(process_name, sizeof(process_name), "%s-zn-%s",
           last ? last + 1 : process, module->module_id);
  char fd_string[32];
  snprintf(fd_string, sizeof(fd_string), "%d", child_fd);
  char command[] = "zn-companion";
  char *child_argv[] = {process_name, command, fd_string, NULL};

  pid_t pid = fork();
  if (pid < 0) {
    LOGE("Failed forking ZN companion: %s", strerror(errno));
    close(daemon_fd);
    close(companion_fd);
    return -1;
  }

  if (pid == 0) {
    /* Only async-signal-safe operations are allowed between fork and execve:
     * the daemon may already have broker threads running. dup2() also clears
     * FD_CLOEXEC on the fixed child descriptor. */
    close(daemon_fd);
    if (dup2(companion_fd, child_fd) == -1) _exit(127);
    close(companion_fd);
    execve(ZYGISKD_PATH, child_argv, environ);
    _exit(127);
  }

  close(companion_fd);
  int library_fd = open(module->library, O_RDONLY | O_CLOEXEC);
  if (library_fd < 0) {
    LOGE("Failed opening ZN companion library %s: %s",
         module->library, strerror(errno));
    close(daemon_fd);
    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR) {}
    return -1;
  }

  if (write_string(daemon_fd, module->module_id) < 0 ||
      write_fd(daemon_fd, library_fd) != 1) {
    LOGE("Failed sending ZN companion bootstrap data for %s",
         module->module_id);
    close(library_fd);
    close(daemon_fd);
    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR) {}
    return -1;
  }
  close(library_fd);

  uint8_t response = 0;
  if (read_uint8_t(daemon_fd, &response) != sizeof(response) || response != 1) {
    LOGE("ZN companion module initialization rejected for %s",
         module->module_id);
    close(daemon_fd);
    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR) {}
    return -2;
  }

  module->companion_pid = pid;
  LOGI("Started ZN companion for module %s (pid=%d)",
       module->module_id, pid);
  return daemon_fd;
}

static void close_zn_companion(struct zn_module_entry *module) {
  if (!module) return;
  if (module->companion_fd >= 0) {
    (void)shutdown(module->companion_fd, SHUT_RDWR);
    close(module->companion_fd);
    module->companion_fd = -1;
  }
  if (module->companion_pid > 0) {
    pid_t waited;
    do {
      waited = waitpid(module->companion_pid, NULL, 0);
    } while (waited == -1 && errno == EINTR);
    if (waited == module->companion_pid ||
        (waited == -1 && errno == ECHILD))
      module->companion_pid = -1;
  }
}

struct zn_broker_thread_args {
  struct Context *context;
  size_t module_index;
  int broker_fd;
  char *restrict *argv;
};

static void *zn_companion_broker_thread(void *opaque) {
  struct zn_broker_thread_args *args = opaque;
  struct Context *context = args->context;
  const size_t index = args->module_index;
  const int broker_fd = args->broker_fd;
  char *restrict *argv = args->argv;
  free(args);

  LOGI("ZN companion broker started for manifest index %zu", index);
  for (;;) {
    int client_fd = read_fd(broker_fd);
    if (client_fd < 0) break;

    bool dispatched = false;
    pthread_mutex_lock(&context->zn_mutex);
    if (index < context->zn_modules.count) {
      struct zn_module_entry *module = &context->zn_modules.items[index];
      if (module->companion_fd >= 0 &&
          !check_unix_socket(module->companion_fd, false))
        close_zn_companion(module);

      if (module->companion_fd < 0) {
        module->companion_fd = spawn_zn_companion(argv, module);
      }

      if (module->companion_fd >= 0 &&
          write_fd(module->companion_fd, client_fd) == 1) {
        dispatched = true;
      } else if (module->companion_fd >= 0) {
        close_zn_companion(module);
      }
    }
    pthread_mutex_unlock(&context->zn_mutex);

    if (!dispatched) {
      uint8_t ack = 0;
      (void)write_uint8_t(client_fd, ack);
    }
    close(client_fd);
  }

  /* Keep the broker FD owned by the manifest entry until it is joined. */
  LOGI("ZN companion broker stopped for manifest index %zu", index);
  return NULL;
}

static bool register_zn_companion_broker(int client_fd,
                                         struct Context *context,
                                         char *restrict argv[]) {
  struct ucred peer = {0};
  socklen_t peer_size = sizeof(peer);
  if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
      peer.uid != 0) {
    LOGW("Rejecting ZN companion broker registration from uid %u", peer.uid);
    (void)write_uint8_t(client_fd, 0);
    return false;
  }

  char library[PATH_MAX];
  if (read_string(client_fd, library, sizeof(library)) < 0) {
    LOGE("Failed reading ZN companion broker library path");
    (void)write_uint8_t(client_fd, 0);
    return false;
  }

  int broker_fd = read_fd(client_fd);
  if (broker_fd < 0) {
    LOGE("Failed receiving ZN companion broker FD");
    (void)write_uint8_t(client_fd, 0);
    return false;
  }

  int socket_type = 0;
  socklen_t socket_type_size = sizeof(socket_type);
  if (getsockopt(broker_fd, SOL_SOCKET, SO_TYPE, &socket_type,
                 &socket_type_size) != 0 || socket_type != SOCK_DGRAM) {
    LOGW("ZN companion broker must be SOCK_DGRAM");
    close(broker_fd);
    (void)write_uint8_t(client_fd, 0);
    return false;
  }

  size_t index = SIZE_MAX;
  for (size_t i = 0; i < context->zn_modules.count; ++i) {
    const struct zn_module_entry *entry = &context->zn_modules.items[i];
    if (entry->companion && strcmp(entry->library, library) == 0) {
      index = i;
      break;
    }
  }
  if (index == SIZE_MAX) {
    LOGW("Rejecting broker for undeclared ZN companion library %s", library);
    close(broker_fd);
    (void)write_uint8_t(client_fd, 0);
    return false;
  }

  struct zn_module_entry *entry = &context->zn_modules.items[index];
  int old_fd = -1;
  pthread_t old_thread = (pthread_t)0;
  bool join_old = false;

  pthread_mutex_lock(&context->zn_mutex);
  if (entry->companion_broker_fd >= 0) {
    old_fd = entry->companion_broker_fd;
    old_thread = entry->companion_broker_thread;
    join_old = entry->companion_broker_running;
    entry->companion_broker_fd = -1;
    entry->companion_broker_running = false;
  }
  pthread_mutex_unlock(&context->zn_mutex);

  if (old_fd >= 0) {
    (void)shutdown(old_fd, SHUT_RDWR);
    close(old_fd);
  }
  if (join_old) pthread_join(old_thread, NULL);

  struct zn_broker_thread_args *args = calloc(1, sizeof(*args));
  if (!args) {
    close(broker_fd);
    (void)write_uint8_t(client_fd, 0);
    return false;
  }
  args->context = context;
  args->module_index = index;
  args->broker_fd = broker_fd;
  args->argv = argv;

  pthread_mutex_lock(&context->zn_mutex);
  entry->companion_broker_fd = broker_fd;
  int result = pthread_create(&entry->companion_broker_thread, NULL,
                              zn_companion_broker_thread, args);
  if (result == 0) {
    entry->companion_broker_running = true;
  } else {
    entry->companion_broker_fd = -1;
    entry->companion_broker_running = false;
  }
  pthread_mutex_unlock(&context->zn_mutex);

  if (result != 0) {
    LOGE("Failed starting ZN companion broker thread: %s", strerror(result));
    free(args);
    close(broker_fd);
    (void)write_uint8_t(client_fd, 0);
    return false;
  }

  LOGI("Registered ZN companion broker for %s", library);
  (void)write_uint8_t(client_fd, 1);
  return true;
}

static void stop_zn_companion_brokers(struct Context *context) {
  for (size_t i = 0; i < context->zn_modules.count; ++i) {
    struct zn_module_entry *entry = &context->zn_modules.items[i];
    if (entry->companion_broker_fd >= 0) {
      (void)shutdown(entry->companion_broker_fd, SHUT_RDWR);
      close(entry->companion_broker_fd);
      entry->companion_broker_fd = -1;
    }
    if (entry->companion_broker_running) {
      pthread_join(entry->companion_broker_thread, NULL);
      entry->companion_broker_running = false;
    }
    close_zn_companion(entry);
  }
}

/* WARNING: Dynamic memory based */
void zygiskd_start(char *restrict argv[]) {
  /* INFO: When implementation is None or Multiple, it won't set the values
            for the context, causing it to have garbage values. In response
            to that, "= { 0 }" is used to ensure that the values are clean. */
  struct Context context = { 0 };
  pthread_mutex_init(&context.zn_mutex, NULL);

  struct root_impl impl;
  get_impl(&impl);
  if (impl.impl == None || impl.impl == Multiple) {
    const char *msg = NULL;
    if (impl.impl == None) msg = "Unsupported environment: Unknown root implementation";
    else msg = "Unsupported environment: Multiple root implementations found";

    LOGE("%s", msg);

    size_t err_len = strlen(msg) + 1;

    struct rzd_msg_header *message = malloc(sizeof(struct rzd_msg_header) + err_len);
    if (message == NULL) {
      LOGE("Failed allocating error info message: %s", strerror(errno));

      exit(EXIT_FAILURE);
    }

    message->cmd = DAEMON_SET_ERROR_INFO;
    message->len = (uint32_t)err_len;
    memcpy(message->data, msg, err_len);

    unix_datagram_sendto(CONTROLLER_SOCKET, message, sizeof(struct rzd_msg_header) + err_len);
    free(message);

    exit(EXIT_FAILURE);
  } else {
    load_modules(&context);
    if (!zn_modules_load(PATH_MODULES_DIR, &context.zn_modules)) {
      LOGW("Failed scanning ZN module manifests");
    } else {
      LOGI("Discovered %zu ZN module target(s)", context.zn_modules.count);
    }

    size_t info_len = sizeof(struct rzd_info_payload);
    for (size_t i = 0; i < context.len; i++) {
      info_len += strlen(context.modules[i].name) + 1;
    }

    struct rzd_msg_header *message = malloc(sizeof(struct rzd_msg_header) + info_len);
    if (message == NULL) {
      LOGE("Failed allocating info message: %s", strerror(errno));

      free_modules(&context);
      zn_modules_free(&context.zn_modules);
      root_impl_cleanup();

      return;
    }

    message->cmd = DAEMON_SET_INFO;
    message->len = (uint32_t)info_len;

    struct rzd_info_payload *info = (void *)message->data;
    stringify_root_impl_name(impl, info->impl);
    info->modules_count = (uint32_t)context.len;

    char *raw_payload = info->data;
    for (size_t i = 0; i < context.len; i++) {
      size_t module_name_len = strlen(context.modules[i].name);
      memcpy(raw_payload, context.modules[i].name, module_name_len + 1);
      raw_payload += module_name_len + 1;
    }

    unix_datagram_sendto(CONTROLLER_SOCKET, message, sizeof(struct rzd_msg_header) + info_len);
    free(message);

    LOGI("Sent root implementation and modules information to controller socket");
  }

  int socket_fd = create_daemon_socket();
  if (socket_fd == -1) {
    LOGE("Failed creating daemon socket");

    free_modules(&context);
    zn_modules_free(&context.zn_modules);

    root_impl_cleanup();

    return;
  }

  struct sigaction sa = { .sa_handler = SIG_IGN };
  sigaction(SIGPIPE, &sa, NULL);

  bool first_process = true;
  while (1) {
    int client_fd = accept(socket_fd, NULL, NULL);
    if (client_fd == -1) {
      LOGE("accept: %s", strerror(errno));

      break;
    }

    uint8_t action8 = 0;
    ssize_t len = read_uint8_t(client_fd, &action8);
    if (len == -1) {
      LOGE("read: %s", strerror(errno));

      close(client_fd);

      break;
    } else if (len == 0) {
      LOGI("Client disconnected");

      close(client_fd);

      break;
    }

    enum DaemonSocketAction action = (enum DaemonSocketAction)action8;

    switch (action) {
      case ZygoteInjected: {
        struct rzd_msg_header hdr = {
          .cmd = ZYGOTE_INJECTED,
          .len = 0
        };
        unix_datagram_sendto(CONTROLLER_SOCKET, &hdr, sizeof(hdr));

        break;
      }
      case ZygoteRestart: {
        for (size_t i = 0; i < context.len; i++) {
          if (context.modules[i].companion <= -1) continue;

          close(context.modules[i].companion);
          context.modules[i].companion = -1;
        }

        pthread_mutex_lock(&context.zn_mutex);
        for (size_t i = 0; i < context.zn_modules.count; ++i)
          close_zn_companion(&context.zn_modules.items[i]);
        pthread_mutex_unlock(&context.zn_mutex);

        break;
      }
      case GetProcessFlags: {
        uint32_t uid = 0;
        ssize_t ret = read_uint32_t(client_fd, &uid);
        ASSURE_SIZE_READ("GetProcessFlags", "uid", ret, sizeof(uid), break);

        /* INFO: Only used for Magisk, as it saves process names and not UIDs. */
        char process[PROCESS_NAME_MAX_LEN];
        ret = read_string(client_fd, process, sizeof(process));
        if (ret == -1) {
          LOGE("Failed reading process name.");

          break;
        }

        uint32_t flags = 0;
        if (first_process) {
          flags |= PROCESS_IS_FIRST_STARTED;

          first_process = false;
        }

        if (uid_is_manager(uid)) {
          flags |= PROCESS_IS_MANAGER;
        } else {
          if (uid_granted_root(uid)) {
            flags |= PROCESS_GRANTED_ROOT;
          }
          if (uid_should_umount(uid, (const char *const)process)) {
            flags |= PROCESS_ON_DENYLIST;
          }
        }

        switch (impl.impl) {
          case None: { break; }
          case Multiple: { break; }
          case KernelSU: {
            flags |= PROCESS_ROOT_IS_KSU;

            break;
          }
          case APatch: {
            flags |= PROCESS_ROOT_IS_APATCH;

            break;
          }
          case Magisk: {
            flags |= PROCESS_ROOT_IS_MAGISK;

            break;
          }
        }

        ret = write_uint32_t(client_fd, flags);
        ASSURE_SIZE_WRITE("GetProcessFlags", "flags", ret, sizeof(flags), break);

        break;
      }
      case GetInfo: {
        uint32_t flags = 0;

        switch (impl.impl) {
          case None: { break; }
          case Multiple: { break; }
          case KernelSU: {
            flags |= PROCESS_ROOT_IS_KSU;

            break;
          }
          case APatch: {
            flags |= PROCESS_ROOT_IS_APATCH;

            break;
          }
          case Magisk: {
            flags |= PROCESS_ROOT_IS_MAGISK;

            break;
          }
        }

        ssize_t ret = write_uint32_t(client_fd, flags);
        ASSURE_SIZE_WRITE("GetInfo", "flags", ret, sizeof(flags), break);

        /* TODO: Use pid_t */
        uint32_t pid = (uint32_t)getpid();
        ret = write_uint32_t(client_fd, pid);
        ASSURE_SIZE_WRITE("GetInfo", "pid", ret, sizeof(pid), break);

        size_t modules_len = context.len;
        ret = write_size_t(client_fd, modules_len);
        ASSURE_SIZE_WRITE("GetInfo", "modules_len", ret, sizeof(modules_len), break);

        for (size_t i = 0; i < modules_len; i++) {
          ret = write_string(client_fd, context.modules[i].name);
          if (ret == -1) {
            LOGE("Failed writing module name.");

            break;
          }
        }

        break;
      }
      case RegisterZnCompanionBroker: {
        (void)register_zn_companion_broker(client_fd, &context, argv);
        break;
      }
      case GetZnModuleFd: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("GetZnModuleFd", "index", ret,
                         sizeof(index), break);

        if (index >= context.zn_modules.count) {
          LOGW("Invalid ZN module index for image request: %zu", index);
          break;
        }

        const struct zn_module_entry *entry = &context.zn_modules.items[index];
        int image_fd = create_zn_module_memfd(entry->library);
        if (image_fd < 0) break;

        ret = write_fd(client_fd, image_fd);
        close(image_fd);
        if (ret != 1) {
          LOGE("Failed sending ZN module image fd for %s", entry->module_id);
        } else {
          LOGI("Passed sealed ZN module image for %s", entry->module_id);
        }
        break;
      }
      case RequestZnCompanionSocket: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("RequestZnCompanionSocket", "index", ret,
                         sizeof(index), break);

        if (index >= context.zn_modules.count ||
            !context.zn_modules.items[index].companion) {
          LOGW("Invalid or undeclared ZN companion index: %zu", index);
          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RequestZnCompanionSocket", "response", ret,
                            sizeof(uint8_t), break);
          break;
        }

        pthread_mutex_lock(&context.zn_mutex);
        struct zn_module_entry *module = &context.zn_modules.items[index];
        if (module->companion_fd >= 0 &&
            !check_unix_socket(module->companion_fd, false)) {
          LOGW("ZN companion for module %s disconnected", module->module_id);
          close_zn_companion(module);
        }

        if (module->companion_fd < 0) {
          module->companion_fd = spawn_zn_companion(argv, module);
        }

        bool dispatched = module->companion_fd >= 0 &&
                          write_fd(module->companion_fd, client_fd) == 1;
        if (!dispatched && module->companion_fd >= 0)
          close_zn_companion(module);
        pthread_mutex_unlock(&context.zn_mutex);

        if (!dispatched) {
          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RequestZnCompanionSocket", "response", ret,
                            sizeof(uint8_t), break);
        }
        break;
      }
      case ReadZnModules: {
        size_t count = context.zn_modules.count;
        ssize_t ret = write_size_t(client_fd, count);
        ASSURE_SIZE_WRITE("ReadZnModules", "count", ret, sizeof(count), break);

        for (size_t i = 0; i < count; ++i) {
          const struct zn_module_entry *entry = &context.zn_modules.items[i];
          ret = write_string(client_fd, entry->module_id);
          ASSURE_SIZE_WRITE("ReadZnModules", "module id", ret,
                            strlen(entry->module_id), break);
          ret = write_string(client_fd, entry->target);
          ASSURE_SIZE_WRITE("ReadZnModules", "target", ret,
                            strlen(entry->target), break);
          ret = write_string(client_fd, entry->library);
          ASSURE_SIZE_WRITE("ReadZnModules", "library", ret,
                            strlen(entry->library), break);
          ret = write_uint8_t(client_fd, entry->target_type);
          ASSURE_SIZE_WRITE("ReadZnModules", "target type", ret,
                            sizeof(uint8_t), break);
          ret = write_uint8_t(client_fd, entry->companion);
          ASSURE_SIZE_WRITE("ReadZnModules", "companion", ret,
                            sizeof(uint8_t), break);
        }
        break;
      }
      case ReadModules: {
        size_t clen = context.len;
        ssize_t ret = write_size_t(client_fd, clen);
        ASSURE_SIZE_WRITE("ReadModules", "len", ret, sizeof(clen), break);

        for (size_t i = 0; i < clen; i++) {
          char lib_path[PATH_MAX];
          snprintf(lib_path, PATH_MAX, "/data/adb/modules/%s/zygisk/" ARCH_STR ".so", context.modules[i].name);

          if (write_string(client_fd, lib_path) == -1) {
            LOGE("Failed writing module path.");

            break;
          }
        }

        break;
      }
      case RequestCompanionSocket: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("RequestCompanionSocket", "index", ret, sizeof(index), break);

        if (index >= context.len) {
          LOGE("Invalid module index: %zu", index);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), break);

          break;
        }

        struct Module *module = &context.modules[index];
        if (module->companion >= 0) {
          if (!check_unix_socket(module->companion, false)) {
            LOGE(" - Companion for module \"%s\" crashed", module->name);

            close(module->companion);
            module->companion = -1;
          }
        }

        if (module->companion <= -1) {
          module->companion = spawn_companion(argv, module->name, module->lib_fd);

          if (module->companion >= 0) {
            LOGI(" - Spawned companion for \"%s\": %d", module->name, module->companion);
          } else if (module->companion == -2) {
            LOGE(" - No companion spawned for \"%s\" because it has no entry.", module->name);
          } else {
            LOGE(" - Failed to spawn companion for \"%s\": %s", module->name, strerror(errno));
          }
        }

        /*
          INFO: Companion already exists or was created. In any way,
                 it should be in the while loop to receive fds now,
                 so just sending the file descriptor of the client is
                 safe.
        */
        if (module->companion >= 0) {
          LOGI(" - Sending companion fd socket of module \"%s\"", module->name);

          if (write_fd(module->companion, client_fd) == -1) {
            LOGE(" - Failed to send companion fd socket of module \"%s\"", module->name);

            ret = write_uint8_t(client_fd, 0);
            ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), break);

            close(module->companion);
            module->companion = -1;
          }
        } else {
          LOGE(" - Failed to spawn companion for module \"%s\"", module->name);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), break);
        }

        break;
      }
      case GetModuleDir: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("GetModuleDir", "index", ret, sizeof(index), break);

        if (index >= context.len) {
          LOGE("Invalid module index: %zu", index);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("GetModuleDir", "response", ret, sizeof(uint8_t), break);

          break;
        }

        char module_dir[PATH_MAX];
        snprintf(module_dir, PATH_MAX, "%s/%s", PATH_MODULES_DIR, context.modules[index].name);

        int fd = open(module_dir, O_RDONLY);
        if (fd == -1) {
          LOGE("Failed opening module directory \"%s\": %s", module_dir, strerror(errno));

          break;
        }

        if (write_fd(client_fd, fd) == -1) {
          LOGE("Failed sending module directory \"%s\" fd: %s", module_dir, strerror(errno));

          close(fd);

          break;
        }

        close(fd);

        break;
      }
      case UpdateMountNamespace: {
        pid_t pid = 0;
        ssize_t ret = read_uint32_t(client_fd, (uint32_t *)&pid);
        ASSURE_SIZE_READ("UpdateMountNamespace", "pid", ret, sizeof(pid), break);

        uint32_t target_uid = 0;
        ret = read_uint32_t(client_fd, &target_uid);
        ASSURE_SIZE_READ("UpdateMountNamespace", "uid", ret, sizeof(target_uid), break);

        char target_process[PROCESS_NAME_MAX_LEN];
        ret = read_string(client_fd, target_process, sizeof(target_process));
        if (ret == -1) {
          LOGE("Failed reading target process name for mount namespace update");
          break;
        }

        uint8_t mns_state = 0;
        ret = read_uint8_t(client_fd, &mns_state);
        ASSURE_SIZE_READ("UpdateMountNamespace", "mns_state", ret, sizeof(mns_state), break);

        uint32_t our_pid = (uint32_t)getpid();
        ret = write_uint32_t(client_fd, our_pid);
        ASSURE_SIZE_WRITE("UpdateMountNamespace", "our_pid", ret, sizeof(our_pid), break);

        /*
         * Classify using specialize metadata supplied by the zygote hook.
         * /proc/<pid>/cmdline is not reliable at this point: the child has
         * not completed specialization and may still look like a zygote.
         */
        if ((enum MountNamespaceState)mns_state == Clean &&
            should_preserve_mount_namespace((uid_t)target_uid, target_process)) {
          uint32_t skip_namespace = UINT32_MAX;
          ret = write_uint32_t(client_fd, skip_namespace);
          ASSURE_SIZE_WRITE("UpdateMountNamespace", "skip namespace", ret,
                            sizeof(skip_namespace), break);
          break;
        }

        if ((enum MountNamespaceState)mns_state == Clean)
          save_mns_fd(pid, (uid_t)target_uid, Mounted, impl);

        int ns_fd = save_mns_fd(pid, (uid_t)target_uid, (enum MountNamespaceState)mns_state, impl);
        if (ns_fd == -1) {
          LOGE("Failed to save mount namespace fd for pid %d: %s", pid, strerror(errno));

          ret = write_uint32_t(client_fd, (uint32_t)0);
          ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(ns_fd), break);

          break;
        }

        ret = write_uint32_t(client_fd, (uint32_t)ns_fd);
        ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(ns_fd), break);

        break;
      }
      case RemoveModule: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("RemoveModule", "index", ret, sizeof(index), break);

        if (index >= context.len) {
          LOGE("Invalid module index: %zu", index);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RemoveModule", "response", ret, sizeof(uint8_t), break);

          break;
        }

        struct Module *module = &context.modules[index];
        if (module->companion >= 0) {
          close(module->companion);
          module->companion = -1;
        }

        free(module->name);
        module->name = NULL;

        if (module->lib_fd >= 0) {
          close(module->lib_fd);
          module->lib_fd = -1;
        }

        memmove(&context.modules[index], &context.modules[index + 1], (context.len - index - 1) * sizeof(struct Module));
        context.len--;

        ret = write_uint8_t(client_fd, 1);
        ASSURE_SIZE_WRITE("RemoveModule", "response", ret, sizeof(uint8_t), break);

        break;
      }
    }

    close(client_fd);
  }

  close(socket_fd);
  free_modules(&context);
  stop_zn_companion_brokers(&context);
  zn_modules_free(&context.zn_modules);
  root_impl_cleanup();
}
