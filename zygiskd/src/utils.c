#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <linux/limits.h>
#include <sched.h>
#include <unistd.h>

#include "root_impl/common.h"
#include "root_impl/kernelsu.h"

#include "utils.h"

bool switch_mount_namespace(pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);

  int nsfd = open(path, O_RDONLY | O_CLOEXEC);
  if (nsfd == -1) {
    LOGE("Failed to open nsfd: %s", strerror(errno));

    return false;
  }

  if (setns(nsfd, CLONE_NEWNS) == -1) {
    LOGE("Failed to setns: %s", strerror(errno));

    close(nsfd);

    return false;
  }

  close(nsfd);

  return true;
}

int __system_property_get(const char *, char *);

void get_property(const char *restrict name, char *restrict output) {
  __system_property_get(name, output);
}

void set_socket_create_context(const char *restrict context) {
  FILE *sockcreate = fopen("/proc/thread-self/attr/sockcreate", "w");
  if (sockcreate == NULL) {
    LOGE("Failed to open sockcreate with %d: %s. Retrying with tid.", errno, strerror(errno));

    goto fail;
  }

  if (fwrite(context, 1, strlen(context), sockcreate) != strlen(context)) {
    LOGE("Failed to write to sockcreate with %d: %s. Retrying with tid.", errno, strerror(errno));

    fclose(sockcreate);

    goto fail;
  }

  fclose(sockcreate);

  return;

  fail:
    ;
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/proc/self/task/%d/attr/sockcreate", gettid());

    sockcreate = fopen(path, "w");
    if (sockcreate == NULL) {
      LOGE("Failed to open tid sockcreate with %d: %s", errno, strerror(errno));

      return;
    }

    if (fwrite(context, 1, strlen(context), sockcreate) != strlen(context)) {
      LOGE("Failed to write to tid sockcreate with %d: %s", errno, strerror(errno));

      return;
    }

    fclose(sockcreate);
}

static bool get_current_attr(char *restrict output, size_t size) {
  FILE *current = fopen("/proc/self/attr/current", "r");
  if (current == NULL) {
    LOGE("fopen: %s", strerror(errno));

    return false;
  }

  size_t ret = fread(output, 1, size, current);
  if (ferror(current)) {
    LOGE("fread: %s", strerror(errno));

    fclose(current);

    return false;
  }

  output[ret] = '\0';

  fclose(current);

  return true;
}

void unix_datagram_sendto(const char *restrict path, const void *restrict buf, size_t len) {
  char current_attr[PATH_MAX];
  if (!get_current_attr(current_attr, sizeof(current_attr))) {
    LOGE("Failed to get current attribute");

    return;
  }

  set_socket_create_context(current_attr);

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX
  };
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  int socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (socket_fd == -1) {
    LOGE("socket: %s", strerror(errno));

    set_socket_create_context("u:r:zygote:s0");

    return;
  }

  if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    LOGE("connect: %s", strerror(errno));

    close(socket_fd);

    set_socket_create_context("u:r:zygote:s0");

    return;
  }

  if (sendto(socket_fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    LOGE("sendto: %s", strerror(errno));

    close(socket_fd);

    set_socket_create_context("u:r:zygote:s0");

    return;
  }

  set_socket_create_context("u:r:zygote:s0");

  close(socket_fd);
}

int chcon(const char *restrict path, const char *context) {
  return lsetxattr(path, "security.selinux", context, strlen(context) + 1, 0);
}

int unix_listener_from_path(const char *restrict path) {
  if (remove(path) == -1 && errno != ENOENT) {
    LOGE("remove: %s", strerror(errno));

    return -1;
  }

  int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (socket_fd == -1) {
    LOGE("socket: %s", strerror(errno));

    return -1;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX
  };
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
    LOGE("bind: %s", strerror(errno));

    close(socket_fd);

    return -1;
  }

  if (listen(socket_fd, 2) == -1) {
    LOGE("listen: %s", strerror(errno));

    close(socket_fd);

    return -1;
  }

  if (chcon(path, "u:object_r:zygisk_file:s0") == -1)
    LOGW("chcon (non-fatal): %s", strerror(errno));

  return socket_fd;
}

ssize_t write_fd(int fd, int sendfd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

  ssize_t ret = sendmsg(fd, &msg, 0);
  if (ret == -1) {
    LOGE("sendmsg: %s", strerror(errno));

    return -1;
  }

  return ret;
}

int read_fd(int fd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  int cnt = 1;
  struct iovec iov = {
    .iov_base = &cnt,
    .iov_len = sizeof(cnt)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  ssize_t ret = recvmsg(fd, &msg, MSG_WAITALL);
  if (ret == -1) {
    LOGE("recvmsg: %s", strerror(errno));

    return -1;
  }

  struct cmsghdr *cmsg;
  int sendfd = -1;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) continue;

    memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

    break;
  }

  if (sendfd == -1) {
    LOGE("Failed to receive fd: No valid fd found in ancillary data.");

    return -1;
  }

  return sendfd;
}

#define write_func(type)                    \
  ssize_t write_## type(int fd, type val) { \
    return write(fd, &val, sizeof(type));   \
  }

#define read_func(type)                     \
  ssize_t read_## type(int fd, type *val) { \
    return read(fd, val, sizeof(type));     \
  }

write_func(size_t)
read_func(size_t)

write_func(uint32_t)
read_func(uint32_t)

write_func(uint8_t)
read_func(uint8_t)

ssize_t write_string(int fd, const char *restrict str) {
  size_t str_len = strlen(str);
  ssize_t written_bytes = write(fd, &str_len, sizeof(size_t));
  if (written_bytes != sizeof(size_t)) {
    LOGE("Failed to write string length: Not all bytes were written (%zd != %zu).", written_bytes, sizeof(size_t));

    return -1;
  }

  written_bytes = write(fd, str, str_len);
  if ((size_t)written_bytes != str_len) {
    LOGE("Failed to write string: Not all bytes were written.");

    return -1;
  }

  return written_bytes;
}

ssize_t read_string(int fd, char *restrict buf, size_t buf_size) {
  size_t str_len = 0;
  ssize_t read_bytes = read(fd, &str_len, sizeof(size_t));
  if (read_bytes != (ssize_t)sizeof(size_t)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).", read_bytes, sizeof(size_t));

    return -1;
  }

  if (str_len > buf_size - 1) {
    LOGE("Failed to read string: Buffer is too small (%zu > %zu - 1).", str_len, buf_size);

    return -1;
  }

  read_bytes = read(fd, buf, str_len);
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %zu).", read_bytes, str_len);

    return -1;
  }

  if (str_len > 0) buf[str_len] = '\0';

  return read_bytes;
}

/* INFO: Cannot use restrict here as execv does not have restrict */
bool exec_command(char *restrict buf, size_t len, const char *restrict file, const char *const argv[]) {
  int link[2];
  pid_t pid;

  if (pipe(link) == -1) {
    LOGE("pipe: %s", strerror(errno));

    return false;
  }

  if ((pid = fork()) == -1) {
    LOGE("fork: %s", strerror(errno));

    close(link[0]);
    close(link[1]);

    return false;
  }

  if (pid == 0) {
    dup2(link[1], STDOUT_FILENO);
    close(link[0]);
    close(link[1]);

    /* NOTE: Sonarlint complains about a const qualifier drop here (c:S859),
               but this cast is deliberate and unavoidable.
    */
    execv(file, (char *const *)argv);

    LOGE("execv failed: %s", strerror(errno));
    _exit(1);
  } else {
    close(link[1]);

    ssize_t nbytes = read(link[0], buf, len);
    if (nbytes > 0) buf[nbytes - 1] = '\0';
    /* INFO: If something went wrong, at least we must ensure it is NULL-terminated */
    else buf[0] = '\0';

    wait(NULL);

    close(link[0]);
  }

  return true;
}

bool check_unix_socket(int fd, bool block) {
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN,
    .revents = 0
  };

  int timeout = block ? -1 : 0;
  if (poll(&pfd, 1, timeout) == -1) {
    LOGE("poll: %s", strerror(errno));

    return false;
  }

  return pfd.revents & ~POLLIN ? false : true;
}

/* INFO: Cannot use restrict here as execv does not have restrict */
int non_blocking_execv(const char *restrict file, char *const argv[]) {
  int link[2];
  pid_t pid;

  if (pipe(link) == -1) {
    LOGE("pipe: %s", strerror(errno));

    return -1;
  }

  if ((pid = fork()) == -1) {
    LOGE("fork: %s", strerror(errno));

    close(link[0]);
    close(link[1]);

    return -1;
  }

  if (pid == 0) {
    dup2(link[1], STDOUT_FILENO);
    close(link[0]);
    close(link[1]);

    execv(file, argv);

    _exit(1);
  } else {
    close(link[1]);

    return link[0];
  }

  return -1;
}

void stringify_root_impl_name(struct root_impl impl, char *restrict output) {
  switch (impl.impl) {
    case None: {
      strcpy(output, "None");

      break;
    }
    case Multiple: {
      strcpy(output, "Multiple");

      break;
    }
    case KernelSU: {
      if (impl.variant == KOfficial) strcpy(output, "KernelSU");
      else strcpy(output, "KernelSU Next");

      break;
    }
    case APatch: {
      strcpy(output, "APatch");

      break;
    }
    case Magisk: {
      strcpy(output, "Magisk");

      break;
    }
  }
}

/*
 * Mountinfo parsing and filtering.
 *
 * mountinfo uses octal escapes for whitespace and backslashes.  Tokenizing
 * the raw line and decoding the path fields afterwards avoids the fragile
 * sscanf/%n parsing used by the previous implementation.
 */
struct mountinfo {
  unsigned int id;
  unsigned int parent;
  char *root;
  char *target;
  char *type;
  char *source;
};

struct mountinfos {
  struct mountinfo *mounts;
  size_t length;
};

static char *mount_strdup(const char *str) {
  size_t len = strlen(str);
  char *copy = malloc(len + 1);
  if (copy == NULL) return NULL;
  memcpy(copy, str, len + 1);
  return copy;
}

static void mountinfo_decode(char *value) {
  char *readp = value;
  char *writep = value;

  while (*readp != '\0') {
    if (readp[0] == '\\' && readp[1] != '\0' && readp[2] != '\0' &&
        readp[3] != '\0' && readp[1] >= '0' && readp[1] <= '7' &&
        readp[2] >= '0' && readp[2] <= '7' &&
        readp[3] >= '0' && readp[3] <= '7') {
      unsigned int decoded =
          (unsigned int)(readp[1] - '0') * 64u +
          (unsigned int)(readp[2] - '0') * 8u +
          (unsigned int)(readp[3] - '0');
      *writep++ = (char)decoded;
      readp += 4;
    } else {
      *writep++ = *readp++;
    }
  }
  *writep = '\0';
}

static void free_mounts(struct mountinfos *mounts) {
  if (mounts == NULL) return;

  for (size_t i = 0; i < mounts->length; i++) {
    free(mounts->mounts[i].root);
    free(mounts->mounts[i].target);
    free(mounts->mounts[i].type);
    free(mounts->mounts[i].source);
  }

  free(mounts->mounts);
  mounts->mounts = NULL;
  mounts->length = 0;
}

static bool parse_mount_id(const char *token, unsigned int *value) {
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(token, &end, 10);
  if (errno != 0 || end == token || *end != '\0' || parsed > UINT_MAX)
    return false;

  *value = (unsigned int)parsed;
  return true;
}

static bool parse_mountinfo(const char *pid, struct mountinfos *mounts) {
  char path[PATH_MAX];
  int path_len = snprintf(path, sizeof(path), "/proc/%s/mountinfo", pid);
  if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
    LOGE("mountinfo path is too long");
    return false;
  }

  FILE *file = fopen(path, "r");
  if (file == NULL) {
    LOGE("Failed to open %s: %s", path, strerror(errno));
    return false;
  }

  mounts->mounts = NULL;
  mounts->length = 0;

  char *line = NULL;
  size_t line_capacity = 0;
  ssize_t line_len;
  bool success = true;

  while ((line_len = getline(&line, &line_capacity, file)) != -1) {
    (void)line_len;

    char *tokens[128];
    size_t token_count = 0;
    char *saveptr = NULL;

    for (char *token = strtok_r(line, " \t\r\n", &saveptr);
         token != NULL;
         token = strtok_r(NULL, " \t\r\n", &saveptr)) {
      if (token_count >= sizeof(tokens) / sizeof(tokens[0])) {
        LOGE("Too many fields in mountinfo entry");
        success = false;
        break;
      }
      tokens[token_count++] = token;
    }

    if (!success) break;
    if (token_count < 10) {
      LOGE("Malformed mountinfo entry: too few fields");
      success = false;
      break;
    }

    size_t separator = 6;
    while (separator < token_count && strcmp(tokens[separator], "-") != 0)
      separator++;

    if (separator >= token_count || separator + 3 >= token_count) {
      LOGE("Malformed mountinfo entry: missing separator or filesystem fields");
      success = false;
      break;
    }

    struct mountinfo mount = {0};
    if (!parse_mount_id(tokens[0], &mount.id) ||
        !parse_mount_id(tokens[1], &mount.parent)) {
      LOGE("Malformed mountinfo entry: invalid mount id");
      success = false;
      break;
    }

    mountinfo_decode(tokens[3]);
    mountinfo_decode(tokens[4]);
    mountinfo_decode(tokens[separator + 2]);

    mount.root = mount_strdup(tokens[3]);
    mount.target = mount_strdup(tokens[4]);
    mount.type = mount_strdup(tokens[separator + 1]);
    mount.source = mount_strdup(tokens[separator + 2]);

    if (mount.root == NULL || mount.target == NULL ||
        mount.type == NULL || mount.source == NULL) {
      LOGE("Failed to allocate mountinfo entry");
      free(mount.root);
      free(mount.target);
      free(mount.type);
      free(mount.source);
      success = false;
      break;
    }

    if (mounts->length == SIZE_MAX / sizeof(struct mountinfo)) {
      LOGE("Too many mountinfo entries");
      free(mount.root);
      free(mount.target);
      free(mount.type);
      free(mount.source);
      success = false;
      break;
    }

    struct mountinfo *new_mounts = realloc(
        mounts->mounts, (mounts->length + 1) * sizeof(struct mountinfo));
    if (new_mounts == NULL) {
      LOGE("Failed to grow mountinfo array");
      free(mount.root);
      free(mount.target);
      free(mount.type);
      free(mount.source);
      success = false;
      break;
    }

    mounts->mounts = new_mounts;
    mounts->mounts[mounts->length++] = mount;
  }

  if (ferror(file)) {
    LOGE("Failed while reading %s: %s", path, strerror(errno));
    success = false;
  }

  free(line);
  fclose(file);

  if (!success) free_mounts(mounts);
  return success;
}

static bool path_matches(const char *path, const char *prefix) {
  size_t len = strlen(prefix);
  return strncmp(path, prefix, len) == 0 &&
         (path[len] == '\0' || path[len] == '/');
}

static bool is_root_manager_source(const char *source) {
  static const char *const sources[] = {
    "magisk", "worker", "KSU", "ksu", "KernelSU",
    "KernelSU-Next", "APatch", "apatch"
  };

  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    if (strcasecmp(source, sources[i]) == 0) return true;
  }

  return false;
}

static bool is_root_module_mount(const struct mountinfo *mount) {
  /* Explicit module mount paths are reliable even when source is "overlay". */
  if (path_matches(mount->root, "/adb/modules") ||
      path_matches(mount->root, "/data/adb/modules") ||
      path_matches(mount->target, "/data/adb/modules") ||
      path_matches(mount->source, "/data/adb/modules") ||
      strstr(mount->source, "/adb/modules/") != NULL) {
    return true;
  }

  /*
   * Manager-specific source names are intentionally exact matches.  Generic
   * sources such as "overlay", "tmpfs" and "none" are not sufficient evidence
   * by themselves: unmounting those indiscriminately can break Android.
   */
  return is_root_manager_source(mount->source);
}

static size_t mount_path_depth(const char *path) {
  size_t depth = 0;
  for (const char *p = path; *p != '\0'; p++) {
    if (*p == '/') depth++;
  }
  return depth;
}

static int compare_mount_targets(const void *lhs, const void *rhs) {
  const struct mountinfo *const *a =
      (const struct mountinfo *const *)lhs;
  const struct mountinfo *const *b =
      (const struct mountinfo *const *)rhs;

  size_t depth_a = mount_path_depth((*a)->target);
  size_t depth_b = mount_path_depth((*b)->target);
  if (depth_a != depth_b) return depth_a < depth_b ? 1 : -1;

  /* Newer mount IDs are generally stacked above older mounts at one target. */
  if ((*a)->id == (*b)->id) return 0;
  return (*a)->id < (*b)->id ? 1 : -1;
}

static bool umount_root(struct root_impl impl) {
  /*
   * The caller has already switched into a private clone of the target PID's
   * mount namespace.  Only manager/module mounts are detached here.
   */
  struct mountinfos mounts = {0};
  if (!parse_mountinfo("self", &mounts)) {
    LOGE("Failed to parse mountinfo; refusing partial cleanup");
    return false;
  }

  char impl_name[32] = {0};
  stringify_root_impl_name(impl, impl_name);
  LOGI("[%s] Scanning target mount namespace", impl_name);

  struct mountinfo **selected = NULL;
  size_t selected_count = 0;

  for (size_t i = 0; i < mounts.length; i++) {
    struct mountinfo *mount = &mounts.mounts[i];
    if (!is_root_module_mount(mount)) continue;
    if (strcmp(mount->target, "/") == 0) {
      LOGW("[%s] Refusing to detach the namespace root mount", impl_name);
      continue;
    }

    struct mountinfo **new_selected = realloc(
        selected, (selected_count + 1) * sizeof(struct mountinfo *));
    if (new_selected == NULL) {
      LOGE("[%s] Failed to allocate mount selection", impl_name);
      free(selected);
      free_mounts(&mounts);
      return false;
    }

    selected = new_selected;
    selected[selected_count++] = mount;
    LOGI("[%s] Selected mount id=%u target=%s source=%s root=%s",
         impl_name, mount->id, mount->target, mount->source, mount->root);
  }

  if (selected_count > 1)
    qsort(selected, selected_count, sizeof(struct mountinfo *),
          compare_mount_targets);

  bool all_unmounted = true;
  for (size_t i = 0; i < selected_count; i++) {
    const struct mountinfo *mount = selected[i];

    if (umount2(mount->target, MNT_DETACH) == -1) {
      if (errno == EINVAL || errno == ENOENT) {
        LOGW("[%s] Mount already detached: %s", impl_name, mount->target);
        continue;
      }

      LOGE("[%s] Failed to unmount %s (id=%u): %s",
           impl_name, mount->target, mount->id, strerror(errno));
      all_unmounted = false;
      continue;
    }

    LOGI("[%s] Unmounted %s (id=%u)", impl_name, mount->target, mount->id);
  }

  free(selected);
  free_mounts(&mounts);
  return all_unmounted;
}

int save_mns_fd(int pid, enum MountNamespaceState mns_state, struct root_impl impl) {
  static int clean_namespace_fd = -1;
  static int mounted_namespace_fd = -1;

  if (mns_state == Clean && clean_namespace_fd != -1) return clean_namespace_fd;
  if (mns_state == Mounted && mounted_namespace_fd != -1) return mounted_namespace_fd;

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    LOGE("socketpair: %s", strerror(errno));

    return -1;
  }

  int socket_parent = sockets[0];
  int socket_child = sockets[1];

  pid_t fork_pid = fork();
  if (fork_pid < 0) {
    LOGE("fork: %s", strerror(errno));

    close(socket_parent);
    close(socket_child);

    return -1;
  }

  if (fork_pid == 0) {
    close(socket_parent);

    if (switch_mount_namespace(pid) == false) {
      LOGE("Failed to switch mount namespace");

      if (write_uint8_t(socket_child, 0) == -1)
        LOGE("Failed to write to socket_child: %s", strerror(errno));

      goto finalize_mns_fork;
    }

    if (mns_state == Clean) {
      /*
       * Clone the target namespace and sever propagation before touching any
       * mount.  This keeps cleanup scoped to the namespace fd handed to the
       * specializing app process.
       */
      if (unshare(CLONE_NEWNS) == -1) {
        LOGE("Failed to create private mount namespace: %s", strerror(errno));

        if (write_uint8_t(socket_child, 0) == -1)
          LOGE("Failed to write to socket_child: %s", strerror(errno));

        goto finalize_mns_fork;
      }

      if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        LOGE("Failed to make mount propagation private: %s", strerror(errno));

        if (write_uint8_t(socket_child, 0) == -1)
          LOGE("Failed to write to socket_child: %s", strerror(errno));

        goto finalize_mns_fork;
      }

      if (!umount_root(impl)) {
        LOGE("Failed to umount root");

        if (write_uint8_t(socket_child, 0) == -1)
          LOGE("Failed to write to socket_child: %s", strerror(errno));

        goto finalize_mns_fork;
      }
    }

    if (write_uint8_t(socket_child, 1) == -1) {
      LOGE("Failed to write to socket_child: %s", strerror(errno));

      close(socket_child);

      _exit(1);
    }

    uint8_t has_opened = 0;
    if (read_uint8_t(socket_child, &has_opened) == -1)
      LOGE("Failed to read from socket_child: %s", strerror(errno));

    finalize_mns_fork:
      close(socket_child);

      _exit(0);
  }

  close(socket_child);

  uint8_t has_succeeded = 0;
  if (read_uint8_t(socket_parent, &has_succeeded) == -1) {
    LOGE("Failed to read from socket_parent: %s", strerror(errno));

    close(socket_parent);

    return -1;
  }

  if (!has_succeeded) {
    LOGE("Failed to umount root");

    close(socket_parent);

    return -1;
  }

  char ns_path[PATH_MAX];
  snprintf(ns_path, PATH_MAX, "/proc/%d/ns/mnt", fork_pid);

  int ns_fd = open(ns_path, O_RDONLY);
  if (ns_fd == -1) {
    LOGE("open: %s", strerror(errno));

    close(socket_parent);

    return -1;
  }

  uint8_t opened_signal = 1;
  if (write_uint8_t(socket_parent, opened_signal) == -1) {
    LOGE("Failed to write to socket_parent: %s", strerror(errno));

    close(ns_fd);
    close(socket_parent);

    return -1;
  }

  if (close(socket_parent) == -1) {
    LOGE("Failed to close socket_parent: %s", strerror(errno));

    close(ns_fd);

    return -1;
  }

  if (waitpid(fork_pid, NULL, 0) == -1) {
    LOGE("waitpid: %s", strerror(errno));

    return -1;
  }

  if (mns_state == Clean) clean_namespace_fd = ns_fd;
  else if (mns_state == Mounted) mounted_namespace_fd = ns_fd;

  return ns_fd;
}
