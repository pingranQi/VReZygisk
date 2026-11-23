#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

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

struct mountinfo {
  unsigned int id;
  unsigned int parent;
  dev_t device;
  char *root;
  char *target;
  char *vfs_option;
  struct {
      unsigned int shared;
      unsigned int master;
      unsigned int propagate_from;
  } optional;
  char *type;
  char *source;
  char *fs_option;
};

struct mountinfos {
  struct mountinfo *mounts;
  size_t length;
};

char *strndup(const char *restrict str, size_t length) {
  char *restrict copy = malloc(length + 1);
  if (copy == NULL) return NULL;

  memcpy(copy, str, length);
  copy[length] = '\0';

  return copy;
}

void free_mounts(struct mountinfos *restrict mounts) {
  for (size_t i = 0; i < mounts->length; i++) {
    free(mounts->mounts[i].root);
    free(mounts->mounts[i].target);
    free(mounts->mounts[i].vfs_option);
    free(mounts->mounts[i].type);
    free(mounts->mounts[i].source);
    free(mounts->mounts[i].fs_option);
  }

  free(mounts->mounts);
}

static void decode_mountinfo_field(char *field) {
  char *readp = field;
  char *writep = field;

  while (*readp) {
    if (readp[0] == '\\' && readp[1] >= '0' && readp[1] <= '7' &&
        readp[2] >= '0' && readp[2] <= '7' &&
        readp[3] >= '0' && readp[3] <= '7') {
      *writep++ = (char)(((readp[1] - '0') << 6) |
                         ((readp[2] - '0') << 3) |
                         (readp[3] - '0'));
      readp += 4;
    } else {
      *writep++ = *readp++;
    }
  }

  *writep = '\0';
}

bool parse_mountinfo(const char *restrict pid, struct mountinfos *restrict mounts) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%s/mountinfo", pid);

  FILE *mountinfo = fopen(path, "r");
  if (mountinfo == NULL) {
    LOGE("fopen %s: %s", path, strerror(errno));
    return false;
  }

  char line[PATH_MAX];
  size_t count = 0;
  mounts->mounts = NULL;
  mounts->length = 0;

  while (fgets(line, sizeof(line), mountinfo) != NULL) {
    /* A truncated mountinfo line cannot be used for destructive decisions. */
    if (!strchr(line, '\n') && !feof(mountinfo)) {
      LOGE("Mountinfo line exceeds parser buffer");
      goto fail;
    }

    int root_start = 0, root_end = 0;
    int target_start = 0, target_end = 0;
    int vfs_option_start = 0, vfs_option_end = 0;
    int type_start = 0, type_end = 0;
    int source_start = 0, source_end = 0;
    int fs_option_start = 0, fs_option_end = 0;
    int optional_start = 0, optional_end = 0;
    unsigned int id = 0, parent = 0, major = 0, minor = 0;

    int parsed = sscanf(line,
      "%u "           /* mount ID */
      "%u "           /* parent ID */
      "%u:%u "        /* major:minor */
      "%n%*s%n "      /* root */
      "%n%*s%n "      /* mountpoint */
      "%n%*s%n"       /* VFS options */
      "%n%*[^-]%n - " /* optional fields */
      "%n%*s%n "      /* filesystem type */
      "%n%*s%n "      /* mount source */
      "%n%*s%n",     /* filesystem options */
      &id, &parent, &major, &minor, &root_start, &root_end,
      &target_start, &target_end, &vfs_option_start, &vfs_option_end,
      &optional_start, &optional_end, &type_start, &type_end,
      &source_start, &source_end, &fs_option_start, &fs_option_end);

    size_t line_length = strlen(line);
    if (parsed != 4 ||
        root_start < 0 || root_end <= root_start ||
        target_start < root_end || target_end <= target_start ||
        vfs_option_start < target_end || vfs_option_end <= vfs_option_start ||
        optional_start < vfs_option_end || optional_end < optional_start ||
        type_start < optional_end || type_end <= type_start ||
        source_start < type_end || source_end <= source_start ||
        fs_option_start < source_end || fs_option_end <= fs_option_start ||
        (size_t)fs_option_end > line_length) {
      LOGE("Malformed mountinfo entry; refusing namespace cleanup");
      goto fail;
    }

    struct mountinfo current = {0};
    current.id = id;
    current.parent = parent;
    current.device = (dev_t)makedev(major, minor);
    current.root = strndup(line + root_start, (size_t)(root_end - root_start));
    current.target = strndup(line + target_start, (size_t)(target_end - target_start));
    current.vfs_option = strndup(line + vfs_option_start,
                                 (size_t)(vfs_option_end - vfs_option_start));
    current.type = strndup(line + type_start, (size_t)(type_end - type_start));
    current.source = strndup(line + source_start,
                             (size_t)(source_end - source_start));
    current.fs_option = strndup(line + fs_option_start,
                                (size_t)(fs_option_end - fs_option_start));

    if (!current.root || !current.target || !current.vfs_option ||
        !current.type || !current.source || !current.fs_option) {
      LOGE("Failed allocating mountinfo fields");
      free(current.root);
      free(current.target);
      free(current.vfs_option);
      free(current.type);
      free(current.source);
      free(current.fs_option);
      goto fail;
    }

    decode_mountinfo_field(current.root);
    decode_mountinfo_field(current.target);
    decode_mountinfo_field(current.source);

    size_t optional_length = (size_t)(optional_end - optional_start);
    char *optional = strndup(line + optional_start, optional_length);
    if (!optional) {
      free(current.root);
      free(current.target);
      free(current.vfs_option);
      free(current.type);
      free(current.source);
      free(current.fs_option);
      goto fail;
    }

    char *saveptr = NULL;
    for (char *token = strtok_r(optional, " \t\r\n", &saveptr);
         token != NULL;
         token = strtok_r(NULL, " \t\r\n", &saveptr)) {
      char extra;
      if (strncmp(token, "shared:", 7) == 0) {
        if (sscanf(token, "shared:%u%c", &current.optional.shared, &extra) != 1) {
          free(optional);
          free(current.root);
          free(current.target);
          free(current.vfs_option);
          free(current.type);
          free(current.source);
          free(current.fs_option);
          goto fail;
        }
      } else if (strncmp(token, "master:", 7) == 0) {
        if (sscanf(token, "master:%u%c", &current.optional.master, &extra) != 1) {
          free(optional);
          free(current.root);
          free(current.target);
          free(current.vfs_option);
          free(current.type);
          free(current.source);
          free(current.fs_option);
          goto fail;
        }
      } else if (strncmp(token, "propagate_from:", 15) == 0) {
        if (sscanf(token, "propagate_from:%u%c",
                   &current.optional.propagate_from, &extra) != 1) {
          free(optional);
          free(current.root);
          free(current.target);
          free(current.vfs_option);
          free(current.type);
          free(current.source);
          free(current.fs_option);
          goto fail;
        }
      }
    }
    free(optional);

    struct mountinfo *grown =
        realloc(mounts->mounts, (count + 1) * sizeof(*mounts->mounts));
    if (!grown) {
      LOGE("Failed allocating mountinfo array");
      free(current.root);
      free(current.target);
      free(current.vfs_option);
      free(current.type);
      free(current.source);
      free(current.fs_option);
      goto fail;
    }

    mounts->mounts = grown;
    mounts->mounts[count++] = current;
  }

  if (ferror(mountinfo)) {
    LOGE("Error reading mountinfo");
    goto fail;
  }

  fclose(mountinfo);
  mounts->length = count;
  return true;

fail:
  fclose(mountinfo);
  mounts->length = count;
  free_mounts(mounts);
  mounts->mounts = NULL;
  mounts->length = 0;
  return false;
}

static bool path_is_or_below(const char *path, const char *prefix) {
  size_t length = strlen(prefix);
  return strncmp(path, prefix, length) == 0 &&
         (path[length] == '\0' || path[length] == '/');
}

static bool is_protected_resource_target(const char *target) {
  static const char *const protected_paths[] = {
    "/system/fonts", "/system/framework",
    "/system_ext/fonts", "/system_ext/framework",
    "/product/fonts", "/product/framework",
    "/vendor/etc/fonts", "/apex/com.android.art"
  };

  if (strcmp(target, "/") == 0 || strcmp(target, "/system") == 0 ||
      strcmp(target, "/system_ext") == 0 || strcmp(target, "/vendor") == 0)
    return true;

  if (path_is_or_below(target, "/product")) return true;

  for (size_t i = 0; i < sizeof(protected_paths) / sizeof(protected_paths[0]); i++) {
    if (path_is_or_below(target, protected_paths[i])) return true;
  }

  return false;
}

static bool is_root_mount_candidate(const struct mountinfo *mount,
                                    struct root_impl impl) {
  const char *source_name = "magisk";
  if (impl.impl == KernelSU) source_name = "KSU";
  else if (impl.impl == APatch) source_name = "APatch";

  if (strcmp(mount->source, source_name) == 0 ||
      (impl.impl == Magisk && strcmp(mount->source, "worker") == 0))
    return true;

  if (path_is_or_below(mount->target, "/data/adb/modules") ||
      path_is_or_below(mount->target, "/debug_ramdisk") ||
      path_is_or_below(mount->target, "/sbin/.magisk"))
    return true;

  if (path_is_or_below(mount->root, "/adb/modules") ||
      path_is_or_below(mount->root, "/adb/ksu") ||
      path_is_or_below(mount->root, "/adb/ap"))
    return true;

  return strcmp(mount->type, "overlay") == 0 &&
      (strstr(mount->fs_option, "/data/adb/modules") != NULL ||
       strstr(mount->fs_option, "/debug_ramdisk") != NULL ||
       strstr(mount->root, "/adb/modules/") != NULL);
}

static int mount_descends_from(const struct mountinfos *mounts,
                               size_t index, unsigned int ancestor_id) {
  unsigned int parent = mounts->mounts[index].parent;

  for (size_t depth = 0; depth < mounts->length; depth++) {
    if (parent == ancestor_id) return 1;

    size_t parent_index = mounts->length;
    for (size_t i = 0; i < mounts->length; i++) {
      if (mounts->mounts[i].id == parent) {
        parent_index = i;
        break;
      }
    }

    if (parent_index == mounts->length) return 0;
    parent = mounts->mounts[parent_index].parent;
  }

  return -1;
}

static bool mount_graph_depth(const struct mountinfos *mounts, size_t index,
                              size_t *depth_out) {
  unsigned int parent = mounts->mounts[index].parent;
  size_t depth = 0;

  while (depth < mounts->length) {
    size_t parent_index = mounts->length;
    for (size_t i = 0; i < mounts->length; i++) {
      if (mounts->mounts[i].id == parent) {
        parent_index = i;
        break;
      }
    }

    if (parent_index == mounts->length) {
      *depth_out = depth;
      return true;
    }

    depth++;
    parent = mounts->mounts[parent_index].parent;
  }

  return false;
}

static bool validate_mount_topology(const struct mountinfos *mounts,
                                    const bool *candidate_flags) {
  for (size_t i = 0; i < mounts->length; i++) {
    const struct mountinfo *mount = &mounts->mounts[i];

    for (size_t j = 0; j < i; j++) {
      if (mounts->mounts[j].id == mount->id) {
        LOGW("Duplicate mount ID %u; refusing clean namespace cache", mount->id);
        return false;
      }
    }

    if (mount->optional.shared || mount->optional.master ||
        mount->optional.propagate_from) {
      LOGW("Mount peer relationship remains after MS_PRIVATE: id=%u target=%s shared=%u master=%u propagate_from=%u",
           mount->id, mount->target, mount->optional.shared,
           mount->optional.master, mount->optional.propagate_from);
      return false;
    }

    size_t ignored_depth = 0;
    if (!mount_graph_depth(mounts, i, &ignored_depth)) {
      LOGW("Cyclic mount parent graph at mount ID %u", mount->id);
      return false;
    }
  }

  for (size_t i = 0; i < mounts->length; i++) {
    if (!candidate_flags[i] ||
        is_protected_resource_target(mounts->mounts[i].target))
      continue;

    const struct mountinfo *candidate = &mounts->mounts[i];
    for (size_t j = 0; j < mounts->length; j++) {
      if (i == j) continue;

      const struct mountinfo *other = &mounts->mounts[j];
      if (strcmp(candidate->target, other->target) == 0) {
        LOGW("Stacked mounts at %s; refusing path-based detach",
             candidate->target);
        return false;
      }

      int descendant = mount_descends_from(mounts, j, candidate->id);
      if (descendant < 0) {
        LOGW("Malformed mount parent graph near mount ID %u", other->id);
        return false;
      }

      bool nested_path = path_is_or_below(other->target, candidate->target);
      if ((descendant == 1 && !nested_path) ||
          (descendant == 0 && nested_path)) {
        LOGW("Mount path/parent mismatch: parent=%s child=%s parent_id=%u",
             candidate->target, other->target, other->parent);
        return false;
      }

      if (descendant == 1 &&
          (!candidate_flags[j] ||
           is_protected_resource_target(other->target))) {
        LOGW("Mount %s has a non-root or protected child mount %s",
             candidate->target, other->target);
        return false;
      }
    }
  }

  return true;
}

struct mount_target {
  const char *target;
  size_t depth;
  unsigned int id;
};

static int compare_mount_target_depth(const void *left, const void *right) {
  const struct mount_target *a = left;
  const struct mount_target *b = right;

  if (a->depth < b->depth) return 1;
  if (a->depth > b->depth) return -1;
  if (a->id < b->id) return 1;
  if (a->id > b->id) return -1;
  return 0;
}

bool umount_root(struct root_impl impl) {
  struct mountinfos mounts;
  if (!parse_mountinfo("self", &mounts)) {
    LOGE("Failed to parse mountinfo");
    return false;
  }

  const char *source_name = "magisk";
  if (impl.impl == KernelSU) source_name = "KSU";
  else if (impl.impl == APatch) source_name = "APatch";

  LOGI("[%s] Validating clean namespace mount topology", source_name);

  bool *candidate_flags = calloc(mounts.length, sizeof(*candidate_flags));
  if (!candidate_flags && mounts.length != 0) {
    LOGE("[%s] Failed allocating mount candidate flags", source_name);
    free_mounts(&mounts);
    return false;
  }

  struct mount_target *targets_to_unmount = NULL;
  size_t num_targets = 0;

  for (size_t i = 0; i < mounts.length; i++) {
    struct mountinfo *mount = &mounts.mounts[i];
    bool should_unmount = is_root_mount_candidate(mount, impl);
    candidate_flags[i] = should_unmount;

    if (!should_unmount) continue;

    if (is_protected_resource_target(mount->target)) {
      LOGW("[%s] Keeping protected resource overlay at %s",
           source_name, mount->target);
      continue;
    }

    size_t depth = 0;
    if (!mount_graph_depth(&mounts, i, &depth)) {
      LOGW("[%s] Cyclic mount parent graph at %s", source_name, mount->target);
      free(targets_to_unmount);
      free(candidate_flags);
      free_mounts(&mounts);
      return false;
    }

    struct mount_target *grown =
        realloc(targets_to_unmount, (num_targets + 1) * sizeof(*targets_to_unmount));
    if (!grown) {
      LOGE("[%s] Failed allocating mount target list", source_name);
      free(targets_to_unmount);
      free(candidate_flags);
      free_mounts(&mounts);
      return false;
    }

    targets_to_unmount = grown;
    targets_to_unmount[num_targets].target = mount->target;
    targets_to_unmount[num_targets].depth = depth;
    targets_to_unmount[num_targets].id = mount->id;
    num_targets++;
  }

  /*
   * save_mns_fd() made this namespace recursively private before calling us.
   * Verify that no shared/master peer relationship survived and that every
   * child below a detach candidate is another selected root mount.
   */
  if (!validate_mount_topology(&mounts, candidate_flags)) {
    LOGW("[%s] Mount chain or peer-group validation failed", source_name);
    free(targets_to_unmount);
    free(candidate_flags);
    free_mounts(&mounts);
    return false;
  }

  /* Detach leaves first; a parent detach must never swallow an unprocessed child. */
  qsort(targets_to_unmount, num_targets, sizeof(*targets_to_unmount),
        compare_mount_target_depth);

  bool all_unmounted = true;
  for (size_t i = 0; i < num_targets; i++) {
    const char *target = targets_to_unmount[i].target;
    if (umount2(target, MNT_DETACH) == -1) {
      LOGE("[%s] Failed to unmount %s (id=%u): %s",
           source_name, target, targets_to_unmount[i].id, strerror(errno));
      all_unmounted = false;
      break;
    }

    LOGI("[%s] Unmounted %s (id=%u)",
         source_name, target, targets_to_unmount[i].id);
  }

  free(targets_to_unmount);
  free(candidate_flags);
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
      /* A cloned namespace may retain shared propagation. Make it private
         before detaching anything, or unmount events can escape to Zygote. */
      if (unshare(CLONE_NEWNS) == -1) {
        LOGE("unshare mount namespace: %s", strerror(errno));
        if (write_uint8_t(socket_child, 0) == -1)
          LOGE("Failed to write to socket_child: %s", strerror(errno));
        goto finalize_mns_fork;
      }

      if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        LOGE("make clean namespace private: %s", strerror(errno));
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
