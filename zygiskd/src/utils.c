#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/xattr.h>

#include <linux/limits.h>
#include <unistd.h>

#include "root_impl/common.h"
#include "root_impl/kernelsu.h"

#include "utils.h"

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


