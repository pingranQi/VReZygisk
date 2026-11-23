#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logging.h"
#include "misc.h"
#include "socket_utils.h"

int parse_int(const char *str) {
  int val = 0;

  char *c = (char *)str;
  while (*c) {
    if (*c > '9' || *c < '0')
      return -1;

    val = val * 10 + *c - '0';
    c++;
  }

  return val;
}

struct kernel_version parse_kversion() {
  struct utsname uts;
  if (uname(&uts) == -1) {
    PLOGE("uname");

    return (struct kernel_version) { 0 };
  }

  struct kernel_version version;
  if (sscanf(uts.release, "%hhu.%u.%u", &version.major, &version.minor, &version.patch) != 3) {
    LOGE("Failed to parse kernel version");

    return (struct kernel_version) { 0 };
  }

  return version;
}

/* INFO: Accessing /proc/.../maps will update its access time. This is detectable
           by using stat() to check when the application takes control of the
           execution of the process. However, if we do this before the fork(),
           it will update the access time of the maps file of the parent process,
           not child, making it undetectable.
*/
struct maps_info *parse_maps(const char *pid) {
  /* INFO: The character limit for a 32-bit PID is 10 */
  char path[(sizeof("/proc//maps") - 1) + 10 + 1];
  snprintf(path, sizeof(path), "/proc/%s/maps", pid);

  FILE *fp = fopen(path, "r");
  if (!fp) {
    PLOGE("Failed to open %s", path);

    return NULL;
  }

  struct maps_info *info_array = calloc(1, sizeof(struct maps_info));
  if (!info_array) {
    PLOGE("allocate memory");

    fclose(fp);

    return NULL;
  }

  size_t infos_capacity = 2;
  info_array->maps = malloc(infos_capacity * sizeof(struct map_entry));
  if (!info_array->maps) {
    PLOGE("allocate memory for maps");

    free(info_array);
    fclose(fp);

    return NULL;
  }
  info_array->length = 0;

  char line[1024];
  while (fgets(line, sizeof(line), fp) != NULL) {
    line[strlen(line) - 1] = '\0';

    uintptr_t start, end, offset;
    unsigned int dev_major, dev_minor;
    ino_t inode;
    char perms[5] = { 0 };
    int path_off;

    if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n",
               &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, &path_off) != 7) {
      continue;
    }

    uint8_t perms_bit = 0;
    if (perms[0] == 'r') perms_bit |= PROT_READ;
    if (perms[1] == 'w') perms_bit |= PROT_WRITE;
    if (perms[2] == 'x') perms_bit |= PROT_EXEC;

    while (isspace((unsigned char)line[path_off]))
      path_off++;

    char *path_str = strdup(line + path_off);
    if (!path_str) {
      PLOGE("allocate memory for map path");

      goto cleanup_maps;
    }

    if (info_array->length >= infos_capacity) {
      infos_capacity *= 2;
      struct map_entry *tmp_maps = realloc(info_array->maps, infos_capacity * sizeof(struct map_entry));
      if (!tmp_maps) {
        PLOGE("reallocate (extend: %zu -> %zu) memory for maps", infos_capacity / 2, infos_capacity);

        goto cleanup_maps_and_path;
      }
      info_array->maps = tmp_maps;
    }

    struct map_entry new_map = {
      .start = start,
      .end = end,
      .perms = perms_bit,
      .is_private = (perms[3] == 'p'),
      .offset = offset,
      .dev = makedev(dev_major, dev_minor),
      .inode = inode,
      .path = path_str
    };

    info_array->maps[info_array->length++] = new_map;

    continue;

    cleanup_maps_and_path:
      free(path_str);
    cleanup_maps:
      for (size_t i = 0; i < info_array->length; i++) {
        free(info_array->maps[i].path);
      }
      free(info_array->maps);
      free(info_array);

      fclose(fp);

      return NULL;
  }

  fclose(fp);

  if (info_array->length == 0) {
    LOGE("Failed to find any maps in %s", pid);

    free(info_array);

    return NULL;
  }

  /* INFO: Resize to the actual size */
  struct map_entry *tmp_maps = realloc(info_array->maps, info_array->length * sizeof(struct map_entry));
  if (!tmp_maps)
    PLOGE("reallocate (reduce: %zu -> %zu) memory for maps", infos_capacity, info_array->length);

  if (tmp_maps) info_array->maps = tmp_maps;

  return info_array;
}

void free_maps(struct maps_info *maps) {
  for (size_t i = 0; i < maps->length; i++) {
    free(maps->maps[i].path);
  }

  free(maps->maps);
  free(maps);
}

/* Parse one maps line. The path belongs to the caller's line buffer. */
static bool parse_maps_line(char *line, struct map_entry *entry) {
  line[strcspn(line, "\n")] = '\0';

  uintptr_t start, end, offset;
  unsigned int dev_major, dev_minor;
  ino_t inode;
  char perms[5] = { 0 };
  int path_off = 0;

  if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n",
             &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, &path_off) != 7) {
    return false;
  }

  int perms_bit = 0;
  if (perms[0] == 'r') perms_bit |= PROT_READ;
  if (perms[1] == 'w') perms_bit |= PROT_WRITE;
  if (perms[2] == 'x') perms_bit |= PROT_EXEC;

  while (isspace((unsigned char)line[path_off])) path_off++;

  *entry = (struct map_entry) {
    .start = start,
    .end = end,
    .perms = perms_bit,
    .is_private = (perms[3] == 'p'),
    .offset = offset,
    .dev = makedev(dev_major, dev_minor),
    .inode = inode,
    .path = line + path_off
  };

  return true;
}

/* Walk a maps fd after it has been opened by the forked reader process. */
static bool scan_maps_stream(FILE *fp, maps_visitor visit, void *userdata) {
  char *line = NULL;
  size_t capacity = 0;
  bool complete = true;
  errno = 0;

  while (getline(&line, &capacity, fp) != -1) {
    struct map_entry entry;
    if (!parse_maps_line(line, &entry)) continue;
    if (!visit(&entry, userdata)) {
      complete = false;
      break;
    }
  }

  if (ferror(fp) || (errno == ENOMEM)) complete = false;
  free(line);

  return complete;
}

/*
 * Open /proc/<pid>/maps in a short-lived child and pass the fd with SCM_RIGHTS.
 * The atime update therefore belongs to the child-side proc entry, not to the
 * target process whose maps are being inspected.
 */
bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata) {
  if (pid == NULL || visit == NULL) return false;

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    PLOGE("anonymous-memory: socketpair for maps");
    return false;
  }

  pid_t child = fork();
  if (child == -1) {
    PLOGE("anonymous-memory: fork maps reader");
    close(sockets[0]);
    close(sockets[1]);
    return false;
  }

  if (child == 0) {
    close(sockets[0]);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    int maps_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (maps_fd != -1) {
      (void)write_fd(sockets[1], maps_fd);
      close(maps_fd);
    }

    close(sockets[1]);
    _exit(0);
  }

  close(sockets[1]);
  int maps_fd = read_fd(sockets[0]);
  close(sockets[0]);

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited == -1 && errno == EINTR);

  if (waited == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    if (maps_fd != -1) close(maps_fd);
    LOGE("anonymous-memory: maps reader child did not exit cleanly");
    return false;
  }

  if (maps_fd == -1) {
    LOGE("anonymous-memory: child could not provide /proc/%s/maps", pid);
    return false;
  }

  FILE *fp = fdopen(maps_fd, "r");
  if (fp == NULL) {
    PLOGE("anonymous-memory: fdopen maps");
    close(maps_fd);
    return false;
  }

  bool ok = scan_maps_stream(fp, visit, userdata);
  fclose(fp);
  return ok;
}

