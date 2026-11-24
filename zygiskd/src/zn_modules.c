#include "zn_modules.h"

#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dirent.h>
#include <fcntl.h>

#define ZN_MANIFEST_NAME "zn_modules.txt"
#define ZN_MAX_LINE 4096u
#define ZN_MAX_ENTRIES 512u

static char *trim(char *s) {
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') ++s;
  size_t n = strlen(s);
  while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
               s[n - 1] == '\r' || s[n - 1] == '\n')) {
    s[--n] = '\0';
  }
  return s;
}

static bool valid_module_id(const char *id) {
  if (!id || !*id || !strcmp(id, ".") || !strcmp(id, "..")) return false;
  for (const unsigned char *p = (const unsigned char *)id; *p; ++p) {
    if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
           (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.'))
      return false;
  }
  return true;
}

static bool expand_module_id(char *path, size_t capacity, const char *id) {
  const char *tokens[] = {"${moduleId}", "$moduleId"};
  for (size_t t = 0; t < sizeof(tokens) / sizeof(tokens[0]); ++t) {
    const size_t token_len = strlen(tokens[t]);
    char expanded[PATH_MAX];
    size_t used = 0;
    const char *p = path;
    expanded[0] = '\0';
    while (*p) {
      const char *match = strstr(p, tokens[t]);
      size_t chunk = match ? (size_t)(match - p) : strlen(p);
      if (chunk >= sizeof(expanded) - used) return false;
      memcpy(expanded + used, p, chunk);
      used += chunk;
      if (!match) break;
      size_t id_len = strlen(id);
      if (id_len >= sizeof(expanded) - used) return false;
      memcpy(expanded + used, id, id_len);
      used += id_len;
      p = match + token_len;
    }
    expanded[used] = '\0';
    if (strlen(expanded) >= capacity) return false;
    memcpy(path, expanded, used + 1);
  }
  return true;
}

static bool path_is_inside(const char *root, const char *path) {
  const size_t n = strlen(root);
  return strncmp(root, path, n) == 0 && path[n] == '/';
}

static bool validate_library(const char *module_dir, const char *relative_or_abs,
                             char resolved[PATH_MAX]) {
  char candidate[PATH_MAX];
  if (relative_or_abs[0] == '/') {
    if (snprintf(candidate, sizeof(candidate), "%s", relative_or_abs) >=
        (int)sizeof(candidate)) return false;
  } else {
    if (snprintf(candidate, sizeof(candidate), "%s/%s", module_dir,
                 relative_or_abs) >= (int)sizeof(candidate)) return false;
  }

  char root_real[PATH_MAX];
  char file_real[PATH_MAX];
  if (!realpath(module_dir, root_real) || !realpath(candidate, file_real))
    return false;
  if (!path_is_inside(root_real, file_real)) return false;

  struct stat st;
  if (stat(file_real, &st) != 0 || !S_ISREG(st.st_mode)) return false;

  int fd = open(file_real, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  Elf64_Ehdr ehdr;
  ssize_t n = read(fd, &ehdr, sizeof(ehdr));
  close(fd);
  if (n != (ssize_t)sizeof(ehdr) ||
      memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
      ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
      ehdr.e_type != ET_DYN || ehdr.e_machine != EM_AARCH64 ||
      ehdr.e_version != EV_CURRENT) return false;

  if (snprintf(resolved, PATH_MAX, "%s", file_real) >= PATH_MAX) return false;
  return true;
}

static bool append_entry(struct zn_module_list *list,
                         const struct zn_module_entry *entry) {
  if (list->count >= ZN_MAX_ENTRIES) return false;
  if (list->count >= SIZE_MAX / sizeof(*list->items)) return false;
  struct zn_module_entry *items =
      realloc(list->items, (list->count + 1) * sizeof(*list->items));
  if (!items) return false;
  list->items = items;
  list->items[list->count++] = *entry;
  return true;
}

static void parse_manifest(const char *module_id, const char *module_dir,
                           struct zn_module_list *out) {
  char manifest[PATH_MAX];
  if (snprintf(manifest, sizeof(manifest), "%s/%s", module_dir,
               ZN_MANIFEST_NAME) >= (int)sizeof(manifest)) return;

  FILE *fp = fopen(manifest, "r");
  if (!fp) return;

  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  unsigned int line_no = 0;
  while ((length = getline(&line, &capacity, fp)) >= 0) {
    ++line_no;
    if ((size_t)length > ZN_MAX_LINE) {
      fprintf(stderr, "[zygiskd] ZN: %s:%u: line too long, skipped\n",
              module_id, line_no);
      continue;
    }
    char *text = trim(line);
    if (!*text || *text == '#') continue;

    char *save = NULL;
    char *target = strtok_r(text, " \t", &save);
    char *library = strtok_r(NULL, " \t", &save);
    char *option = strtok_r(NULL, " \t", &save);
    char *extra = strtok_r(NULL, " \t", &save);
    if (!target || !library || (extra && extra[0] != '#')) {
      fprintf(stderr, "[zygiskd] ZN: %s:%u: invalid manifest syntax, skipped\n",
              module_id, line_no);
      continue;
    }

    if (option && option[0] == '#') option = NULL;

    struct zn_module_entry entry = {0};
    if (!strncmp(target, "name=", 5) && target[5] && !strchr(target + 5, '/')) {
      entry.target_type = ZN_TARGET_NAME;
      entry.target = strdup(target + 5);
    } else if (!strncmp(target, "path=", 5) && target[5] == '/') {
      entry.target_type = ZN_TARGET_PATH;
      entry.target = strdup(target + 5);
    } else {
      fprintf(stderr, "[zygiskd] ZN: %s:%u: unsupported target, skipped\n",
              module_id, line_no);
      continue;
    }

    if (option && strcmp(option, "companion") != 0) {
      fprintf(stderr, "[zygiskd] ZN: %s:%u: unknown option '%s', skipped\n",
              module_id, line_no, option);
      free(entry.target);
      continue;
    }
    entry.companion = (uint8_t)(option != NULL);
    entry.companion_fd = -1;
    entry.companion_broker_fd = -1;
    entry.companion_broker_running = false;
    entry.module_id = strdup(module_id);

    char library_expanded[PATH_MAX];
    char resolved[PATH_MAX];
    if (snprintf(library_expanded, sizeof(library_expanded), "%s", library) >=
            (int)sizeof(library_expanded) ||
        !expand_module_id(library_expanded, sizeof(library_expanded), module_id) ||
        !validate_library(module_dir, library_expanded, resolved)) {
      fprintf(stderr, "[zygiskd] ZN: %s:%u: invalid or non-module library '%s', skipped\n",
              module_id, line_no, library);
      free(entry.target);
      free(entry.module_id);
      continue;
    }
    entry.library = strdup(resolved);
    if (!entry.target || !entry.module_id || !entry.library ||
        !append_entry(out, &entry)) {
      fprintf(stderr, "[zygiskd] ZN: %s:%u: allocation/entry limit failure\n",
              module_id, line_no);
      free(entry.target);
      free(entry.module_id);
      free(entry.library);
      break;
    }
    fprintf(stderr, "[zygiskd] ZN: discovered module=%s target=%s library=%s companion=%s\n",
            module_id, target, resolved, entry.companion ? "yes" : "no");
  }
  free(line);
  fclose(fp);
}

bool zn_modules_load(const char *modules_root, struct zn_module_list *out) {
  if (!modules_root || !out) return false;
  out->items = NULL;
  out->count = 0;

  DIR *dir = opendir(modules_root);
  if (!dir) return false;

  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    if (!valid_module_id(de->d_name)) continue;

    char module_dir[PATH_MAX];
    char marker[PATH_MAX];
    if (snprintf(module_dir, sizeof(module_dir), "%s/%s", modules_root,
                 de->d_name) >= (int)sizeof(module_dir)) continue;
    if (snprintf(marker, sizeof(marker), "%s/disable", module_dir) <
            (int)sizeof(marker) && access(marker, F_OK) == 0) continue;
    if (snprintf(marker, sizeof(marker), "%s/remove", module_dir) <
            (int)sizeof(marker) && access(marker, F_OK) == 0) continue;

    struct stat st;
    if (stat(module_dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
    parse_manifest(de->d_name, module_dir, out);
  }
  closedir(dir);
  return true;
}

void zn_modules_free(struct zn_module_list *list) {
  if (!list) return;
  for (size_t i = 0; i < list->count; ++i) {
    if (list->items[i].companion_fd >= 0) close(list->items[i].companion_fd);
    if (list->items[i].companion_broker_fd >= 0) close(list->items[i].companion_broker_fd);
    free(list->items[i].module_id);
    free(list->items[i].target);
    free(list->items[i].library);
  }
  free(list->items);
  list->items = NULL;
  list->count = 0;
}
