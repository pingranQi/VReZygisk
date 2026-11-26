/* /data/adb/modules/rezygisk/loader/src/common/mountinfo.c */
#include "mountinfo.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/sysmacros.h>

#define MOUNTINFO_MAX_LINE (1024U * 1024U)

static void free_entry(struct mountinfo_entry *entry) {
  if (entry == NULL) return;

  free(entry->root);
  free(entry->mount_point);
  free(entry->mount_options);

  for (size_t i = 0; i < entry->optional_count; i++)
    free(entry->optional_fields[i]);
  free(entry->optional_fields);

  free(entry->filesystem_type);
  free(entry->mount_source);
  free(entry->super_options);
  memset(entry, 0, sizeof(*entry));
}

void mountinfo_free(struct mountinfo_table *table) {
  if (table == NULL) return;

  for (size_t i = 0; i < table->count; i++)
    free_entry(&table->entries[i]);

  free(table->entries);
  free(table);
}

static bool parse_u32(const char *text, uint32_t *out) {
  if (text == NULL || *text == '\0' || out == NULL) return false;

  errno = 0;
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (errno == ERANGE || end == text || *end != '\0' || value > UINT32_MAX)
    return false;

  *out = (uint32_t)value;
  return true;
}

static bool parse_device(const char *text, dev_t *out) {
  if (text == NULL || out == NULL) return false;

  const char *colon = strchr(text, ':');
  if (colon == NULL || colon == text || colon[1] == '\0' ||
      strchr(colon + 1, ':') != NULL) {
    return false;
  }

  size_t major_len = (size_t)(colon - text);
  if (major_len >= 32) return false;

  char major_text[32];
  memcpy(major_text, text, major_len);
  major_text[major_len] = '\0';

  uint32_t major_number = 0;
  uint32_t minor_number = 0;
  if (!parse_u32(major_text, &major_number) ||
      !parse_u32(colon + 1, &minor_number)) {
    return false;
  }

  *out = makedev(major_number, minor_number);
  return true;
}

/* Decode kernel mountinfo octal escapes: space, tab, newline, backslash. */
static char *decode_mount_field(const char *field) {
  if (field == NULL) {
    errno = EINVAL;
    return NULL;
  }

  const size_t length = strlen(field);
  char *decoded = malloc(length + 1);
  if (decoded == NULL) return NULL;

  size_t read_index = 0;
  size_t write_index = 0;
  while (read_index < length) {
    if (field[read_index] != '\\') {
      decoded[write_index++] = field[read_index++];
      continue;
    }

    if (length - read_index < 4 ||
        field[read_index + 1] < '0' || field[read_index + 1] > '7' ||
        field[read_index + 2] < '0' || field[read_index + 2] > '7' ||
        field[read_index + 3] < '0' || field[read_index + 3] > '7') {
      free(decoded);
      errno = EINVAL;
      return NULL;
    }

    unsigned int value =
        (unsigned int)(field[read_index + 1] - '0') * 64U +
        (unsigned int)(field[read_index + 2] - '0') * 8U +
        (unsigned int)(field[read_index + 3] - '0');

    if (value == 0 || value > UCHAR_MAX) {
      free(decoded);
      errno = EINVAL;
      return NULL;
    }

    decoded[write_index++] = (char)value;
    read_index += 4;
  }

  decoded[write_index] = '\0';
  return decoded;
}

/* Split a line in-place on ASCII whitespace. */
static size_t split_fields(char *line, char **fields, size_t capacity) {
  size_t count = 0;
  char *cursor = line;

  while (*cursor != '\0') {
    while (*cursor == ' ' || *cursor == '\t' ||
           *cursor == '\r' || *cursor == '\n') {
      cursor++;
    }
    if (*cursor == '\0') break;

    if (count == capacity) return SIZE_MAX;
    fields[count++] = cursor;

    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
           *cursor != '\r' && *cursor != '\n') {
      cursor++;
    }
    if (*cursor != '\0') *cursor++ = '\0';
  }

  return count;
}

static bool set_optional_field(struct mountinfo_entry *entry,
                               const char *field) {
  if (strncmp(field, "shared:", 7) == 0) {
    if (entry->has_shared_id ||
        !parse_u32(field + 7, &entry->shared_id)) return false;
    entry->has_shared_id = true;
  } else if (strncmp(field, "master:", 7) == 0) {
    if (entry->has_master_id ||
        !parse_u32(field + 7, &entry->master_id)) return false;
    entry->has_master_id = true;
  } else if (strncmp(field, "propagate_from:", 15) == 0) {
    if (entry->has_propagate_from_id ||
        !parse_u32(field + 15, &entry->propagate_from_id)) return false;
    entry->has_propagate_from_id = true;
  } else if (strcmp(field, "unbindable") == 0) {
    entry->unbindable = true;
  }

  char **new_fields = realloc(
      entry->optional_fields,
      (entry->optional_count + 1) * sizeof(*entry->optional_fields));
  if (new_fields == NULL) return false;

  entry->optional_fields = new_fields;
  entry->optional_fields[entry->optional_count] = strdup(field);
  if (entry->optional_fields[entry->optional_count] == NULL) return false;

  entry->optional_count++;
  return true;
}

static bool parse_line(char *line, struct mountinfo_entry *entry) {
  /* A mountinfo record has at least 10 fields including the separator. */
  size_t line_length = strlen(line);
  if (line_length == 0) return false;

  char **fields = calloc(line_length / 2 + 2, sizeof(*fields));
  if (fields == NULL) return false;

  size_t count = split_fields(line, fields, line_length / 2 + 2);
  if (count == SIZE_MAX || count < 10) {
    free(fields);
    errno = EINVAL;
    return false;
  }

  size_t separator = 6;
  while (separator < count && strcmp(fields[separator], "-") != 0)
    separator++;

  if (separator >= count || separator + 4 != count) {
    free(fields);
    errno = EINVAL;
    return false;
  }

  bool valid =
      parse_u32(fields[0], &entry->id) &&
      parse_u32(fields[1], &entry->parent_id) &&
      parse_device(fields[2], &entry->device);

  if (!valid) {
    free(fields);
    errno = EINVAL;
    return false;
  }

  entry->root = decode_mount_field(fields[3]);
  entry->mount_point = decode_mount_field(fields[4]);
  entry->mount_options = strdup(fields[5]);
  if (entry->root == NULL || entry->mount_point == NULL ||
      entry->mount_options == NULL) {
    free(fields);
    return false;
  }

  for (size_t i = 6; i < separator; i++) {
    if (!set_optional_field(entry, fields[i])) {
      free(fields);
      return false;
    }
  }

  entry->filesystem_type = strdup(fields[separator + 1]);
  entry->mount_source = decode_mount_field(fields[separator + 2]);
  entry->super_options = strdup(fields[separator + 3]);
  free(fields);

  if (entry->filesystem_type == NULL || entry->mount_source == NULL ||
      entry->super_options == NULL) {
    return false;
  }

  return true;
}

int mountinfo_parse_file(const char *path,
                         struct mountinfo_table **out_table,
                         size_t *error_line) {
  if (out_table == NULL || path == NULL || *path == '\0') {
    errno = EINVAL;
    return -1;
  }

  *out_table = NULL;
  if (error_line != NULL) *error_line = 0;

  FILE *file = fopen(path, "r");
  if (file == NULL) return -1;

  struct mountinfo_table *table = calloc(1, sizeof(*table));
  if (table == NULL) {
    fclose(file);
    return -1;
  }

  char *line = NULL;
  size_t line_capacity = 0;
  size_t line_number = 0;
  int result = 0;

  for (;;) {
    errno = 0;
    ssize_t length = getline(&line, &line_capacity, file);
    if (length < 0) {
      if (ferror(file)) result = -1;
      break;
    }

    line_number++;
    if ((size_t)length > MOUNTINFO_MAX_LINE) {
      errno = EOVERFLOW;
      result = -1;
      break;
    }

    while (length > 0 &&
           (line[length - 1] == '\n' || line[length - 1] == '\r')) {
      line[--length] = '\0';
    }
    if (length == 0) continue;

    struct mountinfo_entry entry = { 0 };
    if (!parse_line(line, &entry)) {
      if (errno == 0) errno = EINVAL;
      free_entry(&entry);
      result = -1;
      break;
    }

    if (table->count == SIZE_MAX / sizeof(*table->entries)) {
      free_entry(&entry);
      errno = EOVERFLOW;
      result = -1;
      break;
    }

    struct mountinfo_entry *new_entries = realloc(
        table->entries, (table->count + 1) * sizeof(*table->entries));
    if (new_entries == NULL) {
      free_entry(&entry);
      result = -1;
      break;
    }

    table->entries = new_entries;
    table->entries[table->count++] = entry;
  }

  free(line);
  if (fclose(file) != 0 && result == 0) result = -1;

  if (result != 0 || table->count == 0) {
    if (result == 0) errno = ENODATA;
    if (error_line != NULL) *error_line = line_number;
    mountinfo_free(table);
    return -1;
  }

  *out_table = table;
  return 0;
}
