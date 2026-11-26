/* /data/adb/modules/rezygisk/loader/tests/test_mountinfo.c */
#include "mountinfo.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_all(int fd, const char *data, size_t length) {
  while (length > 0) {
    ssize_t written = write(fd, data, length);
    assert(written > 0);
    data += written;
    length -= (size_t)written;
  }
}

static char *make_fixture(const char *contents) {
  char template_path[] = "/tmp/vrez-mountinfo-XXXXXX";
  int fd = mkstemp(template_path);
  assert(fd >= 0);

  write_all(fd, contents, strlen(contents));
  assert(close(fd) == 0);

  return strdup(template_path);
}

static void test_valid_and_unescape(void) {
  const char *fixture =
      "36 25 0:32 /root\\040dir /mnt/test\\040space rw,nosuid "
      "shared:7 master:2 propagate_from:1 - ext4 /dev/block/dm-0 rw,seclabel\n"
      "37 36 0:33 / /mnt/tab\\011name rw - tmpfs tmpfs rw\n";

  char *path = make_fixture(fixture);
  struct mountinfo_table *table = NULL;
  size_t error_line = 0;

  assert(mountinfo_parse_file(path, &table, &error_line) == 0);
  assert(error_line == 0);
  assert(table != NULL && table->count == 2);

  assert(table->entries[0].id == 36);
  assert(table->entries[0].parent_id == 25);
  assert(strcmp(table->entries[0].root, "/root dir") == 0);
  assert(strcmp(table->entries[0].mount_point, "/mnt/test space") == 0);
  assert(strcmp(table->entries[0].filesystem_type, "ext4") == 0);
  assert(strcmp(table->entries[0].mount_source, "/dev/block/dm-0") == 0);
  assert(table->entries[0].has_shared_id);
  assert(table->entries[0].shared_id == 7);
  assert(table->entries[0].has_master_id);
  assert(table->entries[0].master_id == 2);
  assert(table->entries[0].has_propagate_from_id);
  assert(table->entries[0].propagate_from_id == 1);
  assert(strcmp(table->entries[1].mount_point, "/mnt/tab\tname") == 0);

  mountinfo_free(table);
  assert(unlink(path) == 0);
  free(path);
}

static void test_malformed_record(void) {
  char *path = make_fixture("1 2 0:1 / /mnt rw - ext4\n");
  struct mountinfo_table *table = NULL;
  size_t error_line = 0;

  errno = 0;
  assert(mountinfo_parse_file(path, &table, &error_line) == -1);
  assert(errno == EINVAL);
  assert(table == NULL);
  assert(error_line == 1);

  assert(unlink(path) == 0);
  free(path);
}

static void test_bad_escape(void) {
  char *path = make_fixture(
      "1 2 0:1 / /mnt\\04x rw - ext4 source rw\n");
  struct mountinfo_table *table = NULL;
  size_t error_line = 0;

  assert(mountinfo_parse_file(path, &table, &error_line) == -1);
  assert(table == NULL);
  assert(error_line == 1);

  assert(unlink(path) == 0);
  free(path);
}

int main(void) {
  test_valid_and_unescape();
  test_malformed_record();
  test_bad_escape();
  puts("mountinfo parser tests: PASS");
  return 0;
}
