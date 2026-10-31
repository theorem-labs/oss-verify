/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * A whole program for tools/tests/test_builder.py: its own main, linked with $OV_PROGRAM_LDFLAGS and no driver. Its
 * first argument chooses what it does:
 *   (none)    write "hello" and exit 0;
 *   env       write the value of OV_TEST_VALUE, which no seal of getenv hides, and exit 0;
 *   huge      ask malloc for more memory than any build gives, and exit 3 when it returns NULL: in every build, as
 *             $OV_PROGRAM_LDFLAGS sets allocator_may_return_null=1 in the AddressSanitizer builds;
 *   overflow  read one byte past a heap block: exit 0 in the plain and ubsan builds, and in the AddressSanitizer
 *             builds abort with no report (status 134), as $OV_PROGRAM_LDFLAGS silences the reports;
 *   another   exit 2.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
  if (argc < 2) {
    puts("hello");
    return 0;
  }
  if (strcmp(argv[1], "env") == 0) {
    const char *value = getenv("OV_TEST_VALUE");
    puts(value ? value : "(unset)");
    return 0;
  }
  if (strcmp(argv[1], "huge") == 0) {
    volatile size_t size = SIZE_MAX / 2;
    void *block = malloc(size);
    if (block == NULL)
      return 3;
    free(block);
    return 1;
  }
  if (strcmp(argv[1], "overflow") == 0) {
    char *volatile block = malloc(16);
    if (block == NULL)
      return 1;
    volatile char past = block[16];
    (void)past;
    free(block);
    return 0;
  }
  return 2;
}
