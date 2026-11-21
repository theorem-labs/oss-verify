/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * The driver every fuzz target is linked with ($LIB_FUZZING_ENGINE, with adapter.c). It replaces libFuzzer: it
 * reads one input file and hands it to the target once.
 *
 *     <binary> INPUT
 *
 * INPUT is [u16 config word][config bytes][u32 allocation mask][payload], both integers little-endian. The low 15
 * bits of the config word are the length of the config bytes. adapter.c calls LLVMFuzzerTestOneInput on the payload
 * (config[0] & 3) + 1 times, once when there is no config. An OSS-Fuzz testcase needs the six bytes
 * 00 00 00 00 00 00 in front of it.
 *
 * Exit status 2 means the driver refused the input without calling the target: a wrong argument count, an input it
 * cannot open or read, one shorter than its header, one at or above the limit, or no memory for it. The limit is 64 MiB
 * unless the fuzz target's build sets OV_MAX_INPUT_LOG2 (27 to 31; docs/build-contract.md, with the other statuses).
 *
 * The code is the oss-fuzz-theorems 2026.10 release recipe's (src/cli.c), but input_limit.h defines MAX_INPUT.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "grow_buf.h"
#include "target.h"

/* MAX_INPUT (input_limit.h): an input of this size or more is refused. */
#include "input_limit.h"

#define HDR_MIN 6 /* the config word and the allocation mask, with no config bytes */

/* The config word: the low 15 bits are the config length; the top bit asks for the allocation count instead of the
 * target's status (adapters that do not count allocations report 0). */
#define CFG_LEN_MASK   0x7fffu
#define CFG_COUNT_BIT  0x8000u
/* The largest allocation count reported as an exit status. */
#define COUNT_MAX 251

#ifdef HARNESS_QUIET
#define DIAG(...) ((void)0)
#else
#define DIAG(...) fprintf(stderr, __VA_ARGS__)
#endif

/* Read by the AddressSanitizer runtime, which reads no environment variable in these builds. With it, malloc returns
 * NULL when memory is refused, as it does in the plain build, instead of the runtime ending the process. Unused in
 * the builds without AddressSanitizer. */
const char *__asan_default_options(void);
const char *__asan_default_options(void) { return "allocator_may_return_null=1"; }

/* Each read lands in this static buffer and is then copied into the heap buffer. */
static unsigned char read_stage[1u << 16];

static unsigned char *read_all(const char *path, size_t *out_len) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) { DIAG("cli: cannot open %s\n", path); exit(2); }
  size_t cap = 1 << 16, len = 0;
  unsigned char *buf = (unsigned char *)malloc(cap);
  if (!buf) { DIAG("cli: out of memory\n"); exit(2); }
  for (;;) {
    if (len == cap) {
      if (cap >= MAX_INPUT) { DIAG("cli: input >= %u bytes, refused\n", MAX_INPUT); exit(2); }
      unsigned char *nb = (unsigned char *)grow_buf(buf, len, cap * 2);
      if (!nb) { DIAG("cli: out of memory\n"); exit(2); }
      buf = nb; cap *= 2;
    }
    size_t want = cap - len;
    if (want > sizeof read_stage) want = sizeof read_stage;
    ssize_t n = read(fd, read_stage, want);
    if (n < 0) { DIAG("cli: read error on %s\n", path); exit(2); }
    if (n == 0) break;
    memcpy(buf + len, read_stage, (size_t)n);
    len += (size_t)n;
  }
  close(fd);
  *out_len = len;
  return buf;
}

int main(int argc, char **argv) {
  if (argc != 2) { DIAG("usage: %s INPUT\n", argv[0]); return 2; }

  size_t len = 0;
  unsigned char *buf = read_all(argv[1], &len);
  if (len < HDR_MIN) { DIAG("cli: input shorter than header\n"); free(buf); return 2; }

  unsigned cfg_word = (unsigned)buf[0] | ((unsigned)buf[1] << 8);
  int count_allocs = (cfg_word & CFG_COUNT_BIT) != 0;
  size_t config_len = (size_t)(cfg_word & CFG_LEN_MASK);
  if (len < HDR_MIN + config_len) { DIAG("cli: config_len overruns input\n"); free(buf); return 2; }

  const unsigned char *config = buf + 2;
  const unsigned char *p = config + config_len;
  unsigned int bitmap = (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
                        ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
  const unsigned char *payload = p + 4;
  size_t payload_len = len - HDR_MIN - config_len;

  target_alloc_init(bitmap);
  int status = target_run(config, config_len, payload, payload_len);

  /* In counting mode the exit status is the number of allocations the adapter counted, capped at COUNT_MAX. */
  if (count_allocs) {
    unsigned n = target_alloc_count();
    status = n < COUNT_MAX ? (int)n : COUNT_MAX;
  }

  free(buf);
  return status;
}
