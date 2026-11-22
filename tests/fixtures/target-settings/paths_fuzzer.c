/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The harness of paths_fuzzer and none_fuzzer. It keeps two source paths in the binary: its own __FILE__, and the
 * __FILE__ of the vendored file oft-vendor/v.c. Each one is the path that the compiler got. It returns 0. */
#include <stddef.h>
#include <stdint.h>
#include "fxs.h"

const char *fxs_vendor_file(void);

/* The fuzz target stores both paths here. The compiler keeps each store to a volatile object, so the link keeps both
 * strings. */
const char *volatile fxs_paths_seen[2];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fxs_paths_seen[0] = __FILE__;
  fxs_paths_seen[1] = fxs_vendor_file();
  return fxs_step(data, size);
}
