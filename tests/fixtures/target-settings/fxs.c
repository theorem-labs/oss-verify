/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The library of the test project. It has one global array, which the AddressSanitizer builds instrument. */
#include "fxs.h"

unsigned char fxs_table[16];

int fxs_step(const unsigned char *data, size_t size) {
  fxs_table[size == 0 ? 0 : data[0] % 16u] += 1;
  return 0;
}
