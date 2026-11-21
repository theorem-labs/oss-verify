/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The harness of limit_fuzzer, limit_af_fuzzer and oss_none_fuzzer. It calls the library once and returns 0. */
#include <stddef.h>
#include <stdint.h>
#include "fxs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return fxs_step(data, size); }
