/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The harness of libc_fuzzer and undeclared_fuzzer. It calls fxs_libc_marker, which only the libc.a of its block
 * defines. Thus the link fails when it does not take that libc.a. It returns 0. */
#include <stddef.h>
#include <stdint.h>
#include "fxs.h"

int fxs_libc_marker(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return fxs_step(data, size) + fxs_libc_marker(); }
