/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>
#include "example.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return example_run(data, size); }
