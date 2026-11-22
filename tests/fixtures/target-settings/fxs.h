/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef FXS_H
#define FXS_H
#include <stddef.h>

/* Counts the input in a global array. It returns 0 for every input. */
int fxs_step(const unsigned char *data, size_t size);

#endif
