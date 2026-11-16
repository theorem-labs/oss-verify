/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef EXAMPLE_H
#define EXAMPLE_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* What the fuzz targets do with an input, by its first byte. */
int example_run(const unsigned char *data, size_t size);
#ifdef __cplusplus
}
#endif
#endif
