/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The one member that build.sh adds to its copy of the C library, as marker.o. No other libc.a defines
 * fxs_libc_marker. */
int fxs_libc_marker(void) { return 0; }
