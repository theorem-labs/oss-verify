/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Linked into every whole program of the asan and asan-ubsan builds through $OV_PROGRAM_LDFLAGS (compile;
 * docs/build-contract.md, "Whole programs"). A whole program links no driver, so it gets the driver's AddressSanitizer
 * option from here: the runtime reads no environment variable in these builds, and with this option malloc returns
 * NULL when the runtime refuses memory, as in the plain build, instead of the runtime ending the process.
 * The definition is the one in cli.c, which keeps its own copy so that no fuzz target's bytes change.
 */
const char *__asan_default_options(void);
const char *__asan_default_options(void) { return "allocator_may_return_null=1"; }
