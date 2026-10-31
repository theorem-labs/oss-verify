/* SPDX-License-Identifier: MIT OR Apache-2.0 */
// The msan build's counterpart of cli.c's __asan_default_options: a malloc the MemorySanitizer allocator cannot
// serve returns NULL to the program, as it does in the plain build, rather than ending it with a report.
const char *__msan_default_options(void);
const char *__msan_default_options(void) { return "allocator_may_return_null=1"; }
