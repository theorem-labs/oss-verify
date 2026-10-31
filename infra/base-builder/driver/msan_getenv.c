/* SPDX-License-Identifier: MIT OR Apache-2.0 */
// The getenv seal of the msan build: the program reads no environment. MemorySanitizer's runtime wraps getenv
// (--wrap=getenv), so the seal cannot be another __wrap_getenv; it is getenv itself, which the wrapper calls.
#include <stddef.h>
char *getenv(const char *name);
char *getenv(const char *name) {
  (void)name;
  return NULL;
}
