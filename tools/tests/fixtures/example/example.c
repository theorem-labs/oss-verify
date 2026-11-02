/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * One behaviour per first byte, so that the test can check every exit status the driver documents
 * (docs/build-contract.md) in every build. */
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "example.h"

/* An exit handler the target registers while it runs. Handlers run last-registered-first, so this one runs before
 * the driver's guard, which the driver registered before it called LLVMFuzzerInitialize. A real fuzz target must not
 * do this, nor call exit() (docs/build-contract.md, "What the driver does not intercept"). */
static void late_exit_0(void) { _Exit(0); }
static void late_return(void) { }

int example_run(const unsigned char *data, size_t size) {
  if (size == 0) return 0;
  switch (data[0]) {
    case 'r': return 1;                                   /* a return value other than 0 or -1: 78 */
    case 'm': return -1;                                  /* -1 is allowed: 0 */
    case 'x': exit(3);                                    /* exit() in the target: 77 */
    case 'L':                                             /* a later handler that ends the process: its status */
      atexit(late_exit_0);
      exit(3);
    case 'G':                                             /* a later handler that returns: the guard still gives 77 */
      atexit(late_return);
      exit(3);
    case 'u': _exit(5);                                   /* _exit, _Exit and quick_exit are not intercepted */
    case 'U': _Exit(6);
    case 'k': quick_exit(7);
    case 'a': abort();                                    /* abort(): 134 */
    case 's': { volatile int *p = 0; return *p; }         /* a segmentation fault: 139 */
    case 'n': { volatile unsigned long zero = 0; int *p = (int *)zero; return *p; }  /* a null load UBSan checks */
    case 'o': { volatile int big = INT_MAX; volatile int sum = big + (int)size; (void)sum; return 0; }  /* signed overflow */
    case 'h': {                                           /* a heap read one past the end */
      unsigned char *copy = malloc(size);
      if (copy == NULL) return 0;
      memcpy(copy, data, size);
      volatile unsigned char past = copy[size];
      free(copy);
      return past == 255 ? 0 : 0;
    }
  }
  return 0;
}
