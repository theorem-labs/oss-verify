/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT
 * tramp_alloc.c - the one schedule, the one counter, and the C-family
 * trampolines the renamed library archives resolve to.
 * See tramp_alloc.h for what a bit means and why the library is the only thing
 * that can reach this file. What is specific to this translation unit:
 *
 * COMPILED WITH THE DRIVER'S COMPILER, not the library's -- the same recipe
 * as cli.o and wrap_getenv.o -- so this object is byte-identical across the
 * plain, asan, ubsan and gcc flavours of one target and across targets, and
 * the driver-object check can say so by hash. An instrumented trampoline would
 * put a sanitizer-runtime call between the library's request and the
 * allocator on one side of the T2 pair and not the other.
 *
 * NO DYNAMIC ALLOCATION OF ITS OWN. The extension copy is a static array and
 * everything else is a scalar. A trampoline that allocated to do its job
 * would tick its own schedule, or need an unscheduled escape name that the
 * rename map would then have to know about.
 *
 * THE REAL FUNCTIONS ARE THE SYSTEM'S DECLARATIONS. tramp_malloc calls malloc,
 * declared by <stdlib.h>; on the target that reference is musl's, or in the
 * asan flavours whatever the sealed runtime's --wrap list redirects it to.
 * This object is not passed through the rename, so its own references keep
 * their public names, and it does not know which flavour it is in. memalign,
 * valloc and reallocarray are declared by both glibc and musl only under
 * _GNU_SOURCE (musl: `defined(_GNU_SOURCE) || defined(_BSD_SOURCE)`, stdlib.h),
 * so that is defined before any include; the explicit extern declarations
 * below are compatible redeclarations that make this file compile against a
 * libc that hides them anyway, and would make an INCOMPATIBLE system
 * prototype a compile error rather than a silent ABI mismatch. musl has no
 * pvalloc, so there is no trampoline for it.
 * THE COUNT IS `unsigned`, uncapped. cli.c clamps its own copy at 251 for
 * the exit-status channel; the VM sub-ops read the full value. It wraps at
 * 2^32 allocations, which no program in this tier approaches (the largest
 * authored program is 1,475 frames).
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "tramp_alloc.h"

/* Belt and braces for the three names not every libc header exposes; see the
 * header comment. Standard prototypes, so a libc that does declare them
 * (glibc and musl both do under _GNU_SOURCE) sees a compatible
 * redeclaration and nothing else. C linkage spelled out so the file also
 * links when a host driver compiles it as C++ (g++ treats a .c operand as
 * C++ and would otherwise mangle these three into references nothing
 * defines; measured 2026-09-10). On the target it is always compiled as C
 * by $DRVCC, where the block is a no-op. */
#ifdef __cplusplus
extern "C" {
#endif
extern void *memalign(size_t alignment, size_t size);
extern void *valloc(size_t size);
extern void *reallocarray(void *ptr, size_t nmemb, size_t size);
#ifdef __cplusplus
}
#endif

static uint32_t tramp_bits32 = 0;
static uint8_t tramp_ext[TRAMP_ALLOC_EXT_MAX];
static size_t tramp_ext_len = 0;
static unsigned tramp_n = 0;
static int tramp_armed = 0;

void tramp_alloc_arm(uint32_t bits32) {
  tramp_bits32 = bits32;
  tramp_n = 0;
  tramp_armed = 1;
}

void tramp_alloc_extend(const uint8_t *p, size_t n) {
  if (p == NULL) n = 0;
  if (n > TRAMP_ALLOC_EXT_MAX) n = TRAMP_ALLOC_EXT_MAX;
  if (n) memcpy(tramp_ext, p, n);
  tramp_ext_len = n;
}

/* The 4.1 predicate: bit i of the schedule, 0 past whatever was installed. */
static int tramp_bit(unsigned i) {
  size_t k;
  unsigned j;
  if (i < 32u) return (int)((tramp_bits32 >> i) & 1u);
  k = (size_t)(i - 32u) >> 3;
  j = (i - 32u) & 7u;
  if (k >= tramp_ext_len) return 0;
  return (int)((tramp_ext[k] >> j) & 1u);
}

int tramp_alloc_deny(void) {
  unsigned i;
  if (!tramp_armed) return 0;
  i = tramp_n++;
  return tramp_bit(i);
}

unsigned tramp_alloc_count(void) { return tramp_n; }

int tramp_alloc_can_fire(void) {
  size_t k;
  unsigned first;
  if (!tramp_armed) return 0;
  if (tramp_n < 32u && (tramp_bits32 >> tramp_n) != 0u) return 1;
  /* Extension bits at index >= max(tramp_n, 32): the rest of the byte the
   * index falls in, then any nonzero byte after it. */
  first = tramp_n < 32u ? 0u : tramp_n - 32u;
  k = (size_t)first >> 3;
  if (k >= tramp_ext_len) return 0;
  if ((tramp_ext[k] >> (first & 7u)) != 0u) return 1;
  for (k++; k < tramp_ext_len; k++)
    if (tramp_ext[k]) return 1;
  return 0;
}

/* The driver's arena allocator: the real malloc, no tick (tramp_alloc.h). */
void *tramp_alloc_raw_malloc(size_t size) { return malloc(size); }

/* The trampolines. One tick each, FIRST, before any argument is looked at;
 * on denial the pointer-returning ones behave as a failed allocation does on
 * both libcs this tier links against (NULL, errno ENOMEM), and
 * tramp_posix_memalign as musl's own does (it returns errno after aligned_alloc
 * set it, so ENOMEM in both places). Otherwise: the real call, its result
 * returned untouched. */
void *tramp_malloc(size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return malloc(size);
}

void *tramp_calloc(size_t nmemb, size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return calloc(nmemb, size);
}

void *tramp_realloc(void *ptr, size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return realloc(ptr, size);
}

void *tramp_reallocarray(void *ptr, size_t nmemb, size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return reallocarray(ptr, nmemb, size);
}

void *tramp_aligned_alloc(size_t alignment, size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return aligned_alloc(alignment, size);
}

void *tramp_memalign(size_t alignment, size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return memalign(alignment, size);
}

void *tramp_valloc(size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return valloc(size);
}

int tramp_posix_memalign(void **memptr, size_t alignment, size_t size) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return ENOMEM; }
  return posix_memalign(memptr, alignment, size);
}

char *tramp_strdup(const char *s) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return strdup(s);
}

char *tramp_strndup(const char *s, size_t n) {
  if (tramp_alloc_deny()) { errno = ENOMEM; return NULL; }
  return strndup(s, n);
}
