/* aef_alloc.c - the one schedule, the one counter, and the C-family
 * trampolines the renamed library archives resolve to.
 *
 * See aef_alloc.h for what a bit means and why the library is the only thing
 * that can reach this file. What is specific to this translation unit:
 *
 * COMPILED WITH THE DRIVER'S COMPILER, not the library's -- the same recipe
 * as cli.o and wrap_getenv.o -- so this object is byte-identical across the
 * plain, asan, ubsan and gcc flavours of one target and across targets, and
 * check_driver_object can say so by hash. An instrumented trampoline would
 * put a sanitizer-runtime call between the library's request and the
 * allocator on one side of the T2 pair and not the other.
 *
 * NO DYNAMIC ALLOCATION OF ITS OWN. The extension copy is a static array and
 * everything else is a scalar. A trampoline that allocated to do its job
 * would tick its own schedule, or need an unscheduled escape name that the
 * rename map would then have to know about.
 *
 * THE REAL FUNCTIONS ARE THE SYSTEM'S DECLARATIONS. aef_malloc calls malloc,
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
 *
 * THE COUNT IS `unsigned`, uncapped. cli.c clamps its own copy at 251 for
 * the exit-status channel; the VM sub-ops read the full value. It wraps at
 * 2^32 allocations, which no program in this tier approaches (the largest
 * authored program is 1,475 frames).
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "aef_alloc.h"

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

static uint32_t aef_bits32 = 0;
static uint8_t aef_ext[AEF_ALLOC_EXT_MAX];
static size_t aef_ext_len = 0;
static unsigned aef_n = 0;
static int aef_armed = 0;

void aef_alloc_arm(uint32_t bits32) {
  aef_bits32 = bits32;
  aef_n = 0;
  aef_armed = 1;
}

void aef_alloc_extend(const uint8_t *p, size_t n) {
  if (p == NULL) n = 0;
  if (n > AEF_ALLOC_EXT_MAX) n = AEF_ALLOC_EXT_MAX;
  if (n) memcpy(aef_ext, p, n);
  aef_ext_len = n;
}

/* The 4.1 predicate: bit i of the schedule, 0 past whatever was installed. */
static int aef_bit(unsigned i) {
  size_t k;
  unsigned j;
  if (i < 32u) return (int)((aef_bits32 >> i) & 1u);
  k = (size_t)(i - 32u) >> 3;
  j = (i - 32u) & 7u;
  if (k >= aef_ext_len) return 0;
  return (int)((aef_ext[k] >> j) & 1u);
}

int aef_alloc_deny(void) {
  unsigned i;
  if (!aef_armed) return 0;
  i = aef_n++;
  return aef_bit(i);
}

unsigned aef_alloc_count(void) { return aef_n; }

int aef_alloc_can_fire(void) {
  size_t k;
  unsigned first;
  if (!aef_armed) return 0;
  if (aef_n < 32u && (aef_bits32 >> aef_n) != 0u) return 1;
  /* Extension bits at index >= max(aef_n, 32): the rest of the byte the
   * index falls in, then any nonzero byte after it. */
  first = aef_n < 32u ? 0u : aef_n - 32u;
  k = (size_t)first >> 3;
  if (k >= aef_ext_len) return 0;
  if ((aef_ext[k] >> (first & 7u)) != 0u) return 1;
  for (k++; k < aef_ext_len; k++)
    if (aef_ext[k]) return 1;
  return 0;
}

/* The driver's arena allocator: the real malloc, no tick (aef_alloc.h). */
void *aef_alloc_raw_malloc(size_t size) { return malloc(size); }

/* The trampolines. One tick each, FIRST, before any argument is looked at;
 * on denial the pointer-returning ones behave as a failed allocation does on
 * both libcs this tier links against (NULL, errno ENOMEM), and
 * aef_posix_memalign as musl's own does (it returns errno after aligned_alloc
 * set it, so ENOMEM in both places). Otherwise: the real call, its result
 * returned untouched. */
void *aef_malloc(size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return malloc(size);
}

void *aef_calloc(size_t nmemb, size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return calloc(nmemb, size);
}

void *aef_realloc(void *ptr, size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return realloc(ptr, size);
}

void *aef_reallocarray(void *ptr, size_t nmemb, size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return reallocarray(ptr, nmemb, size);
}

void *aef_aligned_alloc(size_t alignment, size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return aligned_alloc(alignment, size);
}

void *aef_memalign(size_t alignment, size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return memalign(alignment, size);
}

void *aef_valloc(size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return valloc(size);
}

int aef_posix_memalign(void **memptr, size_t alignment, size_t size) {
  if (aef_alloc_deny()) { errno = ENOMEM; return ENOMEM; }
  return posix_memalign(memptr, alignment, size);
}

char *aef_strdup(const char *s) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return strdup(s);
}

char *aef_strndup(const char *s, size_t n) {
  if (aef_alloc_deny()) { errno = ENOMEM; return NULL; }
  return strndup(s, n);
}
