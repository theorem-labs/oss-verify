/* faultalloc.h - the hook-side allocator of the allocation failure schedule:
 * a malloc/realloc/free triple a library's pluggable-allocator hook can point
 * at, which counts every call and asks the schedule whether to refuse it.
 *
 * bit i of the schedule set means the i-th allocation the LIBRARY attempts
 * returns NULL. Keyed on allocation INDEX, never on address or size: ASan
 * changes both, and an address-keyed schedule would not denote the same thing
 * on the two sides of a T2 pair.
 *
 * TWO TIERS INCLUDE THIS FILE AND THEY DIFFER IN WHO DECIDES. The hand-written
 * plugins (cjson, libpng, zlib, tomlc17, xz -- the -repro tier) call fa_init
 * with cli.c's u32 bitmap and take the deny decision from the u32 test on fa_n
 * below: 32 schedulable indices, a bit past the end inert. The DSL tier
 * (src/dsl.h) never calls fa_init: it #defines FA_DENY() as tramp_alloc_deny()
 * before including this file, so the SAME hooks consult the process-wide
 * schedule in src/tramp_alloc.h -- the u32 plus the config[2..] extension, one
 * index shared with the library's direct allocation calls, which build.sh
 * routes to that file by renaming the archive's references. fa_n keeps
 * counting in both tiers (it is what fa_count() reports, and three DSL drivers
 * print it into their digest), so there are two counters with two meanings:
 * fa_n = allocations that came through THESE hooks; tramp_alloc_count() = the
 * schedule index over every covered entry point. Only the decision moved.
 *
 * Wired through each target's NATIVE allocator hook rather than through
 * -Wl,--wrap=malloc, and that is about scoping rather than convenience: --wrap
 * would also catch the driver's own input-buffer growth, where a NULL is a
 * harness failure and not a library finding, and would manufacture
 * counterexamples that refute nothing. (The DSL tier's archive rename is the
 * same scoping by a different mechanism: only the library's own objects are
 * renamed, so only the library's calls reach the schedule.)
 *
 * Three functions, not one: fa_malloc/fa_free for the malloc-shaped hooks
 * (cJSON, libpng), and fa_realloc for the realloc-shaped ones (tomlc17's
 * mem_realloc, expat's realloc_fcn) -- see the realloc-hooks note. They
 * are written here as ONE allocator sharing a block layout, not three
 * independent functions, because a target that mixes hooks (expat calls
 * malloc_fcn and realloc_fcn on the same allocations) must be able to free
 * or grow a block through either entry point.
 *
 * Why fa_realloc cannot just call realloc(): musl's mallocng grows an
 * mmap-served block (anything past ~128 KB) with mremap, which is exactly why
 * src/grow_buf.h exists and why check_syscalls.sh lists mremap in AVOIDED.
 * Routing a library's growth through realloc() here would put mremap back on
 * the trace -- inside the library instead of the driver, but on the same
 * process, so the gate still fails. The failure is also input-dependent (it
 * only appears once a document grows a buffer past the threshold), so a small
 * test fixture would pass and a large one would fail the gate later. Instead
 * fa_realloc grows the same way grow_buf does: malloc a fresh block, copy,
 * free the old one. That path only ever reaches mmap/munmap (or brk, for
 * small sizes), and both are modeled.
 *
 * The remaining problem is that a realloc-shaped call does not tell the
 * callee how big the old block was, and growth needs that to know how much to
 * copy. Three options: (1) over-copy `newsz` bytes from the old block -- reads
 * past its end, which an ASan build reports as a false positive on the T2
 * pair; rejected. (2) track sizes in a side table keyed by pointer -- correct
 * but needless bookkeeping. (3) store the size in a header word immediately
 * before each block, so any of the three entry points can recover it from the
 * pointer alone. Taken: fa_malloc and fa_realloc over-allocate by one header
 * (sized as a union with max_align_t, so the payload keeps whatever alignment
 * malloc would have given it), write the requested size into the header, and
 * return a pointer just past it; fa_free and fa_realloc step back one header
 * to find the real block to free. This perturbs every allocation's size and
 * alignment relative to an unhooked allocator, which is fine here: T2
 * compares the plain and ASan builds of the same driver and the same
 * allocator, so both sides of the pair carry the identical header. It would
 * only matter if some theorem compared this allocator against an unhooked
 * one, and none does.
 *
 * The header-word addition (sizeof(fa_hdr_t) + sz) is guarded against
 * overflow in the allocator, not left to each caller. A hostile or merely
 * huge `sz` near SIZE_MAX would otherwise wrap that addition, so malloc()
 * would succeed with an undersized block while the header records the
 * caller's (huge) requested size -- an undersized allocation the caller
 * believes is large. Not reachable through a hook that takes a single size,
 * but Task 6's zlib and xz hooks take a PRODUCT (items*size, nmemb*size),
 * which is a far easier route to a size near SIZE_MAX than any single
 * argument; a guard every future hook's caller has to remember to add before
 * calling in is a guard that will eventually be forgotten, so it lives here
 * once instead.
 */
#ifndef FAULTALLOC_H
#define FAULTALLOC_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* EXTERNAL linkage, deliberately, in a header. `static` here would give every
 * translation unit that includes this file its OWN bitmap and its OWN counter:
 * one plugin TU installing the hooks and a second one calling fa_init would
 * then run on two independent schedules, and bit i would denote different
 * allocations on the two sides of a T2 pair -- the one property that makes the
 * ASan-vs-plain comparison mean anything. Every target is a single TU today,
 * so `static` was harmless today and would have failed silently the first time
 * that stopped being true.
 *
 * Defined (not merely declared) with an initialiser, so a second TU including
 * this header is a MULTIPLE-DEFINITION LINK ERROR rather than a silent second
 * counter. That is the intended outcome: the failure schedule is per-process,
 * and a build that wants two TUs sharing it must split this header into a .h
 * and a .c on purpose rather than acquire two counters by accident. Note the
 * error does not depend on -fno-common (gcc 10+ default): these are real
 * definitions, not tentative ones, so -fcommon would not merge them either. */
unsigned int fa_bitmap = 0;
unsigned int fa_n = 0;

/* THE DENY DECISION IS ONE MACRO, FA_DENY(), AND THE COUNTER IS NOT. Both
 * entry points below do `fa_n++` first, unconditionally, and then ask
 * FA_DENY() whether the allocation whose index they just claimed is refused.
 * The default is the u32 test the plugin tier has always had -- the index is
 * fa_n - 1, because the increment has already happened -- so a translation
 * unit that defines nothing gets byte-for-byte today's behaviour. src/dsl.h
 * defines FA_DENY() as tramp_alloc_deny() BEFORE including this file, which is
 * the whole of how the DSL tier's hooks join the process-wide schedule: one
 * tick of that schedule's index per hook call, the decision from its bits,
 * and fa_bitmap left at 0 because fa_init is never called there. A macro
 * rather than a function pointer so the plugin tier's objects contain no
 * indirection they did not have, and so a TU that defined FA_DENY after the
 * include would get a redefinition error rather than a silent second policy. */
#ifndef FA_DENY
static inline int fa_deny_bitmap(void) {
  unsigned i = fa_n - 1u;   /* fa_n++ has already claimed this allocation's index */
  return (i < 32u && ((fa_bitmap >> i) & 1u)) ? 1 : 0;
}
#define FA_DENY() fa_deny_bitmap()
#endif

/* THE REAL ALLOCATOR IS ONE MACRO TOO, FA_RAW_MALLOC(). The plugin tier's
 * default is malloc: there its hooks are the only thing between the library
 * and the allocator. src/dsl.h defines it as tramp_alloc_raw_malloc BEFORE
 * including this file, because since 2026-09-14 build.sh renames the
 * allocation family in dsl.o as well as in the archives,
 * so a literal malloc here would be compiled into dsl.o, renamed to tramp_malloc,
 * and tick tramp_alloc_deny() a SECOND time for an allocation FA_DENY() has
 * just ticked -- two ticks per hook call, bit i denying a different allocation
 * than the count names (found by the review of that change). The raw name is
 * in no rename map and never ticks. free() needs no counterpart: it is not
 * renamed, and the trampolines return the real allocator's pointers. */
#ifndef FA_RAW_MALLOC
#define FA_RAW_MALLOC(n) malloc(n)
#endif

/* One header word, sized to preserve malloc's own alignment for the payload
 * that follows it -- see the block-layout note above. */
typedef union {
  size_t sz;
  max_align_t align;
} fa_hdr_t;

static inline void fa_init(unsigned int bitmap) { fa_bitmap = bitmap; fa_n = 0; }
static inline unsigned fa_count(void) { return fa_n; }

static inline void *fa_malloc(size_t sz) {
  fa_n++;                            /* every mode: fa_count() is this tick */
  if (FA_DENY()) return NULL;
  if (sz > SIZE_MAX - sizeof(fa_hdr_t)) return NULL;
  fa_hdr_t *blk = (fa_hdr_t *)FA_RAW_MALLOC(sizeof(fa_hdr_t) + sz);
  if (!blk) return NULL;
  blk->sz = sz;
  return (void *)(blk + 1);
}

static inline void fa_free(void *p) {
  if (!p) return;
  free((fa_hdr_t *)p - 1);
}

/* Growth without realloc() -- see the header comment for why. A NULL ptr is a
 * fresh allocation and counts as one against the schedule; tomlc17 has no
 * separate malloc hook, so every allocation it makes arrives here that way.
 * newsz == 0 is a free, per the realloc() convention both tomlc17 and expat's
 * hooks are documented to follow. */
static inline void *fa_realloc(void *ptr, size_t newsz) {
  fa_n++;                            /* every mode: fa_count() is this tick */
  if (FA_DENY()) return NULL;
  if (newsz == 0) { fa_free(ptr); return NULL; }
  if (newsz > SIZE_MAX - sizeof(fa_hdr_t)) return NULL;

  fa_hdr_t *oldblk = NULL;
  size_t oldsz = 0;
  if (ptr) { oldblk = (fa_hdr_t *)ptr - 1; oldsz = oldblk->sz; }

  fa_hdr_t *nb = (fa_hdr_t *)FA_RAW_MALLOC(sizeof(fa_hdr_t) + newsz);
  if (!nb) return NULL;
  nb->sz = newsz;
  if (oldblk && oldsz) memcpy((void *)(nb + 1), ptr, oldsz < newsz ? oldsz : newsz);
  if (oldblk) free(oldblk);
  return (void *)(nb + 1);
}
#endif /* FAULTALLOC_H */
