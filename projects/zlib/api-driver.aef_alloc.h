/* aef_alloc.h - the DSL tier's allocation-failure schedule: one counter, one
 * schedule, for the whole process, consulted from an object that no flavour
 * instruments.
 *
 * Design: docs/dsl-alloc-failure-mask-design-2026-09-10.md (sections 4.1,
 * 4.2, 4.4). This header is the API the driver (src/dsl.h) calls; the
 * trampolines the library's renamed references land on are declared at the
 * bottom and defined in aef_alloc.c and aef_alloc_cxx.cc.
 *
 * WHAT A BIT MEANS. Bit i set means the i-th allocation the LIBRARY attempts
 * after arming is denied: the C family returns NULL with errno ENOMEM,
 * posix_memalign returns ENOMEM, a throwing operator new throws
 * std::bad_alloc, a nothrow one returns nullptr. Bits 0-31 are the header's
 * u32 (cli.c's alloc_fail_bitmap, unchanged); bit i >= 32 is bit (i-32)%8 of
 * extension byte (i-32)/8, LSB-first, where the extension is config[2..] of
 * the same input -- the bytes dsl.h has always declared reserved. A bit past
 * the end of whatever schedule the input carried is 0: "no schedule" and
 * "short schedule" are indistinguishable by construction, which is what keeps
 * every existing input meaning exactly what it meant before this file
 * existed (an all-zero or absent extension IS today's behaviour).
 *
 * WHY THE LIBRARY AND ONLY THE LIBRARY TICKS. Nothing here interposes on
 * malloc. build.sh renames the allocation family (malloc, calloc, ...,
 * operator new) in a DERIVED copy of the pin-built archives to aef_<name>,
 * and this object defines those names. The renamed references are the
 * program's own objects and nothing else: libc, libc++, libunwind, the
 * driver, and the sanitizer runtime are never passed through the rename, so
 * no path from any of them leads to a trampoline. That is how the hard
 * constraint -- the ASan runtime never sees a denied request -- is met: not
 * by asking the trampoline to tell the runtime's allocations apart from the
 * library's, but by making the runtime's allocations unable to arrive here at
 * all. The trampolines' OWN calls to malloc / ::operator new are ordinary
 * references in an object that is not renamed, so on the target they resolve
 * to musl or, in the asan flavours, to the sealed runtime's interceptor,
 * exactly as a driver's would; this code does not know which and must not.
 *
 * WHY THE EXTENSION IS COPIED. The bytes aef_alloc_extend is handed live in
 * cli.c's input buffer, which cli.c frees before main returns while the
 * schedule stays armed. A library atexit handler or C++ static destructor
 * that allocates after that point is ticked like any other allocation, and a
 * schedule that still pointed into the freed buffer would then be read from
 * memory that is unmapped on plain (the 64 KiB read buffer takes mallocng's
 * mmap branch) and quarantined-but-readable under ASan -- the two flavours
 * would decide differently, which is the one thing this tier exists to rule
 * out. So aef_alloc_extend copies up to AEF_ALLOC_EXT_MAX bytes into static
 * storage and forgets the pointer. Bytes past the copy are inert, the same
 * rule as bytes past the end.
 *
 * WHY THE TICK COMES BEFORE ANY VALIDATION. realloc(p, 0), an overflowing
 * calloc and aligned_alloc's alignment check all tick exactly once, whether
 * the real allocator would have refused them or not. An index that depended
 * on which requests a given allocator considers valid would denote different
 * allocations under musl and under the interceptor.
 *
 * Not thread-safe, on purpose: the tier is single-threaded (the DSL VM), and
 * a library that allocated from a second thread would make "the i-th
 * allocation" ill-defined in a way no counter could repair.
 */
#ifndef AEF_ALLOC_H
#define AEF_ALLOC_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bytes of extension kept; bit index reach is 32 + 8 * AEF_ALLOC_EXT_MAX. */
#define AEF_ALLOC_EXT_MAX 4096u

/* Arm the schedule with the header u32 as bits 0-31. Zeroes the tick counter
 * and marks the schedule live. Does not touch the extension, so this and
 * aef_alloc_extend may be called in either order; cli.c arms first. Called
 * once per process (target_alloc_init); the counter is NOT reset per repeat,
 * which is what lets the extension reach repeats 1-3 at all. */
void aef_alloc_arm(uint32_t bits32);

/* Install config[2..] as bits 32 onward: COPIES min(n, AEF_ALLOC_EXT_MAX)
 * bytes of p into static storage (see the header comment for why a copy is
 * not optional) and forgets p. n == 0 or p == NULL installs an empty
 * extension. Replaces, never appends. */
void aef_alloc_extend(const uint8_t *p, size_t n);

/* ONE tick, and the verdict for it. Unarmed: returns 0 WITHOUT ticking, so
 * pre-arm allocations (runtime start-up, C++ static initialisers, cli.c's own
 * buffer) do not move the index. Armed: i = count++, then 1 iff bit i is set
 * under the rule in the header comment, else 0. Called once, first thing, by
 * every trampoline, and by faultalloc.h's hooks through FA_DENY. */
int aef_alloc_deny(void);

/* Ticks since arming, uncapped. cli.c's counting mode clamps at 251 on the
 * way out; the VM's `expect alloc N` and `allocs` sub-ops read this directly
 * and do not. 0 while unarmed. */
unsigned aef_alloc_count(void);

/* 1 iff a set bit exists at an index >= count, over the u32 and the copied
 * extension; 0 while unarmed (nothing can fire). This is libevent's
 * fa_may_fire generalised: a hook asks it before doing work whose only
 * purpose is to be denied. */
int aef_alloc_can_fire(void);

/* The DRIVER's own allocator, exempt from the schedule BY NAME. Since the
 * LQ 158 fix (2026-09-14) build.sh passes dsl.o and dsl-quiet.o through the
 * same rename map as the archives -- a driver object carries weak COMDAT
 * copies of the library's allocating template helpers, and the copy the
 * linker keeps must tick whichever object it came from -- so a `malloc` in
 * src/dsl.h would now land on aef_malloc and the VM's arena would be
 * scheduled against the library's index. The arena calls this instead: a
 * name no map contains, defined in aef_alloc.o (never renamed), whose own
 * malloc reference resolves exactly as the trampolines' do (musl, or the
 * sealed runtime's interceptor). No tick, no schedule. Two callers may use
 * it and no other: dsl.h's arena, and any hook that ALREADY ticks the
 * schedule through aef_alloc_deny() -- src/faultalloc.h's fa_malloc /
 * fa_realloc (dsl.h defines FA_RAW_MALLOC as this name before including it)
 * and postgis's hand-written lw_alloc_hook / lw_realloc_hook -- because a
 * hook that ticked and then called malloc in the renamed dsl.o would tick
 * twice per allocation (LQ 158 review, defect 1). An authored driver that
 * called it anywhere else would be hiding an allocation from the count. */
void *aef_alloc_raw_malloc(size_t size);

/* The C-family trampolines. Reached ONLY through build.sh's rename of the
 * library archives (src/aef_alloc.redefs) and, since 2026-09-14, of the
 * driver objects dsl.o / dsl-quiet.o; nothing calls these by name. Each ticks once via aef_alloc_deny() before anything
 * else; on denial the pointer-returning ones set errno = ENOMEM and return
 * NULL, aef_posix_memalign returns ENOMEM and leaves *memptr untouched;
 * otherwise each calls the real function of the same name and returns its
 * result unchanged, so free()/malloc_usable_size() on the result need no
 * counterpart here. musl has no pvalloc, so there is no aef_pvalloc. */
void *aef_malloc(size_t size);
void *aef_calloc(size_t nmemb, size_t size);
void *aef_realloc(void *ptr, size_t size);
void *aef_reallocarray(void *ptr, size_t nmemb, size_t size);
void *aef_aligned_alloc(size_t alignment, size_t size);
void *aef_memalign(size_t alignment, size_t size);
void *aef_valloc(size_t size);
int aef_posix_memalign(void **memptr, size_t alignment, size_t size);
char *aef_strdup(const char *s);
char *aef_strndup(const char *s, size_t n);

/* The eight operator-new trampolines (aef__Znwm, aef__Znam, and the nothrow
 * and align_val_t variants) live in aef_alloc_cxx.cc with C linkage under
 * their mangled-derived names; they take C++ types in their signatures and
 * are declared there, not here, so a C driver including this header needs
 * no <new>. */

/* The frame boundary's std::bad_alloc catch, also in aef_alloc_cxx.cc, with
 * C types only so THIS header names no C++ type and src/dsl.h includes no C++
 * standard header. Why dsl.h cannot simply `#include <new>` and catch for
 * itself: build.sh puts the library's source root on every driver's include
 * path, -I directories are searched for <angle> includes before the system
 * ones, and one library ships a text FILE named `new` at its root (cifuzz;
 * another ships `memory`), so the include resolved to it and std::bad_alloc
 * was never declared (measured 2026-09-10). aef_alloc_cxx.o is compiled with
 * -I/work/src alone, so its <new> is the real one. Calls fn(vm, op): returns
 * its result with *caught = 0, or 0 with *caught = 1 when fn threw
 * std::bad_alloc (a scheduled denial of a throwing new, or a real
 * out-of-memory in the driver's own new). Other exceptions propagate.
 * Referenced by dsl.h in every C++ driver TU compiled with exceptions on, so
 * aef_alloc_cxx.o is linked into every C++ DSL driver, not only where the C++
 * rename map applies. */
int aef_call_catching_bad_alloc(int (*fn)(void *, unsigned), void *vm, unsigned op, int *caught);

#ifdef __cplusplus
}
#endif
#endif /* AEF_ALLOC_H */
