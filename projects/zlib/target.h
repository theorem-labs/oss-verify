/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT
 * target.h - the contract every target plugin implements. The driver knows nothing about any library.
 * It decodes the input file, installs the allocator failure schedule, and hands the two byte ranges over.
 */
#ifndef TARGET_H
#define TARGET_H
#include <stddef.h>

/* Human-readable target name, used only in diagnostics. */
const char *target_name(void);

/* Install the failure schedule. THE CONTRACT (the allocation-failure
 * design, s4.3): bit i set means the i-th call, after arming, that
 * the LIBRARY's own objects make to malloc/calloc/realloc/reallocarray/
 * aligned_alloc/posix_memalign/memalign/valloc/strdup/strndup/operator new --
 * or that the library routes through a driver-installed allocator hook --
 * returns NULL (operator new: throws bad_alloc), in call order. Keyed on
 * allocation index, never on address or size -- ASan changes both, and an
 * address-keyed schedule would not denote the same thing across a T2 pair.
 * The driver's own arena and the sanitizer runtime are never on the schedule:
 * the build renames the family in DERIVED copies of the library archive and
 * of the driver objects, and the arena calls tramp_alloc_raw_malloc, a name no
 * map renames (src/tramp_alloc.h).
 *
 * Bits 0-31 are this argument; on the DSL tier bit i >= 32 is bit (i-32)%8 of
 * config[2 + (i-32)/8], LSB first (src/dsl.h hands config[2..] to
 * tramp_alloc_extend). Called once, before target_run. A target with no
 * allocator (jsmn) and the generic OSS-Fuzz adapter implement this as a no-op
 * and ignore the schedule. */
void target_alloc_init(unsigned int fail_bitmap);

/* How many allocations the LIBRARY has attempted since target_alloc_init --
 * i.e. how many times the failure schedule was consulted, whether or not the
 * bit was set. This is N in the spec's section 7 item 2 sweep ("run once
 * counting allocations to get N, then run N more times with bit i set"),
 * which is where the fault-injection coverage actually comes from.
 *
 * Read by the driver AFTER target_run returns, and reported through the exit
 * status only in the counting mode cli.c documents. A target with no allocator
 * (jsmn) returns 0, which is the true count and not a stub. */
unsigned target_alloc_count(void);

/* Decode `config` as an API call-sequence program through this target's state
 * machine, run it over `payload`, and write any output to stdout.
 *
 * Returns 0 on success, or a small positive library status. Must not call
 * abort(), assert(), or exit(). Must not read the environment or any file. */
int target_run(const unsigned char *config, size_t config_len,
               const unsigned char *payload, size_t payload_len);
#endif /* TARGET_H */
