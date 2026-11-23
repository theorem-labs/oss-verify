/* dsl.h - the shared machinery for the SECOND driver: a bytecode DSL that
 * drives a library's API directly, instead of forwarding one buffer to the
 * project's own fuzz harness.
 *
 * A target that carries a targets/<t>/dsl.c (or dsl.cc) gets a second family
 * of binaries beside its <t>-repro pair:
 *
 *   <t>-dsl                 <t>-dsl-quiet
 *   <t>-dsl-asan            <t>-dsl-quiet-asan
 *   <t>-dsl-ubsan           <t>-dsl-quiet-ubsan
 *   <t>-dsl-asanubsan       <t>-dsl-quiet-asanubsan
 *
 * built by the same build.sh flavours, from the same library archive, against
 * the same cli.o. It is OPTIONAL: build.sh keys on the file existing, so a
 * target without one is unchanged, and no existing binary moves.
 *
 * WHY A SECOND DRIVER AT ALL, when src/ossfuzz_adapter.h already onboards the
 * project. The adapter's honest limitation is written down in its own header:
 * a libFuzzer harness exposes exactly ONE entry point, it returns 0 whatever
 * it did with the input, and so "the observable is close to constant". That
 * makes the adapter tier a T2 tier and nothing more -- T1 (library vs a
 * reference, compared on stdout and exit code) is discharged by a reference
 * that prints nothing and returns 0.
 *
 * Two things follow, and they are the whole reason this file exists:
 *
 *   COVERAGE. A harness reaches whatever slice of the API its author needed.
 *   `brotli/c/fuzz/decode_fuzzer.c` calls BrotliDecoderDecompress and stops;
 *   the streaming decoder, the custom-allocator path, the parameter setters,
 *   the metadata callbacks and every error path reachable only from a
 *   half-consumed stream are simply absent from the artefact. An API-level
 *   call-sequence program reaches all of them, and does so in ORDERS the
 *   harness never produces -- which is where handle lifetimes, reset paths and
 *   allocator reuse actually break.
 *
 *   OBSERVABLE. Every operation here reports what the library returned: the
 *   status, the byte count, and a digest of the bytes. Output is a function of
 *   the input program rather than a constant 0, so the loud binaries of this
 *   tier carry real T1 content, and the difftest across flavours has something
 *   to compare beyond an exit status.
 *
 * WHAT IS *NOT* CLAIMED. This is not a model of the library and it is not a
 * reference implementation: nothing here predicts what the library should
 * return. It is an EXERCISER whose output happens to be rich enough to be
 * worth comparing. T2 and T3 (the same library with and without
 * instrumentation) are what these binaries prove, exactly as for the adapter
 * tier; the extra API surface is why they prove more of it.
 *
 *
 * THE PROGRAM IS THE PAYLOAD, AND CONFIG IS THE MODE. §6 asks that config
 * decode to an API call-sequence program, and the adapter reads a call count
 * out of config[0] because one entry point admits no other sequencing. Here
 * there is a real sequence to encode, and it goes in the PAYLOAD:
 *
 *   [u16 config_len][config][u32 bitmap][      payload = the program      ]
 *
 * Not in config, and the reason is measurable rather than aesthetic. Every
 * input this repo generates -- build.sh's wrap_probe, the reach tool's
 * wrap(), every corpus file the funnel replays -- writes a ONE-byte config and
 * puts all the bytes it varies in the payload. A program confined to config
 * would therefore be one byte long in every input the existing pipeline
 * produces, and the whole tier would execute a single operation forever. The
 * payload is also the part cli.c bounds at 64 MiB and reads in 64 KiB
 * transfers, so a program has room to be a program.
 *
 * config keeps the role its name says, and every byte of it is legal:
 *
 *   config[0] bits 0-1 : run the whole program 1 + n times in one process
 *   config[0] bit  2   : terse -- emit only the closing summary, not per-op lines
 *   config[0] bits 3-4 : step budget scale, DSL_STEPS << (2 * n) -- DSL_STEPS is
 *                        4096 unless the driver #defines it lower (32 do)
 *   config[0] bits 5-7 : reserved, ignored
 *   config[1]          : the ONLY seed of the deterministic filler (see dsl_rand
 *                        and target_run)
 *   config[2..]        : the allocation-failure schedule's EXTENSION: bit i of
 *                        the schedule, for i >= 32, is bit (i-32)%8 of
 *                        config[2 + (i-32)/8], LSB-first (the u32's byte order
 *                        continued); a byte the input does not carry reads 0
 *
 * The repeat count is inherited from the adapter for the reason its header
 * gives: repeated invocation in one process is where harness and library
 * global state actually goes wrong, and it is the one thing OSS-Fuzz's own
 * runner does that a single-shot driver does not.
 *
 * THE ALLOCATION-FAILURE SCHEDULE.
 * The header's u32 is bits 0-31 and config[2..] continues it, so an input can
 * schedule the i-th allocation for any i below 32 + 8 * 4096 (src/tramp_alloc.h
 * copies at most 4,096 extension bytes; bytes past that, like bits past the end
 * of what the input carried, read 0). Bit i set means: the i-th call, after
 * arming, that the library's own objects make to malloc/calloc/realloc/
 * reallocarray/aligned_alloc/posix_memalign/memalign/valloc/strdup/strndup/
 * operator new, or that the library routes through a driver-installed
 * allocator hook, in call order, FAILS -- NULL with errno ENOMEM, or
 * std::bad_alloc from a throwing new. Past the end is INERT, not "fail": "no
 * schedule" and "short schedule" are indistinguishable by construction, which
 * is what keeps every input that exists today -- one config byte, all of them
 * -- meaning exactly what it meant. The library reaches the schedule because
 * build.sh renames the allocation family in a DERIVED copy of the pin-built
 * archives to the tramp_* names src/tramp_alloc.c defines; nothing here interposes
 * on malloc. Since 2026-09-14 build.sh passes dsl.o and
 * dsl-quiet.o through the SAME rename as the archives, because a driver object
 * carries weak COMDAT copies of the library's allocating template helpers and
 * the copy the linker keeps has to tick whichever object it came from. So the
 * schedule now covers every allocation compiled from the library's headers or
 * the authored driver -- a dsl.c's direct malloc/strdup (8 drivers, every one
 * NULL-checked to DSL_SKIP) and a dsl.cc's own std::string included, the same
 * in every flavour -- while the VM's ARENA stays out of it BY NAME: dsl_zalloc
 * calls tramp_alloc_raw_malloc, a name no map contains, defined in the unrenamed
 * trampoline object, so an arena refusal is still a DSL_SKIP that no mask can
 * manufacture. cli.o is not renamed (no library header; its buffer is
 * allocated before arming). cli.c is
 * UNCHANGED in this change, so cli.o stays byte-identical to the shipped
 * vintage's and the driver-object check stays quiet against the flavours nobody
 * rebuilds. Its stale comment at cli.c:89-92 ("anything above 32 is past what
 * a u32 can schedule") is prose debt deferred to the next full vintage: in the
 * image's toolchain even a comment-only edit changes cli.o, because the DWARF 5
 * line table carries the source file's MD5 (measured 2026-09-10; a host gcc
 * build showed no such move and was the wrong instrument), so any cli.c edit
 * means rebuilding every flavour of every target. The counter
 * starts at arming (cli.c, before target_run) and is never reset, so with the
 * extension a repeat past the first is reachable, which the u32 alone never
 * was; each repeat records its own base (V.alloc_base, below) so that the two
 * counting sub-ops report THIS repeat's number.
 *
 * Whether bit i names the SAME allocation in the plain and the instrumented
 * flavour is a MEASURED property, per library and per input, not a
 * construction: the tick site is flavour-neutral, but a library's SOURCE may
 * allocate differently under ASan (zstd sizes its workspaces from
 * __has_feature(address_sanitizer); abseil's swiss tables change layout under
 * ABSL_HAVE_ADDRESS_SANITIZER), so the per-frame `allocs` line, byte-compared
 * across flavours, is what certifies the identity -- never this paragraph.
 *
 *
 * AN INSTRUCTION IS A FRAME: [op][len][len operand bytes]. The op byte picks
 * the operation (modulo dsl_ops() -- see below); the len byte says how many
 * bytes of operands the instruction OWNS; the next instruction starts right
 * after them. A len of 255 is an escape -- a little-endian u16 length follows
 * -- so one instruction can carry up to 64 KiB of inline literal: a parse
 * operation fed exact bytes needs that, and a hard 253-byte ceiling would
 * silently cap the reachable inputs of every one-buffer API in the tier.
 *
 * Operand reads NEVER cross a frame. dsl_u8 and everything built on it
 * return 0 once the frame is spent; dsl_take clamps its slice to the frame's
 * remainder; unconsumed operand bytes are SKIPPED when the step returns; and
 * the dsl_flag bit reservoir is cleared at every instruction, because
 * leftover bits from one instruction shifting the meaning of the next is
 * exactly the cross-instruction coupling frames exist to remove. Together
 * those give the property the encoding is FOR: an instruction's meaning is a
 * pure function of (op, its own operand bytes). To make operation k run with
 * operand bytes B, write [k][len(B)][B] -- nothing about the instructions
 * around it needs to be known, let alone simulated. the assembler does
 * exactly that and nothing else.
 *
 * WHY FRAMES, MEASURED BEFORE PAID FOR (the reachability design).
 * The first encoding had no len byte: an operation consumed operands
 * directly from the instruction stream, so the OFFSET of instruction i+1
 * depended on how many operands instruction i's step happened to read --
 * which is a LIBRARY-dependent quantity, because a DSL_SKIP early return
 * reads fewer operands than the success path. Reaching a chosen op at a
 * chosen point meant simulating the driver against the library's answers:
 * reach was a search problem even for a human holding the source, which is
 * the property the design rejects. Frames cost nothing measurable
 * in random-input op coverage -- mean 0.225 framed vs 0.227 unframed over
 * the same 1512-input corpus, against 0.179 for the fixed 4-byte cells that
 * were measured first and rejected -- and make reach trivial by
 * construction.
 *
 * THE PROGRAM RUNS ONCE, IN ORDER. The payload is read from offset 0 to its
 * end, exactly once per repeat: frame after frame, no wrap, no rotation. A
 * frame that would extend past the program's end is clamped to it (its
 * missing operands read as 0, like any spent frame); a lone trailing op byte
 * runs with len 0.
 *
 * HISTORY, kept because the measurements are the record. Until 2026-09-02 the
 * header cursor CYCLED, wrapping to offset `passes % prog_len` so that the byte
 * that was an operand on one pass became an op byte on the next. It existed so
 * the 13-byte probe.bin -- one of the two inputs every gate runs -- would
 * exercise more than the ~4 operations its bytes spell (measured then: 73 steps
 * on the first brotli build, 67 of them DSL_SKIP; the reachability design
 * keeps the record). With authored programs (the assembler, gen_program.py)
 * it no longer earned its complexity -- and worse, it made "the final value of
 * the run" a function of the STEP BUDGET instead of of what the author wrote,
 * which is fatal to expectations (below). So: probe.bin now executes ONE frame
 * (op 0x7b, len 0x22 clamped to its 11 remaining bytes). Gate-green is not
 * coverage; the authored program is.
 *
 * WHAT BOUNDS EXECUTION: the end of the payload, or the step budget, whichever
 * comes first. Every frame dispatched -- project op or VM op -- costs one unit
 * of `budget`, and the run stops when `budget == step_max` (DSL_STEPS scaled by
 * config[0] bits 3-4). `steps` counts PROJECT ops only. On a 2 MiB program the
 * default 4096-unit budget reads only the first few KiB; that is a deliberate
 * trade against qemu runtime, and config[0] bits 3-4 raise it by up to 64x for
 * a caller who wants the rest. A CHECK THE BUDGET PREVENTED FROM RUNNING IS A
 * FAILED CHECK (dsl_unreached, below), so the budget cannot satisfy an
 * expectation by never reaching it.
 *
 *
 * FOUR RULES THE VM ENFORCES SO THAT THE THEOREM STAYS TRUE. These are not
 * style; each one is a way the equivalence becomes false for a reason that has
 * nothing to do with the library, and each has a precedent elsewhere in this
 * repo.
 *
 *  1. EVERY SIZE IS BOUNDED. cli.c refuses inputs at 64 MiB and its header
 *     says why at length: the source and target roles of the equivalence are
 *     seeded with DIFFERENT allocation budgets, so an allocation near either
 *     budget makes one role fail where the other succeeds, and the two
 *     disagree observably. A DSL that handed a program-supplied 32-bit length
 *     to malloc would reintroduce exactly that, and would do it on an input
 *     the bound in cli.c admits. So every length operand is masked into
 *     [0, DSL_BUF_MAX] and total live driver allocation is capped at
 *     DSL_LIVE_MAX -- both far below any role's budget, at every point of the
 *     input space.
 *
 *  2. NO realloc, EVER. src/grow_buf.h's whole header: musl's mallocng grows
 *     an mmap-served block with mremap, and whether mremap is modeled depends
 *     on which linux-process-semantics version is pinned. The arena here only
 *     ever mallocs and frees.
 *
 *  3. NO ADDRESSES IN THE OUTPUT. ASan changes every address and every
 *     allocation size, so a printed pointer makes the plain and instrumented
 *     builds differ on every input and T2 is false everywhere -- a self-
 *     inflicted refutation. dsl_note() is for statuses, counts and digests.
 *     A digest of a BUFFER's CONTENTS is fine and is the intended idiom; a
 *     digest that has swallowed a pointer value is not. A handle's `n` is
 *     passed to dsl_serialize and never printed by the VM: it may be anything,
 *     including (today, libtsm) a pointer.
 *
 *  4. NO ENVIRONMENT, NO FILESYSTEM, NO CLOCK, NO ENTROPY. src/target.h
 *     forbids the first two outright, and the reason generalises: getenv makes
 *     the theorem quantify over envp for real, opening a path makes it
 *     quantify over the initial filesystem, and a clock or an OS random source
 *     makes the run not a function of the input at all. Anything a DSL
 *     operation needs that is not in the program comes from dsl_rand(), which
 *     is a pure function of the program bytes.
 *
 * abort(), assert() and exit() are treated exactly as the adapter treats them
 * and for the same reason (see src/ossfuzz_adapter.h): reaching one executes
 * syscalls outside the modeled set, so the target ERRORS and the equivalence
 * is false on that input, which is a finding about the input rather than a
 * defect to be silenced. Do not add -DNDEBUG and do not wrap library calls in
 * a longjmp to survive them.
 *
 *
 * WHICH COMPILER COMPILES A DSL TRANSLATION UNIT, and why it is the LIBRARY's.
 * build.sh's rule for plugin.c is spec s4's: the driver's objects are compiled
 * uninstrumented in both flavours so cli.o is byte-identical across a T2 pair,
 * and only the library's translation units get the sanitizer -- EXCEPT for a
 * header-only library, where the library's code arrives inside plugin.o by
 * #include and the plugin therefore sits on the library side of the line
 * (without that, jsmn's ASan build instruments nothing and T2 for jsmn is
 * vacuously true).
 *
 * A DSL translation unit is that case by construction, not by accident: it
 * includes the library's headers and calls its API, so any static inline
 * function, macro body or C++ template the header defines is compiled INTO
 * dsl.o. the instrumentation check reads exactly this from DWARF -- an
 * object whose line program has rows attributed to a file under ext/<t>/src is
 * an object carrying library code, and it must be instrumented -- so the same
 * ruling applies and build.sh compiles dsl.c with $CC/$CFLAGS.
 *
 * What that does NOT change: cli.o and cli-quiet.o are still built by the
 * driver's compiler with identical command lines in every flavour, and
 * the driver-object check still compares them. Spec s4.2 check (B) is a claim
 * about the DRIVER object, and the driver object is unmoved.
 *
 * The consequence to be clear-eyed about: in the ASan flavours the VM's own
 * buffers are instrumented too, so a bug in this file, or in a project's
 * dsl.c, surfaces as an ASan report and refutes T2 for a reason that is OURS.
 * That is the right way round -- it is a bug we can fix, reported by the
 * instrument we are validating -- but it means the VM has to be correct, not
 * merely careful.
 *
 *
 * WHAT A PROJECT'S dsl.c LOOKS LIKE. One translation unit, in this order:
 *
 *     #define TRAMP_DSL_NAME "brotli"
 *     #include "dsl.h"                  // this file; also pulls target.h
 *     #include <brotli/decode.h>        // the library's own headers
 *
 *     static unsigned dsl_ops(void) { return 9; }
 *     static const char *dsl_op_name(unsigned op) { ... }
 *     static void dsl_kill(dsl_vm *V, int kind, void *p, size_t n) { ... }
 *     static void dsl_begin(dsl_vm *V) { }
 *     static void dsl_end(dsl_vm *V) { }
 *     static int dsl_step(dsl_vm *V, unsigned op) { switch (op) { ... } }
 *
 * The six functions are forward-declared below and called from target_run(),
 * so they may be defined anywhere in the file after the include -- a C
 * translation unit may declare a static function and define it later, and that
 * is what lets a single header carry both halves of the contract.
 *
 * OPCODES ARE TAKEN MODULO dsl_ops(), NOT RANGE-CHECKED. `op = byte %
 * dsl_ops()` means every one of the 256 byte values is a legal instruction and
 * the whole opcode space is live. The alternative -- treat out-of-range bytes
 * as no-ops -- would make a random program spend 256-n/256 of its steps doing
 * nothing, which for a nine-operation table is 96% of them. Same policy as the
 * adapter's "every config byte is legal", for the same reason: the theorem
 * quantifies over all inputs, so an input that does nothing is a wasted point
 * of the space rather than an invalid one. EXCEPT op byte 255, the VM escape,
 * which is decoded BEFORE the modulo (next section); `dsl_ops()` must be in
 * 1..255.
 *
 *
 * EXPECTATIONS: OP BYTE 255, FAIL-CLOSED, TRANSPARENT, EXIT 3.
 *
 * The requirement (2026-09-02): the DSL takes "one or more expectations of the
 * final values, appropriately expressed in the dsl, and exits with a code
 * depending on whether or not the values match", so that for the task
 * "classify the inputs on which things change and on which they don't",
 * 'change' captures the full functional behaviour of the library. The design:
 *
 * THE ESCAPE. A frame whose op byte is 255 is not a project op. It is decoded
 * before the modulo, so exactly one of the 256 byte values changes meaning
 * (it used to mean `255 % dsl_ops()`); every asm.py-authored program and every
 * witness_payload(k) is unchanged frame by frame. The first operand byte is
 * the SUB-op; the rest are its operands, little-endian, fixed width:
 *
 *   sub  mnemonic                 operands        width  check?
 *   0    snap                     -               0      NO: prints the state
 *   1    expect digest H          u64             8      digest == H
 *   2    expect count SEL N       u8, u32         5      SEL 0 steps 1 ok 2 err 3 skip
 *   3    expect last R            u8              1      last_rc == R (0 ok 1 liberr 2 skip 3 none)
 *   4    expect live K N          u8, u8          2      live slots of kind K == N (K=0: all)
 *   5    expect slot S K          u8, u8          2      h[S].kind == K (K=0: empty)
 *   6    expect obj S K LEN H     u8,u8,u32,u64   14     kind matches and serialized (n,h) == (LEN,H)
 *   7    expect alloc N           u32             4      this repeat's allocation count == N
 *   8    allocs                   -               0      NO: prints `allocs n=<this repeat's count>`
 *   9..  -                        any             -      always a FAILED check
 *
 * FAIL CLOSED. A check with fewer operand bytes than its width FAILS without
 * reading anything (dsl_u8 zero-extends, so `[255][2][2][1]` would otherwise
 * pass an ok-count check against 0). So does an empty 255-frame, an unknown
 * sub, an out-of-range selector/slot/kind, a dead slot, a kind mismatch, and a
 * kind dsl_serialize does not support -- an old binary can never satisfy a
 * check it does not understand. Integers compare exactly; there are no
 * tolerances, because rule 4 makes everything deterministic.
 *
 * EVERY CHECK IS EVALUATED. A failed check sets the repeat's sticky `failed`
 * flag, counts in n_fail, prints one bounded line (`expect <what> ... FAIL`)
 * and execution CONTINUES, so the trace is complete and informative. Checks
 * placed at the program's end are "expectations of the final values"; checks
 * placed between project ops express trajectories (decode gives D, then
 * re-encode gives E).
 *
 * TRANSPARENT, WITHIN THE BUDGET. A VM frame reads only its own operand bytes
 * and the VM's state. It never calls dsl_rand, never allocates, never touches
 * the handle table, never changes steps/n_ok/n_liberr/n_skip/saw_liberr/
 * last_rc/digest/rng. It changes only budget, n_chk, n_fail, failed and the
 * output counters. So a check frame can be inserted anywhere in a check-free
 * program without moving a single value the program computes -- PROVIDED the
 * program plus its VM frames still fits the step budget, because a VM frame
 * costs one budget unit like any other frame. At the boundary it does move
 * something: [snap] + 4096 project frames runs 4095 of them under the default
 * budget, and the evicted project frame is not flagged (only CHECKS are
 * "unreached"; a project frame the budget cut is the budget doing what it
 * says). That is what lets gen_program.py record values from a plain run and
 * assert them afterwards, and why it fits the budget to the CHECKED program,
 * not just the snap-bearing one.
 *
 * THE DIGEST an `expect digest` compares against: FNV-1a 64 (offset basis
 * 1469598103934665603, prime 1099511628211) over, in execution order within
 * this repeat, every byte of dsl_begin's dsl_note/dsl_report lines, then for
 * each PROJECT op executed so far every byte of its dsl_note/dsl_report lines
 * (truncated to DSL_LINE_MAX-1; folded whether or not written) followed by the
 * two bytes [op % dsl_ops()][normalised rc]. VM frames fold NOTHING -- not
 * their notes, verdicts or operands -- so the digest a check sees is the digest
 * after the most recent project op (or after dsl_begin if none), independent
 * of every VM frame in the program. dsl_end's notes fold AFTER the last frame,
 * into the SUMMARY digest only, so a final snap's digest may differ from the
 * summary's; the generator records from snap. The (op, rc) fold is what makes
 * one final digest check cover ops that return without noting.
 *
 * THE SEED. The filler is seeded from config[1] and NOTHING else -- not the
 * repeat index (repeats are identical runs, so a repeat-2 difference is the
 * library's hidden state), not the payload's length or first bytes (inserting a
 * check frame must not move a filler byte). Still a pure function of the input
 * file (rule 4).
 *
 * UNREACHED. When the budget ends the run before the payload's end, the VM
 * walks the REMAINING frames' headers -- a pure function of the payload,
 * O(remaining bytes), no dispatch -- and every check frame it finds (op 255
 * whose sub is neither snap nor allocs, or with no sub byte at all) is one
 * FAILED check. A
 * program with no check frame is untouched by this: its status is 0/1 as it
 * always was, even at budget exhaustion.
 *
 * THE SERIALIZER. `expect obj` and snap's per-slot lines need the CONTENT of a
 * handle. A project opts in with `#define TRAMP_DSL_SERIALIZE 1` and
 *
 *     static int dsl_serialize(dsl_vm *V, int kind, void *p, size_t n, dsl_ser *S);
 *
 * which writes the object's value into S through dsl_ser_bytes/u8/u32/u64/i64/
 * f64/str and returns 0, or returns nonzero for a kind that is not observable
 * (every `expect obj` on it then FAILS and snap prints `ser=-`). The compared
 * value is (accepted byte count, FNV-1a digest) after a trailer byte saying
 * whether DSL_SER_MAX truncated the stream -- never an address (rule 3), never
 * an allocator-chosen size, never anything whose ORDER depends on addresses.
 * The full contract is the DSL driver notes, "Making a handle expectable". Cost:
 * a snap serializes EVERY live slot, so one snap frame is up to DSL_HANDLES x
 * DSL_SER_MAX bytes of hashing (measured: 16 x 16 KiB brotli buffers x 4079
 * snaps = ~1 GB hashed, 1.1 s native); a snap-per-frame program over 4 MiB
 * objects is a timeout -- inconclusive, by the sweep's rules -- not a
 * divergence. Snap where the values matter.
 *
 * EXIT STATUS. 3 if any repeat had a failed check (short, unknown, dead,
 * unsupported, range and unreached included); else 1 if a library call
 * reported failure; else 0. 2 stays cli.c's. A program with no check frame can
 * never be 3. Loud and quiet builds compute IDENTICAL statuses: the VM's lines
 * go through the same counted, capped path as dsl_note, emit.h suppresses the
 * write and not the evaluation, and no check reads what was written.
 *
 * That is the status THE VM returns. A library that ends the process itself --
 * exit(), abort(), an assert -- ends it with ITS status, mid-repeat, before the
 * summary line and before any check after that point (measured 2026-09-02:
 * brotli's encoder calls exit(EXIT_FAILURE) on an injected allocation failure,
 * BROTLI_ENCODER_EXIT_ON_OOM being its default, so a class-7 sweep input that
 * had already failed a check in repeats 0-1 exited 1 in repeat 2 with two
 * summary lines for four repeats). That is the library's behaviour, observed
 * identically by every flavour, and the paragraph above on abort()/exit()
 * applies: a finding about the input, not a status the VM owes. A tool that
 * reads summaries must therefore COUNT them against the repeats and read
 * stderr when they are short, rather than assume a status < 124 came from
 * target_run.
 */
#ifndef TRAMP_DSL_H
#define TRAMP_DSL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "emit.h"
#include "target.h"
#include "tramp_alloc.h"  /* the one allocation-failure schedule; C linkage */
#ifdef __cplusplus
}
#endif

#ifndef TRAMP_DSL_NAME
#error "define TRAMP_DSL_NAME before including dsl.h"
#endif

/* ---------------------------------------------------------------- budgets --
 *
 * Every one of these is overridable by a project that #defines it before the
 * include, and none of them should be raised without reading rule 1 above.
 * They are deliberately far below any allocation budget either role of the
 * equivalence is seeded with: the point is not to be generous, it is to make
 * the two roles agree at every point of the input space.
 */

/* The largest buffer any operation may ask for, driver-side or library-side.
 * 64 KiB is cli.c's own per-read transfer bound (a QA review found that the
 * trusted spec's read_spec tests count against rw_bytes_max = 131072 before
 * touching the file), so a DSL operation cannot ask for a transfer the spec
 * would not model even if a future operation performs one. */
#ifndef DSL_BUF_MAX
#define DSL_BUF_MAX (64u * 1024u)
#endif

/* Total live ARENA allocation -- the VM's and the project's scratch buffers,
 * not the library's own. A program that asks for more gets DSL_SKIP on the
 * operation that would have exceeded it, deterministically, at the same step
 * in every flavour. */
#ifndef DSL_LIVE_MAX
#define DSL_LIVE_MAX (4u * 1024u * 1024u)
#endif

/* How many operations one execution of the program may perform, before the
 * config[0] bits 3-4 scale is applied. Chosen against qemu runtime rather
 * than against coverage: the gates run every binary under qemu-user on two
 * probes, and a sweep runs them over a whole corpus. */
#ifndef DSL_STEPS
#define DSL_STEPS 4096u
#endif


/* Handle slots. A handle is whatever the project puts in one -- a decoder
 * state, a parsed document, an open context -- with a small positive KIND tag
 * so an operation can ask for "a live handle of kind 3" and get NULL rather
 * than a type confusion. 16 is enough for a program to build several live
 * objects of several kinds and still collide often enough to exercise the
 * kill-and-replace path. */
#ifndef DSL_HANDLES
#define DSL_HANDLES 16
#endif

/* The largest KIND tag a project may use. Kinds are 1..DSL_KIND_MAX; 0 means
 * an empty slot.
 *
 * THE RANGE EXISTS SO TEARDOWN CAN BE ORDERED, and the ordering is a contract
 * a project has to know about: at the end of an execution the VM destroys live
 * handles in DESCENDING KIND ORDER, so a kind that DEPENDS on another must be
 * numbered HIGHER than the one it depends on.
 *
 * Slot order -- the obvious implementation -- is wrong, and wrong in the way
 * that costs the most to debug. Take a library where a context borrows a
 * prepared dictionary (brotli, zstd, several compressors): destroying the
 * dictionary first leaves the context holding a freed pointer, and destroying
 * the context then reads it. That is a use-after-free the DRIVER manufactured.
 * In the plain build it is silent; in the ASan build it is a report, so T2 is
 * false on that input -- and the refutation is ours, not the library's, which
 * is the one kind of finding this tier must not produce.
 *
 * Numbering by kind cannot express every dependency graph (two kinds that
 * depend on each other, a dependency that only exists sometimes). A project
 * with one of those should keep the dependent resource OUT of the handle table
 * and free it in dsl_end(), which runs after every handle is gone. */
#ifndef DSL_KIND_MAX
#define DSL_KIND_MAX 64
#endif

/* Bytes the loud build may write. Bounds output without bounding the RUN:
 * past the cap the digest keeps folding in everything that would have been
 * printed, so the closing summary is still a function of the whole execution.
 * The quiet build writes nothing either way and its digest is identical --
 * emit.h suppresses the write, not the formatting. */
#ifndef DSL_OUT_MAX
#define DSL_OUT_MAX (256u * 1024u)
#endif

/* One formatted trace line. Truncation past this is deterministic and folded
 * into the digest as truncated, so it is not a divergence between flavours. */
#ifndef DSL_LINE_MAX
#define DSL_LINE_MAX 240
#endif

/* ------------------------------------------------------- operation results --
 *
 * The distinction between LIBERR and SKIP is what keeps the exit status
 * meaningful. LIBERR means the library was called and said no, which is a fact
 * about the input. SKIP means the operation never happened -- no handle of the
 * kind it needs was live, or the arena refused -- which is a fact about the
 * program's shape, and folding it into the status would make almost every
 * status 1 for a reason that is not about the library at all.
 */
#define DSL_OK      0   /* the library was called and reported success */
#define DSL_LIBERR  1   /* the library was called and reported failure */
#define DSL_SKIP    2   /* the operation could not run; nothing was called */
#define DSL_NONE    3   /* last_rc only: no project op has run yet this repeat */

/* THE VM ESCAPE: an op byte of 255 is not a project op. Decoded BEFORE the
 * modulo; the first operand byte selects the VM op. See "EXPECTATIONS". */
#define DSL_OP_VM       255u
#define DSL_VOP_SNAP    0
#define DSL_VOP_DIGEST  1
#define DSL_VOP_COUNT   2
#define DSL_VOP_LAST    3
#define DSL_VOP_LIVE    4
#define DSL_VOP_SLOT    5
#define DSL_VOP_OBJ     6
#define DSL_VOP_ALLOC   7   /* expect alloc N: this repeat's schedule ticks == N */
#define DSL_VOP_ALLOCS  8   /* allocs: print this repeat's count; NOT a check */
/* 9..255: reserved; always a FAILED check, so an old binary can never satisfy
 * a check it does not understand. */

/* How many bytes dsl_serialize may sink before the stream is TRUNCATED (the
 * trailer records that it was). Bounds serializer TIME, not memory: the sink
 * keeps a running digest and a count, never a buffer. */
#ifndef DSL_SER_MAX
#define DSL_SER_MAX (4u * 1024u * 1024u)
#endif

typedef struct dsl_arena_blk {
  struct dsl_arena_blk *next;
  size_t size;
} dsl_arena_blk;

typedef struct dsl_handle {
  int kind;       /* 0 = empty; a project's own positive tag otherwise */
  void *p;
  size_t n;       /* whatever "size" means for that kind; the project's choice */
} dsl_handle;

typedef struct dsl_vm {
  /* The program: the input's payload, read ONCE from offset 0 to its end. */
  const unsigned char *prog;
  size_t prog_len;
  size_t pc;

  /* The current instruction's frame -- see "AN INSTRUCTION IS A FRAME" in the
   * header. op_off is the program offset its op byte was read from (for the
   * loud trace and for the VM test's linear-cursor check); frame_end is
   * one past its last operand byte, and every operand read below clamps to it. */
  size_t op_off;
  size_t frame_end;

  /* The config bytes, verbatim, for a project that wants more than the mode
   * bits the VM already decoded. Reserved bits are reserved, not private:
   * reading them here is fine, but note that every existing input generator in
   * this repo writes config = {0}. */
  const unsigned char *cfg;
  size_t cfg_len;

  /* Decoded mode. */
  unsigned repeats;        /* 1 + (config[0] & 3) */
  int terse;               /* config[0] bit 2 */
  unsigned long step_max;

  /* Accounting. */
  unsigned long budget;      /* frames dispatched this repeat, project AND VM: the loop bound */
  unsigned long steps;       /* PROJECT ops dispatched this repeat */
  unsigned long n_ok, n_liberr, n_skip;
  int saw_liberr;
  int last_rc;               /* normalised result of the most recent project op;
                              * DSL_NONE before any has run this repeat */
  unsigned long n_chk, n_fail;   /* expectation checks evaluated / failed this repeat */
  int failed;                /* sticky per repeat: some check failed */
  unsigned alloc_base;       /* the schedule's tick count at the top of this
                              * repeat -- written by target_run's loop, never by
                              * a frame. `expect alloc` and `allocs` report
                              * tramp_alloc_count() - alloc_base, so a count
                              * harvested from one repeat holds in every repeat */

  /* Output. */
  unsigned long out_bytes;   /* counted whether or not it was written */
  unsigned long out_written;
  uint64_t digest;           /* FNV-1a 64 over every byte dsl_note formatted, plus
                              * the [op][rc] pair after every project op -- see
                              * "THE DIGEST" in the header */

  /* Deterministic filler state -- see dsl_rand. */
  uint64_t rng;

  /* Arena. */
  dsl_arena_blk *arena;
  size_t live;

  dsl_handle h[DSL_HANDLES];

  /* A bit reservoir for dsl_flag(), so a boolean operand costs one bit of
   * program rather than one byte. Refilled from the frame a byte at a time and
   * CLEARED at every instruction -- see "AN INSTRUCTION IS A FRAME". */
  unsigned bits;
  unsigned nbits;

  /* Free for the project to use across operations within one execution --
   * cleared to zero before dsl_begin() and never touched by the VM. A project
   * that needs more should keep a file-scope static and clear it in
   * dsl_begin(); note that a static survives the repeats, which is exactly the
   * global-state exercise the repeat count exists for. */
  long scratch[8];
} dsl_vm;

/* ------------------------------------------- the per-project contract ------
 *
 * Declared here, defined by the project's dsl.c below its #include.
 */

/* How many operations the table has. Must be >= 1 and must not change between
 * calls: it is the modulus that maps a program byte to an operation, so a
 * varying answer would make the same program mean different things. */
static unsigned dsl_ops(void);

/* A short, stable, address-free name for the loud trace. Any string is fine;
 * "?" for an out-of-range op is fine. Used for output only. */
static const char *dsl_op_name(unsigned op);

/* Destroy one handle. Called by the VM when a slot is overwritten, when an
 * operation drops a handle explicitly, and for every live slot at the end of
 * an execution -- so a project need not track its own objects to avoid leaks.
 * Must tolerate being called with any kind it ever stored. Must not emit. */
static void dsl_kill(dsl_vm *V, int kind, void *p, size_t n);

/* Called once at the start of each execution of the program (so `repeats`
 * times per run), after the handle table and arena are empty. Any library
 * one-time initialisation belongs behind a file-scope `static int done` here.
 * May be empty. */
static void dsl_begin(dsl_vm *V);

/* Called once at the end of each execution, AFTER every live handle has been
 * killed and BEFORE the arena is released. The place to tear down anything
 * that is not a handle. May be empty. */
static void dsl_end(dsl_vm *V);

/* Perform operation `op` (already reduced modulo dsl_ops()). Read operands
 * from V with the dsl_* helpers -- never from anywhere else -- call the
 * library, and return DSL_OK, DSL_LIBERR or DSL_SKIP. */
static int dsl_step(dsl_vm *V, unsigned op);

/* THE ALLOCATION-FAILURE SCHEDULE IS EVERY DRIVER'S, and the decision lives in
 * one place. src/tramp_alloc.h is the API: cli.c's u32 arms it (target_alloc_init
 * below), target_run installs config[2..] as its extension, and the library's
 * own allocation calls reach it because build.sh renames malloc/calloc/.../
 * operator new in a derived copy of the pin-built archives to the tramp_* names
 * that object defines (header, "THE ALLOCATION-FAILURE SCHEDULE"). Nothing in
 * this header interposes on anything, and no driver has to do anything.
 *
 * Optional, IN ADDITION: a project whose library takes a PLUGGABLE allocator
 * can point it at src/faultalloc.h's fa_malloc/fa_realloc/fa_free, which
 * covers allocation paths the rename cannot see -- header-only library code
 * compiled into dsl.o (templates, static inline allocators, stb-style macros)
 * and libraries that allocate only through a callback table. To opt in,
 * #define TRAMP_DSL_ALLOC_HOOK before the include and define
 *
 *     static void dsl_alloc_install(void);
 *
 * which is called once, after arming and before the first execution. FA_DENY
 * is defined HERE, before faultalloc.h is included, so those hooks take their
 * verdict from tramp_alloc_deny(): one tick of the SAME index the renamed calls
 * tick, one schedule per process, no second bitmap (fa_init is never called in
 * this tier and fa_bitmap stays 0). fa_n still counts hook-routed calls, which
 * is what fa_count() has always meant and what three drivers print into their
 * digest. FA_RAW_MALLOC is defined here too, as tramp_alloc_raw_malloc: since
 * 2026-09-14 build.sh renames the allocation family in dsl.o as
 * well, so the hooks' own malloc -- compiled into this object -- would land on
 * tramp_malloc and tick a SECOND time for the allocation FA_DENY() just ticked.
 * The same rule binds a hand-written hook: a hook body that asks
 * tramp_alloc_deny() itself (postgis does, to hand the library exact malloc
 * chunks) must allocate through tramp_alloc_raw_malloc, never through malloc;
 * a hook body that neither calls fa_malloc nor asks tramp_alloc_deny() and
 * allocates through malloc is scheduled once, by the rename, like any other
 * allocation compiled into this object. */
#ifdef FA_DENY
#error "dsl.h owns FA_DENY: the DSL tier has exactly one allocation schedule (src/tramp_alloc.h)"
#endif
#define FA_DENY() tramp_alloc_deny()
#ifdef FA_RAW_MALLOC
#error "dsl.h owns FA_RAW_MALLOC: the hook tier's real allocator is tramp_alloc_raw_malloc (src/tramp_alloc.h)"
#endif
#define FA_RAW_MALLOC(n) tramp_alloc_raw_malloc(n)
#ifdef TRAMP_DSL_ALLOC_HOOK
#include "faultalloc.h"
static void dsl_alloc_install(void);
#endif

/* ------------------------------------------------------------- the cursor --
 *
 * Reads never fail and never read out of bounds. A helper that returned an
 * error would put an error check on every operand read in every project's
 * dsl.c, and the one a project forgot would be an out-of-bounds read in the
 * driver -- reported by ASan, refuting T2, about us.
 *
 * There are two readers and the split IS the encoding. dsl_fetch reads the
 * instruction HEADER bytes (op, len) for the dispatch loop alone: past the end
 * of the program it returns 0 and stays put -- the program is read once, and a
 * missing header byte reads as 0. dsl_u8 -- the only one a project's dsl.c may
 * call, directly or through the helpers below -- reads OPERAND bytes: it is
 * clamped to the current frame and returns 0 once the frame is spent, so an
 * operand can never be shifted by what came before nor consume what comes
 * after.
 */
static unsigned dsl_fetch(dsl_vm *V) {
  return V->pc < V->prog_len ? V->prog[V->pc++] : 0u;
}

/* One frame header at V->pc: op, len, the u16 escape, the clamp. Leaves pc at
 * the first operand byte and frame_end one past the last; missing header bytes
 * read as 0 (a lone trailing op byte runs with len 0; `[k][255]` missing its
 * u16 runs with flen 0). Used by the dispatch loop AND by dsl_unreached, so the
 * two decoders cannot drift. The subtraction cannot wrap: dsl_fetch never
 * leaves pc past prog_len. */
static unsigned dsl_frame_hdr(dsl_vm *V) {
  unsigned raw, lenb;
  size_t flen;
  V->op_off = V->pc;
  raw = dsl_fetch(V);
  lenb = dsl_fetch(V);
  if (lenb == 255) {
    size_t lo = dsl_fetch(V);
    flen = lo | ((size_t)dsl_fetch(V) << 8);
  } else {
    flen = lenb;
  }
  V->frame_end = flen <= V->prog_len - V->pc ? V->pc + flen : V->prog_len;
  return raw;
}

static unsigned dsl_u8(dsl_vm *V) {
  if (V->pc >= V->frame_end) return 0;   /* the frame is spent: operands
                                          * zero-extend, the cursor stays */
  return V->prog[V->pc++];
}

static unsigned dsl_u16(dsl_vm *V) {
  unsigned a = dsl_u8(V), b = dsl_u8(V);
  return a | (b << 8);
}

static unsigned long dsl_u32(dsl_vm *V) {
  unsigned long a = dsl_u16(V);
  return a | ((unsigned long)dsl_u16(V) << 16);
}

/* One bit, from a reservoir, so a boolean operand does not cost a whole byte.
 * A program that is mostly flags then encodes eight decisions per byte. */
static int dsl_flag(dsl_vm *V) {
  if (V->nbits == 0) { V->bits = dsl_u8(V); V->nbits = 8; }
  V->nbits--;
  { int b = (int)(V->bits & 1u); V->bits >>= 1; return b; }
}

/* A value in [0, n), from one program byte. n == 0 is treated as 1 rather
 * than dividing by zero: a project computing n from a library-reported count
 * can legitimately reach 0, and a trap there would be a UBSan finding about
 * the driver. */
static unsigned dsl_choice(dsl_vm *V, unsigned n) {
  unsigned b = dsl_u8(V);
  return n ? (b % n) : 0u;
}

/* A length in [0, cap], cap itself clamped to DSL_BUF_MAX. Two program bytes,
 * so a program can select any size in the range rather than only 256 of them.
 *
 * The modulo is the whole point of the helper and is why no project should
 * compute a size any other way: rule 1 above. */
static size_t dsl_bounded(dsl_vm *V, size_t cap) {
  unsigned v = dsl_u16(V);
  if (cap > DSL_BUF_MAX) cap = DSL_BUF_MAX;
  return (size_t)(v % (unsigned)(cap + 1));
}

/* ----------------------------------------------------------- the filler ----
 *
 * xorshift64*, seeded from config[1] and from NOTHING else (see target_run for
 * why not the repeat index or the payload), so it is a pure function of the
 * input file and unmoved by a check frame inserted anywhere. It exists because a
 * great many API operations need BYTES that the program has no room to spell
 * out -- a 64 KiB buffer to compress, a window to fill -- and the two
 * alternatives are both wrong: reading them from the program consumes the
 * program (a 2 MiB payload would encode one operation), and leaving the buffer
 * uninitialised is undefined behaviour that MSan-class instrumentation is
 * right to flag and that makes the run depend on whatever the allocator
 * returned, which ASan changes.
 */
static uint64_t dsl_rand(dsl_vm *V) {
  uint64_t x = V->rng;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  V->rng = x;
  return x * 0x2545F4914F6CDD1DULL;
}

static void dsl_fill(dsl_vm *V, void *p, size_t n) {
  unsigned char *q = (unsigned char *)p;
  size_t i;
  for (i = 0; i < n; i++) q[i] = (unsigned char)(dsl_rand(V) >> 24);
}

/* ------------------------------------------------------------- the arena ---
 *
 * malloc/free only -- never realloc (rule 2) -- with a live cap (rule 1) and a
 * bulk release at the end of each execution. Every block is zeroed, so a
 * project never hands the library uninitialised bytes by accident.
 *
 * The header sits before the payload and is sized as a union with a max-align
 * type, so the pointer handed back keeps the alignment malloc would have
 * given. That matters here for the same reason it matters in
 * ossfuzz_adapter.h's tramp_aligned_copy: harnesses and libraries cast buffers
 * to wider types, and a misaligned load is UB that the trap-mode UBSan build
 * turns into SIGILL.
 */
typedef union dsl_arena_hdr {
  dsl_arena_blk blk;
  long double align_ld;
  void *align_p;
  uint64_t align_u64;
} dsl_arena_hdr;

static void *dsl_zalloc(dsl_vm *V, size_t n) {
  dsl_arena_hdr *h;
  size_t total;
  if (n > DSL_BUF_MAX) return NULL;
  /* The addition cannot wrap: n is already bounded above by DSL_BUF_MAX. The
   * check is kept anyway, because the bound is a #define a project may raise
   * and an unchecked size arithmetic that is safe only because of a constant
   * elsewhere is the shape faultalloc.h's header warns about. */
  total = sizeof(dsl_arena_hdr) + n;
  if (total < n) return NULL;
  if (V->live + total > (size_t)DSL_LIVE_MAX) return NULL;
  /* tramp_alloc_raw_malloc, not malloc: since 2026-09-14 build.sh
   * renames the allocation family in THIS object too, so a plain malloc here
   * would tick the library's schedule and a set bit could deny the VM its own
   * arena. The raw name is outside every map and never ticks (tramp_alloc.h). */
  h = (dsl_arena_hdr *)tramp_alloc_raw_malloc(total);
  if (h == NULL) return NULL;
  memset(h, 0, total);
  h->blk.next = V->arena;
  h->blk.size = total;
  V->arena = &h->blk;
  V->live += total;
  return (void *)((unsigned char *)h + sizeof(dsl_arena_hdr));
}

static void dsl_arena_release(dsl_vm *V) {
  dsl_arena_blk *b = V->arena;
  while (b) {
    dsl_arena_blk *next = b->next;
    free(b);
    b = next;
  }
  V->arena = NULL;
  V->live = 0;
}

/* An inline literal: a length-prefixed slice of the program, returned as a
 * pointer INTO the program. Cheap, and correct for any API that takes
 * (ptr, len) and does not require alignment or a NUL.
 *
 * The slice never leaves the instruction's frame: the length is clamped to the
 * frame's remainder, like every other operand read, so the same instruction
 * means the same bytes wherever and whenever it executes. */
static const unsigned char *dsl_take(dsl_vm *V, size_t cap, size_t *out_n) {
  size_t want = dsl_bounded(V, cap);
  size_t avail;
  const unsigned char *p;
  if (V->pc >= V->frame_end) { *out_n = 0; return (const unsigned char *)""; }
  avail = V->frame_end - V->pc;
  if (want > avail) want = avail;
  p = V->prog + V->pc;
  V->pc += want;
  *out_n = want;
  return p;
}

/* The same slice, copied into an aligned, zero-padded arena block. `extra`
 * zero bytes are appended (pass 1 for a NUL terminator). Returns NULL if the
 * arena refused, which the caller must treat as DSL_SKIP -- not as a library
 * error, since the library was never called. */
static void *dsl_dup(dsl_vm *V, const void *p, size_t n, size_t extra) {
  void *q;
  if (n > DSL_BUF_MAX || extra > DSL_BUF_MAX || n + extra > DSL_BUF_MAX) return NULL;
  q = dsl_zalloc(V, n + extra);
  if (q == NULL) return NULL;
  if (n) memcpy(q, p, n);
  return q;
}

/* A NUL-terminated copy of an inline literal, for the very many APIs that take
 * a C string. Interior NUL bytes are left alone: they are a legal part of the
 * input space and truncating there would hide inputs rather than exercise
 * them. */
static char *dsl_cstr(dsl_vm *V, size_t cap) {
  size_t n = 0;
  const unsigned char *p = dsl_take(V, cap, &n);
  return (char *)dsl_dup(V, p, n, 1);
}

/* A buffer of program-chosen size, filled deterministically by dsl_rand. For
 * the compress/encode/render side of an API, where the CONTENT matters less
 * than the size and the library's own handling of it. */
static void *dsl_buf(dsl_vm *V, size_t cap, size_t *out_n) {
  size_t n = dsl_bounded(V, cap);
  void *p = dsl_zalloc(V, n ? n : 1);
  if (p == NULL) { *out_n = 0; return NULL; }
  if (n) dsl_fill(V, p, n);
  *out_n = n;
  return p;
}

/* ------------------------------------------------------------ the output ---
 *
 * One path to stdout, and it is the only one a project may use: emit.h's
 * emit_bytes, through here. A project that calls printf directly writes in the
 * QUIET build too, and check_quiet.sh fails the binary -- which is the gate
 * doing its job, but it is cheaper to read this paragraph.
 *
 * The digest is folded in the QUIET build as well. Nothing reads it there, and
 * that is deliberate: emit.h suppresses the write and not the formatting
 * precisely so that a quiet run performs the same work and returns the same
 * status as a loud one, and a digest computed only in one of them would be a
 * second, invisible difference between the pair that check_loud_quiet_agree
 * cannot see.
 */
static void dsl_fold(dsl_vm *V, const void *p, size_t n) {
  const unsigned char *q = (const unsigned char *)p;
  uint64_t h = V->digest;
  size_t i;
  for (i = 0; i < n; i++) {
    h ^= (uint64_t)q[i];
    h *= 1099511628211ULL;
  }
  V->digest = h;
}

/* The one formatter behind dsl_note and dsl_vnote. `fold` says whether the
 * line enters the digest: a project's lines do, the VM's own lines (snap,
 * expect) do not -- see "THE DIGEST" in the header for why a check must not
 * change the value the next check compares against. */
static void dsl_vnote_v(dsl_vm *V, int fold, const char *fmt, va_list ap) {
  char line[DSL_LINE_MAX];
  int r;
  size_t n;
  r = vsnprintf(line, sizeof line, fmt, ap);
  if (r < 0) return;
  n = (size_t)r < sizeof line - 1 ? (size_t)r : sizeof line - 1;
  /* Counted before the cap is applied, so out_bytes says how much the run
   * WOULD have written -- a quantity a caller can compare across flavours
   * without having to reason about the cap. */
  V->out_bytes += (unsigned long)n;
  if (fold) dsl_fold(V, line, n);
  if (V->terse) return;
  if (V->out_written + n > (unsigned long)DSL_OUT_MAX) return;
  V->out_written += (unsigned long)n;
  emit_bytes(line, n);
}

/* A bounded, formatted trace line, FOLDED into the digest. NEVER pass a
 * pointer value (rule 3). */
static void dsl_note(dsl_vm *V, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dsl_vnote_v(V, 1, fmt, ap);
  va_end(ap);
}

/* The VM's own lines (snap, expect): counted, capped, silenced by terse and by
 * HARNESS_QUIET exactly like dsl_note -- and NEVER folded. See "THE DIGEST". */
static void dsl_vnote(dsl_vm *V, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dsl_vnote_v(V, 0, fmt, ap);
  va_end(ap);
}

/* Fold a library-produced buffer's CONTENTS into the digest and report its
 * length and its own hash. The intended way to report output: it is a function
 * of the bytes, it is bounded whatever the bytes are, and it contains no
 * address. */
static void dsl_report(dsl_vm *V, const char *what, int rc, const void *p, size_t n) {
  uint64_t h = 1469598103934665603ULL;
  const unsigned char *q = (const unsigned char *)p;
  size_t i;
  for (i = 0; i < n; i++) { h ^= (uint64_t)q[i]; h *= 1099511628211ULL; }
  dsl_note(V, "%s rc=%d n=%lu h=%016llx\n", what, rc,
           (unsigned long)n, (unsigned long long)h);
}

/* ----------------------------------------------------------- the handles ---
 *
 * A slot is chosen by the program. dsl_hget scans CIRCULARLY from the chosen
 * slot for a live handle of the requested kind, so a program that has built
 * one object of a kind can reach it from any slot operand -- without that, a
 * random program would find an empty slot almost every time and the whole
 * table would sit unused while every operation returned DSL_SKIP.
 */
static void dsl_hclear(dsl_vm *V, int slot) {
  if (V->h[slot].kind != 0) {
    int kind = V->h[slot].kind;
    void *p = V->h[slot].p;
    size_t n = V->h[slot].n;
    V->h[slot].kind = 0;
    V->h[slot].p = NULL;
    V->h[slot].n = 0;
    /* Cleared BEFORE the destructor runs, so a destructor that somehow
     * re-entered the VM cannot see the slot it is destroying. */
    dsl_kill(V, kind, p, n);
  }
}

/* Store p under `kind` in a program-chosen slot, destroying whatever was there.
 * Returns the slot, for a project that wants to note it.
 *
 * IT CAN DESTROY A HANDLE YOU ARE STILL HOLDING, AND THAT HAS ALREADY COST A
 * REFUTATION. The slot is chosen by the PROGRAM, so a sequence like
 *
 *     Foo *f = (Foo *)dsl_hget(V, K_FOO, NULL);   // f lives in some slot
 *     dsl_hput(V, K_BAR, bar, 0);                 // may pick THAT slot
 *     foo_write(f, ...);                          // f is freed
 *
 * is a use-after-free whenever the program's slot byte happens to name the slot
 * f came from. MEASURED: cpp-httplib's driver held a BufferStream fetched from
 * K_STREAM across a dsl_hput(K_HEADERS, ...), and on one input of
 * the flavour sweep's seed the put evicted exactly that slot --
 * heap-use-after-free WRITE at httplib.h:11663, plain and ubsan dying of
 * SIGSEGV while asan and asanubsan exited 1, i.e. a cross-flavour disagreement
 * caused by the DRIVER. Three sibling instances of the same shape were in the
 * same file.
 *
 * dsl_hput CANNOT fix this for you: which slot to reuse is the program's choice
 * and refusing an occupied slot would make the kill-and-replace path
 * unreachable, which is half of what the handle table is for. So the rule is on
 * the caller: DO NOT HOLD A HANDLE POINTER ACROSS A dsl_hput OF ANY KIND. If an
 * operation must, re-validate it afterwards by scanning the table for exactly
 * (kind, pointer) -- consuming NO program bytes, so the check is identical at
 * the same step in every flavour -- and treat a missing entry as DSL_SKIP.
 * cpp-httplib's dsl.cc carries that helper as tramp_still_live(); it is per-project
 * rather than here only because it needs the project's own kind constants. */
static int dsl_hput(dsl_vm *V, int kind, void *p, size_t n) {
  int slot = (int)dsl_choice(V, (unsigned)DSL_HANDLES);
  dsl_hclear(V, slot);
  V->h[slot].kind = kind;
  V->h[slot].p = p;
  V->h[slot].n = n;
  return slot;
}

/* A live handle of `kind`, or NULL. `*out_n` is set only when one is found. */
static void *dsl_hget(dsl_vm *V, int kind, size_t *out_n) {
  int start = (int)dsl_choice(V, (unsigned)DSL_HANDLES);
  int i;
  for (i = 0; i < DSL_HANDLES; i++) {
    int slot = (start + i) % DSL_HANDLES;
    if (V->h[slot].kind == kind) {
      if (out_n) *out_n = V->h[slot].n;
      return V->h[slot].p;
    }
  }
  return NULL;
}

/* Destroy a program-chosen live handle of `kind`. Returns 1 if one was found.
 * Worth an operation of its own in most tables: an explicit teardown in the
 * middle of a program is how the library's free path gets exercised at a point
 * where other objects are still live, which is where double-free and
 * use-after-free bugs live. */
static int dsl_hdrop(dsl_vm *V, int kind) {
  int start = (int)dsl_choice(V, (unsigned)DSL_HANDLES);
  int i;
  for (i = 0; i < DSL_HANDLES; i++) {
    int slot = (start + i) % DSL_HANDLES;
    if (V->h[slot].kind == kind) { dsl_hclear(V, slot); return 1; }
  }
  return 0;
}

/* Update a handle in place -- for an API whose "reset" returns a new object,
 * or whose size changes. Finds a live handle of `kind` and replaces its
 * payload without destroying it (the caller owns the old pointer). */
static int dsl_hset(dsl_vm *V, int kind, void *old, void *newp, size_t n) {
  int i;
  for (i = 0; i < DSL_HANDLES; i++) {
    if (V->h[i].kind == kind && V->h[i].p == old) {
      V->h[i].p = newp;
      V->h[i].n = n;
      return 1;
    }
  }
  return 0;
}

/* -------------------------------------------------------- the serializer ---
 *
 * How a handle's CONTENT becomes expectable (header, "EXPECTATIONS"). A
 * dsl_ser is a sink with no buffer: FNV-1a state plus the count of bytes it
 * accepted. A project's dsl_serialize writes the object's value into it with
 * the helpers below; `expect obj` and snap compare or print (n, h) after
 * dsl_ser_close. DSL_SER_MAX bounds the serializer's TIME (rule 1's spirit: a
 * 4 MiB decoded image sinks in one pass; nothing larger is walked), and the
 * trailer folded by dsl_ser_close records whether it truncated, so a truncated
 * stream can never equal an exactly-DSL_SER_MAX one.
 */
typedef struct dsl_ser {
  uint64_t h;      /* FNV-1a 64 running state */
  size_t n;        /* bytes accepted so far */
  int truncated;   /* set once DSL_SER_MAX refused a byte */
} dsl_ser;

static void dsl_ser_init(dsl_ser *S) {
  S->h = 1469598103934665603ULL;
  S->n = 0;
  S->truncated = 0;
}

static void dsl_ser_bytes(dsl_ser *S, const void *p, size_t n) {
  const unsigned char *q = (const unsigned char *)p;
  size_t i;
  for (i = 0; i < n; i++) {
    if (S->n >= (size_t)DSL_SER_MAX) { S->truncated = 1; return; }
    S->h ^= (uint64_t)q[i];
    S->h *= 1099511628211ULL;
    S->n++;
  }
}

static void dsl_ser_u8(dsl_ser *S, unsigned v) {
  unsigned char b = (unsigned char)v;
  dsl_ser_bytes(S, &b, 1);
}

static void dsl_ser_u32(dsl_ser *S, uint32_t v) {
  unsigned char b[4];
  b[0] = (unsigned char)v;
  b[1] = (unsigned char)(v >> 8);
  b[2] = (unsigned char)(v >> 16);
  b[3] = (unsigned char)(v >> 24);
  dsl_ser_bytes(S, b, 4);
}

static void dsl_ser_u64(dsl_ser *S, uint64_t v) {
  dsl_ser_u32(S, (uint32_t)v);
  dsl_ser_u32(S, (uint32_t)(v >> 32));
}

static void dsl_ser_i64(dsl_ser *S, int64_t v) { dsl_ser_u64(S, (uint64_t)v); }

/* The bit pattern, never %f: a formatted float is locale- and libc-shaped, and
 * two libcs can print the same double differently. */
static void dsl_ser_f64(dsl_ser *S, double d) {
  uint64_t u;
  memcpy(&u, &d, sizeof u);
  dsl_ser_u64(S, u);
}

/* u32 length then the bytes; NULL is 0xFFFFFFFF, distinct from "". */
static void dsl_ser_str(dsl_ser *S, const char *s) {
  size_t n;
  if (s == NULL) { dsl_ser_u32(S, 0xFFFFFFFFu); return; }
  n = strlen(s);
  dsl_ser_u32(S, (uint32_t)(n > 0xFFFFFFFEu ? 0xFFFFFFFEu : n));
  dsl_ser_bytes(S, s, n);
}

/* A one-byte tag, for a pre-order walk that needs to say which node kind
 * follows (the DSL driver notes, "Making a handle expectable"). */
static void dsl_ser_tag(dsl_ser *S, unsigned tag) { dsl_ser_u8(S, tag); }

/* The compared value is (n, h) AFTER close: the trailer byte `truncated` is
 * folded so a truncated stream never equals an exactly-DSL_SER_MAX one. */
static void dsl_ser_close(dsl_ser *S) {
  S->h ^= (uint64_t)(S->truncated != 0);
  S->h *= 1099511628211ULL;
}

/* OPTIONAL per-project hook. #define TRAMP_DSL_SERIALIZE before the include and
 * define
 *
 *     static int dsl_serialize(dsl_vm *V, int kind, void *p, size_t n, dsl_ser *S);
 *
 * 0 = the stream written into S IS the object's value; nonzero = this kind is
 * not observable, so every `expect obj` on it FAILS and snap prints `ser=-`.
 * The contract (the DSL driver notes, "Making a handle expectable"), in short: it
 * is an OBSERVATION -- no operand reads, no handle-table calls, no arena, no
 * dsl_rand, no dsl_note; read-only library queries only; never an address or
 * anything whose order depends on one; floats as bit patterns; return nonzero
 * for anything you cannot make deterministic. Without the define, every kind is
 * unsupported, which is the honest answer rather than a stub that passes. */
#ifdef TRAMP_DSL_SERIALIZE
static int dsl_serialize(dsl_vm *V, int kind, void *p, size_t n, dsl_ser *S);
#else
static int dsl_serialize(dsl_vm *V, int kind, void *p, size_t n, dsl_ser *S) {
  (void)V; (void)kind; (void)p; (void)n; (void)S;
  return 1;
}
#endif

/* -------------------------------------------------------------- VM ops -----
 *
 * The op-255 frames: snap and allocs (observe) and the seven checks. Everything
 * here obeys the TRANSPARENCY rule from the header, asserted by
 * the VM test: a VM frame reads only its own operand bytes and VM state
 * (the schedule's tick count included -- reading it is not a tick); it never
 * calls dsl_rand, dsl_zalloc, dsl_hput/hget/hdrop/hset, and never changes
 * steps, n_ok, n_liberr, n_skip, saw_liberr, last_rc, digest, rng, alloc_base,
 * the handles or the arena. It changes only budget, n_chk, n_fail, failed,
 * out_bytes, out_written.
 */

/* Fail closed: a check whose frame holds fewer than `n` operand bytes must not
 * read them (dsl_u8 would zero-extend and the check could pass by accident). */
static int dsl_expect_need(dsl_vm *V, size_t n) { return V->frame_end - V->pc >= n; }

/* Two statements: two calls in one expression are unsequenced in C. */
static uint64_t dsl_vop_u64(dsl_vm *V) {
  uint64_t lo = dsl_u32(V);
  uint64_t hi = dsl_u32(V);
  return lo | (hi << 32);
}

/* snap: print the state a check could assert, in the form gen_program.py
 * harvests. Not a check -- n_chk and n_fail are untouched. At most
 * 1 + DSL_HANDLES lines; the per-slot line carries kind and serialized (n, h)
 * only, never the handle's `n` (rule 3: it may be a pointer). */
static void dsl_snap(dsl_vm *V) {
  unsigned live = 0;
  int i;
  for (i = 0; i < DSL_HANDLES; i++) if (V->h[i].kind != 0) live++;
  dsl_vnote(V, "snap digest=%016llx steps=%lu ok=%lu err=%lu skip=%lu last=%d live=%u\n",
            (unsigned long long)V->digest, V->steps, V->n_ok, V->n_liberr, V->n_skip,
            V->last_rc, live);
  for (i = 0; i < DSL_HANDLES; i++) {
    dsl_ser S;
    if (V->h[i].kind == 0) continue;
    dsl_ser_init(&S);
    if (dsl_serialize(V, V->h[i].kind, V->h[i].p, V->h[i].n, &S) != 0) {
      dsl_vnote(V, "snap slot=%d kind=%d ser=-\n", i, V->h[i].kind);
      continue;
    }
    dsl_ser_close(&S);
    dsl_vnote(V, "snap slot=%d kind=%d ser=%lu/%016llx%s\n", i, V->h[i].kind,
              (unsigned long)S.n, (unsigned long long)S.h, S.truncated ? " trunc" : "");
  }
}

/* One VM frame. pc is at the first operand byte (the sub), frame_end one past
 * the last; the dispatch loop skips to frame_end afterwards like any frame. */
static void dsl_vop(dsl_vm *V) {
  unsigned sub;
  int ok = 0;
  if (!dsl_expect_need(V, 1)) {            /* an empty 255-frame is a FAILED check */
    V->n_chk++; V->n_fail++; V->failed = 1;
    dsl_vnote(V, "expect short sub=- FAIL\n");
    return;
  }
  sub = dsl_u8(V);
  if (sub == DSL_VOP_SNAP) { dsl_snap(V); return; }   /* observe: not a check */
  if (sub == DSL_VOP_ALLOCS) {                         /* observe: not a check */
    /* This repeat's schedule ticks so far. Loud only and never folded, like
     * every VM line, so a program can carry one after every frame (gen_program
     * cover --allocs) and answer "which op does allocation #N fall in" from
     * one plain run -- and, byte-compared across flavours, certify that bit i
     * names the same allocation on both sides (header, "MEASURED"). */
    dsl_vnote(V, "allocs n=%u\n", tramp_alloc_count() - V->alloc_base);
    return;
  }
  V->n_chk++;
  switch (sub) {
  case DSL_VOP_DIGEST: {
    uint64_t want, got = V->digest;
    if (!dsl_expect_need(V, 8)) { dsl_vnote(V, "expect digest short FAIL\n"); break; }
    want = dsl_vop_u64(V);
    ok = (want == got);
    dsl_vnote(V, "expect digest want=%016llx got=%016llx %s\n",
              (unsigned long long)want, (unsigned long long)got, ok ? "pass" : "FAIL");
    break; }
  case DSL_VOP_COUNT: {
    unsigned sel;
    unsigned long want, got;
    if (!dsl_expect_need(V, 5)) { dsl_vnote(V, "expect count short FAIL\n"); break; }
    sel = dsl_u8(V);
    want = dsl_u32(V);
    if (sel > 3) { dsl_vnote(V, "expect count sel=%u unknown FAIL\n", sel); break; }
    got = sel == 0 ? V->steps : sel == 1 ? V->n_ok : sel == 2 ? V->n_liberr : V->n_skip;
    ok = (want == got);
    dsl_vnote(V, "expect count sel=%u want=%lu got=%lu %s\n", sel, want, got, ok ? "pass" : "FAIL");
    break; }
  case DSL_VOP_LAST: {
    unsigned want;
    if (!dsl_expect_need(V, 1)) { dsl_vnote(V, "expect last short FAIL\n"); break; }
    want = dsl_u8(V);
    if (want > (unsigned)DSL_NONE) { dsl_vnote(V, "expect last want=%u unknown FAIL\n", want); break; }
    ok = ((int)want == V->last_rc);
    dsl_vnote(V, "expect last want=%u got=%d %s\n", want, V->last_rc, ok ? "pass" : "FAIL");
    break; }
  case DSL_VOP_LIVE: {
    unsigned kind, want, got = 0;
    int i;
    if (!dsl_expect_need(V, 2)) { dsl_vnote(V, "expect live short FAIL\n"); break; }
    kind = dsl_u8(V);
    want = dsl_u8(V);
    if (kind > (unsigned)DSL_KIND_MAX) { dsl_vnote(V, "expect live kind=%u range FAIL\n", kind); break; }
    for (i = 0; i < DSL_HANDLES; i++)
      if (V->h[i].kind != 0 && (kind == 0 || (unsigned)V->h[i].kind == kind)) got++;
    ok = (want == got);
    dsl_vnote(V, "expect live kind=%u want=%u got=%u %s\n", kind, want, got, ok ? "pass" : "FAIL");
    break; }
  case DSL_VOP_SLOT: {
    unsigned slot, kind;
    if (!dsl_expect_need(V, 2)) { dsl_vnote(V, "expect slot short FAIL\n"); break; }
    slot = dsl_u8(V);
    kind = dsl_u8(V);
    if (slot >= (unsigned)DSL_HANDLES) { dsl_vnote(V, "expect slot slot=%u range FAIL\n", slot); break; }
    ok = ((unsigned)V->h[slot].kind == kind);
    dsl_vnote(V, "expect slot slot=%u want=%u got=%d %s\n", slot, kind, V->h[slot].kind, ok ? "pass" : "FAIL");
    break; }
  case DSL_VOP_OBJ: {
    unsigned slot, kind;
    unsigned long want_n;
    uint64_t want_h;
    dsl_ser S;
    if (!dsl_expect_need(V, 14)) { dsl_vnote(V, "expect obj short FAIL\n"); break; }
    slot = dsl_u8(V);
    kind = dsl_u8(V);
    want_n = dsl_u32(V);
    want_h = dsl_vop_u64(V);
    if (slot >= (unsigned)DSL_HANDLES) { dsl_vnote(V, "expect obj slot=%u range FAIL\n", slot); break; }
    if (V->h[slot].kind == 0) { dsl_vnote(V, "expect obj slot=%u dead FAIL\n", slot); break; }
    if ((unsigned)V->h[slot].kind != kind) {
      dsl_vnote(V, "expect obj slot=%u want kind=%u got kind=%d FAIL\n", slot, kind, V->h[slot].kind);
      break;
    }
    dsl_ser_init(&S);
    if (dsl_serialize(V, V->h[slot].kind, V->h[slot].p, V->h[slot].n, &S) != 0) {
      dsl_vnote(V, "expect obj slot=%u kind=%u unsupported FAIL\n", slot, kind);
      break;
    }
    dsl_ser_close(&S);
    ok = (S.n == (size_t)want_n && S.h == want_h);
    dsl_vnote(V, "expect obj slot=%u kind=%u want=%lu/%016llx got=%lu/%016llx%s %s\n", slot, kind,
              want_n, (unsigned long long)want_h, (unsigned long)S.n, (unsigned long long)S.h,
              S.truncated ? " trunc" : "", ok ? "pass" : "FAIL");
    break; }
  case DSL_VOP_ALLOC: {
    /* An uncapped count channel through the exit status: in the quiet tier
     * this decides 3 against the library's 0/1 with no write, so N is
     * recoverable by bisection where cli.c's counting mode clamps at 251. */
    unsigned long want, got = (unsigned long)(tramp_alloc_count() - V->alloc_base);
    if (!dsl_expect_need(V, 4)) { dsl_vnote(V, "expect alloc short FAIL\n"); break; }
    want = dsl_u32(V);
    ok = (want == got);
    dsl_vnote(V, "expect alloc want=%lu got=%lu %s\n", want, got, ok ? "pass" : "FAIL");
    break; }
  default:
    dsl_vnote(V, "expect unknown sub=%u FAIL\n", sub);
    break;
  }
  if (!ok) { V->n_fail++; V->failed = 1; }
}

/* THE BUDGET MUST NOT SATISFY A CHECK BY NEVER REACHING IT. Called after the
 * loop; a no-op when the program ran to its end. Header-only walk, O(remaining
 * bytes), pure function of the payload; snaps and allocs frames do not count
 * (neither is a check when executed, so neither is one when skipped). A
 * 255-frame with no sub byte is a check (it would have FAILED as `expect
 * short`), so it counts too. */
static void dsl_unreached(dsl_vm *V) {
  unsigned long n = 0;
  if (V->pc >= V->prog_len) return;
  while (V->pc < V->prog_len) {
    unsigned raw = dsl_frame_hdr(V);
    if (raw == DSL_OP_VM) {
      if (V->frame_end == V->pc
          || (V->prog[V->pc] != DSL_VOP_SNAP && V->prog[V->pc] != DSL_VOP_ALLOCS)) n++;
    }
    V->pc = V->frame_end;
  }
  if (n) {
    V->n_chk += n; V->n_fail += n; V->failed = 1;
    dsl_vnote(V, "expect unreached n=%lu budget=%lu FAIL\n", n, V->step_max);
  }
}

/* --------------------------------------------------------- target.h impl ---
 *
 * From here down is the driver side, and no project should need to read it.
 */

#ifdef __cplusplus
extern "C" {
#endif

const char *target_name(void) { return TRAMP_DSL_NAME "-dsl"; }

#if defined(__cplusplus) && (defined(__cpp_exceptions) || defined(__EXCEPTIONS))
/* The dispatch loop's std::bad_alloc catch lives in src/tramp_alloc_cxx.cc
 * (tramp_call_catching_bad_alloc), reached through this thunk, and NOT in a
 * try/catch here -- because naming std::bad_alloc needs <new>, and this header
 * MUST NOT include any C++ standard header by angle name: build.sh compiles a
 * driver with the library's source root on the include path, -I directories
 * win over the system ones for <angle> includes, and one library ships a text
 * file named `new` at its root (cifuzz; another ships `memory`), so a
 * `#include <new>` here resolved to that file and `std` was undeclared
 * (measured 2026-09-10). The trampoline object is compiled with -I/work/src
 * only, so its <new> is the real one. Only where exceptions are enabled: a
 * -fno-exceptions TU (serenity) lets a bad_alloc terminate, as the design says
 * it must -- a Class-B status, not a divergence -- and references nothing. */
static int dsl_step_thunk(void *v, unsigned op) { return dsl_step((dsl_vm *)v, op); }
#endif

/* ONE schedule for every driver, hooked or not. cli.c hands the header u32
 * here once, before target_run, and it goes straight to the trampoline object
 * (src/tramp_alloc.c) that the library's renamed allocation references also
 * reach. A hooked driver additionally remembers that arming happened, so that
 * target_run installs its hook exactly once, before the first execution, as
 * before. There is no "honest zero" branch any more: a driver without a hook
 * is scheduled through the archive rename, so its count is the true count of
 * covered allocations -- 0 only when the library allocated nothing, which
 * build.sh records as "schedule inert", never as "wired". */
#ifdef TRAMP_DSL_ALLOC_HOOK
static int dsl_alloc_armed = 0;
#endif
void target_alloc_init(unsigned int fail_bitmap) {
  tramp_alloc_arm(fail_bitmap);
#ifdef TRAMP_DSL_ALLOC_HOOK
  dsl_alloc_armed = 1;
#endif
}
/* The schedule index, uncapped: every covered allocation since arming, the
 * hook-routed ones (through FA_DENY) and the library's direct calls alike.
 * cli.c clamps it at 251 for the exit-status channel; the VM's `expect alloc`
 * and `allocs` sub-ops read it whole. NOT fa_count(): that is the hook-only
 * tick, which three drivers print and which keeps its meaning. */
unsigned target_alloc_count(void) { return tramp_alloc_count(); }

int target_run(const unsigned char *config, size_t config_len,
               const unsigned char *payload, size_t payload_len) {
  dsl_vm V;
  unsigned char c0 = config_len > 0 ? config[0] : 0;
  unsigned char c1 = config_len > 1 ? config[1] : 0;
  unsigned repeats = 1u + (unsigned)(c0 & 3u);
  int terse = (c0 >> 2) & 1;
  unsigned scale = (unsigned)((c0 >> 3) & 3u);
  unsigned long step_max = (unsigned long)DSL_STEPS << (2u * scale);
  int status = 0, any_failed = 0;
  unsigned rep;

  /* config[2..] is the schedule's extension (header, "THE ALLOCATION-FAILURE
   * SCHEDULE"): installed before anything the library could allocate in --
   * before the hook, before dsl_begin -- and COPIED by tramp_alloc_extend,
   * because config points into cli.c's input buffer, which cli.c frees while
   * the schedule stays armed (src/tramp_alloc.h says what goes wrong otherwise).
   * A one- or two-byte config installs an empty extension: today's inputs. */
  if (config_len > 2) tramp_alloc_extend(config + 2, config_len - 2);
  else tramp_alloc_extend(NULL, 0);

#ifdef TRAMP_DSL_ALLOC_HOOK
  if (dsl_alloc_armed) { dsl_alloc_armed = 0; dsl_alloc_install(); }
#endif

  for (rep = 0; rep < repeats; rep++) {
    int i;
    memset(&V, 0, sizeof V);
    V.prog = payload;
    V.prog_len = payload_len;
    V.cfg = config;
    V.cfg_len = config_len;
    V.repeats = repeats;
    V.terse = terse;
    V.step_max = step_max;
    V.digest = 1469598103934665603ULL;
    V.last_rc = DSL_NONE;            /* memset left 0 == DSL_OK: a check before any op would pass */
    /* THE SEED: config[1] and nothing else. Not the repeat index (repeats are
     * identical runs, so a repeat-2 difference is the library's hidden state and
     * nothing else), not the payload's length or first bytes (inserting a check
     * frame must not move a single filler byte, or a value recorded from a plain
     * run is unreproducible once the check asserting it is added). Rule 4 holds:
     * still a pure function of the input file. */
    V.rng = 0x9E3779B97F4A7C15ULL ^ (uint64_t)c1;
    if (V.rng == 0) V.rng = 0x2545F4914F6CDD1DULL;  /* xorshift's fixed point */
    /* This repeat's allocation base. The schedule's counter runs for the whole
     * process (armed once, never reset, so the extension can reach repeats
     * 1-3), but `expect alloc N` and `allocs` report THIS repeat's count: the
     * number an author harvests from one loud run, which holds in every repeat
     * because repeats are identical runs -- a process-wide N could hold in at
     * most one of them. Written by the loop, not by a frame: the transparency
     * rule is about what a FRAME may change. Taken before dsl_begin, whose
     * allocations are this repeat's. */
    V.alloc_base = tramp_alloc_count();

    dsl_begin(&V);

    /* THE DISPATCH LOOP: once over the payload, in order, or until the budget
     * is spent -- see "THE PROGRAM RUNS ONCE" and "WHAT BOUNDS EXECUTION". */
    while (V.pc < V.prog_len && V.budget < V.step_max) {
      unsigned raw = dsl_frame_hdr(&V);
      V.nbits = 0;                  /* the bit reservoir is per-frame */
      V.budget++;
      if (raw == DSL_OP_VM) {
        dsl_vop(&V);
      } else {
        unsigned nops = dsl_ops();
        int r;
        if (nops == 0 || nops > 255u) break;   /* contract: 1 <= dsl_ops() <= 255 (measured max 30) */
        V.steps++;
#if defined(__cplusplus) && (defined(__cpp_exceptions) || defined(__EXCEPTIONS))
        /* A scheduled denial of a throwing operator new arrives here as
         * std::bad_alloc (src/tramp_alloc_cxx.cc throws it from uninstrumented
         * code, identically in every flavour), and so does a real
         * out-of-memory in a C++ driver's own `new`. Uncaught, either ends
         * the process through std::terminate -> abort, rc 134 in every
         * flavour -- an unmodeled syscall path and a status that says nothing
         * about which call failed. Caught at this frame boundary -- the one
         * the VM owns -- it is what it is: the library call reported failure.
         * The op's partial state is whatever the op left (a handle it had
         * already stored is still stored; one it was about to store is gone),
         * which is deterministic and identical across flavours because the
         * throw site is. The catch itself is in tramp_alloc_cxx.o (see
         * dsl_step_thunk above for why it cannot be spelled here). */
        {
          int caught = 0;
          r = tramp_call_catching_bad_alloc(dsl_step_thunk, &V, raw % nops, &caught);
          if (caught) {
            dsl_note(&V, "step: allocation refused (bad_alloc)\n");
            r = DSL_LIBERR;
          }
        }
#else
        r = dsl_step(&V, raw % nops);
#endif
        V.last_rc = (r == DSL_OK || r == DSL_LIBERR) ? r : DSL_SKIP;
        {
          /* Every project op leaves (op, rc) in the digest, so one final digest
           * check covers ops that return without noting (brotli's dec_free). */
          unsigned char tag[2];
          tag[0] = (unsigned char)(raw % nops);
          tag[1] = (unsigned char)V.last_rc;
          dsl_fold(&V, tag, 2);
        }
        switch (V.last_rc) {
          case DSL_OK:     V.n_ok++; break;
          case DSL_LIBERR: V.n_liberr++; V.saw_liberr = 1; break;
          default:         V.n_skip++; break;
        }
      }
      /* Unconsumed operands are skipped: instruction i+1 starts where the LEN
       * BYTE said, not where the step's last read left off. This line is half
       * of the frame property; dsl_u8's clamp is the other half. */
      V.pc = V.frame_end;
    }
    dsl_unreached(&V);

    /* Every live handle, then everything the project holds, then the arena.
     * In that order: a destructor may still need its scratch buffers.
     *
     * Handles go in descending KIND order -- see DSL_KIND_MAX for why slot
     * order would be a driver-manufactured use-after-free for any library
     * where one object borrows another. */
    {
      int k;
      for (k = DSL_KIND_MAX; k >= 1; k--)
        for (i = 0; i < DSL_HANDLES; i++)
          if (V.h[i].kind == k) dsl_hclear(&V, i);
      /* Anything a project stored with a kind outside 1..DSL_KIND_MAX would be
       * leaked by the loop above, so it is caught here rather than left to
       * leak silently. Not an assert: reaching abort() executes unmodeled
       * syscalls (see the header), so a contract violation in a project's
       * dsl.c must not become a refutation of the theorem. It gets destroyed,
       * out of order, which is the best available answer. */
      for (i = 0; i < DSL_HANDLES; i++) dsl_hclear(&V, i);
    }
    dsl_end(&V);
    dsl_arena_release(&V);

    /* The closing summary is emitted even in terse mode, and it is the whole
     * observable there. Counts and a digest only -- no address, no size that
     * an allocator could have chosen. */
    {
      char line[DSL_LINE_MAX];
      int r = snprintf(line, sizeof line,
                       "%s rep=%u steps=%lu ok=%lu err=%lu skip=%lu chk=%lu fail=%lu out=%lu digest=%016llx\n",
                       TRAMP_DSL_NAME, rep, V.steps, V.n_ok, V.n_liberr, V.n_skip,
                       V.n_chk, V.n_fail, V.out_bytes, (unsigned long long)V.digest);
      if (r > 0) {
        size_t n = (size_t)r < sizeof line - 1 ? (size_t)r : sizeof line - 1;
        emit_bytes(line, n);
      }
    }

    if (V.failed) any_failed = 1;
    if (V.saw_liberr) status = 1;
  }

  /* 3: some expectation failed in some repeat (including short, unknown, dead,
   * unsupported, range and unreached). Else 1: a library call reported failure.
   * Else 0. Never 2: cli.c reserves that for a harness or IO error, and an
   * arena refusal is a SKIP rather than an error precisely so that a program's
   * shape cannot masquerade as one. A program with no check frame can never
   * be 3. */
  return any_failed ? 3 : status;
}

#ifdef __cplusplus
}
#endif

#endif /* TRAMP_DSL_H */
