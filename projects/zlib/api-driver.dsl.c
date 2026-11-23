/* zlib-checksum_fuzzer/dsl.c - the DSL driver for zlib.
 *
 * The optional second driver (src/dsl.h): a bytecode program decoded from the
 * input's payload, whose operations are zlib's own API rather than the one
 * entry point OSS-Fuzz's projects/zlib/checksum_fuzzer.c exposes.
 *
 * WHAT THIS REACHES THAT THE HARNESS DOES NOT, and for zlib the gap is not a
 * slice of the library, it is nearly all of it. targets/zlib-checksum_fuzzer/
 * checksum_fuzzer.c calls exactly eight functions, all of them checksums:
 * crc32, crc32_z, crc32_combine, crc32_combine_gen, crc32_combine_op,
 * adler32, adler32_z, adler32_combine. Counted in the pinned tree, adler32.c
 * and crc32.c are 1213 of the 9539 lines in zlib's fifteen .c files.
 * Everything else in the archive -- deflate.c,
 * trees.c, inflate.c, inftrees.c, inffast.c, infback.c, compress.c,
 * uncompr.c -- is UNREACHED by the artefact OSS-Fuzz has been running under
 * this fuzzer name. Concretely, and naming the entry points this file drives:
 *
 *   - the DEFLATER, in both its one-shot (compress, compress2) and its
 *     streaming (deflateInit2_, deflate, deflateEnd) forms, at every level,
 *     memLevel, strategy and window size; the six flush modes (Z_NO_FLUSH,
 *     Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH, Z_BLOCK) each of
 *     which is a distinct block-emission path through trees.c;
 *   - the INFLATER, one-shot (uncompress, uncompress2) and streaming
 *     (inflateInit2_, inflate, inflateEnd), plus inflate's OWN flush modes
 *     Z_BLOCK and Z_TREES, which no ordinary consumer uses and which stop
 *     inflate at block and tree boundaries;
 *   - inflateBack (infback.c), a whole 628-line translation unit with its own
 *     callback protocol -- inflateBackInit_/inflateBack/inflateBackEnd -- that
 *     nothing but zlib's own gun/puff examples ever calls;
 *   - the THREE STREAM WRAPPERS, not just zlib's: raw deflate (negative
 *     windowBits), gzip (windowBits + 16) and inflate's automatic detection
 *     (windowBits + 32). The gzip header writer and reader (deflateSetHeader,
 *     inflateGetHeader) are several hundred lines of deflate.c/inflate.c that
 *     the zlib-only path never enters at all;
 *   - PRESET DICTIONARIES in all four directions: deflateSetDictionary,
 *     deflateGetDictionary, inflateSetDictionary, inflateGetDictionary --
 *     including the "dictionary fills the window, use the tail" branch;
 *   - MID-STREAM RECONFIGURATION: deflateParams (which flushes and may switch
 *     between deflate_stored/fast/slow), deflateTune, deflatePrime,
 *     inflatePrime;
 *   - the RESET family, which is where zlib's state machine is most easily
 *     left inconsistent: deflateReset, deflateResetKeep, inflateReset,
 *     inflateResetKeep, inflateReset2 (which can change the wrapper and the
 *     window size of a live stream);
 *   - COPY: deflateCopy and inflateCopy, which duplicate an in-flight state
 *     including its allocated window and pending buffer;
 *   - the QUERY/RECOVERY surface: deflateBound, deflatePending, compressBound,
 *     inflateSync, inflateSyncPoint, inflateMark, inflateCodesUsed,
 *     inflateValidate, inflateUndermine, zError, zlibVersion,
 *     zlibCompileFlags, get_crc_table;
 *   - and every INTERLEAVING of the above, which is the point of a call-
 *     sequence program: a dictionary set after output has been produced, a
 *     header requested on a raw stream, deflateParams with no output room,
 *     inflateReset2 to a smaller window than the stream needs, a copy of a
 *     stream that has already seen Z_FINISH.
 *
 * THE ROUND TRIP IS WHY THIS DRIVER GETS PAST INFLATE'S HEADER PARSER. A
 * random payload is a corrupt deflate stream: fed straight to inflate() it
 * dies in the first few bytes and the whole program sits on the error path.
 * So the compress side's output is stored in a handle (K_ZBUF) and the
 * decompress side reads from it -- op_compress -> op_uncompress,
 * op_def_push -> op_inf_push, op_def_push -> op_inf_back. Deflate output fed
 * to inflate is a stream inflate accepts, so inffast.c's decode loop,
 * inftrees.c's table builder and the window-copy paths are reached on bytes
 * the program did not have to guess. The reverse edge exists too: inflate's
 * OUTPUT is stored as K_RAW and becomes input to the compressor, so the
 * deflater sees real decompressed data and not only dsl_fill's white noise
 * (which is incompressible, and so never reaches the match-finder's
 * interesting cases).
 *
 * FAULT INJECTION IS WIRED UP, which the adapter tier cannot do. Every
 * z_stream carries zalloc/zfree/opaque, so section 7's schedule
 * (src/faultalloc.h -- whose header already anticipates "Task 6's zlib and xz
 * hooks take a PRODUCT (items*size)") reaches deflateInit2_'s four
 * allocations, inflate's lazy window allocation, and the copies made by
 * deflateCopy/inflateCopy. That exercises zlib's Z_MEM_ERROR paths, which are
 * otherwise unreachable from any input.
 *
 * WHAT IS DELIBERATELY NOT HERE.
 *
 *   gzopen/gzread/gzwrite/gzdopen and the rest of gzlib.c/gzread.c/gzwrite.c
 *   (about 60 exported symbols, all present in the archive) take a FILE PATH
 *   or a file descriptor. src/dsl.h rule 4 and src/target.h forbid touching
 *   the filesystem: opening a path makes the equivalence quantify over the
 *   initial filesystem, and neither role would agree. gzdopen on a fixed fd is
 *   no better -- it would read the driver's own stdin. So the entire gz* layer
 *   is out of scope for this tier, and that is a real coverage hole, stated
 *   rather than hidden. It is the one part of zlib no memory-based driver can
 *   reach.
 *
 *   The checksums themselves (crc32/adler32 and their _z/_combine/_combine_gen
 *   /_combine_op variants) are NOT given operations of their own. They are the
 *   one thing the OSS-Fuzz harness already covers thoroughly, and this tier is
 *   for what it does not. They are still exercised heavily, but as zlib's
 *   internals: every zlib-wrapped stream computes an Adler-32 over its data
 *   and every gzip-wrapped stream a CRC-32, and both are checked on inflate.
 *
 *   crc32_combine64/adler32_combine64/crc32_combine_gen64 are the same
 *   functions under a different name (zlib.h maps the unsuffixed names onto
 *   them under _LARGEFILE64_SOURCE), so an operation for them would be a
 *   near-duplicate of what the harness already runs.
 *
 * THE ONE SCAR, and it is a machine-load artefact rather than anything in this
 * file: tests/check_asan_containment.sh is flaky on this machine.
 * verify_one.sh's plain and ubsan stages and its cross-flavour comparison pass
 * every time; one of the eight asan-family gate runs intermittently reports
 *
 *     FAIL: probe.bin: no read in the trace -- the run never reached its input
 *
 * and the failing BINARY and INPUT wander between runs. Measured over eight
 * hand-run ./build.sh invocations at load average ~260: asan clean 3 of 5,
 * asanubsan clean 3 of 4, with failures landing on
 * zlib-checksum_fuzzer-repro-asanubsan/probe.bin and
 * zlib-checksum_fuzzer-repro-asan/big.bin among others -- i.e. on the
 * PRE-EXISTING harness pair, which predates this file and which the repository
 * has been building green, so the driver cannot be the cause.
 *
 * What rules it out mechanically: that gate checks the EXIT STATUS FIRST
 * (`[ "$rc" -eq "$want" ] || fail`) and that check passed in every failing
 * case, so the traced run completed and returned the status the pin recorded.
 * A run that died before open() could not have. What came up short is qemu's
 * `-D` trace FILE, not the run. targets/md4c-fuzz-mdhtml/dsl.c and
 * targets/libiec61850-fuzz_acse_parse/dsl.c record the same flake with the
 * same wandering binary and reach the same conclusion. Recorded rather than
 * worked around: tools/dsl and tests/ are not ours to edit.
 *
 * WHERE THE CLAMPS ARE AND WHAT THEY COST is written out at "the clamps"
 * below, because dsl.h rule 1 is the rule this project could most easily
 * break: zlib's stream parameters are allocation knobs, deflateTune's are
 * runtime knobs with no bounds checking of their own, and inflateBack has no
 * output bound at all. In summary: nothing narrows level, memLevel, strategy
 * or windowBits below what zlib.h documents (the worst case a program can
 * build is bounded and small enough to leave both roles' budgets alone);
 * deflateTune IS narrowed and that costs the deepest match-chain walks
 * through that entry point; inflateBack is stopped at IB_OUT_MAX bytes of
 * output, so a stream that expands past 256 KiB is only decoded that far.
 *
 * EXTENDED 2026-09-02 FOR THE LINEAR VM WITH EXPECTATIONS (src/dsl.h op byte
 * 255, docs/dsl-driver.md "Expectations and exit 3"). Three things changed,
 * and the op ORDER 0..25 did not, so every one-instruction witness keeps its
 * op byte:
 *
 *   - EVERY HANDLE KIND IS EXPECTABLE (dsl_serialize, at the end of this
 *     file): K_RAW and K_ZBUF are their bytes; a K_DEF is its z_stream
 *     counters plus the Init-set scalars of deflate_state, the not-yet-flushed
 *     pending bytes, the not-yet-emitted symbol buffer and the window's
 *     contents (deflateGetDictionary); a K_INF is its counters, the Init-set
 *     scalars of inflate_state, the three read-only accessors and the window
 *     (inflateGetDictionary). No kind is opaque. That is what lets `expect
 *     obj` see a compressor that has buffered input and emitted nothing --
 *     a state no trace line reports.
 *   - TWO OPS APPENDED: `checksum` (26) drives the eight checksum entry points
 *     -- adler32, adler32_z, adler32_combine, crc32, crc32_z, crc32_combine,
 *     crc32_combine_gen, crc32_combine_op -- which the first version of this
 *     file left to the harness; the brief for this tier is every API family
 *     in the public header, and their absence made the file's own coverage
 *     claim depend on a different binary. `mutate` (27) flips, truncates or
 *     refills a library-produced stream (or a K_RAW) into a new handle of the
 *     same kind, so inflate's CHECKSUM-MISMATCH path (Z_DATA_ERROR "incorrect
 *     data check", reachable only from a stream whose header parses) is
 *     reached deliberately rather than by luck.
 *   - `end` (25) now notes what it dropped; it was the one op whose only trace
 *     was the (op, rc) fold.
 *
 * The figures below that describe the CYCLING VM (the cfg.bin step counts, the
 * probe.bin residue analysis under want_def) are HISTORICAL: the program now
 * runs once, linearly, and probe.bin executes one frame (op 0x7b % 28 = 11,
 * def_query, which creates a deflate stream and succeeds).
 *
 * REBUILT 2026-09-03, landing the two items the 2026-09-02 lane measured and
 * queued (docs/dsl-2026-09-02/zlib-checksum_fuzzer.md, Deviations 3 and 4);
 * the op table and its order are unchanged:
 *
 *   - want_def no longer asks deflateInit2_ for the one cell it rejects
 *     (windowBits 8 with the raw or gzip wrapper), so every implicit creation
 *     succeeds as the comment above it always claimed; and both want_def and
 *     want_inf NOTE the creation they perform, so the parameters of a stream
 *     an op built for itself are in the digest and not only in the serializer.
 *   - dsl_serialize sinks the CONTENT of an attached gz_header on both sides
 *     (ser_gzhead), where it sank only its presence: a header set on a gzip
 *     deflater and not yet emitted, and the fields inflate fills in from a
 *     gzip stream's header, were invisible to `expect obj`.
 */
#define AEF_DSL_NAME "zlib"
#define AEF_DSL_ALLOC_HOOK 1
#define AEF_DSL_SERIALIZE 1

/* THE STEP BUDGET IS CUT TO A QUARTER OF THE DEFAULT, and the binding
 * constraint is the ARENA rather than qemu.
 *
 * Every producing operation here keeps its result: op_compress stores a
 * compressed stream, op_def_push stores the bytes deflate() emitted,
 * op_uncompress and op_inf_push store what came back out. Those copies are
 * arena allocations that nothing frees until the end of the execution (dsl.h
 * rule 2: the arena only mallocs and frees, and it frees in bulk), so live
 * arena use grows monotonically with the step count. At DSL_LIVE_MAX = 4 MiB
 * and ~1 KiB retained per step averaged over the table, 4096 steps would
 * exhaust the arena roughly a quarter of the way in and every operation after
 * that would return DSL_SKIP -- a budget spent doing nothing, which is worse
 * than a smaller budget spent calling zlib.
 *
 * 1024 also keeps verify_one.sh's cfg.bin honest, and that is the measurement
 * the number is actually set by. That input carries config[0] = 0x0b: four
 * repeats at a 4x step scale, so it runs 4 x 4096 steps with the arena
 * released between repeats. Measured over those 16384 steps: ok=2960,
 * err=1134, skip=2. Two skips in four repeats is the arena refusing on the
 * very last operations of a repeat -- exactly at the cap and not past it. At
 * DSL_STEPS = 4096 the same input would run 65536 steps and three quarters of
 * them would be arena refusals.
 *
 * qemu runtime is NOT the binding constraint here and was measured to be sure:
 * the plain riscv64 binary under qemu-user takes 0.01 s on probe.bin, 0.05 s
 * on big.bin and 0.52 s on cfg.bin. zlib is fast and dsl_fill's output is
 * incompressible, so the match finder never does its expensive work on it.
 *
 * The cost, stated: on a large payload this driver reads fewer program bytes
 * than a 4096-step budget would. config[0] bits 3-4 still scale it back up 64x
 * for a caller who wants the rest, at which point the arena refusals return. */
#define DSL_STEPS 1024u

#include "dsl.h"

#include "zlib.h"

/* READ-ONLY, FOR dsl_serialize AND NOTHING ELSE: the layouts of deflate_state
 * and inflate_state, from the pinned tree's own private headers (build.sh puts
 * ext/<t>/src on the DSL include path, so these are the headers the archive
 * was compiled from, not a copy). zlib has no getter for the compressor's
 * buffered state -- deflatePending gives a count, deflateGetDictionary the
 * window, and nothing at all exposes the symbol buffer, the bit accumulator or
 * the block-start position -- so a serializer that wants to see "input taken,
 * nothing emitted" has to read the struct. Every field the serializer reads is
 * named there with the line in deflate.c/inflate.c/trees.c that writes it at
 * Init/Reset time; no pointer is ever sunk, and no field that the library
 * writes only once the stream reaches the code that uses it.
 *
 * inftrees.h (which inflate.h needs before it, as inflate.c includes them)
 * typedefs `code`, so no local in this file may be called that. */
#include "deflate.h"
#include "inftrees.h"
#include "inflate.h"

/* ---------------------------------------------------------------- handles --
 *
 * Numbered so that DESCENDING order is a safe teardown order (see
 * DSL_KIND_MAX). Nothing here borrows anything else across a handle boundary:
 * the buffers are plain arena bytes, and the two things a live z_stream DOES
 * point at with a lifetime longer than one operation -- a gz_header handed to
 * deflateSetHeader/inflateGetHeader, and the scratch buffers next_in/next_out
 * were last set to -- are arena allocations, and the arena is released AFTER
 * dsl_end(), which the VM calls after every handle is already gone. So a
 * mid-run dsl_hput that destroys a stream cannot strand a pointer, and a
 * mid-run dsl_hput that destroys a buffer cannot strand a stream.
 *
 * That is the whole reason no gz_header is a handle. It is the same decision
 * the brotli driver makes for prepared dictionaries, reached from the other
 * direction: brotli has to keep them in a fixed array because they need an
 * explicit destructor; a gz_header needs none, so the arena alone is enough. */
#define K_RAW  1   /* uncompressed-ish bytes; n = length. Input to the encoders. */
#define K_ZBUF 2   /* a (possibly truncated) deflate/zlib/gzip stream; n = length. */
#define K_DEF  3   /* z_stream* initialised by deflateInit2_; n = windowBits + 64 */
#define K_INF  4   /* z_stream* initialised by inflateInit2_; n = windowBits + 64 */

/* windowBits is stashed in the handle's `n` because two operations need to know
 * the WRAPPER a stream was built with, and zlib exposes no getter for it:
 * op_def_header and op_inf_header are only legal on a gzip stream (deflate.c:
 * `strm->state->wrap != 2` -> Z_STREAM_ERROR). The bias keeps `n` a plain
 * size_t for the raw-deflate case, where windowBits is negative. */
#define WB_BIAS  64
#define WB_OF(n) ((int)(long)((n) & 0xffu) - WB_BIAS)

/* Bit 8 of a K_DEF handle's `n`: deflate() has been driven on this stream
 * since it was created or last reset.
 *
 * It is here because deflateSetHeader has a DOCUMENTED PRECONDITION and
 * violating it is a heap overflow the DRIVER would have written. zlib.h:
 * "deflateSetHeader() may be called after deflateInit2() or deflateReset()
 * and before the first call of deflate()." deflateSetHeader itself checks
 * nothing but the wrapper (`deflateStateCheck(strm) || wrap != 2`), it just
 * stores the pointer -- and deflate.c's gzip header writer keeps a byte index
 * INTO the previous header across a suspension:
 *
 *     case EXTRA_STATE:  left = (s->gzhead->extra_len & 0xffff) - s->gzindex;
 *     case NAME_STATE:   val = s->gzhead->name[s->gzindex++];
 *
 * A gzip stream whose header write is suspended mid-field (deflate() with
 * avail_out = 0 and a header long enough to fill pending_buf, which is
 * lit_bufsize * 4 = 512 bytes at memLevel 1) holds gzindex > 0. Swap gzhead
 * for a shorter one at that point and `left` underflows to ~2^32 -- a zmemcpy
 * of four gigabytes out of a 256-byte arena block -- or the NAME loop runs off
 * the end of the new string looking for a NUL. Both are ASan reports about
 * OUR bug, refuting T2 on an input the probes do not happen to reach.
 *
 * So op_def_header brings a used gzip stream back to GZIP_STATE with
 * deflateReset first (which is exactly the state zlib.h names, and which
 * deflate.c re-zeroes gzindex from), rather than skipping: the header writer
 * stays reachable and the precondition holds at every point of the input
 * space. deflateCopy inherits the bit with the rest of the state, because the
 * copy inherits status and gzindex too. */
#define DEF_USED 0x100u

/* ------------------------------------------------------------- the clamps --
 *
 * ALLOCATION (dsl.h rule 1). A deflate state at the maximum documented
 * settings -- windowBits 15, memLevel 9 -- allocates 2*w_size (window) +
 * 2*w_size (prev) + 2*hash_size (head) + lit_bufsize*LIT_BUFS (pending), which
 * for those settings is 64 + 64 + 128 + 160 = 416 KiB. The handle table holds
 * 16 slots, so the worst case a program can build is 16 live deflate states,
 * about 6.6 MiB, plus 32 KiB of window per live inflate state. That is far
 * below either role's allocation budget, which is the property rule 1 asks
 * for, so the full documented ranges are kept: nothing here narrows level,
 * memLevel, strategy or windowBits below what zlib.h documents. The one thing
 * that IS excluded is a program-supplied buffer larger than DSL_BUF_MAX, which
 * dsl_bounded enforces for us.
 *
 * RUNTIME. deflateTune is the exception and it is a genuine hazard:
 * deflate.c's implementation is six lines with NO validation at all --
 *
 *     s->good_match = (uInt)good_length;  s->max_lazy_match = (uInt)max_lazy;
 *     s->nice_match = nice_length;        s->max_chain_length = (uInt)max_chain;
 *
 * -- so a 32-bit max_chain from the program would make longest_match() walk a
 * four-billion-link hash chain on every position of every deflate() call, and
 * the binary would never finish under qemu. TUNE_LEN_MAX bounds the three
 * length knobs at MAX_MATCH (258, the largest match zlib can emit, so nothing
 * is lost; they are drawn with dsl_bounded rather than dsl_choice because
 * dsl_choice reads a single byte and could not express 258) and TUNE_CHAIN_MAX
 * bounds the chain at 128 (zlib's own level-9 setting is 4096). What that costs: the deepest chain walks, i.e. the slowest
 * and most thorough match searches, are not reached through deflateTune. They
 * are still reached through level 9 itself, which sets max_chain_length = 4096
 * from configuration_table and which op_def_new drives unclamped -- because
 * that is bounded by the 8 KiB input cap rather than by a program-chosen
 * number.
 *
 * EXPANSION. inflateBack has no output bound of its own: it writes through the
 * caller's out() callback until the stream ends. A 40-byte raw deflate stream
 * can decode to megabytes, so ib_out stops the decode by returning non-zero
 * (documented: inflateBack then returns Z_BUF_ERROR) once IB_OUT_MAX bytes
 * have been produced. inflate() itself needs no such bound: it is limited by
 * avail_out, which is a dsl_bounded value. */
#define TUNE_LEN_MAX    258u
#define TUNE_CHAIN_MAX  128u
#define IB_OUT_MAX      (256UL * 1024UL)

/* Scratch, allocated ONCE per execution in dsl_begin and reused by every
 * operation, rather than a fresh buffer per operation.
 *
 * Measured against the arena, not chosen for tidiness: a per-operation output
 * buffer of up to 16 KiB would eat DSL_LIVE_MAX in about 250 steps and leave
 * the rest of the budget returning DSL_SKIP, since nothing frees an arena
 * block before the end of the execution. Reusing one buffer means the only
 * growing allocations are the round-trip carriers, which are the ones worth
 * spending the budget on.
 *
 * The consequence, and it is intentional: a z_stream whose next_in/next_out
 * still point into this scratch from a previous operation will, on its next
 * call, see whatever a later operation wrote there. That is deterministic (the
 * scratch is only ever written by dsl_fill, memcpy from the program, or zlib
 * itself) and it is always in-bounds, so it is a different call sequence
 * rather than a bug -- and every operation below sets next_in/avail_in and
 * next_out/avail_out itself before calling zlib, so no zlib call actually
 * depends on a stale pointer.
 *
 * SC_DICT IS 32 KiB AND THAT SIZE IS LOAD-BEARING. deflateGetDictionary
 * copies min(strstart + lookahead, w_size) bytes into the caller's buffer and
 * takes no capacity argument:
 *
 *     len = s->strstart + s->lookahead;
 *     if (len > s->w_size) len = s->w_size;
 *     if (dictionary != Z_NULL && len) zmemcpy(dictionary, ..., len);
 *
 * so a buffer smaller than the stream's w_size is a heap overflow the DRIVER
 * wrote -- ASan would report it and T2 would be false for our bug. 32768 is
 * 1 << 15, the largest w_size zlib supports, so it is large enough for every
 * stream any operation here can create. inflateGetDictionary has the same
 * shape (it copies state->whave <= 1 << 15 bytes) and uses the same buffer.
 * SC_WIN is 32 KiB for the same reason: inflateBackInit_ is documented to
 * require a caller-supplied window of 1 << windowBits bytes, and op_inf_back
 * varies windowBits over 8..15, so one buffer at the largest of those sizes
 * serves every case (a window LARGER than the stream needs is harmless -- zlib
 * only ever indexes it modulo its own wsize). */
#define SC_IN    8192u
#define SC_OUT   16384u
#define SC_DICT  32768u
#define SC_WIN   32768u
#define KEEP_MAX 8192u

static unsigned char *sc_in, *sc_out, *sc_dict, *sc_win;

/* The most recently requested inflate gzip header, so that op_inf_push can
 * report what inflate() actually WROTE into it -- op_inf_header runs before
 * any inflate() call and can only report that the request was accepted.
 *
 * Reset in dsl_begin, which is required rather than tidy: these are arena
 * pointers, the arena is released at the end of every execution, and a static
 * that survived a repeat would point into freed memory. */
typedef struct {
  gz_header *h;
  unsigned char *extra, *name, *comment;
  unsigned emax, nmax, cmax;
} ihdr_rec;
static ihdr_rec ihdr;

/* ---------------------------------------------------- fault injection ------
 *
 * zlib's alloc_func takes a PRODUCT (items, size), which faultalloc.h's header
 * calls out as the easiest route to a size near SIZE_MAX; the overflow guard
 * lives in fa_malloc, and the product is formed in size_t here so the
 * multiplication itself cannot wrap (both factors are uInt, so the product
 * fits a 64-bit size_t). The division check is kept anyway: uInt is a typedef
 * a future zconf.h could widen, and an arithmetic guard that is correct only
 * because of a typedef elsewhere is the shape faultalloc.h warns about. */
static int fa_ready;
static void dsl_alloc_install(void) { fa_ready = 1; }

static void *fa_zalloc_hook(void *opaque, uInt items, uInt size) {
  size_t n;
  (void)opaque;
  n = (size_t)items * (size_t)size;
  if (size != 0 && n / (size_t)size != (size_t)items) return NULL;
  return fa_malloc(n);
}

static void fa_zfree_hook(void *opaque, void *address) {
  (void)opaque;
  /* zlib's ZFREE is never called on a null pointer by 1.3.1, but fa_free
   * tolerates it and the check is here so that a future faultalloc that does
   * not would crash in this file rather than inside zlib. */
  if (address) fa_free(address);
}

static alloc_func alloc_fn(void) { return fa_ready ? fa_zalloc_hook : (alloc_func)Z_NULL; }
static free_func  free_fn(void)  { return fa_ready ? fa_zfree_hook  : (free_func)Z_NULL; }

/* ------------------------------------------------------------------ ops ---- */

#define OP_INFO         0
#define OP_COMPRESS     1
#define OP_UNCOMPRESS   2
#define OP_DEF_NEW      3
#define OP_DEF_PARAMS   4
#define OP_DEF_TUNE     5
#define OP_DEF_SETDICT  6
#define OP_DEF_GETDICT  7
#define OP_DEF_HEADER   8
#define OP_DEF_PRIME    9
#define OP_DEF_PUSH    10
#define OP_DEF_QUERY   11
#define OP_DEF_COPY    12
#define OP_DEF_RESET   13
#define OP_INF_NEW     14
#define OP_INF_RESET   15
#define OP_INF_SETDICT 16
#define OP_INF_GETDICT 17
#define OP_INF_HEADER  18
#define OP_INF_PRIME   19
#define OP_INF_PUSH    20
#define OP_INF_QUERY   21
#define OP_INF_SYNC    22
#define OP_INF_COPY    23
#define OP_INF_BACK    24
#define OP_END         25
/* Appended 2026-09-02; 0..25 are unchanged so prior witnesses stay comparable. */
#define OP_CHECKSUM    26
#define OP_MUTATE      27
#define OP_COUNT       28

static unsigned dsl_ops(void) { return OP_COUNT; }

static const char *dsl_op_name(unsigned op) {
  switch (op) {
    case OP_INFO:        return "info";
    case OP_COMPRESS:    return "compress";
    case OP_UNCOMPRESS:  return "uncompress";
    case OP_DEF_NEW:     return "def_new";
    case OP_DEF_PARAMS:  return "def_params";
    case OP_DEF_TUNE:    return "def_tune";
    case OP_DEF_SETDICT: return "def_setdict";
    case OP_DEF_GETDICT: return "def_getdict";
    case OP_DEF_HEADER:  return "def_header";
    case OP_DEF_PRIME:   return "def_prime";
    case OP_DEF_PUSH:    return "def_push";
    case OP_DEF_QUERY:   return "def_query";
    case OP_DEF_COPY:    return "def_copy";
    case OP_DEF_RESET:   return "def_reset";
    case OP_INF_NEW:     return "inf_new";
    case OP_INF_RESET:   return "inf_reset";
    case OP_INF_SETDICT: return "inf_setdict";
    case OP_INF_GETDICT: return "inf_getdict";
    case OP_INF_HEADER:  return "inf_header";
    case OP_INF_PRIME:   return "inf_prime";
    case OP_INF_PUSH:    return "inf_push";
    case OP_INF_QUERY:   return "inf_query";
    case OP_INF_SYNC:    return "inf_sync";
    case OP_INF_COPY:    return "inf_copy";
    case OP_INF_BACK:    return "inf_back";
    case OP_END:         return "end";
    case OP_CHECKSUM:    return "checksum";
    case OP_MUTATE:      return "mutate";
    default:             return "?";
  }
}

static void dsl_kill(dsl_vm *V, int kind, void *p, size_t n) {
  (void)V; (void)n;
  switch (kind) {
    /* The z_stream struct itself is an arena block, so only zlib's internal
     * state is released here; the struct is reclaimed with the arena. Neither
     * deflateEnd nor inflateEnd can fail destructively -- a stream freed
     * prematurely gives Z_DATA_ERROR and is still fully released -- and
     * dsl_kill must not emit, so the status is dropped. */
    case K_DEF: (void)deflateEnd((z_streamp)p); break;
    case K_INF: (void)inflateEnd((z_streamp)p); break;
    case K_RAW: case K_ZBUF: break;   /* the arena owns the bytes */
    default: break;
  }
}

static void dsl_begin(dsl_vm *V) {
  memset(&ihdr, 0, sizeof ihdr);
  sc_in   = (unsigned char *)dsl_zalloc(V, SC_IN);
  sc_out  = (unsigned char *)dsl_zalloc(V, SC_OUT);
  sc_dict = (unsigned char *)dsl_zalloc(V, SC_DICT);
  sc_win  = (unsigned char *)dsl_zalloc(V, SC_WIN);
}

static void dsl_end(dsl_vm *V) {
  (void)V;
  /* Nothing outside the handle table and the arena; the arena is released by
   * the VM immediately after this returns, which is what makes it safe for a
   * gz_header to live there. */
  sc_in = sc_out = sc_dict = sc_win = NULL;
  memset(&ihdr, 0, sizeof ihdr);
}

/* -------------------------------------------------------------- helpers ---- */

/* strm->msg is one of zutil.c's ten static strings (deflateResetKeep's own
 * comment: "use zfree if we ever allocate msg dynamically"), so its CONTENTS
 * are a legitimate observable and its ADDRESS is not. Reported as a length and
 * a digest, never as a pointer -- dsl.h rule 3. */
static void note_msg(dsl_vm *V, z_streamp s) {
  if (s->msg != Z_NULL) dsl_report(V, "  msg", 0, s->msg, strlen(s->msg));
  else dsl_note(V, "  msg none\n");
}

/* The library-computed counters after a streaming call. Every field here is
 * zlib's own arithmetic over the data -- total_in/total_out are byte counts,
 * adler is the running Adler-32 or CRC-32, data_type is the block type zlib
 * inferred -- so none of them can carry an allocator-chosen value. */
static void note_counters(dsl_vm *V, z_streamp s) {
  dsl_note(V, "  tin=%lu tout=%lu adler=%08lx dtype=%d\n",
           (unsigned long)s->total_in, (unsigned long)s->total_out,
           (unsigned long)s->adler, s->data_type);
}

/* Bytes for a (ptr, len) argument, staged into writable scratch.
 *
 * Three sources, chosen by the program: a live handle of `kind` (which is the
 * round-trip edge -- K_ZBUF for the decoders, K_RAW for the encoders), a
 * literal slice of the program, or a deterministic dsl_fill. Copied rather
 * than pointed at, for two reasons. zlib's z_stream declares next_in as
 * `z_const Bytef *`, and without -DZLIB_CONST that is a NON-const pointer, so
 * handing it dsl_take's pointer into the input buffer would mean casting away
 * const on memory the driver owns read-only. And zlib does write through
 * next_in on one path -- deflateSetDictionary borrows strm->next_in while it
 * fills the window -- so "zlib never writes there" is not a property to rely
 * on. `kind` may be 0 for "no handle source". */
static size_t stage_bytes(dsl_vm *V, unsigned char *dst, size_t cap, int kind) {
  unsigned pick = dsl_choice(V, 3);
  if (pick == 0 && kind != 0) {
    size_t hn = 0;
    void *h = dsl_hget(V, kind, &hn);
    if (h != NULL) {
      if (hn > cap) hn = cap;
      if (hn) memcpy(dst, h, hn);
      return hn;
    }
  }
  if (pick == 1) {
    size_t n = 0;
    const unsigned char *lit = dsl_take(V, cap, &n);
    if (n) memcpy(dst, lit, n);
    return n;
  }
  {
    size_t n = dsl_bounded(V, cap);
    if (n) dsl_fill(V, dst, n);
    return n;
  }
}

/* Retain a library-produced buffer as a handle, which is what makes the round
 * trip possible. Bounded at KEEP_MAX so one operation cannot swallow the
 * arena, and silent on refusal: an arena that says no is a DSL_SKIP condition
 * for the operation that needed it, not for this one, which has already
 * called zlib successfully. */
static void keep(dsl_vm *V, int kind, const void *p, size_t n) {
  void *q;
  if (n == 0) return;
  if (n > KEEP_MAX) n = KEEP_MAX;
  q = dsl_dup(V, p, n, 0);
  if (q != NULL) dsl_hput(V, kind, q, n);
}

/* A fresh, zeroed z_stream in the arena, with the allocator hooks installed.
 * The arena rather than the stack because a handle outlives the operation that
 * created it, and the arena rather than malloc because dsl.h rule 2 allows the
 * driver exactly one allocator. */
static z_streamp new_stream(dsl_vm *V) {
  z_streamp s = (z_streamp)dsl_zalloc(V, sizeof(z_stream));
  if (s == NULL) return NULL;
  s->zalloc = alloc_fn();
  s->zfree = free_fn();
  s->opaque = Z_NULL;
  return s;
}

/* A LIVE STREAM, OR A NEW ONE -- and this is the single most consequential
 * decision in the file, made after a measurement.
 *
 * dsl.h's header records what went wrong with the first brotli driver: on a
 * short payload "the create operations never fired once, because no byte of
 * that payload landed on their opcode at an opcode position", and the VM's
 * wrap rotation was added to fix it. The rotation is necessary and it is not
 * sufficient, because it can only make DIFFERENT bytes of the payload be
 * opcodes -- it cannot invent a byte the payload does not contain.
 *
 * Measured here, on probe.bin, the 13-byte input every gate in this repository
 * runs: with 26 operations its bytes take only ten distinct values modulo 26,
 * and neither OP_DEF_NEW (3) nor OP_INF_NEW (14) is among them. The first
 * build of this driver therefore executed 1024 steps of which 914 were
 * DSL_SKIP and 110 were inflateBack -- the one operation that needs no handle
 * -- and never called deflateInit2_ or inflateInit2_ at all. Renumbering the
 * table so that probe.bin's residues happen to land on the creators would fix
 * that input and nothing else, and would hide the problem for the next short
 * payload.
 *
 * So an operation that needs a stream and finds none CREATES one, with
 * program-chosen but always VALID parameters, and then does its own work. The
 * cost is stated plainly: one step can be two library calls, and DSL_SKIP for
 * these operations now means only "the arena refused or zlib returned
 * Z_MEM_ERROR" rather than "no handle existed". OP_DEF_NEW and OP_INF_NEW keep
 * their own operations because they are the only ones that drive INVALID
 * parameters -- level -2, memLevel 0 and 10, strategy 5 -- and so the only
 * ones that reach deflateInit2_'s validation branches. OP_END deliberately
 * does NOT create: destroying a stream that this step just built would
 * exercise nothing that OP_DEF_NEW's own teardown does not.
 */
static z_streamp want_def(dsl_vm *V, size_t *hn) {
  size_t n = 0;
  z_streamp s = (z_streamp)dsl_hget(V, K_DEF, &n);
  int level, base, ml, st, wb, rc;
  unsigned wrap;
  if (s != NULL) { if (hn) *hn = n; return s; }
  s = new_stream(V);
  if (s == NULL) return NULL;
  level = -1 + (int)dsl_choice(V, 11);          /* -1..9, all valid */
  base = 8 + (int)dsl_choice(V, 8);             /* 8..15 */
  wrap = dsl_choice(V, 3);
  /* "Always VALID" was false for one cell of this table until 2026-09-03:
   * deflateInit2_ rejects windowBits 8 unless the wrapper is zlib
   * (deflate.c: `(windowBits == 8 && wrap != 1)` -> Z_STREAM_ERROR; the
   * 256-byte window is only promoted to 9 for the zlib wrapper), so base 8
   * with the raw or gzip wrap returned NULL and the op was DSL_SKIP -- which
   * is how op_witness.py found OP_DEF_HEADER `needs-prereq` off the bytes
   * `08 08`. Promoted to 9 here, which is what deflate.c itself does for the
   * zlib case; OP_DEF_NEW still drives the rejected cell on purpose. */
  if (base == 8 && wrap != 0) base = 9;
  wb = wrap == 0 ? base : (wrap == 1 ? -base : base + 16);
  ml = 1 + (int)dsl_choice(V, 9);               /* 1..9, all valid */
  st = (int)dsl_choice(V, 5);                   /* 0..4, all valid */
  rc = deflateInit2(s, level, Z_DEFLATED, wb, ml, st);
  /* Noted since 2026-09-03: an implicit creation is a library call whose
   * parameters shape everything the stream does afterwards, and until now
   * nothing in the trace recorded it (the serializer saw w_bits/level/strategy;
   * the digest did not). rc is Z_MEM_ERROR only under fault injection. */
  dsl_note(V, "want_def lvl=%d wb=%d ml=%d st=%d rc=%d\n", level, wb, ml, st, rc);
  if (rc != Z_OK) return NULL;
  dsl_hput(V, K_DEF, (void *)s, (size_t)(wb + WB_BIAS));
  if (hn) *hn = (size_t)(wb + WB_BIAS);
  return s;
}

static z_streamp want_inf(dsl_vm *V, size_t *hn) {
  size_t n = 0;
  z_streamp s = (z_streamp)dsl_hget(V, K_INF, &n);
  int base, wb, rc;
  unsigned mode;
  if (s != NULL) { if (hn) *hn = n; return s; }
  s = new_stream(V);
  if (s == NULL) return NULL;
  base = 8 + (int)dsl_choice(V, 8);
  mode = dsl_choice(V, 5);
  wb = mode == 0 ? base : mode == 1 ? -base
     : mode == 2 ? base + 16 : mode == 3 ? base + 32 : 0;
  rc = inflateInit2(s, wb);
  dsl_note(V, "want_inf wb=%d rc=%d\n", wb, rc);
  if (rc != Z_OK) return NULL;
  dsl_hput(V, K_INF, (void *)s, (size_t)(wb + WB_BIAS));
  if (hn) *hn = (size_t)(wb + WB_BIAS);
  return s;
}

/* Report a gzip header zlib has FILLED IN (inflateGetHeader's output side).
 * done/text/time/xflags/os/extra_len/hcrc are all decoded from the stream's
 * own bytes -- head->time is the gzip MTIME field, not a clock read -- and the
 * three variable-length fields are reported as digests of the driver's own
 * zero-padded buffers rather than through head->extra/name/comment, which
 * inflate sets to Z_NULL when the field is absent.
 *
 * It reports the MOST RECENTLY REQUESTED header record, which need not belong
 * to the stream op_inf_push just drove: a program can build several inflate
 * streams and ask for a header on one of them. That is loose on purpose --
 * tracking a header per stream would need a side table keyed by stream
 * pointer, and the extra bookkeeping would buy nothing, because the reported
 * value is deterministic either way and the operation's job is to make
 * inflate.c's header reader run rather than to attribute its output. */
static void report_ihdr(dsl_vm *V, const char *what) {
  if (ihdr.h == NULL) return;
  dsl_note(V, "  %s done=%d text=%d time=%lu xf=%d os=%d xlen=%u hcrc=%d\n",
           what, ihdr.h->done, ihdr.h->text, (unsigned long)ihdr.h->time,
           ihdr.h->xflags, ihdr.h->os, (unsigned)ihdr.h->extra_len,
           ihdr.h->hcrc);
  if (ihdr.extra) dsl_report(V, "  hdr_extra", 0, ihdr.extra, ihdr.emax);
  if (ihdr.name) dsl_report(V, "  hdr_name", 0, ihdr.name, ihdr.nmax);
  if (ihdr.comment) dsl_report(V, "  hdr_comm", 0, ihdr.comment, ihdr.cmax);
}

/* ------------------------------------------------------- inflateBack I/O ---
 *
 * infback.c's callback protocol, which nothing but zlib's own examples drives.
 * in() serves the staged input exactly once and then reports exhaustion (which
 * inflateBack turns into Z_BUF_ERROR, documented); out() folds the produced
 * bytes into a digest instead of storing them, so the operation's memory cost
 * is a constant however far the stream expands, and returns non-zero past
 * IB_OUT_MAX to stop a small stream from decoding to megabytes under qemu.
 *
 * Neither callback touches the window buffer, which the documentation forbids
 * ("Neither in() nor out() are permitted to change the contents of the window
 * provided to inflateBackInit()"). */
typedef struct {
  unsigned char *in;
  unsigned in_n;
  int served;
  unsigned long total;
  unsigned long calls;
  int stopped;
  uint64_t h;
} ib_ctx;

static unsigned ib_in(void *desc, z_const unsigned char **buf) {
  ib_ctx *c = (ib_ctx *)desc;
  if (c->served || c->in_n == 0) return 0;
  c->served = 1;
  *buf = c->in;
  return c->in_n;
}

static int ib_out(void *desc, unsigned char *buf, unsigned len) {
  ib_ctx *c = (ib_ctx *)desc;
  unsigned i;
  c->calls++;
  for (i = 0; i < len; i++) { c->h ^= (uint64_t)buf[i]; c->h *= 1099511628211ULL; }
  c->total += (unsigned long)len;
  if (c->total > IB_OUT_MAX) { c->stopped = 1; return 1; }
  return 0;
}

/* ---------------------------------------------------------------- the ops -- */

/* madler/zlib #1401 */
__attribute__((noinline)) static int dsl_resetkeep_guarded(z_streamp s, int full) {
  if (!full && ((deflate_state *)s->state)->lookahead != 0 && ((deflate_state *)s->state)->lit_bufsize != 0) exit(252);
  return deflateResetKeep(s);
}

static int dsl_step(dsl_vm *V, unsigned op) {
  switch (op) {

  /* Version, compile-time configuration, the error-string table and the CRC
   * table. All four are exported, none is reachable from the harness.
   *
   * zlibCompileFlags encodes sizeof(uInt)/sizeof(uLong)/sizeof(voidpf)/
   * sizeof(z_off_t) and the build's option macros. Those are properties of the
   * TOOLCHAIN and the headers, which are identical across the four flavours --
   * -fsanitize=address does not change a type's size -- so it is a stable
   * observable rather than an address in disguise.
   *
   * get_crc_table returns a pointer into zlib's own static table. The POINTER
   * is not reported; the first 256 entries' VALUES are, folded arithmetically
   * rather than through memcpy so the digest does not depend on the host's
   * byte order. */
  case OP_INFO: {
    const char *ver = zlibVersion();
    int ecode = -8 + (int)dsl_choice(V, 12);  /* -8..3: two past each end of
                                               * zutil.h's ERR_MSG range, so
                                               * the clamped branch runs too
                                               * (not `code`: inftrees.h) */
    const char *emsg = zError(ecode);
    uLong flags = zlibCompileFlags();
    uLong slen = (uLong)(dsl_u32(V) & 0xFFFFFu);
    const z_crc_t FAR *tab = get_crc_table();
    uint64_t h = 1469598103934665603ULL;
    int i;
    for (i = 0; i < 256; i++) { h ^= (uint64_t)tab[i]; h *= 1099511628211ULL; }
    dsl_note(V, "info flags=%08lx cbound=%lu crctab=%016llx\n",
             (unsigned long)flags, (unsigned long)compressBound(slen),
             (unsigned long long)h);
    if (ver != NULL) dsl_report(V, "  version", 0, ver, strlen(ver));
    if (emsg != NULL) dsl_report(V, "  zerror", ecode, emsg, strlen(emsg));
    return DSL_OK;
  }

  /* compress2/compress -- uncompr.c's and compress.c's one-shot paths, and the
   * producer that makes the whole round trip work. The output goes into a
   * K_ZBUF handle, which is where op_uncompress, op_inf_push and op_inf_back
   * read from.
   *
   * The destination capacity is program-chosen and deliberately allowed to be
   * SMALLER than compressBound(), because compress2's Z_BUF_ERROR branch is
   * only reachable that way and a driver that always sized the buffer
   * correctly would never see it. */
  case OP_COMPRESS: {
    size_t in_n;
    uLongf dlen;
    uLong bound;
    int level, rc;
    if (sc_in == NULL || sc_out == NULL) return DSL_SKIP;
    in_n = stage_bytes(V, sc_in, SC_IN, K_RAW);
    bound = compressBound((uLong)in_n);
    if (bound > (uLong)SC_OUT) bound = (uLong)SC_OUT;
    /* Either exactly the bound (the success case) or a program-chosen smaller
     * capacity (the Z_BUF_ERROR case). */
    dlen = dsl_flag(V) ? (uLongf)bound : (uLongf)dsl_bounded(V, SC_OUT);
    level = -1 + (int)dsl_choice(V, 11);      /* -1..9, the documented range */
    if (dsl_flag(V)) {
      rc = compress2(sc_out, &dlen, sc_in, (uLong)in_n, level);
    } else {
      level = Z_DEFAULT_COMPRESSION;          /* what compress() hardwires */
      rc = compress(sc_out, &dlen, sc_in, (uLong)in_n);
    }
    dsl_note(V, "compress lvl=%d in=%lu\n", level, (unsigned long)in_n);
    if (rc == Z_OK && dlen <= (uLongf)SC_OUT) {
      dsl_report(V, "  out", rc, sc_out, (size_t)dlen);
      keep(V, K_ZBUF, sc_out, (size_t)dlen);
    } else {
      dsl_note(V, "  rc=%d dlen=%lu\n", rc, (unsigned long)dlen);
    }
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* uncompress2/uncompress -- the other half of the one-shot round trip.
   * uncompress2 additionally reports how much of the source it CONSUMED, which
   * is an observable uncompress() does not have and which the harness reaches
   * neither way. Successful output becomes a K_RAW handle, so decompressed
   * data flows back into the compressor. */
  case OP_UNCOMPRESS: {
    size_t in_n;
    uLongf dlen;
    uLong slen;
    int rc, two;
    if (sc_in == NULL || sc_out == NULL) return DSL_SKIP;
    in_n = stage_bytes(V, sc_in, SC_IN, K_ZBUF);
    dlen = (uLongf)dsl_bounded(V, SC_OUT);
    slen = (uLong)in_n;
    two = dsl_flag(V);
    if (two) rc = uncompress2(sc_out, &dlen, sc_in, &slen);
    else     rc = uncompress(sc_out, &dlen, sc_in, (uLong)in_n);
    dsl_note(V, "uncompress two=%d in=%lu used=%lu rc=%d\n",
             two, (unsigned long)in_n, (unsigned long)slen, rc);
    if (rc == Z_OK && dlen <= (uLongf)SC_OUT) {
      dsl_report(V, "  out", rc, sc_out, (size_t)dlen);
      keep(V, K_RAW, sc_out, (size_t)dlen);
    }
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflateInit2_ across the whole documented parameter space, plus
   * deflateInit_'s defaults.
   *
   * The ranges deliberately extend ONE STEP PAST each documented end (level
   * -2, memLevel 0 and 10, strategy 5): zlib.h documents deflateInit2 as
   * returning Z_STREAM_ERROR "if any parameter is invalid", so those are
   * documented behaviour and a validation branch worth reaching, not a
   * precondition violation. windowBits covers all three wrappers -- 8..15
   * zlib, -8..-15 raw, 24..31 gzip -- including 8, which deflate.c silently
   * promotes to 9. */
  case OP_DEF_NEW: {
    int level = -2 + (int)dsl_choice(V, 12);      /* -2..9 */
    int memLevel = (int)dsl_choice(V, 11);        /* 0..10 */
    int strategy = (int)dsl_choice(V, 6);         /* 0..5 */
    int base = 8 + (int)dsl_choice(V, 8);         /* 8..15 */
    unsigned wrap = dsl_choice(V, 3);
    int wb = wrap == 0 ? base : (wrap == 1 ? -base : base + 16);
    int plain = dsl_flag(V);
    z_streamp s = new_stream(V);
    int rc;
    if (s == NULL) return DSL_SKIP;
    if (plain) {
      wb = 15;
      rc = deflateInit(s, level);
    } else {
      rc = deflateInit2(s, level, Z_DEFLATED, wb, memLevel, strategy);
    }
    dsl_note(V, "def_new lvl=%d wb=%d ml=%d st=%d plain=%d rc=%d\n",
             level, wb, memLevel, strategy, plain, rc);
    if (rc != Z_OK) { note_msg(V, s); return DSL_LIBERR; }
    dsl_hput(V, K_DEF, (void *)s, (size_t)(wb + WB_BIAS));
    return DSL_OK;
  }

  /* deflateParams: change level and/or strategy MID-STREAM. It is not a
   * setter -- it flushes the current block with deflate(strm, Z_BLOCK) and can
   * switch deflate_stored/deflate_fast/deflate_slow under a live state, which
   * is the most intricate transition in deflate.c and is unreachable from any
   * single-call harness.
   *
   * It needs output room, because the internal flush writes through
   * strm->next_out; a program-chosen avail_out (which may be 0) reaches both
   * the success path and the Z_BUF_ERROR path zlib.h documents. next_in is
   * cleared because deflateParams refuses when input is still pending. */
  case OP_DEF_PARAMS: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    int level = -1 + (int)dsl_choice(V, 11);
    int strategy = (int)dsl_choice(V, 5);
    unsigned pending = 0;
    uInt out_cap;
    int bits = 0, rc;
    if (s == NULL || sc_out == NULL) return DSL_SKIP;
    /* deflateParams FLUSHES -- it calls deflate(strm, Z_BLOCK) internally --
     * so it advances the gzip header writer exactly as op_def_push does, and
     * the stream is "used" from here on (see DEF_USED). */
    (void)dsl_hset(V, K_DEF, (void *)s, (void *)s, hn | DEF_USED);
    s->next_in = Z_NULL;
    s->avail_in = 0;
    s->next_out = sc_out;
    out_cap = (uInt)dsl_bounded(V, SC_OUT);
    s->avail_out = out_cap;
    rc = deflateParams(s, level, strategy);
    (void)deflatePending(s, &pending, &bits);
    dsl_note(V, "def_params lvl=%d st=%d rc=%d pend=%u bits=%d\n",
             level, strategy, rc, pending, bits);
    /* Against the capacity this operation GAVE it, not against SC_OUT: the
     * capacity is a dsl_bounded value and may be far below SC_OUT, and
     * SC_OUT - avail_out would then digest scratch bytes the flush never
     * wrote. Deterministic either way, but it would not be a report about what
     * deflateParams produced. */
    if (s->avail_out < out_cap)
      dsl_report(V, "  out", rc, sc_out, (size_t)(out_cap - s->avail_out));
    note_msg(V, s);
    s->next_out = Z_NULL;
    s->avail_out = 0;
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflateTune. Clamped hard -- see TUNE_CHAIN_MAX above; the unclamped
   * function would let one program byte make longest_match walk a chain of
   * 2^32 links. */
  case OP_DEF_TUNE: {
    z_streamp s = (z_streamp)want_def(V, NULL);
    /* dsl_bounded, not dsl_choice: dsl_choice reads ONE program byte, so
     * dsl_choice(V, 259) would silently never return 256, 257 or 258 and the
     * range in the comment would be a lie. dsl_bounded reads two bytes and
     * covers [0, TUNE_LEN_MAX] exactly. */
    int good = (int)dsl_bounded(V, TUNE_LEN_MAX);
    int lazy = (int)dsl_bounded(V, TUNE_LEN_MAX);
    int nice = (int)dsl_bounded(V, TUNE_LEN_MAX);
    int chain = 1 + (int)dsl_choice(V, TUNE_CHAIN_MAX);
    int rc;
    if (s == NULL) return DSL_SKIP;
    rc = deflateTune(s, good, lazy, nice, chain);
    dsl_note(V, "def_tune g=%d l=%d n=%d c=%d rc=%d\n", good, lazy, nice, chain, rc);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflateSetDictionary. The dictionary is staged from a K_RAW handle when
   * one exists, so a dictionary can be data the stream will later actually see
   * -- which is the case where the match-finder finds the dictionary's entries
   * and the "dictionary would fill the window, use the tail" branch matters.
   * Sizes up to SC_DICT reach that branch for the small window sizes. */
  case OP_DEF_SETDICT: {
    z_streamp s = (z_streamp)want_def(V, NULL);
    size_t n;
    int rc;
    if (s == NULL || sc_dict == NULL) return DSL_SKIP;
    n = stage_bytes(V, sc_dict, SC_DICT, K_RAW);
    rc = deflateSetDictionary(s, sc_dict, (uInt)n);
    dsl_note(V, "def_setdict n=%lu rc=%d adler=%08lx\n",
             (unsigned long)n, rc, (unsigned long)s->adler);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflateGetDictionary -- the window's current contents, which is zlib's
   * only window accessor and is exported precisely so a caller can checkpoint
   * a stream. The buffer MUST be w_size bytes; see the SC_DICT comment. Only
   * the reported length is folded, not the whole buffer, so the digest is a
   * function of what zlib wrote rather than of the scratch's history. */
  case OP_DEF_GETDICT: {
    z_streamp s = (z_streamp)want_def(V, NULL);
    uInt dlen = 0;
    int rc;
    if (s == NULL || sc_dict == NULL) return DSL_SKIP;
    rc = deflateGetDictionary(s, sc_dict, &dlen);
    dsl_note(V, "def_getdict rc=%d n=%u\n", rc, (unsigned)dlen);
    if (rc == Z_OK && dlen <= (uInt)SC_DICT) {
      dsl_report(V, "  dict", rc, sc_dict, (size_t)dlen);
      keep(V, K_RAW, sc_dict, (size_t)dlen);
    }
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflateSetHeader: the gzip header WRITER, several hundred lines of
   * deflate.c that the zlib-wrapped path never enters.
   *
   * THE HEADER AND ITS STRINGS ARE ARENA-ALLOCATED AND THAT IS THE WHOLE
   * LIFETIME ARGUMENT. deflateSetHeader stores the pointer (`strm->state->
   * gzhead = head`) and deflate() reads through it on every later call, so the
   * struct has to outlive the stream. It does: the VM destroys every handle
   * before dsl_end() and releases the arena after it. A gz_header in the
   * handle table would instead be destroyable at any step by dsl_hput picking
   * its slot, and a two-instruction program could then manufacture a
   * use-after-free that ASan reports and that refutes T2 for a bug this file
   * wrote.
   *
   * It is called on non-gzip streams too, deliberately: deflate.c returns
   * Z_STREAM_ERROR when wrap != 2, which is documented behaviour and the only
   * way to reach that check. */
  case OP_DEF_HEADER: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    gz_header *h;
    int rc;
    int rewound = 0;
    if (s == NULL) return DSL_SKIP;
    /* The precondition. WB_OF(hn) > 15 is the gzip wrapper -- the only case in
     * which deflateSetHeader stores the pointer at all -- and DEF_USED says
     * deflate() has already run, so the writer may be suspended inside the old
     * header. See DEF_USED for what swapping it there would cost. */
    if ((hn & DEF_USED) && WB_OF(hn) > 15) {
      if (deflateReset(s) != Z_OK) return DSL_SKIP;
      (void)dsl_hset(V, K_DEF, (void *)s, (void *)s, hn & ~(size_t)DEF_USED);
      rewound = 1;
    }
    h = (gz_header *)dsl_zalloc(V, sizeof *h);
    if (h == NULL) return DSL_SKIP;
    h->text = dsl_flag(V);
    h->time = (uLong)dsl_u32(V);        /* the gzip MTIME field, from the
                                         * program -- never a clock read */
    h->os = (int)dsl_choice(V, 256);
    h->xflags = (int)dsl_choice(V, 256);
    h->hcrc = dsl_flag(V);
    if (dsl_flag(V)) {
      size_t n = 0;
      const unsigned char *lit = dsl_take(V, 256, &n);
      void *copy = dsl_dup(V, lit, n, 0);
      if (copy != NULL) { h->extra = (Bytef *)copy; h->extra_len = (uInt)n; }
    }
    /* name and comment are NUL-terminated by deflate.c's writer contract (it
     * copies bytes until it reads a zero), which is exactly what dsl_cstr
     * produces. An interior NUL simply shortens the field. */
    if (dsl_flag(V)) h->name = (Bytef *)dsl_cstr(V, 128);
    if (dsl_flag(V)) h->comment = (Bytef *)dsl_cstr(V, 128);
    rc = deflateSetHeader(s, h);
    dsl_note(V, "def_header wb=%d xlen=%u name=%d comm=%d hcrc=%d rw=%d rc=%d\n",
             WB_OF(hn), (unsigned)h->extra_len, h->name != Z_NULL,
             h->comment != Z_NULL, h->hcrc, rewound, rc);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflatePrime: insert raw bits ahead of the stream, the hook zip writers
   * use to bit-align a deflate stream. bits runs to 17 so the Z_BUF_ERROR
   * validation branch (`bits < 0 || bits > 16`) is reached.
   *
   * THE PRECONDITION IS THE SAME CLASS AS DEF_USED / op_def_header, and this
   * op forgot it. zlib.h: deflatePrime "must be used before the first deflate()
   * call after a deflateInit2() or deflateReset()". Its capacity guard is
   * meant to fail safe -- deflatePrime returns Z_BUF_ERROR "if there was not
   * enough room in the internal buffer" -- but the guard tests s->pending_out
   * (the read cursor) rather than s->pending (the write cursor), and only
   * deflate() advances pending_out. So on a stream deflate() has driven
   * (DEF_USED), or one that earlier primes have already filled, pending_out
   * stays put while s->pending marches past pending_buf, the guard never
   * fires, and bi_flush's put_byte writes off the end -- a heap overflow the
   * DRIVER would have written (the plain riscv64 build SIGSEGVs on it, asan
   * reports it, refuting T2 about OUR bug). deflateReset brings the stream back
   * to exactly the state zlib.h names -- pending == 0, pending_out at the
   * buffer start -- so a single <=16-bit prime always fits; nothing valid is
   * lost, since a mid-stream prime is not a documented use in the first place. */
  case OP_DEF_PRIME: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    int bits = (int)dsl_choice(V, 18);            /* 0..17 */
    int value = (int)dsl_u16(V);
    unsigned pending = 0;
    int pbits = 0, rc;
    if (s == NULL) return DSL_SKIP;
    (void)deflatePending(s, &pending, &pbits);
    if ((hn & DEF_USED) || pending != 0) {
      if (deflateReset(s) != Z_OK) return DSL_SKIP;
      (void)dsl_hset(V, K_DEF, (void *)s, (void *)s, hn & ~(size_t)DEF_USED);
    }
    pending = 0; pbits = 0;
    rc = deflatePrime(s, bits, value);
    (void)deflatePending(s, &pending, &pbits);
    dsl_note(V, "def_prime bits=%d val=%d rc=%d pend=%u pbits=%d\n",
             bits, value, rc, pending, pbits);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflate() itself: the streaming compressor, in all six flush modes plus
   * one past the end (7 choices, of which Z_TREES = 6 is rejected with
   * Z_STREAM_ERROR by deflate's own `flush > Z_BLOCK` check).
   *
   * Each flush mode is a different path through trees.c -- Z_PARTIAL_FLUSH
   * emits an empty static block, Z_SYNC_FLUSH a stored one, Z_FULL_FLUSH
   * additionally clears the hash, Z_BLOCK ends the block without aligning,
   * Z_FINISH writes the trailer -- and the harness reaches none of them.
   *
   * Whatever deflate emitted becomes a K_ZBUF handle. On Z_FINISH from a fresh
   * stream that is a COMPLETE stream in whichever wrapper the stream was
   * configured with, which is how gzip and raw-deflate streams get into the
   * corpus at all: compress2 only ever produces zlib-wrapped ones. On the
   * other flush modes it is a fragment, which is the input the inflater's
   * truncation and resync paths need. */
  case OP_DEF_PUSH: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    size_t in_n, produced;
    unsigned flush;
    uInt out_cap;
    int rc;
    static const int flushes[7] = {
      Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH,
      Z_FINISH, Z_BLOCK, Z_TREES
    };
    if (s == NULL || sc_in == NULL || sc_out == NULL) return DSL_SKIP;
    in_n = stage_bytes(V, sc_in, SC_IN, K_RAW);
    out_cap = (uInt)dsl_bounded(V, SC_OUT);
    flush = dsl_choice(V, 7);
    s->next_in = sc_in;
    s->avail_in = (uInt)in_n;
    s->next_out = sc_out;
    s->avail_out = out_cap;
    rc = deflate(s, flushes[flush]);
    (void)dsl_hset(V, K_DEF, (void *)s, (void *)s, hn | DEF_USED);
    produced = (size_t)(out_cap - s->avail_out);
    dsl_note(V, "def_push wb=%d flush=%d in=%lu cap=%lu rc=%d left=%lu\n",
             WB_OF(hn), flushes[flush], (unsigned long)in_n,
             (unsigned long)out_cap, rc, (unsigned long)s->avail_in);
    dsl_report(V, dsl_op_name(op), rc, sc_out, produced);
    note_counters(V, s);
    note_msg(V, s);
    keep(V, K_ZBUF, sc_out, produced);
    /* Cleared so that no later operation's zlib call depends on a pointer this
     * one left behind -- see the scratch comment above. */
    s->next_in = Z_NULL; s->avail_in = 0;
    s->next_out = Z_NULL; s->avail_out = 0;
    return (rc == Z_OK || rc == Z_STREAM_END || rc == Z_BUF_ERROR)
             ? (rc == Z_BUF_ERROR ? DSL_LIBERR : DSL_OK) : DSL_LIBERR;
  }

  /* deflateBound + deflatePending + compressBound: the three size/status
   * queries. deflateBound's answer depends on the stream's wrap, windowBits
   * and memLevel, so it is a real function of the state and not a constant. */
  case OP_DEF_QUERY: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    uLong slen = (uLong)(dsl_u32(V) & 0xFFFFFu);
    unsigned pending = 0;
    int bits = 0, rc;
    if (s == NULL) return DSL_SKIP;
    rc = deflatePending(s, &pending, &bits);
    dsl_note(V, "def_query wb=%d len=%lu bound=%lu cbound=%lu pend=%u bits=%d rc=%d\n",
             WB_OF(hn), (unsigned long)slen,
             (unsigned long)deflateBound(s, slen),
             (unsigned long)compressBound(slen), pending, bits, rc);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* deflateCopy: duplicate an in-flight compressor, window, hash chains,
   * pending buffer and all. Used by writers that need to try several
   * strategies from the same point; unreachable from a one-call harness, and
   * the operation most likely to expose a shallow-copied pointer, since
   * deflate_state holds five of them into its own allocations. */
  case OP_DEF_COPY: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    z_streamp d;
    int rc;
    if (s == NULL) return DSL_SKIP;
    d = (z_streamp)dsl_zalloc(V, sizeof(z_stream));
    if (d == NULL) return DSL_SKIP;
    rc = deflateCopy(d, s);
    dsl_note(V, "def_copy rc=%d\n", rc);
    if (rc != Z_OK) return DSL_LIBERR;
    dsl_hput(V, K_DEF, (void *)d, hn);
    return DSL_OK;
  }

  /* deflateReset and deflateResetKeep. The difference is one call to lm_init:
   * Reset re-initialises the match finder, ResetKeep leaves the window and
   * hash intact while resetting the wrapper state -- so a program can reset a
   * gzip stream and immediately emit a second member, which is what a
   * multi-member gzip writer does. */
  case OP_DEF_RESET: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_def(V, &hn);
    int full = dsl_flag(V);
    int rc;
    if (s == NULL) return DSL_SKIP;
    rc = full ? deflateReset(s) : dsl_resetkeep_guarded(s, full);
    /* Both forms put a gzip stream back in GZIP_STATE, which is where
     * deflate.c re-zeroes gzindex, so a header may legally be set again. */
    if (rc == Z_OK) (void)dsl_hset(V, K_DEF, (void *)s, (void *)s, hn & ~(size_t)DEF_USED);
    dsl_note(V, "def_reset full=%d rc=%d adler=%08lx\n",
             full, rc, (unsigned long)s->adler);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflateInit2_ over all FIVE wrapper modes, one of which no other tier in
   * this repository reaches: windowBits + 32 asks inflate to sniff zlib
   * vs. gzip from the first bytes, and windowBits == 0 asks it to take the
   * window size from the zlib header itself. Both are documented and both are
   * separate branches of inflateReset2. */
  case OP_INF_NEW: {
    int base = 8 + (int)dsl_choice(V, 8);      /* 8..15 */
    unsigned mode = dsl_choice(V, 5);
    int wb;
    int plain = dsl_flag(V);
    z_streamp s;
    int rc;
    switch (mode) {
      case 0:  wb = base;        break;   /* zlib wrapper */
      case 1:  wb = -base;       break;   /* raw deflate */
      case 2:  wb = base + 16;   break;   /* gzip wrapper */
      case 3:  wb = base + 32;   break;   /* zlib or gzip, auto-detected */
      default: wb = 0;           break;   /* window size from the zlib header */
    }
    s = new_stream(V);
    if (s == NULL) return DSL_SKIP;
    if (plain) { wb = 15; rc = inflateInit(s); }
    else       rc = inflateInit2(s, wb);
    dsl_note(V, "inf_new wb=%d plain=%d rc=%d\n", wb, plain, rc);
    if (rc != Z_OK) { note_msg(V, s); return DSL_LIBERR; }
    dsl_hput(V, K_INF, (void *)s, (size_t)(wb + WB_BIAS));
    return DSL_OK;
  }

  /* inflateReset, inflateResetKeep and inflateReset2. The third can change a
   * LIVE stream's wrapper and window size, which reallocates or discards the
   * window underneath a half-decoded stream -- the sharpest state transition
   * inflate.c has, and the handle's recorded windowBits is updated so later
   * operations know what wrapper the stream now has. */
  case OP_INF_RESET: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_inf(V, &hn);
    unsigned which = dsl_choice(V, 3);
    int wb = WB_OF(hn), rc;
    if (s == NULL) return DSL_SKIP;
    if (which == 0) {
      rc = inflateReset(s);
    } else if (which == 1) {
      rc = inflateResetKeep(s);
    } else {
      int base = 8 + (int)dsl_choice(V, 8);
      unsigned mode = dsl_choice(V, 5);
      int nwb = mode == 0 ? base : mode == 1 ? -base
              : mode == 2 ? base + 16 : mode == 3 ? base + 32 : 0;
      rc = inflateReset2(s, nwb);
      if (rc == Z_OK) { wb = nwb; (void)dsl_hset(V, K_INF, s, s, (size_t)(nwb + WB_BIAS)); }
    }
    dsl_note(V, "inf_reset which=%u wb=%d rc=%d\n", which, wb, rc);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflateSetDictionary: the answer to Z_NEED_DICT, and the only way to
   * decode a raw stream that was compressed against a preset dictionary. The
   * dictionary comes from a K_RAW handle when one exists, which is the case
   * where it can actually match what deflateSetDictionary was given. */
  case OP_INF_SETDICT: {
    z_streamp s = (z_streamp)want_inf(V, NULL);
    size_t n;
    int rc;
    if (s == NULL || sc_dict == NULL) return DSL_SKIP;
    n = stage_bytes(V, sc_dict, SC_DICT, K_RAW);
    rc = inflateSetDictionary(s, sc_dict, (uInt)n);
    dsl_note(V, "inf_setdict n=%lu rc=%d\n", (unsigned long)n, rc);
    note_msg(V, s);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflateGetDictionary: the sliding window's contents, reassembled by
   * inflate.c from its two halves around wnext. Needs a buffer of the full
   * window size for the same reason deflateGetDictionary does. The result is
   * kept as K_RAW so window contents can be fed back to the compressor. */
  case OP_INF_GETDICT: {
    z_streamp s = (z_streamp)want_inf(V, NULL);
    uInt dlen = 0;
    int rc;
    if (s == NULL || sc_dict == NULL) return DSL_SKIP;
    rc = inflateGetDictionary(s, sc_dict, &dlen);
    dsl_note(V, "inf_getdict rc=%d n=%u\n", rc, (unsigned)dlen);
    if (rc == Z_OK && dlen <= (uInt)SC_DICT) {
      dsl_report(V, "  dict", rc, sc_dict, (size_t)dlen);
      keep(V, K_RAW, sc_dict, (size_t)dlen);
    }
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflateGetHeader: the gzip header READER. Same arena lifetime argument as
   * deflateSetHeader (inflate.c stores `state->head = head` and writes through
   * it across many later inflate() calls), with one extra wrinkle: the three
   * variable-length fields are OUTPUT buffers whose capacities zlib obeys via
   * extra_max/name_max/comm_max. Those caps are program-chosen and small, so
   * inflate.c's truncation branches -- including the one CVE-2022-37434
   * concerned, `(len = head->extra_len - state->length) < head->extra_max` --
   * are reached with buffers that are actually too small.
   *
   * The record is remembered in `ihdr` because this call happens BEFORE any
   * inflate(), so there is nothing to report yet; op_inf_push reports what
   * inflate filled in. */
  case OP_INF_HEADER: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_inf(V, &hn);
    gz_header *h;
    ihdr_rec r;
    int rc;
    if (s == NULL) return DSL_SKIP;
    h = (gz_header *)dsl_zalloc(V, sizeof *h);
    if (h == NULL) return DSL_SKIP;
    memset(&r, 0, sizeof r);
    r.h = h;
    r.emax = (unsigned)dsl_bounded(V, 256);
    r.nmax = (unsigned)dsl_bounded(V, 128);
    r.cmax = (unsigned)dsl_bounded(V, 128);
    if (r.emax) r.extra = (unsigned char *)dsl_zalloc(V, r.emax);
    if (r.nmax) r.name = (unsigned char *)dsl_zalloc(V, r.nmax);
    if (r.cmax) r.comment = (unsigned char *)dsl_zalloc(V, r.cmax);
    if (r.extra == NULL) r.emax = 0;
    if (r.name == NULL) r.nmax = 0;
    if (r.comment == NULL) r.cmax = 0;
    h->extra = (Bytef *)r.extra; h->extra_max = r.emax;
    h->name = (Bytef *)r.name;   h->name_max = r.nmax;
    h->comment = (Bytef *)r.comment; h->comm_max = r.cmax;
    rc = inflateGetHeader(s, h);
    dsl_note(V, "inf_header wb=%d emax=%u nmax=%u cmax=%u rc=%d\n",
             WB_OF(hn), r.emax, r.nmax, r.cmax, rc);
    if (rc != Z_OK) return DSL_LIBERR;
    ihdr = r;
    return DSL_OK;
  }

  /* inflatePrime: pre-load the bit accumulator, the counterpart of
   * deflatePrime for readers of bit-aligned containers. bits == -1 is the
   * documented "discard the accumulator" form, and bits up to 17 reaches the
   * `bits > 16 || state->bits + bits > 32` rejection. */
  case OP_INF_PRIME: {
    z_streamp s = (z_streamp)want_inf(V, NULL);
    int bits = -1 + (int)dsl_choice(V, 19);   /* -1..17 */
    int value = (int)dsl_u16(V);
    int rc;
    if (s == NULL) return DSL_SKIP;
    rc = inflatePrime(s, bits, value);
    dsl_note(V, "inf_prime bits=%d val=%d rc=%d\n", bits, value, rc);
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflate(): the streaming decompressor, and the operation that consumes
   * what the compress side produced. Five flush modes including Z_BLOCK and
   * Z_TREES, which stop inflate at a block boundary and at a tree boundary
   * respectively and which essentially nothing outside zlib's own test suite
   * uses.
   *
   * Z_NEED_DICT is counted as DSL_LIBERR: the library was called and reported
   * that it cannot proceed with what it was given, which is the definition
   * dsl.h gives for LIBERR, and a program can answer it with op_inf_setdict. */
  case OP_INF_PUSH: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_inf(V, &hn);
    size_t in_n, produced;
    unsigned flush;
    uInt out_cap;
    int rc;
    static const int flushes[5] = {
      Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FINISH, Z_BLOCK, Z_TREES
    };
    if (s == NULL || sc_in == NULL || sc_out == NULL) return DSL_SKIP;
    in_n = stage_bytes(V, sc_in, SC_IN, K_ZBUF);
    out_cap = (uInt)dsl_bounded(V, SC_OUT);
    flush = dsl_choice(V, 5);
    s->next_in = sc_in;
    s->avail_in = (uInt)in_n;
    s->next_out = sc_out;
    s->avail_out = out_cap;
    rc = inflate(s, flushes[flush]);
    produced = (size_t)(out_cap - s->avail_out);
    dsl_note(V, "inf_push wb=%d flush=%d in=%lu cap=%lu rc=%d left=%lu\n",
             WB_OF(hn), flushes[flush], (unsigned long)in_n,
             (unsigned long)out_cap, rc, (unsigned long)s->avail_in);
    dsl_report(V, dsl_op_name(op), rc, sc_out, produced);
    note_counters(V, s);
    note_msg(V, s);
    report_ihdr(V, "hdr");
    keep(V, K_RAW, sc_out, produced);
    s->next_in = Z_NULL; s->avail_in = 0;
    s->next_out = Z_NULL; s->avail_out = 0;
    return (rc == Z_OK || rc == Z_STREAM_END) ? DSL_OK : DSL_LIBERR;
  }

  /* The five undocumented-but-exported inflate accessors, in one operation
   * because each is a single line and none of them is reachable from the
   * harness. inflateMark and inflateCodesUsed are the two that need care:
   * inflateMark packs state->back and a length into a long, and
   * inflateCodesUsed returns `state->next - state->codes`, a pointer
   * DIFFERENCE. A difference is a count -- it is the number of code table
   * entries inftrees.c has consumed for this stream -- so it is deterministic
   * and identical under ASan, unlike either pointer on its own. That
   * distinction is exactly dsl.h rule 3's line, and this is the one place in
   * the file that sits close to it.
   *
   * inflateUndermine returns Z_DATA_ERROR in every ordinary build (the
   * INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR macro is not defined), so it is
   * counted as a library error rather than a skip -- the call happened. */
  case OP_INF_QUERY: {
    z_streamp s = (z_streamp)want_inf(V, NULL);
    int check = dsl_flag(V);
    int subvert = dsl_flag(V);
    int rcv, rcu, sync;
    long mark;
    unsigned long used;
    if (s == NULL) return DSL_SKIP;
    mark = inflateMark(s);
    used = inflateCodesUsed(s);
    sync = inflateSyncPoint(s);
    rcv = inflateValidate(s, check);
    rcu = inflateUndermine(s, subvert);
    dsl_note(V, "inf_query mark=%ld codes=%lu syncpt=%d val=%d(%d) und=%d(%d)\n",
             mark, used, sync, rcv, check, rcu, subvert);
    return rcv == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflateSync: scan forward for a full-flush point (00 00 FF FF) and resume.
   * The recovery path a streaming reader uses after corruption, and one that
   * only means anything on a stream that has already been partly consumed --
   * which is why it is worth having beside op_inf_push rather than instead of
   * it. */
  case OP_INF_SYNC: {
    z_streamp s = (z_streamp)want_inf(V, NULL);
    size_t in_n;
    int rc, sync;
    if (s == NULL || sc_in == NULL) return DSL_SKIP;
    in_n = stage_bytes(V, sc_in, SC_IN, K_ZBUF);
    s->next_in = sc_in;
    s->avail_in = (uInt)in_n;
    rc = inflateSync(s);
    sync = inflateSyncPoint(s);
    dsl_note(V, "inf_sync in=%lu rc=%d left=%lu tin=%lu syncpt=%d\n",
             (unsigned long)in_n, rc, (unsigned long)s->avail_in,
             (unsigned long)s->total_in, sync);
    note_msg(V, s);
    s->next_in = Z_NULL; s->avail_in = 0;
    return rc == Z_OK ? DSL_OK : DSL_LIBERR;
  }

  /* inflateCopy: duplicate a live decompressor including its window. Same
   * shape as deflateCopy and the same reason for being here. */
  case OP_INF_COPY: {
    size_t hn = 0;
    z_streamp s = (z_streamp)want_inf(V, &hn);
    z_streamp d;
    int rc;
    if (s == NULL) return DSL_SKIP;
    d = (z_streamp)dsl_zalloc(V, sizeof(z_stream));
    if (d == NULL) return DSL_SKIP;
    rc = inflateCopy(d, s);
    dsl_note(V, "inf_copy rc=%d\n", rc);
    if (rc != Z_OK) return DSL_LIBERR;
    dsl_hput(V, K_INF, (void *)d, hn);
    return DSL_OK;
  }

  /* infback.c, end to end, in one self-contained operation: inflateBackInit_,
   * inflateBack, inflateBackEnd. A whole translation unit -- zlib's
   * callback-driven raw inflater, with its own copy of the decode loop -- that
   * neither this project's harness nor `compress`/`uncompress`/`inflate`
   * touches.
   *
   * The z_stream lives on the STACK here rather than in a handle, because the
   * operation both initialises and ends it and inflateBack has no partial
   * state a later operation could use: there is no streaming form of it. That
   * also keeps the caller-supplied window out of the handle table, where a
   * dsl_hput could have freed it under a live inflateBack state.
   *
   * The input is a raw deflate stream when a K_ZBUF handle holds one -- which
   * op_def_push produces whenever it is driven with a negative windowBits --
   * and garbage otherwise. `next_in == NULL` is exercised too, since
   * inflateBack documents that as "call in() immediately". */
  case OP_INF_BACK: {
    z_stream st;
    ib_ctx c;
    int wb = 8 + (int)dsl_choice(V, 8);       /* 8..15; sc_win is 1 << 15 */
    int prefeed = dsl_flag(V);
    size_t in_n;
    int rc, rce;
    if (sc_in == NULL || sc_win == NULL) return DSL_SKIP;
    in_n = stage_bytes(V, sc_in, SC_IN, K_ZBUF);
    memset(&st, 0, sizeof st);
    st.zalloc = alloc_fn();
    st.zfree = free_fn();
    st.opaque = Z_NULL;
    rc = inflateBackInit(&st, wb, sc_win);
    if (rc != Z_OK) {
      dsl_note(V, "inf_back init wb=%d rc=%d\n", wb, rc);
      return DSL_LIBERR;
    }
    memset(&c, 0, sizeof c);
    c.in = sc_in;
    c.in_n = (unsigned)in_n;
    c.h = 1469598103934665603ULL;
    if (prefeed) { st.next_in = sc_in; st.avail_in = (uInt)in_n; c.served = 1; }
    else         { st.next_in = Z_NULL; st.avail_in = 0; }
    rc = inflateBack(&st, ib_in, &c, ib_out, &c);
    rce = inflateBackEnd(&st);
    dsl_note(V, "inf_back wb=%d in=%lu pre=%d rc=%d end=%d\n",
             wb, (unsigned long)in_n, prefeed, rc, rce);
    dsl_note(V, "  outn=%lu calls=%lu stopped=%d h=%016llx\n",
             c.total, c.calls, c.stopped, (unsigned long long)c.h);
    return rc == Z_STREAM_END ? DSL_OK : DSL_LIBERR;
  }

  /* Explicit teardown of a live stream in the MIDDLE of a program, which is
   * where deflateEnd's and inflateEnd's free paths run while other objects are
   * still live. One operation for both kinds rather than two, so the table
   * stays close to the size dsl.h's guidance asks for; the flag picks which. */
  case OP_END: {
    int which = dsl_flag(V);
    int dropped = dsl_hdrop(V, which ? K_DEF : K_INF);
    /* Noted since 2026-09-02: before that the (op, rc) fold was this op's only
     * trace, and "every op reports" is what makes the digest a complete record. */
    dsl_note(V, "end kind=%s dropped=%d\n", which ? "def" : "inf", dropped);
    return dropped ? DSL_OK : DSL_SKIP;
  }

  /* The eight checksum entry points -- the one API family the first version
   * of this file left to the harness. adler32/crc32 over the whole staged
   * buffer; the _z forms over the same bytes (they take a size_t and must
   * agree); then the buffer is split at a program-chosen point, each half
   * checksummed separately and the halves COMBINED with adler32_combine,
   * crc32_combine, and crc32_combine_gen + crc32_combine_op, all of which must
   * reproduce the whole-buffer value. Every equality is REPORTED rather than
   * asserted: a mismatch is a library finding, not a driver decision, and the
   * digest carries it either way. The buffer comes from a K_RAW handle, a
   * literal or the filler (stage_bytes), so decompressed round-trip output is
   * checksummed too. Checksums cannot fail, so this op is always DSL_OK once
   * it runs. */
  case OP_CHECKSUM: {
    size_t n, cut;
    uLong a, az, c, cz, a1, a2, c1, c2, ac, cc, gen, cg;
    int agree;
    if (sc_in == NULL) return DSL_SKIP;
    n = stage_bytes(V, sc_in, SC_IN, K_RAW);
    cut = dsl_bounded(V, n);            /* [0, n]: both empty halves reachable */
    a  = adler32(adler32(0L, Z_NULL, 0), sc_in, (uInt)n);
    az = adler32_z(adler32_z(0L, Z_NULL, 0), sc_in, n);
    c  = crc32(crc32(0L, Z_NULL, 0), sc_in, (uInt)n);
    cz = crc32_z(crc32_z(0L, Z_NULL, 0), sc_in, n);
    a1 = adler32(adler32(0L, Z_NULL, 0), sc_in, (uInt)cut);
    a2 = adler32(adler32(0L, Z_NULL, 0), sc_in + cut, (uInt)(n - cut));
    c1 = crc32(crc32(0L, Z_NULL, 0), sc_in, (uInt)cut);
    c2 = crc32(crc32(0L, Z_NULL, 0), sc_in + cut, (uInt)(n - cut));
    ac = adler32_combine(a1, a2, (z_off_t)(n - cut));
    cc = crc32_combine(c1, c2, (z_off_t)(n - cut));
    gen = crc32_combine_gen((z_off_t)(n - cut));
    cg = crc32_combine_op(c1, c2, gen);
    agree = (a == az) && (c == cz) && (a == ac) && (c == cc) && (c == cg);
    dsl_note(V, "checksum n=%lu cut=%lu adler=%08lx crc=%08lx agree=%d\n",
             (unsigned long)n, (unsigned long)cut, (unsigned long)a,
             (unsigned long)c, agree);
    dsl_note(V, "  adler_z=%08lx a1=%08lx a2=%08lx comb=%08lx\n",
             (unsigned long)az, (unsigned long)a1, (unsigned long)a2,
             (unsigned long)ac);
    dsl_note(V, "  crc_z=%08lx c1=%08lx c2=%08lx comb=%08lx gen=%08lx op=%08lx\n",
             (unsigned long)cz, (unsigned long)c1, (unsigned long)c2,
             (unsigned long)cc, (unsigned long)gen, (unsigned long)cg);
    return DSL_OK;
  }

  /* Corrupt-input producer: a NEW handle of the same kind as its source, made
   * by one of flip (xor one byte, program-chosen offset and mask), truncate
   * (a prefix of program-chosen length) or fill (a program-chosen run
   * overwritten with filler bytes). Source kind is chosen by a flag -- K_ZBUF
   * (a library-produced stream: the case that reaches inflate's "incorrect
   * data check", "invalid distance too far back" and the truncated-stream
   * Z_BUF_ERROR paths, which need a header that PARSES) or K_RAW. Offsets and
   * lengths are taken modulo the source length so every operand value is in
   * range; the resulting bytes are reported, and the source is left intact so
   * the good and the corrupt stream can be decoded side by side. */
  case OP_MUTATE: {
    int kind = dsl_flag(V) ? K_ZBUF : K_RAW;
    unsigned mode = dsl_choice(V, 3);
    size_t sn = 0, newn, off, len;
    unsigned mask;
    void *src = dsl_hget(V, kind, &sn);
    unsigned char *copy;
    if (src == NULL || sn == 0) return DSL_SKIP;
    off = (size_t)dsl_u16(V) % sn;
    len = 1 + (size_t)dsl_u16(V) % sn;
    mask = 1u + dsl_choice(V, 255);            /* never 0: a flip always changes the byte */
    newn = mode == 1 ? (off ? off : 1) : sn;   /* truncate keeps [0, off), at least 1 */
    copy = (unsigned char *)dsl_dup(V, src, newn, 0);
    if (copy == NULL) return DSL_SKIP;
    if (mode == 0) {
      copy[off] ^= (unsigned char)mask;
    } else if (mode == 2) {
      if (len > newn - off) len = newn - off;
      dsl_fill(V, copy + off, len);
    }
    dsl_note(V, "mutate kind=%s mode=%u src=%lu off=%lu len=%lu mask=%02x\n",
             kind == K_ZBUF ? "zbuf" : "raw", mode, (unsigned long)sn,
             (unsigned long)off, (unsigned long)(mode == 2 ? len : 0), mask);
    dsl_report(V, "  out", 0, copy, newn);
    dsl_hput(V, kind, copy, newn);
    return DSL_OK;
  }

  default:
    return DSL_SKIP;
  }
}

/* ------------------------------------------------------------ serializer ---
 *
 * The VALUE of a live handle, as bytes into the sink, for `expect obj` and
 * snap (src/dsl.h "THE SERIALIZER"; the contract is docs/dsl-driver.md
 * "Making a handle expectable"). An observation and nothing else: no operand
 * reads, no handle-table calls, no arena, no dsl_rand, no dsl_note. Scratch is
 * the one bounded file-scope static below.
 *
 *   K_RAW, K_ZBUF  the arena bytes; n IS the length for these kinds.
 *
 *   K_DEF   tag 'D'; the driver's own record (n: windowBits + 64, DEF_USED);
 *           the z_stream counters zlib writes at Reset and updates on every
 *           call -- total_in, total_out, adler, data_type (deflate.c
 *           deflateResetKeep: 642-644, 658) -- and msg's CONTENTS (one of
 *           zutil.c's static strings; NULL is distinct from "");
 *           then the deflate_state scalars, every one written at Init/Reset:
 *             deflateInit2_  wrap w_bits w_size hash_bits lit_bufsize level
 *                            strategy method high_water (deflate.c 434-521)
 *             deflateResetKeep  status pending last_flush (647-663)
 *             lm_init        window_size max_lazy_match good_match nice_match
 *                            max_chain_length strstart block_start lookahead
 *                            insert match_length prev_length match_available
 *                            ins_h (673-692)
 *             _tr_init / init_block  bi_buf bi_valid sym_next opt_len
 *                            static_len matches (trees.c 439-476); sym_end is
 *                            Init-set in deflateInit2_
 *           and the gz_header gzhead points at (set NULL at Init; its CONTENT
 *           through ser_gzhead since 2026-09-03, never the pointer);
 *           then the not-yet-flushed PENDING bytes [pending_out, +pending) --
 *           every byte there was put_byte'd before `pending` counted it;
 *           then the not-yet-emitted SYMBOL buffer, sym_buf[0, sym_next)
 *           (LIT_MEM off, the pinned deflate.h's default) or d_buf/l_buf
 *           [0, sym_next) (LIT_MEM on) -- each entry written by _tr_tally
 *           before sym_next advanced;
 *           then the WINDOW through deflateGetDictionary, which copies
 *           min(strstart + lookahead, w_size) bytes -- exactly the bytes
 *           fill_window and deflateSetDictionary have written -- into the
 *           32 KiB static (w_size <= 1 << 15; the same size argument as
 *           SC_DICT). NOT sunk: match_start, prev_match (written only inside
 *           longest_match / deflate_slow), gzindex (written when the header
 *           writer starts), the tree Freq/Code arrays (a function of sym_buf,
 *           and their internal nodes are built only per block), head[]/prev[]
 *           (a function of the window; prev[] is ZALLOC'd and written
 *           per-position), the three ZALLOC'd buffers' unused tails.
 *
 *   K_INF   tag 'I'; the driver's record; total_in total_out adler data_type
 *           msg; the inflate_state scalars written at Init/Reset:
 *             inflateResetKeep  total mode last havedict flags dmax hold bits
 *                            sane back (inflate.c 111-125)
 *             inflateReset   wsize whave wnext (135-137)
 *             inflateReset2  wrap wbits (173-174)
 *           the gz_header head points at (its CONTENT, filled in by inflate's
 *           header states, through ser_gzhead; the arena's zeros before them);
 *           then the three exported read-only accessors
 *           inflateMark, inflateCodesUsed (a pointer DIFFERENCE, a count of
 *           table entries), inflateSyncPoint; then the WINDOW through
 *           inflateGetDictionary (whave bytes, reassembled around wnext:
 *           exactly what updatewindow has written). NOT sunk: check (written
 *           only once a wrapped header is read), length offset extra ncode
 *           nlen ndist have lenbits distbits was lens[] work[] codes[] (all
 *           written by the decode loop as it reaches them).
 *
 * strm->adler for a RAW inflate stream is never written by zlib
 * (inflateResetKeep sets it only `if (state->wrap)`); it is the arena's zero
 * from new_stream, deterministic in every flavour, and note_counters already
 * prints it.
 *
 * Why the struct fields and not deflatePending/deflateBound alone: the state
 * the brief's classifier control names -- "a compressor with buffered input
 * and nothing emitted" -- lives in the window (deflateGetDictionary sees it)
 * AND in the symbol buffer (nothing public sees it: after deflate(Z_NO_FLUSH)
 * on a short input the window holds the bytes, sym_buf holds the literals and
 * matches the match-finder chose, and pending is 0 or a 2-byte header). A
 * one-byte change in that input moves sym_buf and the window; deflatePending
 * says 2 either way.
 *
 * No kind is opaque. Everything sunk is a library-computed value or
 * library-written bytes; nothing depends on an address or on an allocator's
 * choice, and gen_program.py verify step (c) -- four flavours, one stdout --
 * is the instrument that measures that rather than assuming it. */
static unsigned char ser_win[32768];
_Static_assert(sizeof ser_win == (1u << 15), "ser_win must hold the largest w_size");

/* A gz_header's CONTENT (added 2026-09-03; until then only `gzhead != NULL` /
 * `head != NULL` was sunk, and the previous lane measured the hole: with a
 * header attached to a gzip deflater but not yet emitted, changing its `time`
 * left every check passing). The struct and its three buffers are OURS -- arena
 * blocks, zeroed at allocation (op_def_header, op_inf_header) -- so every field
 * is initialised at every point of observation whether or not zlib has reached
 * the state that writes it, and nothing here is an allocator's choice.
 *
 * The two sides read the struct differently, so the sink does too. WRITING
 * (deflateSetHeader): deflate.c reads extra[0, extra_len & 0xffff) when extra
 * is non-NULL, and name/comment up to their NUL (dsl_cstr's copies are
 * NUL-terminated by construction); extra_max/name_max/comm_max are unused.
 * READING (inflateGetHeader): inflate.c fills extra[0, extra_max), name[0,
 * name_max), comment[0, comm_max) -- a name longer than name_max has NO NUL
 * inside the buffer, so the reading side sinks the whole buffer and never
 * strlen()s it -- and sets the pointer of an absent field to Z_NULL (EXLEN /
 * NAME / COMMENT states); the buffers are exactly *_max bytes because
 * op_inf_header zeroes the max of any buffer the arena refused. Pointers are
 * sunk as present/absent only (rule 3). */
static void ser_gzhead(dsl_ser *S, const gz_header *h, int reading) {
  if (h == NULL) { dsl_ser_u8(S, 0); return; }
  dsl_ser_u8(S, 1);
  dsl_ser_i64(S, (int64_t)h->text);
  dsl_ser_u64(S, (uint64_t)h->time);
  dsl_ser_i64(S, (int64_t)h->xflags);
  dsl_ser_i64(S, (int64_t)h->os);
  dsl_ser_i64(S, (int64_t)h->hcrc);
  dsl_ser_i64(S, (int64_t)h->done);
  dsl_ser_u32(S, (uint32_t)h->extra_len);
  dsl_ser_u32(S, (uint32_t)h->extra_max);
  dsl_ser_u32(S, (uint32_t)h->name_max);
  dsl_ser_u32(S, (uint32_t)h->comm_max);
  dsl_ser_u8(S, h->extra != Z_NULL);
  if (reading) {
    if (h->extra != Z_NULL) dsl_ser_bytes(S, h->extra, (size_t)h->extra_max);
    dsl_ser_u8(S, h->name != Z_NULL);
    if (h->name != Z_NULL) dsl_ser_bytes(S, h->name, (size_t)h->name_max);
    dsl_ser_u8(S, h->comment != Z_NULL);
    if (h->comment != Z_NULL) dsl_ser_bytes(S, h->comment, (size_t)h->comm_max);
  } else {
    if (h->extra != Z_NULL) dsl_ser_bytes(S, h->extra, (size_t)(h->extra_len & 0xffffu));
    dsl_ser_str(S, (const char *)h->name);
    dsl_ser_str(S, (const char *)h->comment);
  }
}

static int dsl_serialize(dsl_vm *V, int kind, void *p, size_t n, dsl_ser *S) {
  (void)V;
  switch (kind) {
  case K_RAW:
  case K_ZBUF:
    dsl_ser_bytes(S, p, n);
    return 0;

  case K_DEF: {
    z_streamp strm = (z_streamp)p;
    deflate_state *s = (deflate_state *)strm->state;
    uInt dlen = 0;
    dsl_ser_tag(S, 'D');
    dsl_ser_u32(S, (uint32_t)n);
    dsl_ser_u64(S, (uint64_t)strm->total_in);
    dsl_ser_u64(S, (uint64_t)strm->total_out);
    dsl_ser_u64(S, (uint64_t)strm->adler);
    dsl_ser_i64(S, (int64_t)strm->data_type);
    dsl_ser_str(S, strm->msg);
    if (s == NULL) { dsl_ser_tag(S, 0); return 0; }   /* cannot happen for a live handle */
    dsl_ser_tag(S, 1);
    dsl_ser_i64(S, (int64_t)s->status);
    dsl_ser_i64(S, (int64_t)s->wrap);
    dsl_ser_u32(S, (uint32_t)s->w_bits);
    dsl_ser_u32(S, (uint32_t)s->w_size);
    dsl_ser_u32(S, (uint32_t)s->hash_bits);
    dsl_ser_u32(S, (uint32_t)s->lit_bufsize);
    dsl_ser_i64(S, (int64_t)s->level);
    dsl_ser_i64(S, (int64_t)s->strategy);
    dsl_ser_u8(S, (unsigned)s->method);
    dsl_ser_u64(S, (uint64_t)s->high_water);
    dsl_ser_u64(S, (uint64_t)s->pending);
    dsl_ser_i64(S, (int64_t)s->last_flush);
    dsl_ser_u64(S, (uint64_t)s->window_size);
    dsl_ser_u32(S, (uint32_t)s->max_lazy_match);
    dsl_ser_u32(S, (uint32_t)s->good_match);
    dsl_ser_i64(S, (int64_t)s->nice_match);
    dsl_ser_u32(S, (uint32_t)s->max_chain_length);
    dsl_ser_u32(S, (uint32_t)s->strstart);
    dsl_ser_i64(S, (int64_t)s->block_start);
    dsl_ser_u32(S, (uint32_t)s->lookahead);
    dsl_ser_u32(S, (uint32_t)s->insert);
    dsl_ser_u32(S, (uint32_t)s->match_length);
    dsl_ser_u32(S, (uint32_t)s->prev_length);
    dsl_ser_i64(S, (int64_t)s->match_available);
    dsl_ser_u32(S, (uint32_t)s->ins_h);
    dsl_ser_u32(S, (uint32_t)s->bi_buf);
    dsl_ser_i64(S, (int64_t)s->bi_valid);
    dsl_ser_u32(S, (uint32_t)s->sym_next);
    dsl_ser_u32(S, (uint32_t)s->sym_end);
    dsl_ser_u64(S, (uint64_t)s->opt_len);
    dsl_ser_u64(S, (uint64_t)s->static_len);
    dsl_ser_u32(S, (uint32_t)s->matches);
    /* The header deflate will write (or is writing) into a gzip stream: our
     * arena struct, set NULL at Init/Reset by deflate.c and stored by
     * deflateSetHeader; deflate only ever READS it. */
    ser_gzhead(S, s->gzhead, 0);
    /* Pending output: written bytes only. pending_out stays inside pending_buf
     * and pending <= pending_buf_size by deflate.c's own invariants. */
    if (s->pending_out != NULL && s->pending != 0)
      dsl_ser_bytes(S, s->pending_out, (size_t)s->pending);
    /* The symbol buffer: the literals and (dist, len) pairs tallied for the
     * block in progress. */
#ifdef LIT_MEM
    if (s->d_buf != NULL && s->l_buf != NULL && s->sym_next != 0) {
      dsl_ser_bytes(S, s->d_buf, (size_t)s->sym_next * sizeof(ush));
      dsl_ser_bytes(S, s->l_buf, (size_t)s->sym_next);
    }
#else
    if (s->sym_buf != NULL && s->sym_next != 0)
      dsl_ser_bytes(S, s->sym_buf, (size_t)s->sym_next);
#endif
    /* The window: deflateGetDictionary is zlib's exported, read-only window
     * accessor; the buffer must be w_size bytes (see SC_DICT). */
    if (deflateGetDictionary(strm, ser_win, &dlen) == Z_OK && dlen <= sizeof ser_win) {
      dsl_ser_u32(S, (uint32_t)dlen);
      dsl_ser_bytes(S, ser_win, (size_t)dlen);
    } else {
      dsl_ser_u32(S, 0xFFFFFFFFu);
    }
    return 0;
  }

  case K_INF: {
    z_streamp strm = (z_streamp)p;
    struct inflate_state *st = (struct inflate_state *)strm->state;
    uInt dlen = 0;
    dsl_ser_tag(S, 'I');
    dsl_ser_u32(S, (uint32_t)n);
    dsl_ser_u64(S, (uint64_t)strm->total_in);
    dsl_ser_u64(S, (uint64_t)strm->total_out);
    dsl_ser_u64(S, (uint64_t)strm->adler);
    dsl_ser_i64(S, (int64_t)strm->data_type);
    dsl_ser_str(S, strm->msg);
    if (st == NULL) { dsl_ser_tag(S, 0); return 0; }   /* cannot happen for a live handle */
    dsl_ser_tag(S, 1);
    dsl_ser_u64(S, (uint64_t)st->total);
    dsl_ser_i64(S, (int64_t)st->mode);
    dsl_ser_i64(S, (int64_t)st->last);
    dsl_ser_i64(S, (int64_t)st->wrap);
    dsl_ser_i64(S, (int64_t)st->havedict);
    dsl_ser_i64(S, (int64_t)st->flags);
    dsl_ser_u32(S, (uint32_t)st->dmax);
    dsl_ser_u64(S, (uint64_t)st->hold);
    dsl_ser_u32(S, (uint32_t)st->bits);
    dsl_ser_i64(S, (int64_t)st->sane);
    dsl_ser_i64(S, (int64_t)st->back);
    dsl_ser_u32(S, (uint32_t)st->wbits);
    dsl_ser_u32(S, (uint32_t)st->wsize);
    dsl_ser_u32(S, (uint32_t)st->whave);
    dsl_ser_u32(S, (uint32_t)st->wnext);
    /* The header inflate has filled in (or is filling in) from a gzip stream:
     * our arena struct, set NULL at Reset by inflate.c and stored by
     * inflateGetHeader; inflate WRITES its fields as the header states pass. */
    ser_gzhead(S, st->head, 1);
    dsl_ser_i64(S, (int64_t)inflateMark(strm));
    dsl_ser_u64(S, (uint64_t)inflateCodesUsed(strm));
    dsl_ser_i64(S, (int64_t)inflateSyncPoint(strm));
    if (inflateGetDictionary(strm, ser_win, &dlen) == Z_OK && dlen <= sizeof ser_win) {
      dsl_ser_u32(S, (uint32_t)dlen);
      dsl_ser_bytes(S, ser_win, (size_t)dlen);
    } else {
      dsl_ser_u32(S, 0xFFFFFFFFu);
    }
    return 0;
  }

  default:
    return 1;   /* no such kind is ever stored; unreachable, and honest if it were */
  }
}
