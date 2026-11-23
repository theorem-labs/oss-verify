/* Single-file form of rt_mem.h, rt_settings.h, rt_mem.c, rt_settings.c and the harness, joined in that
 * order with their local #include lines removed. Sources (md5):
 *   rt_mem.h 9838cd70d7e4216bc4e8a93b1c6d43ef
 *   rt_settings.h 2a24a94988c386d6d081696b79aab01e
 *   rt_mem.c 5596b8eaf8120a4823450382528cd994
 *   rt_settings.c 734c9eb84ccc651f003da86d4e1e28a8
 *   compress_roundtrip_full_fuzzer.c 89defc74c7d3eddfbb11be4e79a53fca, before the file-mode change
 */

#define _POSIX_C_SOURCE 200809L

/* ---- rt_mem.h ---- */
/* rt_mem.h - the memory policy of the zlib round-trip harness. Included by rt_settings.h.
 *
 * The harness's own allocations and the allocations of the zlib streams it sets up go through these, and a refused
 * allocation aborts: within the input cap no accepted input can run out of memory, so a refusal is a bug to report,
 * not an allowed way to end. compress2 and uncompress2 use zlib's default allocator instead; a refusal there makes
 * them answer Z_MEM_ERROR, and a zlib call that answers Z_MEM_ERROR aborts too, through rt_check (Z_MEM_ERROR is never
 * an allowed answer). */
#ifndef RT_MEM_H
#define RT_MEM_H

#include <stddef.h>
#include "zlib.h"

/* The whole-file input cap, the one build-time define. It is backed out from the peak memory: in whole-file mode
 * four input-sized buffers are alive at once (the driver's input, the driver's aligned copy of it, the one-shot
 * compressed copy of compressBound(n) bytes, and the one-shot result), so the peak is about 4n, up to 5n near a power
 * of two, where the driver's read buffer has already doubled. The default suits a 2 GiB budget; a build with a
 * 256 GiB budget passes -DRT_INPUT_CAP='((size_t)1 << 35)'. */
#ifndef RT_INPUT_CAP
#define RT_INPUT_CAP ((size_t)1 << 28)
#endif

voidpf rt_zalloc(voidpf opaque, uInt items, uInt size);  /* zlib's zalloc: aborts on overflow or refusal */
void rt_zfree(voidpf opaque, voidpf address);             /* zlib's zfree */
void *rt_xmalloc(size_t n);                               /* n == 0 is allowed; never returns NULL */

/* abort unless ret is one of the allowed answers (repeat a code to fill an unused slot) */
void rt_check(int ret, int ok1, int ok2, int ok3);

#endif

/* ---- rt_settings.h ---- */
/* rt_settings.h - the settings decoder of the zlib round-trip harness.
 * The memory policy is in rt_mem.h (included here). Build: rt_settings.c and rt_mem.c.
 *
 * Every read is a pure function of the input bytes, and a read past the end of the input gives 0, so every input
 * decodes and every decoded value is valid by construction (there is no reject path).
 *
 * The settings, RT_SETTINGS_BYTES = 6 bytes, first in the input, in this order:
 *   level       b % 11 - 1          -1 (zlib's default, 6) or 0..9
 *   strategy    b % 5               default, filtered, Huffman-only, run-length, fixed
 *   format      b % 3               zlib, raw, gzip
 *   window      zlib: 8 + b % 8     8..15 (zlib.h: 8 is allowed only in zlib format; deflate then uses 9 and
 *               raw, gzip: 9 + b % 7  writes 9 in the header, and a decompressor must use 0 or at least 9)
 *   mem_level   1 + b % 9           1..9
 *   inf window  one byte, always a value inflateInit2 accepts for the stream deflate makes. With w the stream's
 *               window (zlib: max(window, 9); raw and gzip: window), the choices are, in order, b % count:
 *                 zlib: 0, w..15, 32 + 0, 32 + (w..15)
 *                 gzip: 16 + 0, 16 + (w..15), 32 + 0, 32 + (w..15)
 *                 raw:  -(w..15)
 *               16 + 0 and 32 + 0 on a gzip stream mean a window of 15 (inflate.c; ChangeLog 1.2.9, "Fix
 *               inflateInit2() bug when windowBits is 16 or 32").
 *
 * Per-call choices, each from its own bytes:
 *   rt_deflate_flush   1 byte, b % 5      none, partial, sync, full, block (never finish: the caller finishes)
 *   rt_inflate_flush   1 byte             with_finish != 0: b % 5 over none, sync, block, trees, finish
 *                                          with_finish == 0: b % 4 over none, sync, block, trees
 *   rt_piece           3 bytes            s = b0 % 17, v = b1 | b2 << 8, p = 1 + (v >> s), result 1 + (p - 1) % max:
 *                                          every size 1..65536 is reachable (s = 0) and small sizes are common
 */
#ifndef RT_SETTINGS_H
#define RT_SETTINGS_H

#include <stddef.h>
#include <stdint.h>
#include "zlib.h"

#define RT_FMT_ZLIB 0
#define RT_FMT_RAW 1
#define RT_FMT_GZIP 2

#define RT_SETTINGS_BYTES 6
#define RT_PIECE_MAX ((size_t)65536)  /* the largest piece size and output room; also the 64 KiB read limit */

/* the input; reads past the end give 0 */
typedef struct rt_cur {
  const uint8_t *p;
  size_t n;
} rt_cur;

uint8_t rt_u8(rt_cur *c);
uint16_t rt_u16(rt_cur *c);  /* little-endian */
uint32_t rt_u32(rt_cur *c);  /* little-endian */
uint64_t rt_u64(rt_cur *c);  /* little-endian */
/* up to want bytes: *out points at them, the return is how many (fewer only at the end of the input) */
size_t rt_take(rt_cur *c, size_t want, const uint8_t **out);

typedef struct rt_settings {
  int level;            /* -1..9 */
  int strategy;         /* Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED */
  int format;           /* RT_FMT_ZLIB, RT_FMT_RAW, RT_FMT_GZIP */
  int window;           /* the window the input chose: 8..15 in zlib format, 9..15 otherwise */
  int window_bits;      /* deflateInit2's: window (zlib), -window (raw), 16 + window (gzip) */
  int mem_level;        /* 1..9 */
  int inf_window_bits;  /* inflateInit2's, valid for the stream deflateInit2(window_bits) makes */
} rt_settings;

/* reads exactly RT_SETTINGS_BYTES bytes, in the order above */
void rt_settings_decode(rt_cur *c, rt_settings *s);

int rt_deflate_flush(rt_cur *c);
int rt_inflate_flush(rt_cur *c, int with_finish);
size_t rt_piece(rt_cur *c, size_t max);  /* 1..max; max must be at least 1 (0 aborts) */

/* deflate's output room for one call with this flush: zlib.h asks for more than six bytes with a sync or full flush
 * (a partial flush has the same loop), so those get at least 7; others get room as is */
size_t rt_deflate_room(int flush, size_t room);

#endif

/* ---- rt_mem.c ---- */
/* rt_mem.c - see rt_mem.h. */
#include <stdint.h>
#include <stdlib.h>

voidpf rt_zalloc(voidpf opaque, uInt items, uInt size) {
  (void)opaque;
  if (size != 0 && (size_t)items > SIZE_MAX / (size_t)size) abort();
  size_t n = (size_t)items * (size_t)size;
  void *p = malloc(n ? n : 1);
  if (p == NULL) abort();
  return p;
}

void rt_zfree(voidpf opaque, voidpf address) {
  (void)opaque;
  free(address);
}

void *rt_xmalloc(size_t n) {
  void *p = malloc(n ? n : 1);
  if (p == NULL) abort();
  return p;
}

void rt_check(int ret, int ok1, int ok2, int ok3) {
  if (ret != ok1 && ret != ok2 && ret != ok3) abort();
}

/* ---- rt_settings.c ---- */
/* rt_settings.c - see rt_settings.h. */
#include <stdlib.h>

uint8_t rt_u8(rt_cur *c) {
  if (c->n == 0) return 0;
  uint8_t v = c->p[0];
  c->p++;
  c->n--;
  return v;
}

uint16_t rt_u16(rt_cur *c) {
  uint16_t lo = rt_u8(c);
  uint16_t hi = rt_u8(c);
  return (uint16_t)(lo | (uint16_t)(hi << 8));
}

uint32_t rt_u32(rt_cur *c) {
  uint32_t lo = rt_u16(c);
  uint32_t hi = rt_u16(c);
  return lo | (hi << 16);
}

uint64_t rt_u64(rt_cur *c) {
  uint64_t lo = rt_u32(c);
  uint64_t hi = rt_u32(c);
  return lo | (hi << 32);
}

size_t rt_take(rt_cur *c, size_t want, const uint8_t **out) {
  size_t k = want < c->n ? want : c->n;
  *out = c->p;
  c->p += k;
  c->n -= k;
  return k;
}

static int level_of(unsigned b) { return (int)(b % 11) - 1; }

static int strategy_of(unsigned b) {
  static const int s[5] = {Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED};
  return s[b % 5];
}

static int window_of(int format, unsigned b) {
  if (format == RT_FMT_ZLIB) return 8 + (int)(b % 8);
  return 9 + (int)(b % 7);
}

static int window_bits_of(int format, int window) {
  if (format == RT_FMT_RAW) return -window;
  if (format == RT_FMT_GZIP) return 16 + window;
  return window;
}

static int inf_window_bits_of(int format, int window, unsigned b) {
  int w = window;
  if (format == RT_FMT_ZLIB && w < 9) w = 9;  /* deflate writes 9 for a window of 8 */
  unsigned span = (unsigned)(16 - w);         /* the windows w..15 */
  if (format == RT_FMT_RAW) return -(w + (int)(b % span));
  unsigned k = b % (2 * (span + 1));
  int base = format == RT_FMT_GZIP ? 16 : 0;
  if (k > span) {                             /* 32 + 0 or 32 + (w..15): detect zlib or gzip */
    k -= span + 1;
    base = 32;
  }
  return base + (k == 0 ? 0 : w + (int)(k - 1));
}

void rt_settings_decode(rt_cur *c, rt_settings *s) {
  s->level = level_of(rt_u8(c));
  s->strategy = strategy_of(rt_u8(c));
  s->format = (int)(rt_u8(c) % 3);
  s->window = window_of(s->format, rt_u8(c));
  s->window_bits = window_bits_of(s->format, s->window);
  s->mem_level = 1 + (int)(rt_u8(c) % 9);
  s->inf_window_bits = inf_window_bits_of(s->format, s->window, rt_u8(c));
}

int rt_deflate_flush(rt_cur *c) {
  static const int f[5] = {Z_NO_FLUSH, Z_PARTIAL_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_BLOCK};
  return f[rt_u8(c) % 5];
}

int rt_inflate_flush(rt_cur *c, int with_finish) {
  static const int f[5] = {Z_NO_FLUSH, Z_SYNC_FLUSH, Z_BLOCK, Z_TREES, Z_FINISH};
  return f[rt_u8(c) % (with_finish ? 5u : 4u)];
}

size_t rt_piece(rt_cur *c, size_t max) {
  if (max == 0) abort();
  unsigned s = rt_u8(c) % 17;
  size_t p = 1 + ((size_t)rt_u16(c) >> s);  /* 1..65536 */
  return 1 + (p - 1) % max;
}

size_t rt_deflate_room(int flush, size_t room) {
  if ((flush == Z_PARTIAL_FLUSH || flush == Z_SYNC_FLUSH || flush == Z_FULL_FLUSH) && room < 7) return 7;
  return room;
}

/* ---- compress_roundtrip_full_fuzzer.c ---- */
/* compress_roundtrip_full_fuzzer.c - zlib round trip at every setting. oss-fuzz's form: an
 * LLVMFuzzerTestOneInput entry and no main of its own.
 *
 * The harness asserts that every zlib call returns a documented success answer and that the bytes come back
 * equal, at every level, strategy, window and format, memory level and flush point, with the decompressor's own
 * window, piece sizes and flush. Any failure aborts. It never runs out of memory: the harness's own allocations and
 * the streaming pass's zlib allocations go through rt_mem.h and abort on a refusal; compress2 and uncompress2 use
 * zlib's default allocator, where a refusal makes them answer Z_MEM_ERROR, and Z_MEM_ERROR is never an allowed answer,
 * so the harness aborts there too.
 *
 * The input, in order (bytes past the end read as 0, so every input is accepted):
 *   6 bytes    the settings (rt_settings.h): level, strategy, format, window, memory level, inflate's window
 *   1 byte     the mode: bit 0 = 0 whole-file mode, 1 streaming-file mode; bit 1 = 1 in whole-file mode, the last
 *              piece goes to deflate with Z_FINISH (otherwise Z_FINISH comes alone, with no input)
 *   1 byte     the deflate steps in use: 1 + b % 8
 *   8 x 7      the deflate steps: input piece size (3 bytes, rt_piece), output room (3), flush (1, never finish)
 *   1 byte     the inflate steps in use: 1 + b % 8
 *   8 x 7      the inflate steps: input piece size (3), output room (3), flush (1, finish included)
 *   the rest   whole-file mode: the data. Streaming-file mode: a bare file name.
 * The steps are used in turn: deflate step k for deflate's k-th piece, inflate step k for inflate's k-th call.
 *
 * Whole-file mode: one-shot (compress2 at the level, then uncompress2 into exactly the input's size), skipped above
 * RT_INPUT_CAP (rt_mem.h: 2^28 by default, 2^35 for a 256 GiB budget), then streaming. The peak is about 4n, up to 5n
 * near a power of two: four input-sized buffers are alive at once (the driver's input, the driver's aligned copy of
 * it, one-shot's compressed copy of compressBound(n) bytes and one-shot's result), and the driver's read buffer may
 * already have doubled. Streaming: deflate (deflateInit2 with every setting) and inflate (inflateInit2 with inflate's
 * window) run as one pipeline in fixed memory. Every byte deflate gives is handed to inflate at once, and
 * every byte inflate gives is checked against the data. After a partial, sync or full flush, inflate must give back
 * all the data so far (zlib.h: "All of the input data so far will be available to the decompressor"). At the end,
 * inflate answers Z_STREAM_END with every compressed byte used and every data byte given back.
 *
 * Streaming-file mode: the name must be bare, so an empty name, a slash or a 0 byte returns before any open, and so do
 * the names proc and sys when the working directory is "/" or getcwd fails other than with ERANGE: a guard for a gap of
 * the process model, which does not reach those two names there. The file is opened twice, with O_NOFOLLOW, so a
 * symlink is not followed, and O_NONBLOCK, so opening a FIFO or a device does not wait; a descriptor that fstat does
 * not show as a regular file returns at once. The first descriptor feeds deflate, read in pieces of at most 64 KiB (the
 * deflate steps' piece sizes). The second is read, also at most 64 KiB at a time, to check inflate's bytes, and must
 * end where inflate's output ends. A failed open, fstat, read or close returns normally, at once, and nothing read
 * before it is compared as if it were the whole file. The memory is fixed at any file size, up to 2^63 - 1 bytes.
 */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "zlib.h"

#define RT_STEPS 8
/* consecutive calls that neither take nor give a byte before the harness calls the stream stuck. Such a call is
 * legitimate in one case: inflate with Z_BLOCK returns when it reaches the end of a block, and with Z_TREES also just
 * after a block's header, and every bit it decodes on the way may already sit in its bit buffer, pulled in by an
 * earlier call. The call still moves inflate on, and the bit buffer holds only a few dozen bits, so a run of such calls
 * is short and ends in a call that takes or gives a byte. A stuck stream is the only way to reach this many. */
#define RT_STALL_MAX 1024

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef struct rt_step {
  size_t in;   /* input piece size, 1..65536 */
  size_t out;  /* output room, 1..65536 */
  int flush;
} rt_step;

typedef struct rt_plan {
  rt_settings s;
  int file_mode;
  int finish_last;
  unsigned nd, ni;
  rt_step d[RT_STEPS];
  rt_step i[RT_STEPS];
} rt_plan;

static void plan_decode(rt_cur *c, rt_plan *pl) {
  rt_settings_decode(c, &pl->s);
  unsigned m = rt_u8(c);
  pl->file_mode = (int)(m & 1);
  pl->finish_last = (int)((m >> 1) & 1);
  pl->nd = 1 + rt_u8(c) % RT_STEPS;
  for (int k = 0; k < RT_STEPS; k++) {
    pl->d[k].in = rt_piece(c, RT_PIECE_MAX);
    pl->d[k].out = rt_piece(c, RT_PIECE_MAX);
    pl->d[k].flush = rt_deflate_flush(c);
  }
  pl->ni = 1 + rt_u8(c) % RT_STEPS;
  for (int k = 0; k < RT_STEPS; k++) {
    pl->i[k].in = rt_piece(c, RT_PIECE_MAX);
    pl->i[k].out = rt_piece(c, RT_PIECE_MAX);
    pl->i[k].flush = rt_inflate_flush(c, 1);
  }
}

/* --- one-shot ------------------------------------------------------------------------------------------------- */

static void oneshot(const rt_plan *pl, const unsigned char *data, size_t n) {
  if (n > RT_INPUT_CAP) return;
  uLong bound = compressBound((uLong)n);
  unsigned char *comp = rt_xmalloc((size_t)bound);
  uLongf clen = bound;
  rt_check(compress2(comp, &clen, data, (uLong)n, pl->s.level), Z_OK, Z_OK, Z_OK);
  unsigned char *out = rt_xmalloc(n);
  uLongf olen = (uLongf)n;
  uLong slen = clen;
  rt_check(uncompress2(out, &olen, comp, &slen), Z_OK, Z_OK, Z_OK);
  if (olen != (uLongf)n || slen != clen) abort();
  if (n != 0 && memcmp(out, data, n) != 0) abort();
  free(out);
  free(comp);
}

/* --- streaming ------------------------------------------------------------------------------------------------ */

typedef struct rt_run {
  const rt_plan *pl;
  z_stream ds, is;
  unsigned char *cbuf;  /* deflate's output, handed whole to inflate before the next deflate call */
  unsigned char *obuf;  /* inflate's output, checked after every call */
  unsigned long ik;     /* inflate calls so far */
  int inf_end;          /* inflate answered Z_STREAM_END */
  /* the bytes inflate must give back: whole-file mode */
  const unsigned char *exp;
  size_t exp_n, exp_off;
  /* streaming-file mode: the second descriptor (efd >= 0) */
  int efd;
  unsigned char *ebuf;
  size_t e_have, e_off;
} rt_run;

#define RT_GO 0
#define RT_STOP 1  /* a read failed: return normally, comparing nothing more */

static void run_init(rt_run *r, const rt_plan *pl) {
  memset(r, 0, sizeof *r);
  r->pl = pl;
  r->efd = -1;
  r->ds.zalloc = rt_zalloc;
  r->ds.zfree = rt_zfree;
  r->ds.opaque = Z_NULL;
  rt_check(deflateInit2(&r->ds, pl->s.level, Z_DEFLATED, pl->s.window_bits, pl->s.mem_level, pl->s.strategy), Z_OK,
           Z_OK, Z_OK);
  r->is.zalloc = rt_zalloc;
  r->is.zfree = rt_zfree;
  r->is.opaque = Z_NULL;
  r->is.next_in = Z_NULL;
  r->is.avail_in = 0;
  rt_check(inflateInit2(&r->is, pl->s.inf_window_bits), Z_OK, Z_OK, Z_OK);
  r->cbuf = rt_xmalloc(RT_PIECE_MAX);
  r->obuf = rt_xmalloc(RT_PIECE_MAX);
}

/* finished: deflate answered Z_STREAM_END, so deflateEnd must answer Z_OK; after a stop it may also answer
 * Z_DATA_ERROR ("freed prematurely") */
static void run_end(rt_run *r, int finished) {
  int dret = deflateEnd(&r->ds);
  if (finished)
    rt_check(dret, Z_OK, Z_OK, Z_OK);
  else
    rt_check(dret, Z_OK, Z_DATA_ERROR, Z_DATA_ERROR);
  rt_check(inflateEnd(&r->is), Z_OK, Z_OK, Z_OK);
  free(r->cbuf);
  free(r->obuf);
}

/* check the k bytes inflate just gave against the data */
static int expect(rt_run *r, const unsigned char *q, size_t k) {
  if (r->efd < 0) {
    if (k > r->exp_n - r->exp_off) abort();  /* more bytes than the data holds */
    if (k != 0 && memcmp(q, r->exp + r->exp_off, k) != 0) abort();
    r->exp_off += k;
    return RT_GO;
  }
  while (k > 0) {
    if (r->e_off == r->e_have) {
      size_t want = k < RT_PIECE_MAX ? k : RT_PIECE_MAX;
      ssize_t got = read(r->efd, r->ebuf, want);
      if (got < 0) return RT_STOP;
      if (got == 0) abort();  /* the file ends before inflate's output does */
      r->e_have = (size_t)got;
      r->e_off = 0;
    }
    size_t m = r->e_have - r->e_off;
    if (m > k) m = k;
    if (memcmp(q, r->ebuf + r->e_off, m) != 0) abort();
    q += m;
    k -= m;
    r->e_off += m;
  }
  return RT_GO;
}

/* one inflate call at the next inflate step, with a fresh output room; *moved says whether it took or gave a byte */
static int inflate_call(rt_run *r, int *moved) {
  const rt_step *st = &r->pl->i[r->ik % r->pl->ni];
  r->ik++;
  r->is.next_out = r->obuf;
  r->is.avail_out = (uInt)st->out;
  uInt in0 = r->is.avail_in;
  int ret = inflate(&r->is, st->flush);
  rt_check(ret, Z_OK, Z_BUF_ERROR, Z_STREAM_END);
  size_t got = st->out - r->is.avail_out;
  if (ret == Z_STREAM_END) r->inf_end = 1;
  *moved = got != 0 || r->is.avail_in != in0;
  return expect(r, r->obuf, got);
}

/* Hand inflate the clen compressed bytes at c, in inflate's own piece sizes, checking every byte it gives. With last
 * set these are the stream's final bytes, and inflate must answer Z_STREAM_END having used every one of them. */
static int inflate_feed(rt_run *r, const unsigned char *c, size_t clen, int last) {
  size_t off = 0;
  unsigned stall = 0;
  for (;;) {
    if (r->is.avail_in == 0 && off < clen) {
      size_t piece = r->pl->i[r->ik % r->pl->ni].in;
      if (piece > clen - off) piece = clen - off;
      r->is.next_in = (Bytef *)(uintptr_t)(c + off);
      r->is.avail_in = (uInt)piece;
      off += piece;
    }
    if (r->is.avail_in == 0 && off == clen && (!last || r->inf_end)) return RT_GO;
    if (r->inf_end) abort();  /* compressed bytes left after the end of the stream */
    int moved;
    int rc = inflate_call(r, &moved);
    if (rc != RT_GO) return rc;
    if (moved)
      stall = 0;
    else if (++stall > RT_STALL_MAX)
      abort();
  }
}

/* after a partial, sync or full flush: inflate, holding every compressed byte so far, gives back all the data so far */
static int inflate_drain(rt_run *r) {
  unsigned stall = 0;
  while (r->is.total_out < r->ds.total_in) {
    if (r->inf_end) abort();
    int moved;
    int rc = inflate_call(r, &moved);
    if (rc != RT_GO) return rc;
    if (moved)
      stall = 0;
    else if (++stall > RT_STALL_MAX)
      abort();
  }
  if (r->is.total_out != r->ds.total_in) abort();
  return RT_GO;
}

/* One deflate step: the n bytes at p with this flush (Z_FINISH: on to the end of the stream). Each call gets a fresh
 * output room, and what it gives goes to inflate before the next call, so a call that fills the room is followed by
 * one with the same flush and more room, as zlib.h asks. */
static int deflate_step(rt_run *r, const unsigned char *p, size_t n, int flush, size_t room) {
  unsigned stall = 0;
  room = rt_deflate_room(flush, room);
  r->ds.next_in = (Bytef *)(uintptr_t)p;
  r->ds.avail_in = (uInt)n;
  for (;;) {
    r->ds.next_out = r->cbuf;
    r->ds.avail_out = (uInt)room;
    uInt in0 = r->ds.avail_in;
    int ret = deflate(&r->ds, flush);
    rt_check(ret, Z_OK, Z_BUF_ERROR, flush == Z_FINISH ? Z_STREAM_END : Z_OK);
    size_t made = room - r->ds.avail_out;
    int full = r->ds.avail_out == 0;
    int moved = made != 0 || r->ds.avail_in != in0;
    int rc = inflate_feed(r, r->cbuf, made, ret == Z_STREAM_END);
    if (rc != RT_GO) return rc;
    if (ret == Z_STREAM_END) return RT_GO;
    if (flush != Z_FINISH && r->ds.avail_in == 0 && !full) break;
    if (moved)
      stall = 0;
    else if (++stall > RT_STALL_MAX)
      abort();
  }
  if (flush == Z_PARTIAL_FLUSH || flush == Z_SYNC_FLUSH || flush == Z_FULL_FLUSH) return inflate_drain(r);
  return RT_GO;
}

/* the end of a stream that reached Z_STREAM_END: every count agrees (total = the data's length) */
static void stream_done(rt_run *r, uLong total) {
  if (!r->inf_end) abort();
  if (r->ds.total_in != total || r->is.total_out != total || r->is.total_in != r->ds.total_out) abort();
  if (r->is.avail_in != 0) abort();
}

static void stream_mem(const rt_plan *pl, const unsigned char *data, size_t n) {
  rt_run r;
  run_init(&r, pl);
  r.exp = data;
  r.exp_n = n;
  size_t off = 0;
  unsigned long dk = 0;
  int finished = 0;
  while (off < n) {
    const rt_step *st = &pl->d[dk++ % pl->nd];
    size_t piece = n - off < st->in ? n - off : st->in;
    int flush = st->flush;
    if (pl->finish_last && off + piece == n) flush = Z_FINISH;
    (void)deflate_step(&r, data + off, piece, flush, st->out);  /* never RT_STOP: no reads in this mode */
    off += piece;
    if (flush == Z_FINISH) finished = 1;
  }
  if (!finished) (void)deflate_step(&r, data + n, 0, Z_FINISH, pl->d[dk % pl->nd].out);
  stream_done(&r, (uLong)n);
  if (r.exp_off != n) abort();
  run_end(&r, 1);
}

static void stream_file(const rt_plan *pl, const unsigned char *name, size_t len) {
  if (len == 0 || memchr(name, '/', len) != NULL || memchr(name, 0, len) != NULL) return;
  if ((len == 4 && memcmp(name, "proc", 4) == 0) || (len == 3 && memcmp(name, "sys", 3) == 0)) {
    /* a guard for a gap of the process model, which does not reach these two names in "/": refuse them only there
       (getcwd fits in 2 bytes only for "/"), and on any getcwd error but ERANGE */
    char cwd[2];
    if (getcwd(cwd, sizeof cwd) != NULL || errno != ERANGE) return;
  }
  char *path = rt_xmalloc(len + 1);
  memcpy(path, name, len);
  path[len] = 0;
  int fd1 = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd1 < 0) {
    free(path);
    return;
  }
  struct stat sb;
  if (fstat(fd1, &sb) != 0 || !S_ISREG(sb.st_mode)) {
    (void)close(fd1);
    free(path);
    return;
  }
  int fd2 = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  free(path);
  if (fd2 < 0) {
    (void)close(fd1);
    return;
  }
  if (fstat(fd2, &sb) != 0 || !S_ISREG(sb.st_mode)) {
    (void)close(fd1);
    (void)close(fd2);
    return;
  }
  rt_run r;
  run_init(&r, pl);
  unsigned char *rbuf = rt_xmalloc(RT_PIECE_MAX);
  r.efd = fd2;
  r.ebuf = rt_xmalloc(RT_PIECE_MAX);
  uLong total = 0;
  unsigned long dk = 0;
  int rc;
  for (;;) {
    const rt_step *st = &pl->d[dk++ % pl->nd];
    ssize_t got = read(fd1, rbuf, st->in);
    if (got < 0) {
      rc = RT_STOP;
      break;
    }
    if (got == 0) {
      rc = deflate_step(&r, rbuf, 0, Z_FINISH, st->out);
      break;
    }
    total += (uLong)got;
    rc = deflate_step(&r, rbuf, (size_t)got, st->flush, st->out);
    if (rc != RT_GO) break;
  }
  int finished = 0;
  if (rc == RT_GO) {
    stream_done(&r, total);
    finished = 1;
    if (r.e_off != r.e_have) abort();
    ssize_t got = read(fd2, r.ebuf, RT_PIECE_MAX);  /* the second pass must be at the end of the file too */
    if (got > 0) abort();                            /* the file is longer than inflate's output */
  }
  run_end(&r, finished);
  free(rbuf);
  free(r.ebuf);
  (void)close(fd1);  /* a failed close changes nothing: the comparison is complete or was abandoned */
  (void)close(fd2);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t empty[1] = {0};
  rt_cur c = {data != NULL ? data : empty, data != NULL ? size : 0};
  rt_plan pl;
  plan_decode(&c, &pl);
  const uint8_t *rest;
  size_t n = rt_take(&c, SIZE_MAX, &rest);
  if (pl.file_mode) {
    stream_file(&pl, rest, n);
  } else {
    oneshot(&pl, rest, n);
    stream_mem(&pl, rest, n);
  }
  return 0;
}
