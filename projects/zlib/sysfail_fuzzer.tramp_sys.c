/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: MIT
 * tramp_sys.c - the six file-system-call trampolines, the one in-memory regular
 * file they answer from, and the per-kind failure schedule. See tramp_sys.h for
 * the contract (what a schedule entry means, rules (a)-(f), the non-claims).
 * What is specific to this translation unit:
 *
 * THE FLAG VALUES ARE LINUX'S, SPELLED HERE. The library passes open/fcntl
 * flags compiled against the libc's headers; the model interprets them with
 * the asm-generic octal values below, and every one the libc also defines is
 * checked against it at compile time, so a libc whose values differ breaks the
 * build instead of making the model read a different flag. O_LARGEFILE is the
 * one the libcs spell differently (glibc on x86-64 defines it as 0 for user
 * space; the kernel sets 0100000 in every 64-bit description), so the model
 * accepts both spellings in open and reports the kernel's in F_GETFL. errno
 * values are the libc's own macros: the library compares errno against them.
 *
 * ORDER OF EVERY TRAMPOLINE: tick (rule (a)), then the model's own answer
 * without changing any state, then the injection decision on a model success
 * (rules (b), (f)), then the state change, then the return. A failure the
 * model itself produces (EBADF on a closed descriptor) is never replaced.
 * fcntl ticks and never injects: it has no failure class.
 * THE FILE: `fsize` is its size as the Linux model and the kernel state it, any
 * 64-bit value a write can reach. `fbytes` STORES its first TRAMP_SYS_FILE_MAX
 * bytes, with the invariant that every stored byte at or past `fsize` is zero.
 * Truncation zeroes [new, old) of the stored part; growth by a write past the
 * end therefore reads the gap as zeros with no memset, and the total cost of a
 * run is O(bytes written + bytes truncated). Bytes past TRAMP_SYS_FILE_MAX are
 * counted, not kept: a write lands all of them as far as every answer goes
 * (count, offset, size), and a read of them returns zeros (tramp_sys.h, "PAST
 * TRAMP_SYS_FILE_MAX"; the driver stops every file operation once the file is
 * that large, so zlib never reads one). The file starts PRESENT and empty
 * (`fabsent` is zero-initialised so even a process that never calls
 * tramp_sysm_reset starts that way).
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "tramp_sys.h"

/* ------------------------------------------------- Linux's flag values ---- */
#define M_O_ACCMODE   03
#define M_O_RDONLY    00
#define M_O_WRONLY    01
#define M_O_RDWR      02
#define M_O_CREAT     0100
#define M_O_EXCL      0200
#define M_O_NOCTTY    0400
#define M_O_TRUNC     01000
#define M_O_APPEND    02000
#define M_O_NONBLOCK  04000
#define M_O_DIRECT    040000
#define M_O_LARGEFILE 0100000
#define M_O_NOATIME   01000000
#define M_O_CLOEXEC   02000000
#define M_F_GETFD     1
#define M_F_SETFD     2
#define M_F_GETFL     3
#define M_F_SETFL     4
#define M_FD_CLOEXEC  1
#define M_SEEK_SET    0
#define M_SEEK_CUR    1
#define M_SEEK_END    2

#if defined(O_ACCMODE)
/* musl spells O_ACCMODE as (03|O_PATH) (measured: the first riscv64 build of
 * this file stopped here, 2097155 != 3), glibc as 03; the access-mode bits are
 * 03 in both, and they are what the model reads. */
_Static_assert((O_ACCMODE & 03) == M_O_ACCMODE, "O_ACCMODE's access-mode bits are not Linux's");
#endif
_Static_assert(O_RDONLY == M_O_RDONLY && O_WRONLY == M_O_WRONLY && O_RDWR == M_O_RDWR, "access modes are not Linux's");
_Static_assert(O_CREAT == M_O_CREAT, "O_CREAT is not Linux's asm-generic value");
_Static_assert(O_EXCL == M_O_EXCL, "O_EXCL is not Linux's asm-generic value");
_Static_assert(O_NOCTTY == M_O_NOCTTY, "O_NOCTTY is not Linux's asm-generic value");
_Static_assert(O_TRUNC == M_O_TRUNC, "O_TRUNC is not Linux's asm-generic value");
_Static_assert(O_APPEND == M_O_APPEND, "O_APPEND is not Linux's asm-generic value");
_Static_assert(O_NONBLOCK == M_O_NONBLOCK, "O_NONBLOCK is not Linux's asm-generic value");
#if defined(O_DIRECT)
_Static_assert(O_DIRECT == M_O_DIRECT, "O_DIRECT is not Linux's asm-generic value");
#endif
#if defined(O_NOATIME)
_Static_assert(O_NOATIME == M_O_NOATIME, "O_NOATIME is not Linux's asm-generic value");
#endif
#if defined(O_CLOEXEC)
_Static_assert(O_CLOEXEC == M_O_CLOEXEC, "O_CLOEXEC is not Linux's asm-generic value");
#endif
#if defined(O_LARGEFILE)
_Static_assert(O_LARGEFILE == 0 || O_LARGEFILE == M_O_LARGEFILE, "O_LARGEFILE is neither 0 nor Linux's value");
#define LIBC_O_LARGEFILE O_LARGEFILE
#else
#define LIBC_O_LARGEFILE 0
#endif
_Static_assert(F_GETFD == M_F_GETFD && F_SETFD == M_F_SETFD && F_GETFL == M_F_GETFL && F_SETFL == M_F_SETFL,
               "fcntl commands are not Linux's");
_Static_assert(FD_CLOEXEC == M_FD_CLOEXEC, "FD_CLOEXEC is not Linux's");
_Static_assert(SEEK_SET == M_SEEK_SET && SEEK_CUR == M_SEEK_CUR && SEEK_END == M_SEEK_END, "whence values are not Linux's");
_Static_assert(sizeof(off_t) == 8, "the model's offsets are 64-bit; off_t is not");
_Static_assert(sizeof(size_t) == 8, "the file's size and every count are 64-bit here; size_t is not");

/* The kernel's MAX_RW_COUNT, INT_MAX & PAGE_MASK at 4 KiB pages (riscv64 and
 * x86-64 alike): vfs_read and vfs_write move at most this many bytes per call,
 * after rw_verify_area has checked the count the call named. The Linux model
 * clamps both directions the same way. zlib never asks for more than 1 GiB in
 * one call (gzread.c, gzwrite.c: `max`), so this is the model's answer kept,
 * not one zlib can tell from the unclamped one. */
#define MAX_RW_COUNT ((size_t)0x7ffff000)

/* What open accepts; anything else is EINVAL (a documented non-claim). */
#define OPEN_OK_BITS (M_O_ACCMODE | M_O_CREAT | M_O_EXCL | M_O_TRUNC | M_O_APPEND | M_O_NONBLOCK | \
                      M_O_CLOEXEC | M_O_NOCTTY | M_O_LARGEFILE | LIBC_O_LARGEFILE)
/* What a description keeps from open's flags (F_GETFL shows them). */
#define OPEN_STATUS_BITS (M_O_APPEND | M_O_NONBLOCK)
/* What F_SETFL may change: Linux's SETFL_MASK, measured on tmpfs under Linux
 * 6.12 (an F_SETFL of -1 on an O_RDWR descriptor read back 0x4cc02: these four,
 * O_LARGEFILE and the access mode; FASYNC does not stick on tmpfs, which has no
 * fasync method). O_DIRECT sticks only on a kernel whose tmpfs supports it (6.6
 * and later); see tramp_sys.h's non-claims. */
#define SETFL_BITS (M_O_APPEND | M_O_NONBLOCK | M_O_DIRECT | M_O_NOATIME)

/* ------------------------------------------------------------- state ----- */
static unsigned char fbytes[TRAMP_SYS_FILE_MAX];   /* the stored part: bytes [0, TRAMP_SYS_FILE_MAX) */
static size_t fsize;                         /* the size, which may pass TRAMP_SYS_FILE_MAX */
static int fabsent;                          /* 0 = present (the initial state) */

/* Past TRAMP_SYS_FILE_MAX: a write's bytes are read from the caller's buffer into
 * `sink` and dropped (so in the asan flavours the memcpy interceptor still
 * checks every byte a kernel's copy would read), and a read returns `zeros`. */
static unsigned char sink[4096];
static const unsigned char zeros[4096];

typedef struct {
  int used;
  int acc;          /* M_O_RDONLY / M_O_WRONLY / M_O_RDWR */
  int status;       /* SETFL_BITS subset */
  int cloexec;
  int64_t off;
} tramp_desc;
static tramp_desc fds[TRAMP_SYS_NFD];

static unsigned char plan_tab[TRAMP_SYS_NKINDS][TRAMP_SYS_PLAN_MAX];
static unsigned plan_len[TRAMP_SYS_NKINDS];
static unsigned plan_pos[TRAMP_SYS_NKINDS];
static unsigned call_total[TRAMP_SYS_NKINDS];

/* fcntl has one class, success: its entries are spent and decide nothing
 * (tramp_sys_fcntl). */
static const unsigned nclass[TRAMP_SYS_NKINDS] = { 6, 6, 3, 5, 3, 1 };

/* The short-count table; 0 marks the two sentinels at 22 (m/2) and 23 (m-1). */
static const size_t short_tab[TRAMP_SYS_SHORT_N] = {
  1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
  511, 512, 1023, 1024, 4095, 4096, 0, 0
};

/* --------------------------------------------------------- the schedule -- */

/* Rule (a): count the call, and return its entry byte, or -1 past the table. */
static int tick(unsigned kind) {
  unsigned i = plan_pos[kind]++;
  call_total[kind]++;
  return i < plan_len[kind] ? (int)plan_tab[kind][i] : -1;
}

static unsigned entry_class(unsigned kind, int e) { return e < 0 ? 0u : (unsigned)e % nclass[kind]; }
static unsigned entry_arg(unsigned kind, int e) { return e < 0 ? 0u : (unsigned)e / nclass[kind]; }

/* k for a short transfer of a model count m >= 2: always in [1, m-1]. */
static size_t short_count(size_t m, unsigned arg) {
  unsigned idx = arg % TRAMP_SYS_SHORT_N;
  size_t k;
  if (idx == 22) k = m / 2;
  else if (idx == 23) k = m - 1;
  else k = short_tab[idx];
  if (k < 1) k = 1;
  if (k > m - 1) k = m - 1;
  return k;
}

/* --------------------------------------------------------- the file ------ */

/* The stored part keeps the invariant: every stored byte at or past fsize is 0. */
static void file_truncate(size_t n) {
  size_t top = fsize < TRAMP_SYS_FILE_MAX ? fsize : TRAMP_SYS_FILE_MAX;
  if (n < top) memset(fbytes + n, 0, top - n);
  fsize = n;
}

/* n bytes of the file from position pos into dst: the stored part, then zeros. */
static void file_copy_out(unsigned char *dst, uint64_t pos, size_t n) {
  size_t a = 0, c;
  if (pos < TRAMP_SYS_FILE_MAX) {
    a = TRAMP_SYS_FILE_MAX - (size_t)pos;
    if (a > n) a = n;
    memcpy(dst, fbytes + (size_t)pos, a);
  }
  for (; a < n; a += c) {
    c = n - a < sizeof zeros ? n - a : sizeof zeros;
    memcpy(dst + a, zeros, c);
  }
}

/* n bytes from src into the file at position pos: the part below
 * TRAMP_SYS_FILE_MAX is stored, the rest is read and dropped. The empty asm
 * tells the compiler the sink's bytes are used, so it cannot delete the copies
 * that make the asan flavours check the source. */
static void file_copy_in(uint64_t pos, const unsigned char *src, size_t n) {
  size_t a = 0, c;
  if (pos < TRAMP_SYS_FILE_MAX) {
    a = TRAMP_SYS_FILE_MAX - (size_t)pos;
    if (a > n) a = n;
    memcpy(fbytes + (size_t)pos, src, a);
  }
  for (; a < n; a += c) {
    c = n - a < sizeof sink ? n - a : sizeof sink;
    memcpy(sink, src + a, c);
    __asm__ __volatile__("" : : "r"(sink) : "memory");
  }
}

static tramp_desc *desc_of(int fd) {
  if (fd < TRAMP_SYS_FD_BASE || fd >= TRAMP_SYS_FD_BASE + TRAMP_SYS_NFD) return NULL;
  if (!fds[fd - TRAMP_SYS_FD_BASE].used) return NULL;
  return &fds[fd - TRAMP_SYS_FD_BASE];
}

static int nfds_open(void) {
  int i, n = 0;
  for (i = 0; i < TRAMP_SYS_NFD; i++) n += fds[i].used != 0;
  return n;
}

/* open's checks, in Linux's order (flags, then the descriptor, then the
 * lookup): 0 if the open would succeed, else the errno. No state changes. */
static int open_check(int flags) {
  if ((flags & ~OPEN_OK_BITS) != 0) return EINVAL;
  if ((flags & M_O_ACCMODE) == M_O_ACCMODE) return EINVAL;
  if (nfds_open() >= TRAMP_SYS_NFD) return EMFILE;
  if (fabsent && !(flags & M_O_CREAT)) return ENOENT;
  if (!fabsent && (flags & M_O_CREAT) && (flags & M_O_EXCL)) return EEXIST;
  return 0;
}

/* The state change of a successful open; returns the descriptor. */
static int open_commit(int flags) {
  int i;
  if (fabsent) { fabsent = 0; file_truncate(0); }
  else if (flags & M_O_TRUNC) file_truncate(0);   /* every access mode, as tmpfs does */
  for (i = 0; i < TRAMP_SYS_NFD; i++) {
    if (!fds[i].used) {
      fds[i].used = 1;
      fds[i].acc = flags & M_O_ACCMODE;
      fds[i].status = flags & OPEN_STATUS_BITS;
      fds[i].cloexec = (flags & M_O_CLOEXEC) != 0;
      fds[i].off = 0;
      return TRAMP_SYS_FD_BASE + i;
    }
  }
  return -1;   /* unreachable: open_check refused a full table */
}

static int getfl_of(const tramp_desc *d) { return d->acc | d->status | M_O_LARGEFILE; }

/* The kernel's rw_verify_area, which read and write run after access_ok and
 * before any transfer: EINVAL when offset + count passes LLONG_MAX (the
 * differential found the model answering 0 or writing where the kernel says
 * EINVAL, at an offset lseek had put at or near LLONG_MAX). n <= SSIZE_MAX and
 * off >= 0 here, so the unsigned sum cannot wrap 2^64. */
static int rw_overflows(int64_t off, size_t n) {
  return (int64_t)((uint64_t)off + (uint64_t)n) < 0;
}

/* null_faults: a NULL buffer is EFAULT only where the kernel's copy would touch
 * it. access_ok passes address 0 (it checks the range against TASK_SIZE only),
 * rw_verify_area runs next, and the fault comes from the copy itself, so read
 * at end of file answers 0, write of 0 bytes answers 0, an offset + count past
 * LLONG_MAX is EINVAL, and only a transfer of at least one byte is EFAULT,
 * with nothing changed. Refusing every NULL buffer with a nonzero count up
 * front would not be the kernel's answer: at end of file a read answers 0,
 * not EFAULT, and an offset + count past LLONG_MAX answers EINVAL, not
 * EFAULT. */

/* ------------------------------------------------------- trampolines ----- */

int tramp_sys_open(const char *path, int flags, ...) {
  int e = tick(TRAMP_SYS_OPEN), err;
  unsigned cls;
  (void)path;                       /* paths are not a filesystem */
  err = open_check(flags);
  if (err) { errno = err; return -1; }
  /* The four errnos the Linux model's open may choose for a call it would
   * otherwise answer (its environment failures). ENOENT and EEXIST are never
   * injected: the model answers them from the file's state, deterministically,
   * and so does open_check above. */
  cls = entry_class(TRAMP_SYS_OPEN, e);
  switch (cls) {
    case 1: errno = ENOMEM; return -1;
    case 2: errno = EACCES; return -1;
    case 3: errno = EMFILE; return -1;
    case 4: errno = ENFILE; return -1;
    default: break;
  }
  return open_commit(flags);
}

ssize_t tramp_sys_read(int fd, void *buf, size_t n) {
  int e = tick(TRAMP_SYS_READ);
  tramp_desc *d = desc_of(fd);
  size_t m, k;
  unsigned cls;
  if (d == NULL || d->acc == M_O_WRONLY) { errno = EBADF; return -1; }
  if (n > (size_t)SSIZE_MAX) { errno = EFAULT; return -1; }
  if (rw_overflows(d->off, n)) { errno = EINVAL; return -1; }
  m = (d->off >= 0 && (uint64_t)d->off < (uint64_t)fsize) ? (size_t)(fsize - (size_t)d->off) : 0;
  if (m > n) m = n;
  if (m > MAX_RW_COUNT) m = MAX_RW_COUNT;
  if (buf == NULL && m != 0) { errno = EFAULT; return -1; }   /* null_faults */
  cls = entry_class(TRAMP_SYS_READ, e);
  k = m;
  switch (cls) {
    case 1: if (m >= 2) k = short_count(m, entry_arg(TRAMP_SYS_READ, e)); break;
    case 2: return 0;               /* early end of file: nothing moves */
    case 3: errno = EIO; return -1;
    case 4: errno = EINTR; return -1;
    case 5:
      if (d->status & M_O_NONBLOCK) { errno = EAGAIN; return -1; }
      break;                        /* rule (f) */
    default: break;
  }
  if (k) file_copy_out((unsigned char *)buf, (uint64_t)d->off, k);
  d->off += (int64_t)k;
  return (ssize_t)k;
}

ssize_t tramp_sys_write(int fd, const void *buf, size_t n) {
  int e = tick(TRAMP_SYS_WRITE);
  tramp_desc *d = desc_of(fd);
  uint64_t pos;
  size_t w, k;
  unsigned cls;
  if (d == NULL || d->acc == M_O_RDONLY) { errno = EBADF; return -1; }
  if (n > (size_t)SSIZE_MAX) { errno = EFAULT; return -1; }
  /* Against the descriptor's OFFSET even under O_APPEND, where the bytes go to
   * the end of the file: the kernel checks f_pos before it repositions. */
  if (rw_overflows(d->off, n)) { errno = EINVAL; return -1; }
  if (n == 0) {
    /* Linux returns 0 before positioning: the offset does not move, even with
     * O_APPEND. Injections still apply to the success (rule (b)). */
    cls = entry_class(TRAMP_SYS_WRITE, e);
    switch (cls) {
      case 2: errno = ENOSPC; return -1;
      case 3: errno = EIO; return -1;
      case 4: errno = EINTR; return -1;
      case 5: if (d->status & M_O_NONBLOCK) { errno = EAGAIN; return -1; } break;
      default: break;
    }
    return 0;
  }
  /* Every byte lands, as the Linux model says and the kernel on a tmpfs with
   * room does: no unscheduled short count and no ENOSPC, at any size (a short
   * count at 1 MiB, or ENOSPC past it, would be answers zlib could reach with
   * no schedule, and the model never gives). Past TRAMP_SYS_FILE_MAX the bytes
   * are counted and dropped (file_copy_in). Then the kernel's two limits, which
   * zlib cannot reach: MAX_RW_COUNT, and tmpfs's s_maxbytes (LLONG_MAX), where
   * generic_write_check_limits answers EFBIG at the limit and clamps the count
   * below it. Only an O_APPEND write can meet the second: rw_overflows has
   * already refused an offset + count past LLONG_MAX. */
  pos = (d->status & M_O_APPEND) ? (uint64_t)fsize : (uint64_t)d->off;
  if (pos >= (uint64_t)INT64_MAX) { errno = EFBIG; return -1; }
  w = n < MAX_RW_COUNT ? n : MAX_RW_COUNT;                     /* the kernel's clamp, and the model's */
  if ((uint64_t)w > (uint64_t)INT64_MAX - pos) w = (size_t)((uint64_t)INT64_MAX - pos);
  if (buf == NULL) { errno = EFAULT; return -1; }   /* null_faults: w >= 1 bytes would move */
  cls = entry_class(TRAMP_SYS_WRITE, e);
  k = w;
  switch (cls) {
    case 1: if (w >= 2) k = short_count(w, entry_arg(TRAMP_SYS_WRITE, e)); break;
    case 2: errno = ENOSPC; return -1;
    case 3: errno = EIO; return -1;
    case 4: errno = EINTR; return -1;
    case 5:
      if (d->status & M_O_NONBLOCK) { errno = EAGAIN; return -1; }
      break;
    default: break;
  }
  file_copy_in(pos, (const unsigned char *)buf, k);
  if (pos + k > (uint64_t)fsize) fsize = (size_t)(pos + k);
  d->off = (int64_t)(pos + k);
  return (ssize_t)k;
}

off_t tramp_sys_lseek(int fd, off_t off, int whence) {
  int e = tick(TRAMP_SYS_LSEEK);
  tramp_desc *d = desc_of(fd);
  uint64_t base;
  int64_t nw;
  unsigned cls;
  if (d == NULL) { errno = EBADF; return -1; }
  switch (whence) {
    case M_SEEK_SET: base = 0; break;
    case M_SEEK_CUR: base = (uint64_t)d->off; break;
    case M_SEEK_END: base = (uint64_t)fsize; break;
    default: errno = EINVAL; return -1;       /* SEEK_DATA/SEEK_HOLE: a non-claim */
  }
  /* Wrapping addition, as the kernel computes it (it builds with
   * -fno-strict-overflow): CUR +1 from LLONG_MAX and END +LLONG_MAX both wrap
   * negative, and a negative result is EINVAL. Unsigned here, so no C overflow. */
  nw = (int64_t)(base + (uint64_t)(int64_t)off);
  if (nw < 0) { errno = EINVAL; return -1; }
  cls = entry_class(TRAMP_SYS_LSEEK, e);
  if (cls == 1) { errno = ESPIPE; return -1; }
  if (cls == 2) { errno = EINVAL; return -1; }
  d->off = nw;
  return (off_t)nw;
}

int tramp_sys_close(int fd) {
  int e = tick(TRAMP_SYS_CLOSE);
  tramp_desc *d = desc_of(fd);
  unsigned cls;
  if (d == NULL) { errno = EBADF; return -1; }
  d->used = 0;                      /* rule (d): released whatever close then says */
  cls = entry_class(TRAMP_SYS_CLOSE, e);
  if (cls == 1) { errno = EIO; return -1; }
  /* Class 2 is the kernel's -EINTR, answered as musl's close answers it: 0,
   * errno untouched (src/unistd/close.c, `if (r == -EINTR) r = 0;`; measured in
   * the riscv64 libc.a's close.lo, a compare with -4 and a branch to 0). This
   * trampoline REPLACES musl's close in zlib's objects, so it must give zlib
   * musl's answer, which is also the Linux model's (its close never fails) and
   * the proofs' gz model's (c_close). -1/EINTR, the glibc answer, would be
   * neither, and a differential against the kernel on glibc cannot tell. */
  if (cls == 2) return 0;           /* EINTR as musl reports it: rule (d) */
  return 0;
}

int tramp_sys_fcntl(int fd, int cmd, ...) {
  tramp_desc *d;
  int arg = 0, r;
  va_list ap;
  /* Rule (a): the call is counted and its entry, if any, is spent. But fcntl
   * has NO failure class, so the entry decides nothing. EBADF injected on an
   * OPEN descriptor would be an answer Linux never gives (rule (f)), and
   * through zlib's unchecked F_GETFL (gzdopen "N", gzlib.c:261) it would make
   * zlib's F_SETFL(-1 | O_NONBLOCK) set O_APPEND. */
  (void)tick(TRAMP_SYS_FCNTL);
  d = desc_of(fd);
  if (d == NULL) { errno = EBADF; return -1; }     /* the descriptor before the command */
  switch (cmd) {
    case M_F_GETFL: r = getfl_of(d); break;
    case M_F_GETFD: r = d->cloexec ? M_FD_CLOEXEC : 0; break;
    case M_F_SETFL:
    case M_F_SETFD:
      /* The third argument is read only for the two commands that take one;
       * zlib's F_GETFL/F_GETFD calls pass none (gzlib.c:261,265). */
      va_start(ap, cmd);
      arg = va_arg(ap, int);
      va_end(ap);
      r = 0;
      break;
    default: errno = EINVAL; return -1;
  }
  if (cmd == M_F_SETFL) d->status = arg & SETFL_BITS;
  else if (cmd == M_F_SETFD) d->cloexec = (arg & M_FD_CLOEXEC) != 0;
  return r;
}

/* ------------------------------------------------------- driver API ------ */

void tramp_sysm_reset(void) {
  file_truncate(0);
  fabsent = 0;
  memset(fds, 0, sizeof fds);
  memset(plan_len, 0, sizeof plan_len);
  memset(plan_pos, 0, sizeof plan_pos);
  memset(call_total, 0, sizeof call_total);
}

void tramp_sysm_plan(unsigned kind, const unsigned char *entries, size_t n) {
  if (kind >= TRAMP_SYS_NKINDS) {
    memset(plan_len, 0, sizeof plan_len);
    memset(plan_pos, 0, sizeof plan_pos);
    return;
  }
  if (entries == NULL) n = 0;
  if (n > TRAMP_SYS_PLAN_MAX) n = TRAMP_SYS_PLAN_MAX;
  if (n) memcpy(plan_tab[kind], entries, n);
  plan_len[kind] = (unsigned)n;
  plan_pos[kind] = 0;
}

unsigned tramp_sysm_calls(unsigned kind) { return kind < TRAMP_SYS_NKINDS ? call_total[kind] : 0u; }

int tramp_sysm_file_set(const void *p, size_t n) {
  if (n > TRAMP_SYS_FILE_MAX || (p == NULL && n != 0)) return -1;
  fabsent = 0;
  file_truncate(0);
  if (n) memcpy(fbytes, p, n);
  fsize = n;
  return 0;
}

size_t tramp_sysm_file_get(void *dst, size_t cap) {
  size_t n = fabsent ? 0 : fsize;
  if (n > cap) n = cap;
  if (n && dst != NULL) file_copy_out((unsigned char *)dst, 0, n);
  return dst != NULL ? n : 0;
}

size_t tramp_sysm_file_size(void) { return fabsent ? 0 : fsize; }
int tramp_sysm_file_present(void) { return !fabsent; }

/* Over the STORED part only (at most TRAMP_SYS_FILE_MAX bytes): past it the
 * content is not kept, and the driver asks for no digest then (it stops every
 * file operation once the file is past TRAMP_SYS_FILE_MAX). */
uint64_t tramp_sysm_file_digest(void) {
  uint64_t h = 1469598103934665603ULL;
  size_t i, n = fabsent ? 0 : fsize < TRAMP_SYS_FILE_MAX ? fsize : TRAMP_SYS_FILE_MAX;
  for (i = 0; i < n; i++) { h ^= (uint64_t)fbytes[i]; h *= 1099511628211ULL; }
  return h;
}

int tramp_sysm_unlink(void) {
  if (fabsent || nfds_open() != 0) return -1;
  file_truncate(0);
  fabsent = 1;
  return 0;
}

int tramp_sysm_open(int flags) {
  int err = open_check(flags);
  if (err) { errno = err; return -1; }
  return open_commit(flags);
}

int tramp_sysm_close(int fd) {
  tramp_desc *d = desc_of(fd);
  if (d == NULL) { errno = EBADF; return -1; }
  d->used = 0;
  return 0;
}

int tramp_sysm_nfds(void) { return nfds_open(); }

int tramp_sysm_fd_info(int fd, int64_t *off, int *flags, int *cloexec) {
  tramp_desc *d = desc_of(fd);
  if (d == NULL) return -1;
  if (off) *off = d->off;
  if (flags) *flags = getfl_of(d);
  if (cloexec) *cloexec = d->cloexec;
  return 0;
}
