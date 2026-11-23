/* tramp_sys.h - the system-call failure schedule and the one in-memory file it
 * acts on, for a DSL driver whose library makes file system calls (zlib's
 * gz functions).
 *
 * WHAT THIS IS. A DSL driver may not touch the filesystem (src/dsl.h rule 4:
 * the run must be a function of the input alone). A library whose file layer
 * calls open/read/write/lseek/close/fcntl (zlib's gz* functions) is therefore
 * given ONE in-memory regular file instead of a filesystem, and every one of
 * those six calls the LIBRARY makes is answered here, by tramp_sys.c, without a
 * system call. build.sh renames the six names in a derived copy of the
 * pin-built archive to the tramp_sys_<name> trampolines below (src/tramp_sys.redefs,
 * the same llvm-objcopy --redefine-syms mechanism the allocation schedule uses;
 * OV_DSL_LIBRARY_REDEFS). The driver object, cli.o, libc and the sanitizer
 * runtime are never renamed, so the driver's own reading of its input and its
 * writes to stdout are real system calls that no schedule can fail.
 *
 * PATHS ARE NOT A FILESYSTEM. Any path names the one file; the path string is
 * never read. A successful call answers exactly as Linux answers for one
 * regular file on tmpfs (O_RDONLY/O_WRONLY/O_RDWR, O_CREAT, O_EXCL, O_TRUNC,
 * O_APPEND, O_NONBLOCK, O_CLOEXEC; lseek SEEK_SET/CUR/END including past the
 * end, where the gap reads as zeros; reads at end of file return 0; writes
 * extend; descriptors are the lowest free number; a closed number is reused).
 * a differential test runs the same random call sequences against this model
 * and against the kernel on tmpfs and compares every return value, errno,
 * byte, offset and descriptor flag; that differential is the evidence, not
 * this comment.
 *
 * AND AS THE LINUX MODEL ANSWERS. The zlib team's proofs reason with the
 * Linux model (LPS), not with the kernel, so every success answer here
 * must also be that model's. Where the model and the kernel differ, the
 * model's answer is the one given, unless zlib cannot reach the case through
 * the driver; the driver's design notes, "The Linux model and the
 * kernel", lists every such difference and which side this file takes.
 * A model test checks the zlib team's table of the model's
 * answers row by row.
 *
 * THE SCHEDULE. For each of the six kinds there is a table of entry bytes,
 * installed by the driver from the fuzz input (tramp_sysm_plan). Entry i decides
 * the i-th call of that kind the library makes after the table was installed:
 * class = byte % NCLASS[kind], arg = byte / NCLASS[kind].
 *
 *   read   (6)  0 success  1 short  2 zero (early EOF)  3 EIO  4 EINTR  5 EAGAIN
 *   write  (6)  0 success  1 short  2 ENOSPC  3 EIO  4 EINTR  5 EAGAIN
 *   lseek  (3)  0 success  1 ESPIPE  2 EINVAL
 *   open   (5)  0 success  1 ENOMEM  2 EACCES  3 EMFILE  4 ENFILE
 *   close  (3)  0 success  1 EIO  2 EINTR, answered as musl's close answers
 *                it: 0, errno untouched, the descriptor released
 *   fcntl  (1)  0 success: NO failure class. Its table is installed and its
 *                entries are spent one per call like any kind's, and every
 *                byte means success, so an fcntl entry changes no answer and
 *                no state. The kind byte keeps its number (5) and "6 clears
 *                every table" keeps its, so every other kind's encoding is
 *                byte for byte what it was.
 *
 * fcntl had one class until review round 3: 1 was EBADF, injected on an OPEN
 * descriptor. Linux answers EBADF only for a descriptor that is not open, so
 * rule (f) below forbids that injection; and zlib does not check F_GETFL's
 * result (gzdopen with "N", gzlib.c:261), so the injected -1 became
 * F_SETFL(-1 | O_NONBLOCK) and set O_APPEND on zlib's descriptor. Nothing
 * replaced it: the Linux model never fails F_SETFD or a no-op F_SETFL on an
 * open descriptor, and declines the other commands zlib makes.
 *
 * open's four are the Linux model's own environment failures, the errnos it
 * may choose for an open it would otherwise answer. ENOENT and EEXIST are never
 * injected: the model gives them from the file's state alone (a missing file
 * without O_CREAT; O_CREAT|O_EXCL on a present one), and so does this file.
 * (Before review round 2, classes 1 and 4 were ENOENT, injected on a present
 * file, and EEXIST, injected only with O_CREAT|O_EXCL.) close's class 2 is
 * the kernel's -EINTR as a musl program sees it: musl's close maps it to 0
 * (src/unistd/close.c), the trampoline replaces musl's close in zlib's
 * objects, so it gives zlib musl's 0 (before round 2 it returned -1/EINTR, the
 * glibc answer, which the Linux model and the zlib team's gz model never give).
 *
 * A short transfer moves k bytes, k = TRAMP_SYS_SHORT[arg % 24] clamped to
 * [1, m-1] where m is what the model would have moved (index 22 is m/2, index
 * 23 is m-1); a short with m < 2 is the model's own answer. "1 byte" is entry
 * 0x01 and "EIO" is entry 0x03 for read. Beyond the end of a table, and before
 * any table, every call SUCCEEDS (the allocation schedule's "past the end is
 * inert").
 *
 * The rules that make a schedule mean the same thing everywhere:
 *   (a) every trampoline ticks its kind's counter FIRST, before any argument is
 *       looked at (tramp_alloc_deny does the same);
 *   (b) an injected outcome applies only when the model's own answer would be a
 *       success; a call the model refuses (EBADF, ...) keeps the model's error;
 *   (c) an injected -1 changes no state (open: no create, no truncate, no
 *       descriptor), a short transfer moves exactly k bytes and advances the
 *       offset by k, a zero read moves nothing;
 *   (d) an injected close failure RELEASES the descriptor, which is what Linux
 *       does, and then returns -1/EIO, or 0 for EINTR (musl's answer);
 *   (e) errno is set on every -1 and left untouched on success;
 *   (f) an injected errno Linux cannot return for that call is not injected and
 *       the model's answer stands: EAGAIN only on a descriptor with O_NONBLOCK
 *       (the model's table: "EAGAIN in N mode"); and no fcntl failure at all, since
 *       EBADF on an open descriptor was the only one it had.
 *
 * DOCUMENTED NON-CLAIMS (the model answers these, and the answers are not
 * Linux's; the differential's generator never produces them and its unit cases
 * pin the answers below):
 *   - path-dependent errors (EACCES, ENOTDIR, ENAMETOOLONG, ELOOP, ...) exist
 *     only as injections; the path is never examined;
 *   - open flag bits outside O_ACCMODE|O_CREAT|O_EXCL|O_TRUNC|O_APPEND|
 *     O_NONBLOCK|O_CLOEXEC|O_NOCTTY|O_LARGEFILE, and access mode 3, answer
 *     EINVAL (Linux ignores unknown bits and opens mode 3 as a no-I/O
 *     descriptor);
 *   - lseek SEEK_DATA/SEEK_HOLE answer EINVAL (Linux supports them; zlib uses
 *     only SEEK_SET/CUR/END: gzlib.c:275,281,365,403,485);
 *   - PAST TRAMP_SYS_FILE_MAX the bytes are not stored. Every answer is still
 *     the model's (and an unfull tmpfs's): a write lands all n bytes as far as
 *     its count, the offset and the size go, at any size (the kernel's
 *     MAX_RW_COUNT clamp and tmpfs's LLONG_MAX limit, EFBIG, are kept); but a
 *     read of a byte at or past TRAMP_SYS_FILE_MAX returns 0 where the model
 *     returns what was written, and tramp_sysm_file_digest covers the stored
 *     part only. zlib cannot reach that read through the driver: once the
 *     file is larger than TRAMP_SYS_FILE_MAX, the driver skips every file
 *     operation for the rest of the repeat, with a `file_cap` note (dsl.c),
 *     and zlib reads its file only inside such an operation. (Review round 2:
 *     the first draft cut a write short at the cap and refused one past it
 *     with ENOSPC, answers the model never gives, and zlib reached them with no
 *     schedule: a "wT" handle, 17 forward gzseeks of 65535, then gzputc.);
 *   - TRAMP_SYS_NFD descriptors, numbered 3..66, lowest first; 0, 1 and 2 answer
 *     EBADF. In the Linux model they are the process's open stdin, stdout and
 *     stderr; the driver never hands zlib one of them (its gz_dopen maps the
 *     literals 0..2 to 67..69, which are never open), so zlib cannot tell;
 *   - O_DIRECT, O_NOATIME and FASYNC are stored by F_SETFL as Linux stores them
 *     and have no effect on I/O; no fsync, dup, ftruncate, stat or mtime. The
 *     O_DIRECT answer is tmpfs's since Linux 6.6 (measured on 6.12.95); tmpfs
 *     before 6.6 is believed to refuse it with EINVAL (not measured). The
 *     differential probes its kernel and says when it could not compare this;
 *   - tramp_sysm_unlink refuses while any descriptor is open (no orphan inodes);
 *   - buffer addresses are not checked against the address space: a read or
 *     write count above SSIZE_MAX answers EFAULT (the kernel's access_ok
 *     refuses every such range), but a count up to SSIZE_MAX whose range runs
 *     past the top of user space (TASK_SIZE) is answered as an ordinary
 *     transfer, where the kernel says EFAULT; the model moves only the bytes
 *     it returns, so a large count over a small file is safe. zlib caps every
 *     read and write it makes (gz_load, gz_comp) far below that.
 *
 * NEW ANSWERS. Where the Linux model gives NO answer (it declines the call, so
 * a proof that reaches one stops there), this file answers as Linux on tmpfs
 * does, and the differential checks it. zlib reaches these through the driver:
 *   - fcntl F_GETFL on a regular-file descriptor, which the model declines on
 *     every one (zlib's gzdopen with "N", gzlib.c:261): access mode | O_APPEND
 *     | O_NONBLOCK | O_LARGEFILE. Its only use in zlib is as F_SETFL's
 *     argument, masked to the settable bits, so the word itself is not seen;
 *   - fcntl F_GETFD, declined on every descriptor (gzdopen with "e",
 *     gzlib.c:265): the close-on-exec bit;
 *   - fcntl F_SETFL whose argument has O_APPEND, O_NONBLOCK, FASYNC, O_DIRECT
 *     or O_NOATIME set, or any F_SETFL on an O_APPEND descriptor, both declined
 *     (gzdopen's "N" sets O_NONBLOCK): 0, the settable bits stored;
 *   - open's O_NONBLOCK and O_CLOEXEC, which the model accepts and ignores,
 *     are recorded: O_NONBLOCK lets a scheduled EAGAIN apply and shows in
 *     F_GETFL, O_CLOEXEC shows in F_GETFD. No success answer of read, write,
 *     lseek or close depends on either;
 *   - a write more than 128 KiB past the end of the file (the model declines
 *     a hole that large): the gap reads as zeros. zlib reaches it only with two
 *     handles on one descriptor, a read handle seeking it far and a write
 *     handle writing there (gz_dopen twice on one fd_open descriptor);
 *   - descriptors from the DRIVER's fd_open, which can carry open flag words
 *     the model declines to open at all (O_RDWR|O_APPEND, O_WRONLY without
 *     O_CREAT, O_RDONLY with O_TRUNC or O_CREAT, O_WRONLY|O_CREAT alone, ...):
 *     every call zlib makes on one after gz_dopen is Linux's answer. zlib's
 *     own open words (r, w, wx, a, ax, each with e and N) are all the model's.
 * zlib cannot reach the remaining ones: SEEK_DATA/SEEK_HOLE and unknown open
 * flags (EINVAL here, above); a read or write whose offset + count passes
 * LLONG_MAX (EINVAL here, the kernel's rw_verify_area; the model answers such
 * a read 0), because zlib's offsets stay far below it (the driver's huge seek
 * offsets are the two zlib refuses before it calls lseek).
 *
 * NULL buffers are not a non-claim: like the kernel, the model answers EFAULT
 * only when at least one byte would move (read at end of file and transfers of
 * 0 bytes answer 0, an overflowing offset answers EINVAL first), and the
 * differential passes NULL buffers to both sides.
 *
 * COMPILED WITH THE DRIVER'S COMPILER like tramp_alloc.o (byte-identical across
 * flavours, uninstrumented), no dynamic allocation, static state, not thread
 * safe: the DSL tier is single-threaded. Data moves with memcpy of exactly the
 * returned count, never the requested one, so in the asan flavours the sealed
 * runtime's memcpy interceptor (the static link's --wrap=memcpy) checks the
 * library's buffer for the bytes a kernel would have written into it.
 */
#ifndef TRAMP_SYS_H
#define TRAMP_SYS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The six kinds, in the order the plan's kind byte names them. */
#define TRAMP_SYS_READ   0
#define TRAMP_SYS_WRITE  1
#define TRAMP_SYS_LSEEK  2
#define TRAMP_SYS_OPEN   3
#define TRAMP_SYS_CLOSE  4
#define TRAMP_SYS_FCNTL  5
#define TRAMP_SYS_NKINDS 6

#define TRAMP_SYS_PLAN_MAX 256u               /* entry bytes per kind's table */
#define TRAMP_SYS_FILE_MAX (1024u * 1024u)    /* the bytes of the one file that are STORED (not a size limit) */
#define TRAMP_SYS_NFD      64                 /* descriptors 3 .. 3+64-1 */
#define TRAMP_SYS_FD_BASE  3

/* The short-count table (indices 22 and 23 are the m/2 and m-1 sentinels). */
#define TRAMP_SYS_SHORT_N 24

/* ---- the trampolines: reached ONLY through the archive rename ------------ */
int tramp_sys_open(const char *path, int flags, ...);
ssize_t tramp_sys_read(int fd, void *buf, size_t n);
ssize_t tramp_sys_write(int fd, const void *buf, size_t n);
off_t tramp_sys_lseek(int fd, off_t off, int whence);
int tramp_sys_close(int fd);
int tramp_sys_fcntl(int fd, int cmd, ...);

/* ---- the driver's API: never ticks, never injects ----------------------- */

/* Everything back to the start of a repeat: the file present and empty, no
 * descriptor open, every table empty, every counter zero. */
void tramp_sysm_reset(void);

/* Install `n` (<= TRAMP_SYS_PLAN_MAX; more is truncated) entry bytes as KIND's
 * table, replacing the old one and zeroing that kind's plan position, so entry
 * i decides the i-th call of the kind after this. kind >= TRAMP_SYS_NKINDS
 * clears every table and every plan position. */
void tramp_sysm_plan(unsigned kind, const unsigned char *entries, size_t n);

/* Calls of KIND the library made since the last reset (not since the plan). */
unsigned tramp_sysm_calls(unsigned kind);

/* The file's content from outside the library (an external writer): present,
 * exactly these n bytes (n > TRAMP_SYS_FILE_MAX is refused with -1). Open
 * descriptors keep their offsets. */
int tramp_sysm_file_set(const void *p, size_t n);
size_t tramp_sysm_file_get(void *dst, size_t cap);   /* min(size, cap) bytes, as reads return them */
size_t tramp_sysm_file_size(void);       /* the size, which may be past TRAMP_SYS_FILE_MAX */
int tramp_sysm_file_present(void);
uint64_t tramp_sysm_file_digest(void);   /* FNV-1a 64 over the stored content (the first TRAMP_SYS_FILE_MAX bytes at most) */
/* Remove the file: 0, or -1 if it is absent or any descriptor is open. */
int tramp_sysm_unlink(void);

/* The model's open and close with no tick and no injection (the driver's own
 * fd_open/fd_close). Same answers as the trampolines, errno included. */
int tramp_sysm_open(int flags);
int tramp_sysm_close(int fd);

int tramp_sysm_nfds(void);
/* 0 and the description of an open descriptor (offset; F_GETFL's value;
 * close-on-exec), or -1 if fd is not open. Any out pointer may be NULL. */
int tramp_sysm_fd_info(int fd, int64_t *off, int *flags, int *cloexec);

#ifdef __cplusplus
}
#endif

#endif /* TRAMP_SYS_H */
