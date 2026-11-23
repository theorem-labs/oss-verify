/* emit.h - the plugins' only route to stdout, and the thing -DHARNESS_QUIET
 * actually silences.
 *
 * WHY THIS EXISTS. Spec s4 says the quiet driver "writes nothing to stdout or
 * stderr" on success, and spec s2 leans on it: T3's observable is the exit
 * code alone, which is only true if a successful quiet run emits no WriteEv at
 * all. Before this header, -DHARNESS_QUIET reached exactly one thing --
 * cli.c's DIAG(), which is stderr -- and every plugin wrote its result to
 * stdout unconditionally. A "quiet" build therefore still issued writev (and
 * with it the isatty ioctl, see check_syscalls.sh), so the trace that carries
 * T3 was the loud trace with the diagnostics removed. The macro was named for
 * a property the build did not have.
 *
 * WHAT IS SUPPRESSED, AND WHAT IS NOT. Only the write. The formatting
 * arguments are still evaluated -- these are function calls, not macros that
 * drop their operands -- and every plugin's own accounting (libpng's
 * R.produced, xz's and zlib's OUT_MAX truncation, expat's `capped`) runs
 * unchanged, so the exit status a quiet run returns is the status the loud
 * build would have returned. That is the point: T3 is a claim about the
 * library's behaviour, and a quiet build that also skipped the work would be
 * proving something about a different program.
 *
 * WHY NOT REDEFINE printf. A macro over the stdio names would silence library
 * code that includes <stdio.h> too, which is not this file's business, and it
 * would break the plugins' snprintf() calls into fixed buffers -- those format
 * bytes that later get emitted and must keep working in both builds.
 */
/* emit_putc and not emit_char, and the name is the scar. targets/expat/plugin.c
 * already had its own `static void emit_char(char)`, which counts bytes against
 * OUT_MAX before writing one. Naming this one emit_char turned that function
 * into `emit_char(ch) { ...; emit_char(ch); }` -- unbounded recursion -- and the
 * only reason it did not ship is that C rejected the redefinition first. */
#ifndef HARNESS_EMIT_H
#define HARNESS_EMIT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#ifdef HARNESS_QUIET

/* The arguments are still evaluated by the call; only the write is gone. The
 * return values are the ones a successful write would have produced, so a
 * caller that checks them behaves identically -- no plugin does today, and a
 * quiet build that started failing on a short write would be a difference
 * between the pair that has nothing to do with the library. */
static inline int emit_printf(const char *fmt, ...) { (void)fmt; return 0; }
static inline size_t emit_bytes(const void *p, size_t n) { (void)p; return n; }
static inline int emit_putc(int c) { return c; }

#else

static inline int emit_printf(const char *fmt, ...) {
  va_list ap;
  int r;
  va_start(ap, fmt);
  r = vprintf(fmt, ap);
  va_end(ap);
  return r;
}
static inline size_t emit_bytes(const void *p, size_t n) {
  return fwrite(p, 1, n, stdout);
}
static inline int emit_putc(int c) { return putchar(c); }

#endif

#endif /* HARNESS_EMIT_H */
