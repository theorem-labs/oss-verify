/* SPDX-License-Identifier: (Apache-2.0 OR MIT) */

/* The OSS Verify fuzz targets for Racket CS.

   Boots Racket CS once, with the boot files and the compiled harness
   modules embedded (embed-data.S), loads "safe-eval.rkt", and calls one
   of its `fuzz-*` entry points on each input. An entry point returns 0
   for every expected outcome; otherwise, a check below calls `abort`.

   Compile-time settings (strings):
     FUZZ_ENTRY       entry point name, such as "fuzz-eval"
     FUZZ_ADDON_DIR   the addon directory, so that Racket does not look
                      for the home directory */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chezscheme.h"
#include "racketcs.h"

#ifndef __has_feature
# define __has_feature(x) 0
#endif
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
# include <sanitizer/lsan_interface.h>
# define FUZZ_LSAN_DISABLE() __lsan_disable()
# define FUZZ_LSAN_ENABLE() __lsan_enable()
#else
# define FUZZ_LSAN_DISABLE() (void)0
# define FUZZ_LSAN_ENABLE() (void)0
#endif

#ifndef FUZZ_ENTRY
# define FUZZ_ENTRY "fuzz-eval"
#endif

static ptr entry_proc;

extern char fuzz_petite_boot[], fuzz_petite_boot_end[];
extern char fuzz_scheme_boot[], fuzz_scheme_boot_end[];
extern char fuzz_racket_boot[], fuzz_racket_boot_end[];
extern char fuzz_modules[], fuzz_modules_end[];

/* OSS Verify wants a target to install no signal handlers, so put
   back the default action for every signal that Chez Scheme or
   rktio handles, so that a memory fault ends the process with the
   signal. Ignored signals stay ignored. */
static void reset_signal_handlers(void)
{
  int sig;

  for (sig = 1; sig < NSIG; sig++) {
    struct sigaction sa;
    if ((sigaction(sig, NULL, &sa) == 0)
        && ((sa.sa_flags & SA_SIGINFO)
            || ((sa.sa_handler != SIG_DFL) && (sa.sa_handler != SIG_IGN))))
      signal(sig, SIG_DFL);
  }
}

static int initialized = 0;

/* An error while booting or loading the harness ends the process with
   `exit`, often with status 0, which would look like a passing run.
   Once Racket is ready, this handler returns, so an `exit` during a
   call still reaches the driver's guard. */
static void check_initialized(void)
{
  /* not a property: Racket failed to boot or to load the harness */
  if (!initialized) {
    fprintf(stderr, "racket-fuzz: initialization failed\n");
    abort();
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  racket_boot_arguments_t ba;

  atexit(check_initialized);

  memset(&ba, 0, sizeof(ba));
  ba.boot1_data = fuzz_petite_boot;
  ba.boot1_len = fuzz_petite_boot_end - fuzz_petite_boot;
  ba.boot2_data = fuzz_scheme_boot;
  ba.boot2_len = fuzz_scheme_boot_end - fuzz_scheme_boot;
  ba.boot3_data = fuzz_racket_boot;
  ba.boot3_len = fuzz_racket_boot_end - fuzz_racket_boot;
  ba.collects_dir = "";
  ba.config_dir = NULL;
  ba.exec_file = "racket-fuzz";
  ba.exit_after = 0;
#ifdef FUZZ_ADDON_DIR
  /* Naming the addon directory keeps Racket from finding it through
     the home directory, which looks in "/etc/passwd" when HOME is not
     set; "-n" is what a NULL `argv` would mean */
  {
    static char *args[] = { "-A", FUZZ_ADDON_DIR, "-n", NULL };
    ba.argc = 3;
    ba.argv = args;
  }
#endif

  /* Racket keeps what it allocates while booting until the process
     exits, often referenced only from the Scheme heap, which
     LeakSanitizer does not scan; so don't report those as leaks.
     Leaks from running an input are still reported. */
  FUZZ_LSAN_DISABLE();

  racket_boot(&ba);

  reset_signal_handlers();

  racket_embedded_load_bytes(fuzz_modules, fuzz_modules_end - fuzz_modules, 0);

  {
    /* "embed-modules.rkt" declares the module as 'fuzz:safe-eval */
    ptr mod_path = Scons(Sstring_to_symbol("quote"),
                         Scons(Sstring_to_symbol("fuzz:safe-eval"), Snil));
    ptr vals = racket_dynamic_require(mod_path, Sstring_to_symbol(FUZZ_ENTRY));
    entry_proc = Scar(vals);
    Slock_object(entry_proc);
  }

  FUZZ_LSAN_ENABLE();

  initialized = 1;

  return 0;
}

/* OSS Verify reads each property as a call of `abort` and its guard,
   and each comment names a breakage, a change that makes the check
   fail on an input of the target's seed corpus. An entry point of
   "safe-eval.rkt" returns 0, the number of a property that failed, or
   a string that describes an error that Racket must not raise. Each
   breakage is a patch in fuzz/mutants, with paths from the top of the
   Racket repository, where the Dockerfile puts these files in fuzz/.
   Racket CS builds from the generated "racket/src/cs/schemified" files,
   so a breakage of Racket's core changes those. */
static void check_result(ptr vals)
{
  ptr r;

  /* not a property: `racket_apply` returns the list of results */
  if (!Spairp(vals))
    abort();
  r = Scar(vals);

  /* Racket reports no internal error.
     breakage: fuzz/mutants/internal-error.patch,
     caught by the seed input eval-error */
  if (Sstringp(r))
    abort();

  /* not a property: an entry point returns a fixnum or a string */
  if (!Sfixnump(r))
    abort();

  switch (Sfixnum_value(r)) {
  case 0:
    break;
  case 1:
    /* `write` prints readable data so that `read` gives an equal value.
       breakage: fuzz/mutants/print-roundtrip.patch,
       caught by the seed input print-tab-char */
    abort();
  case 2:
    /* An exact number that `string->number` reads prints with
       `number->string` as text that reads back as the same number.
       breakage: fuzz/mutants/exact-number.patch,
       caught by the seed input number-fraction */
    abort();
  case 3:
    /* The same for an inexact real number, other than +nan.0.
       breakage: fuzz/mutants/inexact-number.patch,
       caught by the seed input number-small-flonum */
    abort();
  case 4:
    /* `regexp-match` and `regexp-match-positions` agree on whether and
       where a regexp matches.
       breakage: fuzz/mutants/regexp-positions.patch,
       caught by the seed input regexp-match */
    abort();
  case 5:
    /* A value that `fasl->s-exp` decodes encodes with `s-exp->fasl` to
       bytes that decode to an equal value.
       breakage: fuzz/mutants/fasl-roundtrip.patch,
       caught by the seed input fasl-keyword */
    abort();
  case 6:
    /* `fasl->s-exp` fails only by raising `exn:fail`.
       breakage: fuzz/mutants/fasl-raise.patch,
       caught by the seed input fasl-bad-prefix */
    abort();
  case 7:
    /* After a program runs, Chez Scheme's check of the whole heap during
       a collection finds no error.
       breakage: fuzz/mutants/heap-check.patch,
       caught by the seed input heap-eval-witness */
    abort();
  default:
    /* not a property: "safe-eval.rkt" has no property with this number */
    abort();
  }
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  ptr bstr = Smake_bytevector(size, 0);

  memcpy(Sbytevector_data(bstr), data, size);
  check_result(racket_apply(entry_proc, Scons(bstr, Snil)));

  return 0;
}
