# Patch style and report preferences

Racket CS is Racket on Chez Scheme. The fuzz targets run untrusted input through the reader, the printer, number parsing, regexps, fasl decoding, and the expander, compiler and runtime, and one target checks the whole heap during a collection after a program runs (`safe-eval.rkt` in this directory).

## Findings

Send findings to samth@racket-lang.org. Give a short reproducer that runs under plain `racket`, if the bug can be reached that way, as well as the fuzz input.

## Patches

- Write every patch against racket/racket `master`, including a fix to Chez Scheme, which is in `racket/src/ChezScheme` of the Racket repository. The maintainers split patches further as needed.
- One fix per patch.
- Add a test in `pkgs/racket-test-core` where possible.
- Racket CS builds from the generated files in `racket/src/cs/schemified/`. Change the Racket sources in `racket/src/expander`, `racket/src/io`, `racket/src/regexp` and the rest, not the generated files.
