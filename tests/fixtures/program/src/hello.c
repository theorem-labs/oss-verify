/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * A small whole program for tests/test_binary_checks_docker.py: its own main, a string literal that it prints, and a
 * second function, so that the link map names more than one symbol of the program. */
#include <stdio.h>

/* compile defines FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION in the CFLAGS of each fuzz build, and the program's own
 * build does not. As in the programs of OSS-Fuzz, the macro changes what the program prints, so a build with the
 * CFLAGS of a fuzz build gives other bytes. The test's negative control of the environment comparison needs this: the
 * program is so small that -Os and -O2 give the same code, and clang puts no flag in the debug information. */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define GREETING "hello from a fuzzing build"
#else
#define GREETING "hello from a whole program"
#endif

/* noinline keeps greet a function of its own at -O2, so that the link map names it beside main. */
__attribute__((noinline)) int greet(const char *text) {
    return puts(text);
}

int main(void) {
    return greet(GREETING) < 0;
}
