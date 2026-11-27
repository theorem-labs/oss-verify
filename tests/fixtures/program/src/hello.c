/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * A small whole program for tests/test_binary_checks_docker.py: its own main, a string literal that it prints, and a
 * second function, so that the link map names more than one symbol of the program. */
#include <stdio.h>

/* noinline keeps greet a function of its own at -O2, so that the link map names it beside main. */
__attribute__((noinline)) int greet(const char *text) {
    return puts(text);
}

int main(void) {
    return greet("hello from a whole program") < 0;
}
