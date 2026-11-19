/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The C probe of .github/scripts/frame-pointers/probe: a fuzz target whose fp_probe_* functions frames.py reads. On a
 * frame-pointer image, each of them that calls sets s0 from sp before its first call. On the base image, a compiler
 * can keep a value in s0 instead: fp_probe_keeps_a_value gives it one to keep across a call. LLVMFuzzerTestOneInput
 * calls each of them, so the link's --gc-sections keeps them. Each reads the input and a volatile, so no call folds
 * away. */
#include <stddef.h>
#include <stdint.h>

int fp_probe_leaf(int x);
int fp_probe_keeps_a_value(int x);
int fp_probe_tail_call(int x);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* A value the compiler cannot know, and a place for each result: each access is a load or a store. */
static volatile int opaque = 7;
static volatile int sink;

/* A leaf: it calls nothing. */
__attribute__((noinline, used)) int fp_probe_leaf(int x) { return x * opaque + 1; }

/* It keeps a value live across a call, in a callee-saved register: without frame pointers, that can be s0. */
__attribute__((noinline, used)) int fp_probe_keeps_a_value(int x) {
  int kept = x ^ opaque;
  int got = fp_probe_leaf(x);
  return kept * got;
}

/* It ends in a tail call: a jump, not a call. */
__attribute__((noinline, used)) int fp_probe_tail_call(int x) { return fp_probe_leaf(x + opaque); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int x = size ? data[0] : 0;
  sink = fp_probe_keeps_a_value(x);
  sink = fp_probe_tail_call(x);
  sink = fp_probe_leaf(x);
  return 0;
}
