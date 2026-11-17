// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

//! The Rust probe of .github/scripts/frame-pointers/probe: the same three kinds of function as its probe.c, which
//! frames.py reads by their names. On a frame-pointer image, each of them that calls sets s0 from sp before its first
//! call. On the base image, rustc can keep a value in s0 instead: fp_probe_keeps_a_value gives it one to keep across a
//! call. The fuzz target calls each of them, and black_box hides each value, so no call folds away.

use std::hint::black_box;

/// A leaf: it calls nothing.
#[no_mangle]
#[inline(never)]
pub extern "C" fn fp_probe_leaf(x: u64) -> u64 {
    black_box(x).wrapping_mul(7).wrapping_add(1)
}

/// It keeps a value live across a call, in a callee-saved register: without frame pointers, that can be s0.
#[no_mangle]
#[inline(never)]
pub extern "C" fn fp_probe_keeps_a_value(x: u64) -> u64 {
    let kept = black_box(x ^ 0x5a5a);
    let got = fp_probe_leaf(x);
    kept.wrapping_mul(got)
}

/// It ends in a tail call: a jump, not a call.
#[no_mangle]
#[inline(never)]
pub extern "C" fn fp_probe_tail_call(x: u64) -> u64 {
    fp_probe_leaf(x.wrapping_add(3))
}
