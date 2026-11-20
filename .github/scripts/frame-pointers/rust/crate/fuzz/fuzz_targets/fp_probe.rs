// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

fuzz_target!(|data: &[u8]| {
    let x = u64::from(data.first().copied().unwrap_or(0));
    black_box(example::fp_probe_keeps_a_value(x));
    black_box(example::fp_probe_tail_call(x));
    black_box(example::fp_probe_leaf(x));
});
