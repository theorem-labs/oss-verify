// Copyright 2026 Tushar Dahiya
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use napkin_profile::Dtype;
use napkin_profile::collective::{Collective, parse_curve};

fuzz_target!(|input: &[u8]| check_curve(input));

fn check_curve(input: &[u8]) {
    let Some((&selector, json)) = input.split_first() else {
        return;
    };
    let collective = Collective::ALL[usize::from(selector) % Collective::ALL.len()];
    let Ok(json) = std::str::from_utf8(json) else {
        return;
    };

    // Only the collective and document vary. The run has two BF16 ranks in one process.
    let Ok(points) = parse_curve(collective, 2, 1, Dtype::Bf16, json) else {
        return;
    };

    // A successful parse must supply at least one measurement for interpolation.
    // mutant: upstream/napkin-math-gpu/crates/napkin-profile/src/collective.rs:341 `Ok(points)` -> `Ok(Vec::new())`
    // input: all-reduce
    if points.is_empty() {
        std::process::abort();
    }

    let mut previous_bytes = 0;
    for point in points {
        // Positive, strictly increasing sizes make each interpolation interval usable.
        // mutant: upstream/napkin-math-gpu/crates/napkin-profile/src/collective.rs:329 `point.bytes <= previous.bytes` -> `point.bytes < previous.bytes`
        // input: duplicate-size
        if point.bytes <= previous_bytes {
            std::process::abort();
        }
        previous_bytes = point.bytes;

        // Rate calculations need a finite, positive duration.
        // mutant: upstream/napkin-math-gpu/crates/napkin-profile/src/collective.rs:290 `time_us: result.time` -> `time_us: -result.time`
        // input: all-reduce
        if !point.time_us.is_finite() || point.time_us <= 0.0 {
            std::process::abort();
        }

        // Curve consumers need finite algorithm and bus rates.
        // mutant: upstream/napkin-math-gpu/crates/napkin-profile/src/collective.rs:291 `algbw_gbps: result.alg_bw` -> `algbw_gbps: f64::INFINITY`
        // input: all-reduce
        if !point.algbw_gbps.is_finite() || !point.busbw_gbps.is_finite() {
            std::process::abort();
        }
    }
}
