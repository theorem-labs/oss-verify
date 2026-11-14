// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    if example::run(data) {
        Corpus::Keep
    } else {
        Corpus::Reject
    }
});
