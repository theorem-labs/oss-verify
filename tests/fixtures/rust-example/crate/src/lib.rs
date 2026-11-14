// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

//! A library for tests/test_builder.py: each function ends a run in one way.

use std::alloc::{handle_alloc_error, Layout};

/// Does one thing for each first byte of `data`, as tests/test_builder.py's RUST_EXPECTED says.
pub fn run(data: &[u8]) -> bool {
    match data.first() {
        Some(b'p') => panic!("a failed property"),
        Some(b'o') => handle_alloc_error(Layout::new::<u64>()),
        Some(b'c') => {
            // More than isize::MAX bytes: a capacity overflow, which panics.
            let v: Vec<u8> = Vec::with_capacity(std::hint::black_box(usize::MAX));
            v.capacity() == 0
        }
        Some(b'x') => std::process::exit(3),
        Some(b'h') => {
            let v = vec![0u8; 8];
            // A read past the end of a heap block: AddressSanitizer finds it.
            let byte = unsafe { std::ptr::read_volatile(v.as_ptr().add(16)) };
            byte == 1
        }
        Some(b'u') => {
            let b = [0u32; 4];
            // A slice at a misaligned address: rustc's UB checks find it.
            let p = unsafe { (b.as_ptr() as *const u8).add(1) } as *const u32;
            let s = unsafe { std::slice::from_raw_parts(p, 1) };
            s.len() == 2
        }
        Some(b'r') => false,
        _ => true,
    }
}
