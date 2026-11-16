// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

// An object whose only global function is the shim's, and which defines a local function
// beside it. It makes no memory access, so only the rule that every function it defines,
// of any binding, must be the shim's can refuse it.
#![no_std]

#[inline(never)]
fn rounded(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

#[no_mangle]
pub extern "C" fn __rust_alloc(size: usize, align: usize) -> *mut u8 {
    rounded(size, align) as *mut u8
}
