// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

// An exempt-by-name object that hides a whole translation unit of checked code:
// every memory access lives in LOCAL functions, which the exemption never looks at.
#![no_std]
static mut POOL: [u8; 64] = [0u8; 64];

#[inline(never)]
unsafe fn parse(buf: *const u8, n: usize) -> u8 {
    let mut acc = 0u8;
    let mut i = 0usize;
    while i <= n {
        // off-by-one: reads buf[n]
        acc = acc.wrapping_add(*buf.add(i));
        i += 1;
    }
    acc
}

#[inline(never)]
unsafe fn store(v: u8, at: usize) {
    let base = core::ptr::addr_of_mut!(POOL) as *mut u8;
    *base.add(at) = v; // unbounded store
}

#[no_mangle]
pub unsafe extern "C" fn __rust_alloc(size: usize, _align: usize) -> *mut u8 {
    let base = core::ptr::addr_of_mut!(POOL) as *mut u8;
    let v = parse(base, size);
    store(v, size);
    base
}
