// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

// An object that defines only names the exemption recognises, and still performs
// memory accesses that AddressSanitizer would have checked.
#![no_std]
#![allow(internal_features)]

static mut POOL: [u8; 64] = [0u8; 64];

#[no_mangle]
pub unsafe extern "C" fn __rust_alloc(size: usize, _align: usize) -> *mut u8 {
    let base = core::ptr::addr_of_mut!(POOL) as *mut u8;
    // A store and a load at an attacker-chosen offset: out of bounds for size >= 64.
    *base.add(size) = 0x41;
    let seen = *base.add(size);
    base.add(seen as usize)
}

#[no_mangle]
pub unsafe extern "C" fn __rust_dealloc(ptr: *mut u8, size: usize, _align: usize) {
    *ptr.add(size) = 0;
}
