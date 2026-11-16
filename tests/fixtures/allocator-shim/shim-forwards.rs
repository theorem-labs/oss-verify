// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0

// An honest allocator shim: it defines the shim's functions, forwards each to the standard
// library with a tail call, and makes no memory access, which is why an AddressSanitizer
// build may link it uninstrumented. The check must exempt it.
#![no_std]

unsafe extern "C" {
    fn __rdl_alloc(size: usize, align: usize) -> *mut u8;
    fn __rdl_dealloc(ptr: *mut u8, size: usize, align: usize);
    fn __rdl_realloc(ptr: *mut u8, size: usize, align: usize, new: usize) -> *mut u8;
    fn __rdl_alloc_zeroed(size: usize, align: usize) -> *mut u8;
    fn __rdl_oom(size: usize, align: usize);
}

#[no_mangle]
pub unsafe extern "C" fn __rust_alloc(size: usize, align: usize) -> *mut u8 {
    __rdl_alloc(size, align)
}

#[no_mangle]
pub unsafe extern "C" fn __rust_dealloc(ptr: *mut u8, size: usize, align: usize) {
    __rdl_dealloc(ptr, size, align)
}

#[no_mangle]
pub unsafe extern "C" fn __rust_realloc(ptr: *mut u8, size: usize, align: usize, new: usize) -> *mut u8 {
    __rdl_realloc(ptr, size, align, new)
}

#[no_mangle]
pub unsafe extern "C" fn __rust_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    __rdl_alloc_zeroed(size, align)
}

#[no_mangle]
pub unsafe extern "C" fn __rust_alloc_error_handler(size: usize, align: usize) {
    __rdl_oom(size, align)
}

#[no_mangle]
pub extern "C" fn __rust_no_alloc_shim_is_unstable() {}
