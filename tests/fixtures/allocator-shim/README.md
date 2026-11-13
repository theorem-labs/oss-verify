<!-- Copyright 2026 Theorem Labs, PBC. SPDX-License-Identifier: Apache-2.0 -->
# Allocator-shim objects for the AddressSanitizer check

Five riscv64 relocatable objects for `tests/test_binary_checks.py`. Four are
compiled from the `.rs` file beside them; the fifth is a real build's member. They are
here because the exemption that `src/oss_verify/check_links.py` gives rustc's allocator shim is a
claim about an object's **code**, and a synthetic symbol table cannot test it.

| object | what it is | the check |
|---|---|---|
| `shim-forwards.o` | the shim's six functions, each a tail forward, no memory access | exempt |
| `shim-stores.o` | the same names, and `__rust_alloc`/`__rust_dealloc` each store a byte | a finding |
| `shim-local-access.o` | one global, `__rust_alloc`; the loads and stores are in two local functions | a finding |
| `shim-local-call.o` | one global, `__rust_alloc`, and a local function of another name; no memory access at all | a finding |
| `shim-rustc-v0.o` | the shim that the pinned Rust toolchain writes, taken from a real `asan` link | no memory access; its v0 names are not ones this recognises |

`main` before this change exempted the first four: it read the names and not the code, and
it never looked at a local function.

The four compiled objects were written with the box's `rustc 1.101.0-nightly`, which is not
the pinned toolchain; nothing here depends on the toolchain, only on the instructions in
the object:

    rustc --edition 2021 --crate-type=lib --emit=obj \
      --target riscv64gc-unknown-linux-gnu -C opt-level=2 -C panic=abort \
      -o <name>.o <name>.rs

`shim-rustc-v0.o` is `liboft.a(oft-14ce290e9998f884.cerkve21j1i8ita04mxj97m20.rcgu.o)` of
the `asan` link of `tessera-sort`'s `sort` fuzz target, built with the Rust toolchain image
of `infra/toolchains.tsv`
(`ghcr.io/theorem-labs/oss-fuzz-theorems-toolchain-rust@sha256:ad8a4572d32d…`). Its code is
52 bytes: one `OP-IMM`, five `AUIPC` and seven `JALR`, and no load, store or atomic. It
holds no code of the project that was built: rustc writes the shim itself, in its
synthetic `__rustc` crate, so the object is rustc's own output, under `Apache-2.0 OR MIT`.
