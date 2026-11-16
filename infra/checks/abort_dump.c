// Copyright 2026 Theorem Labs, PBC
// SPDX-License-Identifier: Apache-2.0
//
// For the coverage build of oss-verify check --checks only (compile-coverage), never a published binary. Each link of
// that build has -Wl,--wrap=abort, so each call of abort() in the library and the fuzz target comes here. This writes
// the profile, which the runtime otherwise writes only at exit, so that it also counts the abort() call that ends the
// run. Then it aborts.

int __llvm_profile_write_file(void);
_Noreturn void __real_abort(void);

_Noreturn void __wrap_abort(void) {
  __llvm_profile_write_file();
  __real_abort();
}
