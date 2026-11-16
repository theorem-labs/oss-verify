#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of data-encoding into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_any_spec: the release's target data-encoding-fuzz_any_spec
(
ov_target_begin data-encoding-fuzz_any_spec
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=fuzz_any_spec
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build fuzz_any_spec
)

# impl_decode: the release's target data-encoding-impl_decode
(
ov_target_begin data-encoding-impl_decode
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_decode
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_decode
)

# impl_decode_len: the release's target data-encoding-impl_decode_len
(
ov_target_begin data-encoding-impl_decode_len
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_decode_len
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_decode_len
)

# impl_encode: the release's target data-encoding-impl_encode
(
ov_target_begin data-encoding-impl_encode
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_encode
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_encode
)

# impl_encode_append: the release's target data-encoding-impl_encode_append
(
ov_target_begin data-encoding-impl_encode_append
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_encode_append
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_encode_append
)

# impl_encode_len: the release's target data-encoding-impl_encode_len
(
ov_target_begin data-encoding-impl_encode_len
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_encode_len
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_encode_len
)

# impl_encode_mut_str: the release's target data-encoding-impl_encode_mut_str
(
ov_target_begin data-encoding-impl_encode_mut_str
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_encode_mut_str
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_encode_mut_str
)

# impl_encode_write_buffer: the release's target data-encoding-impl_encode_write_buffer
(
ov_target_begin data-encoding-impl_encode_write_buffer
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_encode_write_buffer
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_encode_write_buffer
)

# impl_new_encoder: the release's target data-encoding-impl_new_encoder
(
ov_target_begin data-encoding-impl_new_encoder
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=impl_new_encoder
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build impl_new_encoder
)

# spec_decode_encode: the release's target data-encoding-spec_decode_encode
(
ov_target_begin data-encoding-spec_decode_encode
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=spec_decode_encode
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build spec_decode_encode
)

# spec_encode_decode: the release's target data-encoding-spec_encode_decode
(
ov_target_begin data-encoding-spec_encode_decode
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=spec_encode_decode
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build spec_encode_decode
)

# spec_spec_base: the release's target data-encoding-spec_spec_base
(
ov_target_begin data-encoding-spec_spec_base
CARGO_FUZZ_DIR=lib/fuzz
FUZZ_BIN=spec_spec_base
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build spec_spec_base
)
