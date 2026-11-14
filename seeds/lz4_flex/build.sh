#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of lz4_flex into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_decomp_corrupt_block: the release's target lz4_flex-fuzz_decomp_corrupt_block
(
ov_target_begin lz4_flex-fuzz_decomp_corrupt_block
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_decomp_corrupt_block
CARGO_DEBUG_ASSERTIONS=0
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
ov_target_build fuzz_decomp_corrupt_block
)

# fuzz_decomp_corrupt_frame: the release's target lz4_flex-fuzz_decomp_corrupt_frame
(
ov_target_begin lz4_flex-fuzz_decomp_corrupt_frame
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_decomp_corrupt_frame
CARGO_DEBUG_ASSERTIONS=0
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
ov_target_build fuzz_decomp_corrupt_frame
)

# fuzz_roundtrip: the release's target lz4_flex-fuzz_roundtrip
(
ov_target_begin lz4_flex-fuzz_roundtrip
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_roundtrip
CARGO_DEBUG_ASSERTIONS=0
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
ov_target_build fuzz_roundtrip
)

# fuzz_roundtrip_cpp_compress: the release's target lz4_flex-fuzz_roundtrip_cpp_compress
(
ov_target_begin lz4_flex-fuzz_roundtrip_cpp_compress
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_roundtrip_cpp_compress
CARGO_DEBUG_ASSERTIONS=0
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
ov_target_build fuzz_roundtrip_cpp_compress
)

# fuzz_roundtrip_cpp_decompress: the release's target lz4_flex-fuzz_roundtrip_cpp_decompress
(
ov_target_begin lz4_flex-fuzz_roundtrip_cpp_decompress
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_roundtrip_cpp_decompress
CARGO_DEBUG_ASSERTIONS=0
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
ov_target_build fuzz_roundtrip_cpp_decompress
)

# fuzz_roundtrip_frame: the release's target lz4_flex-fuzz_roundtrip_frame
(
ov_target_begin lz4_flex-fuzz_roundtrip_frame
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_roundtrip_frame
CARGO_DEBUG_ASSERTIONS=0
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
ov_target_build fuzz_roundtrip_frame
)
