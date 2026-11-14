#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of mp4parse-rust into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# avif: the release's target mp4parse-rust-avif
(
ov_target_begin mp4parse-rust-avif
CARGO_FUZZ_DIR=mp4parse_capi/fuzz
FUZZ_BIN=avif
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_ALL_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build avif
)

# mp4: the release's target mp4parse-rust-mp4
(
ov_target_begin mp4parse-rust-mp4
CARGO_FUZZ_DIR=mp4parse_capi/fuzz
FUZZ_BIN=mp4
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_ALL_FEATURES=0
CARGO_PROFILE_ENV=""
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build mp4
)
