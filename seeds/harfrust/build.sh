#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of harfrust into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_shape: the release's target harfrust-fuzz_shape
(
ov_target_begin harfrust-fuzz_shape
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_shape
CARGO_DEBUG_ASSERTIONS=1
CARGO_FEATURES=""
CARGO_NO_DEFAULT_FEATURES=0
CARGO_ALL_FEATURES=0
CARGO_PROFILE_ENV="CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=false"
OFT_RUST_QUIET_STDIO=0
. /usr/local/lib/oss-verify/rust/recipes.sh
build_lib() {
  oft_build_cargo_shim
  oft_seal_getenv
}
LIB_ARCHIVE="lib/liboft.a"
ov_target_build fuzz_shape
)
