#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of quick-xml into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_chunked_reader: the release's target quick-xml-fuzz_chunked_reader
(
ov_target_begin quick-xml-fuzz_chunked_reader
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_chunked_reader
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
ov_target_build fuzz_chunked_reader
)

# fuzz_target_1: the release's target quick-xml-fuzz_target_1
(
ov_target_begin quick-xml-fuzz_target_1
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_target_1
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
ov_target_build fuzz_target_1
)

# structured_roundtrip: the release's target quick-xml-structured_roundtrip
(
ov_target_begin quick-xml-structured_roundtrip
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=structured_roundtrip
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
ov_target_build structured_roundtrip
)
