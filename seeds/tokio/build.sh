#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of tokio into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_linked_list: the release's target tokio-fuzz_linked_list
(
ov_target_begin tokio-fuzz_linked_list
CARGO_FUZZ_DIR=tokio/fuzz
FUZZ_BIN=fuzz_linked_list
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
ov_target_build fuzz_linked_list
)

# fuzz_stream_map: the release's target tokio-fuzz_stream_map
(
ov_target_begin tokio-fuzz_stream_map
CARGO_FUZZ_DIR=tokio-stream/fuzz
FUZZ_BIN=fuzz_stream_map
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
ov_target_build fuzz_stream_map
)
