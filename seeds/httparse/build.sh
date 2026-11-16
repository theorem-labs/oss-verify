#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of httparse into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# parse_chunk_size: the release's target httparse-parse_chunk_size
(
ov_target_begin httparse-parse_chunk_size
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=parse_chunk_size
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
ov_target_build parse_chunk_size
)

# parse_headers: the release's target httparse-parse_headers
(
ov_target_begin httparse-parse_headers
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=parse_headers
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
ov_target_build parse_headers
)

# parse_request: the release's target httparse-parse_request
(
ov_target_begin httparse-parse_request
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=parse_request
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
ov_target_build parse_request
)

# parse_request_multspaces: the release's target httparse-parse_request_multspaces
(
ov_target_begin httparse-parse_request_multspaces
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=parse_request_multspaces
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
ov_target_build parse_request_multspaces
)

# parse_response: the release's target httparse-parse_response
(
ov_target_begin httparse-parse_response
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=parse_response
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
ov_target_build parse_response
)

# parse_response_multspaces: the release's target httparse-parse_response_multspaces
(
ov_target_begin httparse-parse_response_multspaces
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=parse_response_multspaces
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
ov_target_build parse_response_multspaces
)
