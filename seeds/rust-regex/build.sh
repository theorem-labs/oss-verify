#!/bin/sh -e
# Ported from the Rust build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of rust-regex into $OUT, each from the release's Rust target for it (rust/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# ast_fuzz_match: the release's target rust-regex-ast_fuzz_match
(
ov_target_begin rust-regex-ast_fuzz_match
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=ast_fuzz_match
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
ov_target_build ast_fuzz_match
)

# ast_fuzz_match_bytes: the release's target rust-regex-ast_fuzz_match_bytes
(
ov_target_begin rust-regex-ast_fuzz_match_bytes
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=ast_fuzz_match_bytes
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
ov_target_build ast_fuzz_match_bytes
)

# ast_fuzz_regex: the release's target rust-regex-ast_fuzz_regex
(
ov_target_begin rust-regex-ast_fuzz_regex
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=ast_fuzz_regex
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
ov_target_build ast_fuzz_regex
)

# ast_roundtrip: the release's target rust-regex-ast_roundtrip
(
ov_target_begin rust-regex-ast_roundtrip
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=ast_roundtrip
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
ov_target_build ast_roundtrip
)

# fuzz_regex_automata_deserialize_dense_dfa: the release's target rust-regex-fuzz_regex_automata_deserialize_dense_dfa
(
ov_target_begin rust-regex-fuzz_regex_automata_deserialize_dense_dfa
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_regex_automata_deserialize_dense_dfa
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
ov_target_build fuzz_regex_automata_deserialize_dense_dfa
)

# fuzz_regex_automata_deserialize_sparse_dfa: the release's target rust-regex-fuzz_regex_automata_deserialize_sparse_dfa
(
ov_target_begin rust-regex-fuzz_regex_automata_deserialize_sparse_dfa
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_regex_automata_deserialize_sparse_dfa
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
ov_target_build fuzz_regex_automata_deserialize_sparse_dfa
)

# fuzz_regex_lite_match: the release's target rust-regex-fuzz_regex_lite_match
(
ov_target_begin rust-regex-fuzz_regex_lite_match
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_regex_lite_match
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
ov_target_build fuzz_regex_lite_match
)

# fuzz_regex_match: the release's target rust-regex-fuzz_regex_match
(
ov_target_begin rust-regex-fuzz_regex_match
CARGO_FUZZ_DIR=fuzz
FUZZ_BIN=fuzz_regex_match
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
ov_target_build fuzz_regex_match
)
