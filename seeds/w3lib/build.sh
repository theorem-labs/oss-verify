#!/bin/sh -e
# Ported from the Python build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# Builds the fuzz targets of w3lib into $OUT, each from the release's Python target for it (python/recipes.sh).
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_parse_data_uri: the release's target w3lib-fuzz_parse_data_uri
(
ov_target_begin w3lib-fuzz_parse_data_uri
PY_HARNESS=fuzz_parse_data_uri.py
PY_INSTALL="."
PY_ALLOW_MISSING="_hashlib _ssl"
. /usr/local/lib/oss-verify/python/recipes.sh
build_lib() {
  oft_py_build
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_parse_data_uri
)

# fuzz_safe_download_url: the release's target w3lib-fuzz_safe_download_url
(
ov_target_begin w3lib-fuzz_safe_download_url
PY_HARNESS=fuzz_safe_download_url.py
PY_INSTALL="."
PY_ALLOW_MISSING="_hashlib _ssl"
. /usr/local/lib/oss-verify/python/recipes.sh
build_lib() {
  oft_py_build
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_safe_download_url
)

# fuzz_url_safe: the release's target w3lib-fuzz_url_safe
(
ov_target_begin w3lib-fuzz_url_safe
PY_HARNESS=fuzz_url_safe.py
PY_INSTALL="."
PY_ALLOW_MISSING="_hashlib _ssl"
. /usr/local/lib/oss-verify/python/recipes.sh
build_lib() {
  oft_py_build
  oft_seal_getenv
  oft_seal_getpid
  oft_seal_mkstemp
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build fuzz_url_safe
)
