#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of opencensus-cpp into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# b3_fuzzer: the release's target opencensus-cpp-b3_fuzzer
(
ov_target_begin opencensus-cpp-b3_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "opencensus/trace/internal/b3_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















































































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ABSEIL="$SRCDIR/oft-vendor/abseil" \
    -DFETCHCONTENT_SOURCE_DIR_PROMETHEUS="$SRCDIR/oft-vendor/prometheus"
  oft_build_harness "opencensus/trace/internal/b3_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/abseil sha256:91ac87d30cc6d79f9ab974c51874a704de9c2647c40f6932597329a282217ba8 https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.tar.gz 1
oft-vendor/prometheus sha256:397544fe91e183029120b4eebcfab24ed9ec833d15850aae78fd5db19062d13a https://github.com/jupp0r/prometheus-cpp/archive/refs/tags/v1.1.0.tar.gz 1
"
ov_target_build b3_fuzzer
)

# cloud_trace_context_fuzzer: the release's target opencensus-cpp-cloud_trace_context_fuzzer
(
ov_target_begin opencensus-cpp-cloud_trace_context_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "opencensus/trace/internal/cloud_trace_context_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""


























































































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ABSEIL="$SRCDIR/oft-vendor/abseil" \
    -DFETCHCONTENT_SOURCE_DIR_PROMETHEUS="$SRCDIR/oft-vendor/prometheus"
  oft_build_harness "opencensus/trace/internal/cloud_trace_context_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
















CFLAGS="$CFLAGS -DABSL_USE_UNSCALED_CYCLECLOCK=0"









VENDOR_TREES="
oft-vendor/abseil sha256:91ac87d30cc6d79f9ab974c51874a704de9c2647c40f6932597329a282217ba8 https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.tar.gz 1
oft-vendor/prometheus sha256:397544fe91e183029120b4eebcfab24ed9ec833d15850aae78fd5db19062d13a https://github.com/jupp0r/prometheus-cpp/archive/refs/tags/v1.1.0.tar.gz 1
"
ov_target_build cloud_trace_context_fuzzer
)

# grpc_tags_bin_fuzzer: the release's target opencensus-cpp-grpc_tags_bin_fuzzer
(
ov_target_begin opencensus-cpp-grpc_tags_bin_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "opencensus/tags/internal/grpc_tags_bin_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















































































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ABSEIL="$SRCDIR/oft-vendor/abseil" \
    -DFETCHCONTENT_SOURCE_DIR_PROMETHEUS="$SRCDIR/oft-vendor/prometheus"
  oft_build_harness "opencensus/tags/internal/grpc_tags_bin_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
















CFLAGS="$CFLAGS -DABSL_USE_UNSCALED_CYCLECLOCK=0"









VENDOR_TREES="
oft-vendor/abseil sha256:91ac87d30cc6d79f9ab974c51874a704de9c2647c40f6932597329a282217ba8 https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.tar.gz 1
oft-vendor/prometheus sha256:397544fe91e183029120b4eebcfab24ed9ec833d15850aae78fd5db19062d13a https://github.com/jupp0r/prometheus-cpp/archive/refs/tags/v1.1.0.tar.gz 1
"
ov_target_build grpc_tags_bin_fuzzer
)

# grpc_trace_bin_fuzzer: the release's target opencensus-cpp-grpc_trace_bin_fuzzer
(
ov_target_begin opencensus-cpp-grpc_trace_bin_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "opencensus/trace/internal/grpc_trace_bin_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















































































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ABSEIL="$SRCDIR/oft-vendor/abseil" \
    -DFETCHCONTENT_SOURCE_DIR_PROMETHEUS="$SRCDIR/oft-vendor/prometheus"
  oft_build_harness "opencensus/trace/internal/grpc_trace_bin_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/abseil sha256:91ac87d30cc6d79f9ab974c51874a704de9c2647c40f6932597329a282217ba8 https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.tar.gz 1
oft-vendor/prometheus sha256:397544fe91e183029120b4eebcfab24ed9ec833d15850aae78fd5db19062d13a https://github.com/jupp0r/prometheus-cpp/archive/refs/tags/v1.1.0.tar.gz 1
"
ov_target_build grpc_trace_bin_fuzzer
)

# trace_context_fuzzer: the release's target opencensus-cpp-trace_context_fuzzer
(
ov_target_begin opencensus-cpp-trace_context_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "opencensus/trace/internal/trace_context_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""

















































































































build_lib() {
  oft_require_target_cxx
  oft_build_cmake -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_ABSEIL="$SRCDIR/oft-vendor/abseil" \
    -DFETCHCONTENT_SOURCE_DIR_PROMETHEUS="$SRCDIR/oft-vendor/prometheus"
  oft_build_harness "opencensus/trace/internal/trace_context_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/abseil sha256:91ac87d30cc6d79f9ab974c51874a704de9c2647c40f6932597329a282217ba8 https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.1.tar.gz 1
oft-vendor/prometheus sha256:397544fe91e183029120b4eebcfab24ed9ec833d15850aae78fd5db19062d13a https://github.com/jupp0r/prometheus-cpp/archive/refs/tags/v1.1.0.tar.gz 1
"
ov_target_build trace_context_fuzzer
)
