#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of arrow into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# arrow-csv-fuzz: the release's target arrow-arrow-csv-fuzz
(
ov_target_begin arrow-arrow-csv-fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "cpp/src/arrow/csv/fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




































































































VENDOR_FILES="
oft-vendor/brotli-v1.0.9.tar.gz sha256:f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46 https://github.com/google/brotli/archive/v1.0.9.tar.gz
oft-vendor/lz4-v1.10.0.tar.gz sha256:537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b https://github.com/lz4/lz4/archive/v1.10.0.tar.gz
oft-vendor/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz sha256:b9290a9a6d444c8e049bd589ab804e0ccf2b05dc5984a19ed5ae75d090064806 https://github.com/miloyip/rapidjson/archive/232389d4f1012dddec4ef84861face2d2ba85709.tar.gz
oft-vendor/simdjson-v4.6.4.tar.gz sha256:b091107844fe928158c5c2265c20360fff312889ddf7ebc4528a0f0f8f2ff9cd https://github.com/simdjson/simdjson/archive/refs/tags/v4.6.4.tar.gz
oft-vendor/snappy-1.2.2.tar.gz sha256:90f74bc1fbf78a6c56b3c4a082a05103b3a56bb17bca1a27e052ea11723292dc https://github.com/google/snappy/archive/1.2.2.tar.gz
oft-vendor/thrift-0.22.0.tar.gz sha256:794a0e455787960d9f27ab92c38e34da27e8deeda7a5db0e59dc64a00df8a1e5 https://www.apache.org/dyn/closer.lua/thrift/0.22.0/thrift-0.22.0.tar.gz?action=download
oft-vendor/xsimd-14.2.0.tar.gz sha256:21e841ab684b05331e81e7f782431753a029ef7b7d9d6d3ddab837e7782a40ee https://github.com/xtensor-stack/xsimd/archive/14.2.0.tar.gz
oft-vendor/zlib-1.3.1.tar.gz sha256:9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 https://zlib.net/fossils/zlib-1.3.1.tar.gz
oft-vendor/zstd-1.5.7.tar.gz sha256:eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3 https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
"



OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-8}"
export OFT_MAKE_JOBS
build_lib() {
  local f v
  oft_require_target_cxx


  for f in brotli-v1.0.9.tar.gz lz4-v1.10.0.tar.gz \
           rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz simdjson-v4.6.4.tar.gz \
           snappy-1.2.2.tar.gz thrift-0.22.0.tar.gz xsimd-14.2.0.tar.gz zlib-1.3.1.tar.gz \
           zstd-1.5.7.tar.gz; do
    [ -f "$SRCDIR/oft-vendor/$f" ] || { echo "oft: arrow: vendored $f missing from $SRCDIR/oft-vendor" >&2; return 1; }
  done

  v="$BUILDDIR/src/oft-vendor"
  ARROW_BROTLI_URL="$v/brotli-v1.0.9.tar.gz"
  ARROW_LZ4_URL="$v/lz4-v1.10.0.tar.gz"
  ARROW_RAPIDJSON_URL="$v/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz"
  ARROW_SIMDJSON_URL="$v/simdjson-v4.6.4.tar.gz"
  ARROW_SNAPPY_URL="$v/snappy-1.2.2.tar.gz"
  ARROW_THRIFT_URL="$v/thrift-0.22.0.tar.gz"
  ARROW_XSIMD_URL="$v/xsimd-14.2.0.tar.gz"
  ARROW_ZLIB_URL="$v/zlib-1.3.1.tar.gz"
  ARROW_ZSTD_URL="$v/zstd-1.5.7.tar.gz"
  export ARROW_BROTLI_URL ARROW_LZ4_URL ARROW_RAPIDJSON_URL ARROW_SIMDJSON_URL \
         ARROW_SNAPPY_URL ARROW_THRIFT_URL ARROW_XSIMD_URL ARROW_ZLIB_URL ARROW_ZSTD_URL

  echo 'add_definitions(-DADDRESS_SANITIZER)' > "$BUILDDIR/oft-arrow-fuzzing-defs.cmake"

  {
    echo 'if(PROJECT_NAME STREQUAL "zlib")'
    echo '  set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "oft: static-only toolchain" FORCE)'
    echo 'elseif(PROJECT_NAME STREQUAL "brotli")'
    echo '  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-Bdynamic")'
    echo 'endif()'
  } > "$BUILDDIR/oft-arrow-ep-fixes.cmake"
  OFT_BUILD_SUBDIR=cpp
  oft_build_cmake \
    -DCMAKE_PROJECT_arrow_INCLUDE="$BUILDDIR/oft-arrow-fuzzing-defs.cmake" \
    -DCMAKE_PROJECT_INCLUDE="$BUILDDIR/oft-arrow-ep-fixes.cmake" \
    -DARROW_USE_CCACHE=OFF \
    -DARROW_DEPENDENCY_SOURCE=BUNDLED \
    -DARROW_OPENSSL_USE_SHARED=OFF \
    -DBOOST_SOURCE=SYSTEM \
    -DARROW_BOOST_USE_SHARED=OFF \
    -DARROW_EXTRA_ERROR_CONTEXT=OFF \
    -DARROW_BUILD_SHARED=OFF \
    -DARROW_BUILD_STATIC=ON \
    -DARROW_BUILD_BENCHMARKS=OFF \
    -DARROW_BUILD_EXAMPLES=OFF \
    -DARROW_BUILD_INTEGRATION=OFF \
    -DARROW_BUILD_TESTS=OFF \
    -DARROW_TESTING=OFF \
    -DARROW_BUILD_UTILITIES=OFF \
    -DARROW_TEST_LINKAGE=static \
    -DPARQUET_BUILD_EXAMPLES=OFF \
    -DPARQUET_BUILD_EXECUTABLES=OFF \
    -DPARQUET_REQUIRE_ENCRYPTION=ON \
    -DARROW_CSV=ON \
    -DARROW_JSON=ON \
    -DARROW_FILESYSTEM=ON \
    -DARROW_JEMALLOC=OFF \
    -DARROW_MIMALLOC=OFF \
    -DARROW_PARQUET=ON \
    -DARROW_WITH_BROTLI=ON \
    -DARROW_WITH_BZ2=OFF \
    -DARROW_WITH_LZ4=ON \
    -DARROW_WITH_SNAPPY=ON \
    -DARROW_WITH_ZLIB=ON \
    -DARROW_WITH_ZSTD=ON \
    -DARROW_USE_ASAN=OFF \
    -DARROW_USE_UBSAN=OFF \
    -DARROW_USE_TSAN=OFF \
    -DARROW_FUZZING=OFF








  OFT_CXX_STD=-std=c++20
  oft_build_harness "cpp/src/arrow/csv/fuzz.cc" "-I$BUILDDIR/src/cpp/src" "-I$BUILDDIR/cmk/src" \
    -DNDEBUG -DARROW_STATIC -DPARQUET_STATIC -DADDRESS_SANITIZER
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build arrow-csv-fuzz
)

# arrow-ipc-file-fuzz: the release's target arrow-arrow-ipc-file-fuzz
(
ov_target_begin arrow-arrow-ipc-file-fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "cpp/src/arrow/ipc/file_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




































































































VENDOR_FILES="
oft-vendor/brotli-v1.0.9.tar.gz sha256:f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46 https://github.com/google/brotli/archive/v1.0.9.tar.gz
oft-vendor/lz4-v1.10.0.tar.gz sha256:537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b https://github.com/lz4/lz4/archive/v1.10.0.tar.gz
oft-vendor/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz sha256:b9290a9a6d444c8e049bd589ab804e0ccf2b05dc5984a19ed5ae75d090064806 https://github.com/miloyip/rapidjson/archive/232389d4f1012dddec4ef84861face2d2ba85709.tar.gz
oft-vendor/simdjson-v4.6.4.tar.gz sha256:b091107844fe928158c5c2265c20360fff312889ddf7ebc4528a0f0f8f2ff9cd https://github.com/simdjson/simdjson/archive/refs/tags/v4.6.4.tar.gz
oft-vendor/snappy-1.2.2.tar.gz sha256:90f74bc1fbf78a6c56b3c4a082a05103b3a56bb17bca1a27e052ea11723292dc https://github.com/google/snappy/archive/1.2.2.tar.gz
oft-vendor/thrift-0.22.0.tar.gz sha256:794a0e455787960d9f27ab92c38e34da27e8deeda7a5db0e59dc64a00df8a1e5 https://www.apache.org/dyn/closer.lua/thrift/0.22.0/thrift-0.22.0.tar.gz?action=download
oft-vendor/xsimd-14.2.0.tar.gz sha256:21e841ab684b05331e81e7f782431753a029ef7b7d9d6d3ddab837e7782a40ee https://github.com/xtensor-stack/xsimd/archive/14.2.0.tar.gz
oft-vendor/zlib-1.3.1.tar.gz sha256:9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 https://zlib.net/fossils/zlib-1.3.1.tar.gz
oft-vendor/zstd-1.5.7.tar.gz sha256:eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3 https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
"



OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-8}"
export OFT_MAKE_JOBS
build_lib() {
  local f v
  oft_require_target_cxx


  for f in brotli-v1.0.9.tar.gz lz4-v1.10.0.tar.gz \
           rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz simdjson-v4.6.4.tar.gz \
           snappy-1.2.2.tar.gz thrift-0.22.0.tar.gz xsimd-14.2.0.tar.gz zlib-1.3.1.tar.gz \
           zstd-1.5.7.tar.gz; do
    [ -f "$SRCDIR/oft-vendor/$f" ] || { echo "oft: arrow: vendored $f missing from $SRCDIR/oft-vendor" >&2; return 1; }
  done

  v="$BUILDDIR/src/oft-vendor"
  ARROW_BROTLI_URL="$v/brotli-v1.0.9.tar.gz"
  ARROW_LZ4_URL="$v/lz4-v1.10.0.tar.gz"
  ARROW_RAPIDJSON_URL="$v/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz"
  ARROW_SIMDJSON_URL="$v/simdjson-v4.6.4.tar.gz"
  ARROW_SNAPPY_URL="$v/snappy-1.2.2.tar.gz"
  ARROW_THRIFT_URL="$v/thrift-0.22.0.tar.gz"
  ARROW_XSIMD_URL="$v/xsimd-14.2.0.tar.gz"
  ARROW_ZLIB_URL="$v/zlib-1.3.1.tar.gz"
  ARROW_ZSTD_URL="$v/zstd-1.5.7.tar.gz"
  export ARROW_BROTLI_URL ARROW_LZ4_URL ARROW_RAPIDJSON_URL ARROW_SIMDJSON_URL \
         ARROW_SNAPPY_URL ARROW_THRIFT_URL ARROW_XSIMD_URL ARROW_ZLIB_URL ARROW_ZSTD_URL

  echo 'add_definitions(-DADDRESS_SANITIZER)' > "$BUILDDIR/oft-arrow-fuzzing-defs.cmake"

  {
    echo 'if(PROJECT_NAME STREQUAL "zlib")'
    echo '  set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "oft: static-only toolchain" FORCE)'
    echo 'elseif(PROJECT_NAME STREQUAL "brotli")'
    echo '  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-Bdynamic")'
    echo 'endif()'
  } > "$BUILDDIR/oft-arrow-ep-fixes.cmake"
  OFT_BUILD_SUBDIR=cpp
  oft_build_cmake \
    -DCMAKE_PROJECT_arrow_INCLUDE="$BUILDDIR/oft-arrow-fuzzing-defs.cmake" \
    -DCMAKE_PROJECT_INCLUDE="$BUILDDIR/oft-arrow-ep-fixes.cmake" \
    -DARROW_USE_CCACHE=OFF \
    -DARROW_DEPENDENCY_SOURCE=BUNDLED \
    -DARROW_OPENSSL_USE_SHARED=OFF \
    -DBOOST_SOURCE=SYSTEM \
    -DARROW_BOOST_USE_SHARED=OFF \
    -DARROW_EXTRA_ERROR_CONTEXT=OFF \
    -DARROW_BUILD_SHARED=OFF \
    -DARROW_BUILD_STATIC=ON \
    -DARROW_BUILD_BENCHMARKS=OFF \
    -DARROW_BUILD_EXAMPLES=OFF \
    -DARROW_BUILD_INTEGRATION=OFF \
    -DARROW_BUILD_TESTS=OFF \
    -DARROW_TESTING=OFF \
    -DARROW_BUILD_UTILITIES=OFF \
    -DARROW_TEST_LINKAGE=static \
    -DPARQUET_BUILD_EXAMPLES=OFF \
    -DPARQUET_BUILD_EXECUTABLES=OFF \
    -DPARQUET_REQUIRE_ENCRYPTION=ON \
    -DARROW_CSV=ON \
    -DARROW_JSON=ON \
    -DARROW_FILESYSTEM=ON \
    -DARROW_JEMALLOC=OFF \
    -DARROW_MIMALLOC=OFF \
    -DARROW_PARQUET=ON \
    -DARROW_WITH_BROTLI=ON \
    -DARROW_WITH_BZ2=OFF \
    -DARROW_WITH_LZ4=ON \
    -DARROW_WITH_SNAPPY=ON \
    -DARROW_WITH_ZLIB=ON \
    -DARROW_WITH_ZSTD=ON \
    -DARROW_USE_ASAN=OFF \
    -DARROW_USE_UBSAN=OFF \
    -DARROW_USE_TSAN=OFF \
    -DARROW_FUZZING=OFF








  OFT_CXX_STD=-std=c++20
  oft_build_harness "cpp/src/arrow/ipc/file_fuzz.cc" "-I$BUILDDIR/src/cpp/src" "-I$BUILDDIR/cmk/src" \
    -DNDEBUG -DARROW_STATIC -DPARQUET_STATIC -DADDRESS_SANITIZER
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build arrow-ipc-file-fuzz
)

# arrow-ipc-stream-fuzz: the release's target arrow-arrow-ipc-stream-fuzz
(
ov_target_begin arrow-arrow-ipc-stream-fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "cpp/src/arrow/ipc/stream_fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




































































































VENDOR_FILES="
oft-vendor/brotli-v1.0.9.tar.gz sha256:f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46 https://github.com/google/brotli/archive/v1.0.9.tar.gz
oft-vendor/lz4-v1.10.0.tar.gz sha256:537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b https://github.com/lz4/lz4/archive/v1.10.0.tar.gz
oft-vendor/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz sha256:b9290a9a6d444c8e049bd589ab804e0ccf2b05dc5984a19ed5ae75d090064806 https://github.com/miloyip/rapidjson/archive/232389d4f1012dddec4ef84861face2d2ba85709.tar.gz
oft-vendor/simdjson-v4.6.4.tar.gz sha256:b091107844fe928158c5c2265c20360fff312889ddf7ebc4528a0f0f8f2ff9cd https://github.com/simdjson/simdjson/archive/refs/tags/v4.6.4.tar.gz
oft-vendor/snappy-1.2.2.tar.gz sha256:90f74bc1fbf78a6c56b3c4a082a05103b3a56bb17bca1a27e052ea11723292dc https://github.com/google/snappy/archive/1.2.2.tar.gz
oft-vendor/thrift-0.22.0.tar.gz sha256:794a0e455787960d9f27ab92c38e34da27e8deeda7a5db0e59dc64a00df8a1e5 https://www.apache.org/dyn/closer.lua/thrift/0.22.0/thrift-0.22.0.tar.gz?action=download
oft-vendor/xsimd-14.2.0.tar.gz sha256:21e841ab684b05331e81e7f782431753a029ef7b7d9d6d3ddab837e7782a40ee https://github.com/xtensor-stack/xsimd/archive/14.2.0.tar.gz
oft-vendor/zlib-1.3.1.tar.gz sha256:9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 https://zlib.net/fossils/zlib-1.3.1.tar.gz
oft-vendor/zstd-1.5.7.tar.gz sha256:eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3 https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
"



OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-8}"
export OFT_MAKE_JOBS
build_lib() {
  local f v
  oft_require_target_cxx


  for f in brotli-v1.0.9.tar.gz lz4-v1.10.0.tar.gz \
           rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz simdjson-v4.6.4.tar.gz \
           snappy-1.2.2.tar.gz thrift-0.22.0.tar.gz xsimd-14.2.0.tar.gz zlib-1.3.1.tar.gz \
           zstd-1.5.7.tar.gz; do
    [ -f "$SRCDIR/oft-vendor/$f" ] || { echo "oft: arrow: vendored $f missing from $SRCDIR/oft-vendor" >&2; return 1; }
  done

  v="$BUILDDIR/src/oft-vendor"
  ARROW_BROTLI_URL="$v/brotli-v1.0.9.tar.gz"
  ARROW_LZ4_URL="$v/lz4-v1.10.0.tar.gz"
  ARROW_RAPIDJSON_URL="$v/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz"
  ARROW_SIMDJSON_URL="$v/simdjson-v4.6.4.tar.gz"
  ARROW_SNAPPY_URL="$v/snappy-1.2.2.tar.gz"
  ARROW_THRIFT_URL="$v/thrift-0.22.0.tar.gz"
  ARROW_XSIMD_URL="$v/xsimd-14.2.0.tar.gz"
  ARROW_ZLIB_URL="$v/zlib-1.3.1.tar.gz"
  ARROW_ZSTD_URL="$v/zstd-1.5.7.tar.gz"
  export ARROW_BROTLI_URL ARROW_LZ4_URL ARROW_RAPIDJSON_URL ARROW_SIMDJSON_URL \
         ARROW_SNAPPY_URL ARROW_THRIFT_URL ARROW_XSIMD_URL ARROW_ZLIB_URL ARROW_ZSTD_URL

  echo 'add_definitions(-DADDRESS_SANITIZER)' > "$BUILDDIR/oft-arrow-fuzzing-defs.cmake"

  {
    echo 'if(PROJECT_NAME STREQUAL "zlib")'
    echo '  set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "oft: static-only toolchain" FORCE)'
    echo 'elseif(PROJECT_NAME STREQUAL "brotli")'
    echo '  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-Bdynamic")'
    echo 'endif()'
  } > "$BUILDDIR/oft-arrow-ep-fixes.cmake"
  OFT_BUILD_SUBDIR=cpp
  oft_build_cmake \
    -DCMAKE_PROJECT_arrow_INCLUDE="$BUILDDIR/oft-arrow-fuzzing-defs.cmake" \
    -DCMAKE_PROJECT_INCLUDE="$BUILDDIR/oft-arrow-ep-fixes.cmake" \
    -DARROW_USE_CCACHE=OFF \
    -DARROW_DEPENDENCY_SOURCE=BUNDLED \
    -DARROW_OPENSSL_USE_SHARED=OFF \
    -DBOOST_SOURCE=SYSTEM \
    -DARROW_BOOST_USE_SHARED=OFF \
    -DARROW_EXTRA_ERROR_CONTEXT=OFF \
    -DARROW_BUILD_SHARED=OFF \
    -DARROW_BUILD_STATIC=ON \
    -DARROW_BUILD_BENCHMARKS=OFF \
    -DARROW_BUILD_EXAMPLES=OFF \
    -DARROW_BUILD_INTEGRATION=OFF \
    -DARROW_BUILD_TESTS=OFF \
    -DARROW_TESTING=OFF \
    -DARROW_BUILD_UTILITIES=OFF \
    -DARROW_TEST_LINKAGE=static \
    -DPARQUET_BUILD_EXAMPLES=OFF \
    -DPARQUET_BUILD_EXECUTABLES=OFF \
    -DPARQUET_REQUIRE_ENCRYPTION=ON \
    -DARROW_CSV=ON \
    -DARROW_JSON=ON \
    -DARROW_FILESYSTEM=ON \
    -DARROW_JEMALLOC=OFF \
    -DARROW_MIMALLOC=OFF \
    -DARROW_PARQUET=ON \
    -DARROW_WITH_BROTLI=ON \
    -DARROW_WITH_BZ2=OFF \
    -DARROW_WITH_LZ4=ON \
    -DARROW_WITH_SNAPPY=ON \
    -DARROW_WITH_ZLIB=ON \
    -DARROW_WITH_ZSTD=ON \
    -DARROW_USE_ASAN=OFF \
    -DARROW_USE_UBSAN=OFF \
    -DARROW_USE_TSAN=OFF \
    -DARROW_FUZZING=OFF








  OFT_CXX_STD=-std=c++20
  oft_build_harness "cpp/src/arrow/ipc/stream_fuzz.cc" "-I$BUILDDIR/src/cpp/src" "-I$BUILDDIR/cmk/src" \
    -DNDEBUG -DARROW_STATIC -DPARQUET_STATIC -DADDRESS_SANITIZER
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build arrow-ipc-stream-fuzz
)

# parquet-arrow-fuzz: the release's target arrow-parquet-arrow-fuzz
(
ov_target_begin arrow-parquet-arrow-fuzz
build_lib() {
  oft_require_target_cxx
  oft_build_blind
  oft_build_harness "cpp/src/parquet/arrow/fuzz.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




































































































VENDOR_FILES="
oft-vendor/brotli-v1.0.9.tar.gz sha256:f9e8d81d0405ba66d181529af42a3354f838c939095ff99930da6aa9cdf6fe46 https://github.com/google/brotli/archive/v1.0.9.tar.gz
oft-vendor/lz4-v1.10.0.tar.gz sha256:537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b https://github.com/lz4/lz4/archive/v1.10.0.tar.gz
oft-vendor/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz sha256:b9290a9a6d444c8e049bd589ab804e0ccf2b05dc5984a19ed5ae75d090064806 https://github.com/miloyip/rapidjson/archive/232389d4f1012dddec4ef84861face2d2ba85709.tar.gz
oft-vendor/simdjson-v4.6.4.tar.gz sha256:b091107844fe928158c5c2265c20360fff312889ddf7ebc4528a0f0f8f2ff9cd https://github.com/simdjson/simdjson/archive/refs/tags/v4.6.4.tar.gz
oft-vendor/snappy-1.2.2.tar.gz sha256:90f74bc1fbf78a6c56b3c4a082a05103b3a56bb17bca1a27e052ea11723292dc https://github.com/google/snappy/archive/1.2.2.tar.gz
oft-vendor/thrift-0.22.0.tar.gz sha256:794a0e455787960d9f27ab92c38e34da27e8deeda7a5db0e59dc64a00df8a1e5 https://www.apache.org/dyn/closer.lua/thrift/0.22.0/thrift-0.22.0.tar.gz?action=download
oft-vendor/xsimd-14.2.0.tar.gz sha256:21e841ab684b05331e81e7f782431753a029ef7b7d9d6d3ddab837e7782a40ee https://github.com/xtensor-stack/xsimd/archive/14.2.0.tar.gz
oft-vendor/zlib-1.3.1.tar.gz sha256:9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 https://zlib.net/fossils/zlib-1.3.1.tar.gz
oft-vendor/zstd-1.5.7.tar.gz sha256:eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3 https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
"



OFT_MAKE_JOBS="${OFT_MAKE_JOBS:-8}"
export OFT_MAKE_JOBS
build_lib() {
  local f v
  oft_require_target_cxx


  for f in brotli-v1.0.9.tar.gz lz4-v1.10.0.tar.gz \
           rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz simdjson-v4.6.4.tar.gz \
           snappy-1.2.2.tar.gz thrift-0.22.0.tar.gz xsimd-14.2.0.tar.gz zlib-1.3.1.tar.gz \
           zstd-1.5.7.tar.gz; do
    [ -f "$SRCDIR/oft-vendor/$f" ] || { echo "oft: arrow: vendored $f missing from $SRCDIR/oft-vendor" >&2; return 1; }
  done

  v="$BUILDDIR/src/oft-vendor"
  ARROW_BROTLI_URL="$v/brotli-v1.0.9.tar.gz"
  ARROW_LZ4_URL="$v/lz4-v1.10.0.tar.gz"
  ARROW_RAPIDJSON_URL="$v/rapidjson-232389d4f1012dddec4ef84861face2d2ba85709.tar.gz"
  ARROW_SIMDJSON_URL="$v/simdjson-v4.6.4.tar.gz"
  ARROW_SNAPPY_URL="$v/snappy-1.2.2.tar.gz"
  ARROW_THRIFT_URL="$v/thrift-0.22.0.tar.gz"
  ARROW_XSIMD_URL="$v/xsimd-14.2.0.tar.gz"
  ARROW_ZLIB_URL="$v/zlib-1.3.1.tar.gz"
  ARROW_ZSTD_URL="$v/zstd-1.5.7.tar.gz"
  export ARROW_BROTLI_URL ARROW_LZ4_URL ARROW_RAPIDJSON_URL ARROW_SIMDJSON_URL \
         ARROW_SNAPPY_URL ARROW_THRIFT_URL ARROW_XSIMD_URL ARROW_ZLIB_URL ARROW_ZSTD_URL

  echo 'add_definitions(-DADDRESS_SANITIZER)' > "$BUILDDIR/oft-arrow-fuzzing-defs.cmake"

  {
    echo 'if(PROJECT_NAME STREQUAL "zlib")'
    echo '  set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "oft: static-only toolchain" FORCE)'
    echo 'elseif(PROJECT_NAME STREQUAL "brotli")'
    echo '  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-Bdynamic")'
    echo 'endif()'
  } > "$BUILDDIR/oft-arrow-ep-fixes.cmake"
  OFT_BUILD_SUBDIR=cpp
  oft_build_cmake \
    -DCMAKE_PROJECT_arrow_INCLUDE="$BUILDDIR/oft-arrow-fuzzing-defs.cmake" \
    -DCMAKE_PROJECT_INCLUDE="$BUILDDIR/oft-arrow-ep-fixes.cmake" \
    -DARROW_USE_CCACHE=OFF \
    -DARROW_DEPENDENCY_SOURCE=BUNDLED \
    -DARROW_OPENSSL_USE_SHARED=OFF \
    -DBOOST_SOURCE=SYSTEM \
    -DARROW_BOOST_USE_SHARED=OFF \
    -DARROW_EXTRA_ERROR_CONTEXT=OFF \
    -DARROW_BUILD_SHARED=OFF \
    -DARROW_BUILD_STATIC=ON \
    -DARROW_BUILD_BENCHMARKS=OFF \
    -DARROW_BUILD_EXAMPLES=OFF \
    -DARROW_BUILD_INTEGRATION=OFF \
    -DARROW_BUILD_TESTS=OFF \
    -DARROW_TESTING=OFF \
    -DARROW_BUILD_UTILITIES=OFF \
    -DARROW_TEST_LINKAGE=static \
    -DPARQUET_BUILD_EXAMPLES=OFF \
    -DPARQUET_BUILD_EXECUTABLES=OFF \
    -DPARQUET_REQUIRE_ENCRYPTION=ON \
    -DARROW_CSV=ON \
    -DARROW_JSON=ON \
    -DARROW_FILESYSTEM=ON \
    -DARROW_JEMALLOC=OFF \
    -DARROW_MIMALLOC=OFF \
    -DARROW_PARQUET=ON \
    -DARROW_WITH_BROTLI=ON \
    -DARROW_WITH_BZ2=OFF \
    -DARROW_WITH_LZ4=ON \
    -DARROW_WITH_SNAPPY=ON \
    -DARROW_WITH_ZLIB=ON \
    -DARROW_WITH_ZSTD=ON \
    -DARROW_USE_ASAN=OFF \
    -DARROW_USE_UBSAN=OFF \
    -DARROW_USE_TSAN=OFF \
    -DARROW_FUZZING=OFF








  OFT_CXX_STD=-std=c++20
  oft_build_harness "cpp/src/parquet/arrow/fuzz.cc" "-I$BUILDDIR/src/cpp/src" "-I$BUILDDIR/cmk/src" \
    -DNDEBUG -DARROW_STATIC -DPARQUET_STATIC -DADDRESS_SANITIZER
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build parquet-arrow-fuzz
)
