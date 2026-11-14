#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libhevc into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# hevc_dec_fuzzer: the release's target libhevc-hevc_dec_fuzzer
(
ov_target_begin libhevc-hevc_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/hevc_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""














































































































































































export SOURCE_DATE_EPOCH=1756684800

build_lib() {
  oft_require_target_cxx



  [ -f "${SRCDIR:?}/oft-vendor/googletest/CMakeLists.txt" ] \
    || { echo "oft: libhevc oft-vendor/googletest absent; refusing" >&2; return 1; }
  [ -f "${SRCDIR:?}/oft-vendor/hevc_test_data/README.md" ] \
    || { echo "oft: libhevc oft-vendor/hevc_test_data absent; refusing" >&2; return 1; }
  rm -rf -- "${BUILDDIR:?}/src-patched"
  mkdir -p "${BUILDDIR:?}/src-patched"
  cp -a "${SRCDIR:?}/." "${BUILDDIR:?}/src-patched/"



  grep -qF 'add_compile_options(-msse4.2 -mno-avx)' \
      "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libhevc -mno-avx line not where this pin expects; refusing" >&2; return 1; }
  [ -f "${BUILDDIR:?}/src-patched/decoder/riscv64/ihevcd_function_selector.c" ] \
    || { echo "oft: libhevc decoder/riscv64 selector absent; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libhevc-riscv64.patch" <<'OFT_LIBHEVC_PATCH'
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 1511a9e..fe3623a 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -17,7 +17,10 @@ if(NOT DEFINED SYSTEM_NAME)
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+                                                                             
+                                                                         
+                                     
+  set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index dbaaad6..7ba1420 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -6,6 +6,8 @@ function(libhevc_add_compile_options)
     add_compile_options(-march=armv8-a)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon -marm)
+  elseif("${SYSTEM_PROCESSOR}" STREQUAL "riscv64")
+                                                                               
   else()
     add_compile_options(-msse4.2 -mno-avx)
   endif()
@@ -46,6 +48,9 @@ function(libhevc_add_definitions)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q -DENABLE_NEON
                     -DDISABLE_NEONINTR)
+  elseif("${SYSTEM_PROCESSOR}" STREQUAL "riscv64")
+                                                                               
+                                                                       
   else()
     add_definitions(-DX86 -DX86_LINUX=1 -DDISABLE_AVX2
                     -DDEFAULT_ARCH=D_ARCH_X86_SSE42)
diff --git a/common/common.cmake b/common/common.cmake
index a3bb40f..d64046e 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -240,6 +240,9 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${HEVC_ROOT}/common/arm/ihevc_function_selector_a9q.c")
 
   include_directories(${HEVC_ROOT}/common/arm)
+elseif("${SYSTEM_PROCESSOR}" STREQUAL "riscv64")
+                                                                              
+  include_directories(${HEVC_ROOT}/common/riscv64)
 else()
   list(
     APPEND
diff --git a/decoder/libhevcdec.cmake b/decoder/libhevcdec.cmake
index 0ec751b..c8e7dcf 100644
--- a/decoder/libhevcdec.cmake
+++ b/decoder/libhevcdec.cmake
@@ -57,6 +57,9 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${HEVC_ROOT}/decoder/arm/ihevcd_itrans_recon_dc_luma.s")
 
   include_directories(${HEVC_ROOT}/decoder/arm)
+elseif("${SYSTEM_PROCESSOR}" STREQUAL "riscv64")
+  list(APPEND LIBHEVCDEC_SRCS
+       "${HEVC_ROOT}/decoder/riscv64/ihevcd_function_selector.c")
 else()
   list(
     APPEND
OFT_LIBHEVC_PATCH
  ( cd "${BUILDDIR:?}/src-patched" && patch -p1 < "${BUILDDIR:?}/oft-libhevc-riscv64.patch" ) \
    || { echo "oft: libhevc riscv64 patch failed to apply; refusing" >&2; return 1; }
  oft_libhevc_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"


  oft_build_cmake \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="${BUILDDIR:?}/src/oft-vendor/googletest" \
    -DFETCHCONTENT_SOURCE_DIR_HEVC_TEST_DATA="${BUILDDIR:?}/src/oft-vendor/hevc_test_data"
  SRCDIR=$oft_libhevc_srcdir_orig
  oft_build_harness "fuzzer/hevc_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}









VENDOR_TREES="
oft-vendor/googletest sha256:1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4 https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip 1
oft-vendor/hevc_test_data sha256:81d669b5b09c56b10270345416588a7cfd71beca1425a0b058d8bcc6bc487617 https://storage.googleapis.com/android_media/external/libhevc/tests/HevcTestRes-1.0.zip 1
"
ov_target_build hevc_dec_fuzzer
)
