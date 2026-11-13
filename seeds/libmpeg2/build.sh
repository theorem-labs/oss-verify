#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libmpeg2 into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# mpeg2_dec_fuzzer: the release's target libmpeg2-mpeg2_dec_fuzzer
(
ov_target_begin libmpeg2-mpeg2_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/mpeg2_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""




















































build_lib() {
  oft_require_target_cxx
  rm -rf -- "${BUILDDIR:?}/src-patched"
  mkdir -p "${BUILDDIR:?}/src-patched"
  cp -a "${SRCDIR:?}/." "${BUILDDIR:?}/src-patched/"
  grep -qF 'add_compile_options(-msse4.2 -mno-avx)' "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libmpeg2 -mno-avx line not where this pin expects; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libmpeg2-riscv.patch" <<'OFT_LIBMPEG2_PATCH'
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -6,7 +6,11 @@
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+                                                                                
+                                                                              
+                                                               
+                                                                          
+  set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
@@ -116,6 +120,14 @@
   include_directories(${MPEG2_ROOT}/common/arm)
   include_directories(${MPEG2_ROOT}/decoder/arm)
 
+elseif("${SYSTEM_PROCESSOR}" MATCHES "riscv")
+  list(APPEND LIBMPEG2DEC_SRCS
+                "${MPEG2_ROOT}/common/riscv/ideint_function_selector.c"
+                "${MPEG2_ROOT}/decoder/riscv/impeg2d_function_selector.c")
+
+  include_directories(${MPEG2_ROOT}/common/riscv)
+  include_directories(${MPEG2_ROOT}/decoder/riscv)
+
 else()
   list(APPEND LIBMPEG2DEC_SRCS
                 "${MPEG2_ROOT}/common/x86/icv_sad_ssse3.c"
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -7,6 +7,9 @@
     add_compile_options(-march=armv8-a)
   elseif(${SYSTEM_PROCESSOR} STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "riscv")
+                                                                              
+                                                       
   else()
     add_compile_options(-msse4.2 -mno-avx)
   endif()
@@ -44,6 +47,8 @@
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC -DENABLE_NEON -DMULTICORE)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q -DENABLE_NEON -DMULTICORE)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "riscv")
+    add_definitions(-DRISCV -DMULTICORE)
   else()
     add_definitions(-DX86 -DX86_LINUX=1 -DDISABLE_AVX2
                     -DDEFAULT_ARCH=D_ARCH_X86_SSE42 -DMULTICORE)
OFT_LIBMPEG2_PATCH
  ( cd "${BUILDDIR:?}/src-patched" && patch -p1 < "${BUILDDIR:?}/oft-libmpeg2-riscv.patch" ) \
    || { echo "oft: libmpeg2 riscv patch failed to apply; refusing" >&2; return 1; }
  oft_libmpeg2_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake
  SRCDIR=$oft_libmpeg2_srcdir_orig
  oft_build_harness "fuzzer/mpeg2_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build mpeg2_dec_fuzzer
)
