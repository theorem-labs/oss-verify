#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libavc into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# avc_dec_fuzzer: the release's target libavc-avc_dec_fuzzer
(
ov_target_begin libavc-avc_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/avc_dec_fuzzer.cpp"
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


  grep -qF 'add_compile_options(-msse4.2 -mavx2 -mfma)' \
      "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libavc -mfma line not where this pin expects; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libavc-riscv.patch" <<'OFT_LIBAVC_PATCH'
diff --git a/CMakeLists.txt b/CMakeLists.txt
index a32ae8c..692d8e2 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -6,7 +6,14 @@ if(NOT DEFINED SYSTEM_NAME)
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  if(CMAKE_CROSSCOMPILING)
+                                                                           
+                                                                         
+                                                                      
+    set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
+  else()
+    set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  endif()
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index 003db87..db05bec 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -7,6 +7,9 @@ function(libavc_add_compile_options)
     add_compile_options(-march=armv8-a)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                         
+                                                             
   else()
     add_compile_options(-msse4.2 -mavx2 -mfma)
   endif()
@@ -44,6 +47,9 @@ function(libavc_add_definitions)
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                            
+                                                                            
   else()
     add_definitions(-DX86 -DX86_LINUX=1
 	    -DDEFAULT_ARCH=D_ARCH_X86_SSE42)
diff --git a/common/common.cmake b/common/common.cmake
index a750f09..311d6de 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -91,6 +91,8 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/common/arm/ih264_weighted_pred_a9q.s")
 
   include_directories(${AVC_ROOT}/common/arm)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/common/svccommon.cmake b/common/svccommon.cmake
index 89785db..fa7603c 100644
--- a/common/svccommon.cmake
+++ b/common/svccommon.cmake
@@ -22,6 +22,8 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR
     "${AVC_ROOT}/common/arm/svc/isvc_mem_fns_neon.c"
     "${AVC_ROOT}/common/arm/svc/isvc_resi_trans_quant_neon.c")
   include_directories(${AVC_ROOT}/common/arm/svc)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/decoder/libavcdec.cmake b/decoder/libavcdec.cmake
index 48a7325..96a1ed6 100644
--- a/decoder/libavcdec.cmake
+++ b/decoder/libavcdec.cmake
@@ -42,6 +42,9 @@ if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "a
     APPEND LIBAVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCDEC_SRCS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBAVCDEC_SRCS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/mvc/libmvcdec.cmake b/decoder/mvc/libmvcdec.cmake
index 6c4639b..a0102c0 100644
--- a/decoder/mvc/libmvcdec.cmake
+++ b/decoder/mvc/libmvcdec.cmake
@@ -50,6 +50,9 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBMVCDEC_ASMS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/svc/libsvcdec.cmake b/decoder/svc/libsvcdec.cmake
index 6644353..dcc0c74 100644
--- a/decoder/svc/libsvcdec.cmake
+++ b/decoder/svc/libsvcdec.cmake
@@ -81,6 +81,13 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_iquant_itrans_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_pred_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_residual_resamp_neon.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCDEC_ASMS
+    "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c"
+    "${AVC_ROOT}/decoder/riscv/svc/isvcd_function_selector.c")
+  include_directories(${AVC_ROOT}/decoder/riscv/svc)
 else()
   list(
     APPEND
diff --git a/encoder/libavcenc.cmake b/encoder/libavcenc.cmake
index a8b525c..736cac9 100644
--- a/encoder/libavcenc.cmake
+++ b/encoder/libavcenc.cmake
@@ -72,6 +72,10 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
 
   include_directories(${AVC_ROOT}/encoder/armv8)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCENC_SRCS
+       "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
 else()
   list(
     APPEND
diff --git a/encoder/svc/libsvcenc.cmake b/encoder/svc/libsvcenc.cmake
index 91dda45..512b16a 100644
--- a/encoder/svc/libsvcenc.cmake
+++ b/encoder/svc/libsvcenc.cmake
@@ -100,6 +100,14 @@ elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ih264e_fmt_conv.s"
     "${AVC_ROOT}/encoder/arm/ih264e_half_pel.s"
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCENC_SRCS
+    "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c"
+    "${AVC_ROOT}/encoder/riscv/svc/isvce_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
+  include_directories(${AVC_ROOT}/encoder/riscv/svc)
 else()
   list(
     APPEND
OFT_LIBAVC_PATCH
  ( cd "${BUILDDIR:?}/src-patched" \
    && patch -p1 < "${BUILDDIR:?}/oft-libavc-riscv.patch" ) \
    || { echo "oft: libavc riscv patch failed to apply; refusing" >&2; return 1; }
  oft_libavc_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake
  SRCDIR=$oft_libavc_srcdir_orig
  oft_build_harness "fuzzer/avc_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build avc_dec_fuzzer
)

# avc_enc_fuzzer: the release's target libavc-avc_enc_fuzzer
(
ov_target_begin libavc-avc_enc_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/avc_enc_fuzzer.cpp"
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


  grep -qF 'add_compile_options(-msse4.2 -mavx2 -mfma)' \
      "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libavc -mfma line not where this pin expects; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libavc-riscv.patch" <<'OFT_LIBAVC_PATCH'
diff --git a/CMakeLists.txt b/CMakeLists.txt
index a32ae8c..692d8e2 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -6,7 +6,14 @@ if(NOT DEFINED SYSTEM_NAME)
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  if(CMAKE_CROSSCOMPILING)
+                                                                           
+                                                                         
+                                                                      
+    set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
+  else()
+    set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  endif()
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index 003db87..db05bec 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -7,6 +7,9 @@ function(libavc_add_compile_options)
     add_compile_options(-march=armv8-a)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                         
+                                                             
   else()
     add_compile_options(-msse4.2 -mavx2 -mfma)
   endif()
@@ -44,6 +47,9 @@ function(libavc_add_definitions)
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                            
+                                                                            
   else()
     add_definitions(-DX86 -DX86_LINUX=1
 	    -DDEFAULT_ARCH=D_ARCH_X86_SSE42)
diff --git a/common/common.cmake b/common/common.cmake
index a750f09..311d6de 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -91,6 +91,8 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/common/arm/ih264_weighted_pred_a9q.s")
 
   include_directories(${AVC_ROOT}/common/arm)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/common/svccommon.cmake b/common/svccommon.cmake
index 89785db..fa7603c 100644
--- a/common/svccommon.cmake
+++ b/common/svccommon.cmake
@@ -22,6 +22,8 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR
     "${AVC_ROOT}/common/arm/svc/isvc_mem_fns_neon.c"
     "${AVC_ROOT}/common/arm/svc/isvc_resi_trans_quant_neon.c")
   include_directories(${AVC_ROOT}/common/arm/svc)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/decoder/libavcdec.cmake b/decoder/libavcdec.cmake
index 48a7325..96a1ed6 100644
--- a/decoder/libavcdec.cmake
+++ b/decoder/libavcdec.cmake
@@ -42,6 +42,9 @@ if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "a
     APPEND LIBAVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCDEC_SRCS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBAVCDEC_SRCS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/mvc/libmvcdec.cmake b/decoder/mvc/libmvcdec.cmake
index 6c4639b..a0102c0 100644
--- a/decoder/mvc/libmvcdec.cmake
+++ b/decoder/mvc/libmvcdec.cmake
@@ -50,6 +50,9 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBMVCDEC_ASMS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/svc/libsvcdec.cmake b/decoder/svc/libsvcdec.cmake
index 6644353..dcc0c74 100644
--- a/decoder/svc/libsvcdec.cmake
+++ b/decoder/svc/libsvcdec.cmake
@@ -81,6 +81,13 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_iquant_itrans_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_pred_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_residual_resamp_neon.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCDEC_ASMS
+    "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c"
+    "${AVC_ROOT}/decoder/riscv/svc/isvcd_function_selector.c")
+  include_directories(${AVC_ROOT}/decoder/riscv/svc)
 else()
   list(
     APPEND
diff --git a/encoder/libavcenc.cmake b/encoder/libavcenc.cmake
index a8b525c..736cac9 100644
--- a/encoder/libavcenc.cmake
+++ b/encoder/libavcenc.cmake
@@ -72,6 +72,10 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
 
   include_directories(${AVC_ROOT}/encoder/armv8)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCENC_SRCS
+       "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
 else()
   list(
     APPEND
diff --git a/encoder/svc/libsvcenc.cmake b/encoder/svc/libsvcenc.cmake
index 91dda45..512b16a 100644
--- a/encoder/svc/libsvcenc.cmake
+++ b/encoder/svc/libsvcenc.cmake
@@ -100,6 +100,14 @@ elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ih264e_fmt_conv.s"
     "${AVC_ROOT}/encoder/arm/ih264e_half_pel.s"
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCENC_SRCS
+    "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c"
+    "${AVC_ROOT}/encoder/riscv/svc/isvce_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
+  include_directories(${AVC_ROOT}/encoder/riscv/svc)
 else()
   list(
     APPEND
OFT_LIBAVC_PATCH
  ( cd "${BUILDDIR:?}/src-patched" \
    && patch -p1 < "${BUILDDIR:?}/oft-libavc-riscv.patch" ) \
    || { echo "oft: libavc riscv patch failed to apply; refusing" >&2; return 1; }
  oft_libavc_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake
  SRCDIR=$oft_libavc_srcdir_orig
  oft_build_harness "fuzzer/avc_enc_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build avc_enc_fuzzer
)

# mvc_dec_fuzzer: the release's target libavc-mvc_dec_fuzzer
(
ov_target_begin libavc-mvc_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/mvc_dec_fuzzer.cpp"
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


  grep -qF 'add_compile_options(-msse4.2 -mavx2 -mfma)' \
      "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libavc -mfma line not where this pin expects; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libavc-riscv.patch" <<'OFT_LIBAVC_PATCH'
diff --git a/CMakeLists.txt b/CMakeLists.txt
index a32ae8c..692d8e2 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -6,7 +6,14 @@ if(NOT DEFINED SYSTEM_NAME)
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  if(CMAKE_CROSSCOMPILING)
+                                                                           
+                                                                         
+                                                                      
+    set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
+  else()
+    set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  endif()
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index 003db87..db05bec 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -7,6 +7,9 @@ function(libavc_add_compile_options)
     add_compile_options(-march=armv8-a)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                         
+                                                             
   else()
     add_compile_options(-msse4.2 -mavx2 -mfma)
   endif()
@@ -44,6 +47,9 @@ function(libavc_add_definitions)
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                            
+                                                                            
   else()
     add_definitions(-DX86 -DX86_LINUX=1
 	    -DDEFAULT_ARCH=D_ARCH_X86_SSE42)
diff --git a/common/common.cmake b/common/common.cmake
index a750f09..311d6de 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -91,6 +91,8 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/common/arm/ih264_weighted_pred_a9q.s")
 
   include_directories(${AVC_ROOT}/common/arm)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/common/svccommon.cmake b/common/svccommon.cmake
index 89785db..fa7603c 100644
--- a/common/svccommon.cmake
+++ b/common/svccommon.cmake
@@ -22,6 +22,8 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR
     "${AVC_ROOT}/common/arm/svc/isvc_mem_fns_neon.c"
     "${AVC_ROOT}/common/arm/svc/isvc_resi_trans_quant_neon.c")
   include_directories(${AVC_ROOT}/common/arm/svc)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/decoder/libavcdec.cmake b/decoder/libavcdec.cmake
index 48a7325..96a1ed6 100644
--- a/decoder/libavcdec.cmake
+++ b/decoder/libavcdec.cmake
@@ -42,6 +42,9 @@ if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "a
     APPEND LIBAVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCDEC_SRCS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBAVCDEC_SRCS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/mvc/libmvcdec.cmake b/decoder/mvc/libmvcdec.cmake
index 6c4639b..a0102c0 100644
--- a/decoder/mvc/libmvcdec.cmake
+++ b/decoder/mvc/libmvcdec.cmake
@@ -50,6 +50,9 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBMVCDEC_ASMS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/svc/libsvcdec.cmake b/decoder/svc/libsvcdec.cmake
index 6644353..dcc0c74 100644
--- a/decoder/svc/libsvcdec.cmake
+++ b/decoder/svc/libsvcdec.cmake
@@ -81,6 +81,13 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_iquant_itrans_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_pred_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_residual_resamp_neon.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCDEC_ASMS
+    "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c"
+    "${AVC_ROOT}/decoder/riscv/svc/isvcd_function_selector.c")
+  include_directories(${AVC_ROOT}/decoder/riscv/svc)
 else()
   list(
     APPEND
diff --git a/encoder/libavcenc.cmake b/encoder/libavcenc.cmake
index a8b525c..736cac9 100644
--- a/encoder/libavcenc.cmake
+++ b/encoder/libavcenc.cmake
@@ -72,6 +72,10 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
 
   include_directories(${AVC_ROOT}/encoder/armv8)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCENC_SRCS
+       "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
 else()
   list(
     APPEND
diff --git a/encoder/svc/libsvcenc.cmake b/encoder/svc/libsvcenc.cmake
index 91dda45..512b16a 100644
--- a/encoder/svc/libsvcenc.cmake
+++ b/encoder/svc/libsvcenc.cmake
@@ -100,6 +100,14 @@ elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ih264e_fmt_conv.s"
     "${AVC_ROOT}/encoder/arm/ih264e_half_pel.s"
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCENC_SRCS
+    "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c"
+    "${AVC_ROOT}/encoder/riscv/svc/isvce_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
+  include_directories(${AVC_ROOT}/encoder/riscv/svc)
 else()
   list(
     APPEND
OFT_LIBAVC_PATCH
  ( cd "${BUILDDIR:?}/src-patched" \
    && patch -p1 < "${BUILDDIR:?}/oft-libavc-riscv.patch" ) \
    || { echo "oft: libavc riscv patch failed to apply; refusing" >&2; return 1; }
  oft_libavc_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake -DENABLE_MVC=ON
  SRCDIR=$oft_libavc_srcdir_orig
  oft_build_harness "fuzzer/mvc_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build mvc_dec_fuzzer
)

# svc_dec_fuzzer: the release's target libavc-svc_dec_fuzzer
(
ov_target_begin libavc-svc_dec_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/svc_dec_fuzzer.cpp"
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


  grep -qF 'add_compile_options(-msse4.2 -mavx2 -mfma)' \
      "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libavc -mfma line not where this pin expects; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libavc-riscv.patch" <<'OFT_LIBAVC_PATCH'
diff --git a/CMakeLists.txt b/CMakeLists.txt
index a32ae8c..692d8e2 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -6,7 +6,14 @@ if(NOT DEFINED SYSTEM_NAME)
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  if(CMAKE_CROSSCOMPILING)
+                                                                           
+                                                                         
+                                                                      
+    set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
+  else()
+    set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  endif()
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index 003db87..db05bec 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -7,6 +7,9 @@ function(libavc_add_compile_options)
     add_compile_options(-march=armv8-a)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                         
+                                                             
   else()
     add_compile_options(-msse4.2 -mavx2 -mfma)
   endif()
@@ -44,6 +47,9 @@ function(libavc_add_definitions)
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                            
+                                                                            
   else()
     add_definitions(-DX86 -DX86_LINUX=1
 	    -DDEFAULT_ARCH=D_ARCH_X86_SSE42)
diff --git a/common/common.cmake b/common/common.cmake
index a750f09..311d6de 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -91,6 +91,8 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/common/arm/ih264_weighted_pred_a9q.s")
 
   include_directories(${AVC_ROOT}/common/arm)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/common/svccommon.cmake b/common/svccommon.cmake
index 89785db..fa7603c 100644
--- a/common/svccommon.cmake
+++ b/common/svccommon.cmake
@@ -22,6 +22,8 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR
     "${AVC_ROOT}/common/arm/svc/isvc_mem_fns_neon.c"
     "${AVC_ROOT}/common/arm/svc/isvc_resi_trans_quant_neon.c")
   include_directories(${AVC_ROOT}/common/arm/svc)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/decoder/libavcdec.cmake b/decoder/libavcdec.cmake
index 48a7325..96a1ed6 100644
--- a/decoder/libavcdec.cmake
+++ b/decoder/libavcdec.cmake
@@ -42,6 +42,9 @@ if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "a
     APPEND LIBAVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCDEC_SRCS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBAVCDEC_SRCS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/mvc/libmvcdec.cmake b/decoder/mvc/libmvcdec.cmake
index 6c4639b..a0102c0 100644
--- a/decoder/mvc/libmvcdec.cmake
+++ b/decoder/mvc/libmvcdec.cmake
@@ -50,6 +50,9 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBMVCDEC_ASMS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/svc/libsvcdec.cmake b/decoder/svc/libsvcdec.cmake
index 6644353..dcc0c74 100644
--- a/decoder/svc/libsvcdec.cmake
+++ b/decoder/svc/libsvcdec.cmake
@@ -81,6 +81,13 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_iquant_itrans_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_pred_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_residual_resamp_neon.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCDEC_ASMS
+    "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c"
+    "${AVC_ROOT}/decoder/riscv/svc/isvcd_function_selector.c")
+  include_directories(${AVC_ROOT}/decoder/riscv/svc)
 else()
   list(
     APPEND
diff --git a/encoder/libavcenc.cmake b/encoder/libavcenc.cmake
index a8b525c..736cac9 100644
--- a/encoder/libavcenc.cmake
+++ b/encoder/libavcenc.cmake
@@ -72,6 +72,10 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
 
   include_directories(${AVC_ROOT}/encoder/armv8)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCENC_SRCS
+       "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
 else()
   list(
     APPEND
diff --git a/encoder/svc/libsvcenc.cmake b/encoder/svc/libsvcenc.cmake
index 91dda45..512b16a 100644
--- a/encoder/svc/libsvcenc.cmake
+++ b/encoder/svc/libsvcenc.cmake
@@ -100,6 +100,14 @@ elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ih264e_fmt_conv.s"
     "${AVC_ROOT}/encoder/arm/ih264e_half_pel.s"
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCENC_SRCS
+    "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c"
+    "${AVC_ROOT}/encoder/riscv/svc/isvce_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
+  include_directories(${AVC_ROOT}/encoder/riscv/svc)
 else()
   list(
     APPEND
OFT_LIBAVC_PATCH
  ( cd "${BUILDDIR:?}/src-patched" \
    && patch -p1 < "${BUILDDIR:?}/oft-libavc-riscv.patch" ) \
    || { echo "oft: libavc riscv patch failed to apply; refusing" >&2; return 1; }
  oft_libavc_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake -DENABLE_SVC=ON
  SRCDIR=$oft_libavc_srcdir_orig
  oft_build_harness "fuzzer/svc_dec_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build svc_dec_fuzzer
)

# svc_enc_fuzzer: the release's target libavc-svc_enc_fuzzer
(
ov_target_begin libavc-svc_enc_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "fuzzer/svc_enc_fuzzer.cpp"
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


  grep -qF 'add_compile_options(-msse4.2 -mavx2 -mfma)' \
      "${BUILDDIR:?}/src-patched/cmake/utils.cmake" \
    || { echo "oft: libavc -mfma line not where this pin expects; refusing" >&2; return 1; }
  cat > "${BUILDDIR:?}/oft-libavc-riscv.patch" <<'OFT_LIBAVC_PATCH'
diff --git a/CMakeLists.txt b/CMakeLists.txt
index a32ae8c..692d8e2 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -6,7 +6,14 @@ if(NOT DEFINED SYSTEM_NAME)
 endif()
 
 if(NOT DEFINED SYSTEM_PROCESSOR)
-  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  if(CMAKE_CROSSCOMPILING)
+                                                                           
+                                                                         
+                                                                      
+    set(SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
+  else()
+    set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+  endif()
 endif()
 
 if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index 003db87..db05bec 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -7,6 +7,9 @@ function(libavc_add_compile_options)
     add_compile_options(-march=armv8-a)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                         
+                                                             
   else()
     add_compile_options(-msse4.2 -mavx2 -mfma)
   endif()
@@ -44,6 +47,9 @@ function(libavc_add_definitions)
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
   elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q)
+  elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+                                                                            
+                                                                            
   else()
     add_definitions(-DX86 -DX86_LINUX=1
 	    -DDEFAULT_ARCH=D_ARCH_X86_SSE42)
diff --git a/common/common.cmake b/common/common.cmake
index a750f09..311d6de 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -91,6 +91,8 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/common/arm/ih264_weighted_pred_a9q.s")
 
   include_directories(${AVC_ROOT}/common/arm)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/common/svccommon.cmake b/common/svccommon.cmake
index 89785db..fa7603c 100644
--- a/common/svccommon.cmake
+++ b/common/svccommon.cmake
@@ -22,6 +22,8 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR
     "${AVC_ROOT}/common/arm/svc/isvc_mem_fns_neon.c"
     "${AVC_ROOT}/common/arm/svc/isvc_resi_trans_quant_neon.c")
   include_directories(${AVC_ROOT}/common/arm/svc)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  include_directories(${AVC_ROOT}/common/riscv)
 else()
   list(
     APPEND
diff --git a/decoder/libavcdec.cmake b/decoder/libavcdec.cmake
index 48a7325..96a1ed6 100644
--- a/decoder/libavcdec.cmake
+++ b/decoder/libavcdec.cmake
@@ -42,6 +42,9 @@ if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "a
     APPEND LIBAVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCDEC_SRCS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBAVCDEC_SRCS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/mvc/libmvcdec.cmake b/decoder/mvc/libmvcdec.cmake
index 6c4639b..a0102c0 100644
--- a/decoder/mvc/libmvcdec.cmake
+++ b/decoder/mvc/libmvcdec.cmake
@@ -50,6 +50,9 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_av8.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBMVCDEC_ASMS
+       "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c")
 else()
   list(
     APPEND LIBMVCDEC_ASMS "${AVC_ROOT}/decoder/x86/ih264d_function_selector.c"
diff --git a/decoder/svc/libsvcdec.cmake b/decoder/svc/libsvcdec.cmake
index 6644353..dcc0c74 100644
--- a/decoder/svc/libsvcdec.cmake
+++ b/decoder/svc/libsvcdec.cmake
@@ -81,6 +81,13 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_iquant_itrans_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_pred_residual_recon_neon.c"
     "${AVC_ROOT}/decoder/arm/svc/isvcd_residual_resamp_neon.c")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCDEC_ASMS
+    "${AVC_ROOT}/decoder/riscv/ih264d_function_selector.c"
+    "${AVC_ROOT}/decoder/riscv/svc/isvcd_function_selector.c")
+  include_directories(${AVC_ROOT}/decoder/riscv/svc)
 else()
   list(
     APPEND
diff --git a/encoder/libavcenc.cmake b/encoder/libavcenc.cmake
index a8b525c..736cac9 100644
--- a/encoder/libavcenc.cmake
+++ b/encoder/libavcenc.cmake
@@ -72,6 +72,10 @@ elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
 
   include_directories(${AVC_ROOT}/encoder/armv8)
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(APPEND LIBAVCENC_SRCS
+       "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
 else()
   list(
     APPEND
diff --git a/encoder/svc/libsvcenc.cmake b/encoder/svc/libsvcenc.cmake
index 91dda45..512b16a 100644
--- a/encoder/svc/libsvcenc.cmake
+++ b/encoder/svc/libsvcenc.cmake
@@ -100,6 +100,14 @@ elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
     "${AVC_ROOT}/encoder/arm/ih264e_fmt_conv.s"
     "${AVC_ROOT}/encoder/arm/ih264e_half_pel.s"
     "${AVC_ROOT}/encoder/arm/ime_distortion_metrics_a9q.s")
+elseif("${SYSTEM_PROCESSOR}" MATCHES "^riscv")
+  list(
+    APPEND
+    LIBSVCENC_SRCS
+    "${AVC_ROOT}/encoder/riscv/ih264e_function_selector.c"
+    "${AVC_ROOT}/encoder/riscv/svc/isvce_function_selector.c")
+  include_directories(${AVC_ROOT}/encoder/riscv)
+  include_directories(${AVC_ROOT}/encoder/riscv/svc)
 else()
   list(
     APPEND
OFT_LIBAVC_PATCH
  ( cd "${BUILDDIR:?}/src-patched" \
    && patch -p1 < "${BUILDDIR:?}/oft-libavc-riscv.patch" ) \
    || { echo "oft: libavc riscv patch failed to apply; refusing" >&2; return 1; }
  oft_libavc_srcdir_orig=$SRCDIR
  SRCDIR="${BUILDDIR:?}/src-patched"
  oft_build_cmake -DENABLE_SVC=ON
  SRCDIR=$oft_libavc_srcdir_orig
  oft_build_harness "fuzzer/svc_enc_fuzzer.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build svc_enc_fuzzer
)
