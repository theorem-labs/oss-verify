#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of sleuthkit into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fls_apfs_fuzzer: the release's target sleuthkit-fls_apfs_fuzzer
(
ov_target_begin sleuthkit-fls_apfs_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "ossfuzz/fls_apfs_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





























































oft_sleuthkit_stdcxx_shim() {
  OFT_SLEUTHKIT_SHIM=/tmp/oft-sleuthkit-stdcxx-shim
  mkdir -p "$OFT_SLEUTHKIT_SHIM"
  printf '!<arch>\n' > "$OFT_SLEUTHKIT_SHIM/libstdc++.a"
}



build_lib() {
  oft_require_target_cxx
  oft_sleuthkit_stdcxx_shim
  oft_build_autotools --disable-java --without-afflib --without-libcrypto \
    --without-libewf --without-libvhdi --without-libvmdk \
    LDFLAGS="-L$OFT_SLEUTHKIT_SHIM"
  oft_build_harness "ossfuzz/fls_apfs_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fls_apfs_fuzzer
)

# fls_ext_fuzzer: the release's target sleuthkit-fls_ext_fuzzer
(
ov_target_begin sleuthkit-fls_ext_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "ossfuzz/fls_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































oft_sleuthkit_stdcxx_shim() {
  OFT_SLEUTHKIT_SHIM=/tmp/oft-sleuthkit-stdcxx-shim
  mkdir -p "$OFT_SLEUTHKIT_SHIM"
  printf '!<arch>\n' > "$OFT_SLEUTHKIT_SHIM/libstdc++.a"
}



build_lib() {
  oft_require_target_cxx
  oft_sleuthkit_stdcxx_shim
  oft_build_autotools --disable-java --without-afflib --without-libcrypto \
    --without-libewf --without-libvhdi --without-libvmdk \
    LDFLAGS="-L$OFT_SLEUTHKIT_SHIM"
  oft_build_harness "ossfuzz/fls_fuzzer.cc" -DFSTYPE=TSK_FS_TYPE_EXT_DETECT
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fls_ext_fuzzer
)

# fls_ntfs_fuzzer: the release's target sleuthkit-fls_ntfs_fuzzer
(
ov_target_begin sleuthkit-fls_ntfs_fuzzer
build_lib() {
  oft_require_target_cxx
  oft_build_autotools
  oft_build_harness "ossfuzz/fls_fuzzer.cc"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""






























































oft_sleuthkit_stdcxx_shim() {
  OFT_SLEUTHKIT_SHIM=/tmp/oft-sleuthkit-stdcxx-shim
  mkdir -p "$OFT_SLEUTHKIT_SHIM"
  printf '!<arch>\n' > "$OFT_SLEUTHKIT_SHIM/libstdc++.a"
}



build_lib() {
  oft_require_target_cxx
  oft_sleuthkit_stdcxx_shim
  oft_build_autotools --disable-java --without-afflib --without-libcrypto \
    --without-libewf --without-libvhdi --without-libvmdk \
    LDFLAGS="-L$OFT_SLEUTHKIT_SHIM"
  oft_build_harness "ossfuzz/fls_fuzzer.cc" -DFSTYPE=TSK_FS_TYPE_NTFS
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fls_ntfs_fuzzer
)
