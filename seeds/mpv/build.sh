#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of mpv into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzzer_json: the release's target mpv-fuzzer_json
(
ov_target_begin mpv-fuzzer_json
build_lib() {
  oft_build_meson
  oft_build_harness "fuzzers/fuzzer_json.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""














































































build_lib() {
  oft_copy_src
  oftcfg="$BUILDDIR/oftcfg"
  mkdir -p "$oftcfg/libavutil"
  cat > "$oftcfg/config.h" <<'EOF'
                                                    
                                                                               
#define HAVE_POSIX 1
#define HAVE_MEMRCHR 1
EOF
  cat > "$oftcfg/libavutil/common.h" <<'EOF'
                                                                     
                                                                    
                               
#pragma once
#include <stdint.h>
#define oft_av_log2(x) (31 - __builtin_clz((unsigned)(x)))
#define PUT_UTF8(val, tmp, PUT_BYTE)\
    {\
        int bytes, shift;\
        uint32_t in = val;\
        if (in < 0x80) {\
            tmp = in;\
            PUT_BYTE\
        } else {\
            bytes = (oft_av_log2(in) + 4) / 5;\
            shift = (bytes - 1) * 6;\
            tmp = (256 - (256 >> bytes)) | (in >> shift);\
            PUT_BYTE\
            while (shift >= 6) {\
                shift -= 6;\
                tmp = 0x80 | ((in >> shift) & 0x3f);\
                PUT_BYTE\
            }\
        }\
    }
EOF
  cat > "$oftcfg/libavutil/error.h" <<'EOF'
                                                                         
                                                                   
#pragma once
#define AVERROR(e) (-(e))
int av_strerror(int errnum, char *errbuf, unsigned long errbuf_size);
EOF
  cat > "$oftcfg/libavutil/mathematics.h" <<'EOF'
                                                                       
                                                                   
#pragma once
#include <stdint.h>
int64_t av_gcd(int64_t a, int64_t b);
EOF
  mkdir -p "$BUILDDIR/subset"
  for f in misc/json.c misc/bstr.c common/common.c ta/ta.c ta/ta_talloc.c ta/ta_utils.c; do

    "$CC" $CFLAGS -D_GNU_SOURCE \
      -I"$BUILDDIR/src" -I"$BUILDDIR/src/include" -I"$oftcfg" \
      -c "$BUILDDIR/src/$f" \
      -o "$BUILDDIR/subset/$(echo "$f" | tr / _).o" || return 1
  done
  "$CHOST-ar" rcs "$BUILDDIR/subset/libmpvjson.a" "$BUILDDIR/subset"/*.o || return 1
  oft_merge_archives
  oft_build_harness "fuzzers/fuzzer_json.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build fuzzer_json
)
