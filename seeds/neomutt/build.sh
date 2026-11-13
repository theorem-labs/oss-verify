#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of neomutt into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cli-fuzz: the release's target neomutt-cli
(
ov_target_begin neomutt-cli
build_lib() {
  oft_build_autotools
  oft_build_harness "fuzz/cli.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







































build_lib() {
  oft_copy_src
  ( cd "$BUILDDIR/src" \
    && CHOST="$CHOST" CC="$CC" CFLAGS="$CFLAGS" \
       CC_FOR_BUILD=/usr/bin/cc CFLAGS_FOR_BUILD="-O2" \
       ./configure --host="$CHOST" --build=x86_64-pc-linux-gnu \
         --prefix="${OFT_PREFIX:?}" --disable-doc --disable-nls --disable-idn2 \
    && oft_make_then_keep_going \
    && { make install || true; } )
  ( cd "$BUILDDIR/src" || exit 1
    rm -f libneomuttmain.a
    keep=""
    for o in conststrings.o editmsg.o external.o flags.o git_ver.o \
             globals.o help.o module.o mutt_config.o mutt_logging.o \
             mutt_mailbox.o mutt_signal.o mutt_socket.o muttlib.o mx.o \
             system.o usage.o version.o monitor.o; do
      if [ -f "$o" ]; then keep="$keep $o"; fi
    done
    if [ -z "$keep" ]; then
      echo "oft: neomutt: no NEOMUTTOBJS objects found; library build failed upstream of archiving" >&2
      exit 1
    fi
    ar cr libneomuttmain.a $keep )
  oft_merge_archives
  oft_build_harness "fuzz/cli.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}




LIB_EXTRA="-lncursesw -ltinfo"
ov_target_build cli-fuzz
)
