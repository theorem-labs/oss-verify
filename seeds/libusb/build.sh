#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of libusb into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# fuzz_bos_descriptor: the release's target libusb-fuzz_bos_descriptor
(
ov_target_begin libusb-fuzz_bos_descriptor
COMMIT=$(git -C "$SRC/upstream/libusb" rev-parse HEAD)
build_lib() {
  oft_build_autotools
  oft_build_harness "tests/fuzz/fuzz_bos_descriptor.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid







  LIB_EXTRA=$(printf '%s' "${LIB_EXTRA:-}" | sed 's| /opt/musl-sysroot/usr/lib/libsystemd\.a||')
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""



















































build_lib() {
  local stage saved_srcdir e describe=v1.0.30-140-ga45bb163
  case "${COMMIT:?}" in
    a45bb163*) ;;
    *) echo "oft: the .tarball-version constant $describe is for a45bb163, but COMMIT=$COMMIT; re-derive it" >&2; return 1 ;;
  esac
  [ ! -e "${SRCDIR:?}/.tarball-version" ] \
    || { echo "oft: $SRCDIR/.tarball-version exists upstream now; this block would silently override it" >&2; return 1; }
  stage=$(mktemp -d)
  for e in "$SRCDIR"/* "$SRCDIR"/.[!.]* "$SRCDIR"/..?*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    case "${e##*/}" in .git) continue ;; esac
    cp -a "$e" "$stage/"
  done
  [ ! -e "$stage/.git" ] || { echo "oft: $stage/.git exists; the stage did not exclude it" >&2; return 1; }
  grep -qF 'elif [ -f "$srcdir/.tarball-version" ]; then' "$stage/build-aux/gen-describe.sh" \
    || { echo "oft: gen-describe.sh no longer has the .tarball-version arm; re-read the mechanism" >&2; return 1; }
  printf '%s\n' "$describe" > "$stage/.tarball-version"
  [ "$(cat "$stage/.tarball-version")" = "$describe" ] \
    || { echo "oft: $stage/.tarball-version was not written" >&2; return 1; }
  saved_srcdir="$SRCDIR"
  SRCDIR="$stage"
  oft_build_autotools
  SRCDIR="$saved_srcdir"
  grep -qxF "#define LIBUSB_DESCRIBE \"$describe\"" "$BUILDDIR/src/libusb/version_describe.h" \
    || { echo "oft: libusb/version_describe.h does not carry the pinned describe:" >&2
         cat "$BUILDDIR/src/libusb/version_describe.h" >&2 || echo "oft: (no version_describe.h at all)" >&2
         return 1; }
  oft_build_harness "tests/fuzz/fuzz_bos_descriptor.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid


  LIB_EXTRA=$(printf '%s' "${LIB_EXTRA:-}" | sed 's| /opt/musl-sysroot/usr/lib/libsystemd\.a||')
}
ov_target_build fuzz_bos_descriptor
)
