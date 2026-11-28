# check=skip=InvalidDefaultArgInFrom
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The oss-verify builder: a toolchain image, pinned by digest in infra/toolchains.tsv or a lock, plus the interface a
# project's Dockerfile and build.sh are written against, in OSS-Fuzz's names ($SRC, $WORK, $OUT, $CC, $CFLAGS,
# $LIB_FUZZING_ENGINE, $SANITIZER, compile).
# docs/build-contract.md describes it.
#
# The toolchain image is a build argument with no default, so the build fails without one ("base name (${TOOLCHAIN})
# should not be blank"). oss-verify check passes it (--build-arg TOOLCHAIN=<image>): the image --toolchain gives, else
# the one the project's lock names, else the newest for the project's language in infra/toolchains.tsv, the one file
# that lists the toolchains (docs/build-contract.md, "Toolchains"). The parser directive on line 1 keeps BuildKit from
# warning, on every build, that the argument has no default.
ARG TOOLCHAIN
FROM ${TOOLCHAIN}

# SECURITY: the builder trusts no root of eMudhra's emSign CAs or of Comodo's AAA Certificate Services: private keys of
# intermediates under them are compromised (Mozilla's security blog, 2026-10-20, names eMudhra's; the intermediates
# were also cross-signed under AAA Certificate Services). The toolchain images carry them: Alpine's store has the four
# emSign roots, and the certifi of pip, on disk and in ensurepip's wheels, has those and AAA. A project's Dockerfile
# runs on this image with the network, so distrust-roots.py removes them from every store and fails the build if one
# remains. It changes no file that the linker reads, and it runs before the COPYs, so a change to them does not run it
# again. It is bind-mounted, so it leaves no file in the image.
RUN --mount=type=bind,source=distrust-roots.py,target=/tmp/distrust-roots.py python3 /tmp/distrust-roots.py

COPY toolchain.sh link-fuzz-target layout.py dsl.py record-compile recipes.sh release-target.sh /usr/local/lib/oss-verify/
COPY driver/ /usr/local/lib/oss-verify/driver/
COPY rust/ /usr/local/lib/oss-verify/rust/
COPY python/ /usr/local/lib/oss-verify/python/
COPY go/ /usr/local/lib/oss-verify/go/
COPY compile fetch-commit git-credential-oss-verify lay-out-sources /usr/local/bin/
# COPY keeps each file's mode from the checkout, and a checkout's modes follow its umask: 664 and 775 under umask 002
# (Ubuntu's default for a user with a group of their own), 644 and 755 under 022 (a GitHub runner's). The key of the
# CPython runtime (python/runtime.sh) reads the modes of these files and of their directories, so the first chmod gives
# them modes that git alone decides: read for everyone, write for the owner, and execute where git says so (X). The
# second makes the commands executable whatever git says.
RUN chmod -R u=rwX,go=rX /usr/local/lib/oss-verify \
 && chmod 0755 /usr/local/bin/compile /usr/local/bin/fetch-commit /usr/local/bin/lay-out-sources \
               /usr/local/bin/git-credential-oss-verify \
               /usr/local/lib/oss-verify/link-fuzz-target /usr/local/lib/oss-verify/record-compile \
               /usr/local/lib/oss-verify/go/compile-go \
 && mkdir -p /src /work /out

ENV SRC=/src \
    WORK=/work \
    OUT=/out \
    SANITIZER=none
WORKDIR /src
CMD ["compile"]
