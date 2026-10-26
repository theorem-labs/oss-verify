# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The oss-verify builder: the pinned toolchain image plus the interface a project's Dockerfile and build.sh are
# written against, in OSS-Fuzz's names ($SRC, $WORK, $OUT, $CC, $CFLAGS, $LIB_FUZZING_ENGINE, $SANITIZER, compile).
# docs/build-contract.md describes it.
#
# The toolchain image is a build argument with no default, so the build fails without one. tools/check passes it
# (--build-arg TOOLCHAIN=<image>): the image the project's lock names, else the newest for the project's language in
# infra/toolchains.tsv, the one file that chooses a toolchain (docs/build-contract.md, "Toolchains").
ARG TOOLCHAIN
FROM ${TOOLCHAIN}

COPY toolchain.sh link-fuzz-target recipes.sh release-target.sh /usr/local/lib/oss-verify/
COPY driver/ /usr/local/lib/oss-verify/driver/
COPY rust/ /usr/local/lib/oss-verify/rust/
COPY python/ /usr/local/lib/oss-verify/python/
COPY go/ /usr/local/lib/oss-verify/go/
COPY compile fetch-commit lay-out-sources /usr/local/bin/
RUN chmod 0755 /usr/local/bin/compile /usr/local/bin/fetch-commit /usr/local/bin/lay-out-sources \
               /usr/local/lib/oss-verify/link-fuzz-target /usr/local/lib/oss-verify/go/compile-go \
 && mkdir -p /src /work /out

ENV SRC=/src \
    WORK=/work \
    OUT=/out \
    SANITIZER=none
WORKDIR /src
CMD ["compile"]
