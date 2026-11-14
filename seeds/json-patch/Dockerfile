# Ported from the Go build of the oss-fuzz-theorems 2026.10 release (seeds/languages.tsv); do not edit.
#
# json-patch on the OSS Verify builder, as the release built it: OSS-Fuzz's build.sh with OSS-Fuzz's Go helpers, in the
# Go toolchain image (go/compile-go). oss-verify check passes REPO, COMMIT and BASE_BUILDER.
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER}
ARG REPO
ARG COMMIT
# The modules that go.lock pins, as the module proxy of the build (lay-out-sources).
COPY sources go.lock $WORK/project/
RUN lay-out-sources $WORK/project/sources $WORK
# From here, OSS-Fuzz's projects/json-patch/Dockerfile (oss-fuzz 10625fc98598) as the release's build carried it out: the
# checkout at COMMIT in place of its git clone, and its other RUN lines not run.
RUN fetch-commit $SRC/json-patch
# not run: RUN wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && mkdir temp-go && ...
COPY fuzz_*.go $SRC/json-patch/
COPY build.sh $SRC/
WORKDIR $SRC/json-patch
