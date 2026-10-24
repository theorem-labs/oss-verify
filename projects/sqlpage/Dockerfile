# Copyright 2026 SQLPage contributors. SPDX-License-Identifier: Apache-2.0
ARG BASE_BUILDER=oss-verify-base-builder
FROM ${BASE_BUILDER} AS source
ARG REPO
ARG COMMIT
RUN fetch-commit $SRC/upstream/sqlpage

FROM node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS frontend
COPY --from=source /src/upstream/sqlpage /sqlpage
WORKDIR /sqlpage
RUN npm ci --ignore-scripts && npm run build

FROM source
COPY --from=frontend /sqlpage/frontend/dist/ $SRC/upstream/sqlpage/frontend/dist/
COPY . $SRC/project/
RUN lay-out-sources $SRC/project/sources $WORK \
 && cp $SRC/project/build.sh $SRC/build.sh
WORKDIR $SRC
