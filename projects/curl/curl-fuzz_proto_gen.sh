#!/bin/sh
# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The message code of curl-fuzzer de8de303d3e0's structured fuzz targets, made as its CMakeLists.txt:1652-1789 makes
# it. The code is the same in each build (plain, ubsan, asan, asan-ubsan), so the Dockerfile runs this file one time,
# after lay-out-sources, which lays it out as /work/gen/curl-fuzz_proto_gen.sh. build.sh compiles what it writes.
#
# It writes in /work/gen/curl-fuzz_proto what CMakeLists.txt writes in its build directory:
#   schema_eligibility/annotated.desc     the descriptor set of schemas/curl_fuzzer.proto, with its options
#   schema_eligibility/profiles/<profile>/
#                                         for each profile below: the descriptor, the report, the schema and the
#                                         traits that schema_eligibility.py writes, and the C++ code of that schema
#                                         (generated/<profile>/<profile>.pb.cc and .pb.h)
#   schema_eligibility/authoring.desc, schemas/, schema_eligibility/runtime/, curl_fuzzer_option_manifest.inc
#                                         what schema_eligibility.py also writes for the profile compatibility
#   curl_fuzzer.pb.cc, curl_fuzzer.pb.h   the C++ code of the runtime schema
# The tools: the toolchain's protoc 3.21.12, whose code fits the sysroot's protobuf 3.21.12 that the fuzz targets
# link, with the descriptor.proto of its own install; and, for schema_eligibility.py, the image's python3 with the
# pure-Python protobuf 7.36.2 that curl-fuzzer's uv.lock pins (sources lays it out). The curl.h that the profiles are
# checked against is that of curl-fuzz_bufq's tree, the curl that the fuzz targets build.
set -eu
TREE=/work/ext/curl-fuzzer-de8de303d3e0
PYTHON_PROTOBUF=/work/ext/python-protobuf-7.36.2
CURL_H=/work/ext/curl-fuzz_bufq/src/include/curl/curl.h
PROTOC_INCLUDE=/opt/oft/host-protobuf/include
GEN=/work/gen/curl-fuzz_proto
SE=$GEN/schema_eligibility
# The profiles of the structured fuzz targets that build.sh builds. compatibility comes first: it also writes the
# runtime schema and the option manifest.
PROFILES="compatibility fast_http2 fast_ldap"

rm -rf "$GEN"
mkdir -p "$SE/runtime" "$GEN/schemas"
protoc --proto_path="$TREE/schemas" --proto_path="$PROTOC_INCLUDE" --include_imports --include_source_info \
  --descriptor_set_out="$SE/annotated.desc" "$TREE/schemas/curl_fuzzer.proto"
for profile in $PROFILES; do
  dir=$SE/profiles/$profile
  mkdir -p "$dir"
  set --
  if [ "$profile" = compatibility ]; then
    set -- --authoring-descriptor-out "$SE/authoring.desc" --authoring-schema-out-dir "$GEN/schemas" \
      --runtime-descriptor-out "$SE/runtime/runtime.desc" --runtime-schema-out-dir "$SE/runtime" \
      --native-manifest-out "$GEN/curl_fuzzer_option_manifest.inc"
  fi
  PYTHONPATH="$TREE/src:$PYTHON_PROTOBUF" PYTHONDONTWRITEBYTECODE=1 \
    python3 "$TREE/src/curl_fuzzer_tools/schema_eligibility.py" --descriptor-set "$SE/annotated.desc" \
    --curl-header "$CURL_H" --target-profile-header "$TREE/proto_fuzzer/target_profile.h" --profile "$profile" \
    --projected-descriptor-out "$dir/$profile.desc" --report-out "$dir/$profile.json" --schema-out-dir "$dir" \
    --adapter-out "$dir/generated/$profile/${profile}_traits.h" "$@"
  protoc --descriptor_set_in="$dir/$profile.desc" --cpp_out="$dir" "generated/$profile/$profile.proto"
done
protoc --descriptor_set_in="$SE/runtime/runtime.desc" --cpp_out="$GEN" curl_fuzzer.proto
