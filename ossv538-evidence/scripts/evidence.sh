#!/bin/bash
# OSSV-538: each absence, with the command that shows it, spelled out.
# Usage: evidence.sh <work dir> <token file> <log file> <image tag>
set -u
work=$1; token=$(cat "$2"); log=$3; tag=$4
run() { printf '\n$ %s\n' "$1"; eval "$1"; }

echo "image: $tag"
echo "the token this build used: ${#token} bytes, read back from the recording token command"

run "docker history --no-trunc '$tag' | grep -c -F -- \"\$(cat $2)\""
run "docker image inspect '$tag' | grep -c -F -- \"\$(cat $2)\""
run "ls $work/layers/blobs/sha256 | wc -l"
run "for b in $work/layers/blobs/sha256/*; do tar -xOf \"\$b\" 2>/dev/null || cat \"\$b\"; done | grep -c -F -- \"\$(cat $2)\""
run "grep -c -F -- \"\$(cat $2)\" $work/image.tar"
run "docker run --rm --network=none --entrypoint sh '$tag' -c 'printenv | grep -ci oss_verify_git_token; ls -A /run/secrets 2>/dev/null | wc -l'"
run "grep -rc -F -- \"\$(cat $2)\" $work/manifest.yaml"
run "find $work -type f ! -name image.tar ! -path '$work/layers/*' -exec grep -l -F -- \"\$(cat $2)\" {} + | wc -l"
run "grep -c -F -- \"\$(cat $2)\" $log"
