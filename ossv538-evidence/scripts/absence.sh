#!/bin/bash
# OSSV-538: show that the token a build used is in none of the places it could be kept.
# Usage: absence.sh <work dir> <token file> <log file>
set -u
work=$1; tokenfile=$2; log=$3
token=$(cat "$tokenfile")
image=$(python3 - "$work" <<'EOF'
import pathlib, sys, yaml
print(yaml.safe_load((pathlib.Path(sys.argv[1]) / "manifest.yaml").read_text())["builder"]["project_image"])
EOF
)
tag=$(tail -1 "$work/images")
echo "### image $tag ($image)"
echo "### token: ${#token} bytes, starts ${token:0:4}"

echo
echo "--- 1. image history: docker history --no-trunc"
docker history --no-trunc --format '{{.CreatedBy}}' "$tag" > "$work/history.txt"
printf 'lines: %s   copies of the token: %s\n' "$(wc -l < "$work/history.txt")" \
  "$(grep -c -F -- "$token" "$work/history.txt")"

echo
echo "--- 1b. image configuration: docker image inspect (env, args, labels)"
docker image inspect "$tag" > "$work/inspect.json"
printf 'bytes: %s   copies of the token: %s\n' "$(wc -c < "$work/inspect.json")" \
  "$(grep -c -F -- "$token" "$work/inspect.json")"

echo
echo "--- 2. every layer: docker save, then each layer's bytes"
rm -rf "$work/layers"; mkdir -p "$work/layers"
docker save "$tag" -o "$work/image.tar"
tar -xf "$work/image.tar" -C "$work/layers"
layers=$(find "$work/layers" -name '*.tar' -o -name 'layer.tar' | sort -u)
count=0
hits=0
for layer in $layers; do
  count=$((count + 1))
  n=$(tar -xOf "$layer" 2>/dev/null | grep -c -F -- "$token")
  hits=$((hits + n))
  printf '  layer %-70s files-with-token %s\n' "${layer#$work/layers/}" "$n"
done
# Every other file of the saved image (manifest, config blobs, and any blob that is not a tar).
other=$(find "$work/layers" -type f ! -name '*.tar' | wc -l)
otherhits=$(find "$work/layers" -type f ! -name '*.tar' -exec grep -l -F -- "$token" {} + 2>/dev/null | wc -l)
printf 'layers: %s  copies of the token in layer contents: %s\n' "$count" "$hits"
printf 'other files in the saved image: %s  holding the token: %s\n' "$other" "$otherhits"
# Belt and braces: the whole saved image as one byte stream.
printf 'the whole saved image (%s bytes) holds the token: %s time(s)\n' \
  "$(wc -c < "$work/image.tar")" "$(grep -c -F -- "$token" "$work/image.tar")"

echo
echo "--- 2b. the running container's filesystem and environment"
docker run --rm --network=none --entrypoint sh "$tag" -c \
  'printenv | grep -c -i "oss_verify_git_token\|ossv_git_token" ; ls /run/secrets 2>/dev/null | wc -l' \
  > "$work/container.txt" 2>&1
echo "environment variables naming the token / files in /run/secrets:"
cat "$work/container.txt"
echo "the checkout's remote and config in the image:"
docker run --rm --network=none --entrypoint sh "$tag" -c \
  'git -C $(ls -d /src/*/ | head -1) remote -v; grep -c -F -- "'"$token"'" $(ls -d /src/*/ | head -1).git/config 2>/dev/null || true' 2>&1 | sed 's/^/    /'

echo
echo "--- 3. the facts: everything tools/check wrote"
printf 'files: %s   holding the token: %s\n' \
  "$(find "$work" -type f ! -name 'image.tar' ! -path "$work/layers/*" | wc -l)" \
  "$(find "$work" -type f ! -name 'image.tar' ! -path "$work/layers/*" -exec grep -l -F -- "$token" {} + 2>/dev/null | wc -l)"
printf 'manifest.yaml holds the token: %s time(s)\n' "$(grep -c -F -- "$token" "$work/manifest.yaml")"

echo
echo "--- 4. the build log"
printf '%s: %s lines, %s copies of the token\n' "$log" "$(wc -l < "$log")" "$(grep -c -F -- "$token" "$log")"
