#!/bin/bash
# OSSV-538: scan every layer of a saved image for the token, one line per layer.
# Usage: layers.sh <work dir> <token file>
set -u
work=$1
token=$(cat "$2")
root=$work/layers
mapfile -t blobs < <(find "$root/blobs/sha256" -type f | sort)
echo "blobs in the saved image: ${#blobs[@]}"
layers=0
hits=0
for blob in "${blobs[@]}"; do
  kind=$(file -b --mime-type "$blob")
  if tar -tf "$blob" > /dev/null 2>&1; then
    layers=$((layers + 1))
    files=$(tar -tf "$blob" 2>/dev/null | wc -l)
    n=$(tar -xOf "$blob" 2>/dev/null | grep -c -F -- "$token")
    hits=$((hits + n))
    printf 'layer  %s  %-26s %7s files   token in %s of them\n' "$(basename "$blob")" "$kind" "$files" "$n"
  else
    n=$(grep -c -F -- "$token" "$blob")
    hits=$((hits + n))
    printf 'other  %s  %-26s %7s bytes   token %s time(s)\n' "$(basename "$blob")" "$kind" "$(wc -c < "$blob")" "$n"
  fi
done
printf 'layers scanned: %s   total copies of the token across every layer and blob: %s\n' "$layers" "$hits"
