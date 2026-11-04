#!/usr/bin/env bash
# Build the executables of deploy/boards/native.list for arm64 inside an Ubuntu 22.04 userland, with docker buildx and
# QEMU, into dist/native/arm64/. `just build-arm64` picks them up. Run it from the repository root:
# `just build-arm64-native`. CI builds the same on a hosted arm64 runner (the job native-arm64).
set -euo pipefail

command -v docker >/dev/null || { echo "build-arm64-native: docker is not on PATH" >&2; exit 1; }
command -v file >/dev/null || { echo "build-arm64-native: file is not on PATH" >&2; exit 1; }
docker buildx version >/dev/null 2>&1 || { echo "build-arm64-native: docker buildx is not available" >&2; exit 1; }

out=dist/native/arm64
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --platform linux/arm64 runs the userland of the board's architecture; on an amd64 host that is QEMU (binfmt).
docker buildx build --platform linux/arm64 --target artifact --output "type=local,dest=$tmp" \
	-f deploy/boards/Dockerfile.native .

[ -d "$tmp/arm64" ] || { echo "build-arm64-native: the build made no arm64 output" >&2; exit 1; }
rm -rf "$out"
mkdir -p "$(dirname "$out")"
mv "$tmp/arm64" "$out"

# Each one is a dynamically linked ARM aarch64 ELF (it links libpcsclite and glibc).
bad=0
while IFS=$'\t' read -r pkg _tags; do
	[ -n "$pkg" ] || continue
	[[ "$pkg" != '#'* ]] || continue
	[ -f "$out/$pkg" ] || { echo "build-arm64-native: no $pkg in $out" >&2; bad=1; continue; }
	desc=$(file -b "$out/$pkg")
	for want in "ELF 64-bit LSB" "ARM aarch64" "dynamically linked"; do
		case "$desc" in *"$want"*) ;; *) echo "build-arm64-native: $pkg: not \"$want\": $desc" >&2; bad=1 ;; esac
	done
	printf '%-40s %s\n' "$pkg" "$desc"
done <deploy/boards/native.list
[ "$bad" -eq 0 ] || exit 1
echo "build-arm64-native: done, in $out"
