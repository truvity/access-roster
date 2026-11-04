#!/usr/bin/env bash
# Cross-compile every executable of sluis for the arm64 boards into dist/arm64/, and check what came out.
#
#   Go    actors/<a>, drivers/<owner>/<d>, cli/<c>   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath
#   Rust  the same directories                        cargo zigbuild --release --target aarch64-unknown-linux-musl
#
# The output keeps the directory: dist/arm64/actors/<a>, dist/arm64/drivers/<owner>/<d>, dist/arm64/cli/<c>
# (PLAN.md "Board deployment"). Run it from the repository root: `just build-arm64`.
# A build that makes no binary, or one that is not a static aarch64 ELF, fails.
set -euo pipefail

for tool in go cargo jq file; do
	command -v "$tool" >/dev/null || { echo "build-arm64: $tool is not on PATH (run it as: devbox run -- just build-arm64)" >&2; exit 1; }
done

target=aarch64-unknown-linux-musl
out=dist/arm64
version_pkg=github.com/truvity/sluis/v2/kits/go/version
version=${SLUIS_VERSION:-0.0.0-dev}

rm -rf "$out"
mkdir -p "$out"
built=()

# Go: every package main below actors/, drivers/ and cli/. The test binaries (kits/conformance) are not product.
while IFS= read -r rel; do
	[ -n "$rel" ] || continue
	echo "go    $rel"
	mkdir -p "$out/$(dirname "$rel")"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X ${version_pkg}.Version=${version}" -o "$out/$rel" "./$rel"
	built+=("$rel")
done < <(
	# An empty pattern only warns ("matched no packages"); a real error must show, so stderr is kept for it.
	errs=$(mktemp)
	if ! list=$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./actors/... ./drivers/... ./cli/... 2>"$errs"); then
		cat "$errs" >&2
		rm -f "$errs"
		echo "build-arm64: go list failed" >&2
		exit 1
	fi
	rm -f "$errs"
	printf '%s\n' "${list//github.com\/truvity\/sluis\/v2\//}"
)

# Rust: every package of the workspace below actors/ and drivers/ that has a binary. cargo metadata names the
# directory of the manifest; the binary is copied to the same place in dist.
root=$(pwd)
meta=$(cargo metadata --format-version 1 --no-deps)
tdir=$(jq -r .target_directory <<<"$meta")
while IFS=$'\t' read -r pkg dir bin; do
	[ -n "$pkg" ] || continue
	rel=${dir#"$root"/}
	case "$rel" in actors/* | drivers/*/* | cli/*) ;; *) continue ;; esac
	echo "rust  $rel ($pkg)"
	SLUIS_VERSION=$version cargo zigbuild --release --target "$target" -p "$pkg"
	mkdir -p "$out/$(dirname "$rel")"
	install -m 0755 "$tdir/$target/release/$bin" "$out/$rel"
	built+=("$rel")
done < <(jq -r '.packages[] | . as $p | $p.targets[] | select(.kind | index("bin")) | [$p.name, ($p.manifest_path | rtrimstr("/Cargo.toml")), .name] | @tsv' <<<"$meta")

[ "${#built[@]}" -gt 0 ] || { echo "build-arm64: no executable found below actors/, drivers/ or cli/: nothing was built" >&2; exit 1; }

# Every output is a statically linked ARM aarch64 ELF executable.
bad=0
for rel in "${built[@]}"; do
	desc=$(file -b "$out/$rel")
	for want in "ELF 64-bit LSB" "ARM aarch64" "statically linked"; do
		case "$desc" in *"$want"*) ;; *) echo "build-arm64: $rel: not \"$want\": $desc" >&2; bad=1 ;; esac
	done
	printf '%-40s %s\n' "$rel" "$desc"
done
[ "$bad" -eq 0 ] || exit 1
echo "build-arm64: ${#built[@]} executables in $out"
