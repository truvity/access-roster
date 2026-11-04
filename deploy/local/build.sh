#!/usr/bin/env bash
# Build every executable of sluis for this machine's architecture into dist/local/bin/, static, the images' content.
#
#   Go    actors/<a>, drivers/<owner>/<d>, cli/<c>   CGO_ENABLED=0 GOOS=linux go build -trimpath
#   Rust  the same directories                        cargo zigbuild --release --target <arch>-unknown-linux-musl
#
# The output keeps the directory: dist/local/bin/actors/<a>, dist/local/bin/drivers/<owner>/<d>, dist/local/bin/cli/<c>.
# Run it from the repository root, inside devbox: `devbox run -- just local-build`. The Dockerfile copies one of them
# into a distroless static image (decision D-9 of the first working version). Cargo and Go cache, so a second run
# builds only what changed.
set -euo pipefail

for tool in go cargo jq file; do
	command -v "$tool" >/dev/null || { echo "local-build: $tool is not on PATH (run it as: devbox run -- just local-build)" >&2; exit 1; }
done

case "$(uname -m)" in
x86_64 | amd64) goarch=amd64 target=x86_64-unknown-linux-musl want="x86-64" ;;
aarch64 | arm64) goarch=arm64 target=aarch64-unknown-linux-musl want="ARM aarch64" ;;
*) echo "local-build: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

out=dist/local/bin
version_pkg=github.com/truvity/sluis/v2/kits/go/version
version=${SLUIS_VERSION:-0.0.0-dev}

rm -rf "$out"
mkdir -p "$out"
built=()

# Go: every package main below actors/, drivers/ and cli/.
errs=$(mktemp)
if ! gopkgs=$(go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./actors/... ./drivers/... ./cli/... 2>"$errs"); then
	cat "$errs" >&2
	rm -f "$errs"
	echo "local-build: go list failed" >&2
	exit 1
fi
rm -f "$errs"
gopkgs=${gopkgs//github.com\/truvity\/sluis\/v2\//}
while IFS= read -r rel; do
	[ -n "$rel" ] || continue
	echo "go    $rel"
	mkdir -p "$out/$(dirname "$rel")"
	CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -ldflags "-s -w -X ${version_pkg}.Version=${version}" -o "$out/$rel" "./$rel"
	built+=("$rel")
done <<<"$gopkgs"

# Rust: every package of the workspace below actors/ and drivers/ that has a binary, in one cargo run.
root=$(pwd)
meta=$(cargo metadata --format-version 1 --no-deps)
tdir=$(jq -r .target_directory <<<"$meta")
pkgargs=()
declare -A bins=()
while IFS=$'\t' read -r pkg dir bin; do
	[ -n "$pkg" ] || continue
	rel=${dir#"$root"/}
	case "$rel" in actors/* | drivers/*/* | cli/*) ;; *) continue ;; esac
	echo "rust  $rel ($pkg)"
	pkgargs+=(-p "$pkg")
	bins[$rel]=$bin
done < <(jq -r '.packages[] | . as $p | $p.targets[] | select(.kind | index("bin")) | [$p.name, ($p.manifest_path | rtrimstr("/Cargo.toml")), .name] | @tsv' <<<"$meta")
if [ "${#pkgargs[@]}" -gt 0 ]; then
	SLUIS_VERSION=$version cargo zigbuild --release --target "$target" "${pkgargs[@]}"
	for rel in "${!bins[@]}"; do
		mkdir -p "$out/$(dirname "$rel")"
		install -m 0755 "$tdir/$target/release/${bins[$rel]}" "$out/$rel"
		built+=("$rel")
	done
fi

[ "${#built[@]}" -gt 0 ] || { echo "local-build: no executable found below actors/, drivers/ or cli/: nothing was built" >&2; exit 1; }

# Every output is a statically linked ELF executable of this machine's architecture.
bad=0
for rel in "${built[@]}"; do
	desc=$(file -b "$out/$rel")
	for need in "ELF 64-bit LSB" "$want" "statically linked"; do
		case "$desc" in *"$need"*) ;; *) echo "local-build: $rel: not \"$need\": $desc" >&2; bad=1 ;; esac
	done
done
[ "$bad" -eq 0 ] || exit 1
echo "local-build: ${#built[@]} executables in $out"
