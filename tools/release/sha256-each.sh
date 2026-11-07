#!/usr/bin/env bash
# Writes the .sha256 file of one release artifact: `<hash>  <name>`, the form `sha256sum -c` reads from the directory of the
# artifact. GoReleaser calls it from the stage it names "sign" (.goreleaser.yaml, signs), because that is the stage that makes
# one file per artifact. It signs nothing and holds no key.
#
#   tools/release/sha256-each.sh <artifact> <output>
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: sha256-each.sh <artifact> <output>" >&2; exit 2; }
artifact=$1
out=$2
[ -f "$artifact" ] || { echo "sha256-each: $artifact is not a file" >&2; exit 1; }
hash=$(sha256sum "$artifact" | cut -d' ' -f1)
[ "${#hash}" -eq 64 ] || { echo "sha256-each: no hash for $artifact" >&2; exit 1; }
printf '%s  %s\n' "$hash" "$(basename "$artifact")" >"$out"
