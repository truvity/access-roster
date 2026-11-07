#!/usr/bin/env bash
# The SPDX JSON SBOM of every image of a release, made by syft from the image in the registry, by digest. It reads
# release-images.txt (`<repository>:<tag>@sha256:<digest>`, one image a line) and writes `<name>.sbom.spdx.json` into the
# output directory, named after the image. SLUIS_SBOM_INSECURE=1 reads a registry over plain HTTP (the throwaway registry of
# `just release-rehearsal`); a release reads ghcr.io.
#
#   tools/release/sbom-images.sh <release-images.txt> <output directory>
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: sbom-images.sh <release-images.txt> <output directory>" >&2; exit 2; }
list=$1
out=$2
[ -s "$list" ] || { echo "sbom-images: $list is missing or empty" >&2; exit 1; }
mkdir -p "$out"
if [ "${SLUIS_SBOM_INSECURE:-}" = 1 ]; then
    export SYFT_REGISTRY_INSECURE_USE_HTTP=true
fi
n=0
while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    case "$ref" in *@sha256:*) ;; *) echo "sbom-images: $ref has no digest" >&2; exit 1 ;; esac
    # repository:tag@digest: the name is the last path element of the repository (host:port has a colon of its own).
    path=${ref%@*}
    path=${path%:*}
    name=${path##*/}
    syft scan "registry:${path}@${ref#*@}" --source-name "$name" --quiet --output "spdx-json=$out/$name.sbom.spdx.json"
    [ -s "$out/$name.sbom.spdx.json" ] || { echo "sbom-images: syft wrote nothing for $ref" >&2; exit 1; }
    n=$((n + 1))
done <"$list"
[ "$n" -gt 0 ] || { echo "sbom-images: no image in $list" >&2; exit 1; }
echo "sbom-images: $n documents in $out"
