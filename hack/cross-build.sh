#!/usr/bin/env bash
# Build every (command, GOOS, GOARCH) that .goreleaser.yaml ships.
#
# `go build ./...` builds for the HOST only, so a platform-specific call
# compiles here and fails in the release. That is not hypothetical: the
# v1.25.1 tag was cut, the release failed on `undefined: syscall.Flock`
# for windows_arm64, and the tag was left with no release and no assets
# while CI had been green throughout.
#
# The matrix is READ FROM .goreleaser.yaml rather than repeated here, so
# adding a platform there cannot leave this check behind.
set -euo pipefail

cd "$(dirname "$0")/.."

[[ -f .goreleaser.yaml ]] || { echo "cross-build: no .goreleaser.yaml"; exit 1; }

matrix=$(yq -o=json '[.builds[] | {"main": .main, "goos": .goos, "goarch": .goarch}]' .goreleaser.yaml)

total=0
failed=0
while IFS=$'\t' read -r main goos goarch; do
  [[ -n "$main" ]] || continue
  total=$((total + 1))
  if ! out=$(CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -o /dev/null "$main" 2>&1); then
    failed=$((failed + 1))
    printf 'CROSS  %s  %s/%s\n' "$main" "$goos" "$goarch"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
done < <(printf '%s' "$matrix" | jq -r '.[] | . as $b | $b.goos[] as $os | $b.goarch[] as $arch | [$b.main, $os, $arch] | @tsv')

# A guard that checked nothing must not report success.
if (( total == 0 )); then
  echo "cross-build: no targets found in .goreleaser.yaml -- refusing to pass on nothing"
  exit 1
fi

if (( failed > 0 )); then
  echo "cross-build: $failed of $total targets failed"
  exit 1
fi

echo "cross-build: $total targets built, all platforms clean"
