#!/usr/bin/env bash
# The packages of the previous release, for the upgrade and the downgrade of the install tier.
#
#   deploy/verify/previous.sh [<version> [<out-dir>]]     default: the previous release (versions.sh), dist/previous
#
# No release has published packages yet, so there is nothing to fetch. This takes what the previous release did publish, its
# archives, from its GitHub release (anonymously; the sums of the release are the check of every file), and builds packages from them
# with the packaging of THIS tree, the same tool that builds the release under test. The executables are the previous release's, byte
# for byte; the units, users, directories and maintainer scripts are this tree's. So the upgrade tests what an upgrade of the
# executables does under this packaging, and not a change between two packagings, which no release has made yet. From the first
# release with packages on, fetch its packages instead (docs/distribution/packages.md, "The install tier").
# The URL is https only (TLS 1.2 or later), and the SHA256SUMS of the release is held to the hash committed in previous.sums, which is
# bumped when a release becomes the previous one. Leaves <out-dir>/release (the archives, SHA256SUMS and metadata.json) and <out-dir>/packages.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
version=${1:-$("$root/deploy/verify/versions.sh" previous)}
out=${2:-$root/dist/previous}
repo=${SLUIS_REPOSITORY:-truvity/sluis}
base="https://github.com/$repo/releases/download/v$version"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "previous: '$version' is not a release version" >&2; exit 2; }

rm -rf "${out:?}"
mkdir -p "$out/release" "$out/packages"
fetch() { curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --retry 4 --retry-all-errors --retry-delay 3 --output "$2" "$1"; }
fetch "$base/SHA256SUMS" "$out/release/SHA256SUMS.published"
# The sums themselves are pinned in the repository (previous.sums): the hash of each archive is only as good as the file that lists it.
pin=$(awk -v v="$version" '$1 == v { print $2 }' "$root/deploy/verify/previous.sums")
[ -n "$pin" ] || { echo "previous: deploy/verify/previous.sums has no line for $version: add the SHA-256 of its published SHA256SUMS (the command is in that file)" >&2; exit 1; }
got=$(sha256sum "$out/release/SHA256SUMS.published" | awk '{ print $1 }')
[ "$got" = "$pin" ] || { echo "previous: the published SHA256SUMS of $version is $got, previous.sums pins $pin" >&2; exit 1; }

# The archives the plan needs: the package of every image built from an archive, and the command-line tool.
mapfile -t names < <({ sed -n 's/^    package: \(sluis-[a-z0-9-]*\)$/\1/p' "$root/deploy/release/images.yaml"; echo sluis; } | LC_ALL=C sort -u)
[ "${#names[@]}" -ge 20 ] || { echo "previous: the list of images gave only ${#names[@]} archives" >&2; exit 1; }
for n in "${names[@]}"; do
    for arch in amd64 arm64; do
        f="${n}_${version}_linux_${arch}.tar.gz"
        fetch "$base/$f" "$out/release/$f"
        want=$(awk -v f="$f" '$2 == f { print $1 }' "$out/release/SHA256SUMS.published")
        [ -n "$want" ] || { echo "previous: the sums of $version do not list $f" >&2; exit 1; }
        got=$(sha256sum "$out/release/$f" | awk '{ print $1 }')
        [ "$got" = "$want" ] || { echo "previous: $f is $got, the sums of $version say $want" >&2; exit 1; }
    done
done
printf '{"version":"%s"}\n' "$version" >"$out/release/metadata.json"
echo "previous: ${#names[@]} archives of $version, each held to the published sums"

go -C "$root/tools/release/packages" run . build -dist "$out/release" -out "$out/packages" -images "$root/deploy/release/images.yaml" -actors "$root/docs/architecture/actors.yaml" -units "$root/deploy/boards/units"
(cd "$root" && go run ./tools/release check-packages -dist "$out/release" -packages "$out/packages" -images deploy/release/images.yaml)
