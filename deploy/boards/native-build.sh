#!/usr/bin/env bash
# Build the executables of deploy/boards/native.list natively, with cgo, and test them, inside an Ubuntu 22.04 userland.
#
# It runs as root in an `ubuntu:22.04` of the architecture it builds for:
#   - in CI, as the steps of the job `native-arm64`, whose container is ubuntu:22.04 on a hosted arm64 runner;
#   - locally, from `deploy/boards/Dockerfile.native` through `just build-arm64-native` (docker buildx, QEMU).
# The output is dist/native/<arch>/<package>. A package with no executable, or one that is not an ELF of this
# architecture that needs the libraries it should need, fails the build.
#
# The driver of a board's card talks to pcscd through libpcsclite (ADR 0006, 0013), so the oldest supported userland
# decides which glibc and which pcsc-lite it runs on. The Go toolchain is the release of go.mod's `toolchain` line,
# taken from go.dev and checked against the SHA-256 that Google publishes for it.
set -euo pipefail

cd "$(dirname "$0")/../.."

[ "$(id -u)" = 0 ] || { echo "native-build: run it as root inside ubuntu:22.04 (see the header)" >&2; exit 1; }
# shellcheck source=/dev/null
. /etc/os-release
[ "${VERSION_ID:-}" = "22.04" ] || { echo "native-build: the build is made in Ubuntu 22.04, not ${PRETTY_NAME:-this system}" >&2; exit 1; }

case "$(uname -m)" in
x86_64) goarch=amd64 ;;
aarch64) goarch=arm64 ;;
*) echo "native-build: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

# The Go release is the one of go.mod's `toolchain` line, so that a bump of the toolchain needs no change here. The tarball
# comes from go.dev and is checked against the SHA-256 that Google publishes for it at dl.google.com, a host other than
# the one that serves the tarball.
go_version=$(sed -n 's/^toolchain go//p' go.mod)
[[ "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "native-build: go.mod has no toolchain line of the form go1.2.3" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gcc libc6-dev pkg-config libpcsclite-dev binutils >/dev/null

if ! command -v go >/dev/null || [ "$(go env GOVERSION 2>/dev/null)" != "go$go_version" ]; then
	tgz=$(mktemp)
	curl -fsSL --retry 5 --retry-all-errors "https://go.dev/dl/go${go_version}.linux-${goarch}.tar.gz" -o "$tgz"
	want_sha=$(curl -fsSL --retry 5 --retry-all-errors "https://dl.google.com/go/go${go_version}.linux-${goarch}.tar.gz.sha256")
	[[ "$want_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "native-build: no SHA-256 published for Go ${go_version}" >&2; exit 1; }
	echo "${want_sha}  $tgz" | sha256sum -c - >/dev/null
	rm -rf /usr/local/go
	tar -C /usr/local -xzf "$tgz"
	rm -f "$tgz"
fi
export PATH=/usr/local/go/bin:$PATH
export GOFLAGS=-buildvcs=false GOTOOLCHAIN=local CGO_ENABLED=1
go version

out=dist/native/$goarch
rm -rf "$out"
mkdir -p "$out"
built=0
while IFS=$'\t' read -r pkg tags; do
	[ -n "$pkg" ] || continue
	[[ "$pkg" != '#'* ]] || continue
	echo "== $pkg (tags: $tags, $goarch)"
	go vet -tags "$tags" "./$pkg/..."
	# The tests of the package run with cgo and the card build both in, and with the race detector unless
	# SLUIS_NATIVE_RACE=0 (ThreadSanitizer does not run under QEMU, which Dockerfile.native sets). They use a fake card;
	# the hardware is exercised on a board (docs/contributing/tools.md, "Hardware tokens").
	race=-race
	[ "${SLUIS_NATIVE_RACE:-1}" = 1 ] || race=
	# shellcheck disable=SC2086 # race is one flag or nothing
	go test $race -count=1 -tags "$tags,sluis_test" "./$pkg/..."
	mkdir -p "$out/$(dirname "$pkg")"
	go build -trimpath -tags "$tags" -ldflags "-s -w -X github.com/truvity/sluis/v2/kits/go/version.Version=${SLUIS_VERSION:-0.0.0-dev}" -o "$out/$pkg" "./$pkg"
	bin=$out/$pkg
	machine=$(readelf -h "$bin" | sed -n 's/^ *Machine: *//p')
	case "$goarch:$machine" in
	arm64:AArch64 | amd64:*X86-64*) ;;
	*) echo "native-build: $pkg: machine is '$machine', not $goarch" >&2; exit 1 ;;
	esac
	needed=$(readelf -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort | tr '\n' ' ')
	echo "needs: $needed"
	case " $needed" in *" libpcsclite.so.1 "*) ;; *) echo "native-build: $pkg does not link libpcsclite" >&2; exit 1 ;; esac
	# The newest glibc symbol it asks for: the floor of every system it runs on.
	glibc=$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
	echo "glibc: ${glibc:-none}"
	built=$((built + 1))
done <deploy/boards/native.list
[ "$built" -gt 0 ] || { echo "native-build: native.list names nothing: nothing was built" >&2; exit 1; }
echo "native-build: $built executables in $out"
