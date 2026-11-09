// Command packages builds the .deb and .rpm packages of a release from the archives GoReleaser left in dist, with the nfpm
// library (ADR 0013, "Packaging per runtime"; docs/distribution/packages.md). The plan of the packages, the reading of a built
// package and its check are the library tools/release/pkgs, which has no dependency but the standard library and yaml:
// `tools/release check-packages` runs the check in the job that holds the write tokens, which therefore never links nfpm.
//
// It is a command of its own, in a module of its own, on purpose: nfpm and its dependencies belong in the job that builds, which
// holds no token, and in no other build.
//
// GoReleaser's own nfpms step is not used. It writes `dependencies` verbatim ({{ .Version }} is not expanded) and both formats
// then ship a dependency that can never be met (MEASURED 2026-11-07 with GoReleaser 2.20.0); here the version of every package is
// computed once, in one function, and every dependency on a package of the release is written from it, in the syntax of the
// format.
//
//	packages build [-images F] [-actors F] [-dist D] [-out D]
//	packages repo  [-packages D] [-out D] [-date T]
//	packages serve [-dir D] [-addr 127.0.0.1:PORT]
//
// `repo` and `serve` make and serve a THROWAWAY apt and dnf repository of the packages, UNSIGNED, so that a test installs the
// release from a repository with apt and dnf (tools/release/repo; `just release-repo-smoke`). They are not the publication site, and
// they live here, out of tools/release, so that the job that holds the write tokens never links them.
package main

import (
	"flag"
	"fmt"
	"os"

	. "github.com/truvity/sluis/v2/tools/release/pkgs" //nolint:revive,staticcheck // see build.go
)

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "repo":
			runRepo(os.Args[2:])
			return
		case "serve":
			runServe(os.Args[2:])
			return
		}
	}
	if len(os.Args) < 2 || os.Args[1] != "build" {
		fmt.Fprintln(os.Stderr, "usage: packages build [-images deploy/release/images.yaml] [-actors docs/architecture/actors.yaml] [-dist dist/release] [-out dist/packages]")
		fmt.Fprintln(os.Stderr, "       packages repo [-packages dist/packages] [-out dist/repo] [-date RFC3339]   (UNSIGNED throwaway apt and dnf trees, for tests)")
		fmt.Fprintln(os.Stderr, "       packages serve [-dir dist/repo] [-addr 127.0.0.1:0]                       (loopback only)")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	acts := fs.String("actors", "docs/architecture/actors.yaml", "the actor registry")
	imgs := fs.String("images", "deploy/release/images.yaml", "the list of the images of the release, which lists every executable built with GoReleaser")
	dist := fs.String("dist", "dist/release", "the dist directory of the GoReleaser run: the archives and metadata.json")
	out := fs.String("out", "dist/packages", "where the packages go: empty or absent")
	_ = fs.Parse(os.Args[2:])
	version, err := DistVersion(*dist)
	if err != nil {
		fail(err)
	}
	specs, _, err := PlanFiles(*imgs, *acts)
	if err != nil {
		fail(err)
	}
	b := Builder{Dist: *dist, Out: *out, Version: version, Specs: specs}
	if err := b.Build(); err != nil {
		fail(err)
	}
	fmt.Printf("packages: build: %d packages of %s in %s\n", len(specs)*len(ArchList())*len(Formats), version, *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "packages: "+err.Error())
	os.Exit(1)
}
