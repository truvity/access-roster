// Command release holds the checks of the release train that are programs and not shell.
//
//	go run ./tools/release check-dist     [-config .goreleaser.yaml] [-dist dist/release]
//	go run ./tools/release release-images [-config .goreleaser.yaml] [-dist dist/release] [-out dist/release/release-images.txt]
//	go run ./tools/release check-images   -registry http://127.0.0.1:5000 [-prefix sluis] [-config ...] [-dist ...]
//
// check-dist reads what a GoReleaser run left in the dist directory and fails on anything the configuration promised and the
// run did not make (docs/distribution/packages.md). release-images writes the list of the images of the release with their
// digests. check-images is the release test of the images against the registry the run pushed to. `just release-rehearsal`
// runs all three.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfg := fs.String("config", ".goreleaser.yaml", "the GoReleaser configuration the run used")
	dist := fs.String("dist", "dist/release", "the dist directory of the run")
	switch os.Args[1] {
	case "check-dist":
		_ = fs.Parse(os.Args[2:])
		finish("check-dist: every archive, checksum and executable is as the configuration says", CheckDist(*cfg, *dist))
	case "release-images":
		out := fs.String("out", "dist/release/release-images.txt", "where release-images.txt goes")
		_ = fs.Parse(os.Args[2:])
		lines, _, err := ReleaseImages(*cfg, *dist)
		if err != nil {
			finish("", []string{err.Error()})
		}
		if err := os.WriteFile(*out, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil { //nolint:gosec // a release file, read by everyone
			finish("", []string{err.Error()})
		}
		fmt.Printf("release: release-images: %d images in %s\n", len(lines), *out)
	case "check-images":
		base := fs.String("registry", "", "the base URL of the throwaway registry the run pushed to, for example http://127.0.0.1:5000")
		prefix := fs.String("prefix", "sluis", "the repository prefix of the images in that registry")
		_ = fs.Parse(os.Args[2:])
		if *base == "" {
			usage()
		}
		finish("check-images: every image is the release's: version tag alone, both platforms, the executable of its archive", CheckImages(*cfg, *dist, *base, *prefix))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: release check-dist | release-images | check-images -registry URL  [-config .goreleaser.yaml] [-dist dist/release]")
	os.Exit(2)
}

func finish(ok string, problems []string) {
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "release: "+p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "release: %d problems\n", len(problems))
		os.Exit(1)
	}
	if ok != "" {
		fmt.Println("release: " + ok)
	}
}
