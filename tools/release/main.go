// Command release holds the checks of the release train that are programs and not shell.
//
//	go run ./tools/release check-dist [-config .goreleaser.yaml] [-dist dist/release]
//
// check-dist reads what a GoReleaser run left in the dist directory and fails on anything the configuration promised and the
// run did not make (docs/distribution/packages.md). `just release-snapshot` runs it after the dry run.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "check-dist" {
		fmt.Fprintln(os.Stderr, "usage: release check-dist [-config .goreleaser.yaml] [-dist dist/release]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("check-dist", flag.ExitOnError)
	cfg := fs.String("config", ".goreleaser.yaml", "the GoReleaser configuration the run used")
	dist := fs.String("dist", "dist/release", "the dist directory of the run")
	_ = fs.Parse(os.Args[2:])
	problems := CheckDist(*cfg, *dist)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "release: "+p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "release: check-dist found %d problems\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("release: check-dist: every archive, checksum and executable is as the configuration says")
}
