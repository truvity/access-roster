// Command release generates .goreleaser.yaml from the tree.
//
//	go run ./tools/gen/release [-root .] [-out .goreleaser.yaml]
//
// Run it from the repository root with `just release-gen`; `go test ./tools/gen/release` fails while the committed file
// differs from what this makes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	out := flag.String("out", ".goreleaser.yaml", "the output file, below the root")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "release: there are no arguments")
		os.Exit(2)
	}
	execs, err := Discover(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*root, *out), []byte(Render(execs)), 0o644); err != nil { //nolint:gosec // a configuration file, read by everyone
		fmt.Fprintf(os.Stderr, "release: %v\n", err)
		os.Exit(1)
	}
}
