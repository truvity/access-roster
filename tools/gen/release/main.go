// Command release generates .goreleaser.yaml and the Dockerfile of each image from the tree.
//
//	go run ./tools/gen/release [-root .]
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
	for _, f := range Generate(execs) {
		p := filepath.Join(*root, f.Name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "release: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(p, []byte(f.Body), f.Mode); err != nil {
			fmt.Fprintf(os.Stderr, "release: %v\n", err)
			os.Exit(1)
		}
	}
}
