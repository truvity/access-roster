// Command units generates the systemd units of the boards from the registries: per actor and per driver a template
// unit, its user (sysusers.d) and its directories (tmpfiles.d), and the index the deploy reads. Run it from the
// repository root with `just units-gen`; `go test ./tools/gen/units` fails while the committed files differ.
//
//	go run ./tools/gen/units [-root .] [-out deploy/boards/units] [-boundary dev] [-uid-block 0]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	out := flag.String("out", "deploy/boards/units", "the output directory, below the root; it is emptied first")
	boundary := flag.String("boundary", "dev", "the boundary of the instances")
	block := flag.String("uid-block", "0", "the uid block of the boundary (REQ-ISO-072)")
	flag.Parse()
	n, err := strconv.ParseUint(*block, 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "units: -uid-block %q: %v\n", *block, err)
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "units: no arguments, only flags")
		os.Exit(2)
	}
	if err := run(*root, *out, Options{Boundary: *boundary, UIDBlock: uint32(n)}); err != nil {
		fmt.Fprintf(os.Stderr, "units: %v\n", err)
		os.Exit(1)
	}
}

func run(root, out string, o Options) error {
	files, err := Generate(o)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, out)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.Name), []byte(f.Body), 0o600); err != nil {
			return err
		}
	}
	return nil
}
