// Command compose generates the Compose project of the local installation from the registries: one container per actor
// and per driver, each as its pinned uid and with only the socket directories it may reach, and the init script that
// makes those directories (docs/runtimes/local.md, "Topology"; decision 0011, "Consequences"). The harness services, the
// forwarder and the engine are written here too, from the same tables.
//
//	go run ./tools/gen/compose [-root .] [-out deploy/local] [-boundary dev] [-uid-block 0]
//
// Run it from the repository root with `just compose-gen`; `go test ./tools/gen/compose` fails while the committed files
// differ from what this makes.
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
	out := flag.String("out", "deploy/local", "the output directory, below the root")
	boundary := flag.String("boundary", "dev", "the boundary of the instances")
	block := flag.String("uid-block", "0", "the uid block of the boundary (REQ-ISO-072)")
	flag.Parse()
	n, err := strconv.ParseUint(*block, 10, 32)
	if err != nil || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "compose: -uid-block must be a number, and there are no arguments")
		os.Exit(2)
	}
	files, err := Generate(Options{Boundary: *boundary, UIDBlock: uint32(n)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compose: %v\n", err)
		os.Exit(1)
	}
	for _, f := range files {
		p := filepath.Join(*root, *out, f.Name)
		if err := os.WriteFile(p, []byte(f.Body), f.Mode); err != nil {
			fmt.Fprintf(os.Stderr, "compose: %v\n", err)
			os.Exit(1)
		}
		if err := os.Chmod(p, f.Mode); err != nil {
			fmt.Fprintf(os.Stderr, "compose: %v\n", err)
			os.Exit(1)
		}
	}
}
