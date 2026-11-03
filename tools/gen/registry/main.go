// Command registry generates the enforcement tables of the three registries (docs/architecture/actors.yaml,
// kinds.yaml and keys.yaml) as a Go package and a Rust crate with the same API: the store's rules (actor x kind
// x verb), key's rules (actor x purpose x op), the call graph and the pinned uids.
//
// "Nothing that enforces least privilege is written by hand" (docs/decisions/0002-families-of-actors.md,
// "Registries generate the enforcement"). Run it from the repository root with `just registry-gen`.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	goOut   = "kits/go/registry/zz_registry.go"
	rustOut = "kits/rust/sluis-registry/src/generated.rs"
)

func run(root string) error {
	in, err := load(root)
	if err != nil {
		return err
	}
	m, err := build(in)
	if err != nil {
		return err
	}
	goSrc, err := emitGo(m)
	if err != nil {
		return err
	}
	rustSrc, err := emitRust(m)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		rel string
		src []byte
	}{{goOut, goSrc}, {rustOut, rustSrc}} {
		p := filepath.Join(root, f.rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.src, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	root := flag.String("root", ".", "the repository root")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "registry: no arguments, only -root")
		os.Exit(2)
	}
	if err := run(*root); err != nil {
		fmt.Fprintf(os.Stderr, "registry: %v\n", err)
		os.Exit(1)
	}
}
