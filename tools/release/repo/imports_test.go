package repo

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This package imports the standard library and tools/release/pkgs, and nothing else: no nfpm, no yaml, no createrepo wrapper. The
// metadata is written in Go so that the code that would build a repository never needs the tools of a distribution, and the job that
// holds the write tokens does not link it at all (tools/release/imports_test.go refuses any import of this repository but pkgs).
const pkgsPath = "github.com/truvity/sluis/v2/tools/release/pkgs"

func foreignImports(t *testing.T, dir string) (bad []string, seen int) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files in %s: %v", dir, err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			seen++
			if p == pkgsPath {
				continue
			}
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				bad = append(bad, filepath.Base(f)+" imports "+p)
			}
		}
	}
	return bad, seen
}

func TestTheRepositoryCodeImportsTheStandardLibraryAndPkgsAlone(t *testing.T) {
	bad, seen := foreignImports(t, ".")
	for _, b := range bad {
		t.Errorf("%s: more than the standard library and tools/release/pkgs", b)
	}
	if seen < 20 {
		t.Fatalf("%d imports found: the scan looks empty", seen)
	}
	dir := t.TempDir()
	src := "package x\nimport (\n\t_ \"os\"\n\t_ \"" + pkgsPath + "\"\n\t_ \"go.yaml.in/yaml/v3\"\n\t_ \"github.com/goreleaser/nfpm/v2\"\n\t_ \"" + pkgsPath + "/sub\"\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if bad, _ := foreignImports(t, dir); len(bad) != 3 {
		t.Fatalf("refused %v: want yaml, nfpm and a package below pkgs", bad)
	}
}
