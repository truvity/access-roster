package pkgs

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// tools/release links this package into the job that publishes, which holds the write tokens (tools/release/imports_test.go). So
// it imports the standard library and yaml/v3 and nothing else: not nfpm, which builds the packages in tools/release/packages, and
// not any other package of this repository.
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
			if p == "go.yaml.in/yaml/v3" {
				continue
			}
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				bad = append(bad, filepath.Base(f)+" imports "+p)
			}
		}
	}
	return bad, seen
}

func TestThePackageCheckImportsTheStandardLibraryAndYAMLAlone(t *testing.T) {
	bad, seen := foreignImports(t, ".")
	for _, b := range bad {
		t.Errorf("%s: a third-party module, or a package of this repository, in the code the job that publishes links", b)
	}
	if seen < 20 {
		t.Fatalf("%d imports found: the scan looks empty", seen)
	}
	dir := t.TempDir()
	src := "package x\nimport (\n\t_ \"os\"\n\t_ \"go.yaml.in/yaml/v3\"\n\t_ \"github.com/goreleaser/nfpm/v2\"\n\t_ \"github.com/truvity/sluis/v2/kits/go/registry\"\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if bad, _ := foreignImports(t, dir); len(bad) != 2 {
		t.Fatalf("refused %v: want nfpm and registry", bad)
	}
}
