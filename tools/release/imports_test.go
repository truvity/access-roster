package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The job that publishes holds the write tokens and runs tools/release, so what tools/release compiles is the code that runs there
// (.github/workflows/release.yaml says so). It imports the standard library and one third-party module, yaml/v3, and nothing else
// but one package of this repository, tools/release/pkgs, which reads and checks packages and which a test of its own holds to
// the same two (pkgs/imports_test.go): nfpm, which builds them, is in tools/release/packages, a module of its own, and is linked
// by no program of this one. A new import has to be argued here, not slipped in.

// pkgsPath is the one exception, by its exact path.
const pkgsPath = "github.com/truvity/sluis/v2/tools/release/pkgs"

// foreignImports returns the imports of the non-test files of dir that are neither the standard library, yaml/v3 nor pkgsPath, and
// how many imports it saw.
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
			if p == "go.yaml.in/yaml/v3" || p == pkgsPath {
				continue
			}
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				bad = append(bad, filepath.Base(f)+" imports "+p)
			}
		}
	}
	return bad, seen
}

func TestToolsReleaseImportsTheStandardLibraryAndYAMLAlone(t *testing.T) {
	bad, seen := foreignImports(t, ".")
	for _, b := range bad {
		t.Errorf("%s: a third-party module in the job that holds the write tokens", b)
	}
	if seen < 20 {
		t.Fatalf("%d imports found: the scan looks empty", seen)
	}
	if _, err := os.Stat("../../go.mod"); err != nil {
		t.Fatal(err)
	}
}

// The exception is the one path and no other: nfpm, another package of this repository, and a package below pkgs are refused, and
// the path itself passes. Without this the test above would pass whatever the exception let in.
func TestTheImportExceptionIsTheOnePackageAndNoOther(t *testing.T) {
	dir := t.TempDir()
	src := "package main\nimport (\n\t_ \"" + pkgsPath + "\"\n\t_ \"go.yaml.in/yaml/v3\"\n\t_ \"os\"\n\t_ \"github.com/goreleaser/nfpm/v2\"\n\t_ \"github.com/truvity/sluis/v2/kits/go/registry\"\n\t_ \"" + pkgsPath + "/sub\"\n\t_ \"" + pkgsPath + "x\"\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	bad, seen := foreignImports(t, dir)
	if seen != 7 || len(bad) != 4 {
		t.Fatalf("saw %d imports and refused %v: want 7 and the four of nfpm, registry, pkgs/sub and pkgsx", seen, bad)
	}
}
