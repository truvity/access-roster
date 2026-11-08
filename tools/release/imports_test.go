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
// (.github/workflows/release.yaml says so). It imports the standard library and one third-party module, yaml/v3, and nothing else:
// a new import has to be argued here, not slipped in.
func TestToolsReleaseImportsTheStandardLibraryAndYAMLAlone(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	seen := 0
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
				t.Errorf("%s imports %s: a third-party module in the job that holds the write tokens", f, p)
			}
		}
	}
	if seen < 20 {
		t.Fatalf("%d imports found: the scan looks empty", seen)
	}
	if _, err := os.Stat("../../go.mod"); err != nil {
		t.Fatal(err)
	}
}
