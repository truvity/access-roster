package evidence

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The package that reads the evidence of a run is linked, later, by the job that publishes a release and holds the write tokens
// (tools/release/imports_test.go names what that job may import), so its code imports the standard library and nothing else. The
// test above it uses a JSON Schema module; only the tests do.
func TestTheEvidenceCodeImportsTheStandardLibraryAlone(t *testing.T) {
	files, _ := filepath.Glob("*.go")
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
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if seen < 10 {
		t.Fatalf("%d imports seen: the scan looks empty", seen)
	}
}
