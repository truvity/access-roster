package port_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/truvity/access-roster/"

// The storage engines are reached through the ports. Business code (the hub,
// the server, the issuer, the rosters, the rails, the settings) names the
// interfaces of internal/port and never internal/kube, internal/valkey or the
// legacy adapter that wraps them: the day an adapter is replaced, nothing
// else changes. Only the adapters and the code that wires an adapter in may.
var forbidden = []string{
	module + "internal/kube",
	module + "internal/valkey",
	module + "internal/port/legacy",
}

// wiring may import them: the engines' own packages, the adapter, the one
// factory that chooses it, the apps that assemble a process from
// configuration, and the commands.
var wiring = []string{
	"internal/kube",
	"internal/valkey",
	"internal/port/legacy",
	"internal/store",
	"internal/app",
	"internal/issuerapp",
	"internal/rosterapp",
	"internal/githubroster/app",
	"internal/slackroster/app",
	"cmd",
}

func isWiring(dir string) bool {
	return slices.ContainsFunc(wiring, func(w string) bool { return dir == w || strings.HasPrefix(dir, w+"/") })
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

func TestBusinessPackagesDoNotImportTheStorageEngines(t *testing.T) {
	root := moduleRoot(t)
	scanned, checked := 0, 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".devbox", "dist", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		// Tests may build a fake engine; what ships may not depend on one.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		rel = filepath.ToSlash(rel)
		if isWiring(rel) {
			return nil
		}
		checked++
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			imported, _ := strconv.Unquote(spec.Path.Value)
			for _, bad := range forbidden {
				if imported == bad || strings.HasPrefix(imported, bad+"/") {
					t.Errorf("%s imports %s: business code names a port (internal/port), not an engine or the legacy adapter", filepath.ToSlash(path[len(root)+1:]), imported)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A guard that scanned nothing proves nothing.
	if scanned < 100 || checked < 50 {
		t.Fatalf("scanned %d files and checked %d: the walk found too little to be a guard", scanned, checked)
	}
}
