// Package auditcatalogue holds the sweep of the audit actions of the Go actors against the AuditCatalogue of the local
// installation. The writer quarantines a record whose metadata.event_code is not in the catalogue, so an action that an
// actor can emit and the catalogue lacks is a fact that is lost. Actions are found in the source, not from a list.
package auditcatalogue

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const root = "../.."

var actionName = regexp.MustCompile(`^[a-z]+(\.[a-z_]+)+$`)

// catalogue is the action names of the catalogue of the local installation.
func catalogue(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "tests/installations/local/config/audit-catalogue.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Default struct {
			Actions []string `yaml:"actions"`
		} `yaml:"default"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Default.Actions) == 0 {
		t.Fatal("the catalogue lists no action: the sweep would pass on nothing")
	}
	out := map[string]bool{}
	for _, a := range doc.Default.Actions {
		out[a] = true
	}
	return out
}

// actionsOf returns the string constants named Action* of the non-test Go files under dir, with their file.
func actionsOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, id := range vs.Names {
				if !strings.HasPrefix(id.Name, "Action") || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, _ := strconv.Unquote(lit.Value)
					if actionName.MatchString(v) {
						out[v] = path
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The Go actors that audit. Each must have actions: an actor that moves, or whose constants are renamed, fails the
// sweep instead of leaving it empty.
func TestEveryAuditActionOfAGoActorIsInTheCatalogue(t *testing.T) {
	cat := catalogue(t)
	dirs, err := filepath.Glob(filepath.Join(root, "actors/*/internal"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"key": false, "session": false, "exchange": false, "adapter-upstream-oidc": false}
	for _, d := range dirs {
		actor := filepath.Base(filepath.Dir(d))
		acts := actionsOf(t, d)
		if _, listed := want[actor]; listed {
			want[actor] = true
			if len(acts) == 0 {
				t.Errorf("%s: no Action constant found: the sweep is empty", actor)
			}
		}
		names := make([]string, 0, len(acts))
		for a := range acts {
			names = append(names, a)
		}
		sort.Strings(names)
		for _, a := range names {
			if !cat[a] {
				t.Errorf("%s: action %q (%s) is not in the audit catalogue: the writer would quarantine it", actor, a, acts[a])
			}
		}
	}
	for actor, seen := range want {
		if !seen {
			t.Errorf("%s: actors/%s/internal not found", actor, actor)
		}
	}
}
