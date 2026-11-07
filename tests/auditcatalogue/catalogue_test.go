// Package auditcatalogue holds the sweeps that keep three lists of audit actions in step: the actions the actors emit
// (found in their source, not from a list), the action table that the emitters and the generated schemas come from
// (docs/architecture/audit-actions.yaml), and the AuditCatalogue of the local installation, whose names the writer
// accepts. An action that an actor can emit and the table or the catalogue lacks is a fact that is lost: the emitter
// refuses it, or the writer quarantines it. It failed on real boards for key.pin.release. The other way round, a row
// that no actor emits is a promise nobody keeps.
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

	"github.com/truvity/sluis/v2/kits/go/audit"
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

// goActors are the Go actors that audit, by directory; each must have actions, so an actor that moves or whose constants
// are renamed fails the sweep instead of leaving it empty.
var goActors = map[string]string{"key": "key", "session": "session", "exchange": "exchange", "adapter-upstream-oidc": "adapter-upstream-oidc"}

// rustActors are the Rust actors that audit, with the prefix of their actions. entry is swept by its routes.
var rustActors = map[string]string{"store": "store", "policy": "policy", "signer": "signer", "reader": "reader"}

// goActions finds the actions of the Go actors: their Action* constants, with the file.
func goActions(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for dir, actor := range goActors {
		acts := actionsOf(t, filepath.Join(root, "actors", dir, "internal"))
		if len(acts) == 0 {
			t.Errorf("%s: no Action constant found under actors/%s/internal: the sweep is empty", actor, dir)
		}
		for a, f := range acts {
			out[a] = f
		}
	}
	return out
}

var (
	rustLiteral = regexp.MustCompile(`"([a-z]+(?:\.[a-z_]+)+)"`)
	entryRoute  = regexp.MustCompile(`(?:route\s*=\s*|route:\s*|ROUTE:\s*&str\s*=\s*)"([a-z]+)"`)
)

// nonTest is the source of a Rust file before its test module: audit actions in a test are fixtures.
func nonTest(b []byte) string {
	s := string(b)
	if i := strings.Index(s, "#[cfg(test)]"); i >= 0 {
		s = s[:i]
	}
	return s
}

// rustActions finds the actions of the Rust actors: the string literals of their source that have the shape and the
// prefix of an action. The routes of entry are found apart, because entry names an action entry.<route>.
func rustActions(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for dir, prefix := range rustActors {
		n := 0
		err := filepath.WalkDir(filepath.Join(root, "actors", dir, "src"), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".rs") {
				return err
			}
			b, err := os.ReadFile(p) //nolint:gosec // a source file of the repository
			if err != nil {
				return err
			}
			for _, m := range rustLiteral.FindAllStringSubmatch(nonTest(b), -1) {
				if strings.HasPrefix(m[1], prefix+".") && actionName.MatchString(m[1]) {
					out[m[1]] = p
					n++
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("%s: no action found under actors/%s/src: the sweep is empty", dir, dir)
		}
	}
	routes := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "actors", "entry", "src"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".rs") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // a source file of the repository
		if err != nil {
			return err
		}
		if strings.Contains(nonTest(b), `"unrouted"`) {
			out["entry.unrouted"] = p
		}
		for _, m := range entryRoute.FindAllStringSubmatch(nonTest(b), -1) {
			if m[1] != "" {
				out["entry."+m[1]] = p
				routes[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) < 5 {
		t.Errorf("entry: %d routes found: the sweep is nearly empty", len(routes))
	}
	return out
}

func sorted(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every action that an actor can emit is a row of the action table: the emitter refuses any other (REQ-AUDIT-022).
//
// verifies: REQ-AUDIT-022
func TestEveryActionOfAnActorIsARowOfTheTable(t *testing.T) {
	tb := audit.Sluis()
	for _, src := range []map[string]string{goActions(t), rustActions(t)} {
		for _, a := range sorted(src) {
			if _, ok := tb.Row(a); !ok {
				t.Errorf("action %q (%s) is not a row of docs/architecture/audit-actions.yaml: the emitter would refuse it", a, src[a])
			}
		}
	}
}

// Every row of the table is emitted by some actor, and by the actor the row names.
func TestEveryRowOfTheTableIsEmittedByItsActor(t *testing.T) {
	tb := audit.Sluis()
	found := goActions(t)
	for a, f := range rustActions(t) {
		found[a] = f
	}
	for _, name := range tb.Names() {
		row, _ := tb.Row(name)
		f, ok := found[name]
		if !ok {
			t.Errorf("the row %q is emitted by no actor: remove it from docs/architecture/audit-actions.yaml, or emit it", name)
			continue
		}
		if !strings.Contains(filepath.ToSlash(f), "actors/"+row.Actor+"/") {
			t.Errorf("the row %q names the actor %q, and it is emitted in %s", name, row.Actor, f)
		}
	}
}

// The AuditCatalogue of the local installation lists exactly the actions of the table: the writer quarantines a
// record whose metadata.event_code it lacks, and a name that no row has is a name no emitter can send.
func TestTheCatalogueOfTheLocalInstallationIsTheTable(t *testing.T) {
	cat := catalogue(t)
	tb := audit.Sluis()
	for _, name := range tb.Names() {
		if !cat[name] {
			t.Errorf("the row %q is not in tests/installations/local/config/audit-catalogue.yaml: the writer would quarantine it", name)
		}
	}
	for name := range cat {
		if _, ok := tb.Row(name); !ok {
			t.Errorf("the catalogue lists %q, which is no row of the table", name)
		}
	}
}
