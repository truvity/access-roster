package deps

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// refusedImports are the Go modules that sluis code does not import, by the list `refused` of
// docs/reference/approved-libraries.yaml. golang-jwt/jwt/v5 is in the build only because go-webauthn needs it for code
// that sluis never calls (the exception of 2026-11-07, REQ-SEC-008): it is not a second JOSE library to choose. The only
// JOSE library is go-jose.
var refusedImports = []string{
	"github.com/golang-jwt/jwt",
	"github.com/lestrrat-go/jwx",
}

// importsOf returns the import paths of a Go source file, read without type checking.
func importsOf(t *testing.T, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var out []string
	for _, im := range f.Imports {
		out = append(out, strings.Trim(im.Path.Value, "\"`"))
	}
	return out
}

func refused(path string) bool {
	for _, r := range refusedImports {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

// The detector finds the import in each way it can be written, so that the sweep below cannot pass on a detector that
// sees nothing.
func TestTheRefusedImportDetectorSeesEveryForm(t *testing.T) {
	for _, src := range []string{
		"package p\nimport \"github.com/golang-jwt/jwt/v5\"\n",
		"package p\nimport jwt \"github.com/golang-jwt/jwt/v5\"\n",
		"package p\nimport _ \"github.com/golang-jwt/jwt/v5\"\n",
		"package p\nimport . \"github.com/golang-jwt/jwt/v5/request\"\n",
		"package p\nimport (\n\t\"fmt\"\n\t\"github.com/lestrrat-go/jwx/v3/jwt\"\n)\n",
		"package p\nimport `github.com/golang-jwt/jwt/v4`\n",
	} {
		var found bool
		for _, p := range importsOf(t, "x.go", src) {
			found = found || refused(p)
		}
		if !found {
			t.Errorf("not seen: %q", src)
		}
	}
	for _, ok := range []string{"github.com/go-jose/go-jose/v4", "github.com/golang-jwt-not/jwt", "github.com/golang-jwt"} {
		if refused(ok) {
			t.Errorf("%s is refused", ok)
		}
	}
}

// No Go file of the repository imports a refused module (REQ-SEC-008, REQ-SEC-018): the one JWT path of sluis is go-jose, and
// golang-jwt/jwt reaches the build through go-webauthn alone. The files are those git tracks.
func TestNoGoFileImportsARefusedModule(t *testing.T) {
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--", "*.go").Output() // #nosec G204 -- a fixed command
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	if len(files) < 100 {
		t.Fatalf("%d Go files: a sweep over nothing proves nothing", len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(root, f)) // #nosec G304 -- a file git tracks in this repository
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range importsOf(t, f, src) {
			if refused(p) {
				t.Errorf("%s imports %s, which sluis does not import (docs/reference/approved-libraries.md)", f, p)
			}
		}
	}
}

// go.mod marks golang-jwt/jwt as an indirect requirement: a direct one means some file of the module imports it.
func TestTheRefusedModulesAreIndirectInGoMod(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- the module file of this repository
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(mod), "\n") {
		for _, r := range refusedImports {
			if strings.Contains(line, r) && strings.HasPrefix(strings.TrimSpace(line), r) && !strings.Contains(line, "// indirect") {
				t.Errorf("go.mod requires %s directly: %q", r, line)
			}
		}
	}
}

// The exception is written down where the list is: the refused entry and the exception name the module and the module that
// brings it.
func TestTheExceptionIsInTheApprovedLibrariesList(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root, "docs/reference/approved-libraries.yaml")) // #nosec G304 -- a file of this repository
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{"github.com/go-webauthn/webauthn", "transitive_exceptions:", "github.com/golang-jwt/jwt/v5", "golang-jwt/jwt (Go)"} {
		if !strings.Contains(text, want) {
			t.Errorf("docs/reference/approved-libraries.yaml does not mention %q", want)
		}
	}
}
