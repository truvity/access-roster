package deps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The acr values a boundary lists in discovery and the ones session enforces in acr_values are one list, the Boundary
// document's acr_values_supported (REQ-AUTHN-009): entry reads it from the Boundary it builds the document from, session from
// the Boundary it reads at /authorize, and neither reads it anywhere else. The behaviour of each side is tested where it is
// (entry's discovery unit test, session's acr_test.go) against the same field; this holds both to that field, so that one of
// them cannot start to read a list of its own and the two disagree.
func TestDiscoveryAndAuthorizeReadTheSameACRList(t *testing.T) {
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- a file of this repository
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	entry := read("actors/entry/src/discovery.rs")
	if n := strings.Count(entry, "b.acr_values_supported"); n < 2 {
		t.Errorf("entry's discovery reads the Boundary's acr_values_supported %d times, want its check and its use", n)
	}
	authorize := read("actors/session/internal/sessiond/authorize.go")
	if !strings.Contains(authorize, "enforcedACRValues(asked, b.GetAcrValuesSupported())") {
		t.Error("session's /authorize does not enforce acr_values against the Boundary's acr_values_supported")
	}
	// No other file of session reads a list of its own.
	files, err := filepath.Glob(filepath.Join(root, "actors/session/internal/sessiond/*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no session files: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- a file of this repository
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "GetAcrValuesSupported") && !strings.HasSuffix(f, "authorize.go") {
			t.Errorf("%s reads acr_values_supported: the one reader is /authorize", filepath.Base(f))
		}
	}
}
