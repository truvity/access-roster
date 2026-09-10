package verify_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/verify"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clusters.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestTheClustersAreReadAsWritten(t *testing.T) {
	t.Parallel()
	federation, err := verify.LoadFederation(write(t, `
clusters:
  - name: kernel
    issuer: https://oidc.eks.example/id/KERNEL
  - name: devel
    issuer: https://api.devel.example
    jwksUri: https://api.devel.example/openid/v1/jwks
`))
	if err != nil {
		t.Fatalf("LoadFederation: %v", err)
	}
	if len(federation.Clusters) != 2 {
		t.Fatalf("clusters = %+v", federation.Clusters)
	}
	verifiers := federation.Verifiers("access-issuer", nil)
	if verifiers[0].Audience != "access-issuer" || verifiers[1].JWKSURI == "" {
		t.Errorf("verifiers = %+v, %+v", verifiers[0], verifiers[1])
	}
}

// No file is a deployment that federates no cluster. That is a real
// posture — an issuer serving people and CI and no workloads — and not a
// failure to configure.
func TestNoFileFederatesNothing(t *testing.T) {
	t.Parallel()
	federation, err := verify.LoadFederation("")
	if err != nil || len(federation.Clusters) != 0 {
		t.Errorf("LoadFederation(\"\") = %+v, %v", federation, err)
	}
}

// A malformed file is a START-UP failure. A row skipped would be a
// cluster whose workloads quietly stop being able to exchange, and the
// only symptom is a refusal that names the wrong cause.
func TestABadRowRefusesToStart(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, content, want string }{
		{"no name", "clusters:\n  - issuer: https://one.example\n", "names no cluster"},
		{"no issuer", "clusters:\n  - name: kernel\n", "names no issuer"},
		{
			// Two rows for one issuer is ambiguous in the one way that
			// matters: the first answers for every token of it, so the
			// second's name never reaches a matcher, and a rule written
			// against that name grants nothing with no reason visible.
			"two rows for one issuer",
			"clusters:\n  - name: kernel\n    issuer: https://one.example\n  - name: devel\n    issuer: https://one.example\n",
			"both claim the issuer",
		},
		{"not YAML", "clusters: [", "parse"},
	} {
		_, err := verify.LoadFederation(write(t, tc.content))
		if err == nil {
			t.Errorf("%s was accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}

	if _, err := verify.LoadFederation(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a path that does not exist was accepted")
	}
}
