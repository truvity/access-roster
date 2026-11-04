//go:build sluis_test

package keyd

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// verifies: REQ-KEYS-111
// The Boundary payload vectors are shared with store@ (actors/store/tests/vectors.rs): key@ takes the environment of the
// floor from the bytes it verified, so it must read them as store@ does.
func TestBoundaryPayloadVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/testdata/signed-config/boundary-payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name        string `json:"name"`
			Payload     string `json:"payload"`
			RefusedPath string `json:"refused_path"`
			Read        *struct {
				Name          string   `json:"name"`
				Kind          string   `json:"kind"`
				Level         string   `json:"level"`
				Environment   string   `json:"environment"`
				Issuer        string   `json:"issuer"`
				UIDBlock      uint32   `json:"uid_block"`
				DefaultTenant string   `json:"default_tenant"`
				DeclaredKinds []string `json:"declared_kinds"`
			} `json:"read"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 35 {
		t.Fatalf("%d cases: a sweep over nothing proves nothing", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			b, err := decodeBoundary([]byte(c.Payload))
			if c.Read == nil {
				if err == nil {
					t.Fatal("want a refusal, got a Boundary")
				}
				if !strings.Contains(err.Error(), c.RefusedPath) {
					t.Fatalf("the refusal %q does not name %q", err, c.RefusedPath)
				}
				return
			}
			if err != nil {
				t.Fatalf("want it read, got %v", err)
			}
			w := c.Read
			if b.GetName() != w.Name || b.GetKind() != w.Kind || b.GetLevel() != w.Level || b.GetEnvironment() != w.Environment ||
				b.GetIssuer() != w.Issuer || b.GetUidBlock() != w.UIDBlock || b.GetDefaultTenant() != w.DefaultTenant {
				t.Errorf("read %v, want %+v", b, w)
			}
			if !slices.Equal(b.GetDeclaredKinds(), w.DeclaredKinds) && (len(b.GetDeclaredKinds()) != 0 || len(w.DeclaredKinds) != 0) {
				t.Errorf("declared_kinds = %v, want %v", b.GetDeclaredKinds(), w.DeclaredKinds)
			}
		})
	}
}
