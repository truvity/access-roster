//go:build sluis_test

package keyd

import (
	"encoding/json"
	"fmt"
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
				ACRValues     []string `json:"acr_values_supported"`
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
			if !slices.Equal(b.GetAcrValuesSupported(), w.ACRValues) && (len(b.GetAcrValuesSupported()) != 0 || len(w.ACRValues) != 0) {
				t.Errorf("acr_values_supported = %v, want %v", b.GetAcrValuesSupported(), w.ACRValues)
			}
			if !slices.Equal(b.GetDeclaredKinds(), w.DeclaredKinds) && (len(b.GetDeclaredKinds()) != 0 || len(w.DeclaredKinds) != 0) {
				t.Errorf("declared_kinds = %v, want %v", b.GetDeclaredKinds(), w.DeclaredKinds)
			}
		})
	}
}

// key@ names the place of the acr value that breaks a rule, as store@'s decoder does (its own tests hold that side): the 17th
// value, the second of a repeat, and a value with a space; and the rules are the rules of the schema, so a value store@ lists
// is a value key@ reads.
func TestKeyReadsTheACRValuesAStoreListsAndNamesThePlaceOfAnyOther(t *testing.T) {
	doc := func(list string) string {
		return "default:\n  name: dev\n  kind: environment\n  level: L2\n  environment: production\n  issuer: https://sluis.example.test\n  uid_block: 0\n  acr_values_supported: " + list + "\n"
	}
	sixteen, seventeen := make([]string, 0, 17), make([]string, 0, 17)
	for i := range 17 {
		v := fmt.Sprintf("v%d", i)
		if i < 16 {
			sixteen = append(sixteen, v)
		}
		seventeen = append(seventeen, v)
	}
	b, err := decodeBoundaryUnvalidated([]byte(doc("[" + strings.Join(sixteen, ", ") + "]")))
	if err != nil || len(b.GetAcrValuesSupported()) != 16 {
		t.Fatalf("sixteen values: %v %v", b.GetAcrValuesSupported(), err)
	}
	for list, want := range map[string]string{
		"[" + strings.Join(seventeen, ", ") + "]": "acr_values_supported[16]",
		"[a, b, a]":                            "acr_values_supported[2]",
		`["a b"]`:                              "acr_values_supported[0]",
		`["a\"b"]`:                             "acr_values_supported[0]",
		`["` + strings.Repeat("a", 257) + `"]`: "acr_values_supported[0]",
		`[""]`:                                 "acr_values_supported[0]",
		`[ok, 1]`:                              "acr_values_supported[1]",
	} {
		if _, err := decodeBoundaryUnvalidated([]byte(doc(list))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.40q: %v, want a refusal naming %s", list, err, want)
		}
		// And the whole reader, schema first, refuses it too, at that place or at the list.
		if _, err := decodeBoundary([]byte(doc(list))); err == nil || !strings.Contains(err.Error(), "acr_values_supported") {
			t.Errorf("%.40q: the reader with its schema says %v", list, err)
		}
	}
	for _, ok := range []string{`["-a", "_b", "1", "urn:example:acr:mfa"]`, `[` + strings.Repeat("a", 256) + `]`} {
		if _, err := decodeBoundaryUnvalidated([]byte(doc(ok))); err != nil {
			t.Errorf("%.40q: %v", ok, err)
		}
	}
}
