//go:build sluis_test

package keyd

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// verifies: REQ-KEYS-110
// The KeyPlan payload vectors are shared with store@ (actors/store/tests/vectors.rs): key@ takes the KeyPlan from the
// bytes it verified, so it must read them as store@ does.
func TestKeyPlanPayloadVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/testdata/signed-config/keyplan-payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name        string `json:"name"`
			Payload     string `json:"payload"`
			RefusedPath string `json:"refused_path"`
			Read        *struct {
				CacheTTLSeconds int64    `json:"cache_ttl_seconds"`
				Recipients      []string `json:"recipients"`
				Purposes        []struct {
					Purpose, Algorithm, Slot string
				} `json:"purposes"`
			} `json:"read"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 30 {
		t.Fatalf("%d cases: a sweep over nothing proves nothing", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			plan, err := decodeKeyPlan([]byte(c.Payload))
			if c.Read == nil {
				if err == nil {
					t.Fatal("want a refusal, got a plan")
				}
				if !strings.Contains(err.Error(), c.RefusedPath) {
					t.Fatalf("the refusal %q does not name %q", err, c.RefusedPath)
				}
				return
			}
			if err != nil {
				t.Fatalf("want it read, got %v", err)
			}
			if got := plan.GetCacheTtl().GetSeconds(); got != c.Read.CacheTTLSeconds {
				t.Errorf("cache_ttl = %d s, want %d", got, c.Read.CacheTTLSeconds)
			}
			if !slices.Equal(plan.GetRecipients(), c.Read.Recipients) && (len(plan.GetRecipients()) != 0 || len(c.Read.Recipients) != 0) {
				t.Errorf("recipients = %v, want %v", plan.GetRecipients(), c.Read.Recipients)
			}
			if len(plan.GetPurposes()) != len(c.Read.Purposes) {
				t.Fatalf("%d purposes, want %d", len(plan.GetPurposes()), len(c.Read.Purposes))
			}
			for i, p := range plan.GetPurposes() {
				w := c.Read.Purposes[i]
				if p.GetPurpose() != w.Purpose || p.GetAlgorithm() != w.Algorithm || p.GetSlot() != w.Slot {
					t.Errorf("purpose %d = %v, want %+v", i, p, w)
				}
			}
		})
	}
}
