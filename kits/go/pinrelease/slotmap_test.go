package pinrelease

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// verifies: REQ-KEYS-115
// The card driver reads the slot map of the KeyPlan payload as key@ and store@ do: the shared vectors
// (tests/testdata/signed-config/keyplan-payloads.json). Every case that reads gives the same slot map, and every case
// refused in its slot map is refused here too, at the same path.
func TestSlotMapOfTheKeyPlanPayloadVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/testdata/signed-config/keyplan-payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name        string `json:"name"`
			Payload     string `json:"payload"`
			RefusedPath string `json:"refused_path"`
			Read        *struct {
				SlotMap []struct {
					Node  string `json:"node"`
					Slots []struct {
						Slot              string `json:"slot"`
						Purpose           string `json:"purpose"`
						PublicKey         string `json:"public_key"`
						Attestation       string `json:"attestation"`
						AttestationSigner string `json:"attestation_signer"`
					} `json:"slots"`
				} `json:"slot_map"`
			} `json:"read"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	var read, refused int
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := SlotMapOf([]byte(c.Payload))
			if c.Read == nil {
				if !strings.Contains(c.RefusedPath, "slot_map") {
					return // a refusal outside the slot map is key@'s reading of the rest of the item
				}
				refused++
				if err == nil {
					t.Fatal("want a refusal, got a slot map")
				}
				if !strings.Contains(err.Error(), c.RefusedPath) {
					t.Fatalf("refused at %q, want %q", err.Error(), c.RefusedPath)
				}
				return
			}
			read++
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(got) != len(c.Read.SlotMap) {
				t.Fatalf("%d nodes, want %d", len(got), len(c.Read.SlotMap))
			}
			for i, n := range c.Read.SlotMap {
				g := got[i]
				if g.GetNode() != n.Node || len(g.GetSlots()) != len(n.Slots) {
					t.Fatalf("node %d: %v", i, g)
				}
				for j, s := range n.Slots {
					k := g.GetSlots()[j]
					if k.GetSlot() != s.Slot || k.GetPurpose() != s.Purpose || enc.EncodeToString(k.GetPublicKey()) != s.PublicKey ||
						enc.EncodeToString(k.GetAttestation()) != s.Attestation || enc.EncodeToString(k.GetAttestationSigner()) != s.AttestationSigner {
						t.Fatalf("node %d slot %d: %v", i, j, k)
					}
				}
			}
		})
	}
	if read < 5 || refused < 10 {
		t.Fatalf("%d read and %d refused slot map cases: a sweep over nothing proves nothing", read, refused)
	}
}

func TestSignerKeyIsSlot87OfTheNode(t *testing.T) {
	m, err := SlotMapOf([]byte("default:\n  cache_ttl: 15m\n  slot_map:\n" +
		"    - { node: board-a, slots: [{ slot: \"87\", purpose: pin-release, public_key: AQID }] }\n" +
		"    - { node: board-b, slots: [{ slot: \"86\", purpose: pin-release, public_key: AQID }] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := SignerKey(m, "board-a"); !ok || k.GetSlot() != "87" {
		t.Fatal("board-a has its key in slot 87")
	}
	if _, ok := SignerKey(m, "board-b"); ok {
		t.Fatal("a pin-release key outside slot 87 is taken")
	}
	if _, ok := SignerKey(m, "board-c"); ok {
		t.Fatal("an unlisted node has a key")
	}
}
