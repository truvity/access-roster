package slotplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type vectorFile struct {
	Cases []struct {
		Name  string `json:"name"`
		Check []struct {
			Purpose   string `json:"purpose"`
			Algorithm string `json:"algorithm"`
			Slot      string `json:"slot"`
		} `json:"check"`
		Error string `json:"error"`
		Card  string `json:"card"`
	} `json:"cases"`
}

// verifies: REQ-PKI-035, REQ-PKI-037, REQ-PKI-038, REQ-PKI-042, REQ-KEYS-268
// The vectors of the slot map check (testdata/vectors.json, shared with the other programs that take a slot map): two
// purposes in one slot (by name or by default) are refused, so are an enabled purpose with no slot, a slot that is no board
// slot, a purpose listed twice and the token-signing key in the intermediate's slot; a map without the slots of purposes that
// are not enabled is accepted. The card check adds the card driver's limit: no override of a slot, no purpose outside the
// map. The RS256 purpose is a card-key purpose like the others: it needs a slot, shares none and is refused on a card, which
// serves no spare slot (an algorithm the check does not list skips every one of these).
func TestTheSlotMapVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 28 {
		t.Fatalf("%d vectors", len(f.Cases))
	}
	want := func(name, got string, err error) {
		t.Helper()
		switch {
		case got == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case got != "" && (err == nil || !strings.Contains(err.Error(), got)):
			t.Errorf("%s: err = %v, want %q", name, err, got)
		}
	}
	for _, c := range f.Cases {
		var ps []Purpose
		for _, x := range c.Check {
			ps = append(ps, Purpose{x.Purpose, x.Algorithm, x.Slot})
		}
		want(c.Name+" (check)", c.Error, Check(ps))
		if c.Error == "" {
			want(c.Name+" (card)", c.Card, CheckCard(ps))
		}
	}
}

// The default map is the one in docs/architecture/keys.yaml, slot for slot.
func TestTheDefaultIsTheRegistrys(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/architecture/keys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var k struct {
		SlotPlan struct {
			Slots map[string]string `yaml:"slots"`
		} `yaml:"slot_plan"`
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	if len(k.SlotPlan.Slots) != len(Default) || len(Default) < 9 {
		t.Fatalf("keys.yaml has %d slots, the default %d", len(k.SlotPlan.Slots), len(Default))
	}
	for slot, purpose := range k.SlotPlan.Slots {
		if Default[purpose] != slot {
			t.Errorf("%s: keys.yaml slot %s, default %q", purpose, slot, Default[purpose])
		}
	}
}
