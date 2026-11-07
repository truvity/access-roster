//go:build sluis_test

package driver

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/slotplan"
)

// keysYAML is the part of docs/architecture/keys.yaml that the slot plan is checked against.
type keysYAML struct {
	Purposes []struct {
		Name      string `yaml:"name"`
		Algorithm string `yaml:"algorithm"`
		Board     struct {
			Slot      string `yaml:"slot"`
			Algorithm string `yaml:"algorithm"`
			Runtimes  []string
		} `yaml:"board"`
	} `yaml:"purposes"`
	SlotPlan struct {
		Slots  map[string]string `yaml:"slots"`
		Spare  struct{ From, To string }
		Unused map[string]string `yaml:"unused"`
	} `yaml:"slot_plan"`
}

func readKeysYAML(t *testing.T) keysYAML {
	t.Helper()
	raw, err := os.ReadFile("../../../../../docs/architecture/keys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var k keysYAML
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	return k
}

// The default slot plan of the card driver gives each key its own slot (ADR 0006, "The slot plan"). Three things are
// checked together: no slot holds two purposes and no purpose sits in two slots, so no key shares a card slot with
// another; the slot of each purpose is the slot that docs/architecture/keys.yaml gives it, with the algorithm that
// the card holds there; and a purpose that the registry puts in a spare slot (an on-use purpose or a named exception,
// one key per purpose and algorithm) has no row, so the driver does not serve it from a slot of the default map.
// The installation's own slot map is checked where it is read, by DecodeSlotMap (kits/go/pinrelease).
//
// verifies: REQ-KEYS-046
func TestTheDefaultSlotPlanGivesEveryKeyASlotOfItsOwn(t *testing.T) {
	bySlot, byPurpose := map[uint8]string{}, map[string]bool{}
	for _, e := range slotPlan {
		if other, dup := bySlot[uint8(e.slot)]; dup {
			t.Errorf("slot %02x holds both %s and %s", uint8(e.slot), other, e.purpose)
		}
		bySlot[uint8(e.slot)] = e.purpose
		if byPurpose[e.purpose] {
			t.Errorf("purpose %s has two rows", e.purpose)
		}
		byPurpose[e.purpose] = true
	}
	if len(slotPlan) < 9 {
		t.Fatalf("the plan has %d rows: the sweep checked nothing", len(slotPlan))
	}

	k := readKeysYAML(t)
	if len(k.Purposes) == 0 || len(k.SlotPlan.Slots) == 0 {
		t.Fatal("keys.yaml gave no purposes or no slot plan")
	}
	// keys.yaml names the same slots and purposes as the driver, once each.
	seen := map[string]bool{}
	for slot, purpose := range k.SlotPlan.Slots {
		if seen[purpose] {
			t.Errorf("keys.yaml puts %s in two slots", purpose)
		}
		seen[purpose] = true
		e, ok := planFor(purpose)
		if !ok {
			t.Errorf("keys.yaml puts %s in slot %s, and the driver has no row for it", purpose, slot)
			continue
		}
		if got := e.slot.String(); got != slot {
			t.Errorf("%s: keys.yaml slot %s, driver slot %s", purpose, slot, got)
		}
	}
	for _, e := range slotPlan {
		if !seen[e.purpose] {
			t.Errorf("the driver has a row for %s that keys.yaml's slot plan does not", e.purpose)
		}
	}
	if len(slotPlan) != len(k.SlotPlan.Slots) {
		t.Errorf("%d rows in the driver, %d slots in keys.yaml", len(slotPlan), len(k.SlotPlan.Slots))
	}

	norm := func(s string) string { return strings.ReplaceAll(s, "-", "") }
	spare := 0
	for _, p := range k.Purposes {
		switch p.Board.Slot {
		case "none":
		case "spare":
			spare++
			if _, ok := planFor(p.Name); ok {
				t.Errorf("%s is a spare-slot purpose, and the default plan has a row for it", p.Name)
			}
		default:
			e, ok := planFor(p.Name)
			if !ok {
				t.Errorf("%s: keys.yaml gives it slot %s, and the driver has no row", p.Name, p.Board.Slot)
				continue
			}
			want := p.Algorithm
			if p.Board.Algorithm != "" {
				want = p.Board.Algorithm
			}
			if norm(e.algorithm) != norm(want) {
				t.Errorf("%s: the card holds %s, keys.yaml says %s", p.Name, e.algorithm, want)
			}
			if k.SlotPlan.Slots[p.Board.Slot] != p.Name {
				t.Errorf("%s: board.slot %s, but the slot plan puts %s there", p.Name, p.Board.Slot, k.SlotPlan.Slots[p.Board.Slot])
			}
		}
	}
	// One purpose and one algorithm per spare-slot key: no two purposes of the registry are the same name.
	if spare == 0 {
		t.Fatal("no purpose takes a spare slot: the sweep checked nothing")
	}
	names := map[string]bool{}
	for _, p := range k.Purposes {
		if names[p.Name] {
			t.Errorf("purpose %s is listed twice in keys.yaml", p.Name)
		}
		names[p.Name] = true
	}
	// The unused slot of the plan is no row's slot.
	for slot := range k.SlotPlan.Unused {
		if p, ok := k.SlotPlan.Slots[slot]; ok {
			t.Errorf("slot %s is both unused and the slot of %s", slot, p)
		}
	}
}

// An installation may override the map in its signed KeyPlan, and the card driver reads that slot map itself (it does
// not trust key@ to have read it). A map that puts two purposes on one slot, or one purpose on two slots, is refused
// with the path of the second; the same slot on two different nodes is two cards and is fine.
//
// verifies: REQ-KEYS-046
func TestAnInstallationSlotMapCannotShareASlotBetweenKeys(t *testing.T) {
	plan := func(a, b string) []byte {
		return []byte("default:\n  cache_ttl: 15m\n  slot_map:\n    - { node: board-a, slots: [" + a + "] }\n    - { node: board-b, slots: [" + b + "] }\n")
	}
	key := func(slot, purpose string) string {
		return "{ slot: \"" + slot + "\", purpose: " + purpose + ", public_key: AQID }"
	}
	ok := plan(key("9d", "wrapping")+", "+key("9a", "token-signing"), key("9d", "wrapping"))
	m, err := pinrelease.SlotMapOf(ok)
	if err != nil || len(m) != 2 || len(m[0].GetSlots()) != 2 {
		t.Fatalf("a map with a slot of its own for each key was refused or misread: %v, %v", m, err)
	}
	for name, c := range map[string]struct {
		doc  []byte
		path string
	}{
		"two purposes on one slot":       {plan(key("9d", "wrapping")+", "+key("9d", "token-signing"), ""), "slot_map[0].slots[1].slot"},
		"one purpose on two slots":       {plan(key("9d", "wrapping")+", "+key("9a", "wrapping"), ""), "slot_map[0].slots[1].purpose"},
		"a collision on the second node": {plan("", key("85", "release-signing")+", "+key("85", "workload-issuer")), "slot_map[1].slots[1].slot"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pinrelease.SlotMapOf(c.doc)
			if err == nil || !strings.Contains(err.Error(), c.path) || !strings.Contains(err.Error(), "listed twice") {
				t.Fatalf("error = %v, want %q listed twice", err, c.path)
			}
		})
	}
}

// The card driver's table is the default map that key@ checks a KeyPlan against (kits/go/slotplan), slot for slot: key@
// refuses a plan the card would not follow only if the two tables are one.
func TestTheDriversTableIsTheSlotPlanKitsDefault(t *testing.T) {
	if len(slotPlan) != len(slotplan.Default) {
		t.Fatalf("the driver has %d purposes, the kit %d", len(slotPlan), len(slotplan.Default))
	}
	for _, e := range slotPlan {
		if got := slotplan.Default[e.purpose]; got != e.slot.String() {
			t.Errorf("%s: the driver's slot %s, the kit's %q", e.purpose, e.slot, got)
		}
	}
}
