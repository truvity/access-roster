package slotplan

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func p(name, alg, slot string) Purpose { return Purpose{name, alg, slot} }

// verifies: REQ-PKI-035, REQ-PKI-037, REQ-PKI-038, REQ-PKI-042
// The check of a slot map: two purposes in one slot (by name or by default) are refused, and so is an enabled purpose that
// has no slot; a slot map without the slots of purposes that are not enabled is accepted; the token-signing key and the key
// of the intermediate never share a slot, so one key cannot serve both.
func TestTheSlotMap(t *testing.T) {
	good := []Purpose{p("wrapping", "ECDH-P384", ""), p("token-signing", "ES384", "9a"), p("audit-log", "ES256", ""), p("data", "AES-256-GCM", "")}
	slots, err := Resolve(good)
	if err != nil || slots["token-signing"] != "9a" || slots["audit-log"] != "84" || slots["wrapping"] != "9d" || len(slots) != 3 {
		t.Fatalf("Resolve = %v, %v", slots, err)
	}
	// An installation that enables neither ssh purpose has no slot for them (REQ-PKI-042), and none is needed.
	if _, ok := slots["ssh-user"]; ok {
		t.Fatal("a purpose that is not enabled got a slot")
	}
	for name, c := range map[string]struct {
		in   []Purpose
		want string
	}{
		"two purposes name one slot":             {[]Purpose{p("token-signing", "ES384", "9a"), p("x509-intermediate", "ES384", "9a")}, "shared with token-signing"},
		"a named slot takes another's default":   {[]Purpose{p("token-signing", "ES384", ""), p("release-signing", "ES384", "9a")}, "shared with token-signing"},
		"the token key in the intermediate slot": {[]Purpose{p("x509-intermediate", "ES384", ""), p("token-signing", "ES384", "9c")}, "shared with x509-intermediate"},
		"an enabled purpose with no slot":        {[]Purpose{p("issuance-log", "ES384", "")}, "no slot"},
		"a slot that is no board slot":           {[]Purpose{p("issuance-log", "ES384", "9e")}, "not a slot of a board"},
		"a slot above the retired range":         {[]Purpose{p("issuance-log", "ES384", "96")}, "not a slot of a board"},
		"an upper-case slot":                     {[]Purpose{p("issuance-log", "ES384", "9A")}, "not a slot of a board"},
		"a purpose listed twice":                 {[]Purpose{p("token-signing", "ES384", ""), p("token-signing", "ES384", "88")}, "listed twice"},
	} {
		err := Check(c.in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if err := Check([]Purpose{p("issuance-log", "ES384", "88")}); err != nil {
		t.Errorf("a spare slot: %v", err)
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
