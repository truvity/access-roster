//go:build sluis_test

package keyd

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// verifies: REQ-PKI-035, REQ-PKI-037, REQ-PKI-038, REQ-PKI-042
// Node initialisation and the check command refuse a KeyPlan whose card slot map is wrong, and say which entry: two
// purposes in one slot (the token-signing key in the intermediate's slot among them, so one key cannot serve both), and an
// enabled purpose that has no slot. A KeyPlan that enables neither ssh purpose has no slot for them and is accepted. The
// board does not start on a refused plan, and no key is asked of the driver.
func TestAWrongSlotMapStopsNodeInitialisationAndTheCheck(t *testing.T) {
	with := func(edit func(*configv2alpha1.KeyPlan)) *testEnv {
		e := newTestEnv(t, "development")
		plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
		edit(plan)
		e.putPlan(plan)
		return e
	}
	add := func(purpose, alg, slot string) func(*configv2alpha1.KeyPlan) {
		return func(p *configv2alpha1.KeyPlan) {
			p.Purposes = append(p.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: purpose, Algorithm: alg, Slot: slot})
		}
	}
	for name, c := range map[string]struct {
		edit func(*configv2alpha1.KeyPlan)
		want string
	}{
		"the token key in the intermediate's slot": {func(p *configv2alpha1.KeyPlan) {
			add("x509-intermediate", "ES384", "9c")(p)
			p.Purposes[1].Slot = "9c" // token-signing
		}, "shared with"},
		"two purposes in one named slot":  {add("release-signing", "ES384", "9a"), "shared with token-signing"},
		"an enabled purpose with no slot": {add("issuance-log", "ES384", ""), "no slot"},
		// An RS256 purpose is a card-key purpose like the others: it needs a slot, and is not skipped for want of one.
		"an enabled RS256 purpose with no slot":     {add("token-signing-rs256", "RS256", ""), "no slot"},
		"the RS256 purpose in the token key's slot": {add("token-signing-rs256", "RS256", "9a"), "shared with token-signing"},
	} {
		t.Run(name, func(t *testing.T) {
			e := with(c.edit)
			n := e.newNode(nodeOpts{})
			err := n.srv.Init(t.Context())
			if err == nil || !strings.Contains(err.Error(), "card slot map") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Init = %v, want a refusal of the slot map with %q", err, c.want)
			}
			if got := driverPurposes(n.driver); len(got) != 1 || got[0] != "wrapping" { // the one the test made to list the node
				t.Fatalf("the driver holds %v after a refused plan, want the wrapping key the test made and no more", got)
			}
			err = n.srv.Check(t.Context())
			if err == nil || !strings.Contains(err.Error(), "card slot map") {
				t.Fatalf("Check = %v, want a refusal of the slot map", err)
			}
		})
	}
	// The plan of tonight enables neither ssh purpose and needs no slot for them.
	e := newTestEnv(t, "development")
	n := e.newNode(nodeOpts{})
	if err := n.srv.Init(t.Context()); err != nil {
		t.Fatalf("the default plan was refused: %v", err)
	}
}

// verifies: REQ-PKI-035, REQ-KEYS-268
// A plan that the card driver would not follow is refused at start and in the check command, with the entry named, before
// any key is asked of the driver: a slot other than the card's for a purpose of its map, and a card-key purpose that the
// map lacks (the spare slots, which the card driver does not serve yet; REQ-KEYS-063), the RS256 purpose among them: the
// card holds no RSA key, and a plan that lists the purpose is refused, not given a board that has none. The same plan is accepted by the
// software driver, which has no slots, and the default plan is accepted on the card.
func TestACardIsNotGivenAPlanItDoesNotFollow(t *testing.T) {
	cases := map[string]struct {
		edit func(*configv2alpha1.KeyPlan)
		want string
	}{
		"another slot for a purpose of the map": {func(p *configv2alpha1.KeyPlan) { p.Purposes[1].Slot = "88" }, "purposes[1].slot: differs from the slot of the card driver"},
		"the issuance log, which has no slot on the card": {func(p *configv2alpha1.KeyPlan) {
			p.Purposes = append(p.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "issuance-log", Algorithm: "ES384", Slot: "88"})
		}, "the card driver serves no slot for this purpose"},
		// The card driver is ECDSA only and serves no spare slot: a plan that lists the RS256 purpose is refused at start
		// and in the check, and is not given a board that silently has no such key.
		"the RS256 purpose, which the card cannot hold": {func(p *configv2alpha1.KeyPlan) {
			p.Purposes = append(p.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "token-signing-rs256", Algorithm: "RS256", Slot: "88"})
		}, "the card driver serves no slot for this purpose"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			for _, store := range []string{"yubikey-piv", "software"} {
				e := newTestEnv(t, "development")
				plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
				c.edit(plan)
				e.putPlan(plan)
				d := newFakeDriver(store)
				d.now = e.clock.now
				n := e.newNode(nodeOpts{driver: d})
				err := n.srv.Init(t.Context())
				if store == "software" {
					if err != nil && strings.Contains(err.Error(), "card driver") {
						t.Fatalf("the software driver was refused for a card's limit: %v", err)
					}
					continue
				}
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Init on a card = %v, want %q", err, c.want)
				}
				if got := driverPurposes(d); len(got) != 1 || got[0] != "wrapping" { // the one the test made to list the node
					t.Fatalf("the driver holds %v after a refused plan, want the test's wrapping key only", got)
				}
				if err := n.srv.Check(t.Context()); err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("Check on a card = %v, want %q", err, c.want)
				}
			}
		})
	}
	e := newTestEnv(t, "development")
	d := newFakeDriver("yubikey-piv")
	d.now = e.clock.now
	n := e.newNode(nodeOpts{driver: d})
	if err := n.srv.Init(t.Context()); err != nil {
		t.Fatalf("the default plan on a card: %v", err)
	}
}
