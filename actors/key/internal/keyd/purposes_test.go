//go:build sluis_test

package keyd

import (
	"context"
	"crypto/elliptic"
	"slices"
	"sort"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// driverPurposes is the purposes the driver holds a key for, sorted.
func driverPurposes(d *fakeDriver) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for p := range d.keys {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// verifies: REQ-KEYS-048
// A purpose outside the baseline has a key only when the KeyPlan of the installation lists it. The release-signing purpose is
// one: the registry gives the signer a rule for it, so a rule alone does not make a key. With the baseline KeyPlan the
// driver is asked for the three keys of the plan and holds three, and the signer's request for the public key and for a
// signature under release-signing is refused as a purpose with no key. A second installation whose KeyPlan lists the
// purpose gets exactly one more key in its driver, the Ensure for it is the one more request, and the public key
// answers. The first installation is not changed by the second.
//
// What this proves is key@'s half: key@ asks for a key of the purposes of the KeyPlan and of no other. The slot is
// the card driver's (TestADevelopmentCardHoldsAKeyOnlyInTheSlotsEnsured in drivers/key/yubikey-piv); the AWS arm
// (an enabled purpose with no key) is not testable here.
func TestAPurposeOutsideTheBaselineHasAKeyOnlyWhenTheKeyPlanEnablesIt(t *testing.T) {
	if !registry.KeyAllows("signer", registry.ScopeBoundary, "release-signing", "public-key") {
		t.Fatal("the registry gives the signer no rule for release-signing: the test would show a refusal by the rule")
	}
	ctx := context.Background()

	off := newTestEnv(t, "development")
	a, spyA := off.spiedNode("node-1")
	baseline := []string{"audit-log", "token-signing", "wrapping"}
	if got := driverPurposes(a.driver); !slices.Equal(got, baseline) {
		t.Fatalf("the baseline driver holds %v, want %v", got, baseline)
	}
	_, err := a.client("signer").PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "release-signing"}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")
	_, err = a.client("signer").Sign(ctx, signReq("release-signing", []byte("x")))
	wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")
	if got := driverPurposes(a.driver); !slices.Equal(got, baseline) {
		t.Fatalf("the refused requests made keys: the driver holds %v", got)
	}

	on := newTestEnv(t, "development")
	plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "release-signing", Algorithm: "ES384", Slot: "85"})
	on.putPlan(plan)
	b, spyB := on.spiedNode("node-1")
	want := append(slices.Clone(baseline), "release-signing")
	sort.Strings(want)
	if got := driverPurposes(b.driver); !slices.Equal(got, want) {
		t.Fatalf("the driver of the enabling installation holds %v, want %v", got, want)
	}
	extra := 0
	for _, p := range spyB.ensures {
		if !slices.Contains(spyA.ensures, p) {
			extra++
			if p != "release-signing" {
				t.Errorf("the enabling installation asked for a key of %q", p)
			}
		}
	}
	if extra != 1 || len(spyB.ensures) != len(spyA.ensures)+1 {
		t.Fatalf("Ensure requests: %v against %v, want exactly one more", spyB.ensures, spyA.ensures)
	}
	res, err := b.client("signer").PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "release-signing"}))
	if err != nil {
		t.Fatalf("PublicKey of the enabled purpose: %v", err)
	}
	pub, _ := publicKey(t, b, "signer", "release-signing")
	if res.Msg.GetAlgorithm() != "ES384" || pub.Curve != elliptic.P384() {
		t.Fatalf("the enabled key is %s on %v", res.Msg.GetAlgorithm(), pub.Curve.Params().Name)
	}
	// The first installation still has no such key.
	_, err = a.client("signer").PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "release-signing"}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")
	if got := driverPurposes(a.driver); !slices.Equal(got, baseline) {
		t.Fatalf("the baseline driver changed: %v", got)
	}
}
