//go:build sluis_test

package keyd

import (
	"context"
	"os"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// keyPurposeNames is every key purpose name of docs/architecture/keys.yaml: the key store's purposes and the data keys
// of a tenant and of the boundary, plus names that are no purpose at all. The sweep below asks for each of them with
// every operation, so a purpose added to the registry is swept without a change here.
func keyPurposeNames(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/architecture/keys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var k struct {
		Purposes []struct {
			Name string `yaml:"name"`
		} `yaml:"purposes"`
		DataKeys map[string]map[string]yaml.Node `yaml:"data_keys"`
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range k.Purposes {
		out = append(out, p.Name)
	}
	for _, scope := range k.DataKeys {
		for name := range scope {
			out = append(out, name)
		}
	}
	out = append(out, "nonsense", "")
	slices.Sort(out)
	return slices.Compact(out)
}

// verifies: REQ-KEYS-029
// The generated key rules matrix: for every caller of key@, every purpose of the registry (and names that are none), both
// scopes and every operation of the service, a call that no rule of the registry allows is refused as permission_denied
// with the reason "rule" and is one audit fact that names the caller, the operation and the purpose; a call that a rule
// allows is not refused by the rule (it may be refused by the grant, the content or the address, which come after).
// The expectation is the registry's own answer, asked of registry.KeyAllows for each cell, so the test checks that key@
// asks the registry for everything and takes no shortcut. Two cells it does not reach are SealGrant and OpenGrant
// (the purpose grant, whose rule they read in the same way), swept as their own operations.
func TestEveryCallerPurposeAndOperationNotInTheRegistryIsRefused(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	ctx := context.Background()
	purposes := keyPurposeNames(t)
	if len(purposes) < 20 {
		t.Fatalf("only %d purposes swept", len(purposes))
	}
	var refusedCells, allowedCells int

	refusedByRule := func(err error) bool {
		reason, _ := refusal.Reason(err)
		return connect.CodeOf(err) == connect.CodePermissionDenied && reason == reasonRule
	}
	for _, actor := range registry.CallersOf("key") {
		c := n.client(actor)
		for _, scope := range []string{registry.ScopeBoundary, registry.ScopeTenant} {
			tenant := ""
			if scope == registry.ScopeTenant {
				tenant = "acme"
			}
			for _, p := range purposes {
				// Each call is one cell of the matrix: the operation, the scope of the key, the purpose.
				calls := map[string]func() error{
					"seal": func() error {
						_, err := seal1(c, p, "kind", tenant, vecID, []byte("x"), nil)
						return err
					},
					"open": func() error {
						_, err := open1(c, p, "kind", tenant, vecID, make([]byte, 64), nil)
						return err
					},
				}
				if scope == registry.ScopeBoundary {
					calls["sign"] = func() error {
						_, err := c.Sign(ctx, signReq(p, []byte("x")))
						return err
					}
					calls["public-key"] = func() error {
						_, err := c.PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: p}))
						return err
					}
				}
				if p == "mac" || p == "pseudonym" || p == "pairwise" {
					calls["mac"] = func() error {
						_, err := c.Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: p, Tenant: tenant, Label: "l", Input: []byte("i"), Epoch: epochOf(p)}))
						return err
					}
				}
				for op, call := range calls {
					// A call has the scope of its purpose (cookie and grant the boundary's, evidence and chain a tenant's, mac
					// the boundary's, the other Mac purposes a tenant's) or, for data, of its address. A cell in the other scope
					// is no call of that scope, and is swept in its own scope's turn.
					actual := scope
					switch {
					case (op == "seal" || op == "open") && (p == "cookie" || p == "grant"), op == "mac" && p == "mac":
						actual = registry.ScopeBoundary
					case (op == "seal" || op == "open") && (p == "evidence" || p == "chain"), op == "mac":
						actual = registry.ScopeTenant
					}
					if actual != scope {
						continue
					}
					// Seal and Open take the scope from the address (a tenant or none); a purpose whose scope is not the
					// cell's is a cell of the other scope, so the cell's scope is the one the call itself carries.
					want := registry.KeyAllows(actor, scope, p, op)
					// Seal and Open check that the purpose is one they take before the rule, and Mac does the same: for a
					// purpose that is not, the refusal is a purpose refusal, which is also an audit fact.
					_, sealableP := sealable(p)
					beforeRule := ((op == "seal" || op == "open") && !sealableP) || (op == "mac" && p != "mac" && p != "pseudonym" && p != "pairwise")
					before := n.audit.count(ActionRefuse)
					err := call()
					cellName := actor + " " + op + " " + scope + "/" + p
					if want {
						allowedCells++
						if err != nil && refusedByRule(err) {
							t.Errorf("%s: the registry allows it and key@ refused it by rule: %v", cellName, err)
						}
						continue
					}
					// Not allowed by a rule: either the rule refuses it, or the purpose is none that the call takes (an
					// invalid_argument, also an audit fact). Never a success.
					if err == nil {
						t.Errorf("%s: the registry does not allow it and key@ answered", cellName)
						continue
					}
					refusedCells++
					if !beforeRule && !refusedByRule(err) {
						t.Errorf("%s: the registry does not allow it and key@ refused it, but not by the rule: %v", cellName, err)
					}
					if n.audit.count(ActionRefuse) != before+1 {
						t.Errorf("%s: %d audit facts for one refusal, want 1", cellName, n.audit.count(ActionRefuse)-before)
					}
				}
			}
		}
	}
	// The sweep is not empty in either direction, and the cells that no rule allows far outnumber the ones that do.
	if allowedCells < 20 || refusedCells < 10*allowedCells {
		t.Fatalf("the sweep checked %d allowed and %d refused cells", allowedCells, refusedCells)
	}
	t.Logf("swept %d cells allowed by a rule and %d refused", allowedCells, refusedCells)
	// The grant operations read the same rules.
	for _, actor := range registry.CallersOf("key") {
		c := n.client(actor)
		_, err := c.SealGrant(ctx, connect.NewRequest(&keyv2alpha1.SealGrantRequest{}))
		if registry.KeyAllows(actor, registry.ScopeBoundary, "grant", "seal") == refusedByRule(err) {
			t.Errorf("%s SealGrant: allowed by the registry = %v, refused by rule = %v", actor, !refusedByRule(err), refusedByRule(err))
		}
		_, err = n.client(actor).OpenGrant(ctx, connect.NewRequest(&keyv2alpha1.OpenGrantRequest{}))
		if registry.KeyAllows(actor, registry.ScopeBoundary, "grant", "open") == refusedByRule(err) {
			t.Errorf("%s OpenGrant: allowed by the registry = %v, refused by rule = %v", actor, !refusedByRule(err), refusedByRule(err))
		}
	}
}

// epochOf is a valid epoch for a pseudonym and none for the other Mac purposes.
func epochOf(purpose string) string {
	if purpose == "pseudonym" {
		return "202611"
	}
	return ""
}
