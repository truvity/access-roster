//go:build sluis_test

package keyd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The two registries the rules come from, read here as YAML and not through the generated code under test. A rule is a
// triple of the two: an actor holds an operation on a purpose when actors.yaml gives it that operation (key_purposes) and
// keys.yaml lists it as a user of the key in that scope with that operation.
type rulesDocs struct {
	actors []actorEntry
	// keys.yaml: purposes (boundary keys of a key store) and data keys of the tenant and of the boundary.
	purposes []purposeEntry
	data     map[string]map[string]dataKeyEntry // scope -> name -> entry
}

type actorEntry struct {
	Name       string   `yaml:"name"`
	Family     string   `yaml:"family"`
	Ports      []string `yaml:"ports"`
	KeyPurpose []struct {
		Purpose string   `yaml:"purpose"`
		Ops     []string `yaml:"ops"`
	} `yaml:"key_purposes"`
}

type purposeEntry struct {
	Name      string   `yaml:"name"`
	Kind      string   `yaml:"kind"`
	Algorithm string   `yaml:"algorithm"`
	Enabled   string   `yaml:"enabled"`
	Ops       []string `yaml:"ops"`
	Users     []string `yaml:"users"`
	Board     struct {
		Slot string `yaml:"slot"`
	} `yaml:"board"`
}

type dataKeyEntry struct {
	Ops   []string `yaml:"ops"`
	Users []string `yaml:"users"`
}

func readRulesDocs(t *testing.T) rulesDocs {
	t.Helper()
	var d rulesDocs
	raw, err := os.ReadFile("../../../../docs/architecture/keys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var k struct {
		Purposes []purposeEntry                     `yaml:"purposes"`
		DataKeys map[string]map[string]dataKeyEntry `yaml:"data_keys"`
	}
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	d.purposes, d.data = k.Purposes, k.DataKeys
	raw, err = os.ReadFile("../../../../docs/architecture/actors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Actors   []actorEntry `yaml:"actors"`
		Platform []actorEntry `yaml:"platform"`
	}
	if err := yaml.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	d.actors = append(a.Actors, a.Platform...)
	return d
}

// callers are the actors that have the keys port: the callers of key@.
func (d rulesDocs) callers() []string {
	var out []string
	for _, a := range d.actors {
		if a.Name != "key" && slices.Contains(a.Ports, "keys") {
			out = append(out, a.Name)
		}
	}
	slices.Sort(out)
	return out
}

// listedUser says whether keys.yaml names actor among the users of an entry ("every work actor" is the actors of the
// family work).
func (d rulesDocs) listedUser(actor string, users []string) bool {
	for _, u := range users {
		if u == actor {
			return true
		}
		if u == "every work actor" {
			for _, a := range d.actors {
				if a.Name == actor && a.Family == "work" {
					return true
				}
			}
		}
	}
	return false
}

// allows is the independent answer: the actor holds op on the key (scope, purpose).
func (d rulesDocs) allows(actor, scope, purpose, op string) bool {
	given := false
	for _, a := range d.actors {
		if a.Name != actor {
			continue
		}
		for _, kp := range a.KeyPurpose {
			if kp.Purpose == purpose && slices.Contains(kp.Ops, op) {
				given = true
			}
		}
	}
	if !given {
		return false
	}
	if scope == registry.ScopeBoundary {
		for _, p := range d.purposes {
			if p.Name == purpose && slices.Contains(p.Ops, op) && d.listedUser(actor, p.Users) {
				return true
			}
		}
	}
	name := "boundary"
	if scope == registry.ScopeTenant {
		name = "tenant"
	}
	e, ok := d.data[name][purpose]
	return ok && slices.Contains(e.Ops, op) && d.listedUser(actor, e.Users)
}

// names is every purpose name of the two files, plus names that are none.
func (d rulesDocs) names() []string {
	var out []string
	for _, p := range d.purposes {
		out = append(out, p.Name)
	}
	for _, scope := range d.data {
		for name := range scope {
			out = append(out, name)
		}
	}
	out = append(out, "nonsense", "")
	slices.Sort(out)
	return slices.Compact(out)
}

// verifies: REQ-KEYS-029
// The rules matrix, with an expectation that does not come from the code that enforces it. The expected matrix is built
// from docs/architecture/actors.yaml (the operations an actor is given on a purpose) and docs/architecture/keys.yaml (the
// users and operations of each key, in the scope of its tenant or boundary), read as YAML by this test. First the generated
// registry is compared with it for every caller, purpose, scope and operation. Then key@ is called for each of those
// cells, over its socket, as that caller: a cell the files do not give is refused as permission_denied/rule with one audit
// fact that names the caller, the operation and the purpose; a cell they give is not refused by the rule, and where the call
// can be made with valid input (Seal, Open, Mac, PublicKey, and Sign of the token, RS256 token, audit log and issuance log) it succeeds.
// A purpose that keys.yaml does not enable in the plan, and a Sign whose content check is its own matter, are shown to reach
// the check after the rule. The counts are asserted.
func TestEveryCallerPurposeAndOperationNotInTheFilesIsRefused(t *testing.T) {
	docs := readRulesDocs(t)
	callers := docs.callers()
	if !slices.Equal(callers, registry.CallersOf("key")) {
		t.Fatalf("callers of key@: actors.yaml says %v, the registry %v", callers, registry.CallersOf("key"))
	}
	names := docs.names()
	scopes := []string{registry.ScopeBoundary, registry.ScopeTenant}
	ops := []string{"seal", "open", "sign", "mac", "public-key", "wrap", "unwrap", "certify"}

	// 1. The generated registry is the files' answer, cell by cell.
	var expectedAllowed int
	for _, actor := range callers {
		for _, scope := range scopes {
			for _, p := range names {
				for _, op := range ops {
					want := docs.allows(actor, scope, p, op)
					if want {
						expectedAllowed++
					}
					if got := registry.KeyAllows(actor, scope, p, op); got != want {
						t.Errorf("registry.KeyAllows(%s, %s, %s, %s) = %v, the files say %v", actor, scope, p, op, got, want)
					}
				}
			}
		}
	}
	if expectedAllowed < 60 {
		t.Fatalf("the files give %d cells, too few: the oracle read the wrong thing", expectedAllowed)
	}

	// 2. key@ enforces it. The plan enables every signing purpose key@ can serve, so that an allowed PublicKey is a success.
	e := newTestEnv(t, "development")
	plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	enabled := map[string]bool{"token-signing": true, "audit-log": true, "wrapping": true}
	spare := 0
	for _, p := range docs.purposes {
		// The RS256 purpose is the one named exception key@ serves besides the ES384 purposes; the others (PS256, EdDSA, ...) are
		// not served and a plan that lists one is refused.
		rs := p.Name == rs256Purpose
		if p.Kind != "signing" || (p.Enabled == "named-exception" && !rs) || (p.Algorithm != "ES384" && !rs) || enabled[p.Name] {
			continue
		}
		slot := p.Board.Slot
		if slot == "spare" {
			slot = fmt.Sprintf("%x", 0x89+spare) // 88 is the RS256 purpose's
			spare++
		}
		plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: p.Name, Algorithm: p.Algorithm, Slot: slot})
		enabled[p.Name] = true
	}
	e.putPlan(plan)
	n := e.startedNode(nodeOpts{})
	ctx := context.Background()
	_, kid := publicKey(t, n, "signer", "token-signing")
	_, rsKid := rsPublic(t, n)
	checkpoint := []byte("example.com/log\n12\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")

	// tenant of the call by the scope of the cell; the address kinds are the ones the sealed kinds use.
	tenantOf := func(scope string) string {
		if scope == registry.ScopeTenant {
			return "acme"
		}
		return ""
	}
	// sealer is an actor the files give Seal on the key; its envelope is what an Open cell opens.
	sealer := func(scope, purpose string) string {
		for _, a := range callers {
			if docs.allows(a, scope, purpose, "seal") {
				return a
			}
		}
		return ""
	}
	grantFor := func(actor, tenant string, ops ...string) []byte {
		if tenant == "" {
			return nil
		}
		if len(ops) == 0 {
			ops = []string{"seal", "open"}
		}
		return n.grant(actor, []string{tenant}, ops, time.Minute)
	}
	kindOf := func(purpose string) string {
		switch purpose {
		case "cookie":
			return "cookie"
		case "credential":
			return "staff-passkey" // the one kind the purpose seals
		}
		return "person"
	}
	refusedByRule := func(err error) bool {
		reason, _ := refusal.Reason(err)
		return connect.CodeOf(err) == connect.CodePermissionDenied && reason == reasonRule
	}
	reasonOf := func(err error) string { r, _ := refusal.Reason(err); return r }

	var refusedCells, succeeded, reached int
	for _, actor := range callers {
		for _, scope := range scopes {
			tenant := tenantOf(scope)
			for _, p := range names {
				for _, op := range ops {
					var call func() error
					var mustSucceed bool
					switch op {
					case "seal":
						call = func() error {
							g := grantFor(actor, tenant) // before the client: making a grant speaks as policy
							_, err := seal1(n.client(actor), p, kindOf(p), tenant, vecID, []byte("x"), g)
							return err
						}
						mustSucceed = true
					case "open":
						call = func() error {
							env := make([]byte, 64)
							if s := sealer(scope, p); s != "" {
								var err error
								sg := grantFor(s, tenant)
								if env, err = seal1(n.client(s), p, kindOf(p), tenant, vecID, []byte("x"), sg); err != nil {
									return fmt.Errorf("the sealer %s: %w", s, err)
								}
							}
							og := grantFor(actor, tenant)
							_, err := open1(n.client(actor), p, kindOf(p), tenant, vecID, env, og)
							return err
						}
						mustSucceed = sealer(scope, p) != ""
					case "sign":
						if scope != registry.ScopeBoundary {
							continue
						}
						body := []byte("x")
						switch p {
						case "token-signing":
							body, mustSucceed = tokenInput(kid, "", ""), true
						case "audit-log", "issuance-log":
							body, mustSucceed = checkpoint, true
						case rs256Purpose:
							body, mustSucceed = rsInput(rsKid), true
						}
						call = func() error { _, err := n.client(actor).Sign(ctx, signReq(p, body)); return err }
					case "public-key":
						if scope != registry.ScopeBoundary {
							continue
						}
						call = func() error {
							_, err := n.client(actor).PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: p}))
							return err
						}
						mustSucceed = enabled[p]
					case "mac":
						call = func() error {
							// A tenant's first pairwise key is made under a grant that names the operation mac (REQ-KEYS-260).
							g := grantFor(actor, tenant, "mac") // before the client: making a grant speaks as policy
							_, err := n.client(actor).Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: p, Tenant: tenant, Label: "l", Input: []byte("i"), Epoch: epochOf(p), Grant: g}))
							return err
						}
						mustSucceed = true
					case "certify":
						// certify is the rule of TokenKey and PutCertificate, on the intermediate only; TokenKey answers whoever the
						// files give it and refuses the rest by rule.
						if scope != registry.ScopeBoundary || p != "x509-intermediate" {
							continue
						}
						call = func() error {
							_, err := n.client(actor).TokenKey(ctx, connect.NewRequest(&keyv2alpha1.TokenKeyRequest{}))
							return err
						}
						mustSucceed = true
					default:
						continue // wrap and unwrap are no call of KeyService
					}
					// A purpose is called in the scope its calls have: cookie, grant and mac the boundary's, evidence, chain,
					// pseudonym and pairwise a tenant's; data either. A cell in another scope is no call of that scope.
					if (op == "seal" || op == "open" || op == "mac") && !scopeFitsPurpose(p, scope) {
						continue
					}
					if p == "grant" && (op == "seal" || op == "open") {
						continue // the grant key is used by SealGrant and OpenGrant, below
					}
					cell := fmt.Sprintf("%s %s %s/%s", actor, op, scope, p)
					before := n.audit.count(ActionRefuse)
					err := call()
					if !docs.allows(actor, scope, p, op) {
						refusedCells++
						if err == nil {
							t.Errorf("%s: the files do not give it and key@ answered", cell)
							continue
						}
						// A purpose or an address the call does not take is refused first, as invalid_argument; otherwise by rule.
						if !refusedByRule(err) && connect.CodeOf(err) != connect.CodeInvalidArgument {
							t.Errorf("%s: refused as %v, want the rule or an invalid argument", cell, err)
						}
						if refusedByRule(err) && n.audit.count(ActionRefuse) != before+1 {
							t.Errorf("%s: %d audit facts for the refusal by rule, want 1", cell, n.audit.count(ActionRefuse)-before)
						}
						continue
					}
					switch {
					case err == nil:
						succeeded++
					case mustSucceed:
						t.Errorf("%s: the files give it, the call is valid, and key@ refused it: %v", cell, err)
					case refusedByRule(err):
						t.Errorf("%s: the files give it and key@ refused it by rule: %v", cell, err)
					default:
						// Reached the check after the rule: a purpose the plan does not enable, a content check, or an Open of
						// a purpose with no sealed kind.
						if r := reasonOf(err); r != reasonPurpose && r != reasonContent && r != reasonOpen && r != reasonAddress && r != reasonIntermediate {
							t.Errorf("%s: refused after the rule for %q: %v", cell, r, err)
						}
						reached++
					}
				}
			}
		}
	}
	// SealGrant and OpenGrant read the rule on the grant key.
	for _, actor := range callers {
		_, serr := n.client(actor).SealGrant(ctx, connect.NewRequest(&keyv2alpha1.SealGrantRequest{}))
		_, oerr := n.client(actor).OpenGrant(ctx, connect.NewRequest(&keyv2alpha1.OpenGrantRequest{}))
		if want := docs.allows(actor, registry.ScopeBoundary, "grant", "seal"); want == refusedByRule(serr) {
			t.Errorf("%s SealGrant: the files give it = %v, refused by rule = %v", actor, want, refusedByRule(serr))
		}
		if want := docs.allows(actor, registry.ScopeBoundary, "grant", "open"); want == refusedByRule(oerr) {
			t.Errorf("%s OpenGrant: the files give it = %v, refused by rule = %v", actor, want, refusedByRule(oerr))
		}
	}
	t.Logf("%d cells given by the files; key@ called %d refused cells, %d succeeded and %d reached the check after the rule", expectedAllowed, refusedCells, succeeded, reached)
	// The counts are the registry's today. A change to the files changes them, in the same pull request: the numbers are
	// the sweep's evidence that it called what it says, and not a smaller set.
	if expectedAllowed != 85 || succeeded != 63 || reached != 15 || refusedCells != 3855 {
		t.Fatalf("cells given by the files %d (want 85), succeeded %d (63), reached the check %d (15), refused %d (3855): "+
			"if the registry changed on purpose, change these numbers with it", expectedAllowed, succeeded, reached, refusedCells)
	}
}

// scopeFitsPurpose says whether a Seal, Open or Mac of the purpose is a call in the scope: cookie, grant and mac are the
// boundary's, evidence, chain, credential, pseudonym and pairwise a tenant's, data either, and a name that is none either.
func scopeFitsPurpose(purpose, scope string) bool {
	switch purpose {
	case "cookie", "grant", "mac":
		return scope == registry.ScopeBoundary
	case "evidence", "chain", "credential", "pseudonym", "pairwise":
		return scope == registry.ScopeTenant
	}
	return true
}

// epochOf is a valid epoch for a pseudonym and none for the other Mac purposes.
func epochOf(purpose string) string {
	if purpose == "pseudonym" {
		return "202611"
	}
	return ""
}
