//go:build sluis_test

package keyd

import (
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// wrapPurposes returns, for each tenant ("" for the boundary), the sorted distinct purposes that have a wrap in the store.
func wrapPurposes(t *testing.T, e *testEnv) map[string][]string {
	t.Helper()
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	set := map[string]map[string]bool{}
	for _, it := range e.store.items {
		if it.GetAddress().GetKind() != "data-key-wrap" {
			continue
		}
		w := &keyv2alpha1.DataKeyWrap{}
		if err := proto.Unmarshal(it.GetValue(), w); err != nil {
			t.Fatal(err)
		}
		tn := it.GetAddress().GetTenant()
		if set[tn] == nil {
			set[tn] = map[string]bool{}
		}
		set[tn][w.GetPurpose()] = true
	}
	out := map[string][]string{}
	for tn, ps := range set {
		for p := range ps {
			out[tn] = append(out[tn], p)
		}
		sort.Strings(out[tn])
	}
	return out
}

// tenantUse is one call that makes the data key of a purpose of a tenant, by the actor that holds the rule for it.
type tenantUse struct {
	purpose string
	do      func(t *testing.T, n *node, tenant string)
}

func macCall(actor, purpose, epoch string) func(*testing.T, *node, string) {
	return func(t *testing.T, n *node, tenant string) {
		t.Helper()
		// A tenant's first pairwise key is made under a grant that names the tenant.
		var grant []byte
		if tenant != "" && purpose == "pairwise" {
			grant = n.grant(actor, []string{tenant}, []string{"mac"}, time.Minute)
		}
		_, err := n.client(actor).Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: purpose, Tenant: tenant, Label: "l", Input: []byte("x"), Epoch: epoch, Grant: grant}))
		if err != nil {
			t.Fatalf("Mac %s for %q: %v", purpose, tenant, err)
		}
	}
}

func sealCall(actor, purpose, kind string) func(*testing.T, *node, string) {
	return func(t *testing.T, n *node, tenant string) {
		t.Helper()
		var grant []byte
		if tenant != "" && (purpose == "data" || purpose == "evidence" || purpose == "chain") {
			grant = n.grant(actor, []string{tenant}, []string{"seal"}, time.Minute)
		}
		if _, err := seal1(n.client(actor), purpose, kind, tenant, vecID, []byte("x"), grant); err != nil {
			t.Fatalf("Seal %s for %q: %v", purpose, tenant, err)
		}
	}
}

// The six purposes of a tenant, each by an actor that holds its rule.
var tenantUses = []tenantUse{
	{"pairwise", macCall("session", "pairwise", "")},
	{"chain", sealCall("session", "chain", "session-chain")},
	{"credential", sealCall("session", "credential", "staff-passkey")},
	{"pseudonym", macCall("reader", "pseudonym", "202611")},
	{"data", sealCall("session", "data", "person")},
	{"evidence", sealCall("writer", "evidence", "usage")},
}

// The four purposes of a boundary, each by an actor that holds its rule. A boundary's grant key is made by the first
// SealGrant, which the grants of the tenant calls above already make; it is listed so that the first call is seen.
var boundaryUses = []tenantUse{
	{"cookie", sealCall("session", "cookie", "cookie")},
	{"mac", macCall("session", "mac", "")},
	{"data", sealCall("exchange", "data", "person")},
}

// useAll makes every data key of a new tenant, and of the boundary when boundary is set, in the order of the tables above.
func useAll(t *testing.T, n *node, tenant string, boundary bool) {
	t.Helper()
	for _, u := range tenantUses {
		u.do(t, n, tenant)
	}
	if boundary {
		for _, u := range boundaryUses {
			u.do(t, n, "")
		}
	}
}

// verifies: REQ-KEYS-035
// A tenant has exactly six data keys, data, pseudonym, pairwise, evidence, chain and credential, and a boundary four of its own:
// grant, cookie, mac and data. The keys are made on the first use (ADR 0006), so the test uses a new tenant and counts
// the purposes that have a wrap after each call: each call makes the one key it needs and no other, and when all are
// used the tenant has six and the boundary four. Then every purpose name key@ could be asked for, by every actor
// that may call it, for the tenant and for the boundary, with and without a grant, is tried; the ones that are
// refused make no key, so no sixth purpose appears. The count is of purposes: the pseudonym key has a generation for
// each month (a second epoch is a second wrap of the same purpose), which the test shows and does not count again.
func TestATenantHasSixDataKeysAndABoundaryFour(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	if got := wrapPurposes(t, e); len(got) != 0 {
		t.Fatalf("wraps before any use = %v: a key is made before it is needed", got)
	}
	const tenant = "initech"
	var made []string
	for _, u := range tenantUses {
		u.do(t, n, tenant)
		made = append(made, u.purpose)
		got := wrapPurposes(t, e)[tenant]
		want := slices.Clone(made)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Fatalf("after %s the tenant has keys %v, want %v", u.purpose, got, want)
		}
	}
	// A tenant call for data and evidence made the boundary's grant key too (policy sealed the grants): the boundary
	// has that one so far.
	if got := wrapPurposes(t, e)[""]; !slices.Equal(got, []string{"grant"}) {
		t.Fatalf("the boundary has keys %v after the tenant's calls, want grant only", got)
	}
	for _, u := range boundaryUses {
		u.do(t, n, "")
	}
	got := wrapPurposes(t, e)
	if want := []string{"chain", "credential", "data", "evidence", "pairwise", "pseudonym"}; !slices.Equal(got[tenant], want) {
		t.Fatalf("the tenant's keys = %v, want exactly %v", got[tenant], want)
	}
	if want := []string{"cookie", "data", "grant", "mac"}; !slices.Equal(got[""], want) {
		t.Fatalf("the boundary's keys = %v, want exactly %v", got[""], want)
	}
	if len(got) != 2 {
		t.Fatalf("wraps are under %d tenants (%v), want the tenant and the boundary", len(got), got)
	}
	// A pseudonym of another month is another generation of the same purpose: the purposes stay six.
	macCall("reader", "pseudonym", "202612")(t, n, tenant)
	if got := wrapPurposes(t, e)[tenant]; len(got) != 6 {
		t.Fatalf("a second pseudonym epoch made the tenant's keys %v", got)
	}

	// Every purpose name, by every actor that can call key@, with a grant that would pass for a tenant call. The
	// calls that the rules and the address checks refuse make no key; the others are the nine above.
	candidates := []string{"data", "pseudonym", "pairwise", "evidence", "chain", "credential", "grant", "cookie", "mac", "wrapping", "token-signing", "audit-log",
		"release-signing", "x509-intermediate", "ssh-user", "ssh-host", "issuance-log", "workload-issuer", "pin-release", "archive", "recovery", "tenant", ""}
	refused, answered := 0, 0
	for _, actor := range registry.CallersOf("key") {
		for _, tn := range []string{tenant, ""} {
			grant := n.grant(actor, []string{tenant}, []string{"seal", "open", "mac"}, time.Minute)
			for _, p := range candidates {
				_, err := seal1(n.client(actor), p, "person", tn, vecID, []byte("x"), grant)
				count(err, &refused, &answered)
				_, err = n.client(actor).Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: p, Tenant: tn, Label: "l", Input: []byte("x"), Epoch: "202611"}))
				count(err, &refused, &answered)
			}
		}
	}
	if refused < 100 || answered == 0 {
		t.Fatalf("the sweep was refused %d times and answered %d: it did not sweep", refused, answered)
	}
	after := wrapPurposes(t, e)
	if want := []string{"chain", "credential", "data", "evidence", "pairwise", "pseudonym"}; !slices.Equal(after[tenant], want) {
		t.Errorf("after the sweep the tenant's keys = %v, want exactly %v", after[tenant], want)
	}
	if want := []string{"cookie", "data", "grant", "mac"}; !slices.Equal(after[""], want) {
		t.Errorf("after the sweep the boundary's keys = %v, want exactly %v", after[""], want)
	}
	if len(after) != 2 {
		t.Errorf("after the sweep wraps are under %v", after)
	}
}

func count(err error, refused, answered *int) {
	if err != nil {
		*refused++
	} else {
		*answered++
	}
}

// verifies: REQ-ISO-070
// A tenant costs the key store nothing: a new tenant gets all six of its data keys, wrapped in the store@ kind
// DataKeyWrap, and the key store (the driver) is not asked for a key of any kind and holds the same keys as before.
// The test counts both the keys the driver holds and the Ensure requests it gets, before the tenants and after three
// of them have used every one of their purposes. It proves that a tenant creates no key in the driver of this
// node; the AWS arm (a count of KMS keys before and after) is not run here, but the driver port has no call that
// makes a key for a name key@ chooses at a request, only Ensure for the purposes of the KeyPlan at the start.
func TestANewTenantCreatesNoKeyInTheKeyStore(t *testing.T) {
	e := newTestEnv(t, "development")
	n, spy := e.spiedNode("node-1")
	keysOf := func() []string {
		n.driver.mu.Lock()
		defer n.driver.mu.Unlock()
		var out []string
		for p := range n.driver.keys {
			out = append(out, p)
		}
		sort.Strings(out)
		return out
	}
	before := keysOf()
	spy.mu.Lock()
	ensuresBefore := slices.Clone(spy.ensures)
	spy.mu.Unlock()
	if want := []string{"audit-log", "token-signing", "wrapping"}; !slices.Equal(before, want) {
		t.Fatalf("the key store holds %v after the start, want the KeyPlan's three", before)
	}
	wrapsBefore := e.store.wrapCount()
	for i, tn := range []string{"initech", "globex", "umbrella"} {
		useAll(t, n, tn, i == 0)
	}
	if got := keysOf(); !slices.Equal(got, before) {
		t.Fatalf("the key store holds %v after three tenants, was %v", got, before)
	}
	spy.mu.Lock()
	ensuresAfter := slices.Clone(spy.ensures)
	spy.mu.Unlock()
	if !slices.Equal(ensuresAfter, ensuresBefore) {
		t.Fatalf("the driver was asked to Ensure %v after the tenants, %v before", ensuresAfter, ensuresBefore)
	}
	// The control: the tenants did get their keys, as wraps: 3 tenants x 6 keys + the grant key and 3 boundary keys.
	if got := e.store.wrapCount() - wrapsBefore; got != 3*6+4 {
		t.Fatalf("%d wraps made for three tenants, want %d: the tenants got no keys, so the count above says nothing", got, 3*6+4)
	}
	if n.driver.made == nil || len(n.driver.made) != len(before) {
		t.Fatalf("the driver made %d keys", len(n.driver.made))
	}
}
