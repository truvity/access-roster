//go:build sluis_test

package keyd

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
)

// verifies: REQ-KEYS-260, REQ-KEYS-263
// A name that is no tenant makes no key, however it is asked for (REQ-KEYS-260). The calls are the ones that used to make
// a key on their own: Seal under chain, which is checked by rule, and Mac under pairwise; data and evidence refuse
// before the key lookup, and are in the sweep for the same reason. The tenant is a name that no config knows.
func TestANameThatIsNoTenantGetsNoKey(t *testing.T) {
	e := newTestEnv(t, "development")
	rec := &recorder{}
	n := e.startedNode(nodeOpts{audit: rec})
	const ghost = "ghost-corp"
	good := time.Minute
	type call struct {
		name string
		do   func(grant []byte) error
		op   string
	}
	seal := func(actor, purpose, kind string) func([]byte) error {
		return func(grant []byte) error {
			_, err := seal1(n.client(actor), purpose, kind, ghost, vecID, []byte("x"), grant)
			return err
		}
	}
	mac := func(grant []byte) error {
		_, err := n.client("session").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{
			Purpose: "pairwise", Tenant: ghost, Label: "l", Input: []byte("x"), Grant: grant,
		}))
		return err
	}
	calls := []call{
		{"chain", seal("session", "chain", "session-chain"), "seal"},
		{"credential", seal("session", "credential", "staff-passkey"), "seal"},
		{"pairwise", mac, "mac"},
		{"data", seal("session", "data", "person"), "seal"},
		{"evidence", seal("writer", "evidence", "usage"), "seal"},
	}
	holder := map[string]string{"chain": "session", "credential": "session", "pairwise": "session", "data": "session", "evidence": "writer"}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			// Grants are made first: the identity of a client is read when it connects.
			other := n.grant(holder[c.name], []string{"acme"}, []string{c.op}, good)
			wrongHolder := n.grant("exchange", []string{ghost}, []string{c.op}, good)
			wrongOp := n.grant(holder[c.name], []string{ghost}, []string{map[string]string{"seal": "open", "mac": "seal"}[c.op]}, good)
			expired := n.grant(holder[c.name], []string{ghost}, []string{c.op}, 5*time.Second)
			e.clock.advance(6 * time.Second)
			before, wrapsBefore := rec.count(ActionRefuse), e.store.wrapCount()
			for name, grant := range map[string][]byte{
				"no grant": nil, "another tenant's": other, "another holder's": wrongHolder, "another operation's": wrongOp, "expired": expired,
				"garbage": []byte("not a grant at all, but long enough to hold a header ............"),
			} {
				err := c.do(grant)
				wantRefusalNamed(t, c.name+" with "+name, err, connect.CodePermissionDenied, "grant")
			}
			// One refusal each, and nothing made: the count of facts is bounded by the count of calls.
			if got := rec.count(ActionRefuse) - before; got != 6 {
				t.Errorf("%d refusals for 6 calls, want one each", got)
			}
			if got := e.store.wrapCount(); got != wrapsBefore {
				t.Errorf("the wraps went from %d to %d: a name that is no tenant got a key", wrapsBefore, got)
			}
			if got := wrapPurposes(t, e)[ghost]; len(got) != 0 {
				t.Errorf("the name has keys %v", got)
			}
		})
	}
	for _, ev := range rec.all() {
		if ev.Tenant == ghost && (ev.Action == ActionDataKeyMake || ev.Action == ActionWrapWrite) {
			t.Errorf("a %s fact for a name that is no tenant", ev.Action)
		}
	}
}

// verifies: REQ-KEYS-260
// Under a grant that names the tenant, for the caller and the operation, the first key is made. Once it exists, chain
// and pairwise are used by rule alone, as before: a refresh holds no grant to seal with, and opening needs none.
func TestAGrantThatNamesTheTenantMakesItsFirstKeyAndAnExistingKeyNeedsNone(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	const tenant = "acme"
	sealGrant := n.grant("session", []string{tenant}, []string{"seal"}, time.Minute)
	macGrant := n.grant("session", []string{tenant}, []string{"mac"}, time.Minute)
	if got := wrapPurposes(t, e)[tenant]; len(got) != 0 {
		t.Fatalf("keys before any call: %v", got)
	}
	env, err := seal1(n.client("session"), "chain", "session-chain", tenant, vecID, []byte("facts"), sealGrant)
	if err != nil {
		t.Fatalf("the first chain key under a grant: %v", err)
	}
	c := n.client("session")
	m1, err := c.Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pairwise", Tenant: tenant, Label: "l", Input: []byte("x"), Grant: macGrant}))
	if err != nil {
		t.Fatalf("the first pairwise key under a grant: %v", err)
	}
	if got := wrapPurposes(t, e)[tenant]; len(got) != 2 {
		t.Fatalf("keys after two calls = %v, want chain and pairwise", got)
	}
	// With no grant at all: the key exists, so seal, open and mac go on by rule.
	if _, err := seal1(n.client("session"), "chain", "session-chain", tenant, vecID, []byte("more"), nil); err != nil {
		t.Errorf("a seal under an existing chain key with no grant: %v", err)
	}
	if pt, err := open1(n.client("exchange"), "chain", "session-chain", tenant, vecID, env, nil); err != nil || string(pt) != "facts" {
		t.Errorf("exchange opens the chain: %q, %v", pt, err)
	}
	m2, err := n.client("session").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pairwise", Tenant: tenant, Label: "l", Input: []byte("x")}))
	if err != nil || string(m1.Msg.GetMac()) != string(m2.Msg.GetMac()) {
		t.Errorf("pairwise with no grant under an existing key: %v", err)
	}
	// A node that comes up with the wraps in the store, as after a restart or a restore of the store with its wraps,
	// finds the keys and needs no grant either.
	n.srv.cache.wipeAll()
	if _, err := seal1(n.client("session"), "chain", "session-chain", tenant, vecID, []byte("again"), nil); err != nil {
		t.Errorf("a seal after the cache was dropped: %v", err)
	}
	// The pseudonym key is the one exception, and is stated as one: no grant is asked for it.
	if _, err := n.client("reader").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pseudonym", Tenant: "other-co", Label: "l", Input: []byte("x"), Epoch: "202611"})); err != nil {
		t.Errorf("a pseudonym with no grant: %v", err)
	}
}

// A call that cannot make a key does not wait for the lock that serializes the makers: while a cold load holds it, a call
// that names a tenant with no key and has no grant is refused at once, so a flood of such calls cannot hold up the load of
// a key for anyone else.
//
// verifies: REQ-KEYS-260
func TestARefusedFirstKeyDoesNotWaitForTheLoadOfAnotherKey(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	n.srv.loadMu.Lock() // a slow cold load is in progress
	defer n.srv.loadMu.Unlock()
	done := make(chan error, 2)
	go func() {
		_, err := seal1(n.client("session"), "chain", "session-chain", "ghost-corp", vecID, []byte("x"), nil)
		done <- err
	}()
	go func() {
		_, err := n.client("session").Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "pairwise", Tenant: "ghost-corp", Label: "l", Input: []byte("x")}))
		done <- err
	}()
	for range 2 {
		select {
		case err := <-done:
			wantRefusalNamed(t, "a refused first key", err, connect.CodePermissionDenied, "grant")
		case <-time.After(5 * time.Second):
			t.Fatal("a call that cannot make a key waited for the lock of the makers")
		}
	}
}

// An Open for a tenant that has no key, under a purpose that is checked by rule alone (chain, credential), does not wait for
// the lock that serializes the makers either: it is refused at once as any open that does not open, so a flood of such opens
// cannot hold up the load of a key for anyone else (a cold open that has no key to find took loadMu before). The envelope is
// one that opens elsewhere, so the call reaches the key lookup.
//
// verifies: REQ-KEYS-260, REQ-KEYS-263
func TestAnOpenForATenantWithNoKeyDoesNotWaitForTheMakers(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	mk := func(actor, purpose, kind string) []byte {
		g := n.grant(actor, []string{"acme"}, []string{"seal"}, time.Minute)
		env, err := seal1(n.client(actor), purpose, kind, "acme", vecID, []byte("x"), g)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	chain, credential := mk("session", "chain", "session-chain"), mk("session", "credential", "staff-passkey")
	type open struct {
		actor, purpose, kind string
		env                  []byte
	}
	opens := []open{
		{"session", "chain", "session-chain", chain}, {"exchange", "chain", "session-chain", chain}, {"session", "credential", "staff-passkey", credential},
	}
	clients := make([]keyv2alpha1connect.KeyServiceClient, len(opens)) // made first: the identity of a client is read when it connects
	for i, o := range opens {
		clients[i] = n.client(o.actor)
		if _, err := open1(clients[i], o.purpose, o.kind, "acme", vecID, o.env, nil); err != nil {
			t.Fatalf("%s opens its own: %v", o.actor, err)
		}
	}
	n.srv.loadMu.Lock() // a slow cold load is in progress
	defer n.srv.loadMu.Unlock()
	done := make(chan error, len(opens))
	for i, o := range opens {
		go func() {
			_, err := open1(clients[i], o.purpose, o.kind, "ghost-corp", vecID, o.env, nil)
			done <- err
		}()
	}
	for range opens {
		select {
		case err := <-done:
			wantRefusal(t, err, connect.CodePermissionDenied, "open")
		case <-time.After(5 * time.Second):
			t.Fatal("an open for a tenant with no key waited for the lock of the makers")
		}
	}
}

// A burst of cold opens of one key is one call to the driver, not one for each open: after a restart the first requests of a
// board ask for the same cookie, chain or credential key at once, and each unwrap is an ECDH on a card.
//
// verifies: REQ-KEYS-260, REQ-KEYS-263
func TestAColdBurstOfOpensOfOneKeyIsOneCallToTheDriver(t *testing.T) {
	const burst = 32
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	// Grants are made first: the identity of a client is read when it connects.
	chainGrant := n.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	credentialGrant := n.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	chain, err := seal1(n.client("session"), "chain", "session-chain", "acme", vecID, []byte("facts"), chainGrant)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := seal1(n.client("session"), "credential", "staff-passkey", "acme", vecID, []byte("key"), credentialGrant)
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]keyv2alpha1connect.KeyServiceClient, 0, burst)
	for range burst {
		c := n.client("session") // connected first: the identity of a client is read when it connects
		if _, err := open1(c, "chain", "session-chain", "acme", vecID, chain, nil); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	run := func(purpose, kind string, env []byte, want string) {
		t.Helper()
		n.srv.cache.wipeAll() // a restart
		before := n.driver.ecdhs.Load()
		n.driver.ecdhHold.Store(int64(100 * time.Millisecond))
		defer n.driver.ecdhHold.Store(0)
		done := make(chan error, burst)
		for _, c := range clients {
			go func() {
				pt, err := open1(c, purpose, kind, "acme", vecID, env, nil)
				if err == nil && string(pt) != want {
					err = errors.New("a wrong plaintext")
				}
				done <- err
			}()
		}
		for range burst {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s open: %v", purpose, err)
				}
			case <-time.After(20 * time.Second):
				t.Fatalf("%s opens did not end", purpose)
			}
		}
		if got := n.driver.ecdhs.Load() - before; got != 1 {
			t.Errorf("%d opens of the %s key cold made %d calls to the driver, want 1", burst, purpose, got)
		}
	}
	run("chain", "session-chain", chain, "facts")
	run("credential", "staff-passkey", credential, "key")
}

// The flight of an open belongs to the opens that wait for it, not to the one that started it, and it ends whatever happens
// to it.
func flightSetup(t *testing.T) (*node, keyRef) {
	t.Helper()
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	g := n.grant("session", []string{"acme"}, []string{"seal"}, time.Minute)
	if _, err := seal1(n.client("session"), "credential", "staff-passkey", "acme", vecID, []byte("k"), g); err != nil {
		t.Fatal(err)
	}
	n.srv.cache.wipeAll()
	return n, keyRef{"acme", "credential", 1}
}

func flightsLeft(n *node) int {
	n.srv.flightMu.Lock()
	defer n.srv.flightMu.Unlock()
	return len(n.srv.flights)
}

func use(ctx context.Context, n *node, ref keyRef) error {
	return n.srv.withExistingKey(ctx, ref, func([]byte) error { return nil })
}

// A caller that goes away while it started the flight does not fail the others: one leader and four waiters, the leader
// cancelled in the driver call, and the waiters all get the key. The leader itself is released at once.
//
// verifies: REQ-KEYS-263
func TestAFlightSurvivesTheCallerThatStartedIt(t *testing.T) {
	n, ref := flightSetup(t)
	n.driver.ecdhHold.Store(int64(400 * time.Millisecond))
	before := n.driver.ecdhs.Load()
	lctx, cancel := context.WithCancel(context.Background())
	lres := make(chan error, 1)
	go func() { lres <- use(lctx, n, ref) }()
	for n.driver.ecdhs.Load() == before { // the leader is in the driver call
		time.Sleep(5 * time.Millisecond)
	}
	wres := make(chan error, 4)
	for range 4 {
		go func() { wres <- use(context.Background(), n, ref) }()
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-lres:
		if err == nil {
			t.Error("the cancelled leader was served: it should have been released")
		}
	case <-time.After(300 * time.Millisecond):
		t.Error("the cancelled leader waited for the flight")
	}
	for i := range 4 {
		select {
		case err := <-wres:
			if err != nil {
				t.Errorf("waiter %d failed with the leader: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %d hung", i)
		}
	}
	if got := n.driver.ecdhs.Load() - before; got != 1 {
		t.Errorf("%d calls to the driver, want 1", got)
	}
	if left := flightsLeft(n); left != 0 {
		t.Errorf("%d flights left", left)
	}
}

// A real error of the open reaches every caller of the flight, the flight leaves, and the next call tries again.
//
// verifies: REQ-KEYS-263
func TestAFlightThatFailsFailsItsWaitersAndLeaves(t *testing.T) {
	n, ref := flightSetup(t)
	n.driver.ecdhHold.Store(int64(300 * time.Millisecond))
	n.driver.mu.Lock()
	n.driver.locked = true // the card is locked: the driver refuses
	n.driver.mu.Unlock()
	res := make(chan error, 5)
	for range 5 {
		go func() { res <- use(context.Background(), n, ref) }()
	}
	for range 5 {
		select {
		case err := <-res:
			if err == nil {
				t.Error("a call was served by a locked card")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a call hung")
		}
	}
	if left := flightsLeft(n); left != 0 {
		t.Errorf("%d flights left", left)
	}
	n.driver.mu.Lock()
	n.driver.locked = false
	n.driver.mu.Unlock()
	if err := use(context.Background(), n, ref); err != nil {
		t.Errorf("the next call, with the card unlocked: %v", err)
	}
}

// A stuck driver ends the flight with the timeout of the open, not the callers one by one, and another key is not held up by
// it: a tenant with no key is refused at once while the first key's flight is still stuck.
//
// verifies: REQ-KEYS-263
func TestAStuckDriverEndsTheFlightAndDoesNotHoldAnotherKey(t *testing.T) {
	n, ref := flightSetup(t)
	n.srv.openTimeoutOverride = 300 * time.Millisecond
	n.driver.ecdhHold.Store(int64(3 * time.Second))
	res := make(chan error, 3)
	t0 := time.Now()
	for range 3 {
		go func() { res <- use(context.Background(), n, ref) }()
	}
	time.Sleep(100 * time.Millisecond) // the flight is stuck in the driver
	t1 := time.Now()
	if err := use(context.Background(), n, keyRef{"ghost-corp", "credential", 1}); err == nil || time.Since(t1) > 150*time.Millisecond {
		t.Errorf("another key was held up by the stuck flight: %v after %v", err, time.Since(t1))
	}
	for range 3 {
		select {
		case err := <-res:
			if err == nil {
				t.Error("a call was served by a stuck driver")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a call waited for a stuck driver past the timeout of the open")
		}
	}
	if d := time.Since(t0); d > 1500*time.Millisecond {
		t.Errorf("the flight took %v, want about 300ms", d)
	}
	if left := flightsLeft(n); left != 0 {
		t.Errorf("%d flights left", left)
	}
}

// A panic in the open ends the flight with an error: it leaves the map and wakes the waiters, and the next call is not left
// waiting for a flight that is gone.
//
// verifies: REQ-KEYS-263
func TestAPanicInTheOpenEndsTheFlight(t *testing.T) {
	n, ref := flightSetup(t)
	n.srv.openFn = func(context.Context, keyRef) ([]byte, error) {
		time.Sleep(100 * time.Millisecond)
		panic("a bug in the open")
	}
	res := make(chan error, 3)
	for range 3 {
		go func() { res <- use(context.Background(), n, ref) }()
	}
	for range 3 {
		select {
		case err := <-res:
			if err == nil {
				t.Error("a call was served by an open that panicked")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a call hung after a panic in the open")
		}
	}
	if left := flightsLeft(n); left != 0 {
		t.Errorf("%d flights left", left)
	}
	n.srv.openFn = nil
	if err := use(context.Background(), n, ref); err != nil {
		t.Errorf("the next call after the panic: %v", err)
	}
}
