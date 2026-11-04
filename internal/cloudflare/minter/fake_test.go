//nolint:lll // messages and fixtures are prose and one-line tables
package minter_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/sluis/internal/audit/audittest"
	"github.com/truvity/sluis/internal/cloudflare"
	"github.com/truvity/sluis/internal/cloudflare/minter"
	"github.com/truvity/sluis/internal/config"
	"github.com/truvity/sluis/internal/secretstore"
	"github.com/truvity/sluis/storage/state"
	"github.com/truvity/sluis/storage/state/memory"
)

// fakeAPI is one Cloudflare account in memory.
type fakeAPI struct {
	mu     sync.Mutex
	tokens map[string]cloudflare.Token
	groups map[string]string
	next   int
	now    func() time.Time

	creates, deletes, lists int
	createErr               error
	deleteErr               error
	listErr                 error
	gotMinter               string
}

func newFake(now func() time.Time) *fakeAPI {
	return &fakeAPI{tokens: map[string]cloudflare.Token{}, now: now, groups: map[string]string{
		"g-dns": "DNS Write", "g-r2": "Workers R2 Storage Write", "g-tok": "Account API Tokens Write", "g-bill": "Billing Read",
	}}
}

func (f *fakeAPI) put(t cloudflare.Token) { f.mu.Lock(); f.tokens[t.ID] = t; f.mu.Unlock() }

func (f *fakeAPI) GetToken(_ context.Context, id string) (cloudflare.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[id]
	if !ok {
		return cloudflare.Token{}, cloudflare.ErrNotFound
	}
	// Cloudflare answers a GET for an expired token, as `expired`.
	if t.Status != cloudflare.StatusDisabled && !t.ExpiresOn.IsZero() && !t.ExpiresOn.After(f.now()) {
		t.Status = cloudflare.StatusExpired
	}
	return t, nil
}

func (f *fakeAPI) CreateToken(_ context.Context, in cloudflare.NewToken) (cloudflare.Created, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.createErr != nil {
		return cloudflare.Created{}, f.createErr
	}
	f.next++
	id := fmt.Sprintf("tok%03d", f.next)
	f.tokens[id] = cloudflare.Token{ID: id, Name: in.Name, Status: cloudflare.StatusActive, ExpiresOn: in.ExpiresOn, Policies: in.Policies, Condition: in.Condition}
	return cloudflare.Created{ID: id, Name: in.Name, ExpiresOn: in.ExpiresOn, Value: "value-" + id}, nil
}

func (f *fakeAPI) DeleteToken(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.tokens[id]; !ok {
		return cloudflare.ErrNotFound
	}
	delete(f.tokens, id)
	return nil
}

func (f *fakeAPI) ListTokens(context.Context) ([]cloudflare.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []cloudflare.Token
	for _, t := range f.tokens {
		// An expired token is hidden from the list (checked against a live account).
		if !t.ExpiresOn.IsZero() && !t.ExpiresOn.After(f.now()) {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeAPI) PermissionGroups(context.Context) (map[string]string, error) {
	return f.groups, nil
}

func (f *fakeAPI) names() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for id, t := range f.tokens {
		out[id] = t.Name
	}
	return out
}

const (
	dnsProto = "proto-dns-0001"
	r2Proto  = "proto-r2-00001"
	acct     = "0123456789abcdef0123456789abcdef"
)

// policies as Cloudflare answers them: with generated ids and names.
func policiesJSON(group string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`[{"id":"pol-1","effect":"allow","resources":{"com.cloudflare.api.account.zone.z1":"*"},"permission_groups":[{"id":%q,"name":"ignored","meta":{"k":"v"}}]}]`, group))
}

type env struct {
	t   *testing.T
	api *fakeAPI
	m   *minter.Minter
	rec *audittest.Recorder
	// v5 is the secrets, on layout v5.
	v5     *secretstore.StoresV5
	v5Root state.Store
	clock  *time.Time
	// cfg is what m was made of, for another replica over the same store.
	cfg minter.Config
	// faults fail the reads or the writes of the records of minted tokens.
	faults recordFaults
}

// recordFaults switch failures of the records of minted tokens on and off.
type recordFaults struct{ get, put atomic.Bool }

var errRecordStore = errors.New("the store is down")

// faultStore is a store whose records of minted tokens can fail.
type faultStore struct {
	state.Store
	f *recordFaults
}

func isRecord(key string) bool { return strings.HasPrefix(key, "minted/") }

func (s faultStore) Get(ctx context.Context, key string) (state.Item, error) {
	if isRecord(key) && s.f.get.Load() {
		return state.Item{}, errRecordStore
	}
	return s.Store.Get(ctx, key)
}

func (s faultStore) Put(ctx context.Context, key string, value []byte, ifRev state.Rev) (state.Rev, error) {
	if isRecord(key) && s.f.put.Load() {
		return "", errRecordStore
	}
	return s.Store.Put(ctx, key, value, ifRev)
}

func (s faultStore) Child(prefix string, opts ...state.Option) state.Store {
	return faultStore{Store: s.Store.Child(prefix, opts...), f: s.f}
}

// replica is another minter over the same store and account: another Lambda
// container or Kubernetes replica, with nothing in memory of its own.
func (e *env) replica() *minter.Minter {
	e.t.Helper()
	m, err := minter.New(e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

// listCount is how many times the account's tokens were listed.
func (e *env) listCount() int {
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	return e.api.lists
}

// external is the preset's stored credential.
func (e *env) external(preset string) state.Value[secretstore.Cloudflarev1] {
	return e.v5.CloudflareExternal().Preset(preset)
}

// minterStore is the store the account's minter credential is kept in.
func (e *env) minterStore() state.Store {
	return e.v5Root.Child("internal").Child("cloudflare/main")
}

// secretsConfig puts the suite's secrets in a minter configuration.
func (e *env) secretsConfig(c *minter.Config) {
	c.V5 = e.v5
}

func (e *env) advance(d time.Duration) { *e.clock = e.clock.Add(d) }

func setup(t *testing.T, grants ...config.CloudflareGrant) *env {
	return setupPaused(t, nil, grants...)
}

// setupPaused is setup with the maintenance gate the module reads.
func setupPaused(t *testing.T, pause minter.Pause, grants ...config.CloudflareGrant) *env {
	t.Helper()
	return setupWith(t, pause, nil, grants...)
}

// setupWith is setupPaused with a change to the declared Cloudflare section
// before the minter is made.
func setupWith(t *testing.T, pause minter.Pause, change func(*config.Cloudflare), grants ...config.CloudflareGrant) *env {
	t.Helper()
	clock := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	e := &env{t: t, clock: &clock, rec: audittest.New(t)}
	now := func() time.Time { return clock }
	e.api = newFake(now)
	e.v5Root = faultStore{Store: memory.New(), f: &e.faults}
	e.v5 = secretstore.FromStoreV5(e.v5Root, "")
	minterAt := e.v5.Cloudflare().MinterAt
	cf := &config.Cloudflare{
		Accounts: map[string]config.CloudflareAccount{"main": {ID: acct, Minter: "internal/cloudflare/main/minter"}},
		Presets: map[string]config.CloudflarePreset{
			"dns":      {Account: "main", Prototype: dnsProto, Description: "DNS", Lifetime: config.Duration(15 * time.Minute), Rotation: config.Duration(5 * time.Minute)},
			"dns-edge": {Account: "main", Prototype: dnsProto, Description: "DNS edge", Lifetime: config.Duration(15 * time.Minute), Rotation: config.Duration(5 * time.Minute)},
			"r2": {Account: "main", Prototype: r2Proto, Description: "R2", Lifetime: config.Duration(15 * time.Minute), Rotation: config.Duration(5 * time.Minute),
				Endpoint: "https://" + acct + ".r2.cloudflarestorage.com"},
		},
	}
	if change != nil {
		change(cf)
	}
	mv, err := minterAt("internal/cloudflare/main/minter")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mv.Put(context.Background(), secretstore.CloudflareMinterv1{Token: "minter-secret"}, ""); err != nil {
		t.Fatal(err)
	}
	e.api.put(cloudflare.Token{ID: dnsProto, Name: "proto dns", Status: cloudflare.StatusDisabled, Policies: policiesJSON("g-dns"),
		Condition: json.RawMessage(`{"request_ip":{"in":["203.0.113.0/24"],"not_in":[]}}`)})
	e.api.put(cloudflare.Token{ID: r2Proto, Name: "proto r2", Status: cloudflare.StatusDisabled, Policies: policiesJSON("g-r2")})
	mc := minter.Config{
		Instance: "example", Cloudflare: cf, Grants: &config.PolicyCloudflare{Grants: grants},
		Dial: func(_ context.Context, id, token string) (minter.API, error) {
			if id != acct {
				return nil, fmt.Errorf("wrong account %s", id)
			}
			e.api.mu.Lock()
			e.api.gotMinter = token
			e.api.mu.Unlock()
			return e.api, nil
		},
		Audit: e.rec, Now: now, Propagation: -1, PublishAfter: -1, Maintenance: pause,
	}
	e.secretsConfig(&mc)
	e.cfg = mc
	e.m, err = minter.New(mc)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
