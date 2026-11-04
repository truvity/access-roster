package exchanged

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// StoreDirectory is the Directory over the kinds of session, read through store@ and key@ (ADR 0017, "Directory
// outages"; kinds.yaml, where exchange is a reader of Person, PersonHold and SessionChain). It reads exactly these:
//
//   - SessionChain, by the token's `sid` in the tenant: the chain that backs the token. A chain that is gone (ended,
//     revoked, expired: they are one answer, the temp kind's item is deleted or lapses) or past its end ends the
//     exchange (REQ-EXCH-005), and the chain's client must be the token's.
//   - Person, by the chain's subject: it must exist. Only its existence is read; the item is sealed under the
//     tenant's data key and opening it needs a grant that a decision gives, which is what these facts are for.
//   - PersonHold, by the same subject: an item means the person is held (ADR 0019, "States"). Existence only.
//   - the chain's sealed facts, opened at key@ under purpose `data` at the address of the chain with no tenant (the
//     boundary's data key, which exchange already holds for its own sealed kinds, and which needs no grant): the
//     accounts, "<upstream>/<subject claim value>", that policy binds grant names to. They are sealed there by
//     session when it begins the chain.
//
// It writes nothing and holds no state: a call is the reads above.
type StoreDirectory struct {
	cfg    *Config
	chains *store.Client[*sessionv2alpha1.SessionChain]
	raw    storev2alpha1connect.StoreServiceClient
	keys   keyv2alpha1connect.KeyServiceClient
	now    func() time.Time
}

// chainSegment is the address segment of the kind SessionChain, and the kind of the address the facts are sealed at.
// The three segments are those of the registry; the constructor checks them.
const (
	segChain = "session-chain"
	segHold  = "person-hold"
	segPerso = "person"
)

// NewStoreDirectory returns the Directory over store@ and key@. now is the clock; nil means time.Now.
func NewStoreDirectory(cfg *Config, c storev2alpha1connect.StoreServiceClient, keys keyv2alpha1connect.KeyServiceClient, now func() time.Time) (*StoreDirectory, error) {
	if cfg == nil || c == nil || keys == nil {
		return nil, errors.New("exchanged: a Config, a store@ client and a key@ client are required")
	}
	for kind, want := range map[string]string{"SessionChain": segChain, "PersonHold": segHold, "Person": segPerso} {
		k, ok := registry.KindByName(kind)
		if !ok || k.Segment != want {
			return nil, fmt.Errorf("exchanged: the registry does not know the kind %s as %q", kind, want)
		}
	}
	chains, err := store.New(c, "SessionChain", func() *sessionv2alpha1.SessionChain { return &sessionv2alpha1.SessionChain{} })
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &StoreDirectory{cfg: cfg, chains: chains, raw: c, keys: keys, now: now}, nil
}

// Person implements Directory.
func (d *StoreDirectory) Person(ctx context.Context, tenant string, c *Subject) (Person, error) {
	// A token of this issuer that session signed carries the chain that backs it. One without has no person to find.
	if c.SID == "" || store.ValidateID(c.SID) != nil {
		return Person{}, ErrUnknownPerson
	}
	it, err := d.chains.Get(ctx, tenant, c.SID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return Person{}, ErrSessionEnded
	case err != nil:
		return Person{}, err
	}
	chain := it.Value
	if ends := chain.GetEndsAt(); ends == nil || !d.now().Before(ends.AsTime()) {
		return Person{}, ErrSessionEnded
	}
	// The chain belongs to one client, and so does the token. A mismatch is a token that the chain did not back.
	if chain.GetClientId() == "" || chain.GetClientId() != c.ClientID {
		return Person{}, ErrUnknownPerson
	}
	subject := chain.GetSubject()
	if store.ValidateID(subject) != nil {
		return Person{}, ErrUnknownPerson
	}

	known, err := d.exists(ctx, segPerso, tenant, subject)
	switch {
	case err != nil:
		return Person{}, err
	case !known:
		return Person{}, ErrUnknownPerson
	}
	held, err := d.exists(ctx, segHold, tenant, subject)
	if err != nil {
		return Person{}, err
	}
	state := "live"
	if held {
		state = "held"
	}

	facts, err := d.facts(ctx, c.SID, chain.GetSealedFacts())
	if err != nil {
		return Person{}, err
	}
	return Person{ID: subject, Accounts: facts.GetAccounts(), State: state, Org: tenant}, nil
}

// Check says whether the directory is bound: store@ answers a read of the chain kind, and exchange is allowed to make
// it. An id that cannot exist is "not found" for a reader and "permission denied" for one the rule of the kind does not
// name.
func (d *StoreDirectory) Check(ctx context.Context) error {
	b, err := d.cfg.Boundary(ctx)
	if err != nil {
		return err
	}
	t, err := TenantOf(b)
	if err != nil {
		return err
	}
	// A valid id that no chain has: 26 characters of the id alphabet.
	_, err = d.chains.Get(ctx, t.ID, "aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err == nil || errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// exists says whether an item of a sealed kind exists, without opening it: store@ checks the envelope's header and
// hands it over, and the directory only needs to know that it is there.
func (d *StoreDirectory) exists(ctx context.Context, segment, tenant, id string) (bool, error) {
	_, err := d.raw.Get(ctx, connect.NewRequest(&storev2alpha1.GetRequest{Address: &typev2alpha1.Address{Kind: segment, Tenant: tenant, Id: id}}))
	switch {
	case err == nil:
		return true, nil
	case connect.CodeOf(err) == connect.CodeNotFound:
		return false, nil
	}
	return false, fmt.Errorf("store get %s: %w", segment, err)
}

// facts opens the sealed facts of a chain. An envelope that does not open (key@ gives one answer for every cause) is a
// chain that this boundary did not make, which ends the exchange.
func (d *StoreDirectory) facts(ctx context.Context, sid string, envelope []byte) (*sessionv2alpha1.SignInFacts, error) {
	if len(envelope) == 0 {
		return nil, ErrSessionEnded
	}
	res, err := d.keys.Open(ctx, connect.NewRequest(&keyv2alpha1.OpenRequest{Items: []*keyv2alpha1.OpenItem{{
		Purpose: "data", Address: &typev2alpha1.Address{Kind: segChain, Id: sid}, Envelope: envelope,
	}}}))
	if err != nil {
		if r, ok := refusal.Reason(err); ok && r == "open" && connect.CodeOf(err) == connect.CodePermissionDenied {
			return nil, ErrSessionEnded
		}
		return nil, fmt.Errorf("key open: %w", err)
	}
	if len(res.Msg.GetPlaintexts()) != 1 {
		return nil, ErrSessionEnded
	}
	pt := res.Msg.GetPlaintexts()[0]
	defer clear(pt)
	var f sessionv2alpha1.SignInFacts
	if err := proto.Unmarshal(pt, &f); err != nil {
		return nil, ErrSessionEnded
	}
	return &f, nil
}
