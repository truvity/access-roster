package sessiond

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"

	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// sealedStore reads and writes the sealed kinds session owns (Person, UpstreamLink) and asks whether a PersonHold
// exists. The typed client of the kit refuses a sealed kind until a sealing helper exists (kits/go/store: "planned:
// sealed helper, with session (#1221)"); this is that helper for the two kinds, kept in session until the kit takes
// it. A sealed value is the envelope key@ made: store@ checks its header and never opens it.
type sealedStore struct {
	c    storev2alpha1connect.StoreServiceClient
	keys keys
}

// segment is the address segment of a kind of the registry.
func segment(kind string) (string, error) {
	k, ok := registry.KindByName(kind)
	if !ok {
		return "", fmt.Errorf("sessiond: unknown kind %q", kind)
	}
	return k.Segment, nil
}

// get reads the envelope of an item. store.ErrNotFound says there is none.
func (s sealedStore) get(ctx context.Context, kind, tenant, id string) ([]byte, error) {
	seg, err := segment(kind)
	if err != nil {
		return nil, err
	}
	if err := store.ValidateID(id); err != nil {
		return nil, err
	}
	res, err := s.c.Get(ctx, connect.NewRequest(&storev2alpha1.GetRequest{Address: &typev2alpha1.Address{Kind: seg, Tenant: tenant, Id: id}}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, fmt.Errorf("store get: %w: %w", store.ErrNotFound, err)
		}
		return nil, fmt.Errorf("store get: %w", err)
	}
	if res.Msg.GetItem() == nil {
		return nil, refusal.New(connect.CodeInternal, "schema", "item")
	}
	return res.Msg.GetItem().GetValue(), nil
}

// holdPage is how many holds one page of the listing in held carries, and holdPages how many pages it reads at most.
const (
	holdPage  = 200
	holdPages = 1000
)

// held says whether the person has a PersonHold. It lists the tenant's holds and looks for the subject, and does not
// Get the one id: a person who is not held is the usual case, store@ audits every refusal (ADR 0005), and a Get of an
// item that is not there is one, written at every sign-in, code and refresh. Holds are written by an operator for a
// person, so there are few; the listing reads every page and fails closed: a listing that cannot be read, or that does
// not end, refuses the sign-in and the refresh. It asks for a linearizable read, as the Get did, because a hold that has
// just been placed must be seen.
func (s sealedStore) held(ctx context.Context, tenant, subject string) (bool, error) {
	seg, err := segment("PersonHold")
	if err != nil {
		return false, err
	}
	if err := store.ValidateID(subject); err != nil {
		return false, err
	}
	token := ""
	for range holdPages {
		res, err := s.c.List(ctx, connect.NewRequest(&storev2alpha1.ListRequest{
			Kind: seg, Tenant: tenant, PageSize: holdPage, PageToken: token, Consistency: storev2alpha1.Consistency_LINEARIZABLE,
		}))
		if err != nil {
			return false, fmt.Errorf("store list: %w", err)
		}
		for _, it := range res.Msg.GetItems() {
			if it.GetAddress().GetId() == subject {
				return true, nil
			}
		}
		if token = res.Msg.GetNextPageToken(); token == "" {
			return false, nil
		}
	}
	return false, fmt.Errorf("store list: more than %d pages of holds", holdPages)
}

// newSealed is one item of createAll: sealed, or plain for a kind whose treatment is plain (UpstreamPin).
type newSealed struct {
	kind, id string
	value    proto.Message
	plain    bool
}

// createAll seals each value under the tenant's data key, or encodes a plain one, and creates all the items in one
// write, all or none, under the grant. If any address is taken nothing is written and the error is store.ErrExists.
func (s sealedStore) createAll(ctx context.Context, tenant string, grant []byte, items ...newSealed) error {
	ops := make([]*storev2alpha1.Operation, 0, len(items))
	for _, it := range items {
		seg, err := segment(it.kind)
		if err != nil {
			return err
		}
		if err := store.ValidateID(it.id); err != nil {
			return err
		}
		var env []byte
		if it.plain {
			env, err = proto.MarshalOptions{Deterministic: true}.Marshal(it.value)
		} else {
			env, err = s.keys.sealData(ctx, seg, tenant, it.id, it.value, grant)
		}
		if err != nil {
			return err
		}
		ops = append(ops, &storev2alpha1.Operation{
			Verb: storev2alpha1.Verb_CREATE, Address: &typev2alpha1.Address{Kind: seg, Tenant: tenant, Id: it.id}, Value: env,
		})
	}
	_, err := s.c.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{Operations: ops, Grant: grant}))
	if err == nil {
		return nil
	}
	if connect.CodeOf(err) == connect.CodeAlreadyExists {
		return fmt.Errorf("store create: %w: %w", store.ErrExists, err)
	}
	return fmt.Errorf("store create: %w", err)
}

// spendAndBegin writes, in one all-or-none batch, the conditional update that marks an AuthCode spent and the create
// of the SessionChain it begins. Both kinds are temp, so one engine takes the batch. A moved version is
// store.ErrVersion: another redemption won.
func (s *Service) spendAndBegin(ctx context.Context, tenant, codeID string, code *sessionv2alpha1.AuthCode, version uint64, sid string, chain *sessionv2alpha1.SessionChain, ttl time.Duration, grant []byte) error {
	m := proto.MarshalOptions{Deterministic: true}
	cv, err := m.Marshal(code)
	if err != nil {
		return refusal.New(connect.CodeInternal, "schema", "value")
	}
	sv, err := m.Marshal(chain)
	if err != nil {
		return refusal.New(connect.CodeInternal, "schema", "value")
	}
	_, err = s.opts.Store.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{
		Operations: []*storev2alpha1.Operation{
			{Verb: storev2alpha1.Verb_UPDATE, Address: &typev2alpha1.Address{Kind: authCodeKind, Tenant: tenant, Id: codeID}, Value: cv, IfVersion: version},
			{Verb: storev2alpha1.Verb_CREATE, Address: &typev2alpha1.Address{Kind: chainKind, Tenant: tenant, Id: sid}, Value: sv, Ttl: durationpb.New(ttl)},
		},
		Grant: grant,
	}))
	if err == nil {
		return nil
	}
	if connect.CodeOf(err) == connect.CodeAborted {
		return fmt.Errorf("store write: %w: %w", store.ErrVersion, err)
	}
	return fmt.Errorf("store write: %w", err)
}
