package sessiond

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

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

// exists says whether an item of a sealed kind exists, without opening it.
func (s sealedStore) exists(ctx context.Context, kind, tenant, id string) (bool, error) {
	_, err := s.get(ctx, kind, tenant, id)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	}
	return false, err
}

// newSealed is one sealed item of createAll.
type newSealed struct {
	kind, id string
	value    proto.Message
}

// createAll seals each value under the tenant's data key and creates all the items in one write, all or none, under
// the grant. If any address is taken nothing is written and the error is store.ErrExists.
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
		env, err := s.keys.sealData(ctx, seg, tenant, it.id, it.value, grant)
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
