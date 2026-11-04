package keyd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// maxBatch is the most operations store@ takes in one write (store-api.md, "Write").
const maxBatch = 64

// errTaken is a CREATE that found the address in use: another key@ made the key first.
var errTaken = errors.New("wrap: address taken")

// wrapStore reads and writes the kind DataKeyWrap. It uses the generated StoreService client and not the typed
// client of the kit: DataKeyWrap is tenant-scoped, and its boundary purposes have no tenant, which the typed
// client refuses (it takes a tenant for a tenant-scoped kind, always). Writing all the wraps of a new key in one
// batch also needs the batch, which the typed client does not offer (ADR 0006, "A new data key is written with
// conditional creates, all its wraps in one atomic write").
type wrapStore struct {
	c       storev2alpha1connect.StoreServiceClient
	segment string
}

func newWrapStore(c storev2alpha1connect.StoreServiceClient) (wrapStore, error) {
	k, ok := registry.KindByName("DataKeyWrap")
	if !ok {
		return wrapStore{}, errors.New("keyd: the registry has no kind DataKeyWrap")
	}
	return wrapStore{c: c, segment: k.Segment}, nil
}

// wrapID is <purpose>/<generation>/<recipient>.
func wrapID(purpose string, generation uint32, recipient string) string {
	return purpose + "/" + strconv.FormatUint(uint64(generation), 10) + "/" + recipient
}

// parseWrapID splits a wrap id into its purpose, generation and recipient.
func parseWrapID(id string) (purpose string, generation uint32, recipient string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return "", 0, "", false
	}
	g, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return "", 0, "", false
	}
	return parts[0], uint32(g), parts[2], true
}

func (w wrapStore) address(tenant, id string) (*typev2alpha1.Address, error) {
	if err := store.ValidateID(id); err != nil {
		return nil, err
	}
	if tenant != "" && !validTenant(tenant) {
		return nil, errors.New("wrap: tenant is not valid")
	}
	return &typev2alpha1.Address{Kind: w.segment, Tenant: tenant, Id: id}, nil
}

// wrapItem is a DataKeyWrap with its id.
type wrapItem struct {
	ID   string
	Wrap *keyv2alpha1.DataKeyWrap
}

// get reads one wrap; found is false when there is none.
func (w wrapStore) get(ctx context.Context, tenant, id string) (*keyv2alpha1.DataKeyWrap, bool, error) {
	addr, err := w.address(tenant, id)
	if err != nil {
		return nil, false, err
	}
	res, err := w.c.Get(ctx, connect.NewRequest(&storev2alpha1.GetRequest{Address: addr}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get wrap: %w", err)
	}
	if res.Msg.GetItem() == nil {
		return nil, false, nil
	}
	v := &keyv2alpha1.DataKeyWrap{}
	if err := proto.Unmarshal(res.Msg.GetItem().GetValue(), v); err != nil {
		return nil, false, errors.New("get wrap: value does not decode")
	}
	return v, true, nil
}

// list returns the wraps of a tenant ("" for the boundary's own purposes), of one purpose when purpose is set
// (by the declared index by_purpose), over every page. Only items of exactly this tenant count.
func (w wrapStore) list(ctx context.Context, tenant, purpose string) ([]wrapItem, error) {
	if tenant != "" && !validTenant(tenant) {
		return nil, errors.New("wrap: tenant is not valid")
	}
	var out []wrapItem
	token := ""
	for {
		req := &storev2alpha1.ListRequest{Kind: w.segment, Tenant: tenant, PageSize: 200, PageToken: token}
		if purpose != "" {
			req.Index, req.IndexValue = indexByPurpose, []byte(purpose)
		}
		res, err := w.c.List(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, fmt.Errorf("list wraps: %w", err)
		}
		for _, it := range res.Msg.GetItems() {
			if it.GetAddress().GetTenant() != tenant {
				continue
			}
			v := &keyv2alpha1.DataKeyWrap{}
			if err := proto.Unmarshal(it.GetValue(), v); err != nil {
				return nil, errors.New("list wraps: value does not decode")
			}
			out = append(out, wrapItem{ID: it.GetAddress().GetId(), Wrap: v})
		}
		token = res.Msg.GetNextPageToken()
		if token == "" {
			return out, nil
		}
	}
}

// The declared indexes of DataKeyWrap (kinds.yaml). Their values are computed here, by the writer.
const (
	indexByPurpose   = "by_purpose"
	indexByRecipient = "by_recipient"
)

// create writes the wraps in one batch, each with CREATE, all or none, with no grant: key@'s own writes of
// DataKeyWrap carry none (0005, "Rules"). A taken address is errTaken.
func (w wrapStore) create(ctx context.Context, tenant string, items []wrapItem) error {
	if len(items) == 0 || len(items) > maxBatch {
		return errors.New("create wraps: batch size")
	}
	ops := make([]*storev2alpha1.Operation, 0, len(items))
	for _, it := range items {
		addr, err := w.address(tenant, it.ID)
		if err != nil {
			return err
		}
		val, err := proto.MarshalOptions{Deterministic: true}.Marshal(it.Wrap)
		if err != nil {
			return err
		}
		ops = append(ops, &storev2alpha1.Operation{
			Verb: storev2alpha1.Verb_CREATE, Address: addr, Value: val,
			Indexes: []*typev2alpha1.IndexEntry{
				{Name: indexByPurpose, Value: []byte(it.Wrap.GetPurpose())},
				{Name: indexByRecipient, Value: []byte(it.Wrap.GetRecipient())},
			},
		})
	}
	_, err := w.c.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{Operations: ops}))
	if connect.CodeOf(err) == connect.CodeAlreadyExists {
		return errTaken
	}
	if err != nil {
		return fmt.Errorf("create wraps: %w", err)
	}
	return nil
}

// validTenant reports whether t is a tenant id: one address part, and never "-" (store-api.md, "Address
// encoding": a tenant id is never "-").
func validTenant(t string) bool {
	return t != "" && t != store.NoTenant && store.ValidateAddress("b", t, "k", "i") == nil
}
