package keyd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// errTaken is a CREATE that found the address in use: another key@ made the key first.
var errTaken = errors.New("wrap: address taken")

// The declared indexes of DataKeyWrap (kinds.yaml). Their values are computed here, by the writer.
const (
	indexByPurpose   = "by_purpose"
	indexByRecipient = "by_recipient"
)

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

// validTenant reports whether t is a tenant id: one address part, and never "-" (store-api.md, "Address
// encoding": a tenant id is never "-").
func validTenant(t string) bool {
	return t != "" && t != store.NoTenant && store.ValidateAddress("b", t, "k", "i") == nil
}

// wrapItem is a DataKeyWrap with its id.
type wrapItem struct {
	ID   string
	Wrap *keyv2alpha1.DataKeyWrap
}

// getWrap reads one wrap of a tenant ("" for the boundary's own purposes); found is false when there is none.
func (s *Server) getWrap(ctx context.Context, tenant, id string) (*keyv2alpha1.DataKeyWrap, bool, error) {
	it, err := s.wraps.Get(ctx, tenant, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return it.Value, true, nil
}

// listWraps returns the wraps of a tenant ("" for the boundary's own purposes), of one purpose when purpose is
// set (by the declared index by_purpose), over every page.
func (s *Server) listWraps(ctx context.Context, tenant, purpose string) ([]wrapItem, error) {
	var out []wrapItem
	token := ""
	for {
		opts := []store.ListOption{store.PageSize(200), store.PageToken(token)}
		if purpose != "" {
			opts = append(opts, store.ByIndex(indexByPurpose, []byte(purpose)))
		}
		items, next, err := s.wraps.List(ctx, tenant, opts...)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if it.Tenant == tenant { // only items of exactly this tenant count
				out = append(out, wrapItem{ID: it.ID, Wrap: it.Value})
			}
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// createWraps writes the wraps in one batch of CREATEs, all or none, with no grant: key@'s own writes of
// DataKeyWrap carry none (0005, "Rules"). A taken address is errTaken.
func (s *Server) createWraps(ctx context.Context, tenant string, items []wrapItem) error {
	batch := make([]store.NewItem[*keyv2alpha1.DataKeyWrap], 0, len(items))
	for _, it := range items {
		batch = append(batch, store.NewItem[*keyv2alpha1.DataKeyWrap]{
			Tenant: tenant, ID: it.ID, Value: it.Wrap,
			Indexes: []store.Index{
				{Name: indexByPurpose, Value: []byte(it.Wrap.GetPurpose())},
				{Name: indexByRecipient, Value: []byte(it.Wrap.GetRecipient())},
			},
		})
	}
	_, err := s.wraps.CreateAll(ctx, batch)
	switch {
	case errors.Is(err, store.ErrExists):
		return errTaken
	case err != nil:
		return fmt.Errorf("create wraps: %w", err)
	}
	return nil
}
