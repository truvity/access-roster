package keyd

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// errNoKey says there is no wrap for this node and no data key at all, and the caller did not ask to make one.
var errNoKey = errors.New("keyd: no such data key")

// errNotWrapped says the data key exists but no wrap of it is for this node yet: another node made it and the
// rewrap pass has not reached us. A new key is never made then, because it would lose the CREATE race at best and
// split the tenant's data across two keys at worst.
var errNotWrapped = errors.New("keyd: the data key has no wrap for this node yet")

// wrapContext is what a wrap is bound to.
func (s *Server) wrapContext(ref keyRef, recipient string) wrap.Context {
	t := ref.tenant
	if t == "" {
		t = envelope.NoTenant
	}
	return wrap.Context{Boundary: s.cfg.Boundary, Tenant: t, Purpose: ref.purpose, Generation: ref.generation, Recipient: recipient}
}

// withKey runs fn with the data key of ref, opened from this node's wrap and cached. With create, a key that has
// no wrap at all is made first (D-4: on the first need). The bytes are valid only during fn.
func (s *Server) withKey(ctx context.Context, ref keyRef, create bool, fn func(key []byte) error) error {
	for range 2 {
		e := s.cache.get(ref)
		if e == nil {
			var err error
			if e, err = s.load(ctx, ref, create); err != nil {
				return err
			}
		}
		if used, err := e.use(fn); used {
			return err
		}
		// The entry was wiped between get and use (it expired): load it again.
	}
	return unavailable(reasonWrap)
}

// load opens the key of ref, making it when asked and when no wrap of it exists. One key is loaded at a time.
func (s *Server) load(ctx context.Context, ref keyRef, create bool) (*entry, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if e := s.cache.get(ref); e != nil {
		return e, nil
	}
	key, err := s.openOwn(ctx, ref)
	switch {
	case err == nil:
	case errors.Is(err, errNoKey) && create:
		if key, err = s.makeKey(ctx, ref); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if ref.tenant != "" {
		// The rewrap pass visits the tenants whose keys this node has used.
		s.tenants.Store(ref.tenant, struct{}{})
	}
	return s.cache.put(ref, key), nil
}

// openOwn reads this node's wrap of ref and opens it. errNoKey when there is no wrap of the key at all,
// errNotWrapped when there are wraps and none is ours.
func (s *Server) openOwn(ctx context.Context, ref keyRef) ([]byte, error) {
	id := wrapID(ref.purpose, ref.generation, s.recipient)
	w, found, err := s.wraps.get(ctx, ref.tenant, id)
	if err != nil {
		return nil, unavailable(reasonStore)
	}
	if found {
		return s.unwrap(ctx, ref, w)
	}
	others, err := s.wraps.list(ctx, ref.tenant, ref.purpose)
	if err != nil {
		return nil, unavailable(reasonStore)
	}
	prefix := fmt.Sprintf("%s/%d/", ref.purpose, ref.generation)
	for _, o := range others {
		if strings.HasPrefix(o.ID, prefix) {
			return nil, errNotWrapped
		}
	}
	return nil, errNoKey
}

// unwrap opens a wrap addressed to this node: the key store does the ECDH with the wrapping key, key@ derives the
// key-encryption key and unwraps. The shared secret is zeroed after use.
func (s *Server) unwrap(ctx context.Context, ref keyRef, w *keyv2alpha1.DataKeyWrap) ([]byte, error) {
	if w.GetPurpose() != ref.purpose || w.GetGeneration() != ref.generation || w.GetRecipient() != s.recipient {
		return nil, errors.New("keyd: the wrap does not match its address")
	}
	if _, err := wrap.ParsePublic(w.GetEphemeralPublic()); err != nil {
		return nil, errors.New("keyd: the wrap has a bad ephemeral key")
	}
	res, err := s.driver.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{
		Purpose: wrappingPurpose, PeerPublic: w.GetEphemeralPublic(),
	}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	secret := res.Msg.GetSharedSecret()
	defer clear(secret)
	key, err := wrap.Unwrap(s.wrapContext(ref, s.recipient), secret, w.GetWrappedKey())
	if err != nil {
		return nil, errors.New("keyd: the wrap does not open")
	}
	return key, nil
}

// recipient is a node that may open data keys: its label and its wrapping public key.
type recipient struct {
	label string
	pub   *ecdh.PublicKey
}

// recipients lists the wrapping certificates, KeyCertificate items wrapping/*, and always this node. A
// certificate that does not parse is skipped and logged.
func (s *Server) recipients(ctx context.Context) ([]recipient, error) {
	var out []recipient
	var token string
	for {
		items, next, err := s.certs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return nil, unavailable(reasonStore)
		}
		for _, it := range items {
			label, ok := strings.CutPrefix(it.ID, certPrefix)
			if !ok || it.Value.GetPurpose() != wrappingPurpose || it.Value.GetRecipient() != label {
				continue
			}
			pub, err := parseP384(it.Value.GetSpkiDer())
			if err != nil {
				slog.Warn("skipping a wrapping certificate that does not parse", "recipient", label)
				continue
			}
			ek, err := pub.ECDH()
			if err != nil {
				continue
			}
			out = append(out, recipient{label: label, pub: ek})
		}
		if next == "" {
			break
		}
		token = next
	}
	if !slices.ContainsFunc(out, func(r recipient) bool { return r.label == s.recipient }) {
		out = append(out, recipient{label: s.recipient, pub: s.wrappingPub})
	}
	slices.SortFunc(out, func(a, b recipient) int { return strings.Compare(a.label, b.label) })
	if len(out) > maxBatch {
		return nil, errors.New("keyd: more recipients than one batch holds")
	}
	return out, nil
}

// wrapFor wraps dataKey for one recipient.
func (s *Server) wrapFor(ref keyRef, r recipient, dataKey []byte) (wrapItem, error) {
	eph, wrapped, err := wrap.Wrap(s.wrapContext(ref, r.label), r.pub, dataKey)
	if err != nil {
		return wrapItem{}, err
	}
	return wrapItem{
		ID: wrapID(ref.purpose, ref.generation, r.label),
		Wrap: &keyv2alpha1.DataKeyWrap{
			Purpose: ref.purpose, Generation: ref.generation, Recipient: r.label, EphemeralPublic: eph, WrappedKey: wrapped,
		},
	}, nil
}

// makeKey makes a data key (32 random bytes from the operating system) and writes its wraps for every recipient
// in one batch of CREATEs. A CREATE that loses means another key@ made the key first: ours is discarded, and
// theirs is read and opened.
func (s *Server) makeKey(ctx context.Context, ref keyRef) ([]byte, error) {
	recips, err := s.recipients(ctx)
	if err != nil {
		return nil, err
	}
	key := make([]byte, wrap.DataKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keyd: random: %w", err)
	}
	items := make([]wrapItem, 0, len(recips))
	for _, r := range recips {
		it, err := s.wrapFor(ref, r, key)
		if err != nil {
			clear(key)
			return nil, fmt.Errorf("keyd: wrap: %w", err)
		}
		items = append(items, it)
	}
	err = s.wraps.create(ctx, ref.tenant, items)
	switch {
	case err == nil:
	case errors.Is(err, errTaken):
		clear(key)
		slog.Info("data key was made by another node first", "purpose", ref.purpose, "generation", ref.generation)
		return s.openOwn(ctx, ref) // errNotWrapped if the winner left us out
	default:
		clear(key)
		return nil, unavailable(reasonStore)
	}
	s.audit(ctx, Event{Action: ActionDataKeyMake, Tenant: ref.tenant, Fields: map[string]any{
		"purpose": ref.purpose, "generation": int64(ref.generation), "recipients": int64(len(items)),
	}})
	for _, it := range items {
		s.auditWrap(ctx, ref, it.Wrap.GetRecipient())
	}
	return key, nil
}

func (s *Server) auditWrap(ctx context.Context, ref keyRef, recipient string) {
	s.audit(ctx, Event{Action: ActionWrapWrite, Tenant: ref.tenant, Fields: map[string]any{
		"purpose": ref.purpose, "generation": int64(ref.generation), "recipient": recipient,
	}})
}

// Rewrap is one rewrap pass: for each data key this node can open, it writes a wrap for every recipient that
// lacks one (ADR 0006, "Keys per board": the other boards rewrap for a new card). It is idempotent: a CREATE
// that finds the wrap there is fine. A failure stops the pass for that tenant and is logged.
func (s *Server) Rewrap(ctx context.Context) error {
	recips, err := s.recipients(ctx)
	if err != nil {
		return err
	}
	tenants := []string{""}
	s.tenants.Range(func(k, _ any) bool { tenants = append(tenants, k.(string)); return true })
	slices.Sort(tenants)
	var errs []error
	for _, t := range tenants {
		if err := s.rewrapTenant(ctx, t, recips); err != nil {
			errs = append(errs, fmt.Errorf("tenant %q: %w", t, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Server) rewrapTenant(ctx context.Context, tenant string, recips []recipient) error {
	all, err := s.wraps.list(ctx, tenant, "")
	if err != nil {
		return err
	}
	// Group the wraps by key (purpose and generation): who has one.
	have := map[keyRef]map[string]bool{}
	for _, it := range all {
		p, g, r, ok := parseWrapID(it.ID)
		if !ok {
			continue
		}
		ref := keyRef{tenant: tenant, purpose: p, generation: g}
		if have[ref] == nil {
			have[ref] = map[string]bool{}
		}
		have[ref][r] = true
	}
	var errs []error
	for ref, got := range have {
		if !got[s.recipient] {
			continue // not ours to open: another node will wrap it for us
		}
		var missing []recipient
		for _, r := range recips {
			if !got[r.label] {
				missing = append(missing, r)
			}
		}
		if len(missing) == 0 {
			continue
		}
		err := s.withKey(ctx, ref, false, func(key []byte) error {
			for _, r := range missing {
				it, err := s.wrapFor(ref, r, key)
				if err != nil {
					return err
				}
				switch err := s.wraps.create(ctx, tenant, []wrapItem{it}); {
				case err == nil:
					s.auditWrap(ctx, ref, r.label)
				case errors.Is(err, errTaken): // another node was first
				default:
					return err
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%d: %w", ref.purpose, ref.generation, err))
		}
	}
	return errors.Join(errs...)
}
