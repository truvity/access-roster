package keyd

import (
	"bytes"
	"context"
	"crypto/x509"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/slotplan"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Status answers `sluis key status` and `sluis doctor` on the admin socket (ADR 0024, "Lifetimes and the warning"): which
// asymmetric keys key@ holds for the KeyPlan, where each lives and which certificate chain is installed for it. It reads
// and writes nothing that an actor depends on, and makes no audit fact; the socket is served only to root (admin.go).
//
// It reads KeyCertificate by listing the kind, never by asking for an item that may be absent: store@ audits a refusal
// for an absent item, and "no certificate yet" is an expected answer (ADR 0005; REQ-AUDIT-180). One call is one list of
// the kind and one call to the driver.
func (s *Server) Status(ctx context.Context, _ *connect.Request[keyv2alpha1.StatusRequest]) (*connect.Response[keyv2alpha1.StatusResponse], error) {
	caps, err := s.driver.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	certs, err := s.certificates(ctx)
	if err != nil {
		return nil, unavailable(reasonStore)
	}
	s.plan.mu.Lock()
	var purposes []*keyv2alpha1.KeyStatus
	if s.plan.last != nil {
		for _, p := range s.plan.last.value.GetPurposes() {
			pk, ok := s.keys[p.GetPurpose()]
			if !ok {
				continue // a data key purpose, or one that key@ holds no asymmetric key for
			}
			st := &keyv2alpha1.KeyStatus{Purpose: p.GetPurpose(), Algorithm: pk.algorithm, SpkiDer: pk.spki, KeyId: pk.keyID}
			if caps.Msg.GetStore() == slotplan.CardStore {
				st.Slot = p.GetSlot()
			}
			st.Chain = chainFor(certs, p.GetPurpose(), pk.spki)
			purposes = append(purposes, st)
		}
	}
	s.plan.mu.Unlock()
	return connect.NewResponse(&keyv2alpha1.StatusResponse{Store: caps.Msg.GetStore(), Environment: s.environment, Keys: purposes}), nil
}

// certificates lists every KeyCertificate of the boundary.
func (s *Server) certificates(ctx context.Context) ([]*keyv2alpha1.KeyCertificate, error) {
	var out []*keyv2alpha1.KeyCertificate
	for token := ""; ; {
		items, next, err := s.certs.List(ctx, "", store.PageSize(200), store.PageToken(token), store.Linearizable())
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			out = append(out, it.Value)
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// chainFor is the chain installed for the key of the purpose: a certificate item of that purpose whose chain is led by a
// certificate that holds this very key. The key is read from the leaf itself and never from the item's own spki_der field,
// which only says what the writer meant; another node's certificate, a stray one for another key and one with no chain are
// not the key's chain. When several qualify, the one whose leaf lives longest: the time key@ published an item (AddedAt)
// comes from key@'s clock, which a board that has just lost its power has wrong, so it only breaks a tie.
func chainFor(certs []*keyv2alpha1.KeyCertificate, purpose string, spki []byte) [][]byte {
	var best *keyv2alpha1.KeyCertificate
	var bestEnd time.Time
	for _, c := range certs {
		if c.GetPurpose() != purpose || len(c.GetChain()) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(c.GetChain()[0])
		if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
			continue
		}
		if best == nil || leaf.NotAfter.After(bestEnd) ||
			(leaf.NotAfter.Equal(bestEnd) && c.GetAddedAt().AsTime().After(best.GetAddedAt().AsTime())) {
			best, bestEnd = c, leaf.NotAfter
		}
	}
	if best == nil {
		return nil
	}
	return best.GetChain()
}
