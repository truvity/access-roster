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
			st.Chain, st.ChainProblem = chainFor(certs, p.GetPurpose(), pk.spki, recipientLabel(pk.keyID))
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

// The values of chain_problem.
const (
	chainUnreadable = "unreadable"
	chainOtherKey   = "other-key"
)

// chainFor is the chain installed for the key of the purpose, and what is wrong with the items that were meant to be one.
//
// An item is a candidate when it is of the purpose and does not name another key (neither by its key field nor by its
// recipient label); an item with no chain is no candidate. The chain of a candidate is usable when every certificate in it
// parses and its leaf, the first, holds this very key: the key is read from the leaf itself and never from the item's own
// field, which only says what the writer meant. Of several usable chains the one that ends last wins, by the earliest
// NotAfter among its certificates (a chain is as old as its first certificate to end); the time key@ published an item
// (AddedAt) comes from key@'s clock, which a board that has just lost its power has wrong, so it only breaks a tie.
//
// When no candidate is usable but some candidate exists, the problem says which way it fails, so that "a certificate that
// cannot be used" is not read as "no certificate".
func chainFor(certs []*keyv2alpha1.KeyCertificate, purpose string, spki []byte, label string) ([][]byte, string) {
	var best *keyv2alpha1.KeyCertificate
	var bestEnd time.Time
	problem := ""
	for _, c := range certs {
		if c.GetPurpose() != purpose || len(c.GetChain()) == 0 {
			continue
		}
		if (len(c.GetSpkiDer()) > 0 && !bytes.Equal(c.GetSpkiDer(), spki)) || (c.GetRecipient() != "" && c.GetRecipient() != label) {
			continue // it names another key: another node's certificate
		}
		end, bad := usableChain(c.GetChain(), spki)
		if bad != "" {
			if problem == "" || bad == chainUnreadable {
				problem = bad
			}
			continue
		}
		if best == nil || end.After(bestEnd) || (end.Equal(bestEnd) && c.GetAddedAt().AsTime().After(best.GetAddedAt().AsTime())) {
			best, bestEnd = c, end
		}
	}
	if best == nil {
		return nil, problem
	}
	return best.GetChain(), ""
}

// usableChain is the earliest end of a chain whose certificates all parse and whose leaf holds the key, or the way it fails.
func usableChain(chain [][]byte, spki []byte) (time.Time, string) {
	var earliest time.Time
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return time.Time{}, chainUnreadable
		}
		if i == 0 && !bytes.Equal(cert.RawSubjectPublicKeyInfo, spki) {
			return time.Time{}, chainOtherKey
		}
		if earliest.IsZero() || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
	return earliest, ""
}
