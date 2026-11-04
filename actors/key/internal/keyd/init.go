package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The algorithms the key store is asked for. The KeyPlan may spell the key-agreement one with the curve's
// hyphen, as keys.yaml does.
const (
	algES384 = "ES384"
	algECDH  = "ECDH-P384"
)

const (
	wrappingPurpose = "wrapping"
	// certPrefix is the id prefix of the KeyCertificate of a wrapping key: wrapping/<recipient>.
	certPrefix = wrappingPurpose + "/"
)

// planAlgorithm maps the algorithm a KeyPlan names to the one the driver takes. It is false for an algorithm
// that is not an asymmetric key of the key store (a data key purpose names AES-256-GCM, for one).
func planAlgorithm(a string) (string, bool) {
	switch a {
	case algES384:
		return algES384, true
	case algECDH, "ECDH-P-384":
		return algECDH, true
	}
	return "", false
}

// Check is the check command: it reaches the driver, store@ and the config key@ needs, and applies the floors.
// It writes nothing and creates no key.
func (s *Server) Check(ctx context.Context) error {
	if err := s.checkRunDir(); err != nil {
		return err
	}
	b, _, err := s.loadConfig(ctx)
	if err != nil {
		return err
	}
	if err := s.checkFloor(ctx, b.GetEnvironment()); err != nil {
		return err
	}
	return s.checkTransport(ctx)
}

// checkTransport reaches the audit transport's emit socket: a facts-less connection, so the check writes no
// audit record.
func (s *Server) checkTransport(ctx context.Context) error {
	if s.cfg.TransportSocket == "" {
		return nil
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", s.cfg.TransportSocket)
	if err != nil {
		return errors.New("audit transport: cannot reach the emit socket")
	}
	return c.Close()
}

// Init makes key@ ready to serve, in the order of ADR 0006 and the brief: the config (a missing document means
// no start), the floors, the keys of the KeyPlan, and this node's wrapping certificate.
func (s *Server) Init(ctx context.Context) error {
	if err := s.checkRunDir(); err != nil {
		return err
	}
	b, plan, err := s.loadConfig(ctx)
	if err != nil {
		return err
	}
	if err := s.checkFloor(ctx, b.GetEnvironment()); err != nil {
		return err
	}
	s.environment = b.GetEnvironment()
	s.defaultTenant = b.GetDefaultTenant()
	if s.defaultTenant != "" && !validTenant(s.defaultTenant) {
		return errors.New("boundary/default: default_tenant is not a valid tenant id")
	}
	ttl, err := cacheTTL(plan)
	if err != nil {
		return err
	}
	s.cache = newCache(ttl, s.now)

	if err := s.ensureKeys(ctx, plan); err != nil {
		return err
	}
	if err := s.publishCertificate(ctx); err != nil {
		return err
	}
	// planned: #1216 — with Tenant items the rewrap pass lists the tenants of the boundary; until then it
	// visits only the default tenant and the tenants this process has used since it started.
	if s.defaultTenant != "" {
		s.tenants.Store(s.defaultTenant, struct{}{})
	}
	slog.Info("rewrap visits only the default tenant and the tenants used since start", "default_tenant", s.defaultTenant)
	s.audit(ctx, Event{Action: ActionStart, Fields: map[string]any{
		"node": s.cfg.Node, "recipient": s.recipient, "purposes": int64(len(s.keys)),
	}})
	slog.Info("key@ ready", "boundary", s.cfg.Boundary, "recipient", s.recipient, "purposes", len(s.keys),
		"cache_ttl", s.cache.ttl.String())
	return nil
}

// ensureKeys asks the driver to Ensure each asymmetric purpose of the KeyPlan (tonight: wrapping ECDH-P384,
// token-signing ES384, audit-log ES384) and keeps its public key. A purpose the KeyPlan does not list gets no key.
func (s *Server) ensureKeys(ctx context.Context, plan *configv2alpha1.KeyPlan) error {
	s.keys = map[string]purposeKey{}
	for _, p := range plan.GetPurposes() {
		alg, ok := planAlgorithm(p.GetAlgorithm())
		if !ok {
			continue
		}
		purpose := p.GetPurpose()
		if purpose == "" || store.ValidateID(purpose) != nil {
			return errors.New("keyplan/default: a purpose name is not valid")
		}
		if _, dup := s.keys[purpose]; dup {
			return fmt.Errorf("keyplan/default: purpose %s is listed twice", purpose)
		}
		res, err := s.driver.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
		if err != nil {
			return fmt.Errorf("key-store driver ensure %s: %w", purpose, err)
		}
		pub, err := parseP384(res.Msg.GetSpkiDer())
		if err != nil {
			return fmt.Errorf("key-store driver ensure %s: %w", purpose, err)
		}
		id, err := thumbprint(pub)
		if err != nil {
			return fmt.Errorf("key-store driver ensure %s: %w", purpose, err)
		}
		s.keys[purpose] = purposeKey{algorithm: alg, spki: res.Msg.GetSpkiDer(), keyID: id, pub: pub}
		slog.Info("key ready", "purpose", purpose, "algorithm", alg, "created", res.Msg.GetCreated())
	}
	w, ok := s.keys[wrappingPurpose]
	if !ok || w.algorithm != algECDH {
		return errors.New("keyplan/default: no wrapping purpose with ECDH-P384")
	}
	ek, err := w.pub.ECDH()
	if err != nil {
		return err
	}
	s.wrappingPub = ek
	s.recipient = recipientLabel(s.cfg.Node, w.spki)
	return nil
}

// publishCertificate writes this node's wrapping public key as KeyCertificate wrapping/<recipient> with Apply,
// no grant (key@'s own boundary-scoped write). There is no chain tonight: no hand-off (D-8). A certificate that
// is already there with the same key is left alone.
func (s *Server) publishCertificate(ctx context.Context) error {
	id := certPrefix + s.recipient
	spki := s.keys[wrappingPurpose].spki
	cur, err := s.certs.Get(ctx, "", id)
	if err == nil && bytes.Equal(cur.Value.GetSpkiDer(), spki) {
		return nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("read %s: %w", id, err)
	}
	_, err = s.certs.Apply(ctx, "", id, &keyv2alpha1.KeyCertificate{
		Purpose: wrappingPurpose, Recipient: s.recipient, SpkiDer: spki, AddedAt: timestamppb.New(s.now()),
	}, store.WithIndex(indexByPurpose, []byte(wrappingPurpose)))
	if err != nil {
		return fmt.Errorf("publish %s: %w", id, err)
	}
	return nil
}

// parseP384 reads an SPKI DER public key and requires a P-384 key.
func parseP384(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("public key does not parse")
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, errors.New("public key is not a P-384 key")
	}
	return pub, nil
}

// thumbprint is the JWK thumbprint of RFC 7638, section 3.2, of an EC key: SHA-256 of the JSON object with the
// members crv, kty, x and y in that (lexicographic) order and no white space, base64url without padding. The
// coordinates have the full length of the curve (RFC 7518, section 6.2.1.2).
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	ek, err := pub.ECDH()
	if err != nil {
		return "", err
	}
	point := ek.Bytes() // 0x04 | X | Y, each coordinate 48 bytes
	enc := base64.RawURLEncoding
	j := `{"crv":"P-384","kty":"EC","x":"` + enc.EncodeToString(point[1:49]) + `","y":"` + enc.EncodeToString(point[49:97]) + `"}`
	sum := sha256.Sum256([]byte(j))
	return enc.EncodeToString(sum[:]), nil
}
