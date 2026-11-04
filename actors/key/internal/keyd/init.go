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
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The algorithms the key store is asked for. The KeyPlan may spell the key-agreement one with the curve's
// hyphen, as keys.yaml does. ES256 (P-256, SHA-256) is the audit-log purpose's alone (ADR 0006, "Named
// exceptions"; D-25); every other signing purpose is ES384.
const (
	algES384 = "ES384"
	algES256 = "ES256"
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
	case algES256:
		return algES256, true
	case algECDH, "ECDH-P-384":
		return algECDH, true
	}
	return "", false
}

// auditLogPurpose is the one purpose whose key is ES256 (ADR 0006, "Named exceptions"; REQ-KEYS-081).
const auditLogPurpose = "audit-log"

// checkPlan refuses a KeyPlan that pairs the audit-log purpose with another algorithm than ES256, or ES256 with
// another purpose (REQ-KEYS-081). The other ES256 purposes of keys.yaml are named exceptions that this key@ does not
// implement, so a plan that names one is refused rather than given a key it would not sign with. It reads the plan
// only, so Check and Init apply it before any key is asked for.
func checkPlan(plan *configv2alpha1.KeyPlan) error {
	for _, p := range plan.GetPurposes() {
		purpose, alg := p.GetPurpose(), p.GetAlgorithm()
		switch {
		case purpose == auditLogPurpose && alg != algES256:
			return errors.New("keyplan/default: the audit-log purpose must be ES256 (P-256, SHA-256)")
		case purpose != auditLogPurpose && alg == algES256:
			return fmt.Errorf("keyplan/default: purpose %s cannot be ES256; only audit-log is", purpose)
		}
	}
	return nil
}

// Check is the check command: it reaches the driver, store@ and the config key@ needs, and applies the floors.
// It writes nothing and creates no key.
func (s *Server) Check(ctx context.Context) error {
	if err := s.checkRunDir(); err != nil {
		return err
	}
	b, plan, err := s.loadConfig(ctx)
	if err != nil {
		return err
	}
	if err := checkPlan(plan); err != nil {
		return err
	}
	if err := s.checkFloor(ctx, b.GetEnvironment()); err != nil {
		return err
	}
	if err := s.checkTransport(ctx); err != nil {
		return err
	}
	return s.checkRecipients(ctx, plan)
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
	if err := checkPlan(plan); err != nil {
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

	if _, err := plannedRecipients(plan); err != nil {
		return err
	}
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
	listed, _ := plannedRecipients(plan)
	slog.Info("key@ ready", "boundary", s.cfg.Boundary, "recipient", s.recipient, "purposes", len(s.keys),
		"cache_ttl", s.cache.ttl.String(), "wrapping_key_id", s.wrappingID, "listed", slices.Contains(listed, s.wrappingID))
	if !slices.Contains(listed, s.wrappingID) {
		slog.Warn("this node's wrapping key is not in the KeyPlan recipients: it makes no data key and gets no wrap until it is listed",
			"wrapping_key_id", s.wrappingID)
	}
	return nil
}

// ensureKeys asks the driver to Ensure each asymmetric purpose of the KeyPlan (tonight: wrapping ECDH-P384,
// token-signing ES384, audit-log ES256) and keeps its public key. A purpose the KeyPlan does not list gets no key.
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
		pub, err := parseKey(res.Msg.GetSpkiDer(), alg)
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
	s.wrappingID = w.keyID
	s.recipient = recipientLabel(w.keyID)
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
func parseP384(spki []byte) (*ecdsa.PublicKey, error) { return parseKey(spki, algES384) }

// parseKey reads an SPKI DER public key and requires the curve of the algorithm: P-256 for ES256, P-384 for the
// others.
func parseKey(spki []byte, algorithm string) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("public key does not parse")
	}
	curve, name := elliptic.P384(), "P-384"
	if algorithm == algES256 {
		curve, name = elliptic.P256(), "P-256"
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != curve {
		return nil, fmt.Errorf("public key is not a %s key", name)
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
	point := ek.Bytes() // 0x04 | X | Y, each coordinate the size of the curve
	n := (len(point) - 1) / 2
	crv := "P-384"
	if pub.Curve == elliptic.P256() {
		crv = "P-256"
	}
	enc := base64.RawURLEncoding
	j := `{"crv":"` + crv + `","kty":"EC","x":"` + enc.EncodeToString(point[1:1+n]) + `","y":"` + enc.EncodeToString(point[1+n:]) + `"}`
	return thumbprintOf(j), nil
}

// thumbprintOf hashes the canonical JSON form of a JWK (RFC 7638, section 3): SHA-256, base64url, no padding.
func thumbprintOf(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// spkiThumbprint is the thumbprint of the P-384 public key in an SPKI DER.
func spkiThumbprint(spki []byte) (string, error) {
	pub, err := parseP384(spki)
	if err != nil {
		return "", err
	}
	return thumbprint(pub)
}

// thumbprintLen is the length of an unpadded base64url SHA-256 (RFC 7638 uses SHA-256).
const thumbprintLen = 43

// validRecipientID reports whether id has the form of a thumbprint: the unpadded base64url of 32 bytes.
func validRecipientID(id string) bool {
	if len(id) != thumbprintLen {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(b) == sha256.Size
}
