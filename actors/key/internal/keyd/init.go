package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/slotplan"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The algorithms the key store is asked for. The KeyPlan may spell the key-agreement one with the curve's
// hyphen, as keys.yaml does. ES256 (P-256, SHA-256) is the audit-log purpose's alone (ADR 0006, "Named
// exceptions"; D-25), RS256 (RSASSA-PKCS1-v1_5 over SHA-256 with an RSA-2048 key) the purpose token-signing-rs256's
// alone (the per-audience exception); every other signing purpose is ES384.
const (
	algES384 = "ES384"
	algES256 = "ES256"
	algRS256 = "RS256"
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
	case algRS256:
		return algRS256, true
	case algECDH, "ECDH-P-384":
		return algECDH, true
	}
	return "", false
}

// dataKeyAlgorithm is the algorithm of a data key purpose: key@ makes those in software and keeps them wrapped, so the
// key store holds no key for them.
const dataKeyAlgorithm = "AES-256-GCM"

// auditLogPurpose is the one purpose whose key is ES256 (ADR 0006, "Named exceptions"; REQ-KEYS-081).
const auditLogPurpose = "audit-log"

// rs256Purpose is the one purpose whose key is RS256: the key of the audiences that need RS256 (ADR 0006, "Named
// exceptions"). The audience, not the caller, picks it (signer).
const rs256Purpose = "token-signing-rs256"

// checkPlan refuses a KeyPlan that pairs the audit-log purpose with another algorithm than ES256, or ES256 with
// another purpose (REQ-KEYS-081), and the RS256 purpose with another algorithm than RS256, or RS256 with another
// purpose (REQ-KEYS-264). The other ES256 purposes of keys.yaml are named exceptions that this key@ does not
// implement, so a plan that names one is refused rather than given a key it would not sign with. It reads the plan
// only, so Check and Init apply it before any key is asked for.
func checkPlan(plan *configv2alpha1.KeyPlan) error {
	for i, p := range plan.GetPurposes() {
		purpose, alg := p.GetPurpose(), p.GetAlgorithm()
		// An algorithm that this key@ holds no key for must not be skipped without a word: the installation would start
		// "ready" with a planned key missing. The one algorithm that is no asymmetric key is the data keys' AES-256-GCM.
		if _, ok := planAlgorithm(alg); !ok && alg != dataKeyAlgorithm {
			return fmt.Errorf("keyplan/default: purposes[%d].algorithm: not one this key@ holds a key for (ES384, ES256, RS256, ECDH-P384 or AES-256-GCM)", i)
		}
		switch {
		case purpose == auditLogPurpose && alg != algES256:
			return errors.New("keyplan/default: the audit-log purpose must be ES256 (P-256, SHA-256)")
		case purpose != auditLogPurpose && alg == algES256:
			return fmt.Errorf("keyplan/default: purpose %s cannot be ES256; only audit-log is", purpose)
		case purpose == rs256Purpose && alg != algRS256:
			return errors.New("keyplan/default: the token-signing-rs256 purpose must be RS256 (RSA-2048, SHA-256)")
		case purpose != rs256Purpose && alg == algRS256:
			return fmt.Errorf("keyplan/default: purpose %s cannot be RS256; only token-signing-rs256 is", purpose)
		}
	}
	// The card slot map: no two purposes in one slot, so no two purposes share a key (REQ-PKI-035, REQ-PKI-037,
	// REQ-PKI-041), and no enabled purpose without a slot (REQ-PKI-038). A purpose the plan does not list is not
	// enabled and needs none (REQ-PKI-042). The software driver has no slots; the plan still has to be one that a
	// board could carry, so that a map is not first found wrong on a card.
	ps := make([]slotplan.Purpose, 0, len(plan.GetPurposes()))
	for _, p := range plan.GetPurposes() {
		ps = append(ps, slotplan.Purpose{Name: p.GetPurpose(), Algorithm: p.GetAlgorithm(), Slot: p.GetSlot()})
	}
	if err := slotplan.Check(ps); err != nil {
		return fmt.Errorf("keyplan/default: %w", err)
	}
	return nil
}

// checkStoreSlots refuses, on a card, a KeyPlan whose slots the card driver does not follow. The card driver serves the
// default slot map and takes no override, so a plan that names another slot, or a card-key purpose the map lacks, would say
// one thing while the card did another, or would fail later with a driver error that names no cause. Software and cloud
// stores have no slots and are not asked.
func (s *Server) checkStoreSlots(ctx context.Context, plan *configv2alpha1.KeyPlan) error {
	caps, err := s.driver.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		return fmt.Errorf("key-store driver capabilities: %w", err)
	}
	if caps.Msg.GetStore() != slotplan.CardStore {
		return nil
	}
	ps := make([]slotplan.Purpose, 0, len(plan.GetPurposes()))
	for _, p := range plan.GetPurposes() {
		ps = append(ps, slotplan.Purpose{Name: p.GetPurpose(), Algorithm: p.GetAlgorithm(), Slot: p.GetSlot()})
	}
	if err := slotplan.CheckCard(ps); err != nil {
		return fmt.Errorf("keyplan/default: %w", err)
	}
	return nil
}

// Check is the check command: it reaches the driver, store@ and the config key@ needs, and applies the floors.
// It writes nothing and creates no key.
func (s *Server) Check(ctx context.Context) error {
	if err := s.checkRunDir(); err != nil {
		return err
	}
	// The check reads the mark and writes nothing: it refuses what the serving process would.
	if err := s.restoreMarks(false); err != nil {
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
	if err := s.checkStoreSlots(ctx, plan); err != nil {
		return err
	}
	if err := s.checkTransport(ctx); err != nil {
		return err
	}
	problems := s.checkRecipients(ctx, plan, b.GetDefaultTenant())
	// This node's entry of the slot map, for the harness that signs it into the KeyPlan (D20b). It is printed whatever
	// the recipients say: a node joins by being read first.
	line, err := s.slotMapLine(ctx, plan)
	if err != nil {
		return errors.Join(problems, err)
	}
	out := s.cfg.Out
	if out == nil {
		out = os.Stdout
	}
	_, _ = fmt.Fprintln(out, line)
	return problems
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
	if err := s.restoreMarks(true); err != nil {
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
	if err := s.checkStoreSlots(ctx, plan); err != nil {
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
		// The KeyPlan this start verified, so that a reviewer matches it to the reviewed file and sees a lag
		// (ADR 0005, "Freshness at a cold start").
		"keyplan_seq": int64(s.plan.last.seq), "keyplan_sha384": s.plan.last.sha384, //nolint:gosec // seq is below 2^53
		"boundary_seq": int64(s.boundary.last.seq), "boundary_sha384": s.boundary.last.sha384, //nolint:gosec // seq is below 2^53
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

// ensureKeys asks the driver to Ensure each asymmetric purpose of the KeyPlan (wrapping ECDH-P384, token-signing ES384,
// audit-log ES256, and the RS256 purpose when it is listed) and keeps its public key. A purpose the KeyPlan does not list gets
// no key; a data key purpose (AES-256-GCM) has none in the key store; any other algorithm was refused by checkPlan.
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
		pk := purposeKey{algorithm: alg, spki: res.Msg.GetSpkiDer()}
		if alg == algRS256 {
			if pk.rsa, err = parseRSA2048(pk.spki); err == nil {
				pk.keyID = thumbprintRSA(pk.rsa)
			}
		} else if pk.pub, err = parseKey(pk.spki, alg); err == nil {
			pk.keyID, err = thumbprint(pk.pub)
		}
		if err != nil {
			return fmt.Errorf("key-store driver ensure %s: %w", purpose, err)
		}
		s.keys[purpose] = pk
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

// parseRSA2048 reads an SPKI DER public key and requires an RSA key of 2048 bits with the public exponent 65537, the one
// key the signer and the key set know for RS256.
func parseRSA2048(spki []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("public key does not parse")
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 || pub.E != 65537 {
		return nil, errors.New("public key is not an RSA-2048 key with the exponent 65537")
	}
	return pub, nil
}

// thumbprintRSA is the JWK thumbprint of RFC 7638, section 3.2, of an RSA key: SHA-256 of the JSON object with the members
// e, kty and n in that (lexicographic) order and no white space, base64url without padding. e and n are the big-endian
// octets of the integers with no leading zero (RFC 7518, section 6.3.1).
func thumbprintRSA(pub *rsa.PublicKey) string {
	enc := base64.RawURLEncoding
	e := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	return thumbprintOf(`{"e":"` + enc.EncodeToString(e) + `","kty":"RSA","n":"` + enc.EncodeToString(pub.N.Bytes()) + `"}`)
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
