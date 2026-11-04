package keyd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Only a person declares a revocation, and key@ writes KeyRevocation only on a declaration (ADR 0041, "A person
// declares, and a suspicion counts"; REQ-KEYS-108). A declaration is a signed document of its own kind,
// KeyRevocationDeclaration, under a publisher key that key@'s copy of the bootstrap file pins: the trust path of the
// KeyPlan and the Boundary (signed_kind.go), so that a revocation needs neither the token keys nor sign-in, which a
// compromise may have taken. key@ takes a declaration only with a seq above the highest it took (a mark of its own in
// the state directory), only for its own boundary, and only when it knows every key the declaration names.

// declarationKind is the kind that the protected header of a declaration names.
const declarationKind = signedconfig.KeyRevocationDeclaration

// maxDeclaredKids bounds the keys of one declaration.
const maxDeclaredKids = 64

// reasonCodes is the closed list of the reasons of a revocation (ADR 0041; the KeyRevocation message).
var reasonCodes = []string{"compromise", "suspicion", "lost-board", "drill"}

// kidPattern is an RFC 7638 thumbprint of SHA-256: 43 characters of base64url without padding.
var kidPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// declarations holds the highest declaration key@ took. One declaration is taken at a time.
type declarations struct {
	mu  sync.Mutex
	seq signedconfig.Sequencer
}

// errDeclarationPath is a payload error at a field path.
type errDeclarationPath struct{ path, rule string }

func (e *errDeclarationPath) Error() string { return e.path + ": " + e.rule }

func badField(path, rule string) error { return &errDeclarationPath{path: path, rule: rule} }

// decodeDeclaration reads the payload of a declaration: the strict profile of the bootstrap file (signed-config.md,
// "The payload"), one mapping with boundary, kids and reason, and allow_unknown when the publisher revokes keys that
// no source of key@ knows.
//
//	boundary: dev
//	kids:
//	  - <RFC 7638 thumbprint>
//	reason: compromise
//	allow_unknown: true      # optional
func decodeDeclaration(payload []byte) (*keyv2alpha1.KeyRevocationDeclaration, error) {
	root, err := signedconfig.StrictYAML(payload)
	if err != nil {
		return nil, badField("", "not the strict YAML profile")
	}
	top, err := asMapping(root, "")
	if err != nil {
		return nil, badField("", "must be a mapping")
	}
	for k := range top.m {
		if k != "boundary" && k != "kids" && k != "reason" && k != "allow_unknown" {
			return nil, badField(k, "not a field of a declaration")
		}
	}
	d := &keyv2alpha1.KeyRevocationDeclaration{}
	b := top.m["boundary"]
	if b == nil || !signedconfig.IsString(b) || !validPart(b.Value) {
		return nil, badField("boundary", "must be the name of a boundary")
	}
	d.Boundary = b.Value
	r := top.m["reason"]
	if r == nil || !signedconfig.IsString(r) || !slices.Contains(reasonCodes, r.Value) {
		return nil, badField("reason", "must be compromise, suspicion, lost-board or drill")
	}
	d.Reason = r.Value
	if a := top.m["allow_unknown"]; a != nil {
		if a.Kind != yaml.ScalarNode || signedconfig.ScalarOf(a) != signedconfig.KindBool {
			return nil, badField("allow_unknown", "must be true or false")
		}
		d.AllowUnknown = a.Value == "true"
	}
	ks := top.m["kids"]
	if ks == nil || ks.Kind != yaml.SequenceNode || len(ks.Content) == 0 || len(ks.Content) > maxDeclaredKids {
		return nil, badField("kids", fmt.Sprintf("must be a list of 1 to %d key ids", maxDeclaredKids))
	}
	for i, k := range ks.Content {
		path := fmt.Sprintf("kids[%d]", i)
		if !signedconfig.IsString(k) || !kidPattern.MatchString(k.Value) {
			return nil, badField(path, "not an RFC 7638 thumbprint")
		}
		if slices.Contains(d.Kids, k.Value) {
			return nil, badField(path, "listed twice")
		}
		d.Kids = append(d.Kids, k.Value)
	}
	return d, nil
}

// signingRingKind is the kind of the token keys every node's signer publishes, which key@ reads to know another
// node's key (kinds.yaml: SigningRing; one item, default).
const signingRingKind = "SigningRing"

// kidCheck is what key@ knows of the kids of a declaration.
type kidCheck struct {
	unknown  []int // the indexes of the kids that no source knows
	wrapping int   // the index of the first kid that is a wrapping key, or -1
}

// checkKids sorts the kids of a declaration. A kid is known when it is a signing key that this key@ holds (any
// signing purpose of the KeyPlan), a token key that the ring lists for any node, or a key that a KeyCertificate of a
// signing purpose certifies. On a retry, a kid that KeyRevocation already lists is known too, so a key that has left
// the ring since the first delivery does not stop the retry. A wrapping key (this node's, a recipient of the KeyPlan,
// or one a wrapping KeyCertificate certifies) is not a signing key: its revocation is a recipient's, which a
// declaration of this version does not carry, so it is refused whatever allow_unknown says (ADR 0041, "The
// declaration"). The store is read only when a kid is not this node's own signing key; a store@ that does not answer
// is "unavailable", never "unknown".
//
// What "known" guards: a mistyped kid, or one of another boundary, is refused instead of being written as a revocation
// that stops nothing while the operator believes the key revoked. The ring is written by every node's signer, and a
// signer can drop its own key from it; a key no source knows (a lost board's own keys, that left) is revoked with
// allow_unknown, which the publisher signs. A store@ that lies can add a kid (whose revocation stops nothing) or hide one
// (the declaration is refused, and says so); it cannot make key@ skip a revocation silently.
func (s *Server) checkKids(ctx context.Context, kids []string, retry bool) (kidCheck, error) {
	out := kidCheck{wrapping: -1}
	known, wrapping := map[string]bool{}, map[string]bool{}
	for _, pk := range s.keys {
		if pk.algorithm == algECDH {
			wrapping[pk.keyID] = true
		} else {
			known[pk.keyID] = true
		}
	}
	var rest []int
	for i, kid := range kids {
		if !known[kid] {
			rest = append(rest, i)
		}
	}
	if len(rest) == 0 {
		return out, nil
	}
	plan, err := fetchVerified(ctx, s, s.plan)
	if err != nil {
		return out, err
	}
	for _, id := range plan.GetRecipients() {
		wrapping[id] = true
	}
	for token := ""; ; {
		items, next, err := s.certs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return out, err
		}
		for _, c := range items {
			id, err := spkiThumbprint(c.Value.GetSpkiDer())
			if err != nil {
				continue
			}
			if c.Value.GetPurpose() == wrappingPurpose {
				wrapping[id] = true
			} else {
				known[id] = true
			}
		}
		if next == "" {
			break
		}
		token = next
	}
	for _, i := range rest {
		if wrapping[kids[i]] {
			out.wrapping = i
			return out, nil
		}
	}
	it, err := s.ring.Get(ctx, "", "default")
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return out, err
	default:
		for _, k := range it.Value.GetKeys() {
			known[k.GetKeyId()] = true
		}
	}
	for _, i := range rest {
		if known[kids[i]] {
			continue
		}
		if retry {
			_, err := s.revocations.Get(ctx, "", revocationID(targetKid, kids[i]))
			if err == nil {
				continue
			}
			if !errors.Is(err, store.ErrNotFound) {
				return out, err
			}
		}
		out.unknown = append(out.unknown, i)
	}
	return out, nil
}

// writeTimeout bounds the writes and the audit fact of a declaration, which do not stop when the caller goes away.
const writeTimeout = 30 * time.Second

// Revoke takes a signed declaration and writes one KeyRevocation item for each key it names (KeyAdminService). The
// steps, each a refusal that is audited: the signature under a pinned publisher key and the kind (signed-config.md,
// steps 1 to 4), the seq, the payload, the boundary, and every kid known unless the declaration allows unknown ones.
//
// The seq is above the highest declaration taken, or equal to it with the same payload: that is a retry of the
// declaration taken last, which completes what a store@ failure stopped half way. The same seq with another payload, and
// a lower one, are refused. The mark is saved before the first item is written. An item that exists already counts as
// revoked (a revocation is never undone and never repeated). The writes and the audit fact run to their end even when
// the caller goes away; a declaration stopped half way is refused as "partial", with the keys still pending.
func (s *Server) Revoke(ctx context.Context, req *connect.Request[keyv2alpha1.RevokeRequest]) (*connect.Response[keyv2alpha1.RevokeResponse], error) {
	const caller, op = "admin", "revoke"
	refuse := func(code connect.Code, reason, path string) error {
		return s.refuse(ctx, caller, op, "", "", code, reason, path)
	}
	s.declarations.mu.Lock()
	defer s.declarations.mu.Unlock()

	v, err := signedconfig.VerifyDeclaration(req.Msg.GetDeclaration(), declarationKind, s.publishers)
	if err != nil {
		slog.Warn("a key revocation declaration is refused", "why", err.Error())
		return nil, refuse(connect.CodePermissionDenied, reasonDeclaration, "declaration")
	}
	retry := false
	switch s.declarations.seq.Peek(v) {
	case signedconfig.Same:
		retry = true
	case signedconfig.Older, signedconfig.Conflict:
		return nil, refuse(connect.CodeFailedPrecondition, reasonSeq, "seq")
	case signedconfig.Newer:
	}
	d, err := decodeDeclaration(v.Payload)
	if err != nil {
		var pe *errDeclarationPath
		path := "declaration"
		if errors.As(err, &pe) && pe.path != "" {
			path = pe.path
		}
		return nil, refuse(connect.CodeInvalidArgument, reasonSchema, path)
	}
	if d.GetBoundary() != s.cfg.Boundary {
		return nil, refuse(connect.CodePermissionDenied, reasonOtherBoundary, "boundary")
	}
	kc, err := s.checkKids(ctx, d.GetKids(), retry)
	if err != nil {
		slog.Warn("the KeyPlan, KeyCertificate, SigningRing or KeyRevocation cannot be read: the declaration is not taken")
		return nil, refuse(connect.CodeUnavailable, reasonStore, "")
	}
	if kc.wrapping >= 0 {
		return nil, refuse(connect.CodeFailedPrecondition, reasonWrappingKey, fmt.Sprintf("kids[%d]", kc.wrapping))
	}
	unknownAt := kc.unknown
	if len(unknownAt) > 0 && !d.GetAllowUnknown() {
		return nil, refuse(connect.CodeFailedPrecondition, reasonUnknownKid, fmt.Sprintf("kids[%d]", unknownAt[0]))
	}
	unknown := map[string]bool{}
	for _, i := range unknownAt {
		unknown[d.GetKids()[i]] = true
	}

	if !retry {
		// The mark comes first: a declaration whose mark cannot be saved is not taken.
		if s.saveMark {
			if err := s.writeMark(declarationMarkFile, seqMark{kind: declarationKind, seq: v.Seq, sha384: v.Digest}); err != nil {
				slog.Error("the key revocation declaration mark cannot be saved", "err", err)
				return nil, refuse(connect.CodeUnavailable, reasonState, "")
			}
		}
		if _, err := s.declarations.seq.Admit(v); err != nil {
			return nil, refuse(connect.CodeFailedPrecondition, reasonSeq, "seq")
		}
	}

	// From here the declaration is taken: the writes and the fact do not stop with the caller.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	now := timestamppb.New(s.now())
	out := &keyv2alpha1.RevokeResponse{Seq: v.Seq}
	t := tally{}
	for _, kid := range d.GetKids() {
		k := &keyv2alpha1.RevokedKey{Kid: kid, Unknown: unknown[kid]}
		out.Keys = append(out.Keys, k)
		if len(t.pending) > 0 {
			k.Pending = true
			t.pending = append(t.pending, kid)
			continue
		}
		item := &keyv2alpha1.KeyRevocation{TargetKind: targetKid, Target: kid, ReasonCode: d.GetReason(), RevokedAt: now}
		_, err := s.revocations.Create(wctx, "", revocationID(targetKid, kid), item)
		switch {
		case err == nil:
			t.written = append(t.written, kid)
		case errors.Is(err, store.ErrExists):
			k.Already = true
			t.already = append(t.already, kid)
		default:
			slog.Error("KeyRevocation cannot be written: the declaration is taken in part; deliver it again", "written", len(t.written)+len(t.already), "of", len(d.GetKids()))
			k.Pending = true
			t.pending = append(t.pending, kid)
		}
	}
	// The revocation stands whatever the audit transport does: a tightening does not wait (principle 12). The fact is
	// made durable or the answer says it was not (REQ-SEC-034).
	peer, _ := adminPeerOf(ctx)
	ev := revokeEvent(v, d, t, unknownAt, retry, s.cfg.Node, peer)
	out.Audited = s.auditBlocking(wctx, ev) == nil
	if len(t.pending) > 0 {
		e := refusal.New(connect.CodeUnavailable, reasonPartial, "")
		if detail, derr := connect.NewErrorDetail(out); derr == nil {
			e.AddDetail(detail)
		}
		return nil, e
	}
	slog.Warn("keys revoked", "seq", v.Seq, "reason", d.GetReason(), "written", len(t.written), "already", len(t.already), "unknown", len(unknownAt), "retry", retry)
	return connect.NewResponse(out), nil
}

// tally is what a declaration did with its keys.
type tally struct{ written, already, pending []string }

// revokeEvent is the audit fact of a declaration: the keys, the reason and the operator, who is the publisher key that
// signed it, with the node that took it and the uid that delivered it (REQ-SEC-034). It names no value of a key.
func revokeEvent(v *signedconfig.Verified, d *keyv2alpha1.KeyRevocationDeclaration, t tally, unknownAt []int, retry bool, node string, peer uint32) Event {
	unknown := []string{}
	for _, i := range unknownAt {
		unknown = append(unknown, d.GetKids()[i])
	}
	partial := len(t.pending) > 0
	return Event{
		Action: ActionRevoke, Failure: partial, Reason: d.GetReason(),
		Fields: map[string]any{
			"kids": slices.Clone(d.GetKids()), "written": nonNil(t.written), "already": nonNil(t.already),
			"pending": nonNil(t.pending), "unknown": unknown, "reason": d.GetReason(), "operator": slices.Clone(v.KIDs),
			"seq":             int64(v.Seq), //nolint:gosec // a seq is below 2^53
			"document_sha384": hex.EncodeToString(v.Digest[:]), "partial": partial, "retry": retry,
			"node": node, "peer_uid": int64(peer),
		},
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
