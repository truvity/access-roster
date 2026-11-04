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

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
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
// "The payload"), one mapping with exactly boundary, kids and reason.
//
//	boundary: dev
//	kids:
//	  - <RFC 7638 thumbprint>
//	reason: compromise
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
		if k != "boundary" && k != "kids" && k != "reason" {
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

// knownKids reports the first kid of the list that key@ does not know, and -1 when it knows them all. A kid is known
// when it is a signing key that this key@ holds (any signing purpose of the KeyPlan), or a token key that the ring
// lists for any node. A wrapping key is not a signing key: its revocation is a recipient's, which this declaration
// does not carry. The ring is read through store@ only when a kid is not this node's own; a store@ that does not
// answer is "unavailable", never "unknown".
//
// What "known" guards: a mistyped kid, or one of another boundary, is refused instead of being written as a
// revocation that stops nothing while the operator believes the key revoked. A store@ that lies can add a kid to the
// ring (whose revocation stops nothing) or hide one (the declaration is refused, and says so); it cannot make key@
// skip a revocation silently.
func (s *Server) knownKids(ctx context.Context, kids []string) (int, error) {
	own := map[string]bool{}
	for _, pk := range s.keys {
		if pk.algorithm != algECDH {
			own[pk.keyID] = true
		}
	}
	var ring map[string]bool
	for i, kid := range kids {
		if own[kid] {
			continue
		}
		if ring == nil {
			it, err := s.ring.Get(ctx, "", "default")
			switch {
			case errors.Is(err, store.ErrNotFound):
				ring = map[string]bool{}
			case err != nil:
				return 0, err
			default:
				ring = map[string]bool{}
				for _, k := range it.Value.GetKeys() {
					ring[k.GetKeyId()] = true
				}
			}
		}
		if !ring[kid] {
			return i, nil
		}
	}
	return -1, nil
}

// Revoke takes a signed declaration and writes one KeyRevocation item for each key it names (KeyAdminService). The
// steps, each a refusal that is audited: the signature under a pinned publisher key and the kind (signed-config.md,
// steps 1 to 4), a seq above the highest declaration taken, the payload, the boundary, and every kid known. The mark of
// the seq is saved before the first item is written, so a declaration is taken once; an item that exists already is
// left as it is (a revocation is never undone and never repeated). A store@ that fails half way leaves the items it
// wrote, and the operator signs a new declaration, with a higher seq, for the rest.
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
	// Step 5 for a declaration: strictly above the highest taken. The same declaration again is a replay, refused like
	// an older one, so a declaration that was seen once can never be played back to make a second set of facts.
	if held, ok := s.declarations.seq.Held(); ok && v.Seq <= held {
		return nil, refuse(connect.CodeFailedPrecondition, reasonSeq, "seq")
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
	at, err := s.knownKids(ctx, d.GetKids())
	if err != nil {
		slog.Warn("SigningRing cannot be read: the declaration is not taken")
		return nil, refuse(connect.CodeUnavailable, reasonStore, "")
	}
	if at >= 0 {
		return nil, refuse(connect.CodeFailedPrecondition, reasonUnknownKid, fmt.Sprintf("kids[%d]", at))
	}

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

	now := timestamppb.New(s.now())
	out := &keyv2alpha1.RevokeResponse{Seq: v.Seq}
	var written, already []string
	for _, kid := range d.GetKids() {
		item := &keyv2alpha1.KeyRevocation{TargetKind: targetKid, Target: kid, ReasonCode: d.GetReason(), RevokedAt: now}
		_, err := s.revocations.Create(ctx, "", revocationID(targetKid, kid), item)
		switch {
		case err == nil:
			written = append(written, kid)
		case errors.Is(err, store.ErrExists):
			already = append(already, kid)
		default:
			slog.Error("KeyRevocation cannot be written: the declaration is taken in part", "written", len(written), "of", len(d.GetKids()))
			s.audit(ctx, revokeEvent(v, d, written, already, true))
			return nil, refuse(connect.CodeUnavailable, reasonStore, "")
		}
		out.Keys = append(out.Keys, &keyv2alpha1.RevokedKey{Kid: kid, Already: slices.Contains(already, kid)})
	}
	// The revocation stands whatever the audit transport does: a tightening does not wait (principle 12). The fact is
	// made durable or the answer says it was not (REQ-SEC-034).
	out.Audited = s.auditBlocking(ctx, revokeEvent(v, d, written, already, false)) == nil
	slog.Warn("keys revoked", "seq", v.Seq, "reason", d.GetReason(), "written", len(written), "already", len(already))
	return connect.NewResponse(out), nil
}

// revokeEvent is the audit fact of a declaration: the keys, the reason and the operator, who is the publisher key that
// signed it (REQ-SEC-034). It names no value of a key.
func revokeEvent(v *signedconfig.Verified, d *keyv2alpha1.KeyRevocationDeclaration, written, already []string, partial bool) Event {
	return Event{
		Action: ActionRevoke, Failure: partial, Reason: d.GetReason(),
		Fields: map[string]any{
			"kids": slices.Clone(d.GetKids()), "written": nonNil(written), "already": nonNil(already),
			"reason": d.GetReason(), "operator": slices.Clone(v.KIDs), "seq": int64(v.Seq), //nolint:gosec // a seq is below 2^53
			"document_sha384": hex.EncodeToString(v.Digest[:]), "partial": partial,
		},
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
