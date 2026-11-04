package keyd

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// key@ does not take the KeyPlan from store@ as a decoded item. A compromised store@ could serve a KeyPlan that lists
// its own key and receive every new data key, because the recipients are the one thing a wrap must not take from an
// unsigned source (ADR 0006, "Who may receive a wrap"; REQ-KEYS-075). So key@ asks store@ for the signed document
// (GetSignedConfig), verifies the signature, the pinned publisher key, the kind and the sequence itself, and reads
// the KeyPlan from the bytes it verified. What store@ says about the KeyPlan is never used.

// keyPlanKind is the config kind key@ verifies.
const keyPlanKind = "KeyPlan"

// reasonKeyPlan is the reason of the audit fact of a signed KeyPlan that key@ refused.
const reasonKeyPlan = "keyplan"

// verifiedPlan is the KeyPlan key@ last verified, with the seq and digest of its document.
type verifiedPlan struct {
	plan   *configv2alpha1.KeyPlan
	seq    uint64
	sha384 string
}

// keyPlan fetches the signed KeyPlan, verifies it and returns the KeyPlan of the verified payload.
//
// A document that is refused (a forged one, one signed by another key, a lower seq than this process has seen, a
// payload that is not a KeyPlan) never reaches the caller. If key@ already holds a verified KeyPlan it keeps using
// that one, audits the refusal once, and logs it; if it holds none (a start), the refusal is the error, so key@ does
// not start. A store@ that does not answer is "unavailable", as for every read: that is no verdict on the document.
//
// What this guards, and what it does not: the highest seq is held in memory and saved in key@'s state directory
// (plan_state.go), so an older document never comes back, in a process or after a restart on a node that has its
// state. A node with none takes the latest validly signed document the store gives it, as store@ does (ADR 0005,
// "Freshness at a cold start"): a compromised store@ can serve it a validly signed older KeyPlan. It cannot sign a new one.
func (s *Server) keyPlan(ctx context.Context) (*configv2alpha1.KeyPlan, error) {
	s.planMu.Lock()
	defer s.planMu.Unlock()
	doc, err := store.GetSignedConfig(ctx, s.st, keyPlanKind)
	if err != nil {
		return nil, unavailable(reasonStore)
	}
	v, err := s.verify(doc)
	if err != nil {
		return s.refusedPlan(ctx, doc, err)
	}
	return proto.Clone(v.plan).(*configv2alpha1.KeyPlan), nil
}

// verify takes the steps of signed-config.md on the document and reads its payload, and remembers the result.
func (s *Server) verify(doc []byte) (*verifiedPlan, error) {
	v, err := signedconfig.Verify(doc, keyPlanKind, s.publishers)
	if err != nil {
		return nil, err
	}
	// Step 5, before the payload is read: an older or conflicting document is refused whatever it says.
	if _, err := s.planSeq.Admit(v); err != nil {
		return nil, err
	}
	if s.planLast != nil && s.planLast.seq == v.Seq {
		return s.planLast, nil // the same document again
	}
	plan, err := decodeKeyPlan(v.Payload)
	if err != nil {
		return nil, fmt.Errorf("step 6: %w", err)
	}
	// The mark is saved before the plan is used: a plan whose mark cannot be saved would be forgotten by a restart.
	if s.saveMark {
		if err := s.writeMark(planMark{seq: v.Seq, sha384: v.Digest}); err != nil {
			return nil, errors.New("the KeyPlan mark cannot be saved")
		}
	}
	s.planLast = &verifiedPlan{plan: plan, seq: v.Seq, sha384: hex.EncodeToString(v.Digest[:])}
	return s.planLast, nil
}

// refusedPlan reports a document that was refused: one audit fact and one log line for each distinct document and
// reason, never the document. It returns the KeyPlan key@ already holds, or the refusal when it holds none.
func (s *Server) refusedPlan(ctx context.Context, doc []byte, why error) (*configv2alpha1.KeyPlan, error) {
	sum := sha512.Sum384(doc)
	key := "keyplan:" + hex.EncodeToString(sum[:]) + ":" + why.Error()
	held := s.planLast != nil
	if _, dup := s.reported.LoadOrStore(key, struct{}{}); !dup {
		slog.Warn("the signed KeyPlan from store@ is refused", "why", why.Error(), "keeps_the_verified_plan", held)
		s.audit(ctx, Event{
			Action: ActionRefuse, Failure: true, Reason: reasonKeyPlan,
			Fields: map[string]any{"op": "keyplan", "why": why.Error(), "keeps_the_verified_plan": held, "document_sha384": hex.EncodeToString(sum[:])},
		})
	}
	if held {
		return proto.Clone(s.planLast.plan).(*configv2alpha1.KeyPlan), nil
	}
	if errors.Is(why, signedconfig.ErrOlder) || errors.Is(why, signedconfig.ErrConflict) {
		if seq, ok := s.planSeq.Held(); ok {
			// The mark is ahead of everything store@ shows (a restore of the store, a reset of the seq).
			return nil, fmt.Errorf("keyplan/default: the signed KeyPlan is refused: %w; the mark %s holds seq %d: publish a KeyPlan with a higher seq (preferred), "+
				"or remove the mark on purpose, knowing that key@ then has no rollback protection until the next plan is verified",
				why, filepath.Join(s.cfg.StateDir, planMarkFile), seq)
		}
	}
	return nil, fmt.Errorf("keyplan/default: the signed KeyPlan is refused: %w", why)
}

// KeyPlan payload: the strict profile of the bootstrap file read into the message, as store@ reads it (signed-config.md,
// "The payload"; payload.rs `key_plan`). Two implementations of one reading, held together by the vectors in
// tests/testdata/signed-config/keyplan-payloads.json. A mapping from item id to item with the one id `default`.

// parseDuration reads a duration of the bootstrap file: one whole number above zero and one unit of s, m, h or d
// (bootstrap-file.md, "Durations"). It returns the seconds.
func parseDuration(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var per int64
	switch s[len(s)-1] {
	case 's':
		per = 1
	case 'm':
		per = 60
	case 'h':
		per = 3600
	case 'd':
		per = 86400
	default:
		return 0, false
	}
	digits := s[:len(s)-1]
	if digits == "" || len(digits) > 9 {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n * per, true
}

type mapping struct {
	path string
	m    map[string]*yaml.Node
}

func asMapping(n *yaml.Node, path string) (*mapping, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: must be a mapping", path)
	}
	out := &mapping{path: path, m: map[string]*yaml.Node{}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out.m[n.Content[i].Value] = n.Content[i+1]
	}
	return out, nil
}

func (o *mapping) at(k string) string {
	if o.path == "" {
		return k
	}
	return o.path + "." + k
}

// take removes the key and returns its node, nil when absent.
func (o *mapping) take(k string) *yaml.Node {
	n := o.m[k]
	delete(o.m, k)
	return n
}

func isNull(n *yaml.Node) bool {
	return n == nil || (n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null")
}

// str is a string; an absent or null key is empty.
func (o *mapping) str(k string) (string, error) {
	n := o.take(k)
	if isNull(n) {
		return "", nil
	}
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
		return "", fmt.Errorf("%s: must be a string", o.at(k))
	}
	return n.Value, nil
}

func (o *mapping) required(k string) (string, error) {
	s, err := o.str(k)
	if err == nil && s == "" {
		err = fmt.Errorf("%s: required", o.at(k))
	}
	return s, err
}

func (o *mapping) done() error {
	if len(o.m) > 0 {
		// An unknown key is the file's own text: name its place, not the key.
		return fmt.Errorf("%s: unknown key", o.at("<key>"))
	}
	return nil
}

// decodeKeyPlan reads the payload of a KeyPlan document: the item `default`.
func decodeKeyPlan(payload []byte) (*configv2alpha1.KeyPlan, error) {
	root, err := signedconfig.StrictYAML(payload)
	if err != nil {
		return nil, err
	}
	top, err := asMapping(root, "")
	if err != nil {
		return nil, errors.New("must be a mapping from item id to item")
	}
	if len(top.m) != 1 || top.m["default"] == nil {
		return nil, errors.New("a singleton kind has one item, with the id default")
	}
	o, err := asMapping(top.m["default"], "default")
	if err != nil {
		return nil, err
	}
	plan := &configv2alpha1.KeyPlan{}
	if n := o.take("purposes"); !isNull(n) {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", o.at("purposes"))
		}
		for i, item := range n.Content {
			p, err := asMapping(item, fmt.Sprintf("%s[%d]", o.at("purposes"), i))
			if err != nil {
				return nil, err
			}
			var pp configv2alpha1.KeyPurposePlan
			if pp.Purpose, err = p.required("purpose"); err != nil {
				return nil, err
			}
			if pp.Algorithm, err = p.required("algorithm"); err != nil {
				return nil, err
			}
			if pp.Slot, err = p.str("slot"); err != nil {
				return nil, err
			}
			if err := p.done(); err != nil {
				return nil, err
			}
			plan.Purposes = append(plan.Purposes, &pp)
		}
	}
	ttl, err := o.required("cache_ttl")
	if err != nil {
		return nil, err
	}
	secs, ok := parseDuration(ttl)
	if !ok {
		return nil, fmt.Errorf("%s: not a duration string", o.at("cache_ttl"))
	}
	plan.CacheTtl = durationpb.New(0)
	plan.CacheTtl.Seconds = secs
	if n := o.take("recipients"); !isNull(n) {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", o.at("recipients"))
		}
		for i, r := range n.Content {
			if r.Kind != yaml.ScalarNode || r.ShortTag() != "!!str" || r.Value == "" {
				return nil, fmt.Errorf("%s[%d]: must be a non-empty string", o.at("recipients"), i)
			}
			plan.Recipients = append(plan.Recipients, r.Value)
		}
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	if _, err := plannedRecipients(plan); err != nil {
		return nil, err
	}
	return plan, nil
}
