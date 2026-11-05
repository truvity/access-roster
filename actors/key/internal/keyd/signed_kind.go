package keyd

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/truvity/sluis/v2/kits/go/signedconfig"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// key@ does not take a config kind it acts on from store@ as a decoded item. A compromised store@ could serve a KeyPlan
// that lists its own key and receive every new data key (ADR 0006, "Who may receive a wrap"; REQ-KEYS-075), or a
// Boundary that says development and relaxes the floor of the software key driver in production (ADR 0006, "Floors in
// code"; REQ-KEYS-111). So for each of these kinds key@ asks store@ for the signed document (GetSignedConfig),
// verifies the signature, the pinned publisher key, the kind and the sequence itself, and reads the kind from the bytes
// it verified. What store@ says about the kind is never used.

// signedKind is one config kind that key@ verifies, and what it holds of it: the highest document seen in this process,
// saved in a mark of the state directory (signed_state.go), and the value last verified.
type signedKind[T proto.Message] struct {
	kind     string // the registry name, as the protected header names it
	label    string // how the errors and the audit fact name it: KeyPlan, Boundary
	op       string // the op of the audit fact
	reason   string // the reason of the audit fact
	markFile string // the file of the mark in the state directory
	decode   func([]byte) (T, error)

	mu   sync.Mutex // one fetch and verification at a time
	seq  signedconfig.Sequencer
	last *verified[T]
}

// verified is the value key@ last verified, with the seq and digest of its document, and the document itself, which
// the card driver verifies again for a PIN release (pinrelease.go).
type verified[T proto.Message] struct {
	value  T
	seq    uint64
	sha384 string
	doc    []byte
}

// fetchVerified fetches the signed document of the kind, verifies it and returns the value of the verified payload.
//
// A document that is refused (a forged one, one signed by another key or for another kind, a lower seq than this
// process has seen, a payload that is not the kind) never reaches the caller. If key@ already holds a verified value it
// keeps using that one, audits the refusal once, and logs it; if it holds none (a start), the refusal is the error, so
// key@ does not start. A store@ that does not answer is "unavailable", as for every read: that is no verdict on the
// document.
//
// What this guards, and what it does not: the highest seq is held in memory and saved in key@'s state directory, so an
// older document never comes back, in a process or after a restart on a node that has its state. A node with none takes
// the latest validly signed document the store gives it, as store@ does (ADR 0005, "Freshness at a cold start"): a
// compromised store@ can serve it a validly signed older document. It cannot sign a new one.
func fetchVerified[T proto.Message](ctx context.Context, s *Server, k *signedKind[T]) (T, error) {
	v, _, err := fetchVerifiedDoc(ctx, s, k)
	return v, err
}

// fetchVerifiedDoc is fetchVerified that also returns the signed document of the value it returns: the one it just
// verified, or the one it holds when store@'s is refused.
func fetchVerifiedDoc[T proto.Message](ctx context.Context, s *Server, k *signedKind[T]) (T, []byte, error) {
	var zero T
	k.mu.Lock()
	defer k.mu.Unlock()
	doc, err := store.GetSignedConfig(ctx, s.st, k.kind)
	if err != nil {
		return zero, nil, unavailable(reasonStore)
	}
	v, err := verifyKind(s, k, doc)
	if err != nil {
		held, err := refusedKind(ctx, s, k, doc, err)
		if err != nil {
			return zero, nil, err
		}
		return held, bytes.Clone(k.last.doc), nil
	}
	return proto.Clone(v.value).(T), bytes.Clone(v.doc), nil
}

// verifyKind takes the steps of signed-config.md on the document and reads its payload, and remembers the result.
func verifyKind[T proto.Message](s *Server, k *signedKind[T], doc []byte) (*verified[T], error) {
	v, err := signedconfig.Verify(doc, k.kind, s.publishers)
	if err != nil {
		return nil, err
	}
	// Step 5, before the payload is read: an older or conflicting document is refused whatever it says.
	if _, err := k.seq.Admit(v); err != nil {
		return nil, err
	}
	if k.last != nil && k.last.seq == v.Seq {
		return k.last, nil // the same document again
	}
	value, err := k.decode(v.Payload)
	if err != nil {
		return nil, fmt.Errorf("step 6: %w", err)
	}
	// The mark is saved before the value is used: a value whose mark cannot be saved would be forgotten by a restart.
	if s.saveMark {
		if err := s.writeMark(k.markFile, seqMark{kind: k.kind, seq: v.Seq, sha384: v.Digest}); err != nil {
			return nil, fmt.Errorf("the %s mark cannot be saved", k.label)
		}
	}
	k.last = &verified[T]{value: value, seq: v.Seq, sha384: hex.EncodeToString(v.Digest[:]), doc: bytes.Clone(doc)}
	return k.last, nil
}

// refusedKind reports a document that was refused: one audit fact and one log line for each distinct document and
// reason, never the document. It returns the value key@ already holds, or the refusal when it holds none.
func refusedKind[T proto.Message](ctx context.Context, s *Server, k *signedKind[T], doc []byte, why error) (T, error) {
	var zero T
	sum := sha512.Sum384(doc)
	key := k.op + ":" + hex.EncodeToString(sum[:]) + ":" + why.Error()
	held := k.last != nil
	if _, dup := s.reported.LoadOrStore(key, struct{}{}); !dup {
		slog.Warn("the signed "+k.label+" from store@ is refused", "why", why.Error(), "keeps_the_verified_one", held)
		s.audit(ctx, Event{
			Action: ActionRefuse, Failure: true, Reason: k.reason,
			Fields: map[string]any{"op": k.op, "why": why.Error(), "keeps_the_verified_one": held, "document_sha384": hex.EncodeToString(sum[:])},
		})
	}
	if held {
		return proto.Clone(k.last.value).(T), nil
	}
	prefix := fmt.Sprintf("%s/default: the signed %s is refused: %%w", k.op, k.label)
	if errors.Is(why, signedconfig.ErrOlder) || errors.Is(why, signedconfig.ErrConflict) {
		if seq, ok := k.seq.Held(); ok {
			// The mark is ahead of everything store@ shows (a restore of the store, a reset of the seq).
			return zero, fmt.Errorf(prefix+"; the mark %s holds seq %d: publish a %s with a higher seq (preferred), "+
				"or remove the mark on purpose, knowing that key@ then has no rollback protection until the next %s is verified",
				why, filepath.Join(s.cfg.StateDir, k.markFile), seq, k.label, k.label)
		}
	}
	return zero, fmt.Errorf(prefix, why)
}
