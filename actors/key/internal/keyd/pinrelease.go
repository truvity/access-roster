package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The PIN release between boards (ADR 0006, "Touch and PIN"; the wire format of kits/go/pinrelease). A locked key@
// asks its peers for the card PIN through the store; an unlocked peer that can verify the request answers with the PIN
// sealed to the request's one-time key. The PIN never reaches key@: the card drivers seal and open it. What key@ does
// is every check, on both sides, and the store writes:
//
//   - the other node is a peer of this boundary: the text names this boundary, and the signed KeyPlan's slot map
//     lists the node, with a wrapping key that the KeyPlan's recipients list (the node is "listed");
//   - nothing of it is revoked (ADR 0041, "Boards"): neither its pin-release key nor its wrapping key (by kid), nor its
//     recipient, read from KeyRevocation at each check and failing closed; and the same of this node, whose answer
//     its peers would refuse: a releasing node whose own keys are revoked refuses the request ("self-revoked") before
//     its driver is called, and seals, signs and audits no release;
//   - its pin-release slot is 87, and the attestation of the slot map, verified by this node's own card driver
//     (piv-go and the pinned Yubico anchors live there), shows that key, PIN never and touch never;
//   - the text is signed (ES384) by that key; a request is fresh (the time of its UUIDv7 id, within the kind's
//     maximum life) and its id is not reused; an answer is for this node's own request in flight.
//
// A request or an answer that fails a check is refused and is an audit fact, and a forged answer never reaches the
// card: the driver is given only an answer whose signature verified, so a compromised store@ cannot burn PIN tries.
//
// The card driver checks again, itself, what a compromised key@ must not be able to skip (#914): it verifies the
// signed KeyPlan that key@ hands it (the document key@ verified), and seals only to a request, or opens only an answer
// for the request it began, that the pin-release key of a peer the slot map lists signed. So a compromised key@ cannot
// obtain the PIN or spend the card's tries without a request or an answer that a listed peer card signed. The checks
// that need the store stay here: revocation, the freshness and the reuse of a request id. A compromised key@ can
// still use a peer key that is revoked but still listed, until a re-signed KeyPlan drops it.

// The kinds of the PIN release.
const (
	kindPinRequest = "PinReleaseRequest"
	kindPinRelease = "PinRelease"
	// pinReleasePurpose is the purpose of slot 87, the one card key that signs while the board is locked.
	pinReleasePurpose = "pin-release"
	pinReleaseSlot    = "87"
	// reasonPinRelease is the reason of the audit fact of a refused request or answer.
	reasonPinRelease = "pin-release"
	// targetRecipient is the target kind of a KeyRevocation that removes a board's recipient (ADR 0041, "Boards").
	targetRecipient = "recipient"
)

// The audit actions of the PIN release.
const (
	ActionPinRelease = "key.pin.release" // this node sealed its PIN to a peer's request
	ActionPinUnlock  = "key.pin.unlock"  // this node's driver took a PIN released by a peer
)

// The periods of the polling. planned: #1204 — watch the two kinds through store@'s Watch (served since #1414) when the
// Go store kit has a Watch client; until then key@ polls with List, backing off while nothing comes. It never polls with
// Get: store@ audits every refusal (ADR 0005), and a Get of an answer that is not written yet is a refusal.
const (
	pinPollFirst   = 500 * time.Millisecond
	pinPollLongest = 10 * time.Second
	// pinLockedRecheck is the longest wait of the releasing loop after a pass that stopped at a request because this node's
	// driver is locked. A person unlocks a board through the driver's admin socket and key@ is not told, so the loop is
	// what finds out; the look costs a refusal line in the driver's journal and no audit fact and no card operation (the
	// locked driver refuses before it reaches the card).
	pinLockedRecheck = 2 * time.Second
	// pinUnlockedRecheck is how often a node whose driver holds the PIN asks it again (a card that is gone restarts
	// the driver locked).
	pinUnlockedRecheck = 30 * time.Second
)

// maxPinPages is how many pages one listing of the PIN release kinds may read, as for KeyRevocation (maxRevocationPages):
// a listing that does not end is a store@ that is not answering as it should, and the pass fails instead of waiting.
const maxPinPages = 1000

var errPinListNotEnded = errors.New("PIN release: the listing did not end")

// pinClockSkew is how far ahead of this node's clock the time of a request id may be: the request was made on another
// node's clock, and time sync keeps the nodes close (the board units start after time-sync.target).
const pinClockSkew = 5 * time.Minute

// pinState is what the PIN release of this process remembers: the request ids it has handled, so that an id is
// answered once and a second text under a used id is refused.
type pinState struct {
	mu     sync.Mutex
	seen   map[string]seenRequest // by node and request id (seenKey)
	listed map[string]struct{}    // the request ids the last pass listed, to tell a request no pass has seen
	wake   chan struct{}          // a signal to the releasing loop that this node can answer now (wakeReleaser)
}

// wakeChan is the channel on which the releasing loop waits for a wake-up, made on first use.
func (p *pinState) wakeChan() chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wake == nil {
		p.wake = make(chan struct{}, 1)
	}
	return p.wake
}

// wakeReleaser tells the releasing loop to pass now and to start again from the short wait. It is called when this
// node has just become able to answer (its driver took a PIN, or was found unlocked), because the requests that a
// peer left open while this node was locked can be answered at once. It never blocks, and one signal is kept.
func (s *Server) wakeReleaser() {
	select {
	case s.pins.wakeChan() <- struct{}{}:
	default:
	}
}

// seenKey is the key of a request among those decided: its node and its id, so that one node's id never stands for
// another's.
func seenKey(r pinrelease.Request) string { return r.Node + "/" + r.ID }

type seenRequest struct {
	digest []byte
	at     time.Time // the time of the id, for forgetting it after the window
}

// pinRequestWindow is how long a request may be answered: the most the kind lets it live (kinds.yaml, 15 minutes).
func pinRequestWindow() time.Duration {
	k, ok := registry.KindByName(kindPinRequest)
	if !ok || k.TTLMax <= 0 {
		return 15 * time.Minute
	}
	return k.TTLMax
}

// peerRefusal is a check that a request or an answer failed: a word for the audit fact, and the field it names.
type peerRefusal struct {
	why string
}

func (p *peerRefusal) Error() string { return "pin release: " + p.why }

func refused(why string) error { return &peerRefusal{why: why} }

// peerKey runs the checks on the other node and returns its verified pin-release key. A store@ that cannot be read
// is an error that is not a refusal: the caller tries again later and audits nothing.
func (s *Server) peerKey(ctx context.Context, rc *revCache, plan *configv2alpha1.KeyPlan, node string) (*ecdsa.PublicKey, error) {
	if node == s.cfg.Node {
		return nil, refused("self")
	}
	var entry *configv2alpha1.NodeSlotMap
	for _, n := range plan.GetSlotMap() {
		if n.GetNode() == node {
			entry = n
		}
	}
	if entry == nil {
		return nil, refused("unlisted")
	}
	var wrap, rel *configv2alpha1.SlotKey
	for _, k := range entry.GetSlots() {
		switch k.GetPurpose() {
		case wrappingPurpose:
			wrap = k
		case pinReleasePurpose:
			rel = k
		}
	}
	if wrap == nil || rel == nil {
		return nil, refused("slot-map")
	}
	recipientID, err := spkiThumbprint(wrap.GetPublicKey())
	if err != nil {
		return nil, refused("slot-map")
	}
	listed, err := plannedRecipients(plan)
	if err != nil || !slices.Contains(listed, recipientID) {
		return nil, refused("unlisted")
	}
	pub, err := parseP384(rel.GetPublicKey())
	if err != nil {
		return nil, refused("slot-map")
	}
	kid, err := thumbprint(pub)
	if err != nil {
		return nil, refused("slot-map")
	}
	if why, err := s.peerRevoked(ctx, rc, kid, recipientID); err != nil {
		return nil, err
	} else if why != "" {
		return nil, refused("revoked")
	}
	if rel.GetSlot() != pinReleaseSlot || len(rel.GetAttestation()) == 0 {
		return nil, refused("slot-map")
	}
	res, err := s.driver.VerifyAttestation(ctx, connect.NewRequest(&keystorev2alpha1.VerifyAttestationRequest{
		Attestation: rel.GetAttestation(), AttestationSigner: rel.GetAttestationSigner(),
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnavailable {
			return nil, err
		}
		return nil, refused("attestation")
	}
	a := res.Msg
	if a.GetSlot() != pinReleaseSlot || a.GetPinPolicy() != "never" || a.GetTouchPolicy() != "never" || !bytes.Equal(a.GetSpkiDer(), rel.GetPublicKey()) {
		return nil, refused("attestation")
	}
	return pub, nil
}

// peerRevoked says which KeyRevocation stops a peer's PIN release: its pin-release key or its wrapping key by kid, or its
// recipient (ADR 0041, "Boards"). An unreadable store@ is an error: "not revoked" is verified, never assumed.
func (s *Server) peerRevoked(ctx context.Context, rc *revCache, kid, recipientID string) (string, error) {
	// One listing for the three ids: a Get of an id that is not revoked is a refusal that store@ audits.
	ids, err := s.revocationSet(ctx, rc)
	if err != nil {
		return "", unavailable(reasonStore)
	}
	for _, id := range []string{revocationID(targetKid, kid), revocationID(targetKid, recipientID), targetRecipient + "/" + recipientLabel(recipientID)} {
		if _, ok := ids[id]; ok {
			return id, nil
		}
	}
	return "", nil
}

// selfRevoked says why this node releases no PIN: "self-revoked" when KeyRevocation lists its own pin-release key or
// wrapping key by kid, or its recipient, the three that stop a peer (peerRevoked), and "self-keys" when it holds no
// pin-release or wrapping key to check. An unreadable store@ is an error, as for a peer.
func (s *Server) selfRevoked(ctx context.Context, rc *revCache) (string, error) {
	rel, okRel := s.keys[pinReleasePurpose]
	wrap, okWrap := s.keys[wrappingPurpose]
	if !okRel || !okWrap {
		return "self-keys", nil
	}
	why, err := s.peerRevoked(ctx, rc, rel.keyID, wrap.keyID)
	if err != nil {
		return "", err
	}
	if why != "" {
		slog.Warn("this node's own key is revoked: it releases no PIN", "revocation", why)
		return "self-revoked", nil
	}
	return "", nil
}

// verifySigned checks an ES384 signature over SHA-384 of a text.
func verifySigned(pub *ecdsa.PublicKey, text, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, pinrelease.Digest(text), sig)
}

// ownSigned checks that a text the card driver wrote and signed is signed by this node's pin-release key, as the
// KeyPlan names it: a driver that signs with another key is caught before the text is published. The driver signs
// these texts itself; its Sign refuses the pin-release purpose.
func (s *Server) ownSigned(text, sig []byte) bool {
	pk, ok := s.keys[pinReleasePurpose]
	return ok && verifySigned(pk.pub, text, sig)
}

// refusePin audits a refused request or answer once per distinct text and reason, and logs it. It carries names and
// ids, never a key or a sealed value.
func (s *Server) refusePin(ctx context.Context, op, node, id string, text []byte, why string) {
	key := "pin:" + op + ":" + base64.RawURLEncoding.EncodeToString(pinrelease.Digest(text)) + ":" + why
	if _, dup := s.reported.LoadOrStore(key, struct{}{}); dup {
		return
	}
	slog.Warn("a PIN release "+op+" is refused", "why", why, "node", node, "request", id)
	s.audit(ctx, pinRefusal(op, node, id, why))
}

// pinNameRE is the form of a name of the audit table's ident type, which a node and a request id of a fact must have.
var pinNameRE = regexp.MustCompile(`^[A-Za-z0-9._:/+=@~*-]{1,256}$`)

// pinName is a node or a request id of a PIN request as a fact may carry it. A peer writes both before anything is verified, and
// the request is refused for that very reason, so a name that is empty, long or of other characters would make the table refuse
// the fact of its refusal: it is written as its digest instead (h- and 16 hex digits of its SHA-256), which the operator can
// compute from the name, and an empty one is left out. A refusal is audited whatever else fails (ADR 0005).
func pinName(s string) (string, bool) {
	switch {
	case s == "":
		return "", false
	case pinNameRE.MatchString(s) && !strings.Contains(s, "@"): // an '@' may make an e-mail shape, which a record never carries
		return s, true
	}
	sum := sha256.Sum256([]byte(s))
	return "h-" + hex.EncodeToString(sum[:8]), true
}

// pinRefusal is the fact of a refused PIN request or answer.
func pinRefusal(op, node, id, why string) Event {
	fields := map[string]any{"op": op, "why": why}
	if n, ok := pinName(node); ok {
		fields["node"] = n
	}
	if n, ok := pinName(id); ok {
		fields["request"] = n
	}
	return Event{Action: ActionRefuse, Failure: true, Reason: reasonPinRelease, Fields: fields}
}

// PinPass is what one pass of the releasing side did. The loop decides its next wait from it (pinLoops).
type PinPass struct {
	Seen     int // the requests of peers and of this node that were listed
	New      int // the requests of peers that no pass listed before
	Answered int // the answers this pass wrote
	// Locked says that the pass stopped at a request because this node's driver holds no PIN. The request waits for a peer,
	// and for a person who unlocks this board by hand, which key@ is not told: the loop looks again sooner (pinLockedRecheck).
	Locked bool
}

// Progress says whether the next pass should come soon: a request that no pass has seen is worth a quick second look,
// and so is an answer, after which a peer's request may be next. A pass that only met the same unanswered requests
// again is not progress: counting those as progress made the loop poll every second for as long as a request stayed
// open, and each poll then cost store@ audit facts.
func (p PinPass) Progress() bool { return p.New > 0 || p.Answered > 0 }

// listed records the ids a pass listed and returns how many of a peer's requests were not listed by the pass before.
func (s *Server) listed(items []store.Item[*keyv2alpha1.PinReleaseRequest]) int {
	now := make(map[string]struct{}, len(items))
	fresh := 0
	s.pins.mu.Lock()
	defer s.pins.mu.Unlock()
	for _, it := range items {
		now[it.ID] = struct{}{}
		if _, ok := s.pins.listed[it.ID]; !ok && !strings.HasPrefix(it.ID, s.cfg.Node+"/") {
			fresh++
		}
	}
	s.pins.listed = now
	return fresh
}

// pinReleases lists the PinRelease answers. The answers of a few requests are a few items; a Get per request, the way
// this was first written, is a refusal of store@ for every request that has no answer yet, and store@ audits it.
func (s *Server) pinReleases(ctx context.Context) ([]store.Item[*keyv2alpha1.PinRelease], error) {
	var out []store.Item[*keyv2alpha1.PinRelease]
	token := ""
	for range maxPinPages {
		page, next, err := s.pinRels.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if next == "" {
			return out, nil
		}
		token = next
	}
	return nil, errPinListNotEnded
}

// ReleasePins is one pass of the releasing side: it answers each fresh, verified request of a peer, once. A node whose
// driver holds no PIN releases nothing (SealPin refuses) and leaves the requests to its peers. It says what it saw and
// what it answered.
func (s *Server) ReleasePins(ctx context.Context) (PinPass, error) {
	var pass PinPass
	// Every page: a flood of requests (a compromised store@ can write them) must not hide a real one behind it. A
	// request already decided costs a map lookup; the kind's short life bounds the rest.
	var items []store.Item[*keyv2alpha1.PinReleaseRequest]
	token, ended := "", false
	for range maxPinPages {
		page, next, err := s.pinReqs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return pass, unavailable(reasonStore)
		}
		items = append(items, page...)
		if next == "" {
			ended = true
			break
		}
		token = next
	}
	if !ended {
		return pass, unavailable(reasonStore)
	}
	pass.Seen, pass.New = len(items), s.listed(items)
	var released map[string]struct{} // the ids that have an answer, listed once, when a request needs it
	var plan *configv2alpha1.KeyPlan
	var planDoc []byte
	var selfWhy string
	selfChecked := false
	var rc revCache // the revocations this pass read, kept for revCacheLife
	for _, it := range items {
		text, sig := it.Value.GetText(), it.Value.GetSignatureDer()
		r, perr := pinrelease.ParseRequest(text)
		if perr != nil || it.ID != r.Node+"/"+r.ID {
			s.refusePin(ctx, "request", "", it.ID, text, "format")
			continue
		}
		if r.Node == s.cfg.Node {
			continue // this node's own request
		}
		if s.handled(ctx, r, text) {
			continue
		}
		if why := s.fresh(r); why != "" {
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, why)
			continue
		}
		if r.Boundary != s.cfg.Boundary {
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, "boundary")
			continue
		}
		if released == nil {
			answers, err := s.pinReleases(ctx)
			if err != nil {
				return pass, unavailable(reasonStore)
			}
			released = make(map[string]struct{}, len(answers))
			for _, a := range answers {
				released[a.ID] = struct{}{}
			}
		}
		if _, ok := released[it.ID]; ok {
			s.markSeen(r, text) // a peer has answered it: one answer per request id
			continue
		}
		// A revoked board releases nothing (ADR 0041, "Boards"): this node's own keys are checked as a peer's are, once a
		// pass, before the KeyPlan, the peer's checks or any call of the driver. Its requesters would refuse the answer,
		// but the release would be sealed, signed and audited as key.pin.release all the same.
		if !selfChecked {
			why, err := s.selfRevoked(ctx, &rc)
			if err != nil {
				return pass, err
			}
			selfWhy, selfChecked = why, true
		}
		if selfWhy != "" {
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, selfWhy)
			continue
		}
		if plan == nil {
			var err error
			if plan, planDoc, err = fetchVerifiedDoc(ctx, s, s.plan); err != nil {
				return pass, err
			}
		}
		pub, err := s.peerKey(ctx, &rc, plan, r.Node)
		var pr *peerRefusal
		switch {
		case errors.As(err, &pr):
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, pr.why)
			continue
		case err != nil:
			return pass, err
		}
		if !verifySigned(pub, text, sig) {
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, "signature")
			continue
		}
		written, err := s.answer(ctx, it.ID, r, text, sig, planDoc)
		if err != nil {
			if errors.Is(err, errNoPIN) {
				pass.Locked = true
				return pass, nil // locked here as well: a peer answers
			}
			if errors.As(err, &pr) {
				// The card driver refused what key@ verified: the two disagree, so the request gets no PIN here.
				s.markSeen(r, text)
				s.refusePin(ctx, "request", r.Node, r.ID, text, pr.why)
				continue
			}
			return pass, err
		}
		if written {
			pass.Answered++
		}
		s.markSeen(r, text)
	}
	s.forgetOld()
	return pass, nil
}

var errNoPIN = errors.New("this node's driver holds no PIN")

// driverChecks are the reasons with which the card driver refuses a request or an answer that it verified itself
// (the driver's pinrelease.go): its verdict on what key@ gave it, not a failure to try again.
var driverChecks = []string{"key_plan", "boundary", "peer", "signature", "request_text", "answer_text"}

// driverRefusal is a refusal of the card driver's own check, as a refusal of the request or answer; nil otherwise.
func driverRefusal(err error) error {
	reason, _ := refusal.Reason(err)
	if c := connect.CodeOf(err); (c == connect.CodeFailedPrecondition || c == connect.CodeInvalidArgument) && slices.Contains(driverChecks, reason) {
		return refused("driver-" + reason)
	}
	return nil
}

// answer seals this node's PIN to a verified request, signs the answer and writes it, after its audit fact is durable.
// The driver is given the request's signature and the KeyPlan document key@ verified, and verifies both itself.
func (s *Server) answer(ctx context.Context, id string, r pinrelease.Request, text, sig, planDoc []byte) (bool, error) {
	sealed, err := s.driver.SealPin(ctx, connect.NewRequest(&keystorev2alpha1.SealPinRequest{RequestText: text, RequestSignatureDer: sig, KeyPlan: planDoc}))
	if err != nil {
		if reason, _ := refusal.Reason(err); connect.CodeOf(err) == connect.CodeFailedPrecondition && (reason == "locked" || reason == "no_pin") {
			return false, errNoPIN
		}
		if rerr := driverRefusal(err); rerr != nil {
			return false, rerr
		}
		return false, fmt.Errorf("key-store driver seal: %w", err)
	}
	// The driver wrote and signed the answer; it is published only if it is this node's answer to this request.
	at, answerSig := sealed.Msg.GetAnswerText(), sealed.Msg.GetAnswerSignatureDer()
	a, err := pinrelease.ParseAnswer(at)
	if err != nil || a.Boundary != s.cfg.Boundary || a.Releaser != s.cfg.Node || a.Requester != r.Node || a.ID != r.ID ||
		!bytes.Equal(a.RequestSHA384, pinrelease.Digest(text)) || !s.ownSigned(at, answerSig) {
		return false, errors.New("key-store driver seal: the answer is not this node's answer to the request")
	}
	// The release is an effect on a secret: its fact is durable before the answer is written (ADR 0024, "Every
	// signature is an audit fact").
	if err := s.auditBlocking(ctx, Event{Action: ActionPinRelease, Fields: map[string]any{"node": r.Node, "request": r.ID}}); err != nil {
		return false, err
	}
	_, err = s.pinRels.Create(ctx, "", id, &keyv2alpha1.PinRelease{Text: at, SignatureDer: answerSig})
	switch {
	case errors.Is(err, store.ErrExists):
		return false, nil // another peer answered first
	case err != nil:
		return false, unavailable(reasonStore)
	}
	slog.Info("a PIN released to a peer", "node", r.Node, "request", r.ID)
	return true, nil
}

// fresh says why a request is not fresh: its id's time is older than the window, or later than this clock allows.
func (s *Server) fresh(r pinrelease.Request) string {
	at, err := pinrelease.UUIDv7Time(r.ID)
	if err != nil {
		return "format"
	}
	now := s.now()
	switch {
	case at.After(now.Add(pinClockSkew)):
		return "future"
	case now.Sub(at) > pinRequestWindow():
		return "stale"
	}
	return ""
}

// handled says whether this process has decided on the request id of this node already. The same text again is skipped; another
// text under a used id is a replay, refused and audited.
func (s *Server) handled(ctx context.Context, r pinrelease.Request, text []byte) bool {
	s.pins.mu.Lock()
	prev, ok := s.pins.seen[seenKey(r)]
	s.pins.mu.Unlock()
	if !ok {
		return false
	}
	if !bytes.Equal(prev.digest, pinrelease.Digest(text)) {
		s.refusePin(ctx, "request", r.Node, r.ID, text, "replayed")
	}
	return true
}

func (s *Server) markSeen(r pinrelease.Request, text []byte) {
	at, _ := pinrelease.UUIDv7Time(r.ID)
	s.pins.mu.Lock()
	defer s.pins.mu.Unlock()
	if s.pins.seen == nil {
		s.pins.seen = map[string]seenRequest{}
	}
	if _, ok := s.pins.seen[seenKey(r)]; !ok {
		s.pins.seen[seenKey(r)] = seenRequest{digest: pinrelease.Digest(text), at: at}
	}
}

// forgetOld drops the ids that are past the window and the clock skew: no request under them is fresh any more.
func (s *Server) forgetOld() {
	cut := s.now().Add(-pinRequestWindow() - pinClockSkew)
	s.pins.mu.Lock()
	defer s.pins.mu.Unlock()
	for id, r := range s.pins.seen {
		if r.at.Before(cut) {
			delete(s.pins.seen, id)
		}
	}
}

// The outcomes of RequestPin.
var (
	// ErrUnlocked is a driver that holds the PIN: there is nothing to ask for.
	ErrUnlocked = errors.New("the key-store driver holds the PIN")
	// ErrPINRefused is a released PIN that the card did not take, or a card that is not sent one: key@ asks no more,
	// because the card blocks after its retry count, and a person unlocks the board.
	ErrPINRefused = errors.New("the card did not take the released PIN")
	// errNoAnswer is a request that expired unanswered, or whose answer was refused.
	errNoAnswer = errors.New("no valid answer to the PIN release request")
)

// RequestPin is one PIN release request of a locked node: a one-time key and the request text from its driver, a signed
// request, and a wait for the answer of a peer, which is verified before the driver is given it.
func (s *Server) RequestPin(ctx context.Context) error {
	now := s.now()
	rid, err := pinrelease.NewID(now)
	if err != nil {
		return err
	}
	begin, err := s.driver.BeginPinRelease(ctx, connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: rid}))
	if err != nil {
		switch reason, _ := refusal.Reason(err); {
		case connect.CodeOf(err) == connect.CodeFailedPrecondition && reason == "unlocked":
			return ErrUnlocked
		case connect.CodeOf(err) == connect.CodeFailedPrecondition && reason == "pin_refused":
			return ErrPINRefused // the driver's stop after a refused PIN: a person unlocks the board
		}
		return fmt.Errorf("key-store driver begin: %w", err)
	}
	// The driver writes and signs the text, and keeps it for the answer: key@ publishes it only if it is the request it
	// asked for, signed by this node's pin-release key.
	text, sig := begin.Msg.GetRequestText(), begin.Msg.GetRequestSignatureDer()
	r, err := pinrelease.ParseRequest(text)
	if err != nil || r.Boundary != s.cfg.Boundary || r.Node != s.cfg.Node || r.ID != rid || !bytes.Equal(r.Ephemeral, begin.Msg.GetEphemeralPublic()) ||
		!s.ownSigned(text, sig) {
		return errors.New("key-store driver begin: the request is not this node's request")
	}
	id := r.Node + "/" + r.ID
	if _, err := s.pinReqs.Create(ctx, "", id, &keyv2alpha1.PinReleaseRequest{Text: text, SignatureDer: sig}); err != nil {
		return unavailable(reasonStore)
	}
	slog.Info("locked: asked the peers for the PIN", "request", r.ID)
	life := 5 * time.Minute
	if k, ok := registry.KindByName(kindPinRequest); ok && k.TTLDefault > 0 {
		life = k.TTLDefault
	}
	deadline := now.Add(life)
	wait := s.pinEvery(pinPollFirst)
	for {
		// The answer is looked for in a listing, never with a Get of its id: until a peer answers, the Get is a refusal
		// that store@ audits, and this loop asked every few seconds for the five minutes of the request's life.
		answers, err := s.pinReleases(ctx)
		if err != nil {
			slog.Warn("the PIN release answer cannot be read", "err", err)
		}
		for _, a := range answers {
			if a.ID == id {
				return s.takeAnswer(ctx, r, text, a.Value)
			}
		}
		if !s.now().Before(deadline) {
			return errNoAnswer
		}
		if _, err := s.pinSleep(ctx, wait, nil); err != nil {
			return err
		}
		wait = min(2*wait, s.pinEvery(pinPollLongest))
	}
}

// takeAnswer verifies the answer to this node's request and only then gives it to the driver. A refused answer is an
// audit fact and is never a PIN attempt.
func (s *Server) takeAnswer(ctx context.Context, r pinrelease.Request, text []byte, v *keyv2alpha1.PinRelease) error {
	at, sig := v.GetText(), v.GetSignatureDer()
	a, err := pinrelease.ParseAnswer(at)
	if err != nil {
		s.refusePin(ctx, "answer", "", r.ID, at, "format")
		return errNoAnswer
	}
	if a.Boundary != s.cfg.Boundary || a.Requester != s.cfg.Node || a.ID != r.ID || !bytes.Equal(a.RequestSHA384, pinrelease.Digest(text)) {
		s.refusePin(ctx, "answer", a.Releaser, r.ID, at, "not-this-request")
		return errNoAnswer
	}
	plan, planDoc, err := fetchVerifiedDoc(ctx, s, s.plan)
	if err != nil {
		return err
	}
	pub, err := s.peerKey(ctx, nil, plan, a.Releaser)
	var pr *peerRefusal
	switch {
	case errors.As(err, &pr):
		s.refusePin(ctx, "answer", a.Releaser, r.ID, at, pr.why)
		return errNoAnswer
	case err != nil:
		return err
	}
	if !verifySigned(pub, at, sig) {
		s.refusePin(ctx, "answer", a.Releaser, r.ID, at, "signature")
		return errNoAnswer
	}
	_, err = s.driver.FinishPinRelease(ctx, connect.NewRequest(&keystorev2alpha1.FinishPinReleaseRequest{
		AnswerText: at, AnswerSignatureDer: sig, KeyPlan: planDoc,
	}))
	if err != nil {
		reason, _ := refusal.Reason(err)
		s.refusePin(ctx, "answer", a.Releaser, r.ID, at, "driver-"+reason)
		switch reason {
		case "pin", "pin_retries", "pin_blocked", "pin_refused":
			return ErrPINRefused
		case "unlocked":
			return ErrUnlocked
		}
		return errNoAnswer
	}
	s.audit(ctx, Event{Action: ActionPinUnlock, Fields: map[string]any{"releaser": a.Releaser, "request": r.ID}})
	slog.Info("unlocked by a peer's PIN release", "releaser", a.Releaser, "request", r.ID)
	return nil
}

// pinSleep waits for d, for a signal on wake (a nil channel never signals) or for the end of ctx. It says whether the wait
// ended on the signal. Tests replace it with a clock they move (Config.PinSleep).
func (s *Server) pinSleep(ctx context.Context, d time.Duration, wake <-chan struct{}) (bool, error) {
	if s.cfg.PinSleep != nil {
		return s.cfg.PinSleep(ctx, d, wake)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-wake:
		return true, nil
	case <-t.C:
		return false, nil
	}
}

// releaseLoop runs the passes of the releasing side until ctx ends. The wait between passes starts short and doubles up
// to pinPollLongest after every pass that made no progress (PinPass.Progress), and starts again from the short one
// after a pass that did, or when wakeReleaser says this node can answer now.
//
// A request that this node cannot answer (its driver is locked too, or a peer has not been heard) stays open for up to
// the kind's life. The loop must not poll it at the short period all that time: it passed every second, and every pass
// cost refusals at store@. Now it sees such a request, tries it, and backs off; what reaches a request sooner is a new
// request (the next pass lists it, at most pinPollLongest later, which is what an idle board always waited) and this
// node becoming able to answer (the wake).
func (s *Server) releaseLoop(ctx context.Context) {
	first, longest := s.pinEvery(pinPollFirst), s.pinEvery(pinPollLongest)
	wait := first
	wake := s.pins.wakeChan()
	for {
		pass, err := s.ReleasePins(ctx)
		if err != nil {
			slog.Warn("PIN release pass failed", "err", err)
		}
		switch {
		case pass.Progress():
			wait = first
		case pass.Locked:
			// Stopped at a request because this driver is locked: a person may unlock it any moment, unseen by key@.
			wait = min(2*wait, s.pinEvery(pinLockedRecheck))
		default:
			wait = min(2*wait, longest)
		}
		woken, serr := s.pinSleep(ctx, wait, wake)
		if serr != nil {
			return
		}
		if woken {
			wait = first
		}
	}
}

// requestLoop runs the requests of this node while its driver is locked, until ctx ends or a person must unlock the board.
// When a PIN has just unlocked the node, or the driver is found unlocked, it wakes the releasing loop (wakeReleaser).
func (s *Server) requestLoop(ctx context.Context) {
	wait := s.pinEvery(pinPollFirst)
	unlocked := false
	for {
		err := s.RequestPin(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			// A peer's PIN unlocked this node: the requests that peers left open meanwhile can be answered now.
			s.wakeReleaser()
			unlocked = true
			wait = s.pinEvery(pinUnlockedRecheck)
		case errors.Is(err, ErrUnlocked):
			if !unlocked {
				s.wakeReleaser() // found unlocked, by a person's unlock for instance
				unlocked = true
			}
			wait = s.pinEvery(pinUnlockedRecheck)
		case errors.Is(err, ErrPINRefused):
			// The stop here is in memory; the card driver keeps its own in its state directory, so a restart of either
			// asks again but sends the card no released PIN (pin_refused) until a person unlocks the board.
			slog.Error("the card did not take a released PIN: no more PIN release requests; unlock the board with sluis node unlock")
			return
		default:
			slog.Warn("PIN release request ended without a PIN", "err", err)
			unlocked = false
			wait = min(2*wait, s.pinEvery(pinPollLongest))
		}
		if _, err := s.pinSleep(ctx, wait, nil); err != nil {
			return
		}
	}
}

// pinLoops runs both sides until ctx ends: the releasing pass, backing off while there are no requests, and the
// requests of this node while its driver is locked. They run only when the KeyPlan names the pin-release purpose and
// the key store attests (a card); a
// released PIN that the card refused stops this node's requests for good (a person unlocks it).
func (s *Server) pinLoops(ctx context.Context) {
	if _, ok := s.keys[pinReleasePurpose]; !ok {
		return
	}
	// A store that does not attest (software) holds no PIN and cannot verify a peer's attestation: it takes no part.
	caps, err := s.driver.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil || !caps.Msg.GetAttests() {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.releaseLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		s.requestLoop(ctx)
	}()
	wg.Wait()
}

// pinEvery scales a period of the PIN release by the configuration (tests run it fast).
func (s *Server) pinEvery(d time.Duration) time.Duration {
	if s.cfg.PinReleaseScale > 0 {
		return time.Duration(float64(d) * s.cfg.PinReleaseScale)
	}
	return d
}

// slotMapEntry is this node's entry of the slot map, as the check command prints it for the harness that signs the
// KeyPlan (deploy/boards/prepare.sh): the slot, purpose and public key of each key of the KeyPlan that the key store
// holds, and the attestation of each slot when the store attests.
type slotMapEntry struct {
	Node  string        `json:"node"`
	Slots []slotMapSlot `json:"slots"`
}

type slotMapSlot struct {
	Slot              string `json:"slot"`
	Purpose           string `json:"purpose"`
	PublicKey         string `json:"public_key"`
	Attestation       string `json:"attestation,omitempty"`
	AttestationSigner string `json:"attestation_signer,omitempty"`
}

// slotMapLine is the line of the check command: "slot map: " and the entry as one line of JSON (which is YAML).
func (s *Server) slotMapLine(ctx context.Context, plan *configv2alpha1.KeyPlan) (string, error) {
	e := slotMapEntry{Node: s.cfg.Node, Slots: []slotMapSlot{}}
	enc := base64.RawURLEncoding
	for _, p := range plan.GetPurposes() {
		if _, ok := planAlgorithm(p.GetAlgorithm()); !ok || p.GetSlot() == "" {
			continue
		}
		res, err := s.driver.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: p.GetPurpose()}))
		if connect.CodeOf(err) == connect.CodeNotFound {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("key-store driver public key %s: %w", p.GetPurpose(), err)
		}
		if _, err := x509.ParsePKIXPublicKey(res.Msg.GetSpkiDer()); err != nil {
			return "", fmt.Errorf("key-store driver public key %s: does not parse", p.GetPurpose())
		}
		sl := slotMapSlot{Slot: p.GetSlot(), Purpose: p.GetPurpose(), PublicKey: enc.EncodeToString(res.Msg.GetSpkiDer())}
		att, err := s.driver.Attest(ctx, connect.NewRequest(&keystorev2alpha1.AttestRequest{Purpose: p.GetPurpose()}))
		if err == nil {
			sl.Attestation = enc.EncodeToString(att.Msg.GetAttestation())
			sl.AttestationSigner = enc.EncodeToString(att.Msg.GetAttestationSigner())
		}
		e.Slots = append(e.Slots, sl)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return "slot map: " + string(b), nil
}
