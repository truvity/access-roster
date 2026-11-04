package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
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
//     recipient, read from KeyRevocation at each check and failing closed;
//   - its pin-release slot is 87, and the attestation of the slot map, verified by this node's own card driver
//     (piv-go and the pinned Yubico anchors live there), shows that key, PIN never and touch never;
//   - the text is signed (ES384) by that key; a request is fresh (the time of its UUIDv7 id, within the kind's
//     maximum life) and its id is not reused; an answer is for this node's own request in flight.
//
// A request or an answer that fails a check is refused and is an audit fact, and a forged answer never reaches the
// card: the driver is given only an answer whose signature verified, so a compromised store@ cannot burn PIN tries.

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
// Go store kit has a Watch client; until then key@ polls with List and Get, backing off while nothing comes.
const (
	pinPollFirst   = 500 * time.Millisecond
	pinPollLongest = 10 * time.Second
	// pinUnlockedRecheck is how often a node whose driver holds the PIN asks it again (a card that is gone restarts
	// the driver locked).
	pinUnlockedRecheck = 30 * time.Second
)

// pinClockSkew is how far ahead of this node's clock the time of a request id may be: the request was made on another
// node's clock, and time sync keeps the nodes close (the board units start after time-sync.target).
const pinClockSkew = 5 * time.Minute

// pinState is what the PIN release of this process remembers: the request ids it has handled, so that an id is
// answered once and a second text under a used id is refused.
type pinState struct {
	mu   sync.Mutex
	seen map[string]seenRequest // by request id
}

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
func (s *Server) peerKey(ctx context.Context, plan *configv2alpha1.KeyPlan, node string) (*ecdsa.PublicKey, error) {
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
	if why, err := s.peerRevoked(ctx, kid, recipientID); err != nil {
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
func (s *Server) peerRevoked(ctx context.Context, kid, recipientID string) (string, error) {
	for _, id := range []string{revocationID(targetKid, kid), revocationID(targetKid, recipientID), targetRecipient + "/" + recipientLabel(recipientID)} {
		if _, err := s.revocations.Get(ctx, "", id); err == nil {
			return id, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return "", unavailable(reasonStore)
		}
	}
	return "", nil
}

// verifySigned checks an ES384 signature over SHA-384 of a text.
func verifySigned(pub *ecdsa.PublicKey, text, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, pinrelease.Digest(text), sig)
}

// signPinText signs a text with this node's pin-release key, which signs whether or not the driver holds the PIN.
func (s *Server) signPinText(ctx context.Context, text []byte) ([]byte, error) {
	res, err := s.driver.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{
		Purpose: pinReleasePurpose, Digest: pinrelease.Digest(text), Algorithm: algES384,
	}))
	if err != nil {
		return nil, err
	}
	pk, ok := s.keys[pinReleasePurpose]
	if !ok || !verifySigned(pk.pub, text, res.Msg.GetSignatureDer()) {
		return nil, errors.New("the pin-release signature does not verify with the key of the plan")
	}
	return res.Msg.GetSignatureDer(), nil
}

// refusePin audits a refused request or answer once per distinct text and reason, and logs it. It carries names and
// ids, never a key or a sealed value.
func (s *Server) refusePin(ctx context.Context, op, node, id string, text []byte, why string) {
	key := "pin:" + op + ":" + base64.RawURLEncoding.EncodeToString(pinrelease.Digest(text)) + ":" + why
	if _, dup := s.reported.LoadOrStore(key, struct{}{}); dup {
		return
	}
	slog.Warn("a PIN release "+op+" is refused", "why", why, "node", node, "request", id)
	s.audit(ctx, Event{Action: ActionRefuse, Failure: true, Reason: reasonPinRelease,
		Fields: map[string]any{"op": op, "why": why, "node": node, "request": id}})
}

// ReleasePins is one pass of the releasing side: it answers each fresh, verified request of a peer, once. A node whose
// driver holds no PIN releases nothing (SealPin refuses) and leaves the requests to its peers. It returns how many
// requests it saw.
func (s *Server) ReleasePins(ctx context.Context) (int, error) {
	items, _, err := s.pinReqs.List(ctx, "", store.PageSize(200))
	if err != nil {
		return 0, unavailable(reasonStore)
	}
	var plan *configv2alpha1.KeyPlan
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
		if _, err := s.pinRels.Get(ctx, "", it.ID); err == nil {
			s.markSeen(r, text) // a peer has answered it: one answer per request id
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return len(items), unavailable(reasonStore)
		}
		if plan == nil {
			if plan, err = fetchVerified(ctx, s, s.plan); err != nil {
				return len(items), err
			}
		}
		pub, err := s.peerKey(ctx, plan, r.Node)
		var pr *peerRefusal
		switch {
		case errors.As(err, &pr):
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, pr.why)
			continue
		case err != nil:
			return len(items), err
		}
		if !verifySigned(pub, text, sig) {
			s.markSeen(r, text)
			s.refusePin(ctx, "request", r.Node, r.ID, text, "signature")
			continue
		}
		if err := s.answer(ctx, it.ID, r, text); err != nil {
			if errors.Is(err, errNoPIN) {
				return len(items), nil // locked here as well: a peer answers
			}
			return len(items), err
		}
		s.markSeen(r, text)
	}
	s.forgetOld()
	return len(items), nil
}

var errNoPIN = errors.New("this node's driver holds no PIN")

// answer seals this node's PIN to a verified request, signs the answer and writes it, after its audit fact is durable.
func (s *Server) answer(ctx context.Context, id string, r pinrelease.Request, text []byte) error {
	sealed, err := s.driver.SealPin(ctx, connect.NewRequest(&keystorev2alpha1.SealPinRequest{RequestText: text}))
	if err != nil {
		if reason, _ := refusal.Reason(err); connect.CodeOf(err) == connect.CodeFailedPrecondition && (reason == "locked" || reason == "no_pin") {
			return errNoPIN
		}
		return fmt.Errorf("key-store driver seal: %w", err)
	}
	at, err := pinrelease.AnswerText(pinrelease.Answer{
		Boundary: s.cfg.Boundary, Releaser: s.cfg.Node, Requester: r.Node, ID: r.ID, RequestSHA384: pinrelease.Digest(text),
		Ephemeral: sealed.Msg.GetReleaserPublic(), Sealed: sealed.Msg.GetSealed(),
	})
	if err != nil {
		return err
	}
	sig, err := s.signPinText(ctx, at)
	if err != nil {
		return err
	}
	// The release is an effect on a secret: its fact is durable before the answer is written (ADR 0024, "Every
	// signature is an audit fact").
	if err := s.auditBlocking(ctx, Event{Action: ActionPinRelease, Fields: map[string]any{"node": r.Node, "request": r.ID}}); err != nil {
		return err
	}
	_, err = s.pinRels.Create(ctx, "", id, &keyv2alpha1.PinRelease{Text: at, SignatureDer: sig})
	switch {
	case errors.Is(err, store.ErrExists):
		return nil // another peer answered first
	case err != nil:
		return unavailable(reasonStore)
	}
	slog.Info("a PIN released to a peer", "node", r.Node, "request", r.ID)
	return nil
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

// handled says whether this process has decided on the request id already. The same text again is skipped; another
// text under a used id is a replay, refused and audited.
func (s *Server) handled(ctx context.Context, r pinrelease.Request, text []byte) bool {
	s.pins.mu.Lock()
	prev, ok := s.pins.seen[r.ID]
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
	if _, ok := s.pins.seen[r.ID]; !ok {
		s.pins.seen[r.ID] = seenRequest{digest: pinrelease.Digest(text), at: at}
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

// RequestPin is one PIN release request of a locked node: a one-time key from its driver, a signed request, and a wait
// for the answer of a peer, which is verified before the driver is given it.
func (s *Server) RequestPin(ctx context.Context) error {
	begin, err := s.driver.BeginPinRelease(ctx, connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{}))
	if err != nil {
		if reason, _ := refusal.Reason(err); connect.CodeOf(err) == connect.CodeFailedPrecondition && reason == "unlocked" {
			return ErrUnlocked
		}
		return fmt.Errorf("key-store driver begin: %w", err)
	}
	now := s.now()
	rid, err := pinrelease.NewID(now)
	if err != nil {
		return err
	}
	r := pinrelease.Request{Boundary: s.cfg.Boundary, Node: s.cfg.Node, ID: rid, Ephemeral: begin.Msg.GetEphemeralPublic()}
	text, err := pinrelease.RequestText(r)
	if err != nil {
		return err
	}
	sig, err := s.signPinText(ctx, text)
	if err != nil {
		return fmt.Errorf("sign the PIN release request: %w", err)
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
	wait := pinPollFirst
	for {
		it, err := s.pinRels.Get(ctx, "", id)
		switch {
		case err == nil:
			return s.takeAnswer(ctx, r, text, it.Value)
		case !errors.Is(err, store.ErrNotFound):
			slog.Warn("the PIN release answer cannot be read", "err", err)
		}
		if !s.now().Before(deadline) {
			return errNoAnswer
		}
		if err := sleep(ctx, wait); err != nil {
			return err
		}
		wait = min(2*wait, pinPollLongest)
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
	plan, err := fetchVerified(ctx, s, s.plan)
	if err != nil {
		return err
	}
	pub, err := s.peerKey(ctx, plan, a.Releaser)
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
		RequestText: text, ReleaserPublic: a.Ephemeral, Sealed: a.Sealed,
	}))
	if err != nil {
		reason, _ := refusal.Reason(err)
		s.refusePin(ctx, "answer", a.Releaser, r.ID, at, "driver-"+reason)
		switch reason {
		case "pin", "pin_retries", "pin_blocked":
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

// sleep waits for d or the end of ctx.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
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
		wait := s.pinEvery(pinPollFirst)
		for {
			n, err := s.ReleasePins(ctx)
			if err != nil {
				slog.Warn("PIN release pass failed", "err", err)
			}
			if n > 0 {
				wait = s.pinEvery(pinPollFirst)
			} else {
				wait = min(2*wait, s.pinEvery(pinPollLongest))
			}
			if sleep(ctx, wait) != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		wait := s.pinEvery(pinPollFirst)
		for {
			err := s.RequestPin(ctx)
			switch {
			case ctx.Err() != nil:
				return
			case err == nil:
				wait = s.pinEvery(pinUnlockedRecheck)
			case errors.Is(err, ErrUnlocked):
				wait = s.pinEvery(pinUnlockedRecheck)
			case errors.Is(err, ErrPINRefused):
				slog.Error("the card did not take a released PIN: no more PIN release requests; unlock the board with sluis node unlock")
				return
			default:
				slog.Warn("PIN release request ended without a PIN", "err", err)
				wait = min(2*wait, s.pinEvery(pinPollLongest))
			}
			if sleep(ctx, wait) != nil {
				return
			}
		}
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
