package writerd

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// writerName is the name policy knows the writer by (decision D-6: the audit pieces are principals).
const writerName = "writer"

// accepted is a message that passed the checks, with the tenant it is routed to.
type accepted struct {
	d      *transportv2alpha1.Delivery
	info   recordInfo
	tenant string
}

// processBatch handles one batch of deliveries to the end: it sorts them into duplicates, refusals and records,
// seals the records, writes the log, and only then acknowledges every delivery of the batch. A failure before the
// first object is written is returned plain, and the stream is opened again; one after it is fatal.
func (s *Server) processBatch(ctx context.Context, ds []*transportv2alpha1.Delivery) error {
	now := s.now()
	nowMS := now.UnixMilli()
	trust := s.clockTrust(now)
	var (
		acc     []accepted
		refused []refusedMessage
		dupes   int
		inBatch = map[string]struct{}{}
		grants  = grantCache{}
	)
	for _, d := range ds {
		m := d.GetMessage()
		if _, twice := inBatch[m.GetUid()]; twice {
			dupes++
			continue
		}
		info, rej := s.chk.check(m.GetUid(), d.GetEmitter(), m.GetRecord(), len(m.GetUsage()))
		if rej != nil && rej.Reason == reasonRetry {
			// The validation did not finish in time. A slow moment (a re-sync, a loaded CPU) must not take a legitimate record out
			// of the log, so the first attempts give the batch back with a loud error and the transport delivers it again;
			// only a record that times out maxSlowAttempts times is refused as it would be for a schema it fails.
			n := s.slowAttempt(m.GetUid())
			slog.Error("the schema validation of a record did not finish in time", "uid", bounded(m.GetUid()), "attempt", n, "of", maxSlowAttempts)
			if n < maxSlowAttempts {
				return fmt.Errorf("validation of a record did not finish in time (attempt %d of %d): the batch is delivered again", n, maxSlowAttempts)
			}
			rej = &rejection{reasonSchema, "record"}
		}
		if rej == nil {
			rej = timeRefusal(info, m.GetUid(), nowMS, trust.ok)
		}
		if rej != nil {
			refused = append(refused, refusedMessage{d, rej})
			continue
		}
		// Only a message the checks took is looked up, and by then its time is inside the window: a refusal never
		// reads a segment, so a damaged one cannot make a message that would be quarantined fatal.
		seen, err := s.state.seenID(ctx, m.GetUid())
		if err != nil {
			if errors.Is(err, ErrSeenSegment) {
				return &fatalError{err} // an id that cannot be looked up is never taken as new
			}
			return fmt.Errorf("look up a record id: %w", err)
		}
		if seen {
			dupes++
			continue
		}
		tenant := info.tenant
		if tenant == "" {
			tenant = s.defaultTenant // REQ-AUDIT-020, 0029: a record of no tenant belongs to the operator's own
		}
		inBatch[m.GetUid()] = struct{}{}
		acc = append(acc, accepted{d, info, tenant})
	}

	// A refusal is reported before anything is acknowledged: it is never silently dropped.
	for _, r := range refused {
		if err := s.quarantine(ctx, grants, r, nowMS); err != nil {
			return fmt.Errorf("report a refused message: %w", err)
		}
	}
	// A batch that took no record but refused some is sealed too: the seal entry inside the tree is the signed trace that
	// the writer refused messages, with how many and why, so a catalogue older than the emitters, which refuses every
	// record, cannot stop the log without a trace. A batch of repeats alone is not: an idle log signs nothing (0029).
	if len(refused) > 0 {
		slog.Error("an audit batch refused messages", "refused", len(refused), "taken", len(acc), "reasons", reasonCounts(refused))
	}
	if len(acc) > 0 || len(refused) > 0 {
		entries, err := s.sealEntries(ctx, grants, acc, batchCounts{len(acc), dupes, len(refused), reasonCounts(refused), trust.timeChecks()}, nowMS)
		if err != nil {
			return err
		}
		ids := make([]string, len(acc))
		for i, a := range acc {
			ids[i] = a.info.uid
		}
		if err := s.write(ctx, entries, ids, nowMS, trust.ok); err != nil {
			return &fatalError{err}
		}
	}
	// An empty batch is never sealed, so an idle log signs nothing (0029).
	return s.ack(ctx, ds)
}

// reasonCounts counts the refused messages of a batch by the reason of their refusal.
func reasonCounts(refused []refusedMessage) map[string]int {
	if len(refused) == 0 {
		return nil
	}
	out := map[string]int{}
	for _, r := range refused {
		out[r.rej.Reason]++
	}
	return out
}

type refusedMessage struct {
	d   *transportv2alpha1.Delivery
	rej *rejection
}

// grantCache holds the sealed grants one batch has asked policy for, by tenant, that carry no expiry and so cannot be
// kept: a grant with an expiry is kept by the writer (heldGrant) and not here.
type grantCache map[string][]byte

// grantMargin is how long before its expiry the writer stops presenting a grant it holds (ADR 0007, "Sealed grants":
// a grant is reusable for about 60 seconds). key@ judges the expiry on its own clock and allows a skew of five seconds
// either way, so a grant that the writer still presents when it is about to die could be refused in the middle of a
// batch; ten seconds is the room for that, for a batch that began just before the margin, and for a clock that is a
// little apart from policy's. The writer therefore makes one decision about every 50 seconds when it is busy.
const grantMargin = 10 * time.Second

// heldGrant is a grant the writer keeps for a tenant until it nears its expiry.
type heldGrant struct {
	sealed []byte
	// until is the wall-clock time after which the grant is no longer presented: policy's expiry less grantMargin.
	until time.Time
	// monoUntil bounds the same on the clock that does not step, counted from when the grant arrived, so that a wall
	// clock set back cannot keep a grant past its life.
	monoUntil time.Duration
}

// usable says whether the writer may still present the grant.
func (h heldGrant) usable(now time.Time, mono time.Duration) bool {
	return len(h.sealed) > 0 && now.Before(h.until) && mono < h.monoUntil
}

// grantFor returns the grant to seal a tenant's evidence with. The writer keeps the grant policy gave it, for the
// grant's life less grantMargin, and presents it to key@ for every seal of every batch in that time; so a batch
// whose records are the by-products of an earlier decision costs no decision of its own, and an idle log goes quiet
// (ADR 0007: "reusable for about 60 seconds"; ADR 0029: none when idle). A refused, expired or denied grant is not
// kept, a restart holds none, and nothing durable holds one.
func (s *Server) grantFor(ctx context.Context, c grantCache, tenant string) ([]byte, error) {
	if h, ok := s.held[tenant]; ok {
		if h.usable(s.now(), s.mono()) {
			return h.sealed, nil
		}
		delete(s.held, tenant)
	}
	if g, ok := c[tenant]; ok {
		return g, nil
	}
	g, err := s.grant(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if g.expires.IsZero() {
		c[tenant] = g.sealed // policy named no expiry: the grant serves this batch only
		return g.sealed, nil
	}
	if s.held == nil {
		s.held = map[string]heldGrant{}
	}
	// The expiry is policy's word: the grant is kept for the life it states less the margin, counted from now on both
	// clocks, and never for more than a grant may live. A far-future expiry therefore buys nothing; key@ judges the
	// real one.
	life := min(g.expires.Sub(s.now()), maxGrantLife) - grantMargin
	if life <= 0 {
		c[tenant] = g.sealed // it dies before it could be reused: it serves this batch only
		return g.sealed, nil
	}
	s.held[tenant] = heldGrant{sealed: g.sealed, until: s.now().Add(life), monoUntil: s.mono() + life}
	return g.sealed, nil
}

// reasonGrant is the word key@ refuses with when the grant is missing, unreadable, for another holder, tenant or
// operation, or expired (permission_denied/grant, actors/key/internal/keyd/grant.go, checkGrant).
const reasonGrant = "grant"

// dropGrant forgets the grant held for a tenant, after key@ refused it: the next seal asks policy again. Only a refusal
// that names the grant drops it. Any other refusal (a tenant whose evidence key is gone, a rule) says nothing against
// the grant, and dropping it would cost one decision and one record for every retry of a batch that cannot be sealed.
func (s *Server) dropGrant(tenant string, err error) {
	if r, ok := refusal.Reason(err); ok && r == reasonGrant {
		delete(s.held, tenant)
	}
}

// quarantineKind is the kind of the address a refused message is sealed at; the id is
// <project>/quarantine/<log>/<SHA-384 of the message>.
const quarantineKind = "audit-quarantine"

// quarantine keeps a refused message until an operator releases it (0029, "Sealing": quarantined and reported; 0030:
// not lost). The whole message, record and usage parts as the transport delivered them, is sealed under the
// evidence key of the tenant its record names (the operator's own when the record names none or cannot be read),
// with a grant from policy, and written once to quarantine/<SHA-384>. Beside the envelope the object holds the
// reason, the field path, the emitter, the size and the digest in clear, and no value of the record: a record that
// fails its checks may hold what 0030 keeps out of a record. The caller acknowledges only after this returns. The
// object is named by the digest, so a message delivered again is kept once.
func (s *Server) quarantine(ctx context.Context, grants grantCache, r refusedMessage, nowMS int64) error {
	m := r.d.GetMessage()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return err
	}
	sum := sha512.Sum384(raw)
	name := hexOf(sum[:])
	tenant := recordTenant(m.GetRecord())
	if tenant == "" {
		tenant = s.defaultTenant
	}
	g, err := s.grantFor(ctx, grants, tenant)
	if err != nil {
		return err
	}
	res, err := s.keys.Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{
		Purpose:   evidencePurpose,
		Address:   &typev2alpha1.Address{Kind: quarantineKind, Tenant: tenant, Id: SealID(s.project, "quarantine", s.logID, name)},
		Plaintext: raw,
		Grant:     g,
	}))
	if err != nil {
		s.dropGrant(tenant, err)
		return fmt.Errorf("seal a refused message: %w", err)
	}
	body, err := audit.Canonical(map[string]any{
		"at": nowMS, "emitter": bounded(r.d.GetEmitter()), "path": r.rej.Path, "reason": r.rej.Reason,
		"sealed": base64.StdEncoding.EncodeToString(res.Msg.GetEnvelope()),
		"sha384": name, "size": int64(len(raw)), "tenant": tenant, "uid": bounded(m.GetUid()),
	})
	if err != nil {
		return err
	}
	slog.Error("an audit message was refused and quarantined", "reason", r.rej.Reason, "path", r.rej.Path,
		"emitter", bounded(r.d.GetEmitter()), "uid", bounded(m.GetUid()), "sha384", name)
	err = s.blob.create(ctx, "quarantine/"+name, body)
	if errors.Is(err, errExists) {
		return nil
	}
	return err
}

// recordTenant reads metadata.tenant_uid from a record that parses, or "".
func recordTenant(rec []byte) string {
	v, err := parseStrict(rec)
	if err != nil {
		return ""
	}
	root, _ := v.(map[string]any)
	md, _ := root["metadata"].(map[string]any)
	if t, ok := md["tenant_uid"].(string); ok && tenantID(t) {
		return t
	}
	return ""
}

// sealEntries seals each record under its tenant's evidence key, with a grant from policy for the batch, and
// returns the entries of the batch in order, the seal entry last.
func (s *Server) sealEntries(ctx context.Context, grants grantCache, acc []accepted, n batchCounts, nowMS int64) ([][]byte, error) {
	entries := make([][]byte, 0, len(acc)+1)
	for _, a := range acc {
		g, err := s.grantFor(ctx, grants, a.tenant)
		if err != nil {
			return nil, err
		}
		res, err := s.keys.Seal(ctx, connect.NewRequest(&keyv2alpha1.SealRequest{
			Purpose:   evidencePurpose,
			Address:   &typev2alpha1.Address{Kind: SealKind, Tenant: a.tenant, Id: SealID(s.project, auditKind, s.logID, a.info.uid)},
			Plaintext: a.d.GetMessage().GetRecord(),
			Grant:     g,
		}))
		if err != nil {
			s.dropGrant(a.tenant, err)
			return nil, fmt.Errorf("seal a record: %w", err)
		}
		e, err := recordEntry(a.info, a.tenant, res.Msg.GetEnvelope(), s.cfg.Instance, nowMS)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	seal, err := sealEntry(n, s.cfg.Instance, nowMS, s.clock())
	if err != nil {
		return nil, err
	}
	return append(entries, seal), nil
}

// policyGrant is the grant policy gave, with the time it expires.
type policyGrant struct {
	sealed []byte
	// expires is the expiry policy states, or the zero time when the answer names none.
	expires time.Time
}

// maxGrantLife is the longest a grant lives (ADR 0007, "Sealed grants"; key@ refuses a longer one).
const maxGrantLife = 60 * time.Second

// grant asks policy for the grant that lets the writer seal a tenant's evidence (decision D-6: action audit.seal,
// a built-in permit of the writer). A refusal is an error: the writer does not seal without one.
func (s *Server) grant(ctx context.Context, tenant string) (policyGrant, error) {
	res, err := s.pol.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action:      "audit.seal",
		Principal:   &policyv2alpha1.EntityRef{Type: "Actor", Id: writerName},
		Resource:    &policyv2alpha1.EntityRef{Type: "Boundary", Id: s.cfg.Boundary},
		Tenant:      tenant,
		Actor:       &policyv2alpha1.ActorFacts{Name: writerName},
		GrantKeyOps: []string{"seal"},
	}))
	if err != nil {
		return policyGrant{}, fmt.Errorf("ask policy for a grant: %w", err)
	}
	if res.Msg.GetDecision() != policyv2alpha1.Decision_ALLOW || len(res.Msg.GetSealedGrant()) == 0 {
		return policyGrant{}, errors.New("policy gave no grant to seal")
	}
	g := policyGrant{sealed: res.Msg.GetSealedGrant()}
	if e := res.Msg.GetExpiresAt(); e != nil && e.IsValid() {
		g.expires = e.AsTime()
	}
	return g, nil
}

// write is the durable part of a batch, in the order of 0029: bundles and tiles, the state in one conditional put,
// the checkpoint at checkpoints/<size>, and the pointer. The state comes before key@ is asked to sign: a stale writer
// loses the put and never signs, so it cannot leave a signed checkpoint of a fork behind. A crash after the state is
// finished by the next start, which signs the missing checkpoint (recover).
func (s *Server) write(ctx context.Context, entries [][]byte, ids []string, nowMS int64, trusted bool) error {
	next, err := s.tree.extend(ctx, s.cur, entries)
	if err != nil {
		return err
	}
	doc, err := s.state.next(ctx, s.logName, next.size, next.root, ids, nowMS, trusted)
	if err != nil {
		return err
	}
	if err := s.state.commit(ctx, s.blob, doc); err != nil {
		return err
	}
	s.cur = next
	data, err := s.checkpointAt(ctx, next.size, next.root)
	if err != nil {
		return err
	}
	return s.movePointer(ctx, data, next.size)
}

// ack acknowledges every delivery of the batch, once the checkpoint that covers them is durable.
func (s *Server) ack(ctx context.Context, ds []*transportv2alpha1.Delivery) error {
	ids := make([]uint64, len(ds))
	for i, d := range ds {
		ids[i] = d.GetDeliveryId()
	}
	if _, err := s.tr.Ack(ctx, connect.NewRequest(&transportv2alpha1.AckRequest{DeliveryIds: ids})); err != nil {
		return fmt.Errorf("acknowledge: %w", err)
	}
	return nil
}

// timeRefusal holds a message that the checks took to the window of the writer's clock (0029, "Sealing"): the
// time of its record and the time of its id must be inside the last 14 days and not more than timeSkew ahead of the
// clock, and within uidSkew of each other. A message outside is quarantined and acknowledged; it never blocks the log.
// The first two need a clock the writer can believe (trusted): without one every message would look old or new by the
// clock's own error, and a backlog stamped by the right clock would be parked with no way back. The third uses no clock.
func timeRefusal(info recordInfo, uid string, nowMS int64, trusted bool) *rejection {
	uidMS, _ := uidTime(uid)
	old, ahead := nowMS-seenFor.Milliseconds(), nowMS+timeSkew.Milliseconds()
	switch {
	case max(uidMS-info.timeMS, info.timeMS-uidMS) > uidSkew.Milliseconds():
		return &rejection{reasonSchema, "metadata.uid"}
	case !trusted:
		return nil
	case info.timeMS < old:
		return &rejection{reasonStale, "time"}
	case uidMS < old:
		return &rejection{reasonStale, "metadata.uid"}
	case info.timeMS > ahead:
		return &rejection{reasonFuture, "time"}
	case uidMS > ahead:
		return &rejection{reasonFuture, "metadata.uid"}
	}
	return nil
}
