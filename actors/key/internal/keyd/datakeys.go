package keyd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// errNoKey says there is no wrap for this node and no data key at all, and the caller did not ask to make one.
var errNoKey = errors.New("keyd: no such data key")

// errNotWrapped says the data key exists but no wrap of it is for this node yet: another node made it and the
// rewrap pass has not reached us. A new key is never made then, because it would lose the CREATE race at best and
// split the tenant's data across two keys at worst.
var errNotWrapped = errors.New("keyd: the data key has no wrap for this node yet")

// wrapContext is what a wrap is bound to.
func (s *Server) wrapContext(ref keyRef, recipient string) wrap.Context {
	t := ref.tenant
	if t == "" {
		t = envelope.NoTenant
	}
	return wrap.Context{Boundary: s.cfg.Boundary, Tenant: t, Purpose: ref.purpose, Generation: ref.generation, Recipient: recipient}
}

// withKey runs fn with the data key of ref, opened from this node's wrap and cached. With create, a key that has
// no wrap at all is made first (D-4: on the first need). The bytes are valid only during fn.
func (s *Server) withKey(ctx context.Context, ref keyRef, create bool, fn func(key []byte) error) error {
	for range 2 {
		e := s.cache.get(ref)
		if e == nil {
			var err error
			if e, err = s.load(ctx, ref, create); err != nil {
				return err
			}
		}
		if used, err := e.use(fn); used {
			return err
		}
		// The entry was wiped between get and use (it expired): load it again.
	}
	return unavailable(reasonWrap)
}

// withExistingKey is withKey for a call that may not make the key: the key is used when it exists, and errNoKey says it does
// not. It makes nothing, so it does not take loadMu, which serializes the makers: a caller that names a tenant with no
// key (and no grant to make one) costs the store a Get and a List, as any call does, and never holds up the cold load of a
// key for anyone else. Two callers that open the same wrap at once do the work twice and the later put replaces the
// earlier entry, which is wiped once its users are done (cache.put).
func (s *Server) withExistingKey(ctx context.Context, ref keyRef, fn func(key []byte) error) error {
	for range 3 {
		e := s.cache.get(ref)
		if e == nil {
			var err error
			if e, err = s.openShared(ctx, ref); err != nil {
				return err
			}
			if e == nil {
				continue // another open of the key ended with its caller gone, or the entry was evicted: look again
			}
		}
		if used, err := e.use(fn); used {
			return err
		}
	}
	return unavailable(reasonWrap)
}

// flight is one open of a key that is under way: the callers that want the same key wait for it.
type flight struct {
	id    string // its correlation id
	done  chan struct{}
	entry *entry // the cache entry, when the open succeeded
	err   error
}

// openOwnTimeout bounds one open of a key from its wrap: the read of the wrap and the call to the driver. A stuck driver ends
// the flight with this, and not the callers one by one.
const openOwnTimeout = 20 * time.Second

// openShared opens the key of ref from this node's wrap, once for all the callers that ask for it at the same time. The
// work is the flight's: it runs in a goroutine of its own, on a context that comes from the server's run context and not
// from any caller (so a caller that goes away, a browser that disconnects, does not fail the others, and shutdown ends the
// flight), bounded by openOwnTimeout (so a stuck driver does not hold the waiters for ever). Serve waits for the flights
// before it wipes the cache, and the cache refuses a key put after it closed, so nothing refills it after shutdown. Every
// caller, the first included, waits for the flight or for its own context. This is not loadMu, which serializes the makers
// and every different key behind one another: a flight is per key, and a caller whose key is not being opened starts its own.
// The result is the cache entry; the caller looks at the cache again when the entry has already been dropped.
//
// Attribution: the flight has a correlation id of its own, made when it starts, and the store Get and the ECDH it makes carry
// it. The log line of the start names the id of the caller that started it, and each caller that joins logs the flight it
// joined (debug), so a trace by a caller's id finds the flight and the flight's id finds the calls it made. The first caller's
// id is not the flight's: it would put the work in one request's trace and leave the others' without it.
func (s *Server) openShared(ctx context.Context, ref keyRef) (*entry, error) {
	s.flightMu.Lock()
	if s.flightsClosed {
		s.flightMu.Unlock()
		return nil, unavailable(reasonWrap)
	}
	f, ok := s.flights[ref]
	if !ok {
		f = &flight{done: make(chan struct{}), id: newFlightID()}
		if s.flights == nil {
			s.flights = map[keyRef]*flight{}
		}
		s.flights[ref] = f
		s.flightWG.Add(1)
		slog.Info("opening a data key", "flight", f.id, "started_by", rpc.CorrelationID(ctx), "purpose", ref.purpose)
		go s.runFlight(ref, f)
	} else {
		slog.Debug("joined the opening of a data key", "flight", f.id, "caller", rpc.CorrelationID(ctx), "purpose", ref.purpose)
	}
	s.flightMu.Unlock()
	select {
	case <-f.done:
		return f.entry, f.err
	case <-ctx.Done():
		return nil, unavailable(reasonWrap)
	}
}

// newFlightID is the correlation id of a flight: "flight-" and 64 random bits in hex.
func newFlightID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "flight-" + hex.EncodeToString(b)
}

// runContext is the context the server runs under, or the background one before Serve and in tests that call the methods
// without it.
func (s *Server) runContext() context.Context {
	if p := s.runCtx.Load(); p != nil {
		return *p
	}
	return context.Background()
}

// endFlights refuses new flights and waits for the ones under way, which end with the run context. Serve calls it after its
// servers have stopped and before it wipes the cache.
func (s *Server) endFlights() {
	s.flightMu.Lock()
	s.flightsClosed = true
	s.flightMu.Unlock()
	s.flightWG.Wait()
}

// runFlight does the work of a flight and ends it, whatever happens: a panic in the open ends the flight with an error and is
// logged (its type and stack, never its value, at most once a minute), and the flight leaves the map and wakes its waiters
// either way, so no later caller of the key waits for a flight that is gone.
func (s *Server) runFlight(ref keyRef, f *flight) {
	defer s.flightWG.Done()
	defer func() {
		if r := recover(); r != nil {
			s.panics.log(ref.purpose, fmt.Sprintf("%T", r), debug.Stack())
			f.entry, f.err = nil, unavailable(reasonWrap)
		}
		s.flightMu.Lock()
		delete(s.flights, ref)
		s.flightMu.Unlock()
		close(f.done)
	}()
	ctx, cancel := context.WithTimeout(rpc.WithCorrelationID(s.runContext(), f.id), s.openTimeout())
	defer cancel()
	open := s.openOwn
	if s.openFn != nil {
		open = s.openFn
	}
	key, err := open(ctx, ref)
	if err != nil {
		f.err = err
		return
	}
	if ref.tenant != "" {
		s.tenants.Store(ref.tenant, struct{}{})
	}
	f.entry = s.cache.put(ref, key)
}

// panicLog logs a panic of an open without its value and at most once a minute, with the number it held back: a bug that
// panics on every cold open would otherwise write a stack for each request.
type panicLog struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (p *panicLog) log(purpose, typ string, stack []byte) {
	p.mu.Lock()
	now := time.Now()
	if !p.last.IsZero() && now.Sub(p.last) < time.Minute {
		p.suppressed++
		p.mu.Unlock()
		return
	}
	held := p.suppressed
	p.last, p.suppressed = now, 0
	p.mu.Unlock()
	slog.Error("opening a data key panicked", "purpose", purpose, "type", typ, "suppressed", held, "stack", string(stack))
}

func (s *Server) openTimeout() time.Duration {
	if s.openTimeoutOverride > 0 {
		return s.openTimeoutOverride
	}
	return openOwnTimeout
}

// load opens the key of ref, making it when asked and when no wrap of it exists. One key is loaded at a time.
// The audit facts of a new key (1 + N, each with its own timeout) are emitted after the lock is released, so a
// slow transport holds up the caller that made the key and no other.
func (s *Server) load(ctx context.Context, ref keyRef, create bool) (*entry, error) {
	e, events, err := s.loadLocked(ctx, ref, create)
	for _, ev := range events {
		s.audit(ctx, ev)
	}
	return e, err
}

func (s *Server) loadLocked(ctx context.Context, ref keyRef, create bool) (*entry, []Event, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if e := s.cache.get(ref); e != nil {
		return e, nil, nil
	}
	var events []Event
	key, err := s.openOwn(ctx, ref)
	switch {
	case err == nil:
	case errors.Is(err, errNoKey) && create:
		if key, events, err = s.makeKey(ctx, ref); err != nil {
			return nil, events, err
		}
	default:
		return nil, nil, err
	}
	if ref.tenant != "" {
		// The rewrap pass visits the tenants whose keys this node has used.
		s.tenants.Store(ref.tenant, struct{}{})
	}
	return s.cache.put(ref, key), events, nil
}

// openOwn reads this node's wrap of ref and opens it. errNoKey when there is no wrap of the key at all,
// errNotWrapped when there are wraps and none is ours.
func (s *Server) openOwn(ctx context.Context, ref keyRef) ([]byte, error) {
	id := wrapID(ref.purpose, ref.generation, s.recipient)
	w, found, err := s.getWrap(ctx, ref.tenant, id)
	if err != nil {
		return nil, unavailable(reasonStore)
	}
	if found {
		return s.unwrap(ctx, ref, w)
	}
	others, err := s.listWraps(ctx, ref.tenant, ref.purpose)
	if err != nil {
		return nil, unavailable(reasonStore)
	}
	prefix := fmt.Sprintf("%s/%d/", ref.purpose, ref.generation)
	var ofKey []wrapItem
	for _, o := range others {
		if strings.HasPrefix(o.ID, prefix) {
			ofKey = append(ofKey, o)
		}
	}
	if len(ofKey) > 0 {
		s.warnLegacy(legacyLabels(ofKey))
		return nil, errNotWrapped
	}
	return nil, errNoKey
}

// unwrap opens a wrap addressed to this node: the key store does the ECDH with the wrapping key, key@ derives the
// key-encryption key and unwraps. The shared secret is zeroed after use.
func (s *Server) unwrap(ctx context.Context, ref keyRef, w *keyv2alpha1.DataKeyWrap) ([]byte, error) {
	if w.GetPurpose() != ref.purpose || w.GetGeneration() != ref.generation || w.GetRecipient() != s.recipient {
		return nil, errors.New("keyd: the wrap does not match its address")
	}
	if _, err := wrap.ParsePublic(w.GetEphemeralPublic()); err != nil {
		return nil, errors.New("keyd: the wrap has a bad ephemeral key")
	}
	res, err := s.driver.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{
		Purpose: wrappingPurpose, PeerPublic: w.GetEphemeralPublic(),
	}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	secret := res.Msg.GetSharedSecret()
	defer clear(secret)
	key, err := wrap.Unwrap(s.wrapContext(ref, s.recipient), secret, w.GetWrappedKey())
	if err != nil {
		return nil, errors.New("keyd: the wrap does not open")
	}
	return key, nil
}

// wrapFor wraps dataKey for one recipient.
func (s *Server) wrapFor(ref keyRef, r recipient, dataKey []byte) (wrapItem, error) {
	eph, wrapped, err := wrap.Wrap(s.wrapContext(ref, r.label), r.pub, dataKey)
	if err != nil {
		return wrapItem{}, err
	}
	return wrapItem{
		ID: wrapID(ref.purpose, ref.generation, r.label),
		Wrap: &keyv2alpha1.DataKeyWrap{
			Purpose: ref.purpose, Generation: ref.generation, Recipient: r.label, EphemeralPublic: eph, WrappedKey: wrapped,
		},
	}, nil
}

// makeKey makes a data key (32 random bytes from the operating system) and writes its wraps for every recipient
// in one batch of CREATEs. A CREATE that loses means another key@ made the key first: ours is discarded, and
// theirs is read and opened. It returns the audit facts of the new key for the caller to emit.
func (s *Server) makeKey(ctx context.Context, ref keyRef) ([]byte, []Event, error) {
	set, err := s.recipients(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !set.self {
		// A key this node could not open again would be lost with its cache entry, and the tenant's data with it.
		slog.Warn("no data key is made: this node's wrapping key is not in the KeyPlan recipients", "wrapping_key_id", s.wrappingID)
		return nil, set.events, unavailable(reasonWrap)
	}
	recips := set.wrap
	key := make([]byte, wrap.DataKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, set.events, fmt.Errorf("keyd: random: %w", err)
	}
	items := make([]wrapItem, 0, len(recips))
	for _, r := range recips {
		it, err := s.wrapFor(ref, r, key)
		if err != nil {
			clear(key)
			return nil, set.events, fmt.Errorf("keyd: wrap: %w", err)
		}
		items = append(items, it)
	}
	err = s.createWraps(ctx, ref.tenant, items)
	switch {
	case err == nil:
	case errors.Is(err, errTaken):
		clear(key)
		slog.Info("data key was made by another node first", "purpose", ref.purpose, "generation", ref.generation)
		key, err := s.openOwn(ctx, ref) // errNotWrapped if the winner left us out
		return key, set.events, err
	default:
		clear(key)
		return nil, set.events, unavailable(reasonStore)
	}
	events := append([]Event(nil), set.events...)
	events = append(events, Event{Action: ActionDataKeyMake, Tenant: ref.tenant, Fields: map[string]any{
		"purpose": ref.purpose, "generation": int64(ref.generation), "recipients": int64(len(items)),
	}})
	for _, it := range items {
		events = append(events, wrapEvent(ref, it.Wrap.GetRecipient()))
	}
	return key, events, nil
}

func wrapEvent(ref keyRef, recipient string) Event {
	return Event{Action: ActionWrapWrite, Tenant: ref.tenant, Fields: map[string]any{
		"purpose": ref.purpose, "generation": int64(ref.generation), "recipient": recipient,
	}}
}

func (s *Server) auditWrap(ctx context.Context, ref keyRef, recipient string) {
	s.audit(ctx, wrapEvent(ref, recipient))
}

// Rewrap is one rewrap pass: for each data key this node can open, it writes a wrap for every recipient of the
// KeyPlan that lacks one (ADR 0006, "Keys per board": the other boards rewrap for a new card; "Who may receive a
// wrap"). The plan is read again at each pass, so a change of the list takes effect at the next one. It is idempotent: a CREATE
// that finds the wrap there is fine. A failure stops the pass for that tenant and is logged.
func (s *Server) Rewrap(ctx context.Context) error {
	set, err := s.recipients(ctx)
	if err != nil {
		return err
	}
	recips := set.wrap
	for _, ev := range set.events {
		s.audit(ctx, ev)
	}
	tenants := []string{""}
	s.tenants.Range(func(k, _ any) bool { tenants = append(tenants, k.(string)); return true })
	slices.Sort(tenants)
	var errs []error
	for _, t := range tenants {
		if err := s.rewrapTenant(ctx, t, recips); err != nil {
			errs = append(errs, fmt.Errorf("tenant %q: %w", t, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Server) rewrapTenant(ctx context.Context, tenant string, recips []recipient) error {
	all, err := s.listWraps(ctx, tenant, "")
	if err != nil {
		return err
	}
	s.warnLegacy(legacyLabels(all))
	// Group the wraps by key (purpose and generation): who has one.
	have := map[keyRef]map[string]bool{}
	for _, it := range all {
		p, g, r, ok := parseWrapID(it.ID)
		if !ok {
			continue
		}
		ref := keyRef{tenant: tenant, purpose: p, generation: g}
		if have[ref] == nil {
			have[ref] = map[string]bool{}
		}
		have[ref][r] = true
	}
	s.dropErased(tenant, have)
	var errs []error
	for ref, got := range have {
		if !got[s.recipient] {
			continue // not ours to open: another node will wrap it for us
		}
		var missing []recipient
		for _, r := range recips {
			if !got[r.label] {
				missing = append(missing, r)
			}
		}
		if len(missing) == 0 {
			continue
		}
		err := s.withKey(ctx, ref, false, func(key []byte) error {
			for _, r := range missing {
				it, err := s.wrapFor(ref, r, key)
				if err != nil {
					return err
				}
				switch err := s.createWraps(ctx, tenant, []wrapItem{it}); {
				case err == nil:
					s.auditWrap(ctx, ref, r.label)
				case errors.Is(err, errTaken): // another node was first
				default:
					return err
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s/%d: %w", ref.purpose, ref.generation, err))
		}
	}
	return errors.Join(errs...)
}

// dropErased drops, from the cache, the data keys of a tenant that have no wrap for this node any more (REQ-KEYS-040). A
// wrap is deleted when its tenant exits, when its evidence retention ends or when this node's recipient is removed, and a
// key that stays in the cache would go on opening what the deletion was meant to make unreadable until its entry expired.
// The listing of the pass is the proof that the wrap is gone: a pass that could not list drops nothing (the entry's time
// to live is the bound then), and a key that was made after the listing was taken is dropped for nothing and loaded
// again from its wrap, which costs a read and nothing else. key@ has no Go client of store@'s Watch yet, so the deletion
// is seen at the next rewrap pass, which is DefaultRewrapEvery at the most. ADR 0006 ("The cache") says watch; this is the bound until the client exists.
func (s *Server) dropErased(tenant string, have map[keyRef]map[string]bool) {
	for _, ref := range s.cache.refsOf(tenant) {
		if !have[ref][s.recipient] {
			s.cache.drop(ref)
			slog.Info("data key dropped: its wrap is gone", "purpose", ref.purpose, "generation", ref.generation)
		}
	}
}
