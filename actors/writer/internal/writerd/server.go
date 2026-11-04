// Package writerd is the audit writer (ADR 0028, 0029, 0030): it takes the messages of its project from the audit
// transport, validates them, drops the ones it has already sealed, seals each record under its tenant's evidence key
// at key@, appends the entries to a C2SP tiled log in the audit blob, and has key@ sign a checkpoint for every batch.
// It acknowledges the transport only once the checkpoint that covers a message is durable.
//
// The write order of a batch is fixed (0029, "The write-once fence"): entry bundles, hash tiles, the checkpoint at
// checkpoints/<size>, the writer's state (one conditional put: the new size and the ids sealed), the checkpoint
// pointer (a conditional put), and then the acknowledgement. Every object but the pointer and the state is created
// once. A failure after the first object of a batch is written stops the writer, and the next start finishes or
// adopts what the crash left (recover).
package writerd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"golang.org/x/mod/sumdb/note"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1/blobv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

const (
	// DefaultBatchMax closes a batch (0029, "Sealing"): 256 messages ...
	DefaultBatchMax = 256
	// DefaultBatchWindow ... or 5 seconds after the first, whichever comes first.
	DefaultBatchWindow = 5 * time.Second

	// logKeyPurpose is the key@ purpose that signs the checkpoints of the audit and usage logs.
	logKeyPurpose = "audit-log"
	// evidencePurpose seals the entries (0029, "Encryption and crypto-shredding").
	evidencePurpose = "evidence"
	// SealKind is the kind of the address an entry is sealed at. The id is SealID. key@ binds the boundary, the
	// tenant, the kind and the id into the envelope, so a record copied to another log or tenant does not open
	// (0029). The indexer and the reader open with the same address.
	SealKind = "audit-entry"
	// auditKind is the kind of the log the writer writes tonight (the usage log comes with the meters).
	auditKind = "audit"

	retryAfter = time.Second
)

// SealID is the id of the address a record is sealed at: <project>/<kind>/<log>/<record id>.
func SealID(project, kind, log, uid string) string {
	return project + "/" + kind + "/" + log + "/" + uid
}

// Config configures a writer.
type Config struct {
	Boundary string
	// Instance names this writer in the entries it stamps: the node on a board, "node-1" locally.
	Instance string

	// The sockets of the services the writer calls (PLAN.md, "Socket layout"). The writer serves none.
	StoreSocket, KeySocket, PolicySocket, BlobSocket, TransportSocket string

	// BatchMax and BatchWindow close a batch; zero means the defaults.
	BatchMax    int
	BatchWindow time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Clock observes the kernel clock for the seal entry; nil asks the kernel.
	Clock func() clockObservation
}

// Server is the writer.
type Server struct {
	cfg   Config
	now   func() time.Time
	clock func() clockObservation

	store storev2alpha1connect.StoreServiceClient
	keys  keyv2alpha1connect.KeyServiceClient
	pol   policyv2alpha1connect.PolicyServiceClient
	blob  blobIO
	tr    transportv2alpha1connect.TransportServiceClient

	// Set by Init, read-only afterwards.
	project, logID, origin, prefix, logName string
	defaultTenant                           string
	chk                                     checker
	key                                     *logKey

	// Set by recover; after that only the consuming goroutine uses them.
	tree        *logTree
	cur         treeState
	state       *writerState
	pointerETag string
}

// fatalError marks a failure after which the writer must stop: a write of a batch was begun, or the fence refused.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

// New dials the services and returns a writer that has not started.
func New(cfg Config) (*Server, error) {
	for name, v := range map[string]string{
		"boundary": cfg.Boundary, "instance": cfg.Instance, "store-socket": cfg.StoreSocket, "key-socket": cfg.KeySocket,
		"policy-socket": cfg.PolicySocket, "blob-socket": cfg.BlobSocket, "transport-socket": cfg.TransportSocket,
	} {
		if v == "" {
			return nil, fmt.Errorf("writerd: %s is required", name)
		}
	}
	dial := func(socket string) (connect.HTTPClient, string) { return rpc.Dial(socket) }
	sh, su := dial(cfg.StoreSocket)
	kh, ku := dial(cfg.KeySocket)
	ph, pu := dial(cfg.PolicySocket)
	bh, bu := dial(cfg.BlobSocket)
	th, tu := dial(cfg.TransportSocket)
	return newServer(cfg,
		storev2alpha1connect.NewStoreServiceClient(sh, su, rpc.ClientOptions()...),
		keyv2alpha1connect.NewKeyServiceClient(kh, ku, rpc.ClientOptions()...),
		policyv2alpha1connect.NewPolicyServiceClient(ph, pu, rpc.ClientOptions()...),
		blobv2alpha1connect.NewBlobServiceClient(bh, bu, rpc.ClientOptions()...),
		transportv2alpha1connect.NewTransportServiceClient(th, tu, rpc.ClientOptions()...)), nil
}

func newServer(cfg Config, st storev2alpha1connect.StoreServiceClient, keys keyv2alpha1connect.KeyServiceClient,
	pol policyv2alpha1connect.PolicyServiceClient, blob blobv2alpha1connect.BlobServiceClient,
	tr transportv2alpha1connect.TransportServiceClient) *Server {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	clk := cfg.Clock
	if clk == nil {
		clk = kernelClock
	}
	if cfg.BatchMax <= 0 {
		cfg.BatchMax = DefaultBatchMax
	}
	if cfg.BatchWindow <= 0 {
		cfg.BatchWindow = DefaultBatchWindow
	}
	return &Server{cfg: cfg, now: now, clock: clk, store: st, keys: keys, pol: pol, blob: blobIO{blob}, tr: tr}
}

// Init reads the documents the writer needs through the data port (AuditLog, AuditCatalogue, Boundary) and the
// public half of the log key. A missing document or key is no start.
func (s *Server) Init(ctx context.Context) error {
	logs, err := store.New(s.store, "AuditLog", func() *configv2alpha1.AuditLog { return &configv2alpha1.AuditLog{} })
	if err != nil {
		return err
	}
	cats, err := store.New(s.store, "AuditCatalogue", func() *configv2alpha1.AuditCatalogue { return &configv2alpha1.AuditCatalogue{} })
	if err != nil {
		return err
	}
	bnds, err := store.New(s.store, "Boundary", func() *configv2alpha1.Boundary { return &configv2alpha1.Boundary{} })
	if err != nil {
		return err
	}
	al, err := logs.Get(ctx, "", "default")
	if err != nil {
		return fmt.Errorf("auditlog/default: %w", err)
	}
	cat, err := cats.Get(ctx, "", "default")
	if err != nil {
		return fmt.Errorf("auditcatalogue/default: %w", err)
	}
	bnd, err := bnds.Get(ctx, "", "default")
	if err != nil {
		return fmt.Errorf("boundary/default: %w", err)
	}
	if n := bnd.Value.GetName(); n != s.cfg.Boundary {
		return errors.New("boundary/default: the name is not the boundary this writer serves")
	}
	if !tenantID(bnd.Value.GetDefaultTenant()) {
		return errors.New("boundary/default: default_tenant is not a tenant id")
	}
	s.defaultTenant = bnd.Value.GetDefaultTenant()

	s.project = al.Value.GetProject()
	if err := store.ValidateID(s.project); err != nil || strings.Contains(s.project, "/") {
		return errors.New("auditlog/default: project is not a name")
	}
	var found bool
	for _, l := range al.Value.GetLogs() {
		if l.GetKind() != auditKind {
			slog.Warn("a log of another kind is declared and is not written by this writer", "kind", l.GetKind(), "log", l.GetId())
			continue
		}
		if found {
			return errors.New("auditlog/default: more than one audit log; this writer writes one")
		}
		found = true
		s.logID, s.origin = l.GetId(), l.GetOrigin()
	}
	if !found {
		return errors.New("auditlog/default: no log of kind audit")
	}
	if err := store.ValidateID(s.logID); err != nil || strings.Contains(s.logID, "/") || s.origin == "" {
		return errors.New("auditlog/default: the audit log needs an id and an origin")
	}
	s.prefix = auditKind + "/" + s.logID + "/"
	s.logName = auditKind + "/" + s.logID

	actions := catalogue{}
	for _, a := range cat.Value.GetActions() {
		actions[a] = struct{}{}
	}
	if len(actions) == 0 {
		return errors.New("auditcatalogue/default: no action")
	}
	s.chk = checker{boundary: s.cfg.Boundary, project: s.project, actions: actions}

	pk, err := s.keys.PublicKey(ctx, connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: logKeyPurpose}))
	if err != nil {
		return fmt.Errorf("the public key of the log key: %w", err)
	}
	if pk.Msg.GetAlgorithm() != "ES384" {
		return errors.New("the log key is not an ES384 key")
	}
	if s.key, err = newLogKey(s.origin, pk.Msg.GetSpkiDer()); err != nil {
		return err
	}
	// The verifier key is public; an auditor needs it to run `sluis audit verify`.
	slog.Info("the log key", "log", s.logName, "origin", s.origin, "verifier_key", s.key.verifierKey())
	return nil
}

// Check reads what a start reads, without writing anything: the documents, the log key and the writer's state.
func (s *Server) Check(ctx context.Context) error {
	if err := s.Init(ctx); err != nil {
		return err
	}
	_, err := loadState(ctx, s.blob)
	return err
}

// VerifierKey returns the verifier key of the log, which Init made.
func (s *Server) VerifierKey() string { return s.key.verifierKey() }

// Run starts the writer and consumes the transport until ctx ends or a failure the writer cannot go on after.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Init(ctx); err != nil {
		return err
	}
	if err := s.recover(ctx); err != nil {
		return err
	}
	for ctx.Err() == nil {
		err := s.consume(ctx)
		var fatal *fatalError
		if errors.As(err, &fatal) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("the transport stream ended; reconnecting", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(retryAfter):
		}
	}
	return nil
}

// stamp is the time the writer records, in milliseconds.
func (s *Server) stamp() int64 { return s.now().UnixMilli() }

// recover brings the log, the state and the pointer to one place after a start. It reads the state, checks the
// committed checkpoint, and adopts the entries a crash left in the blob beyond it: the bundles are written before
// the checkpoint, and the same bytes cannot be created again with other contents, so the entries that are there
// are the ones the log takes. It then makes sure a signed checkpoint covers them, registers them in the state
// (their ids, so the transport's repeat of them is dropped) and moves the pointer.
func (s *Server) recover(ctx context.Context) error {
	s.tree = newLogTree(s.blob, s.prefix)
	st, err := loadState(ctx, s.blob)
	if err != nil {
		return err
	}
	size, root, err := st.position(s.logName)
	if err != nil {
		return err
	}
	if size > 0 {
		cp, _, err := s.readCheckpoint(ctx, size)
		if err != nil {
			return fmt.Errorf("%w: the checkpoint of the committed size: %w", ErrFence, err)
		}
		if cp.root != root {
			return fmt.Errorf("%w: the checkpoint of the committed size has another root", ErrFence)
		}
	}
	tail, err := s.tree.loadTail(ctx, size)
	if err != nil {
		return err
	}
	cur := treeState{size: size, root: root, tail: tail}
	orph, err := s.tree.orphans(ctx, size, tail)
	if err != nil {
		return err
	}
	s.state = st
	if len(orph) > 0 {
		slog.Warn("adopting entries a crash left beyond the last checkpoint", "entries", len(orph))
		adopted, err := s.tree.extend(ctx, cur, orph)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(orph))
		for _, e := range orph {
			if uid, ok := recordUID(e); ok {
				ids = append(ids, uid)
			}
		}
		if _, err := s.checkpointAt(ctx, adopted.size, adopted.root); err != nil {
			return err
		}
		if err := st.commit(ctx, s.blob, st.next(s.logName, adopted.size, adopted.root, ids, s.stamp())); err != nil {
			return err
		}
		cur = adopted
	}
	s.cur = cur
	if cur.size == 0 {
		return nil
	}
	data, err := s.checkpointAt(ctx, cur.size, cur.root)
	if err != nil {
		return err
	}
	return s.movePointer(ctx, data, cur.size)
}

// recordUID reads metadata.uid from the clear envelope of a record entry.
func recordUID(entry []byte) (string, bool) {
	v, err := parseStrict(entry)
	if err != nil {
		return "", false
	}
	m, _ := v.(map[string]any)
	if m["entry"] != entryRecord {
		return "", false
	}
	md, _ := m["metadata"].(map[string]any)
	uid, ok := md["uid"].(string)
	return uid, ok
}

// readCheckpoint reads checkpoints/<size> and checks its signature with the log key.
func (s *Server) readCheckpoint(ctx context.Context, size int64) (checkpoint, []byte, error) {
	data, _, err := s.blob.get(ctx, fmt.Sprintf("%scheckpoints/%d", s.prefix, size))
	if err != nil {
		return checkpoint{}, nil, err
	}
	cp, err := s.openNote(data)
	if err != nil {
		return checkpoint{}, nil, err
	}
	if cp.size != size {
		return checkpoint{}, nil, errors.New("the checkpoint names another size")
	}
	return cp, data, nil
}

// openNote verifies a signed note with the log key and reads its body.
func (s *Server) openNote(data []byte) (checkpoint, error) {
	n, err := note.Open(data, note.VerifierList(s.key))
	if err != nil {
		return checkpoint{}, errors.New("the note does not verify with the log key")
	}
	cp, err := parseCheckpoint(n.Text)
	if err != nil || cp.origin != s.origin {
		return checkpoint{}, errors.New("not a checkpoint of this log")
	}
	return cp, nil
}

// checkpointAt makes sure checkpoints/<size> exists and returns its bytes. One that is there is used, after its
// signature and root are checked; otherwise key@ signs one and it is created once.
func (s *Server) checkpointAt(ctx context.Context, size int64, root [32]byte) ([]byte, error) {
	if cp, data, err := s.readCheckpoint(ctx, size); err == nil {
		if cp.root != root {
			return nil, fmt.Errorf("%w: a checkpoint of this size names another root", ErrFence)
		}
		return data, nil
	} else if !errors.Is(err, errAbsent) {
		return nil, fmt.Errorf("%w: the checkpoint at this size is not the writer's: %w", ErrFence, err)
	}
	body := checkpointBody(s.origin, size, root)
	res, err := s.keys.Sign(ctx, connect.NewRequest(&keyv2alpha1.SignRequest{
		Purpose: logKeyPurpose, Content: body, Algorithm: "ES384",
	}))
	if err != nil {
		return nil, fmt.Errorf("sign the checkpoint: %w", err)
	}
	data, err := s.key.signedNote(body, res.Msg.GetSignatureDer())
	if err != nil {
		return nil, err
	}
	if err := s.tree.createOnce(ctx, fmt.Sprintf("checkpoints/%d", size), data); err != nil {
		return nil, err
	}
	return data, nil
}

// movePointer writes the checkpoint pointer (the tlog-tiles "checkpoint" object, the one object of the format that is
// rewritten) with a conditional put on the entity tag the writer last wrote. At a start, when it holds none, it reads
// the pointer first: a pointer that is not the writer's, or is ahead of the log, is another writer's. A put that
// loses means another writer moved the pointer, and is the fence.
func (s *Server) movePointer(ctx context.Context, data []byte, size int64) error {
	path := s.prefix + "checkpoint"
	etag := s.pointerETag
	if etag == "" {
		have, tag, err := s.blob.get(ctx, path)
		switch {
		case errors.Is(err, errAbsent):
		case err != nil:
			return err
		default:
			cp, err := s.openNote(have)
			if err != nil {
				return fmt.Errorf("%w: the pointer is not the writer's: %w", ErrFence, err)
			}
			if cp.size > size {
				return fmt.Errorf("%w: the pointer is ahead of the log", ErrFence)
			}
			if cp.size == size {
				s.pointerETag = tag
				return nil
			}
			etag = tag
		}
	}
	etag, err := s.blob.put(ctx, path, data, etag)
	if errors.Is(err, errStale) {
		return fmt.Errorf("%w: the checkpoint pointer has moved", ErrFence)
	}
	if err != nil {
		return err
	}
	s.pointerETag = etag
	return nil
}

// consume holds one Receive stream open and processes the batches it delivers. It returns when the stream ends or a
// batch fails; Run opens a new stream, which replays what is not acknowledged.
func (s *Server) consume(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := s.tr.Receive(sctx, connect.NewRequest(&transportv2alpha1.ReceiveRequest{MaxBatch: uint32(s.cfg.BatchMax)})) //nolint:gosec // a small positive number
	if err != nil {
		return fmt.Errorf("receive: %w", err)
	}
	defer func() { _ = stream.Close() }()

	in := make(chan *transportv2alpha1.Delivery, s.cfg.BatchMax)
	ended := make(chan error, 1)
	go func() {
		for stream.Receive() {
			for _, d := range stream.Msg().GetDeliveries() {
				select {
				case in <- d:
				case <-sctx.Done():
					return
				}
			}
		}
		err := stream.Err()
		if err == nil {
			err = errors.New("the stream ended")
		}
		ended <- err
	}()

	for {
		batch, streamErr := s.collect(sctx, in, ended)
		if len(batch) > 0 {
			if err := s.processBatch(ctx, batch); err != nil {
				return err
			}
		}
		if streamErr != nil {
			return streamErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// collect waits for the first message, then gathers until BatchMax or BatchWindow after the first, whichever is
// first. It returns what it has, with the error that ended the stream if that is what stopped it.
func (s *Server) collect(ctx context.Context, in <-chan *transportv2alpha1.Delivery, ended <-chan error) ([]*transportv2alpha1.Delivery, error) {
	var batch []*transportv2alpha1.Delivery
	select {
	case d := <-in:
		batch = append(batch, d)
	case err := <-ended:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	timer := time.NewTimer(s.cfg.BatchWindow)
	defer timer.Stop()
	for len(batch) < s.cfg.BatchMax {
		select {
		case d := <-in:
			batch = append(batch, d)
		case err := <-ended:
			return batch, err
		case <-timer.C:
			return batch, nil
		case <-ctx.Done():
			return batch, ctx.Err()
		}
	}
	return batch, nil
}

// bounded returns s when it is short valid text, so that a report never holds an unbounded value.
func bounded(s string) string {
	if len(s) > 64 || !utf8.ValidString(s) {
		return ""
	}
	return s
}
