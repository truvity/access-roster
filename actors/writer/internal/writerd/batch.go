package writerd

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
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
	var (
		acc     []accepted
		refused []refusedMessage
		dupes   int
		inBatch = map[string]struct{}{}
		grants  = grantCache{}
	)
	for _, d := range ds {
		m := d.GetMessage()
		if _, seen := s.state.seen[m.GetUid()]; seen {
			dupes++
			continue
		}
		if _, twice := inBatch[m.GetUid()]; twice {
			dupes++
			continue
		}
		info, rej := s.chk.check(m.GetUid(), d.GetEmitter(), m.GetRecord(), len(m.GetUsage()))
		if rej == nil && info.timeMS < nowMS-seenFor.Milliseconds() {
			// 0029, "Sealing": the writer remembers ids for 14 days, so an older record cannot be told from a repeat.
			rej = &rejection{reasonStale, "time"}
		}
		if rej != nil {
			refused = append(refused, refusedMessage{d, rej})
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
	if len(acc) > 0 {
		entries, err := s.sealEntries(ctx, grants, acc, batchCounts{len(acc), dupes, len(refused)}, nowMS)
		if err != nil {
			return err
		}
		ids := make([]string, len(acc))
		for i, a := range acc {
			ids[i] = a.info.uid
		}
		if err := s.write(ctx, entries, ids, nowMS); err != nil {
			return &fatalError{err}
		}
	}
	// An empty batch is never sealed, so an idle log signs nothing (0029).
	return s.ack(ctx, ds)
}

type refusedMessage struct {
	d   *transportv2alpha1.Delivery
	rej *rejection
}

// grantCache holds the sealed grants a batch has asked policy for, by tenant.
type grantCache map[string][]byte

func (s *Server) grantFor(ctx context.Context, c grantCache, tenant string) ([]byte, error) {
	if g, ok := c[tenant]; ok {
		return g, nil
	}
	g, err := s.grant(ctx, tenant)
	if err != nil {
		return nil, err
	}
	c[tenant] = g
	return g, nil
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

// grant asks policy for the grant that lets the writer seal a tenant's evidence (decision D-6: action audit.seal,
// a built-in permit of the writer). A refusal is an error: the writer does not seal without one.
func (s *Server) grant(ctx context.Context, tenant string) ([]byte, error) {
	res, err := s.pol.Decide(ctx, connect.NewRequest(&policyv2alpha1.DecideRequest{
		Action:      "audit.seal",
		Principal:   &policyv2alpha1.EntityRef{Type: "Actor", Id: writerName},
		Resource:    &policyv2alpha1.EntityRef{Type: "Boundary", Id: s.cfg.Boundary},
		Tenant:      tenant,
		Actor:       &policyv2alpha1.ActorFacts{Name: writerName},
		GrantKeyOps: []string{"seal"},
	}))
	if err != nil {
		return nil, fmt.Errorf("ask policy for a grant: %w", err)
	}
	if res.Msg.GetDecision() != policyv2alpha1.Decision_ALLOW || len(res.Msg.GetSealedGrant()) == 0 {
		return nil, errors.New("policy gave no grant to seal")
	}
	return res.Msg.GetSealedGrant(), nil
}

// write is the durable part of a batch, in the order of 0029: bundles and tiles, the state in one conditional put,
// the checkpoint at checkpoints/<size>, and the pointer. The state comes before key@ is asked to sign: a stale writer
// loses the put and never signs, so it cannot leave a signed checkpoint of a fork behind. A crash after the state is
// finished by the next start, which signs the missing checkpoint (recover).
func (s *Server) write(ctx context.Context, entries [][]byte, ids []string, nowMS int64) error {
	next, err := s.tree.extend(ctx, s.cur, entries)
	if err != nil {
		return err
	}
	if err := s.state.commit(ctx, s.blob, s.state.next(s.logName, next.size, next.root, ids, nowMS)); err != nil {
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
