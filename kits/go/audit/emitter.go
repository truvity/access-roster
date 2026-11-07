package audit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

const (
	// OCSFVersion is the OCSF release every record pins (0030 "The record format": the first release pins 1.9.0).
	OCSFVersion = "1.9.0"

	// StringMax is the longest string a record may carry, in bytes (0029: free text is bounded).
	StringMax = 1024
	// RecordMax is the largest record, in bytes.
	RecordMax = 16 << 10

	// userTypeSystem is actor.user.type_id 3: "System" in the OCSF 1.9.0 user type enum (0 Unknown, 1 User,
	// 2 Admin, 3 System, 99 Other) and "sluis actor" in 0030 "The record format". The two agree.
	userTypeSystem = 3
	// severityInformational is OCSF severity_id 1.
	severityInformational = 1

	// classApplicationLifecycle and classAuthentication are the OCSF classes whose required attributes the record
	// fills from what the emitter knows (0030 "The class mapping", "The OCSF attributes a class requires").
	classApplicationLifecycle = 6002
	classAuthentication       = 3002
	// userUnknown is the user.uid of an Authentication record whose subject is not known: OCSF requires the user,
	// and a refusal before anyone is identified has none to name. It cannot be a pseudonym (those begin p1.).
	userUnknown = "unknown"
	// user.type_id of the subject (OCSF 1.9.0: 0 Unknown, 1 User, 2 Admin, 3 System, 99 Other): a person is a User, a
	// client or a workload is a System (a service identity), any other kind of identity is Other, and no subject is Unknown.
	userTypeUnknown, userTypeUser, userTypeSystemSubject, userTypeOther = 0, 1, 3, 99
	// entityTypeOther is entity.type_id 99, Other: the type of an entity is the row's own word.
	entityTypeOther = 99

	// pseudonymPurpose, pseudonymLabel and pseudonymBytes fix the pseudonym (0029 "Pseudonyms"): Mac under the
	// tenant's pseudonym key, with this label (which key@ binds in), kept to the first 128 bits.
	pseudonymPurpose = "pseudonym"
	pseudonymLabel   = "sluis-pseudonym-v1"
	pseudonymBytes   = 16
)

// Status is OCSF's status_id.
type Status int

// The outcomes of an action.
const (
	StatusSuccess Status = 1
	StatusFailure Status = 2
)

// An Action is one row of an actor's action table (0030: the table is code).
type Action struct {
	Name       string // metadata.event_code, e.g. "key.sign"
	ClassUID   int    // OCSF class, e.g. 6003 API Activity
	ActivityID int    // OCSF activity within the class, e.g. 99 Other
	// ActivityName is activity_name. It is required when ActivityID is 99 (0030: "activity_name only for
	// activity 99 or where the table names one"), e.g. "Sign" or "Open" for key use.
	ActivityName string
}

// Subject is the person or external actor an event concerns.
type Subject struct {
	Tenant string // the tenant whose pseudonym key is used
	// Kind is the kind of identity (0029 "Pseudonyms"), e.g. "person", "workload" or "client". It is part of the
	// pseudonym's input, so the same identifier of two kinds gives two pseudonyms. Required.
	Kind string
	// Value is the stable identifier of that kind: the sluis subject of a person; the upstream's issuer and subject
	// for an identity sluis has assigned no subject; the SPIFFE ID or client id of a workload or client; a product's
	// own subject id for a person of a product. The emitter turns it into a pseudonym and never sends it.
	Value string
}

// Decision is the outcome of a policy decision: OCSF's security_control action_id.
type Decision int

// The outcomes of a decision; the zero value says none is recorded.
const (
	DecisionAllowed Decision = 1
	DecisionDenied  Decision = 2
)

func (d Decision) caption() string {
	if d == DecisionDenied {
		return "Denied"
	}
	return "Allowed"
}

// PolicyRef is the decision that gated an action (0030 "The class mapping": part of the record of the action).
//
// DecisionID is required: the OCSF policy object needs a uid, and a digest without an id is refused.
type PolicyRef struct {
	DecisionID string   // policy.uid
	Digest     string   // policy.version
	PolicyIDs  []string // authorizations[].policy.uid, one per policy that took part
	Decision   Decision // action_id and authorizations[].decision; zero records none
}

// Entity is the thing an Entity Management action changed (OCSF `entity`): a key of the signing ring, a data key and the
// wrap of it for a recipient, a document at an export destination. Type is a closed word that names the kind of thing
// and is the row's own (the schema of the row holds it to that word). Name, UID and Version identify it; at least one of
// Name and UID is required. They are names, ids and counts the actor knows, never text a request carried.
type Entity struct {
	Type    string
	Name    string
	UID     string
	Version string // a decimal number, such as the generation of a data key
}

// Event is one audit event.
type Event struct {
	Action     Action
	Status     Status
	StatusCode string         // a closed reason, e.g. "grant"; empty on success
	Tenant     string         // metadata.tenant_uid; "" is the operator's own tenant (the writer fills it)
	Subject    *Subject       // optional: the person concerned, as user.uid (a pseudonym)
	Policy     *PolicyRef     // optional: the decision that gated this action
	Sluis      map[string]any // unmapped.sluis: string, bool, int64 (|v| <= 2^53-1), []string, nested map
	// Entity is the thing an Entity Management action (class 3004) changed; required there and refused elsewhere.
	Entity *Entity
	// SubjectBestEffort says the record is worth more than the name of its subject: when key@ cannot make the pseudonym, the
	// record is written as if it had no subject (user.uid `unknown` in an Authentication), and one warning says so. It is for
	// a refusal, which ADR 0005 has audited whatever else fails; a fact that must name its subject leaves it false and fails
	// when the pseudonym cannot be made.
	SubjectBestEffort bool
}

// Config configures an Emitter.
type Config struct {
	Actor, Boundary, Release string // Release is version.Version
	// Transport is the client of the emit socket: rpc.Dial("/run/sluis/audit/<boundary>/emit.sock").
	Transport transportv2alpha1connect.TransportServiceClient
	// Keys is the client of key@; nil for an actor with no pseudonym rule, which then cannot send a Subject.
	Keys keyv2alpha1connect.KeyServiceClient
	// Now is the clock; nil means time.Now. A test injects one.
	Now func() time.Time
	// Table is the action table of the emitting project's release; nil means Sluis(), the table of sluis itself. The
	// emitter refuses an action that is not a row and a record that does not validate against the schema of its row.
	Table *Table
}

// An Emitter builds audit messages and hands them to the transport. It is safe for concurrent use.
//
// It keeps no queue of records. It does keep, for each tenant, a running total of the best-effort facts it failed to
// deliver (see Emit); a record of that tenant carries the total as unmapped.sluis.lost until a record that carries the
// current total has been delivered (0029 "Facts that are lost are counted").
type Emitter struct {
	cfg   Config
	now   func() time.Time
	table *Table
	// process names this emitter for the life of the process: 16 random hex digits. A total belongs to one process.
	process string

	mu       sync.Mutex
	lost     map[string]*tenantLoss // by the tenant of the lost event; "" is the operator's own tenant
	overflow bool                   // the map was full once, and the loss went to the operator's own bucket
}

// maxLostTenants bounds the tenants an emitter keeps a total for, so that a caller cannot grow the map without limit
// with tenants of its choosing. When the bound is hit, a loss for another tenant is counted in the operator's own
// bucket (key ""), and one WARN says so.
const maxLostTenants = 256

// tenantLoss is the running total for one tenant since the process started. since is the time of the first loss that
// has not been reported yet; reported is the largest total a delivered record has carried.
type tenantLoss struct{ total, since, reported int64 }

// New returns an Emitter. Actor, Boundary, Release and Transport are required.
func New(cfg Config) (*Emitter, error) {
	for name, v := range map[string]string{"actor": cfg.Actor, "boundary": cfg.Boundary, "release": cfg.Release} {
		if v == "" {
			return nil, refusal.New(connect.CodeInvalidArgument, "schema", name)
		}
		if len(v) > StringMax || !utf8.ValidString(v) {
			return nil, refusal.New(connect.CodeInvalidArgument, "bound", name)
		}
	}
	if cfg.Transport == nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "transport")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	table := cfg.Table
	if table == nil {
		table = Sluis()
	}
	return &Emitter{cfg: cfg, now: now, table: table, process: newProcessID(), lost: map[string]*tenantLoss{}}, nil
}

// Emit hands the event to the transport and returns once the transport has accepted it (EmitRequest.blocking is
// false). An error is returned to the caller; the library neither buffers nor retries.
//
// Emit is for a best-effort fact: when it fails the fact is gone, so the emitter counts it for the event's tenant, and
// the next record of that tenant carries the total (0029 "Facts that are lost are counted"). A caller that fails its
// operation when the emit fails uses EmitRequired.
func (e *Emitter) Emit(ctx context.Context, ev Event) error { return e.emit(ctx, ev, false, true) }

// EmitRequired is Emit for a caller that fails its operation when the emit fails (session and exchange answer
// unavailable): the fact is not lost, because the operation did not happen, so a failure is not counted.
func (e *Emitter) EmitRequired(ctx context.Context, ev Event) error {
	return e.emit(ctx, ev, false, false)
}

// EmitBlocking returns only when the transport says the message is durable (0029 "Sealing"; blocking is true).
// The caller decides what a failure means; the library does not retry. A failure is not counted as a lost fact:
// the caller fails the operation the fact belongs to. A caller that carries on when this fails uses
// EmitBlockingBestEffort.
func (e *Emitter) EmitBlocking(ctx context.Context, ev Event) error {
	return e.emit(ctx, ev, true, false)
}

// EmitBlockingBestEffort waits for durability like EmitBlocking, for a caller that carries on when it fails (a
// revocation, which a full spool must never block: REQ-AUDIT-015). The fact is then lost, so a failure is counted as
// for Emit.
func (e *Emitter) EmitBlockingBestEffort(ctx context.Context, ev Event) error {
	return e.emit(ctx, ev, true, true)
}

// Lost is the total of best-effort facts this process has failed to deliver, over all tenants, since it started. It
// names no tenant; an actor can export it as a metric.
func (e *Emitter) Lost() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var n int64
	for _, l := range e.lost {
		n = min(n+l.total, maxSafeInt)
	}
	return n
}

// emit builds the record with the note its tenant owes, and sends it. A failure of a best-effort emit adds one to
// the total of the event's tenant, whatever the cause (the transport, a refusal of the event, key@): the fact is gone.
// Nothing is taken or put back: a total only grows, and a record that carries it and reaches the transport, even if
// its caller then times out, is repeated harmlessly by the next record, which carries the same total or a larger one.
func (e *Emitter) emit(ctx context.Context, ev Event, blocking, counted bool) (err error) {
	defer func() {
		if err != nil && counted {
			e.recordLoss(ev.Tenant, e.now().UnixMilli(), factsIn(ev))
		}
	}()
	rec, uid, carried, err := e.build(ctx, ev, e.noteFor(ev.Tenant))
	if err != nil {
		return err
	}
	req := &transportv2alpha1.EmitRequest{
		Message:  &transportv2alpha1.AuditMessage{Uid: uid, Record: rec},
		Blocking: blocking,
	}
	if _, err := e.cfg.Transport.Emit(ctx, connect.NewRequest(req)); err != nil {
		return fmt.Errorf("audit: emit: %w", err)
	}
	e.reported(ev.Tenant, carried)
	return nil
}

// lostNote is what a record carries: the process, its running total for the record's tenant, and the time (Unix
// milliseconds) of the first loss not yet reported. The zero total is none.
type lostNote struct {
	process      string
	total, since int64
}

// bucket is the key a loss of the tenant is counted under: the tenant itself, or the operator's own bucket for a
// tenant that is too long to be one, or when maxLostTenants tenants have lost facts already. Callers hold e.mu.
func (e *Emitter) bucket(tenant string) string {
	if _, ok := e.lost[tenant]; ok {
		return tenant
	}
	if len(tenant) > StringMax || len(e.lost) >= maxLostTenants {
		if !e.overflow && tenant != "" {
			e.overflow = true
			slog.Warn("audit: too many tenants have lost facts; further losses are counted in the operator's own tenant", "process", e.process, "bound", maxLostTenants)
		}
		return ""
	}
	return tenant
}

// factsIn is the number of facts an event stands for. An event is one fact, except the summary of a limiter (refusals, kept
// to a bound): it carries the number of calls it folded in unmapped.sluis.suppressed, and each of them was a fact that the
// limiter did not report one by one so as to keep it. When the summary is lost, those facts are lost with it, and the
// total of lost facts counts them, not the one record that carried them.
func factsIn(ev Event) int64 {
	if n, ok := ev.Sluis["suppressed"].(int64); ok && n > 1 {
		return min(n, maxSafeInt)
	}
	return 1
}

// recordLoss adds n lost facts to the tenant's total, at the time at.
func (e *Emitter) recordLoss(tenant string, at int64, n int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := e.bucket(tenant)
	l := e.lost[k]
	if l == nil {
		l = &tenantLoss{}
		e.lost[k] = l
	}
	if l.total == l.reported {
		l.since = at // a new run of losses starts
	}
	l.total = min(l.total+n, maxSafeInt)
}

// noteFor is the note a record of the tenant carries: its own total, while a record that carries it has not been
// delivered, and never another tenant's. Only the operator's own tenant ("") sees the overflow bucket.
func (e *Emitter) noteFor(tenant string) lostNote {
	e.mu.Lock()
	defer e.mu.Unlock()
	if l := e.lost[tenant]; l != nil && l.total > l.reported {
		return lostNote{process: e.process, total: l.total, since: l.since}
	}
	return lostNote{}
}

// reported records that a record carrying n reached the transport, and says so in the log of the process.
func (e *Emitter) reported(tenant string, n lostNote) {
	if n.total == 0 {
		return
	}
	e.mu.Lock()
	l := e.lost[tenant]
	if l == nil || n.total <= l.reported {
		e.mu.Unlock()
		return
	}
	l.reported = n.total
	e.mu.Unlock()
	// Tenant-free on purpose: the log of the process is read by the operator, whoever the tenant is.
	slog.Warn("audit: facts were lost and a record now reports them", "process", n.process, "total", n.total, "since", n.since)
}

// BuildRecord lays out the record of an event from resolved inputs and returns its RFC 8785 bytes. It is the pure
// serialiser behind the emitter, without the action table and without the schema: the conformance vectors and the
// generator of the example records (tools/gen/audit) use it, so that the bytes do not depend on a clock or on key@.
func BuildRecord(actor, boundary, release, uid string, timeMS int64, correlation, pseudonym string, ev Event) ([]byte, error) {
	if err := validateEvent(ev); err != nil {
		return nil, err
	}
	return buildRecord(recordInput{
		actor: actor, boundary: boundary, release: release, uid: uid, timeMS: timeMS,
		correlation: correlation, pseudonym: pseudonym, ev: ev,
	})
}

// Record builds the message of an event without sending it: the record as RFC 8785 bytes, and its metadata.uid.
// Tests and the command line use it. It carries no note and changes no total.
func (e *Emitter) Record(ctx context.Context, ev Event) ([]byte, string, error) {
	rec, uid, _, err := e.build(ctx, ev, lostNote{})
	return rec, uid, err
}

// build makes the record. When the note makes the record larger than RecordMax, the record is built without it and the
// note stays owed: a fact is never lost to the note, and the note is not lost to a large fact. It returns the note the
// record carries.
func (e *Emitter) build(ctx context.Context, ev Event, note lostNote) ([]byte, string, lostNote, error) {
	if err := validateEvent(ev); err != nil {
		return nil, "", lostNote{}, err
	}
	// REQ-AUDIT-022: an action that is not in the table has no schema to hold its record to.
	if err := e.table.CheckAction(ev.Action); err != nil {
		return nil, "", lostNote{}, err
	}
	t := e.now()
	var pseudonym string
	if ev.Subject != nil {
		p, err := e.pseudonym(ctx, *ev.Subject, t)
		switch {
		case err == nil:
			pseudonym = p
		case ev.SubjectBestEffort:
			// Tenant-free on purpose: the log of the process is read by the operator, whoever the tenant is.
			slog.Warn("audit: a subject could not be named; the record is written without it", "process", e.process, "action", ev.Action.Name)
		default:
			return nil, "", lostNote{}, err
		}
	}
	uid := NewUUIDv7(t)
	in := recordInput{
		actor: e.cfg.Actor, boundary: e.cfg.Boundary, release: e.cfg.Release,
		uid: uid, timeMS: t.UnixMilli(), correlation: rpc.CorrelationID(ctx), pseudonym: pseudonym, ev: ev, lost: note,
	}
	rec, err := buildRecord(in)
	if err != nil && note.total > 0 {
		in.lost, note = lostNote{}, lostNote{}
		rec, err = buildRecord(in)
	}
	if err != nil {
		return nil, "", lostNote{}, err
	}
	// REQ-AUDIT-099: the record, the note of lost facts included, validates against the schema of its action before
	// it leaves the process.
	if err := e.table.Validate(rec); err != nil {
		return nil, "", lostNote{}, err
	}
	return rec, uid, note, nil
}

// newProcessID is 16 random hex digits: the name of one emitter for the life of its process, so that a reader can tell
// the totals of two processes of one actor apart.
func newProcessID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("audit: the operating system's random generator failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// pseudonym asks key@ for the Mac of the subject under the tenant's pseudonym key, with the epoch of the record's
// month, and formats it by 0029 "Pseudonyms": p1.<YYYYMM>.<first 128 bits, base64url, no padding>.
func (e *Emitter) pseudonym(ctx context.Context, s Subject, t time.Time) (string, error) {
	if e.cfg.Keys == nil {
		// Never fall back to the raw subject.
		return "", refusal.New(connect.CodeFailedPrecondition, "keys", "subject")
	}
	epoch := t.UTC().Format("200601")
	resp, err := e.cfg.Keys.Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{
		Purpose: pseudonymPurpose, Tenant: s.Tenant, Label: pseudonymLabel,
		Input: pseudonymInput(e.cfg.Boundary, s), Epoch: epoch,
	}))
	if err != nil {
		return "", fmt.Errorf("audit: pseudonym: %w", err)
	}
	mac := resp.Msg.GetMac()
	if len(mac) < pseudonymBytes {
		return "", refusal.New(connect.CodeInternal, "schema", "subject")
	}
	return "p1." + epoch + "." + base64.RawURLEncoding.EncodeToString(mac[:pseudonymBytes]), nil
}

// pseudonymInput is the Mac input of a pseudonym (0029 "Pseudonyms"): the boundary, the tenant, the kind of identity
// and its identifier, each with a 4-byte big-endian length in front. The label sluis-pseudonym-v1 is the request's
// label, which key@ binds in. The length prefixes make the parts unambiguous: ("ab","c") and ("a","bc") differ.
func pseudonymInput(boundary string, s Subject) []byte {
	var b []byte
	for _, part := range []string{boundary, s.Tenant, s.Kind, s.Value} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part))) //nolint:gosec // every part is at most StringMax bytes
		b = append(b, part...)
	}
	return b
}

func bound(s, path string) error {
	if len(s) > StringMax {
		return refusal.New(connect.CodeInvalidArgument, "bound", path)
	}
	if !utf8.ValidString(s) {
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	return nil
}

// validateEvent checks what the library can know before it asks key@ for anything.
func validateEvent(ev Event) error {
	a := ev.Action
	if a.Name == "" || a.ClassUID < 1000 || a.ClassUID > 99999 || a.ActivityID < 0 || a.ActivityID > 99 {
		return refusal.New(connect.CodeInvalidArgument, "schema", "action")
	}
	if ev.Status != StatusSuccess && ev.Status != StatusFailure {
		return refusal.New(connect.CodeInvalidArgument, "schema", "status")
	}
	if a.ActivityID == 99 && a.ActivityName == "" {
		// 0030: activity 99 (Other) is described by activity_name.
		return refusal.New(connect.CodeInvalidArgument, "schema", "action.activity_name")
	}
	for _, f := range []struct{ v, path string }{
		{a.Name, "action.name"}, {a.ActivityName, "action.activity_name"}, {ev.StatusCode, "status_code"}, {ev.Tenant, "tenant"},
	} {
		if err := bound(f.v, f.path); err != nil {
			return err
		}
		if emailShaped(f.v) {
			return refusal.New(connect.CodeInvalidArgument, "schema", f.path)
		}
	}
	if s := ev.Subject; s != nil {
		if s.Value == "" {
			return refusal.New(connect.CodeInvalidArgument, "schema", "subject.value")
		}
		if s.Kind == "" {
			return refusal.New(connect.CodeInvalidArgument, "schema", "subject.kind")
		}
		// The subject is hashed and never sent, so an e-mail address is a fine subject; its size is still bounded.
		for _, f := range []struct{ v, path string }{
			{s.Value, "subject.value"}, {s.Tenant, "subject.tenant"}, {s.Kind, "subject.kind"},
		} {
			if err := bound(f.v, f.path); err != nil {
				return err
			}
		}
	}
	if p := ev.Policy; p != nil {
		// OCSF's Policy object needs one of name, type or uid, and the record gives it a uid: the decision id.
		// A digest or a list of policies with no decision id has nothing to hang on.
		if p.DecisionID == "" {
			return refusal.New(connect.CodeInvalidArgument, "schema", "policy.decision_id")
		}
		if p.Decision != 0 && p.Decision != DecisionAllowed && p.Decision != DecisionDenied {
			return refusal.New(connect.CodeInvalidArgument, "schema", "policy.decision")
		}
		strs := []struct{ v, path string }{{p.DecisionID, "policy.decision_id"}, {p.Digest, "policy.digest"}}
		for i, id := range p.PolicyIDs {
			strs = append(strs, struct{ v, path string }{id, "policy.policy_ids[" + strconv.Itoa(i) + "]"})
		}
		for _, f := range strs {
			if err := bound(f.v, f.path); err != nil {
				return err
			}
			if emailShaped(f.v) {
				return refusal.New(connect.CodeInvalidArgument, "schema", f.path)
			}
		}
	}
	if e := ev.Entity; e != nil {
		if e.Type == "" || (e.Name == "" && e.UID == "") {
			// OCSF's managed entity needs one of name and uid, and the record gives it a type.
			return refusal.New(connect.CodeInvalidArgument, "schema", "entity")
		}
		for _, f := range []struct{ v, path string }{{e.Type, "entity.type"}, {e.Name, "entity.name"}, {e.UID, "entity.uid"}, {e.Version, "entity.version"}} {
			if err := checkText(f.v, f.path); err != nil {
				return err
			}
		}
	}
	// unmapped.sluis.lost is the emitter's own (0030 "The sluis fields"); a caller cannot write it.
	if _, taken := ev.Sluis[lostKey]; taken {
		return refusal.New(connect.CodeInvalidArgument, "schema", "unmapped.sluis."+lostKey)
	}
	return checkSluis(ev.Sluis, "unmapped.sluis", 0)
}

// emailRE is the e-mail shape of 0030 ("A record never carries ... an e-mail address"). It is deliberately broad:
// a value that looks like an address is refused wherever it is, and the Rust crate applies the same rule.
var emailRE = regexp.MustCompile(`[^@\s]+@[^@\s]+\.[^@\s]+`)

func emailShaped(s string) bool { return emailRE.MatchString(s) }

// checkSluis admits only the types of Event.Sluis, bounded, with no e-mail shape in any string.
func checkSluis(m map[string]any, path string, depth int) error {
	if depth > maxDepth {
		return refusal.New(connect.CodeInvalidArgument, "bound", path)
	}
	for k, v := range m {
		p := path + "." + k
		if err := bound(k, p); err != nil {
			return err
		}
		switch x := v.(type) {
		case string:
			if err := checkText(x, p); err != nil {
				return err
			}
		case bool:
		case int64:
			if x > maxSafeInt || x < -maxSafeInt {
				return refusal.New(connect.CodeInvalidArgument, "bound", p)
			}
		case []string:
			for i, s := range x {
				if err := checkText(s, p+"["+strconv.Itoa(i)+"]"); err != nil {
					return err
				}
			}
		case map[string]any:
			if err := checkSluis(x, p, depth+1); err != nil {
				return err
			}
		default:
			// A float, an int of another width, nil, a slice of another type: refused by name of the field.
			return refusal.New(connect.CodeInvalidArgument, "schema", p)
		}
	}
	return nil
}

func checkText(s, path string) error {
	if err := bound(s, path); err != nil {
		return err
	}
	if emailShaped(s) {
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	return nil
}

// recordInput is everything the record depends on, resolved: tests feed it fixed values.
type recordInput struct {
	actor, boundary, release string
	uid                      string
	timeMS                   int64
	correlation              string
	pseudonym                string
	ev                       Event
	lost                     lostNote // the running total of facts lost for the record's tenant; none when total is 0
}

// lostKey is the member of unmapped.sluis that carries the loss note: {"process": id, "total": n, "since": ms}.
const lostKey = "lost"

// subjectType is user.type_id of a subject by its kind of identity (0029 "Pseudonyms"), so that a pseudonym of a client does
// not pass for one of a person.
func subjectType(s *Subject) int {
	switch {
	case s == nil:
		return userTypeOther
	case s.Kind == "person":
		return userTypeUser
	case s.Kind == "client" || s.Kind == "workload":
		return userTypeSystemSubject
	}
	return userTypeOther
}

// buildRecord lays out the record of 0030 and returns its RFC 8785 bytes. The members are OCSF 1.9.0 base event
// attributes: activity_id, category_uid, class_uid, severity_id, status_id, status_code, time and type_uid; the
// metadata object (correlation_uid, event_code, log_name, product, tenant_uid, uid, version); actor.user; user;
// and, from the security_control profile, policy and authorizations.
func buildRecord(in recordInput) ([]byte, error) {
	a := in.ev.Action
	md := map[string]any{
		"event_code": a.Name,
		"log_name":   in.boundary,
		"product":    map[string]any{"name": "sluis", "version": in.release},
		"uid":        in.uid,
		"version":    OCSFVersion,
	}
	// REQ-AUDIT-120: the record declares the profiles whose attributes it uses. The security_control profile holds
	// policy, action_id and authorizations; Application Lifecycle takes `actor` from the host profile.
	var profiles []string
	if a.ClassUID == classApplicationLifecycle {
		profiles = append(profiles, "host")
	}
	if in.ev.Policy != nil {
		profiles = append(profiles, "security_control")
	}
	if len(profiles) > 0 {
		md["profiles"] = profiles
	}
	if in.correlation != "" {
		md["correlation_uid"] = in.correlation
	}
	if in.ev.Tenant != "" {
		md["tenant_uid"] = in.ev.Tenant
	}
	rec := map[string]any{
		"activity_id":  int64(a.ActivityID),
		"category_uid": int64(a.ClassUID / 1000),
		"class_uid":    int64(a.ClassUID),
		"metadata":     md,
		"actor":        map[string]any{"user": map[string]any{"type_id": int64(userTypeSystem), "uid": in.actor + "@" + in.boundary}},
		"severity_id":  int64(severityInformational),
		"status_id":    int64(in.ev.Status),
		"time":         in.timeMS,
		"type_uid":     int64(a.ClassUID)*100 + int64(a.ActivityID),
	}
	if a.ActivityName != "" {
		rec["activity_name"] = a.ActivityName
	}
	if in.ev.StatusCode != "" {
		rec["status_code"] = in.ev.StatusCode
	}
	switch {
	case in.pseudonym != "":
		rec["user"] = map[string]any{"uid": in.pseudonym, "type_id": int64(subjectType(in.ev.Subject))}
	case a.ClassUID == classAuthentication:
		// OCSF requires the subject of an authentication; none is known, and the record says so.
		rec["user"] = map[string]any{"uid": userUnknown, "type_id": int64(userTypeUnknown)}
	}
	if e := in.ev.Entity; e != nil {
		// OCSF's managed entity: type_id 99 (Other) is required beside a type of the sender's own.
		ent := map[string]any{"type": e.Type, "type_id": int64(entityTypeOther)}
		for k, v := range map[string]string{"name": e.Name, "uid": e.UID, "version": e.Version} {
			if v != "" {
				ent[k] = v
			}
		}
		rec["entity"] = ent
	}
	// The attributes a class requires that the emitter's own name fills: the application that started or reloaded,
	// the service that authenticated. Both are the emitting actor, a name of the registry.
	switch a.ClassUID {
	case classApplicationLifecycle:
		rec["application"] = map[string]any{"name": in.actor}
	case classAuthentication:
		rec["service"] = map[string]any{"name": in.actor}
	}
	sluis := in.ev.Sluis
	if in.lost.total > 0 {
		sluis = maps.Clone(sluis) // the caller's map is theirs; a nil map clones to nil
		if sluis == nil {
			sluis = map[string]any{}
		}
		sluis[lostKey] = map[string]any{"process": in.lost.process, "total": in.lost.total, "since": in.lost.since}
	}
	if len(sluis) > 0 {
		rec["unmapped"] = map[string]any{"sluis": sluis}
	}
	if p := in.ev.Policy; p != nil {
		// security_control profile: the policy object names the decision (uid) and the policy bundle (version,
		// the digest); action_id is the outcome; each policy that took part is an authorization_result with its
		// policy.uid and the same decision.
		pol := map[string]any{"uid": p.DecisionID}
		if p.Digest != "" {
			pol["version"] = p.Digest
		}
		rec["policy"] = pol
		if p.Decision != 0 {
			rec["action_id"] = int64(p.Decision)
		}
		if len(p.PolicyIDs) > 0 {
			auths := make([]any, 0, len(p.PolicyIDs))
			for _, id := range p.PolicyIDs {
				au := map[string]any{"policy": map[string]any{"uid": id}}
				if p.Decision != 0 {
					au["decision"] = p.Decision.caption()
				}
				auths = append(auths, au)
			}
			rec["authorizations"] = auths
		}
	}
	out, err := Canonical(rec)
	if err != nil {
		return nil, err
	}
	if len(out) > RecordMax {
		return nil, refusal.New(connect.CodeInvalidArgument, "bound", "record")
	}
	return out, nil
}
