package audit

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
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

// Event is one audit event.
type Event struct {
	Action     Action
	Status     Status
	StatusCode string         // a closed reason, e.g. "grant"; empty on success
	Tenant     string         // metadata.tenant_uid; "" is the operator's own tenant (the writer fills it)
	Subject    *Subject       // optional: the person concerned, as user.uid (a pseudonym)
	Policy     *PolicyRef     // optional: the decision that gated this action
	Sluis      map[string]any // unmapped.sluis: string, bool, int64 (|v| <= 2^53-1), []string, nested map
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
}

// An Emitter builds audit messages and hands them to the transport. It is safe for concurrent use.
type Emitter struct {
	cfg Config
	now func() time.Time
}

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
	return &Emitter{cfg: cfg, now: now}, nil
}

// Emit hands the event to the transport and returns once the transport has accepted it (EmitRequest.blocking is
// false). An error is returned to the caller; the library neither buffers nor retries.
func (e *Emitter) Emit(ctx context.Context, ev Event) error { return e.emit(ctx, ev, false) }

// EmitBlocking returns only when the transport says the message is durable (0029 "Sealing"; blocking is true).
// The caller decides what a failure means; the library does not retry.
func (e *Emitter) EmitBlocking(ctx context.Context, ev Event) error { return e.emit(ctx, ev, true) }

func (e *Emitter) emit(ctx context.Context, ev Event, blocking bool) error {
	rec, uid, err := e.Record(ctx, ev)
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
	return nil
}

// Record builds the message of an event without sending it: the record as RFC 8785 bytes, and its metadata.uid.
// Tests and the command line use it.
func (e *Emitter) Record(ctx context.Context, ev Event) ([]byte, string, error) {
	if err := validateEvent(ev); err != nil {
		return nil, "", err
	}
	t := e.now()
	var pseudonym string
	if ev.Subject != nil {
		p, err := e.pseudonym(ctx, *ev.Subject, t)
		if err != nil {
			return nil, "", err
		}
		pseudonym = p
	}
	uid := NewUUIDv7(t)
	rec, err := buildRecord(recordInput{
		actor: e.cfg.Actor, boundary: e.cfg.Boundary, release: e.cfg.Release,
		uid: uid, timeMS: t.UnixMilli(), correlation: rpc.CorrelationID(ctx), pseudonym: pseudonym, ev: ev,
	})
	if err != nil {
		return nil, "", err
	}
	return rec, uid, nil
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
	if in.ev.Policy != nil {
		// REQ-AUDIT-120: the record declares the profile whose attributes it uses.
		md["profiles"] = []string{"security_control"}
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
	if in.pseudonym != "" {
		rec["user"] = map[string]any{"uid": in.pseudonym}
	}
	if len(in.ev.Sluis) > 0 {
		rec["unmapped"] = map[string]any{"sluis": in.ev.Sluis}
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
