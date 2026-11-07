package writerd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/mod/semver"

	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// A rejection is why the writer refused a message: a word from the closed list below and the path of the field at
// fault. It never holds a value of the record (0030: a record may carry what must not be repeated).
type rejection struct{ Reason, Path string }

func (r *rejection) Error() string { return "rejected: " + r.Reason + " " + r.Path }

// The reasons of a rejection.
const (
	reasonCanonical = "canonical" // not RFC 8785 bytes of a record of the sluis form
	reasonSchema    = "schema"    // a required field is missing or has another type
	reasonBound     = "bound"     // larger than the writer takes
	reasonAction    = "action"    // metadata.event_code is not in the catalogue
	reasonRelease   = "release"   // metadata.product.version is newer than the catalogue's release, or not a version
	reasonBoundary  = "boundary"  // metadata.log_name is another boundary
	reasonProduct   = "product"   // metadata.product.name is not the project's
	reasonEmitter   = "emitter"   // actor.user.uid is not the emitter the transport saw
	reasonTenant    = "tenant"    // metadata.tenant_uid is not a tenant id
	reasonUsage     = "usage"     // a usage part, which the minimal catalogue declares no meter for
	reasonStale     = "stale"     // older than the writer remembers ids for
	reasonFuture    = "future"    // more than the allowed skew ahead of the writer's clock
)

// maxDepth bounds the nesting the parser follows; the canonical form refuses more than this as well.
const maxDepth = 16

// recordInfo is what the clear envelope of an entry is made of: a projection of the record (0029, "Encryption").
type recordInfo struct {
	uid, event, tenant, actorUID, product string
	classUID, activityID, statusID        int64
	timeMS, actorTypeID                   int64
}

// catalogue is the set of action names of the AuditCatalogue.
type catalogue map[string]struct{}

// checker validates the messages of one project's log against its AuditCatalogue: the action table of the newest
// release, with the JSON Schema of each action's records (0030, "The catalogue is the table with its schemas").
type checker struct {
	boundary, project string
	release           string // the release of the catalogue, a semantic version with a "v"
	actions           catalogue
	schemas           *audit.Schemas
	// The backstop of validation (see validate): how long one record may take, zero for the default, how many timed-out
	// validations may still be running, and a replacement for the schemas' own Validate, for tests.
	budget  time.Duration
	running *atomic.Int32
	valid   func(name string, rec []byte) error
}

// validateBudget is how long the schema validation of one record may take. The policy of the catalogue (kits/go/audit/policy.go)
// bounds the work to a few milliseconds, so this is the backstop for a document the policy let through or an engine that
// misbehaves: the writer is sequential, and one record must not stop the log.
const validateBudget = 250 * time.Millisecond

// maxStuck is how many validations that timed out may still be running before the writer stops starting new ones.
const maxStuck = 4

// validate validates a record against the schema of its action within the budget. A record that does not finish in time is
// refused as `schema` at the path `record` and so quarantined whole and counted in the seal entry like any refusal; the
// validation it started is left to finish and its answer is dropped. After maxStuck of them still running the writer refuses
// without starting another, so a catalogue that makes every record slow costs the log its records (kept in the quarantine)
// and not its availability, and the error line of the batch says so.
func (c checker) validate(name string, rec []byte) error {
	fn := c.valid
	if fn == nil {
		fn = c.schemas.Validate
	}
	budget := c.budget
	if budget == 0 {
		budget = validateBudget
	}
	if c.running != nil && c.running.Load() >= maxStuck {
		return errValidateStuck
	}
	done := make(chan error, 1)
	go func() { done <- fn(name, rec) }()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if c.running != nil {
			c.running.Add(1)
			go func() {
				<-done //nolint:errcheck // the answer of a validation that timed out is dropped
				c.running.Add(-1)
			}()
		}
		slog.Error("the schema validation of a record did not finish in time and the record is refused", "action", name, "budget", budget)
		return errValidateSlow
	}
}

var (
	errValidateSlow  = errors.New("validation did not finish in time")
	errValidateStuck = errors.New("validations that timed out are still running")
)

// check validates one message and returns the projection of its record. The rules are those of 0030 "The record
// format": the bytes are canonical (parse, canonicalise again, compare), the envelope fields have their types, the
// boundary and the product are the log's, the action is in the catalogue and the release is not newer than it, the
// actor is the emitter the transport saw, and the record validates against the schema of its action (REQ-AUDIT-113).
// A usage part is refused: the catalogue declares no meter.
func (c checker) check(uid, emitter string, rec []byte, usage int) (recordInfo, *rejection) {
	var zero recordInfo
	if len(rec) > audit.RecordMax {
		return zero, &rejection{reasonBound, "record"}
	}
	if usage > 0 {
		return zero, &rejection{reasonUsage, "usage"}
	}
	v, err := parseStrict(rec)
	if err != nil {
		return zero, &rejection{reasonCanonical, "record"}
	}
	canon, err := audit.Canonical(v)
	if err != nil || !bytes.Equal(canon, rec) {
		return zero, &rejection{reasonCanonical, "record"}
	}
	root, ok := v.(map[string]any)
	if !ok {
		return zero, &rejection{reasonSchema, "record"}
	}
	var info recordInfo
	md, ok := root["metadata"].(map[string]any)
	if !ok {
		return zero, &rejection{reasonSchema, "metadata"}
	}
	if info.uid, ok = md["uid"].(string); !ok || info.uid == "" || info.uid != uid {
		return zero, &rejection{reasonSchema, "metadata.uid"}
	}
	if _, _, ok := parseUID(info.uid); !ok { // 0029: a UUIDv7 in the form of RFC 9562
		return zero, &rejection{reasonSchema, "metadata.uid"}
	}
	if info.event, ok = md["event_code"].(string); !ok || info.event == "" {
		return zero, &rejection{reasonSchema, "metadata.event_code"}
	}
	if _, known := c.actions[info.event]; !known {
		return zero, &rejection{reasonAction, "metadata.event_code"}
	}
	if name, _ := md["log_name"].(string); name != c.boundary {
		return zero, &rejection{reasonBoundary, "metadata.log_name"}
	}
	prod, ok := md["product"].(map[string]any)
	if !ok {
		return zero, &rejection{reasonSchema, "metadata.product"}
	}
	if info.product, ok = prod["name"].(string); !ok || info.product != c.project {
		return zero, &rejection{reasonProduct, "metadata.product.name"}
	}
	version, ok := prod["version"].(string)
	if !ok || version == "" {
		return zero, &rejection{reasonSchema, "metadata.product.version"}
	}
	// REQ-AUDIT-146: the catalogue is the newest release's table, and within a major version it only grows, so it holds
	// for every older release; a record of a newer one has no catalogue yet and is kept aside.
	if !releaseCovered(c.release, version) {
		return zero, &rejection{reasonRelease, "metadata.product.version"}
	}
	if t, present := md["tenant_uid"]; present {
		s, ok := t.(string)
		if !ok || !tenantID(s) {
			return zero, &rejection{reasonTenant, "metadata.tenant_uid"}
		}
		info.tenant = s
	}
	actor, _ := root["actor"].(map[string]any)
	user, _ := actor["user"].(map[string]any)
	if info.actorUID, ok = user["uid"].(string); !ok || info.actorUID == "" {
		return zero, &rejection{reasonSchema, "actor.user.uid"}
	}
	// 0030: the actor of a record of sluis is <actor>@<boundary>, and the transport knows the emitter from the peer
	// uid, so one actor cannot write as another (T-13).
	if info.actorUID != emitter {
		return zero, &rejection{reasonEmitter, "actor.user.uid"}
	}
	for _, f := range []struct {
		dst  *int64
		v    any
		path string
	}{
		{&info.actorTypeID, user["type_id"], "actor.user.type_id"},
		{&info.classUID, root["class_uid"], "class_uid"},
		{&info.activityID, root["activity_id"], "activity_id"},
		{&info.statusID, root["status_id"], "status_id"},
		{&info.timeMS, root["time"], "time"},
	} {
		n, ok := f.v.(int64)
		if !ok {
			return zero, &rejection{reasonSchema, f.path}
		}
		*f.dst = n
	}
	// REQ-AUDIT-113: the whole record against the schema of its action, unmapped.sluis included. The path names the
	// member and never a value.
	if err := c.validate(info.event+".schema.json", rec); err != nil {
		return zero, &rejection{reasonSchema, schemaPath(err)}
	}
	return info, nil
}

// releaseCovered reports whether a record of release version is covered by the catalogue of release newest: it is not
// newer. Both are releases as semver.org writes them (audit.ValidRelease), the catalogue's with a "v" as x/mod orders them.
// An older release of any major version is covered if its record validates: the table only grows within a major version
// (REQ-AUDIT-119), and across one the schema itself is the guard, so the check here is only for the newer.
func releaseCovered(newest, version string) bool {
	return audit.ValidRelease(version) && semver.Compare("v"+version, newest) <= 0
}

// schemaPath is the path of the member that failed its schema, as a dotted path, or "record" when it is not a plain one.
func schemaPath(err error) string {
	var se *audit.SchemaError
	if !errors.As(err, &se) {
		return "record"
	}
	p := strings.ReplaceAll(strings.TrimPrefix(se.Path, "/"), "/", ".")
	if p == "" || len(p) > 128 || strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return "record"
	}
	return p
}

// tenantID reports whether s is a tenant id: one part of an address, and not the "-" of a kind with no tenant.
func tenantID(s string) bool {
	return s != store.NoTenant && store.ValidateID(s) == nil && !bytes.ContainsRune([]byte(s), '/')
}

var errNotCanonical = errors.New("not a record")

// parseStrict reads one JSON value into nil, bool, string, int64, []any and map[string]any. It refuses what RFC
// 8785 and 0030 leave out of a record: a duplicate key, a number that is not an integer of 64 bits, trailing data.
func parseStrict(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := readValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotCanonical
	}
	return v, nil
}

func readValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errNotCanonical
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case nil, bool, string:
		return t, nil
	case json.Number:
		n, err := strconv.ParseInt(t.String(), 10, 64)
		if err != nil {
			return nil, errNotCanonical
		}
		return n, nil
	case json.Delim:
		if t == '{' {
			m := map[string]any{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, errNotCanonical
				}
				if _, dup := m[key]; dup {
					return nil, errNotCanonical
				}
				if m[key], err = readValue(dec, depth+1); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		}
		a := []any{}
		for dec.More() {
			e, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, e)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return a, nil
	}
	return nil, errNotCanonical
}
