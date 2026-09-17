package audit

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"
)

// The trail speaks the Elastic Common Schema (decided 2026-09-13): in the
// record kept in S3, and on the log line. ECS because it costs one mapping
// here, and what reads it — Elastic, Wazuh, Grafana and Loki tooling, the
// OpenTelemetry Collector, whose semantic conventions absorbed ECS — needs
// no translation of ours. OCSF was the alternative and fits too little of
// what this service does (a token exchange or a workspace connect has no
// class of its own there); if a SIEM ever requires it, a shipper maps ECS to
// OCSF, and nothing here changes.
//
// What ECS has no field for stays under `access_roster.*`, ECS's place for
// a vendor's own: the native outcome, whose `held` and whose refused and
// failed distinction `event.outcome` cannot say, the target by its own
// name, and the attributes.

// ECSVersion is the schema version every record declares.
const ECSVersion = "8.11.0"

// Dataset is every record's event.dataset: the one key that selects this
// trail from everything else a log store holds.
const Dataset = "access_roster.audit"

// The event.category and event.type values used here, from ECS's allowed
// values.
const (
	categoryAuthentication = "authentication"
	categorySession        = "session"
	categoryIAM            = "iam"
	categoryConfiguration  = "configuration"

	typeStart      = "start"
	typeEnd        = "end"
	typeDenied     = "denied"
	typeAccess     = "access"
	typeAdmin      = "admin"
	typeChange     = "change"
	typeCreation   = "creation"
	typeDeletion   = "deletion"
	typeConnection = "connection"
	typeUser       = "user"
	typeInfo       = "info"
)

// classes is one kind's event.category and event.type.
type classes struct {
	category []string
	types    []string
}

func class(category string, types ...string) classes {
	return classes{category: []string{category}, types: types}
}

// kinds is every kind this repository records, by name. A kind added
// without a row here still gets a class, from its prefix or the default,
// and a test names every kind so that the table is where one is decided.
var kinds = map[string]classes{
	"sign-in":                 class(categoryAuthentication, typeStart),
	"sign-in.refused":         class(categoryAuthentication, typeDenied),
	"recovery.sign-in":        class(categoryAuthentication, typeStart, typeAdmin),
	"token.exchanged":         class(categoryAuthentication, typeAccess),
	"github.token.minted":     class(categoryAuthentication, typeAccess),
	"session.refresh-refused": class(categorySession, typeDenied),
	"session.ended":           class(categorySession, typeEnd),
	"session.revoked":         class(categorySession, typeEnd, typeAdmin),

	"workspace.connected":       class(categoryConfiguration, typeCreation, typeConnection),
	"workspace.reconnected":     class(categoryConfiguration, typeChange, typeConnection),
	"workspace.disconnected":    class(categoryConfiguration, typeDeletion),
	"workspace.domains-changed": class(categoryConfiguration, typeChange),
	"workspace.groups-changed":  class(categoryConfiguration, typeChange),

	"github.app.created":           class(categoryConfiguration, typeCreation),
	"github.org.connected":         class(categoryConfiguration, typeCreation, typeConnection),
	"github.org.disconnected":      class(categoryConfiguration, typeDeletion),
	"github.link-app.connected":    class(categoryConfiguration, typeCreation),
	"github.link-app.disconnected": class(categoryConfiguration, typeDeletion),

	"github.member.invite":   class(categoryIAM, typeUser, typeCreation),
	"github.member.add":      class(categoryIAM, typeUser, typeCreation),
	"github.member.remove":   class(categoryIAM, typeUser, typeDeletion),
	"github.member.set-role": class(categoryIAM, typeUser, typeChange),
	"github.action.held":     class(categoryIAM, typeInfo),
	"github.owner.reported":  class(categoryIAM, typeInfo),

	"github.link.created":       class(categoryIAM, typeUser, typeCreation),
	"github.link.matched":       class(categoryIAM, typeUser, typeCreation),
	"github.link.imported":      class(categoryIAM, typeUser, typeCreation),
	"github.link.moved":         class(categoryIAM, typeUser, typeChange),
	"github.link.narrowed":      class(categoryIAM, typeUser, typeChange),
	"github.link.unverifiable":  class(categoryIAM, typeUser, typeChange),
	"github.link.lost":          class(categoryIAM, typeUser, typeDeletion),
	"github.removals.confirmed": class(categoryIAM, typeAdmin, typeChange),
}

// prefixes class a kind no row names, first match wins: a reporter's new
// kind, or one of ours added without a row.
var prefixes = []struct {
	prefix string
	classes
}{
	{"sign-in", class(categoryAuthentication, typeStart)},
	{"recovery.", class(categoryAuthentication, typeStart, typeAdmin)},
	{"session.", class(categorySession, typeInfo)},
	{"workspace.", class(categoryConfiguration, typeChange)},
	{"github.member.", class(categoryIAM, typeUser, typeChange)},
	{"github.link.", class(categoryIAM, typeUser, typeChange)},
	{"github.org.", class(categoryConfiguration, typeChange)},
	{"github.app.", class(categoryConfiguration, typeChange)},
	{"github.link-app.", class(categoryConfiguration, typeChange)},
}

// Classify is a kind's ECS event.category and event.type. A token exchange
// (or an installation token) that was refused is also `denied`: the exchange is the access, and its
// refusal is a control acting. Anything unknown is `iam`/`info`, which is
// true of every event here and claims nothing more.
func Classify(kind, outcome string) (category, types []string) {
	c, ok := kinds[kind]
	if !ok {
		c = class(categoryIAM, typeInfo)
		for _, p := range prefixes {
			if strings.HasPrefix(kind, p.prefix) {
				c = p.classes
				break
			}
		}
	}
	category, types = slices.Clone(c.category), slices.Clone(c.types)
	if (kind == "token.exchanged" || kind == "github.token.minted") && outcome == OutcomeRefused {
		types = append(types, typeDenied)
	}
	return category, types
}

// ecsOutcome is event.outcome: ECS has no word for refused against failed,
// nor for held, which is neither yet.
func ecsOutcome(outcome string) string {
	switch outcome {
	case OutcomeOK:
		return "success"
	case OutcomeRefused, OutcomeFailed:
		return "failure"
	default:
		return "unknown"
	}
}

// nativeOutcome reads event.outcome back, for a document that carries no
// access_roster.outcome of its own.
func nativeOutcome(outcome string) string {
	switch outcome {
	case "success":
		return OutcomeOK
	case "failure":
		return OutcomeFailed
	default:
		return ""
	}
}

// ecsField is one ECS field, by its dotted name.
type ecsField struct {
	name  string
	value any
}

// attributesField is where the attributes go: one object, because an
// attribute's own name may hold a dot and must not become a level.
const attributesField = "access_roster.attributes"

// ecsFields is THE mapping from an event to ECS. The record and the log
// line are both built from it and from nothing else, so the two cannot
// name a field differently. Empty values are left out.
func ecsFields(e Event) []ecsField {
	category, types := Classify(e.Kind, e.Outcome)
	// ECS puts the authenticating user in user.name. A sign-in recorded
	// with no actor names the person as its subject, and is that user.
	user := e.Actor
	if user == "" && slices.Contains(category, categoryAuthentication) {
		user = e.Subject
	}
	all := []ecsField{
		{"ecs.version", ECSVersion},
		{"event.id", e.ID},
		{"event.kind", "event"},
		{"event.dataset", Dataset},
		{"event.provider", e.Source},
		{"event.action", e.Kind},
		{"event.category", category},
		{"event.type", types},
		{"event.outcome", ecsOutcome(e.Outcome)},
		{"event.reason", e.Reason},
		{"user.name", user},
		{"user.target.name", e.Subject},
		{"observer.name", e.Reporter},
		{"service.target.name", e.Target},
		{"client.address", e.ClientAddress},
		{"user_agent.original", e.UserAgent},
		{"http.request.id", e.RequestID},
		{"access_roster.outcome", e.Outcome},
		{"access_roster.target", e.Target},
	}
	out := all[:0]
	for _, f := range all {
		if s, ok := f.value.(string); ok && s == "" {
			continue
		}
		out = append(out, f)
	}
	if len(e.Attributes) > 0 {
		out = append(out, ecsField{attributesField, maps.Clone(e.Attributes)})
	}
	return out
}

// LogAttrs is an event as slog attributes: the ECS fields by their dotted
// names, flat, with each attribute as access_roster.attributes.<name>.
// Flat rather than grouped, because that is what a line-oriented shipper
// and a Loki query expect, and it keeps the time out: the log line's own
// `time` is the event's.
func LogAttrs(e Event) []any {
	var out []any
	for _, f := range ecsFields(e) {
		if attributes, ok := f.value.(map[string]string); ok {
			for _, name := range slices.Sorted(maps.Keys(attributes)) {
				out = append(out, attributesField+"."+name, attributes[name])
			}
			continue
		}
		out = append(out, f.name, f.value)
	}
	return out
}

// EncodeRecord is an event as the ECS document the trail keeps: the same
// fields as the log line, nested as ECS nests them, with @timestamp.
func EncodeRecord(e Event) ([]byte, error) {
	document := map[string]any{"@timestamp": e.At.UTC().Format(time.RFC3339Nano)}
	for _, f := range ecsFields(e) {
		place := document
		path := strings.Split(f.name, ".")
		for _, level := range path[:len(path)-1] {
			next, ok := place[level].(map[string]any)
			if !ok {
				next = map[string]any{}
				place[level] = next
			}
			place = next
		}
		place[path[len(path)-1]] = f.value
	}
	return json.Marshal(document)
}

// ecsRecord is the part of an ECS document a record is read back from.
type ecsRecord struct {
	Timestamp time.Time `json:"@timestamp"`
	Event     struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		Action   string `json:"action"`
		Outcome  string `json:"outcome"`
		Reason   string `json:"reason"`
	} `json:"event"`
	User struct {
		Name   string `json:"name"`
		Target struct {
			Name string `json:"name"`
		} `json:"target"`
	} `json:"user"`
	Observer struct {
		Name string `json:"name"`
	} `json:"observer"`
	Service struct {
		Target struct {
			Name string `json:"name"`
		} `json:"target"`
	} `json:"service"`
	Client struct {
		Address string `json:"address"`
	} `json:"client"`
	UserAgent struct {
		Original string `json:"original"`
	} `json:"user_agent"`
	HTTP struct {
		Request struct {
			ID string `json:"id"`
		} `json:"request"`
	} `json:"http"`
	AccessRoster struct {
		Outcome    string            `json:"outcome"`
		Target     string            `json:"target"`
		Attributes map[string]string `json:"attributes"`
	} `json:"access_roster"`
}

// errNotARecord is a line that is neither format.
var errNotARecord = errors.New("audit: neither an ECS record nor an access-roster 1.6.2 event")

// DecodeRecord reads one kept record back, in either format the trail has
// held: an ECS document, which has an `event` object, or the event line
// access-roster 1.6.2 wrote, which has a top-level `kind`. Both stay
// readable for as long as the bucket keeps objects, which is longer than
// any release.
//
// An authentication event recorded with no actor reads back with its
// subject as the actor, because that is who its record says the user was.
func DecodeRecord(line []byte) (Event, error) {
	var probe struct {
		Event json.RawMessage `json:"event"`
		Kind  *string         `json:"kind"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return Event{}, err
	}
	switch {
	case len(probe.Event) > 0 && probe.Event[0] == '{':
		var r ecsRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return Event{}, err
		}
		e := Event{
			ID:            r.Event.ID,
			At:            r.Timestamp.UTC(),
			Source:        r.Event.Provider,
			Kind:          r.Event.Action,
			Actor:         r.User.Name,
			Reporter:      r.Observer.Name,
			Subject:       r.User.Target.Name,
			Target:        r.AccessRoster.Target,
			Outcome:       r.AccessRoster.Outcome,
			Reason:        r.Event.Reason,
			Attributes:    r.AccessRoster.Attributes,
			ClientAddress: r.Client.Address,
			UserAgent:     r.UserAgent.Original,
			RequestID:     r.HTTP.Request.ID,
		}
		if e.Target == "" {
			e.Target = r.Service.Target.Name
		}
		if e.Outcome == "" {
			e.Outcome = nativeOutcome(r.Event.Outcome)
		}
		return e, nil
	case probe.Kind != nil:
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return Event{}, err
		}
		e.At = e.At.UTC()
		return e, nil
	default:
		return Event{}, errNotARecord
	}
}
