package exchanged

import (
	"errors"
	"strings"

	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// OCSF class 3002 is Authentication; a token grant, refresh or exchange is activity 99, which names itself (0030
// "The class mapping"). The table is code (0030 "The action table is code").
const classAuthentication = 3002

// The actions of exchange: metadata.event_code. Every exchange is one record: ActionToken when a token was issued and
// ActionRefused, with a closed reason, when none was (REQ-EXCH-009).
const (
	ActionToken   = "exchange.token"
	ActionRefused = "exchange.refused"
)

var (
	actionToken   = audit.Action{Name: ActionToken, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Exchange"}
	actionRefused = audit.Action{Name: ActionRefused, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Exchange"}
)

// subjectKind is the Kind of the pseudonym of a person (0029 "Pseudonyms"): the value is the person's id.
const subjectKind = "person"

// attempt is what the audit record of one request says, filled in as the request goes.
type attempt struct {
	audience string // only a value that has the shape of a client id
	tenant   string
	person   *Person
	subject  *Subject
	decision *decision
}

// decision is the answer of policy, for the record of the action it gated.
type decision struct {
	id, digest string
	policies   []string
	allowed    bool
}

// reasonOf is the closed reason of a failure.
func reasonOf(err error) string {
	var r *refused
	var o *outage
	switch {
	case errors.As(err, &r):
		return r.reason
	case errors.As(err, &o):
		return "unavailable_" + o.reason
	}
	return "internal"
}

// event builds the audit event of an attempt and its outcome.
func (a *attempt) event(err error) audit.Event {
	ev := audit.Event{Action: actionToken, Status: audit.StatusSuccess, Tenant: a.tenant}
	if err != nil {
		ev.Action, ev.Status, ev.StatusCode = actionRefused, audit.StatusFailure, reasonOf(err)
	}
	if a.person != nil && a.tenant != "" {
		ev.Subject = &audit.Subject{Tenant: a.tenant, Kind: subjectKind, Value: a.person.ID}
	}
	if d := a.decision; d != nil {
		ev.Policy = &audit.PolicyRef{DecisionID: d.id, Digest: d.digest, PolicyIDs: d.policies, Decision: audit.DecisionDenied}
		if d.allowed {
			ev.Policy.Decision = audit.DecisionAllowed
		}
	}
	sluis := map[string]any{}
	if a.audience != "" {
		sluis["token"] = map[string]any{"audience": a.audience}
	}
	if s := a.subject; s != nil && (s.ACR != nil || s.AMRPresent) {
		m := map[string]any{}
		if s.ACR != nil {
			m["acr"] = *s.ACR
		}
		if s.AMRPresent {
			m["amr"] = append([]string{}, s.AMR...)
		}
		sluis["assurance"] = m
	}
	if len(sluis) > 0 {
		ev.Sluis = sluis
	}
	return ev
}

// audienceForRecord is the audience as the record may carry it. A request names whatever it likes, and a record
// takes only a value that has the shape of a client id: it cannot hold an e-mail address, a token or a long text
// (0030: a record never carries them).
func audienceForRecord(s string) string {
	if len(s) > 128 || strings.TrimSpace(s) != s || store.ValidateID(s) != nil {
		return ""
	}
	return s
}
