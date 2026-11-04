package sessiond

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// OCSF class 3002 is Authentication (0030 "The class mapping"): a sign-in is 3002 / 1 Logon; the stages of a token
// stay activity 99 and name themselves; the end of a session is 3002 / 2 Logoff.
const classAuthentication = 3002

// The actions of session: metadata.event_code. The table is code (0030 "The action table is code").
const (
	ActionAuthorize = "session.authorize"
	ActionSignin    = "session.signin"
	ActionToken     = "session.token"
	ActionRefresh   = "session.refresh"
	ActionChainEnd  = "session.chain.end"
)

var (
	actionAuthorize = audit.Action{Name: ActionAuthorize, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Authorize"}
	actionSignin    = audit.Action{Name: ActionSignin, ClassUID: classAuthentication, ActivityID: 1}
	actionToken     = audit.Action{Name: ActionToken, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Grant"}
	actionRefresh   = audit.Action{Name: ActionRefresh, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Refresh"}
	actionChainEnd  = audit.Action{Name: ActionChainEnd, ClassUID: classAuthentication, ActivityID: 2}
)

// The kinds of identity session names in a record (0029 "Pseudonyms": the kind is part of the pseudonym's input). A
// step with no person yet concerns the client; a step with a person concerns the person.
const (
	subjectPerson = "person"
	subjectClient = "client"
)

// The closed reasons of a failed step. A reason names the rule that refused and never a value.
const (
	reasonClient       = "client"        // unknown client, or one session does not serve
	reasonRedirectURI  = "redirect_uri"  // not the client's registered redirect_uri
	reasonRequest      = "request"       // a parameter missing, repeated or malformed
	reasonPKCE         = "pkce"          // no S256 challenge, or the verifier does not match
	reasonMaxAge       = "max_age"       // the upstream's authentication is older than the client allowed, or undated
	reasonCookie       = "cookie"        // the sign-in cookie is missing, altered or expired
	reasonState        = "state"         // the callback's state is not the one sent
	reasonUpstream     = "upstream"      // the upstream refused or failed the sign-in
	reasonDenied       = "denied"        // policy denied
	reasonHeld         = "held"          // the person is held
	reasonCode         = "code"          // an unknown, expired or spent code
	reasonReuse        = "reuse"         // a spent code or refresh token presented again
	reasonRefresh      = "refresh_token" // an unknown refresh token
	reasonExpired      = "expired"       // the session reached its idle or absolute limit
	reasonStepUp       = "step_up"       // policy asks for a fresher authentication
	reasonScope        = "scope"         // a scope outside the grant
	reasonClientSecret = "client_secret" // a public client sent a secret
)

// audited is the outcome of one step, as the audit record names it.
type audited struct {
	action  audit.Action
	tenant  string
	subject *audit.Subject
	policy  *audit.PolicyRef
	reason  string // empty on success
	sluis   map[string]any
}

func (s *Service) event(a audited) audit.Event {
	ev := audit.Event{Action: a.action, Status: audit.StatusSuccess, Tenant: a.tenant, Subject: a.subject, Policy: a.policy, Sluis: a.sluis}
	if a.reason != "" {
		ev.Status, ev.StatusCode = audit.StatusFailure, a.reason
	}
	return ev
}

// record hands a step to the audit transport. A success is recorded or the step fails: a sign-in, a code or a token
// whose audit fact was not accepted must not leave session (fail closed), so the error is returned and the caller
// returns unavailable. A failed step is recorded best effort: the caller already answers with the refusal, and an
// audit outage must not turn a refusal into something else.
func (s *Service) record(ctx context.Context, a audited) error {
	err := s.opts.Audit.Emit(ctx, s.event(a))
	if err == nil {
		return nil
	}
	slog.Error("audit emit failed", "action", a.action.Name)
	if a.reason != "" {
		return nil
	}
	return refusal.New(connect.CodeUnavailable, "audit", "")
}

func personSubject(tenant, subject string) *audit.Subject {
	return &audit.Subject{Tenant: tenant, Kind: subjectPerson, Value: subject}
}

func clientSubject(tenant, clientID string) *audit.Subject {
	return &audit.Subject{Tenant: tenant, Kind: subjectClient, Value: clientID}
}
