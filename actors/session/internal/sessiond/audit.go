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
	ActionRevoke    = "session.revoke"
)

var (
	actionAuthorize = audit.Action{Name: ActionAuthorize, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Authorize"}
	actionSignin    = audit.Action{Name: ActionSignin, ClassUID: classAuthentication, ActivityID: 1}
	actionToken     = audit.Action{Name: ActionToken, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Grant"}
	actionRefresh   = audit.Action{Name: ActionRefresh, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Refresh"}
	actionChainEnd  = audit.Action{Name: ActionChainEnd, ClassUID: classAuthentication, ActivityID: 2}
	actionRevoke    = audit.Action{Name: ActionRevoke, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Token Revocation"}
)

// The kinds of identity session names in a record (0029 "Pseudonyms": the kind is part of the pseudonym's input). A
// step with no person yet concerns the client; a step with a person concerns the person.
const (
	subjectPerson = "person"
	subjectClient = "client"
)

// The closed reasons of a failed step. A reason names the rule that refused and never a value.
const (
	reasonClient      = "client"       // unknown client, or one session does not serve
	reasonRedirectURI = "redirect_uri" // not the client's registered redirect_uri
	reasonRequest     = "request"      // a parameter missing, repeated or malformed
	reasonPKCE        = "pkce"         // no S256 challenge, or the verifier does not match
	reasonMaxAge      = "max_age"      // the upstream's authentication is older than the client allowed, or undated
	reasonPrompt      = "prompt"       // a prompt that is malformed, or asks for what session does not show (consent, an account chooser)
	reasonFresh       = "fresh"        // prompt=login or max_age=0, and the upstream's authentication is not from this request, or its time cannot be right
	// The four errors of OpenID Connect Core section 3.1.2.6 that an upstream answers a request for no interaction with are
	// reasons too, each as it was sent: reasonLoginRequired, reasonInteractionRequired, reasonConsentRequired and
	// reasonAccountSelectionRequired.
	reasonLoginRequired            = "login_required"
	reasonInteractionRequired      = "interaction_required"
	reasonConsentRequired          = "consent_required"
	reasonAccountSelectionRequired = "account_selection_required"
	reasonCookie                   = "cookie"        // the sign-in cookie is missing, altered or expired
	reasonState                    = "state"         // the callback's state is not the one sent
	reasonUpstream                 = "upstream"      // the upstream refused or failed the sign-in
	reasonDenied                   = "denied"        // policy denied
	reasonHeld                     = "held"          // the person is held
	reasonCode                     = "code"          // an unknown, expired or spent code
	reasonReuse                    = "reuse"         // a spent code or refresh token presented again
	reasonRefresh                  = "refresh_token" // an unknown refresh token
	reasonExpired                  = "expired"       // the session reached its idle or absolute limit
	reasonStepUp                   = "step_up"       // policy asks for a fresher authentication
	reasonScope                    = "scope"         // a scope outside the grant
	reasonClientSecret             = "client_secret" // a public client sent a secret
	reasonHint                     = "id_token_hint" // the hint is not an ID token of this issuer for the client, or the person who signed in is not its subject
	reasonPin                      = "subject_claim" // the upstream's subject claim is not the one its issuer's first link pinned
	reasonTokenType                = "token_type"    // a token of a type the endpoint does not revoke (an access token)
	reasonRevoked                  = "revoked"       // the client revoked a refresh token of the chain
)

// reasons is the closed list of the words above: the only reasons a refusal is logged or audited with.
var reasons = []string{
	reasonClient, reasonRedirectURI, reasonRequest, reasonPKCE, reasonMaxAge, reasonCookie, reasonState, reasonUpstream,
	reasonDenied, reasonHeld, reasonCode, reasonReuse, reasonRefresh, reasonExpired, reasonStepUp, reasonScope,
	reasonClientSecret, reasonHint, reasonPin, reasonTokenType, reasonRevoked,
}

// logRefusal writes the log line of a refusal at the authorization, the callback or the token endpoint (REQ-OBS-020 to
// 022). It names the OAuth error the caller was given, the closed reason and the client when the installation declares
// it, and nothing the caller sent: not the query, the state, a challenge, a code, a token or the client id of a client
// that is not declared. A refusal is the caller's mistake or the person's no, so it is logged at info; a failed
// dependency is logged at error where it fails (unavailable).
func logRefusal(a audit.Action, code, reason, declaredClient string) {
	attrs := []any{"action", a.Name, "error", code, "reason", reason}
	if declaredClient != "" {
		attrs = append(attrs, "client_id", declaredClient)
	}
	slog.Info("refused", attrs...)
}

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
	// A success fails its step when its fact is not accepted, so the fact is not lost and is not counted
	// (EmitRequired); a failed step is best effort, and a loss is counted for the log (Emit).
	emit := s.opts.Audit.Emit
	if a.reason == "" {
		emit = s.opts.Audit.EmitRequired
	}
	err := emit(ctx, s.event(a))
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
