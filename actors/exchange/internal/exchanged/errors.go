package exchanged

import "fmt"

// The error codes of the token endpoint that exchange answers with (RFC 6749 section 5.2; RFC 8693 section 2.2.2).
const (
	codeInvalidRequest   = "invalid_request"
	codeInvalidTarget    = "invalid_target"
	codeInvalidScope     = "invalid_scope"
	codeUnsupportedGrant = "unsupported_grant_type"
)

// The closed reasons of a refusal, as the audit record says them (REQ-EXCH-009). A reason names the check that
// refused and never a value. The caller of the endpoint sees only the OAuth error code.
const (
	reasonGrantType     = "grant_type"
	reasonSubjectToken  = "subject_token"
	reasonSubjectType   = "subject_token_type"
	reasonRequestedType = "requested_token_type"
	reasonActorToken    = "actor_token"
	reasonResource      = "resource"
	reasonScope         = "scope"
	reasonAudience      = "audience"
	reasonClient        = "client"
	reasonIssuer        = "issuer"
	reasonSignature     = "signature"
	reasonClaims        = "claims"
	reasonExpired       = "expired"
	reasonReplay        = "replay"
	reasonProofKind     = "proof_kind"
	reasonPerson        = "person"
	reasonSessionEnded  = "session_ended"
	reasonPolicy        = "policy"
	reasonLifetime      = "lifetime"
)

// refused is an answer in the form of the token endpoint: a status 400 with an OAuth error code. The reason is for
// the audit record only.
type refused struct {
	code   string
	reason string
}

func (r *refused) Error() string { return fmt.Sprintf("refused: %s (%s)", r.code, r.reason) }

func invalidRequest(reason string) error { return &refused{codeInvalidRequest, reason} }
func invalidTarget(reason string) error  { return &refused{codeInvalidTarget, reason} }

// outage is a dependency that did not answer. exchange fails closed: the call ends in a Connect error, never in an
// answer on a weaker basis (ADR 0017, "Directory outages").
type outage struct {
	reason string // the dependency: store, policy, signer, key, directory or audit
	err    error
}

func (o *outage) Error() string { return "unavailable: " + o.reason }
func (o *outage) Unwrap() error { return o.err }

func unavailable(reason string, err error) error { return &outage{reason, err} }
