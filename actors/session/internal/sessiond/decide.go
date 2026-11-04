package sessiond

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

// The states of a person that policy sees (policy.md "Entity types": live or held in the first version). A person
// is held when an operator's PersonHold exists; session computes the state and sends it (0019 "States").
const (
	stateLive = "live"
	stateHeld = "held"
)

// question is what session asks policy: may this person have a token for this client, with how they authenticated.
// The action is always token.issue (policy.md "Actions"): the sign-in, the code exchange and a refresh all ask it,
// each with the facts it has.
type question struct {
	tenant   string
	subject  string
	accounts []string
	state    string
	client   *configv2alpha1.InstallationClient
	assure   assurance
	now      time.Time
	// verbs and ops are what the asker needs the grant to allow; policy narrows, never widens.
	verbs, ops []string
}

// verdict is the answer.
type verdict struct {
	allow      bool
	grant      []byte   // the sealed grant, on allow only
	grantNames []string // the full held set after the ladder, sorted
	id         string   // the decision id, also in policy's audit record
	digest     string
	policyIDs  []string
	stepUp     map[string]string // the values of an @step_up annotation of a determining forbid: acr_values, max_age
}

// ref is the decision as the audit record of the action it gated names it (0030 "The class mapping").
func (v verdict) ref() *audit.PolicyRef {
	if v.id == "" {
		return nil
	}
	d := audit.DecisionDenied
	if v.allow {
		d = audit.DecisionAllowed
	}
	return &audit.PolicyRef{DecisionID: v.id, Digest: v.digest, PolicyIDs: v.policyIDs, Decision: d}
}

// decide asks policy. A denial is an answer and not an error. Anything else is: policy unavailable is unavailable
// for the caller (session cannot decide, so it fails closed), and a refusal of the question itself (a missing fact)
// is a bug of session, never shown to the caller.
func (s *Service) decide(ctx context.Context, q question) (verdict, error) {
	ctxFacts := &policyv2alpha1.Authentication{Acr: q.assure.acr, Amr: q.assure.amr, AmrPresent: q.assure.amrPresent}
	if age, ok := q.assure.authAge(q.now); ok {
		ctxFacts.AuthAge = &age
	}
	req := &policyv2alpha1.DecideRequest{
		Action:    "token.issue",
		Principal: &policyv2alpha1.EntityRef{Type: "Person", Id: q.subject},
		Resource:  &policyv2alpha1.EntityRef{Type: "Client", Id: q.client.GetId()},
		Tenant:    q.tenant,
		Context:   ctxFacts,
		Person: &policyv2alpha1.PersonFacts{
			Subject: q.subject, Accounts: q.accounts, State: q.state, Org: q.tenant,
		},
		Client: &policyv2alpha1.ClientFacts{
			Id: q.client.GetId(), Requires: q.client.GetRequires(), Kind: q.client.GetKind(),
		},
		GrantStoreVerbs: q.verbs,
		GrantKeyOps:     q.ops,
	}
	res, err := s.opts.Policy.Decide(ctx, connect.NewRequest(req))
	if err != nil {
		return verdict{}, fmt.Errorf("policy decide: %w", err)
	}
	m := res.Msg
	v := verdict{id: m.GetDecisionId(), digest: m.GetDigest(), grantNames: m.GetGrantNames()}
	for _, r := range m.GetReasons() {
		v.policyIDs = append(v.policyIDs, r.GetPolicyId())
	}
	switch m.GetDecision() {
	case policyv2alpha1.Decision_ALLOW:
		if len(m.GetSealedGrant()) == 0 {
			// An allow with no grant cannot be carried out: fail closed.
			return verdict{}, fmt.Errorf("policy decide: allow without a grant")
		}
		v.allow, v.grant = true, m.GetSealedGrant()
	case policyv2alpha1.Decision_DENY:
		v.stepUp = stepUpOf(m.GetReasons())
	default:
		return verdict{}, fmt.Errorf("policy decide: no decision")
	}
	return v, nil
}

// stepUpOf reads the @step_up annotation of the policies that denied (policy.md "Step-up"): the values of acr_values
// and max_age that session puts in insufficient_user_authentication (RFC 9470 section 3). Only those two keys are
// read, and max_age only when it is a whole number; anything else in the annotation is ignored, so a policy cannot
// make session write a parameter of its choice.
func stepUpOf(reasons []*policyv2alpha1.Reason) map[string]string {
	for _, r := range reasons {
		raw, ok := r.GetAnnotations()["step_up"]
		if !ok {
			continue
		}
		out := map[string]string{}
		for _, f := range strings.Fields(raw) {
			k, v, ok := strings.Cut(f, "=")
			if !ok || v == "" {
				continue
			}
			switch k {
			case "acr_values":
				out[k] = v
			case "max_age":
				if n, err := strconv.ParseUint(v, 10, 31); err == nil {
					out[k] = strconv.FormatUint(n, 10)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}
