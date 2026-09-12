package issuerapp

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/truvity/access-roster/identity"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/logsafe"
)

// workloadBearer reads a ServiceAccount token a workload presents to the
// console as its bearer, and hands the console the account it proves.
//
// It exists for one kind of caller: a controller in the same cluster —
// the GitHub controller is the first — reading the console's API with the
// token its kubelet projected. The rule is the one
// docs/connect/service-to-service.md states for every same-cluster call:
// present the ServiceAccount token, never an exchange in front of it,
// because the issuer would verify that very token and re-sign it.
//
// The verification is the SAME set of cluster verifiers token exchange
// uses, checked against each cluster's published key set. There is no
// TokenReview here and no second list of clusters: a second place for an
// installation's trust to be configured is a second place for it to be
// wrong.
//
// What the account may then do is not decided here. It becomes a
// principal with a ServiceAccount, and the policy's `service_account`
// matchers put it in groups exactly as they do for an exchange — which
// is how an empty policy admits it to nothing.
//
// Nil when no cluster is federated: there is then nothing a workload
// could present that would verify, and a reader that refuses everything
// is better absent than consulted on every request.
func workloadBearer(clusters issuer.Verifiers, log *slog.Logger) func(*http.Request) (access.Principal, bool) {
	if len(clusters) == 0 {
		return nil
	}
	return func(r *http.Request) (access.Principal, bool) {
		token := identity.TokenFrom(r)
		if token == "" {
			return access.Principal{}, false
		}

		proof, err := clusters.Verify(r.Context(), token, "")
		if err != nil {
			// A token no federated cluster recognises is somebody else's —
			// an issuer-signed bearer on its way to the forwarded path —
			// and is passed on in silence. A token a cluster DID recognise
			// and refused is worth a line: it is a workload with the wrong
			// audience, an expired projection, or a forgery. Why goes to
			// the log and never to the caller.
			if !errors.Is(err, issuer.ErrUnverified) {
				log.WarnContext(r.Context(), "a workload's token was refused at the console",
					"error", logsafe.Error(err))
			}
			return access.Principal{}, false
		}
		// A cluster verifier only ever proves a ServiceAccount, but the
		// check is what keeps a future verifier in this list from
		// admitting something that is not one through the workload door.
		if proof.ServiceAccount == nil {
			return access.Principal{}, false
		}
		return access.Principal{
			Subject:        proof.Subject(),
			Source:         access.SourceWorkload,
			ServiceAccount: proof.ServiceAccount,
		}, true
	}
}
