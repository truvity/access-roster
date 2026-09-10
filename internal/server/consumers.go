package server

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/truvity/access-roster/internal/logsafe"
)

// Consumers is who may call the API listener.
//
// The listener answers the two directory questions for every workspace
// this hub reads — every account, every group, every membership of every
// company it serves — so "reachable" must not be the same as "allowed".
// A NetworkPolicy is a second layer and a good one; it is not an answer
// to "which workload is this", and it is one misapplied label away from
// admitting a namespace nobody meant to.
//
// The proof is a projected ServiceAccount token with this hub's audience,
// verified by the API server. The hub therefore trusts no signature of
// its own and keeps no shared secret: it asks the cluster who is calling,
// and compares the answer to a list the deployment states.
type Consumers struct {
	// Review is [kube.Client.ReviewToken]. Nil means the hub is not
	// running in a cluster and cannot check anything, which is a
	// different situation from an empty list — see [Consumers.Middleware].
	Review func(ctx context.Context, token string, audiences []string) (string, error)
	// Audience the token must have been minted for.
	Audience string
	// Allowed subjects, as the API server spells them.
	Allowed []string
	// Grants is what each admitted subject may ask, keyed the same way
	// as Allowed (INF-679). A subject with no entry keeps full read, so
	// a deployment that declares consumers and no grants behaves exactly
	// as it did.
	Grants map[string]*Grant
	Log    *slog.Logger
}

// Middleware guards a handler.
//
// Two situations that look alike and are not. **No reviewer** is a hub
// outside a cluster — a local run, the demonstration — where there is
// nothing to verify a token against; the listener is open and the caller
// is told so at start, loudly, because that is a development posture and
// never a deployed one. **A reviewer and an empty list** is a deployment
// that named no consumers, and it admits nobody: a hub that answered
// everyone by default would be one forgotten value away from serving a
// company's directory to the cluster.
func (c *Consumers) Middleware(next http.Handler) http.Handler {
	if c == nil || c.Review == nil {
		return next
	}
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			refuse(w, "this listener needs a ServiceAccount token with the audience "+c.Audience)
			return
		}
		subject, err := c.Review(r.Context(), token, []string{c.Audience})
		if err != nil {
			// One message for a rejected token and for a review that
			// could not run. The caller is unauthenticated; which of the
			// two it was is in the hub's log, where an operator can see
			// it and a caller cannot.
			log.WarnContext(r.Context(), "API call refused",
				"path", logsafe.Value(r.URL.Path), "error", logsafe.Error(err))
			refuse(w, "that token was not accepted")
			return
		}
		if !slices.Contains(c.Allowed, subject) {
			log.WarnContext(r.Context(), "API call refused: not a consumer",
				"path", logsafe.Value(r.URL.Path), "subject", logsafe.Value(subject))
			refuse(w, subject+" is not a consumer of this hub")
			return
		}
		grant := c.Grants[subject]
		read, known := readOf(r.URL.Path)
		if !known {
			// A path that is not a procedure of this service. Refused
			// rather than admitted: the read table is what decides what
			// a caller may see, and a call it has no entry for is one
			// nobody has decided about.
			log.WarnContext(r.Context(), "API call refused: not a procedure of this service",
				"path", logsafe.Value(r.URL.Path), "subject", logsafe.Value(subject))
			deny(w, "this listener serves directory.v1.DirectoryService and nothing else")
			return
		}
		if !grant.Allows(read) {
			log.WarnContext(r.Context(), "API call refused: outside the grant",
				"path", logsafe.Value(r.URL.Path), "subject", logsafe.Value(subject),
				"read", string(read), "granted", grantedReads(grant))
			deny(w, "this consumer may not "+string(read))
			return
		}
		// One line per admitted call, naming the rule that let it
		// through. A grant nobody can see the effect of is one an
		// operator has to reason about from the declaration alone.
		log.DebugContext(r.Context(), "API call admitted",
			"path", logsafe.Value(r.URL.Path), "subject", logsafe.Value(subject),
			"read", string(read), "scoped", !grant.Everything())
		next.ServeHTTP(w, r.WithContext(WithGrant(r.Context(), grant)))
	})
}

// bearer reads the token from the Authorization header.
func bearer(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) < 7 || !strings.EqualFold(value[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

func refuse(w http.ResponseWriter, reason string) {
	// WWW-Authenticate so that a client library reports "unauthenticated"
	// rather than a bare transport failure.
	w.Header().Set("WWW-Authenticate", `Bearer realm="directory-roster"`)
	http.Error(w, reason, http.StatusUnauthorized)
}

// deny refuses a call the caller is authenticated for and not permitted.
// Distinct from [refuse] on purpose: 401 tells a client library to go and
// get a credential, and a consumer whose grant does not cover a read has
// the right credential already — sending it back for another one is how a
// permission problem gets diagnosed as an authentication one.
func deny(w http.ResponseWriter, reason string) {
	http.Error(w, reason, http.StatusForbidden)
}

// grantedReads names what a grant does allow, for the refusal's log line.
// Empty means every read, which is not a state that reaches here.
func grantedReads(grant *Grant) []string {
	if grant == nil {
		return nil
	}
	out := make([]string, 0, len(grant.Reads))
	for _, read := range grant.Reads {
		out = append(out, string(read))
	}
	return out
}
