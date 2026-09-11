package issuer

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/truvity/access-roster/policy"
)

// GrantsPath is where a caller asks what its own groups open.
const GrantsPath = "/.access/grants"

// Opens is one client the caller may be issued a token for. Named for
// what it answers rather than `Grant`, which in this package is already
// the decision an exchange returns.
type Opens struct {
	// Audience is the client id, which is the `aud` of a token minted
	// for it and the thing a caller asks an exchange for.
	Audience string `json:"audience"`
	// Kind is public, confidential or exchange: how a caller obtains a
	// token for it, which decides whether a CLI can do it at all.
	Kind string `json:"kind"`
	// Through are the caller's groups that admit it, so a person reading
	// this knows WHY rather than only that.
	Through []string `json:"through"`
}

// grantsHandler answers what the caller's groups open.
//
// It exists so that `accessctl kubeconfig` and `aws-config` can write a
// context per cluster and a profile per role without being told what to
// write. The alternative is a list kept on every laptop, which drifts
// from the policy the moment anybody's groups change — and drifts
// silently, because a stale entry looks exactly like a granted one until
// it is used.
//
// It discloses nothing a caller could not already work out: the answer
// is derived from the groups in the token it presented, and naming what
// they open is the same information the console shows the person about
// themselves.
func grantsHandler(set *policy.Set, verify func(context.Context, string) (string, []string, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := bearerFrom(r)
		if bearer == "" {
			http.Error(w, "a bearer token is required", http.StatusUnauthorized)
			return
		}
		_, groups, err := verify(r.Context(), bearer)
		if err != nil {
			// Why it failed is not said: telling an unauthenticated
			// caller what was wrong with its token helps it make a
			// better one.
			http.Error(w, "that token was not accepted", http.StatusUnauthorized)
			return
		}

		held := policy.Result{Groups: groups}
		clients := set.Clients()
		var out []Opens
		// Indexed rather than ranged by value: a ClientView carries the
		// whole declared client, and copying every one of them per
		// request is work for nothing on the busiest path a laptop has.
		for i := range clients {
			client := &clients[i]
			if !client.Admits(held) {
				continue
			}
			out = append(out, Opens{
				Audience: client.ID,
				Kind:     client.Kind,
				Through:  intersect(client.Requires, groups),
			})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Audience < out[j].Audience })

		w.Header().Set("Content-Type", "application/json")
		// An empty list is an answer — "your groups open nothing" — and
		// it must not encode as null, which a shell reading this with jq
		// cannot iterate.
		if out == nil {
			out = []Opens{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"grants": out})
	})
}

// intersect is the caller's groups that admit a client, in the client's
// own order so two callers see the same reason spelled the same way.
func intersect(requires, held []string) []string {
	var out []string
	for _, name := range requires {
		for _, have := range held {
			if name == have {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// bearerFrom reads the token, from either header a caller may use.
func bearerFrom(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Auth-Request-Access-Token")); forwarded != "" {
		return forwarded
	}
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}
