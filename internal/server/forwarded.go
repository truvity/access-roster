package server

import (
	"log/slog"
	"net/http"

	"github.com/truvity/access-roster/identity"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/logsafe"
)

// forwardedBearer turns a token an authenticating gateway forwarded into
// a principal, by verifying it against the issuer's published keys.
//
// The verification is [identity.Issuer] — the package this project
// publishes for its consumers — and not a copy of it. access-roster uses
// the library it ships: a library its own author does not use is a
// library nobody has tested against a real listener, and every gap in it
// then surfaces first in whichever consumer is unlucky.
//
// What is left here is the part a consumer does NOT share. This service
// resolves groups from its own policy and its own directory, in process,
// so a verified token gives it an ADDRESS and the authorizer does the
// rest; a consumer reads the groups out of the token, because it has no
// policy to consult. Same verification, different question after it.
type forwardedBearer struct {
	issuer *identity.Issuer
	log    *slog.Logger
}

// newForwardedBearer builds the verified path, or nothing.
//
// No issuer means no verification is possible, and a nil verifier is how
// that is said -- not a verifier that accepts everything, which is the
// same mistake as an empty consumer list that admits the cluster.
func newForwardedBearer(cfg ForwardedIdentity, log *slog.Logger) *forwardedBearer {
	if cfg.Issuer == "" {
		return nil
	}
	return &forwardedBearer{
		issuer: &identity.Issuer{URL: cfg.Issuer, Audience: cfg.Audience},
		log:    log,
	}
}

// identity is the console's hook: a verified principal, or nothing.
func (b *forwardedBearer) identity(r *http.Request) (access.Principal, bool) {
	token := identity.TokenFrom(r)
	if token == "" {
		return access.Principal{}, false
	}

	who, err := b.issuer.Verify(r.Context(), token)
	if err != nil {
		// Why it failed goes to the log and not to the caller: telling an
		// unauthenticated client what was wrong with its token helps it
		// produce a better one.
		b.log.WarnContext(r.Context(), "forwarded token rejected", "error", logsafe.Error(err))
		return access.Principal{}, false
	}

	// A ServiceAccount subject is a recovery sign-in at the issuer, which
	// completes as the account rather than as an address. It is not a
	// person and there is no directory to ask about it: the policy's
	// `service_account` matchers decide, exactly as they do for a
	// workload exchanging a token.
	if who.ServiceAccount != nil {
		return access.Principal{
			Subject:        who.Subject,
			Source:         access.SourceForwarded,
			Issuer:         b.issuer.URL,
			ServiceAccount: who.ServiceAccount,
		}, true
	}
	if who.Email == "" {
		b.log.WarnContext(r.Context(), "forwarded token names neither an address nor a ServiceAccount",
			"subject", logsafe.Value(who.Subject))
		return access.Principal{}, false
	}

	return access.Principal{
		Email:   who.Email,
		Subject: who.Subject,
		Source:  access.SourceForwarded,
		Issuer:  b.issuer.URL,
	}, true
}
