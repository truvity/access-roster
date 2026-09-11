package issuerapp

import (
	"net/http"
	"strings"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// signedIn reads the issuer's own browser session and hands the console
// whoever it belongs to.
//
// This is what the merged service buys, and it is worth stating plainly
// because it removes two things at once. Before it, a console on this
// origin was authenticated either by a proxy in front of it — which ran
// an OpenID flow against an issuer in the SAME PROCESS, a network round
// trip and a second session store to learn something already known — or
// by a login of its own, which is the second door an installation with a
// gateway deliberately turns off. Now it is neither: the browser holds
// the issuer's session cookie at this host, so the console asks who it
// is.
//
// A recovery sign-in completes as a ServiceAccount rather than an
// address, and it has to survive this: recovery exists for the day
// nothing else works, and the console is where the operator then
// connects the first directory.
func signedIn(iss *issuer.Issuer) func(*http.Request) (access.Principal, bool) {
	sso := iss.SSO()
	if sso == nil {
		return nil
	}
	return func(r *http.Request) (access.Principal, bool) {
		session, live, err := sso.Get(r.Context(), issuer.SSOFromRequest(r))
		if err != nil || !live || session.Identity == "" {
			return access.Principal{}, false
		}
		if account, ok := policy.ParseServiceAccountSubject(session.Identity); ok {
			return access.Principal{
				Subject:        session.Identity,
				Source:         access.SourceRecovery,
				ServiceAccount: &account,
			}, true
		}
		return access.Principal{
			Email:   strings.ToLower(session.Identity),
			Subject: session.Identity,
			Source:  access.SourceOIDC,
		}, true
	}
}
