package policy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ClientDocuments admits clients that were never declared here.
//
// Every other client in this file is minted as code, and that is the
// right default: a row is reviewable, and its `requires` is where "who
// may obtain a token" is decided. It does not fit a client that is
// somebody's editor or a hosted assistant — software this installation
// does not deploy and cannot enumerate, arriving with the Model Context
// Protocol.
//
// Such a client identifies itself with an HTTPS URL that serves a
// document describing it (OAuth Client ID Metadata Document). The issuer
// fetches the document, validates it, and treats it as a public client.
// Nothing is registered and nothing accumulates.
//
// THE REASON THIS IS PROPORTIONATE, because it is the whole argument:
// registration is not the authorization decision here. Reach is decided
// by the groups a caller holds, and a client this issuer has never seen
// cannot widen them — it can only ask a person to consent to the reach
// that person already has. So the threat is not escalation. It is
// phishing: a hostile client persuading somebody to sign in to it and
// taking the token away. Which is why the guard below is an allow-list
// of ORIGINS rather than a refusal of unknown clients, and why
// [ClientDocuments.Requires] is mandatory rather than optional.
type ClientDocuments struct {
	// Origins are the hosts that may serve a document. A host, or a host
	// and port; never a scheme, a path or a wildcard — the scheme is
	// always HTTPS and a path would be a client, not an origin.
	//
	// Empty turns the whole mechanism off, which is the default: an
	// installation that has not named a host does not accept documents.
	Origins []string `yaml:"origins,omitempty"`
	// Requires lists internal groups, any one of which admits a caller to
	// EVERY document client. It is the same gate a declared client's
	// `requires` is, and it is mandatory: turning this mechanism on
	// without saying who may use it would admit every person who can sign
	// in at all, which is not a decision anybody would make on purpose.
	Requires []string `yaml:"requires,omitempty"`
	// TTLCap caps the lifetime of a document client's tokens, as
	// `ttl_cap` does on a declared client. Optional, and worth setting:
	// these tokens go to software this installation did not deploy.
	TTLCap Duration `yaml:"ttl_cap,omitempty"`
}

// Enabled reports whether any document client may be admitted.
func (d ClientDocuments) Enabled() bool { return len(d.Origins) > 0 }

// Permits reports whether a document URL's host is allow-listed.
//
// An exact host match, because a suffix match is how `claude.ai.evil`
// gets in and a wildcard is how somebody's forgotten subdomain does.
// Comparison is case-insensitive: a host is, and a client that upper-cases
// its own URL should not be refused for it.
func (d ClientDocuments) Permits(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	return slices.ContainsFunc(d.Origins, func(allowed string) bool {
		return strings.ToLower(allowed) == host
	})
}

// validate refuses a block that would admit more than its author meant.
func (d ClientDocuments) validate(groups map[string]Group) error {
	for _, origin := range d.Origins {
		if err := validateOrigin(origin); err != nil {
			return fmt.Errorf("client_documents: %w", err)
		}
	}
	if !d.Enabled() {
		// Off, and the rest is then inert rather than wrong -- except
		// that writing it means somebody expected it to apply.
		if len(d.Requires) > 0 || d.TTLCap.Duration() != 0 {
			return fmt.Errorf("client_documents declares requires or ttl_cap and no origins, so none of it applies")
		}
		return nil
	}
	if len(d.Requires) == 0 {
		return fmt.Errorf("client_documents lists origins and requires no group, which would admit every person who can sign in")
	}
	for _, name := range d.Requires {
		if _, ok := groups[name]; !ok {
			return fmt.Errorf("client_documents requires %q, which is not a declared group", name)
		}
	}
	return nil
}

// validateOrigin holds an origin to a host, so the allow-list cannot be
// read as matching more than it says.
func validateOrigin(origin string) error {
	if strings.TrimSpace(origin) == "" {
		return fmt.Errorf("an origin with no host")
	}
	if strings.Contains(origin, "://") {
		return fmt.Errorf("origin %q carries a scheme; name the host alone (HTTPS is the only scheme served)", origin)
	}
	if strings.ContainsAny(origin, "/?#") {
		return fmt.Errorf("origin %q carries a path; an origin is a host, and a path would be one client rather than a host's clients", origin)
	}
	if strings.Contains(origin, "*") {
		return fmt.Errorf("origin %q is a wildcard; name each host, because a wildcard also admits every subdomain somebody forgot about", origin)
	}
	// url.Parse is forgiving enough to accept a bare host as a path, so
	// the host is checked by parsing it as an authority.
	if _, err := url.Parse("https://" + origin); err != nil {
		return fmt.Errorf("origin %q is not a host: %w", origin, err)
	}
	return nil
}
