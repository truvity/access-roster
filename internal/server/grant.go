package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// What one consumer of the API listener may ask (INF-679).
//
// Admission and authorization were one decision: an admitted consumer
// was admitted to everything. `ListGroups` returned every group of every
// company the hub serves, `Describe` listed every domain, `ResolveUser`
// answered for any address. One consumer -- the issuer -- genuinely
// needs all of that. The next one, a team-sync or a cross-cluster hook,
// needs one directory and one question, and giving it the whole hub
// because it presented a valid token is the gap this closes.
//
// Three axes, one enforcement point. WHO is still the ServiceAccount the
// cluster vouches for; WHICH DIRECTORY is a set of workspaces or the
// domains they serve; WHICH QUESTION is a set of read classes. A
// consumer declared with no grant at all keeps full read, so nothing
// that exists today changes meaning.
//
// Two properties this deliberately preserves:
//
//   - An address outside the grant answers exactly as an address in an
//     unserved domain does -- not found, not in domain, no groups. A
//     refusal would say "this domain exists and you may not see it",
//     which is the fact the grant is there to withhold, and consumers
//     already implement the fail-safe reading of the unserved answer.
//   - The listener is read-only forever. No grant carries a write, and
//     there is no read class that could be spelled to get one: writes
//     live on the console listener behind operator sessions.

// Read is one class of question, and the unit a grant is written in. The
// classes group calls that leak the same thing: whether an address
// exists and what it holds, versus what the directory contains, versus
// what this hub serves at all.
type Read string

const (
	// ReadResolve is ResolveUser, GetAccount and ResolveAccounts: what
	// one address, already known to the caller, resolves to.
	ReadResolve Read = "resolve"
	// ReadGroups is GetGroup and ListGroups: what the directory
	// contains, which is the enumeration a resolve-only consumer must
	// not have.
	ReadGroups Read = "groups"
	// ReadDescribe is Describe: which domains this hub serves. Discovery
	// itself is scoped, so a consumer granted one directory is not told
	// the others exist.
	ReadDescribe Read = "describe"
	// ReadProbe is Probe: whether a workspace's last read succeeded.
	ReadProbe Read = "probe"
)

// reads maps a procedure name onto the class it belongs to. Keyed by the
// bare method rather than the full path so that the mapping reads as the
// contract does, and a method added to the service without a class here
// is refused rather than admitted -- which is the safe direction for a
// table that decides what a caller may see.
var reads = map[string]Read{
	"ResolveUser":     ReadResolve,
	"GetAccount":      ReadResolve,
	"ResolveAccounts": ReadResolve,
	"GetGroup":        ReadGroups,
	"ListGroups":      ReadGroups,
	"Describe":        ReadDescribe,
	"Probe":           ReadProbe,
}

// Grant is one consumer's, as the deployment declares it.
type Grant struct {
	// Consumer is namespace/serviceaccount, for the log. The subject the
	// API server returns is the identity; this is what an operator
	// reading the declaration recognises.
	Consumer string `yaml:"consumer" json:"consumer"`
	// Workspaces this consumer may ask about. Empty is every workspace.
	Workspaces []string `yaml:"workspaces,omitempty" json:"workspaces,omitempty"`
	// Domains this consumer may ask about, which is the API's own
	// routing key. Empty is every domain. Named alongside Workspaces
	// rather than instead of it because a consumer that cares about a
	// tenant should say the tenant, and one that cares about a mail
	// domain should say the domain; either resolves to the same test.
	Domains []string `yaml:"domains,omitempty" json:"domains,omitempty"`
	// Groups this consumer may see, by exact address or by a `*` suffix.
	// Empty is every group. A group outside the grant is absent from
	// ListGroups and not found by GetGroup, and does not appear in the
	// groups an address resolves to.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// Reads this consumer may perform. Empty is every read.
	Reads []Read `yaml:"reads,omitempty" json:"reads,omitempty"`
}

// Validate refuses a grant that cannot mean what it says.
func (g *Grant) Validate() error {
	if g == nil {
		return nil
	}

	for _, read := range g.Reads {
		if !slices.Contains([]Read{ReadResolve, ReadGroups, ReadDescribe, ReadProbe}, read) {
			return fmt.Errorf("consumer %s: %q is not a read class: resolve, groups, describe or probe", g.Consumer, read)
		}
	}

	for _, pattern := range g.Groups {
		if strings.Contains(strings.TrimSuffix(pattern, "*"), "*") {
			return fmt.Errorf("consumer %s: group pattern %q may only end in *", g.Consumer, pattern)
		}
	}

	return nil
}

// Everything reports whether this grant withholds nothing, which is what
// a consumer declared with no grant gets and what the issuer has.
func (g *Grant) Everything() bool {
	return g == nil || (len(g.Workspaces) == 0 && len(g.Domains) == 0 && len(g.Groups) == 0 && len(g.Reads) == 0)
}

// ScopedToDirectories reports whether this grant names particular
// directories. When it does not, no domain has to be resolved and the
// request path stays exactly as short as it is today.
func (g *Grant) ScopedToDirectories() bool {
	return g != nil && (len(g.Workspaces) > 0 || len(g.Domains) > 0)
}

// NeedsRouting reports whether enforcing this grant needs the hub's
// domain-to-workspace map. Only a grant written in workspaces does: one
// written in domains is already in the key every point lookup carries.
func (g *Grant) NeedsRouting() bool { return g != nil && len(g.Workspaces) > 0 }

// Allows reports whether a read class is granted.
func (g *Grant) Allows(read Read) bool {
	return g == nil || len(g.Reads) == 0 || slices.Contains(g.Reads, read)
}

// AllowsDomain reports whether this consumer may ask about a domain.
//
// routing maps domain to workspace and may be nil, in which case a grant
// written in workspaces admits nothing -- the fail-closed direction, and
// the honest one: without the map the hub cannot tell whether the domain
// belongs to a workspace this consumer holds.
func (g *Grant) AllowsDomain(domain string, routing map[string]string) bool {
	if !g.ScopedToDirectories() {
		return true
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	if slices.Contains(g.Domains, domain) {
		return true
	}

	return slices.Contains(g.Workspaces, routing[domain])
}

// AllowsWorkspace reports whether this consumer may ask about a
// workspace, for the calls that carry one directly.
func (g *Grant) AllowsWorkspace(workspace string, routing map[string]string) bool {
	if !g.ScopedToDirectories() {
		return true
	}

	if slices.Contains(g.Workspaces, workspace) {
		return true
	}

	for domain, serving := range routing {
		if serving == workspace && slices.Contains(g.Domains, domain) {
			return true
		}
	}

	return false
}

// AllowsGroup reports whether a group address is inside the grant.
func (g *Grant) AllowsGroup(email string) bool {
	if g == nil || len(g.Groups) == 0 {
		return true
	}

	email = strings.ToLower(strings.TrimSpace(email))

	for _, pattern := range g.Groups {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if prefix, wild := strings.CutSuffix(pattern, "*"); wild {
			if strings.HasPrefix(email, prefix) {
				return true
			}

			continue
		}

		if email == pattern {
			return true
		}
	}

	return false
}

// KeepGroups filters a list of group addresses to the granted ones.
func (g *Grant) KeepGroups(emails []string) []string {
	if g == nil || len(g.Groups) == 0 {
		return emails
	}

	kept := make([]string, 0, len(emails))

	for _, email := range emails {
		if g.AllowsGroup(email) {
			kept = append(kept, email)
		}
	}

	return kept
}

// domainOf reads the domain out of an address. An address with no `@` has
// no domain and belongs to no directory, which every caller here treats
// as outside the grant.
func domainOf(address string) string {
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(address[at+1:]))
}

// readOf returns the class a request path belongs to. The second result
// is false for a path that is not a procedure of this service, which the
// guard refuses rather than admits.
func readOf(path string) (Read, bool) {
	slash := strings.LastIndex(path, "/")
	if slash < 0 {
		return "", false
	}

	read, ok := reads[path[slash+1:]]

	return read, ok
}

type grantKey struct{}

// WithGrant carries one request's grant. Nil means full read, which is
// also what an unguarded listener has.
func WithGrant(ctx context.Context, grant *Grant) context.Context {
	return context.WithValue(ctx, grantKey{}, grant)
}

// GrantOf reads the grant back. Absent is full read: a handler reached
// without passing the guard is a local run, and the guard's own absence
// is already said out loud at start.
func GrantOf(ctx context.Context) *Grant {
	grant, _ := ctx.Value(grantKey{}).(*Grant)

	return grant
}
