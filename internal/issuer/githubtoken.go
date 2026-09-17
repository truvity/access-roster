package issuer

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubapp/mints"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/tokens"
)

// GitHubAppStore is where a created catalogue App's record and key are
// kept: the directory half's Secret.
type GitHubAppStore interface {
	Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error)
}

// GitHubApps is what minting an installation token needs: the catalogue
// that says who may ask for how much, the store that holds each App's
// key, and the way to GitHub.
type GitHubApps struct {
	Catalogue *catalogue.Catalogue
	// Store is nil where the deployment keeps no catalogue Apps, and then
	// every request is refused as naming an App that cannot mint.
	Store GitHubAppStore
	// HTTP reaches GitHub. Nil uses a client with a thirty-second timeout.
	HTTP *http.Client
	// Now is the clock the App's JWT is signed against. Nil is time.Now.
	Now func() time.Time
	// Recent is where the last requests of each App are kept, for the
	// console's page for that App to read without querying the trail.
	// Nil keeps none, and the page then says so; the audit trail is the
	// record either way.
	Recent *mints.Ring
}

// UseGitHubApps gives the issuer the catalogue Apps it may mint
// installation tokens for. Without it every such request is refused.
func (i *Issuer) UseGitHubApps(apps GitHubApps) { i.githubApps = &apps }

// GitHubTokenRequest is one installation token asked for.
type GitHubTokenRequest struct {
	// App is the catalogue id, without the `github-app:` prefix.
	App string
	// Repositories are names within the App's organisation. Empty asks
	// for a token that is not narrowed to any, which only a grant of
	// every repository allows.
	Repositories []string
	// Permissions are name to level. Empty asks for exactly what the
	// grant allows.
	Permissions map[string]string
}

// GitHubToken is a minted installation token and what decided it.
type GitHubToken struct {
	githubapp.MintedToken
	Org          string
	Grant        catalogue.Grant
	Installation int64
}

// The refusals minting can end in. Each maps to one RFC 6749 error at the
// token endpoint; see [githubTokenError].
var (
	// ErrGitHubAppUnavailable is an App that cannot mint: not declared,
	// declared and not created, created and not installed, or uninstalled
	// on GitHub since. `invalid_target`.
	ErrGitHubAppUnavailable = errors.New("that GitHub App cannot mint a token")
	// ErrNoGitHubGrant is a caller whose groups no grant of the App names.
	// `invalid_target`, as an ordinary exchange's refusal is: the audience
	// is the decision.
	ErrNoGitHubGrant = errors.New("no grant of that GitHub App names a group this proof holds")
	// ErrGitHubScope is a request wider than any one grant the caller's
	// groups hold: a repository outside them, a permission above them, or
	// no repositories named where no grant covers every one. `invalid_scope`.
	ErrGitHubScope = errors.New("the request is wider than any grant this proof holds")
	// ErrGitHubUpstream is GitHub failing, or the App's key failing.
	// `server_error`.
	ErrGitHubUpstream = errors.New("GitHub did not mint the token")
)

// DecideGitHubGrant picks the grant a request is minted under, and the
// narrowing sent to GitHub.
//
// The rule is ONE GRANT COVERS THE WHOLE REQUEST. Of the App's grants whose
// group the caller holds, in catalogue order:
//
//   - named repositories: each must match some such grant, and the grant
//     chosen must match all of them;
//   - no repositories: the grant chosen must be for every repository
//     (`["*"]`), and the token is not narrowed to any;
//   - named permissions: the grant chosen must cover each at its level;
//   - no permissions: the token asks for exactly the chosen grant's, never
//     the App's full set.
//
// The first grant satisfying all of that is the one. Combining two grants
// into one token is deliberately not done: a token that exists only
// because two separate grants were added together is one nobody declared.
func DecideGitHubGrant(
	app catalogue.App, groups []string, repositories []string, permissions map[string]string,
) (catalogue.Grant, githubapp.Narrowing, error) {
	var held []catalogue.Grant
	for _, grant := range app.Grants {
		if slices.Contains(groups, grant.Group) {
			held = append(held, grant)
		}
	}
	if len(held) == 0 {
		return catalogue.Grant{}, githubapp.Narrowing{}, fmt.Errorf("%w: %q grants %v, this proof holds %v",
			ErrNoGitHubGrant, app.ID, grantGroups(app.Grants), groups)
	}

	var covering []catalogue.Grant
	if len(repositories) > 0 {
		for _, repository := range repositories {
			if !slices.ContainsFunc(held, func(g catalogue.Grant) bool { return g.Matches(repository) }) {
				return catalogue.Grant{}, githubapp.Narrowing{}, fmt.Errorf(
					"%w: repository %q is in no grant of %q this proof holds", ErrGitHubScope, repository, app.ID)
			}
		}
		for _, grant := range held {
			if !slices.ContainsFunc(repositories, func(r string) bool { return !grant.Matches(r) }) {
				covering = append(covering, grant)
			}
		}
		if len(covering) == 0 {
			return catalogue.Grant{}, githubapp.Narrowing{}, fmt.Errorf(
				"%w: no one grant of %q covers all of %v: ask for them in separate tokens", ErrGitHubScope, app.ID, repositories)
		}
	} else {
		for _, grant := range held {
			if slices.Contains(grant.Repositories, "*") {
				covering = append(covering, grant)
			}
		}
		if len(covering) == 0 {
			return catalogue.Grant{}, githubapp.Narrowing{}, fmt.Errorf(
				"%w: name the repositories: no grant of %q this proof holds covers every repository", ErrGitHubScope, app.ID)
		}
	}

	if len(permissions) == 0 {
		chosen := covering[0]
		return chosen, githubapp.Narrowing{Repositories: repositories, Permissions: maps.Clone(chosen.Permissions)}, nil
	}
	for _, grant := range covering {
		if coversAll(grant.Permissions, permissions) {
			return grant, githubapp.Narrowing{Repositories: repositories, Permissions: maps.Clone(permissions)}, nil
		}
	}
	return catalogue.Grant{}, githubapp.Narrowing{}, fmt.Errorf(
		"%w: %s is more than any grant of %q covering those repositories allows (%s)",
		ErrGitHubScope, FormatPermissions(permissions), app.ID, FormatPermissions(covering[0].Permissions))
}

func coversAll(have, want map[string]string) bool {
	for name, level := range want {
		if !catalogue.Covers(have[name], level) {
			return false
		}
	}
	return true
}

func grantGroups(grants []catalogue.Grant) []string {
	var out []string
	for _, grant := range grants {
		if !slices.Contains(out, grant.Group) {
			out = append(out, grant.Group)
		}
	}
	return out
}

// MintGitHubToken decides a request under the catalogue and asks GitHub
// for the token. groups are what the proof resolved to, from the same
// evaluation an ordinary exchange uses.
//
// Nothing is kept: every token is minted on request, and every request is
// audited by the caller.
func (i *Issuer) MintGitHubToken(ctx context.Context, groups []string, request GitHubTokenRequest) (GitHubToken, error) {
	apps := i.githubApps
	if apps == nil || apps.Catalogue == nil {
		return GitHubToken{}, fmt.Errorf("%w: this deployment declares no GitHub Apps", ErrGitHubAppUnavailable)
	}
	app, declared := apps.Catalogue.Get(request.App)
	if !declared {
		return GitHubToken{}, fmt.Errorf("%w: the catalogue declares no App %q", ErrGitHubAppUnavailable, request.App)
	}

	grant, narrowing, err := DecideGitHubGrant(app, groups, request.Repositories, request.Permissions)
	out := GitHubToken{Org: app.Org, Grant: grant}
	if err != nil {
		return out, err
	}

	if apps.Store == nil {
		return out, fmt.Errorf("%w: this deployment keeps no catalogue Apps", ErrGitHubAppUnavailable)
	}
	record, key, found, err := apps.Store.Get(ctx, app.ID)
	switch {
	case err != nil:
		return out, fmt.Errorf("%w: read App %q: %w", ErrGitHubUpstream, app.ID, err)
	case !found:
		return out, fmt.Errorf("%w: App %q is declared and has not been created", ErrGitHubAppUnavailable, app.ID)
	case !record.Installed() || key == "":
		return out, fmt.Errorf("%w: App %q is created and not installed", ErrGitHubAppUnavailable, app.ID)
	}
	out.Installation = record.InstallationID

	now := time.Now
	if apps.Now != nil {
		now = apps.Now
	}
	appToken, err := githubapp.AppToken(record.AppID, key, now())
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrGitHubUpstream, err)
	}
	client := apps.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	minted, err := githubapp.InstallationTokenFor(ctx, client, appToken, record.InstallationID, narrowing)
	var status *githubapp.StatusError
	switch {
	case errors.As(err, &status) && status.Code == http.StatusNotFound:
		return out, fmt.Errorf("%w: GitHub no longer knows App %q's installation: %w", ErrGitHubAppUnavailable, app.ID, err)
	case errors.As(err, &status) && status.Code == http.StatusUnprocessableEntity:
		// Inside the grant and outside the installation: a repository the
		// installer did not select, or a permission they have not accepted.
		return out, fmt.Errorf("%w: %w", ErrGitHubScope, err)
	case err != nil:
		return out, fmt.Errorf("%w: %w", ErrGitHubUpstream, err)
	}
	out.MintedToken = minted
	return out, nil
}

// FormatPermissions spells permissions the way a request's `scope` does:
// `name:level`, sorted, space separated.
func FormatPermissions(permissions map[string]string) string {
	parts := make([]string, 0, len(permissions))
	for _, name := range slices.Sorted(maps.Keys(permissions)) {
		parts = append(parts, name+":"+permissions[name])
	}
	return strings.Join(parts, " ")
}

var (
	requestedRepository = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	requestedPermission = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// maxRepositories is GitHub's own limit on one token's repositories.
const maxRepositories = 500

// ParseGitHubTokenRequest reads the parameters an installation token is
// asked for with: `repositories`, space separated names without the owner,
// and `scope`, space separated `name:level` permissions.
func ParseGitHubTokenRequest(app, repositories, scope string) (GitHubTokenRequest, error) {
	out := GitHubTokenRequest{App: app}
	for _, name := range strings.Fields(repositories) {
		if !requestedRepository.MatchString(name) {
			return out, fmt.Errorf("repositories: %q is not a repository name; name it without the owner", name)
		}
		if !slices.Contains(out.Repositories, name) {
			out.Repositories = append(out.Repositories, name)
		}
	}
	if len(out.Repositories) > maxRepositories {
		return out, fmt.Errorf("repositories: %d named, GitHub mints a token for at most %d", len(out.Repositories), maxRepositories)
	}
	for _, field := range strings.Fields(scope) {
		name, level, ok := strings.Cut(field, ":")
		if !ok || !requestedPermission.MatchString(name) || !catalogue.Covers(level, level) {
			return out, fmt.Errorf("scope: %q is not a permission: spell it name:read, name:write or name:admin", field)
		}
		if out.Permissions == nil {
			out.Permissions = map[string]string{}
		}
		if previous, seen := out.Permissions[name]; seen && previous != level {
			return out, fmt.Errorf("scope: %s is asked for at both %s and %s", name, previous, level)
		}
		out.Permissions[name] = level
	}
	return out, nil
}

// githubTokenEvent is one installation token request, minted or refused.
// Never the token.
func githubTokenEvent(proof Proof, request GitHubTokenRequest, minted GitHubToken, outcome, reason string) audit.Event {
	subject := proof.Subject()
	attributes := map[string]string{"app": request.App}
	set := func(name, value string) {
		if value != "" {
			attributes[name] = value
		}
	}
	set("proof", proof.kind())
	set("org", minted.Org)
	set("grant", minted.Grant.Group)
	repositories, permissions := request.Repositories, request.Permissions
	if minted.Token != "" {
		repositories, permissions = minted.Repositories, minted.Permissions
		set("expires_at", minted.ExpiresAt.UTC().Format(time.RFC3339))
	}
	set("repositories", strings.Join(repositories, " "))
	set("permissions", FormatPermissions(permissions))
	if minted.Installation != 0 {
		set("installation", strconv.FormatInt(minted.Installation, 10))
	}
	return audit.Event{
		Kind: "github.token.minted", Actor: subject, Subject: subject,
		Target:  tokens.GitHubAppAudiencePrefix + request.App,
		Outcome: outcome, Reason: reason, Attributes: attributes,
	}
}

// recordGitHubToken writes one installation token request down and keeps
// it in that App's ring of recent requests.
//
// One event, read twice: the trail gets it through the recorder as every
// other event is, and the ring keeps what an App's page shows of it. They
// cannot disagree, because the second is made from the first.
//
// Only an App the catalogue declares is kept. The id in a request is
// whatever the caller asked for, and the earliest refusals happen before
// anything has been authenticated at all — a ring keyed on that would be
// a map an anonymous caller could fill.
func (i *Issuer) recordGitHubToken(ctx context.Context, e audit.Event) {
	if i == nil {
		return
	}
	i.record(ctx, e)
	apps := i.githubApps
	if apps == nil || apps.Recent == nil || apps.Catalogue == nil {
		return
	}
	app := strings.TrimPrefix(e.Target, tokens.GitHubAppAudiencePrefix)
	if _, declared := apps.Catalogue.Get(app); !declared {
		return
	}
	now := time.Now
	if apps.Now != nil {
		now = apps.Now
	}
	apps.Recent.Add(app, githubMintOf(e, now()))
}

// githubMintOf is one recorded request as an App's page reads it. The
// attribute names are the ones githubTokenEvent writes, immediately
// above: the event is the one source of both.
func githubMintOf(e audit.Event, at time.Time) mints.Token {
	return mints.Token{
		At: at, Subject: e.Subject, Proof: e.Attributes["proof"], Grant: e.Attributes["grant"],
		Repositories: strings.Fields(e.Attributes["repositories"]), Permissions: e.Attributes["permissions"],
		Outcome: e.Outcome, Reason: e.Reason,
	}
}
