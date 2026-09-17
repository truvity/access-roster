package issuer_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/audit/sinkrpc"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubapp/githubfake"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
	"github.com/truvity/access-roster/tokens"
)

// releaseWorkflow is the one workflow file the publisher grant is pinned to.
const releaseWorkflow = "example-org/app/.github/workflows/release.yml@refs/heads/main"

// githubTokenPolicy is the CLI policy with a group that admits one
// workflow file on one branch of one repository, and nothing else.
var githubTokenPolicy = strings.Replace(cliPolicy, "groups:\n",
	"groups:\n  all:release:publisher:\n    matchers:\n"+
		"      - github: { repository: example-org/app, ref: refs/heads/main, job_workflow_ref: \""+releaseWorkflow+"\" }\n", 1)

// githubTokenCatalogue grants the pinned workflow write on some
// repositories, and a person read on every one.
const githubTokenCatalogue = `
apps:
  - id: publisher
    org: example-org
    permissions: { contents: write, pull_requests: write, metadata: read, issues: write }
    grants:
      - group: all:release:publisher
        repositories: [app, "lib-*"]
        permissions: { contents: write, pull_requests: write }
      - group: all:release:publisher
        repositories: [docs]
        permissions: { issues: write }
      - group: kernel:k8s:admin
        repositories: ["*"]
        permissions: { metadata: read, contents: read }
  - id: pending
    org: example-org
    permissions: { contents: read }
    grants: [{ group: all:release:publisher, repositories: ["*"], permissions: { contents: read } }]
  - id: uncreated
    org: example-org
    permissions: { contents: read }
    grants: [{ group: all:release:publisher, repositories: ["*"], permissions: { contents: read } }]
  - id: uninstalled
    org: example-org
    permissions: { contents: read }
    grants: [{ group: all:release:publisher, repositories: ["*"], permissions: { contents: read } }]
`

// workflowVerifier stands in for GitHub's keys: a `job:<file>` token is a
// run of example-org/app on main from that workflow file. Anything else is
// the ordinary fake's.
type workflowVerifier struct{}

func (workflowVerifier) Verify(ctx context.Context, token, tokenType string) (issuer.Proof, error) {
	file, ok := strings.CutPrefix(token, "job:")
	if !ok {
		return fakeVerifier{}.Verify(ctx, token, tokenType)
	}
	return issuer.Proof{GitHub: &policy.GitHubClaims{
		Repository: "example-org/app", Owner: "example-org", Ref: "refs/heads/main", RefType: "branch", EventName: "push",
		WorkflowRef:    "example-org/app/.github/workflows/" + file + "@refs/heads/main",
		JobWorkflowRef: "example-org/app/.github/workflows/" + file + "@refs/heads/main",
	}}, nil
}

// catalogueStore is the Secret, in memory.
type catalogueStore map[string]catalogueapp.Record

func (s catalogueStore) Get(_ context.Context, id string) (catalogueapp.Record, string, bool, error) {
	record, ok := s[id]
	return record, testAppKey, ok, nil
}

var testAppKey = func() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}()

// githubTokenIssuer is the real OpenID surface with the catalogue wired,
// against a fake GitHub, recording its audit trail.
type githubTokenIssuer struct {
	server *httptest.Server
	iss    *issuer.Issuer
	github *githubfake.Org
	trail  *audit.MemoryWriter
}

// serveGitHubTokens must not run in parallel: the fake GitHub moves the
// client's base URL for the test's duration.
func serveGitHubTokens(t *testing.T) githubTokenIssuer {
	t.Helper()
	declared, err := policy.Parse([]byte(githubTokenPolicy))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	listed, err := catalogue.Parse([]byte(githubTokenCatalogue))
	if err != nil {
		t.Fatalf("parse the catalogue: %v", err)
	}
	github := githubfake.Start(t, "example-org")
	github.Uninstalled = map[int64]bool{44: true}

	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, adaDirectory(), issuer.NewMemoryState())
	trail := audit.NewMemoryWriter(100)
	iss.UseAudit(audit.NewLog(slog.New(slog.DiscardHandler), sinkrpc.InProcess(trail), "test"))
	iss.UseGitHubApps(issuer.GitHubApps{
		Catalogue: listed,
		Store: catalogueStore{
			"publisher":   {ID: "publisher", Org: "example-org", AppID: 7, AppSlug: "publisher", InstallationID: 42},
			"pending":     {ID: "pending", Org: "example-org", AppID: 8, AppSlug: "pending"},
			"uninstalled": {ID: "uninstalled", Org: "example-org", AppID: 9, AppSlug: "uninstalled", InstallationID: 44},
		},
		HTTP: github.Client(),
	})
	storage, err := issuer.NewStorage(iss, workflowVerifier{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return githubTokenIssuer{server: server, iss: iss, github: github, trail: trail}
}

// ask posts one installation token request.
func (g githubTokenIssuer) ask(t *testing.T, client string, form url.Values) (int, map[string]any, http.Header) {
	t.Helper()
	base := url.Values{
		"grant_type":           {string(oidc.GrantTypeTokenExchange)},
		"subject_token_type":   {string(oidc.JWTTokenType)},
		"requested_token_type": {tokens.TypeGitHubInstallationToken},
	}
	maps.Copy(base, form)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, g.server.URL+"/token", strings.NewReader(base.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client != "" {
		request.SetBasicAuth(url.QueryEscape(client), "")
	}
	response, err := g.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var body map[string]any
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return response.StatusCode, body, response.Header
}

// minted is the audit trail's installation token events.
func (g githubTokenIssuer) minted() []audit.Event {
	var out []audit.Event
	for _, event := range g.trail.Events() {
		if event.Kind == "github.token.minted" {
			out = append(out, event)
		}
	}
	return out
}

// The token never reaches the trail, whatever else does.
func (g githubTokenIssuer) assertTokenNotAudited(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(g.trail.Events())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), g.github.Token) {
		t.Errorf("the installation token is in the audit trail: %s", raw)
	}
}

// The reviewed release workflow is minted a token narrowed to exactly the
// repositories and permissions it asked for, and GitHub is asked for
// exactly that.
func TestAPinnedWorkflowIsMintedATokenNarrowedToItsRequest(t *testing.T) {
	g := serveGitHubTokens(t)

	status, body, header := g.ask(t, "github-app:publisher", url.Values{
		"subject_token": {"job:release.yml"}, "audience": {"github-app:publisher"},
		"repositories": {"app lib-core"}, "scope": {"contents:read"},
	})
	if status != http.StatusOK {
		t.Fatalf("mint = %d %v", status, body)
	}
	if body["access_token"] != g.github.Token || body["issued_token_type"] != tokens.TypeGitHubInstallationToken || body["token_type"] != "N_A" {
		t.Errorf("body = %v", body)
	}
	if expires, _ := body["expires_in"].(float64); expires <= 0 || expires > 3600 {
		t.Errorf("expires_in = %v, want GitHub's hour", body["expires_in"])
	}
	if header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", header.Get("Cache-Control"))
	}
	if got, _ := json.Marshal(body["repositories"]); string(got) != `["app","lib-core"]` {
		t.Errorf("repositories = %s", got)
	}
	if got, _ := json.Marshal(body["permissions"]); string(got) != `{"contents":"read"}` {
		t.Errorf("permissions = %s", got)
	}

	if len(g.github.TokenRequests) != 1 {
		t.Fatalf("GitHub was asked %d times", len(g.github.TokenRequests))
	}
	asked := g.github.TokenRequests[0]
	if asked.Installation != 42 || asked.Body == nil ||
		!slices.Equal(asked.Body.Repositories, []string{"app", "lib-core"}) ||
		!maps.Equal(asked.Body.Permissions, map[string]string{"contents": "read"}) {
		t.Errorf("GitHub was asked for %+v %+v", asked, asked.Body)
	}

	// Permissions left out are the grant's, never the App's full set.
	status, body, _ = g.ask(t, "", url.Values{
		"subject_token": {"job:release.yml"}, "audience": {"github-app:publisher"}, "repositories": {"app"},
	})
	if status != http.StatusOK {
		t.Fatalf("mint without scope = %d %v", status, body)
	}
	if got := g.github.TokenRequests[1].Body.Permissions; !maps.Equal(got, map[string]string{"contents": "write", "pull_requests": "write"}) {
		t.Errorf("without scope GitHub was asked for %v, want the grant's permissions", got)
	}

	events := g.minted()
	if len(events) != 2 {
		t.Fatalf("minted events = %+v", events)
	}
	first := events[0]
	want := map[string]string{
		"proof": "ci", "app": "publisher", "org": "example-org", "grant": "all:release:publisher",
		"repositories": "app lib-core", "permissions": "contents:read", "installation": "42",
	}
	for name, value := range want {
		if first.Attributes[name] != value {
			t.Errorf("attribute %s = %q, want %q", name, first.Attributes[name], value)
		}
	}
	if first.Outcome != audit.OutcomeOK || first.Target != "github-app:publisher" ||
		first.Subject != "github:example-org/app" || first.Attributes["expires_at"] == "" {
		t.Errorf("event = %+v", first)
	}
	g.assertTokenNotAudited(t)
}

// Another workflow file in the same repository on the same branch holds
// none of the groups the App grants, and GitHub is never asked.
func TestAnotherWorkflowInTheSameRepositoryIsRefused(t *testing.T) {
	g := serveGitHubTokens(t)

	status, body, _ := g.ask(t, "github-app:publisher", url.Values{
		"subject_token": {"job:test.yml"}, "audience": {"github-app:publisher"}, "repositories": {"app"},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Fatalf("another workflow = %d %v, want invalid_target", status, body)
	}
	if len(g.github.TokenRequests) != 0 {
		t.Errorf("GitHub was asked for a token nobody was granted: %+v", g.github.TokenRequests)
	}
	events := g.minted()
	if len(events) != 1 || events[0].Outcome != audit.OutcomeRefused || events[0].Reason == "" ||
		events[0].Attributes["repositories"] != "app" {
		t.Errorf("events = %+v, want one refusal naming the request", events)
	}
}

// A request wider than every grant the caller holds is invalid_scope: a
// permission above the grant, one the grant does not name, a repository
// outside it, two repositories no ONE grant covers, and no repositories
// at all where no grant is for every one.
func TestARequestWiderThanTheGrantIsInvalidScope(t *testing.T) {
	g := serveGitHubTokens(t)

	for name, form := range map[string]url.Values{
		"a permission above the grant":   {"repositories": {"app"}, "scope": {"contents:admin"}},
		"a permission the grant lacks":   {"repositories": {"app"}, "scope": {"administration:read"}},
		"a repository outside it":        {"repositories": {"app infra"}},
		"two grants' repositories":       {"repositories": {"app docs"}},
		"a grant's permission elsewhere": {"repositories": {"app"}, "scope": {"issues:write"}},
		"no repositories named":          {},
	} {
		form.Set("subject_token", "job:release.yml")
		form.Set("audience", "github-app:publisher")
		status, body, _ := g.ask(t, "github-app:publisher", form)
		if status != http.StatusBadRequest || body["error"] != "invalid_scope" {
			t.Errorf("%s = %d %v, want invalid_scope", name, status, body)
		}
	}
	if len(g.github.TokenRequests) != 0 {
		t.Errorf("GitHub was asked: %+v", g.github.TokenRequests)
	}
	if events := g.minted(); len(events) != 6 || slices.ContainsFunc(events, func(e audit.Event) bool { return e.Outcome != audit.OutcomeRefused }) {
		t.Errorf("events = %+v, want six refusals", events)
	}
}

// An App that cannot mint is invalid_target, whatever the reason: not
// declared, declared and never created, created and not installed, or
// uninstalled on GitHub since.
func TestAnAppThatCannotMintIsInvalidTarget(t *testing.T) {
	g := serveGitHubTokens(t)

	for _, app := range []string{"undeclared", "uncreated", "pending", "uninstalled"} {
		status, body, _ := g.ask(t, "", url.Values{
			"subject_token": {"job:release.yml"}, "audience": {"github-app:" + app}, "repositories": {"app"},
		})
		if status != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Errorf("%s = %d %v, want invalid_target", app, status, body)
		}
	}
	if len(g.github.TokenRequests) != 1 || g.github.TokenRequests[0].Installation != 44 {
		t.Errorf("GitHub was asked %+v, want only the uninstalled App's installation", g.github.TokenRequests)
	}
}

// A person's sign-in is a proof here by exactly the rules it is for an
// ordinary exchange: presented by the client it was issued to. Their grant
// is for every repository, so no repositories need be named and the token
// is not narrowed to any.
func TestASignInIsMintedAnUnnarrowedTokenUnderItsOwnRules(t *testing.T) {
	g := serveGitHubTokens(t)
	signedIn := signedInTokens(t, g.server, g.iss, "cli")
	access, _ := signedIn["access_token"].(string)

	form := url.Values{
		"subject_token": {access}, "subject_token_type": {string(oidc.AccessTokenType)}, "audience": {"github-app:publisher"},
	}
	status, body, _ := g.ask(t, "cli", form)
	if status != http.StatusOK {
		t.Fatalf("a sign-in = %d %v", status, body)
	}
	asked := g.github.TokenRequests[0].Body
	if asked == nil || len(asked.Repositories) != 0 || !maps.Equal(asked.Permissions, map[string]string{"metadata": "read", "contents": "read"}) {
		t.Errorf("GitHub was asked for %+v, want the grant's permissions and no repositories", asked)
	}
	if events := g.minted(); len(events) != 1 || events[0].Subject != "ada@north.example" || events[0].Attributes["proof"] != "person" {
		t.Errorf("events = %+v", events)
	}

	// The same sign-in presented by anybody else is not a proof.
	for _, client := range []string{"github-app:publisher", ""} {
		status, body, _ = g.ask(t, client, form)
		if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("a sign-in presented as %q = %d %v, want invalid_grant", client, status, body)
		}
	}
	// And a client that does not authenticate is refused before anything.
	status, body, _ = g.ask(t, "no-such-client", form)
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Errorf("an unknown client = %d %v, want invalid_client", status, body)
	}
	g.assertTokenNotAudited(t)
}

// Delegation and malformed requests are refused before any proof is read.
func TestMalformedInstallationTokenRequestsAreInvalidRequest(t *testing.T) {
	g := serveGitHubTokens(t)
	for name, form := range map[string]url.Values{
		"an actor token":           {"actor_token": {"job:release.yml"}, "actor_token_type": {string(oidc.JWTTokenType)}},
		"an owner in a repository": {"repositories": {"example-org/app"}},
		"a level that is not one":  {"repositories": {"app"}, "scope": {"contents:everything"}},
		"a bare permission":        {"repositories": {"app"}, "scope": {"contents"}},
	} {
		form.Set("subject_token", "job:release.yml")
		form.Set("audience", "github-app:publisher")
		status, body, _ := g.ask(t, "", form)
		if status != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Errorf("%s = %d %v, want invalid_request", name, status, body)
		}
	}
	status, body, _ := g.ask(t, "", url.Values{"subject_token": {"not-a-proof"}, "audience": {"github-app:publisher"}, "repositories": {"app"}})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("an unverifiable subject = %d %v, want invalid_grant", status, body)
	}
	if len(g.github.TokenRequests) != 0 {
		t.Errorf("GitHub was asked: %+v", g.github.TokenRequests)
	}
}

// Everything that is not an installation token request reaches the
// library as it always did: an ordinary exchange still mints a JWT, and a
// request carrying only one half of the claim is the library's to refuse.
func TestOrdinaryExchangesAreUntouchedBesideInstallationTokens(t *testing.T) {
	g := serveGitHubTokens(t)

	status, body := exchange(t, g.server, "github:example-org/gitops@refs/heads/master", "k8s:devel")
	if status != http.StatusOK || body["issued_token_type"] != string(oidc.AccessTokenType) {
		t.Fatalf("an ordinary exchange = %d %v", status, body)
	}
	if claims := claimsOf(t, g.server, body["access_token"].(string)); claims["aud"] == nil {
		t.Errorf("the ordinary exchange's token did not verify: %v", claims)
	}

	status, body, _ = g.ask(t, "k8s:devel", url.Values{"subject_token": {"github:example-org/gitops@refs/heads/master"}, "audience": {"k8s:devel"}})
	if status == http.StatusOK || body["error"] != "invalid_request" {
		t.Errorf("the installation token type for a client = %d %v, want the library's invalid_request", status, body)
	}
	form := url.Values{"subject_token": {"job:release.yml"}, "audience": {"github-app:publisher"}, "requested_token_type": {""}}
	status, body, _ = g.ask(t, "", form)
	if status == http.StatusOK || body["access_token"] != nil {
		t.Errorf("a github-app audience without the token type = %d %v, want the library's refusal", status, body)
	}
	if len(g.minted()) != 0 || len(g.github.TokenRequests) != 0 {
		t.Errorf("a request that is not an installation token's was served as one: %+v", g.minted())
	}
}

// One grant covers the whole request, and when several do the first in
// catalogue order is the one.
func TestTheFirstGrantCoveringTheWholeRequestIsChosen(t *testing.T) {
	t.Parallel()
	app := catalogue.App{ID: "a", Org: "example-org", Grants: []catalogue.Grant{
		{Group: "g1", Repositories: []string{"app"}, Permissions: map[string]string{"contents": "read"}},
		{Group: "g2", Repositories: []string{"*"}, Permissions: map[string]string{"contents": "write"}},
		{Group: "g3", Repositories: []string{"app", "lib"}, Permissions: map[string]string{"contents": "admin"}},
	}}
	for name, tc := range map[string]struct {
		groups, repositories []string
		permissions          map[string]string
		grant                string
		asks                 githubapp.Narrowing
	}{
		"the first in order":        {[]string{"g1", "g2", "g3"}, []string{"app"}, nil, "g1", githubapp.Narrowing{Repositories: []string{"app"}, Permissions: map[string]string{"contents": "read"}}},
		"the first that covers":     {[]string{"g1", "g2", "g3"}, []string{"app"}, map[string]string{"contents": "write"}, "g2", githubapp.Narrowing{Repositories: []string{"app"}, Permissions: map[string]string{"contents": "write"}}},
		"only groups the proof has": {[]string{"g3"}, []string{"app", "lib"}, nil, "g3", githubapp.Narrowing{Repositories: []string{"app", "lib"}, Permissions: map[string]string{"contents": "admin"}}},
		"every repository":          {[]string{"g1", "g2"}, nil, nil, "g2", githubapp.Narrowing{Permissions: map[string]string{"contents": "write"}}},
	} {
		grant, asks, err := issuer.DecideGitHubGrant(app, tc.groups, tc.repositories, tc.permissions)
		if err != nil || grant.Group != tc.grant || !slices.Equal(asks.Repositories, tc.asks.Repositories) || !maps.Equal(asks.Permissions, tc.asks.Permissions) {
			t.Errorf("%s = %s %+v %v, want %s %+v", name, grant.Group, asks, err, tc.grant, tc.asks)
		}
	}
}
