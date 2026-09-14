package server

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/githubfake"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/hub"
)

// memoryLinkApp keeps the link App in memory.
type memoryLinkApp struct {
	mu         sync.Mutex
	record     *link.App
	credential *link.AppCredential
}

func (m *memoryLinkApp) PutLinkApp(_ context.Context, record link.App, credential link.AppCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record, m.credential = &record, &credential
	return nil
}

func (m *memoryLinkApp) LinkApp(context.Context) (link.App, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil {
		return link.App{}, false, nil
	}
	return *m.record, true, nil
}

func (m *memoryLinkApp) LinkAppCredential(context.Context) (link.AppCredential, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.credential == nil {
		return link.AppCredential{}, false, nil
	}
	return *m.credential, true, nil
}

func (m *memoryLinkApp) DeleteLinkApp(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.record, m.credential = nil, nil
	return nil
}

// memoryLinks keeps links in memory, with the store's own rules.
type memoryLinks struct {
	mu   sync.Mutex
	byID map[int64]link.Link
}

func (m *memoryLinks) List(context.Context) ([]link.Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]link.Link, 0, len(m.byID))
	for _, id := range slices.Sorted(maps.Keys(m.byID)) {
		out = append(out, m.byID[id])
	}
	return out, nil
}

func (m *memoryLinks) Claim(_ context.Context, claimed link.Link, now time.Time) ([]link.Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	written := link.Claim(slices.Collect(maps.Values(m.byID)), claimed, now)
	for k := range written {
		m.byID[written[k].ID] = written[k]
	}
	return written, nil
}

func (m *memoryLinks) Adopt(_ context.Context, candidates []link.Link) ([]link.Link, map[int64]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	adopted, skipped := link.Adopt(slices.Collect(maps.Values(m.byID)), candidates)
	for i := range adopted {
		m.byID[adopted[i].ID] = adopted[i]
	}
	return adopted, skipped, nil
}

func (m *memoryLinks) Invalidate(_ context.Context, reason string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	written := link.Invalidate(slices.Collect(maps.Values(m.byID)), reason, now)
	for k := range written {
		m.byID[written[k].ID] = written[k]
	}
	return len(written), nil
}

// directory answers who an address is, from a table.
type directory map[string]hub.UserResult

func (d directory) ResolveUser(_ context.Context, email string, _ *time.Duration) (hub.UserResult, error) {
	if answer, ok := d[email]; ok {
		answer.Email = email
		return answer, nil
	}
	if strings.HasSuffix(email, "@globex.example") {
		return hub.UserResult{Email: email, InDomain: true, Authoritative: true}, nil
	}
	return hub.UserResult{Email: email}, nil
}

type linkRig struct {
	github  *githubfake.Org
	server  *ConsoleServer
	console *Console
	app     *memoryLinkApp
	links   *memoryLinks
}

func newLinkRig(t *testing.T, dir directory) *linkRig {
	t.Helper()
	github := githubfake.Start(t, "globex")
	server, console := connectServer(t, newMemoryConnections())
	console.deps.Authorizer = access.NewAuthorizer(console.deps.Authorizer.Policy(), dir, 0)
	console.deps.GitHubHTTP = github.Client()
	r := &linkRig{
		github: github, server: server, console: console,
		app:   &memoryLinkApp{},
		links: &memoryLinks{byID: map[int64]link.Link{}},
	}
	console.deps.GitHubLinkApp, console.deps.GitHubLinks = r.app, r.links
	_ = r.app.PutLinkApp(context.Background(),
		link.App{Owner: "globex", AppID: 9, AppSlug: "globex-access-roster-link", ClientID: githubfake.ClientID},
		link.AppCredential{AppID: 9, ClientID: githubfake.ClientID, ClientSecret: githubfake.ClientSecret})
	return r
}

// start opens the link page and returns the state and cookie it set.
func (r *linkRig) start(t *testing.T) (state, cookie string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	r.server.githubLinkPage(recorder, httptest.NewRequest(http.MethodGet, githubLinkPath, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("link page = %d:\n%s", recorder.Code, recorder.Body)
	}
	for _, raw := range recorder.Header().Values("Set-Cookie") {
		if parsed, err := http.ParseSetCookie(raw); err == nil && parsed.Name == access.LinkCookieName {
			cookie = parsed.Value
		}
	}
	body := recorder.Body.String()
	at := strings.Index(body, `href="`+githubapp.WebBase+"/login/oauth/authorize?")
	if at < 0 || cookie == "" {
		t.Fatalf("the page has no authorize button or set no cookie:\n%s", body)
	}
	href := body[at+len(`href="`):]
	end := strings.IndexByte(href, '"')
	if end < 0 {
		t.Fatalf("an unterminated href in:\n%s", body)
	}
	href = strings.ReplaceAll(href[:end], "&amp;", "&")
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("client_id") != githubfake.ClientID ||
		parsed.Query().Get("redirect_uri") != "https://access.example"+githubLinkCallbackPath {
		t.Errorf("authorize = %s", href)
	}
	return parsed.Query().Get("state"), cookie
}

// finish is GitHub sending the person back after they authorized as login.
func (r *linkRig) finish(t *testing.T, login, state, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet,
		githubLinkCallbackPath+"?"+url.Values{"code": {r.github.Authorize(login)}, "state": {state}}.Encode(), nil)
	if cookie != "" {
		request.AddCookie(&http.Cookie{Name: access.LinkCookieName, Value: cookie})
	}
	recorder := httptest.NewRecorder()
	r.server.githubLinkCallback(recorder, request)
	return recorder
}

// A person links by authorizing: the link proves the verified work
// addresses the directory has, live — never a personal address, an
// unverified one, or a suspended account's.
func TestAPersonLinksTheirVerifiedWorkAddress(t *testing.T) {
	r := newLinkRig(t, directory{
		"ada@globex.example": {InDomain: true, Found: true, Authoritative: true},
		"old@globex.example": {InDomain: true, Found: true, Suspended: true, Authoritative: true},
	})
	account := r.github.AddAccount("ada-gh", "ada@globex.example", "old@globex.example", "ada@gmail.example", "draft@globex.example?")

	state, cookie := r.start(t)
	done := r.finish(t, "ada-gh", state, cookie)

	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), "@ada-gh is linked") {
		t.Fatalf("callback = %d:\n%s", done.Code, done.Body)
	}
	body := done.Body.String()
	if strings.Contains(body, "gmail") || strings.Contains(body, "draft@") {
		t.Errorf("the page repeats a personal or unverified address:\n%s", body)
	}
	if !strings.Contains(body, "old@globex.example: the account is suspended") {
		t.Errorf("the page does not say why old@ was not linked:\n%s", body)
	}
	got := r.links.byID[account.ID]
	if got.State != link.StateLinked || !slices.Equal(got.Emails, []string{"ada@globex.example"}) || got.AppID != 9 ||
		got.AccessToken != account.Access || got.RefreshToken != account.Refresh {
		t.Errorf("link = %+v, want ada@ alone, with the App and the pair GitHub issued", got)
	}

	// The page's own state is spent with its cookie.
	if again := r.finish(t, "ada-gh", state, ""); again.Code != http.StatusBadRequest {
		t.Errorf("a callback without the cookie = %d, want 400", again.Code)
	}
}

// An account with no verified work address the directory has is not
// linked, and the page says what to do.
func TestAnAccountWithNoKnownWorkAddressIsNotLinked(t *testing.T) {
	r := newLinkRig(t, directory{})
	r.github.AddAccount("stranger", "someone@gmail.example", "nobody@globex.example")

	state, cookie := r.start(t)
	done := r.finish(t, "stranger", state, cookie)

	if done.Code != http.StatusConflict || !strings.Contains(done.Body.String(), "nobody@globex.example: the directory has no such account") {
		t.Errorf("callback = %d:\n%s", done.Code, done.Body)
	}
	if len(r.links.byID) != 0 {
		t.Errorf("links = %+v, want none", r.links.byID)
	}
}

// A person who links a second account with the same work address moves
// the address to it; the first account, left proving nothing, is lost.
func TestLinkingASecondAccountMovesTheAddress(t *testing.T) {
	r := newLinkRig(t, directory{"ada@globex.example": {InDomain: true, Found: true, Authoritative: true}})
	first := r.github.AddAccount("ada-old", "ada@globex.example")
	second := r.github.AddAccount("ada-new", "ada@globex.example")

	state, cookie := r.start(t)
	r.finish(t, "ada-old", state, cookie)
	state, cookie = r.start(t)
	if done := r.finish(t, "ada-new", state, cookie); done.Code != http.StatusOK {
		t.Fatalf("second link = %d:\n%s", done.Code, done.Body)
	}

	if old := r.links.byID[first.ID]; old.State != link.StateLost || old.AccessToken != "" || !strings.Contains(old.Reason, "@ada-new") {
		t.Errorf("first link = %+v, want lost to @ada-new with its tokens forgotten", old)
	}
	if current := r.links.byID[second.ID]; !current.Active() {
		t.Errorf("second link = %+v, want active", current)
	}
}

// The link page says plainly when linking is not set up, rather than
// sending anybody to GitHub for nothing.
func TestTheLinkPageSaysWhenLinkingIsNotSetUp(t *testing.T) {
	r := newLinkRig(t, directory{})
	_ = r.app.DeleteLinkApp(context.Background())

	recorder := httptest.NewRecorder()
	r.server.githubLinkPage(recorder, httptest.NewRequest(http.MethodGet, githubLinkPath, nil))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "not set up here yet") {
		t.Errorf("link page = %d:\n%s", recorder.Code, recorder.Body)
	}
}

// Creating the link App is one click by an organisation's owner: a public
// App, reading email addresses and nothing else, calling back to the link
// page's callback. Its client credentials are kept.
func TestCreatingTheLinkAppKeepsItsClientCredentials(t *testing.T) {
	startFakeGitHub(t)
	server, console := connectServer(t, newMemoryConnections())
	app, links := &memoryLinkApp{}, &memoryLinks{byID: map[int64]link.Link{}}
	console.deps.GitHubLinkApp, console.deps.GitHubLinks = app, links

	begun, err := console.BeginGitHubLinkAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubLinkAppConnectRequest{Owner: "globex"}))
	if err != nil {
		t.Fatalf("BeginGitHubLinkAppConnect: %v", err)
	}
	var manifest githubapp.Manifest
	if err = json.Unmarshal([]byte(begun.Msg.GetManifest()), &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.Public || !maps.Equal(manifest.DefaultPermissions, map[string]string{"emails": "read"}) ||
		!slices.Equal(manifest.CallbackURLs, []string{"https://access.example" + githubLinkCallbackPath}) {
		t.Errorf("manifest = %+v, want public, emails:read alone, calling back to the link callback", manifest)
	}

	created := redirect(server.githubLinkAppCallback, githubLinkAppCallbackPath,
		url.Values{"code": {"created"}, "state": {mustQuery(t, begun.Msg.GetUrl(), "state")}}, cookieFrom(t, begun.Header()))
	if created.Code != http.StatusFound || created.Header().Get("Location") != "/console/#/github" {
		t.Fatalf("after Create = %d:\n%s", created.Code, created.Body)
	}
	if app.credential == nil || app.credential.ClientSecret != "created-secret" || app.record.ClientID != "Iv1.created" {
		t.Errorf("kept %+v / %+v", app.record, app.credential)
	}

	// An organisation's connect state does not create the link App.
	orgState, _ := console.deps.State.IssueAs(access.Binding{Bind: githubBind + "globex", Actor: "ada@north.example"})
	if got := redirect(server.githubLinkAppCallback, githubLinkAppCallbackPath,
		url.Values{"code": {"created"}, "state": {orgState}}, orgState); got.Code != http.StatusBadRequest {
		t.Errorf("an organisation's state = %d, want 400", got.Code)
	}

	if _, err = console.BeginGitHubLinkAppConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubLinkAppConnectRequest{Owner: "globex"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("creating a second link App = %v, want failed precondition", err)
	}
	viewer := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer})
	if _, err = console.DisconnectGitHubLinkApp(viewer,
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubLinkAppRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer disconnecting = %v, want permission denied", err)
	}
}

// Disconnecting the link App makes every link unverifiable and forgets
// its tokens, and the status page shows links without a token in sight.
func TestDisconnectingTheLinkAppMakesLinksUnverifiable(t *testing.T) {
	r := newLinkRig(t, directory{"ada@globex.example": {InDomain: true, Found: true, Authoritative: true}})
	account := r.github.AddAccount("ada-gh", "ada@globex.example")
	state, cookie := r.start(t)
	r.finish(t, "ada-gh", state, cookie)

	status, err := githubStatus(t, r.console, access.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if !status.GetLinkingAvailable() || status.GetLinkUrl() != "https://access.example"+githubLinkPath ||
		status.GetLinkApp().GetAppSlug() != "globex-access-roster-link" || len(status.GetLinks()) != 1 {
		t.Errorf("status = %+v", status)
	}
	if raw, _ := json.Marshal(status); strings.Contains(string(raw), account.Access) || strings.Contains(string(raw), account.Refresh) {
		t.Error("the status page carries a person's token")
	}

	gone, err := r.console.DisconnectGitHubLinkApp(operator(), connect.NewRequest(&directoryrosterv1.DisconnectGitHubLinkAppRequest{}))
	if err != nil {
		t.Fatalf("DisconnectGitHubLinkApp: %v", err)
	}
	if gone.Msg.GetInvalidated() != 1 {
		t.Errorf("invalidated = %d, want 1", gone.Msg.GetInvalidated())
	}
	if got := r.links.byID[account.ID]; got.State != link.StateUnverifiable || got.AccessToken != "" {
		t.Errorf("link = %+v, want unverifiable with no tokens", got)
	}
	if _, found, _ := r.app.LinkAppCredential(context.Background()); found {
		t.Error("the link App's credential was kept")
	}
}
