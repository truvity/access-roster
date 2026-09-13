package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
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
	"github.com/truvity/access-roster/internal/githubroster/connection"
)

// memoryConnections is the store, in memory.
type memoryConnections struct {
	mu          sync.Mutex
	records     map[string]connection.Record
	credentials map[string]connection.Credential
}

func newMemoryConnections() *memoryConnections {
	return &memoryConnections{records: map[string]connection.Record{}, credentials: map[string]connection.Credential{}}
}

func (m *memoryConnections) Put(_ context.Context, r connection.Record, c connection.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[r.Org], m.credentials[c.Org] = r, c
	return nil
}

func (m *memoryConnections) List(context.Context) ([]connection.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]connection.Record, 0, len(m.records))
	for _, org := range slices.Sorted(maps.Keys(m.records)) {
		out = append(out, m.records[org])
	}
	return out, nil
}

func (m *memoryConnections) Credential(_ context.Context, org string) (connection.Credential, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.credentials[org]
	return c, ok, nil
}

func (m *memoryConnections) Delete(_ context.Context, org string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, org)
	delete(m.credentials, org)
	return nil
}

// fakeGitHub answers the three calls connecting and disconnecting make,
// as GitHub would for an owner of truvity. The package's two base URLs
// are shared state, so tests using this are never parallel.
type fakeGitHub struct {
	pem         string
	owner       string
	uninstalled []string
}

func startFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	fake := &fakeGitHub{
		pem:   string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		owner: "truvity",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app-manifests/{code}/conversions", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("code") != "created" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"code already used"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 42, "slug": "truvity-access-roster", "pem": fake.pem, "client_id": "Iv1.created", "client_secret": "created-secret",
			"html_url": "https://github.com/apps/truvity-access-roster", "owner": map[string]any{"login": fake.owner},
		})
	})
	mux.HandleFunc("GET /app/installations", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 7, "account": map[string]any{"login": "truvity"}}})
	})
	mux.HandleFunc("DELETE /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		fake.uninstalled = append(fake.uninstalled, r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api, web := githubapp.APIBase, githubapp.WebBase
	githubapp.APIBase, githubapp.WebBase = server.URL, "https://github.example"
	t.Cleanup(func() { githubapp.APIBase, githubapp.WebBase = api, web })
	return fake
}

func connectServer(t *testing.T, store GitHubConnections) (*ConsoleServer, *Console) {
	t.Helper()
	console := githubConsole(t, nil)
	console.deps.GitHubOrgs = store
	console.deps.State = access.NewStateCodec([]byte("the service's session key"), 10*time.Minute)
	console.deps.PublicURL = "https://access.example/console"
	console.deps.RootURL = "https://access.example"
	console.deps.GitHubHTTP = http.DefaultClient
	server := &ConsoleServer{
		console:  console,
		state:    console.deps.State,
		sessions: &access.Sessions{},
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		mount:    "/console",
	}
	return server, console
}

func operator() context.Context {
	return WithIdentity(context.Background(), access.Identity{Email: "ada@north.example", Role: access.RoleOperator})
}

// redirect follows one GitHub redirect into the service, carrying the
// cookie the previous step set.
func redirect(handler http.HandlerFunc, path string, query url.Values, cookie string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path+"?"+query.Encode(), nil)
	if cookie != "" {
		request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: cookie})
	}
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func cookieFrom(t *testing.T, header http.Header) string {
	t.Helper()
	for _, raw := range header.Values("Set-Cookie") {
		parsed, err := http.ParseSetCookie(raw)
		if err == nil && parsed.Name == access.ConnectCookieName && parsed.Value != "" {
			return parsed.Value
		}
	}
	t.Fatalf("no flow cookie in %v", header.Values("Set-Cookie"))
	return ""
}

// Two clicks by the owner and nothing typed: Create hands this service the
// App's key, Install is recorded as what GitHub says rather than what the
// redirect claims, and the operator lands back on the GitHub page.
func TestConnectingAnOrganisationIsCreateThenInstall(t *testing.T) {
	github := startFakeGitHub(t)
	store := newMemoryConnections()
	server, console := connectServer(t, store)

	begun, err := console.BeginGitHubConnect(operator(), connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: "truvity"}))
	if err != nil {
		t.Fatalf("BeginGitHubConnect: %v", err)
	}
	if !strings.HasPrefix(begun.Msg.GetUrl(), "https://github.example/organizations/truvity/settings/apps/new?state=") {
		t.Errorf("url = %s, want truvity's create page", begun.Msg.GetUrl())
	}
	var manifest githubapp.Manifest
	if err = json.Unmarshal([]byte(begun.Msg.GetManifest()), &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.RedirectURL != "https://access.example/connect/github/callback" || manifest.SetupURL != "https://access.example/connect/github/setup" {
		t.Errorf("callbacks = %s, %s; want both at the origin root", manifest.RedirectURL, manifest.SetupURL)
	}
	cookie := cookieFrom(t, begun.Header())
	state := mustQuery(t, begun.Msg.GetUrl(), "state")

	// After Create.
	created := redirect(server.githubCallback, githubCallbackPath, url.Values{"code": {"created"}, "state": {state}}, cookie)
	if created.Code != http.StatusFound {
		t.Fatalf("after Create = %d:\n%s", created.Code, created.Body)
	}
	install := created.Header().Get("Location")
	if !strings.HasPrefix(install, "https://github.example/apps/truvity-access-roster/installations/new?state=") {
		t.Errorf("after Create the owner is sent to %s, want the App's install page", install)
	}
	record, _ := recordOf(mustList(t, store), "truvity")
	if record.AppID != 42 || record.Installed() || record.ConnectedBy != "ada@north.example" {
		t.Errorf("after Create the record is %+v", record)
	}
	if credential, _, _ := store.Credential(context.Background(), "truvity"); credential.PrivateKey != github.pem {
		t.Error("the App's key was not kept")
	}
	// The state that brought the browser back is spent; Install runs under
	// a fresh one.
	nextState, nextCookie := mustQuery(t, install, "state"), cookieFrom(t, created.Header())
	if nextState == state {
		t.Error("Install reuses the state Create was finished with")
	}

	// After Install — the redirect claims an installation GitHub does not
	// report, and GitHub's answer is what is kept.
	installed := redirect(server.githubSetup, githubSetupPath,
		url.Values{"installation_id": {"999"}, "setup_action": {"install"}, "state": {nextState}}, nextCookie)
	if installed.Code != http.StatusFound || installed.Header().Get("Location") != "/console/#/github" {
		t.Fatalf("after Install = %d to %q:\n%s", installed.Code, installed.Header().Get("Location"), installed.Body)
	}
	record, _ = recordOf(mustList(t, store), "truvity")
	credential, _, _ := store.Credential(context.Background(), "truvity")
	if record.InstallationID != 7 || credential.InstallationID != 7 {
		t.Errorf("installation = %d / %d, want 7 as GitHub reports, never the redirect's 999", record.InstallationID, credential.InstallationID)
	}

	// Connected and installed: connecting again would put a second App
	// beside the first.
	_, err = console.BeginGitHubConnect(operator(), connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: "truvity"}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("connecting an installed organisation again = %v, want failed precondition", err)
	}
}

// Every way a redirect can arrive that is not the one this browser's
// operator started is refused, and nothing is kept.
func TestAGitHubRedirectThisBrowserDidNotStartIsRefused(t *testing.T) {
	github := startFakeGitHub(t)
	store := newMemoryConnections()
	server, console := connectServer(t, store)

	begun, err := console.BeginGitHubConnect(operator(), connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: "truvity"}))
	if err != nil {
		t.Fatalf("BeginGitHubConnect: %v", err)
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")

	created := url.Values{"code": {"created"}, "state": {state}}
	if got := redirect(server.githubCallback, githubCallbackPath, created, ""); got.Code != http.StatusBadRequest {
		t.Errorf("no cookie = %d, want 400", got.Code)
	}
	if got := redirect(server.githubCallback, githubCallbackPath, created, "another"); got.Code != http.StatusBadRequest {
		t.Errorf("another browser's cookie = %d, want 400", got.Code)
	}

	// A directory consent's state, even pinned properly, is not a GitHub
	// connect.
	directoryState, err := console.deps.State.IssueAs(access.Binding{Actor: "ada@north.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect(server.githubCallback, githubCallbackPath,
		url.Values{"code": {"created"}, "state": {directoryState}}, directoryState); got.Code != http.StatusBadRequest {
		t.Errorf("a directory's state = %d, want 400", got.Code)
	}

	// The create page was truvity's; an App owned by anybody else is not
	// the one asked for.
	github.owner = "somebody-else"
	if got := redirect(server.githubCallback, githubCallbackPath, url.Values{"code": {"created"}, "state": {state}}, cookie); got.Code != http.StatusConflict {
		t.Errorf("an App under another owner = %d, want 409", got.Code)
	}
	// A spent code: GitHub's words reach the page, and a 4xx, never a 5xx.
	github.owner = "truvity"
	used := redirect(server.githubCallback, githubCallbackPath, url.Values{"code": {"spent"}, "state": {state}}, cookie)
	if used.Code != http.StatusConflict || !strings.Contains(used.Body.String(), "code already used") {
		t.Errorf("a spent code = %d:\n%s", used.Code, used.Body)
	}
	if records := mustList(t, store); len(records) != 0 {
		t.Errorf("a refused redirect kept %+v", records)
	}
}

// Only an organisation the policy binds, only by an operator.
func TestOnlyAnOperatorConnectsOnlyABoundOrganisation(t *testing.T) {
	startFakeGitHub(t)
	_, console := connectServer(t, newMemoryConnections())
	begin := func(ctx context.Context, org string) error {
		_, err := console.BeginGitHubConnect(ctx, connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: org}))
		return err
	}
	viewer := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer})
	if err := begin(viewer, "truvity"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer = %v, want permission denied", err)
	}
	if err := begin(operator(), "not-bound"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("an unbound organisation = %v, want failed precondition", err)
	}
	if err := begin(operator(), "not a login"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a malformed login = %v, want invalid argument", err)
	}

	_, noStore := connectServer(t, nil)
	noStore.deps.GitHubOrgs = nil
	if _, err := noStore.BeginGitHubConnect(operator(),
		connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: "truvity"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("no store = %v, want failed precondition", err)
	}
}

// Created and never installed: Connect picks up at Install rather than
// creating a second App.
func TestAnUninstalledAppIsFinishedRatherThanCreatedAgain(t *testing.T) {
	startFakeGitHub(t)
	store := newMemoryConnections()
	_ = store.Put(context.Background(),
		connection.Record{Org: "truvity", AppID: 42, AppSlug: "truvity-access-roster"},
		connection.Credential{Org: "truvity", AppID: 42, PrivateKey: "k"})
	_, console := connectServer(t, store)

	begun, err := console.BeginGitHubConnect(operator(), connect.NewRequest(&directoryrosterv1.BeginGitHubConnectRequest{Org: "truvity"}))
	if err != nil {
		t.Fatalf("BeginGitHubConnect: %v", err)
	}
	if begun.Msg.GetManifest() != "" || !strings.Contains(begun.Msg.GetUrl(), "/apps/truvity-access-roster/installations/new") {
		t.Errorf("response = %+v, want the install page and no manifest", begun.Msg)
	}
}

// Disconnect revokes on GitHub and forgets here; a revoke that fails still
// forgets, and says what is left to do by hand.
func TestDisconnectingUninstallsThenForgets(t *testing.T) {
	github := startFakeGitHub(t)
	store := newMemoryConnections()
	_ = store.Put(context.Background(),
		connection.Record{Org: "truvity", AppID: 42, AppSlug: "truvity-access-roster", InstallationID: 7},
		connection.Credential{Org: "truvity", AppID: 42, InstallationID: 7, PrivateKey: github.pem})
	_, console := connectServer(t, store)

	gone, err := console.DisconnectGitHubOrganisation(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "truvity"}))
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !gone.Msg.GetUninstalled() || !slices.Equal(github.uninstalled, []string{"7"}) {
		t.Errorf("uninstalled = %v, calls = %v", gone.Msg.GetUninstalled(), github.uninstalled)
	}
	if gone.Msg.GetAppSettingsUrl() != "https://github.example/organizations/truvity/settings/apps/truvity-access-roster" {
		t.Errorf("settings url = %s", gone.Msg.GetAppSettingsUrl())
	}
	if records := mustList(t, store); len(records) != 0 {
		t.Errorf("after Disconnect = %+v", records)
	}

	// An unusable key cannot uninstall, and the organisation is still
	// forgotten — with the detail an operator acts on.
	_ = store.Put(context.Background(),
		connection.Record{Org: "truvity", AppID: 42, AppSlug: "truvity-access-roster", InstallationID: 7},
		connection.Credential{Org: "truvity", AppID: 42, InstallationID: 7, PrivateKey: "not a key"})
	gone, err = console.DisconnectGitHubOrganisation(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "truvity"}))
	if err != nil || gone.Msg.GetUninstalled() || gone.Msg.GetDetail() == "" {
		t.Errorf("a failed uninstall = %+v, %v; want forgotten with a detail", gone.Msg, err)
	}
	if records := mustList(t, store); len(records) != 0 {
		t.Error("a failed uninstall kept the organisation")
	}

	if _, err = console.DisconnectGitHubOrganisation(operator(),
		connect.NewRequest(&directoryrosterv1.DisconnectGitHubOrganisationRequest{Org: "truvity"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("disconnecting what is not connected = %v, want not found", err)
	}
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	value := parsed.Query().Get(key)
	if value == "" {
		t.Fatalf("%s has no %s", raw, key)
	}
	return value
}

func mustList(t *testing.T, store GitHubConnections) []connection.Record {
	t.Helper()
	records, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return records
}
