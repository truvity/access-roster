package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackapp"
	slackcatalogue "github.com/truvity/access-roster/internal/slackapp/catalogue"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/policy"
)

const (
	acmeTeam   = "T0123ABCD"
	globexTeam = "T0456EFGH"
)

const slackTestPolicy = `
version: 1
groups:
  all:platform:engineer: { members: [team-platform@globex.example] }
slack:
  workspaces:
    acme:
      team_id: T0123ABCD
      owner: C0north
      domains: [acme.example]
    globex:
      team_id: T0456EFGH
      owner: C0south
      domains: [globex.example]
    initech:
      team_id: T0789IJKL
      domains: [initech.example]
`

const slackTestCatalogue = `
apps:
  - id: sync
    workspace: acme
    description: Keeps channels in step with groups
    botScopes: [channels:read, users:read]
  - id: orphaned
    workspace: acme
    botScopes: [channels:read]
`

type slackHarness struct {
	server   *ConsoleServer
	console  *Console
	store    *kube.SlackCatalogueApps
	client   *kube.Client
	slack    *slackfake.Slack
	recorded *audittest.Recorder
	logs     *bytes.Buffer
}

func newSlackHarness(t *testing.T) *slackHarness {
	t.Helper()
	declared, err := policy.Parse([]byte(slackTestPolicy))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	catalogue, err := slackcatalogue.Parse([]byte(slackTestCatalogue))
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	fakeSlack := slackfake.New(t)
	fakeSlack.AddTeam(acmeTeam, "Acme")
	fakeSlack.AddTeam(globexTeam, "Globex")
	client := kube.NewClient(fake.NewClientset(), "access-issuer", "access-issuer")
	store := kube.NewSlackCatalogueApps(client)
	recorded := audittest.New(t)
	console := &Console{deps: ConsoleDeps{
		Authorizer:         access.NewAuthorizer(set, nil, 0),
		State:              access.NewStateCodec([]byte("the service's session key"), 10*time.Minute),
		PublicURL:          "https://access.example/console",
		RootURL:            "https://access.example",
		SlackCatalogue:     catalogue,
		SlackCatalogueApps: store,
		SlackAPI:           []slackapp.Option{slackapp.WithBaseURL(fakeSlack.URL())},
		Audit:              recorded,
	}}
	logs := &bytes.Buffer{}
	server := &ConsoleServer{
		console:  console,
		state:    console.deps.State,
		sessions: &access.Sessions{},
		log:      slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		mount:    "/console",
	}
	return &slackHarness{server: server, console: console, store: store, client: client, slack: fakeSlack, recorded: recorded, logs: logs}
}

func viewer() context.Context {
	return WithIdentity(context.Background(), access.Identity{Email: "eve@north.example", Role: access.RoleViewer})
}

func (h *slackHarness) secret(t *testing.T) map[string][]byte {
	t.Helper()
	secret, err := h.client.API().CoreV1().Secrets("access-issuer").Get(context.Background(), "access-issuer-slack-catalogue-apps", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read the Slack catalogue Secret: %v", err)
	}
	return secret.Data
}

func (h *slackHarness) app(t *testing.T, id string) *directoryrosterv1.SlackApp {
	t.Helper()
	listed, err := h.console.ListSlackApps(viewer(), connect.NewRequest(&directoryrosterv1.ListSlackAppsRequest{}))
	if err != nil {
		t.Fatalf("ListSlackApps: %v", err)
	}
	if !listed.Msg.GetAvailable() {
		t.Fatal("the Slack catalogue is not available")
	}
	for _, app := range listed.Msg.GetApps() {
		if app.GetId() == id {
			return app
		}
	}
	t.Fatalf("no Slack App %s in %v", id, listed.Msg.GetApps())
	return nil
}

func (h *slackHarness) create(ctx context.Context, id, token string) error {
	_, err := h.console.CreateSlackApp(ctx, connect.NewRequest(&directoryrosterv1.CreateSlackAppRequest{Id: id, ConfigurationToken: token}))
	return err
}

// install begins an install and plays the owner: Slack sends the browser
// back with a code for the workspace the owner chose.
func (h *slackHarness) install(t *testing.T, id, configToken, installIn string) (begun *connect.Response[directoryrosterv1.InstallSlackAppResponse], done func() (code int, location string, body string)) {
	t.Helper()
	begun, err := h.console.InstallSlackApp(operator(), connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: id, ConfigurationToken: configToken}))
	if err != nil {
		t.Fatalf("InstallSlackApp: %v", err)
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")
	app := h.app(t, id)
	code := h.slack.Install(app.GetAppId(), installIn)
	return begun, func() (int, string, string) {
		got := redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, url.Values{"code": {code}, "state": {state}}, cookie)
		return got.Code, got.Header().Get("Location"), got.Body.String()
	}
}

const configToken = "xoxe.xoxp-1-a-throwaway-token"

// fake-config-token is the one the fake Slack accepts.
var accepted = slackfake.ConfigToken

// Declared, created, installed, refused for another workspace, scopes
// missing, reinstalled: the whole life of a catalogue Slack App.
func TestASlackAppIsCreatedInstalledRefusedForTheWrongWorkspaceAndReinstalled(t *testing.T) {
	h := newSlackHarness(t)
	ctx := operator()

	// Declared: shown with the workspace's team id from the policy, and an
	// orphan nowhere yet.
	app := h.app(t, "sync")
	if app.GetState() != slackAppDeclared || app.GetWorkspace() != "acme" || app.GetTeamId() != acmeTeam || app.GetName() != "acme-sync" ||
		!app.GetDeclared() || len(app.GetBotScopes()) != 2 {
		t.Errorf("before Create = %+v", app)
	}

	// Install before Create is refused.
	if _, err := h.console.InstallSlackApp(ctx, connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: "sync"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("Install before Create = %v, want failed precondition", err)
	}

	// Create: the manifest is built from the entry, and what is kept is
	// "created, not installed".
	if err := h.create(ctx, "sync", accepted); err != nil {
		t.Fatalf("Create: %v", err)
	}
	app = h.app(t, "sync")
	if app.GetState() != slackAppCreated || app.GetAppId() == "" || app.GetAppSettingsUrl() != "https://api.slack.com/apps/"+app.GetAppId() || app.GetCreatedBy() == "" {
		t.Errorf("after Create = %+v", app)
	}
	created := h.slack.Apps[app.GetAppId()]
	if created == nil {
		t.Fatalf("Slack knows no App %s", app.GetAppId())
	}
	for _, want := range []string{
		`"redirect_urls":["https://access.example/connect/slack/catalogue/callback"]`, `"bot":["channels:read","users:read"]`,
		`"display_name":"sync"`, `"name":"acme-sync"`, `"socket_mode_enabled":false`,
	} {
		if !strings.Contains(created.Manifest, want) {
			t.Errorf("manifest lacks %s:\n%s", want, created.Manifest)
		}
	}
	for _, unwanted := range []string{"event_subscriptions", "interactivity", "slash_commands"} {
		if strings.Contains(created.Manifest, unwanted) {
			t.Errorf("manifest has %s:\n%s", unwanted, created.Manifest)
		}
	}
	data := h.secret(t)
	if string(data["sync.client_id"]) != created.ClientID || string(data["sync.client_secret"]) != created.ClientSecret {
		t.Error("the client credentials were not kept")
	}
	if _, ok := data["sync.slack_bot_token"]; ok {
		t.Error("before Install the Secret already has a bot token")
	}
	if err := h.create(ctx, "sync", accepted); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a second Create = %v, want failed precondition", err)
	}

	// Install into the WRONG workspace: Slack hands over a token, and it is
	// refused and not kept.
	begun, done := h.install(t, "sync", "", globexTeam)
	for key, want := range map[string]string{
		"redirect_uri": "https://access.example/connect/slack/catalogue/callback", "team": acmeTeam, "scope": "channels:read,users:read",
		"client_id": created.ClientID,
	} {
		if got := mustQuery(t, begun.Msg.GetUrl(), key); got != want {
			t.Errorf("authorize URL %s = %q, want %q", key, got, want)
		}
	}
	code, _, body := done()
	if code != http.StatusConflict || !strings.Contains(body, globexTeam) || !strings.Contains(body, acmeTeam) {
		t.Fatalf("an install into the wrong workspace = %d:\n%s", code, body)
	}
	if _, ok := h.secret(t)["sync.slack_bot_token"]; ok {
		t.Error("a token for the wrong workspace was kept")
	}
	if h.app(t, "sync").GetState() != slackAppCreated {
		t.Errorf("after the refusal the App is %s, want created", h.app(t, "sync").GetState())
	}
	if refused := h.recorded.Find("roster.slack_app.install_refused"); len(refused) != 1 {
		t.Errorf("refusals recorded = %d, want 1", len(refused))
	}

	// Install into the right one.
	_, done = h.install(t, "sync", "", acmeTeam)
	code, location, body := done()
	if code != http.StatusFound || location != "/console/#/slack-apps" {
		t.Fatalf("Install = %d to %q:\n%s", code, location, body)
	}
	app = h.app(t, "sync")
	if app.GetState() != slackAppInstalled || app.GetInstalledTeamId() != acmeTeam || app.GetInstalledTeamName() != "Acme" ||
		app.GetBotUserId() != slackfake.BotID(acmeTeam) || strings.Join(app.GetGrantedScopes(), ",") != "channels:read,users:read" ||
		app.GetInstalledBy() == "" || len(app.GetMissingScopes()) != 0 || app.GetNeedsConfigurationToken() {
		t.Errorf("after Install = %+v", app)
	}
	data = h.secret(t)
	if string(data["sync.slack_bot_token"]) != slackfake.Token(acmeTeam) {
		t.Error("the bot token was not kept under <id>.slack_bot_token")
	}
	if _, ok := data["sync.record.json"]; !ok {
		t.Error("no record beside the token")
	}

	// The entry now declares one more scope: the App holds fewer than
	// declared, and a reinstall alone would grant nothing new.
	h.console.deps.SlackCatalogue, _ = slackcatalogue.Parse([]byte(`
apps:
  - id: sync
    workspace: acme
    botScopes: [channels:read, users:read, users:read.email]
`))
	app = h.app(t, "sync")
	if app.GetState() != slackAppScopesMissing || strings.Join(app.GetMissingScopes(), ",") != "users:read.email" || !app.GetNeedsConfigurationToken() {
		t.Errorf("with a scope added = %+v", app)
	}
	if _, err := h.console.InstallSlackApp(ctx, connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: "sync"})); connect.CodeOf(err) != connect.CodeFailedPrecondition ||
		!strings.Contains(err.Error(), "configuration token") {
		t.Errorf("a reinstall that could grant nothing new = %v", err)
	}
	if _, err := h.console.InstallSlackApp(ctx, connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: "sync", ConfigurationToken: "xoxe-wrong"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a reinstall with a token Slack refuses = %v", err)
	}

	// Reinstall: the token updates the manifest, the owner approves again.
	_, done = h.install(t, "sync", accepted, acmeTeam)
	if code, _, body = done(); code != http.StatusFound {
		t.Fatalf("Reinstall = %d:\n%s", code, body)
	}
	app = h.app(t, "sync")
	if app.GetState() != slackAppInstalled || strings.Join(app.GetGrantedScopes(), ",") != "channels:read,users:read,users:read.email" ||
		len(app.GetMissingScopes()) != 0 || app.GetNeedsConfigurationToken() {
		t.Errorf("after Reinstall = %+v", app)
	}
	if h.slack.Count("apps.manifest.update") != 2 {
		t.Errorf("manifest updates = %d, want 2 (one refused, one accepted)", h.slack.Count("apps.manifest.update"))
	}

	// What was recorded, in order, and never a credential.
	if got := strings.Join(h.recorded.Actions(), ","); got != "roster.slack_app.created,roster.slack_app.install_refused,roster.slack_app.installed,roster.slack_app.installed" {
		t.Errorf("audit actions = %s", got)
	}
}

// The configuration token is used for one call and kept nowhere: not in
// the Secret, not in a record, not in an audit record, not in a log line,
// not in an error a caller reads.
func TestTheConfigurationTokenIsNeverKeptOrLogged(t *testing.T) {
	h := newSlackHarness(t)

	_, refusal := h.console.CreateSlackApp(operator(), connect.NewRequest(&directoryrosterv1.CreateSlackAppRequest{Id: "sync", ConfigurationToken: "xoxe-not-the-accepted-one"}))
	if refusal == nil || strings.Contains(refusal.Error(), "xoxe-not-the-accepted-one") {
		t.Errorf("a refused Create = %v, which must fail and not echo the token", refusal)
	}
	if err := h.create(operator(), "sync", accepted); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, done := h.install(t, "sync", "", acmeTeam)
	done()
	h.console.deps.SlackCatalogue, _ = slackcatalogue.Parse([]byte("apps:\n  - {id: sync, workspace: acme, botScopes: [channels:read, users:read, chat:write]}\n"))
	_, done = h.install(t, "sync", accepted, acmeTeam)
	done()

	var everywhere strings.Builder
	for key, value := range h.secret(t) {
		fmt.Fprintf(&everywhere, "%s=%s\n", key, value)
	}
	everywhere.WriteString(h.logs.String())
	for _, rec := range h.recorded.Records() {
		fmt.Fprintf(&everywhere, "%v\n", rec)
	}
	for _, secret := range []string{accepted, "xoxe-not-the-accepted-one"} {
		if strings.Contains(everywhere.String(), secret) {
			t.Errorf("the configuration token %q turned up in the Secret, the logs or the audit records", secret)
		}
	}
	// The server kept what it needs to install, and that is a client
	// secret and a bot token, which are not the configuration token.
	if !strings.Contains(everywhere.String(), "sync.client_secret=") {
		t.Error("the harness did not read the Secret")
	}
}

func TestOnlyAnOperatorCreatesOrInstalls(t *testing.T) {
	h := newSlackHarness(t)
	if err := h.create(viewer(), "sync", accepted); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer's Create = %v, want permission denied", err)
	}
	if _, err := h.console.InstallSlackApp(viewer(), connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: "sync"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer's Install = %v, want permission denied", err)
	}
	if err := h.create(context.Background(), "sync", accepted); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("an anonymous Create = %v, want unauthenticated", err)
	}
	if _, err := h.console.ListSlackApps(context.Background(), connect.NewRequest(&directoryrosterv1.ListSlackAppsRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("an anonymous List = %v, want unauthenticated", err)
	}
	if len(h.slack.Calls()) != 0 {
		t.Errorf("Slack was called %d times for refused requests", len(h.slack.Calls()))
	}
}

func TestACatalogueAppIsOnlyWhatTheCatalogueAndThePolicyDeclare(t *testing.T) {
	h := newSlackHarness(t)
	for name, err := range map[string]error{
		"an undeclared id":       h.create(operator(), "nobody", accepted),
		"a blank configuration":  h.create(operator(), "sync", ""),
		"a sentence for a token": h.create(operator(), "sync", "my token is here"),
	} {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s = %v, want invalid argument", name, err)
		}
	}
	// An entry whose workspace the policy does not name is refused at the
	// click too, not only at start.
	h.console.deps.SlackCatalogue, _ = slackcatalogue.Parse([]byte("apps:\n  - {id: lost, workspace: umbrella, botScopes: [channels:read]}\n"))
	if err := h.create(operator(), "lost", accepted); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "umbrella") {
		t.Errorf("Create for a workspace the policy does not name = %v", err)
	}
	if len(h.slack.Calls()) != 0 {
		t.Errorf("Slack was called %d times for refused requests", len(h.slack.Calls()))
	}

	// An App created from an entry no longer declared stays listed.
	h.console.deps.SlackCatalogue, _ = slackcatalogue.Parse([]byte(slackTestCatalogue))
	if err := h.create(operator(), "orphaned", accepted); err != nil {
		t.Fatalf("Create: %v", err)
	}
	h.console.deps.SlackCatalogue, _ = slackcatalogue.Parse([]byte("apps:\n  - {id: sync, workspace: acme, botScopes: [channels:read]}\n"))
	if orphan := h.app(t, "orphaned"); orphan.GetDeclared() || orphan.GetState() != slackAppCreated {
		t.Errorf("an App no longer declared = %+v", orphan)
	}

	// No Kubernetes state, no catalogue Apps: listed as declared, unavailable.
	h.console.deps.SlackCatalogueApps = nil
	listed, err := h.console.ListSlackApps(viewer(), connect.NewRequest(&directoryrosterv1.ListSlackAppsRequest{}))
	if err != nil || listed.Msg.GetAvailable() || len(listed.Msg.GetApps()) != 1 {
		t.Errorf("without a store = %+v, %v", listed, err)
	}
	if err = h.create(operator(), "sync", accepted); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("Create without a store = %v, want failed precondition", err)
	}
}

// The state is what stops another site, another browser or another flow
// finishing an install, exactly as for GitHub's connect.
func TestASlackInstallIsFinishedOnlyByTheBrowserThatStartedIt(t *testing.T) {
	h := newSlackHarness(t)
	if err := h.create(operator(), "sync", accepted); err != nil {
		t.Fatalf("Create: %v", err)
	}
	begun, err := h.console.InstallSlackApp(operator(), connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: "sync"}))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")
	code := h.slack.Install(h.app(t, "sync").GetAppId(), acmeTeam)
	query := func(state string) url.Values { return url.Values{"code": {code}, "state": {state}} }

	// The cookie the flow set is HttpOnly, and pinned for ten minutes.
	set := begun.Header().Get("Set-Cookie")
	if !strings.Contains(set, "HttpOnly") || !strings.Contains(set, "Max-Age=600") {
		t.Errorf("flow cookie = %s", set)
	}

	other, _ := h.server.state.IssueAs(access.Binding{Bind: "github-catalogue:sync", Actor: "ada@north.example"})
	noActor, _ := h.server.state.IssueAs(access.Binding{Bind: slackCatalogueBind + "sync"})
	for name, got := range map[string]int{
		"no cookie":                       redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(state), "").Code,
		"another browser's cookie":        redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(state), "a-cookie-from-elsewhere").Code,
		"a tampered state":                redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(state+"x"), cookie).Code,
		"no state":                        redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, url.Values{"code": {code}}, cookie).Code,
		"another flow's state and cookie": redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(other), other).Code,
		"a state with no operator":        redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(noActor), noActor).Code,
	} {
		want := http.StatusBadRequest
		if name == "a state with no operator" {
			want = http.StatusForbidden
		}
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	if h.slack.Count("oauth.v2.access") != 0 {
		t.Error("a refused callback still spent the code at Slack")
	}
	if _, ok := h.secret(t)["sync.slack_bot_token"]; ok {
		t.Error("a refused callback kept a token")
	}

	// Declined in Slack: said, not a failure of this service.
	if got := redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, url.Values{"error": {"access_denied"}, "state": {state}}, cookie); got.Code != http.StatusBadRequest ||
		!strings.Contains(got.Body.String(), "not approved") {
		t.Errorf("a declined install = %d:\n%s", got.Code, got.Body)
	}

	// The one browser that started it finishes it.
	if got := redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(state), cookie); got.Code != http.StatusFound {
		t.Fatalf("the right browser = %d:\n%s", got.Code, got.Body)
	}
	// And the page it lands on says nothing a log should not: no token.
	if strings.Contains(h.logs.String(), slackfake.Token(acmeTeam)) {
		t.Error("the bot token is in the logs")
	}
}
