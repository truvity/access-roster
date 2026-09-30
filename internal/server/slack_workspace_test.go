package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// wsHarness is the Slack harness with the workspace store and the
// controller's report wired in.
type wsHarness struct {
	*slackHarness
	workspaces *kube.SlackWorkspaces
	reports    *kube.SlackStatus
}

func newWorkspaceHarness(t *testing.T) *wsHarness {
	t.Helper()
	h := &wsHarness{slackHarness: newSlackHarness(t)}
	h.slack.AddTeam("T0789IJKL", "Initech")
	h.workspaces = kube.NewSlackWorkspaces(h.client)
	h.reports = kube.NewSlackStatus(h.client)
	if err := h.reports.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.console.deps.SlackWorkspaces = h.workspaces
	h.console.deps.SlackStatus = h.reports
	return h
}

func (h *wsHarness) begin(ctx context.Context, workspace, token string) (*connect.Response[directoryrosterv1.BeginSlackWorkspaceConnectResponse], error) {
	return h.console.BeginSlackWorkspaceConnect(ctx, connect.NewRequest(
		&directoryrosterv1.BeginSlackWorkspaceConnectRequest{Workspace: workspace, ConfigurationToken: token}))
}

func (h *wsHarness) disconnect(
	ctx context.Context, workspace string, force bool,
) (*connect.Response[directoryrosterv1.DisconnectSlackWorkspaceResponse], error) {
	return h.console.DisconnectSlackWorkspace(ctx, connect.NewRequest(
		&directoryrosterv1.DisconnectSlackWorkspaceRequest{Workspace: workspace, ForgetAnyway: force}))
}

func (h *wsHarness) status(ctx context.Context, t *testing.T) *directoryrosterv1.GetSlackStatusResponse {
	t.Helper()
	got, err := h.console.GetSlackStatus(ctx, connect.NewRequest(&directoryrosterv1.GetSlackStatusRequest{}))
	if err != nil {
		t.Fatalf("GetSlackStatus: %v", err)
	}
	return got.Msg
}

func (h *wsHarness) row(ctx context.Context, t *testing.T, workspace string) *directoryrosterv1.SlackWorkspaceStatus {
	t.Helper()
	for _, row := range h.status(ctx, t).GetWorkspaces() {
		if row.GetWorkspace() == workspace {
			return row
		}
	}
	t.Fatalf("no workspace %s in the status", workspace)
	return nil
}

// credentials is the Secret the controller mounts.
func (h *wsHarness) credentials(t *testing.T) map[string][]byte {
	t.Helper()
	secret, err := h.client.API().CoreV1().Secrets("access-issuer").Get(context.Background(), "access-issuer-slack-credentials", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read the Slack credentials Secret: %v", err)
	}
	return secret.Data
}

// finish plays the owner: Slack sends the browser back from an install
// into installIn, with the state and cookie the begin handed out.
func (h *wsHarness) finish(
	t *testing.T, begun *connect.Response[directoryrosterv1.BeginSlackWorkspaceConnectResponse], workspace, installIn string,
) *httpResult {
	t.Helper()
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")
	_, credential, found, err := h.workspaces.Get(context.Background(), workspace)
	if err != nil || !found {
		t.Fatalf("no credential for %s: %v", workspace, err)
	}
	code := h.slack.Install(credential.AppID, installIn)
	got := redirect(h.server.slackWorkspaceCallback, slackWorkspaceCallbackPath, url.Values{"code": {code}, "state": {state}}, cookie)
	return &httpResult{Code: got.Code, Location: got.Header().Get("Location"), Body: got.Body.String()}
}

type httpResult struct {
	Code           int
	Location, Body string
}

// Not connected, created, installed into the wrong workspace (revoked and
// refused), installed, scopes grown (reconnected with a configuration
// token), disconnected (revoked): the whole life of a workspace's App.
func TestAWorkspaceIsConnectedRefusedForTheWrongTeamUpgradedAndDisconnected(t *testing.T) {
	h := newWorkspaceHarness(t)
	ctx := operator()

	row := h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackNotConnected || row.GetTeamId() != acmeTeam || !row.GetCanOperate() || row.GetOwner() != "C0north" {
		t.Errorf("before connecting = %+v", row)
	}
	if got := h.status(ctx, t).GetBotScopes(); !slices.Equal(got, connection.BotScopes) {
		t.Errorf("status scopes = %v", got)
	}

	// A workspace needs a token to be created; a sentence is not one.
	for name, token := range map[string]string{"none": "", "a sentence": "my token is here"} {
		if _, err := h.begin(ctx, "acme", token); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("connect with %s = %v, want invalid argument", name, err)
		}
	}
	if _, err := h.begin(ctx, "nowhere", accepted); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("connect to a workspace the policy does not name = %v", err)
	}
	if h.slack.Count("apps.manifest.create") != 0 {
		t.Fatal("a refused connect reached Slack")
	}

	// Create: the manifest carries the roster's scopes and this console's
	// callback, and what is kept is "created, not installed".
	begun, err := h.begin(ctx, "acme", accepted)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(h.slack.Apps) != 1 {
		t.Fatalf("Slack has %d Apps", len(h.slack.Apps))
	}
	var created *slackfake.App
	for _, app := range h.slack.Apps {
		created = app
	}
	if !slices.Equal(created.Scopes, connection.BotScopes) ||
		!strings.Contains(created.Manifest, "https://access.example"+slackWorkspaceCallbackPath) ||
		!strings.Contains(created.Manifest, `"name":"access-roster-acme"`) {
		t.Errorf("manifest = %s, scopes = %v", created.Manifest, created.Scopes)
	}
	if u := begun.Msg.GetUrl(); mustQuery(t, u, "team") != acmeTeam || mustQuery(t, u, "redirect_uri") != "https://access.example"+slackWorkspaceCallbackPath ||
		mustQuery(t, u, "scope") != strings.Join(connection.BotScopes, ",") {
		t.Errorf("authorize URL = %s", u)
	}
	row = h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackCreated || row.GetConnection().GetAppId() != created.ID || row.GetConnection().GetBotUserId() != "" {
		t.Errorf("after create = %+v", row)
	}
	raw := h.credentials(t)["acme.json"]
	credential, err := connection.DecodeCredential(raw)
	if err != nil || credential.ClientID != created.ClientID || credential.ClientSecret != created.ClientSecret ||
		credential.BotToken != "" || credential.Installed() {
		t.Fatalf("credential after create = %+v, %v", credential, err)
	}
	if h.slack.Count("oauth.v2.access") != 0 {
		t.Error("created and already exchanging a code")
	}
	// A second connect without a token reuses the App: no second App.
	if _, err = h.begin(ctx, "acme", ""); err != nil {
		t.Fatalf("connect again: %v", err)
	}
	if len(h.slack.Apps) != 1 {
		t.Errorf("a second connect created another App: %d", len(h.slack.Apps))
	}

	// Installed into the wrong workspace: the token is revoked, not kept,
	// and the refusal is recorded.
	begun, err = h.begin(ctx, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	got := h.finish(t, begun, "acme", globexTeam)
	if got.Code != http.StatusConflict || !strings.Contains(got.Body, "revoked") || !strings.Contains(got.Body, `href="/console/#/slack"`) {
		t.Fatalf("an install into the wrong workspace = %d:\n%s", got.Code, got.Body)
	}
	if !h.slack.Revoked(globexTeam) || h.slack.Revoked(acmeTeam) {
		t.Errorf("revoked: globex %v acme %v, want only globex", h.slack.Revoked(globexTeam), h.slack.Revoked(acmeTeam))
	}
	if h.row(ctx, t, "acme").GetConnectionState() != slackCreated {
		t.Error("a refused install changed the state")
	}
	if credential, _ = connection.DecodeCredential(h.credentials(t)["acme.json"]); credential.BotToken != "" {
		t.Error("a refused install kept a token")
	}
	if refused := h.recorded.Find("roster.slack_workspace.connect_refused"); len(refused) != 1 {
		t.Fatalf("refusals recorded = %d, want 1", len(refused))
	}
	if strings.Contains(h.logs.String(), slackfake.Token(globexTeam)) {
		t.Error("the refused token is in the logs")
	}

	// Installed into the right one.
	begun, err = h.begin(ctx, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if got = h.finish(t, begun, "acme", acmeTeam); got.Code != http.StatusFound || got.Location != "/console/#/slack" {
		t.Fatalf("the right install = %d %s:\n%s", got.Code, got.Location, got.Body)
	}
	row = h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackInstalled || row.GetConnection().GetBotUserId() != slackfake.BotID(acmeTeam) ||
		!slices.Equal(row.GetConnection().GetGrantedScopes(), connection.BotScopes) || row.GetConnection().GetConnectedBy() != "ada@north.example" ||
		row.GetNeedsConfigurationToken() || len(row.GetMissingScopes()) != 0 {
		t.Errorf("after install = %+v", row)
	}
	if credential, _ = connection.DecodeCredential(h.credentials(t)["acme.json"]); credential.BotToken != slackfake.Token(acmeTeam) ||
		credential.Record == nil || credential.Record.BotUserID != slackfake.BotID(acmeTeam) {
		t.Errorf("credential after install = %+v", credential)
	}
	if connected := h.recorded.Find("roster.slack_workspace.connected"); len(connected) != 1 {
		t.Errorf("connected recorded = %d, want 1", len(connected))
	}

	// The roster's scopes grow: installed, yet scopes are missing, and a
	// reinstall grants nothing new until the App's manifest is updated.
	before := connection.BotScopes
	connection.BotScopes = append(slices.Clone(before), "reactions:read")
	t.Cleanup(func() { connection.BotScopes = before })
	row = h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackAppScopesMissing || !slices.Equal(row.GetMissingScopes(), []string{"reactions:read"}) ||
		!row.GetNeedsConfigurationToken() {
		t.Errorf("after the scopes grew = %+v", row)
	}
	if _, err = h.begin(ctx, "acme", ""); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "configuration token") {
		t.Errorf("reconnect without a token = %v, want failed precondition naming the token", err)
	}
	if _, err = h.begin(ctx, "acme", "not a token"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("reconnect with a sentence = %v", err)
	}
	begun, err = h.begin(ctx, "acme", accepted)
	if err != nil {
		t.Fatalf("reconnect with a token: %v", err)
	}
	if h.slack.Count("apps.manifest.update") != 1 || !slices.Equal(created.Scopes, connection.BotScopes) || len(h.slack.Apps) != 1 {
		t.Errorf("update calls %d, App scopes %v, Apps %d", h.slack.Count("apps.manifest.update"), created.Scopes, len(h.slack.Apps))
	}
	if h.row(ctx, t, "acme").GetNeedsConfigurationToken() {
		t.Error("the manifest is updated and still asks for a token")
	}
	if got = h.finish(t, begun, "acme", acmeTeam); got.Code != http.StatusFound {
		t.Fatalf("the reinstall = %d:\n%s", got.Code, got.Body)
	}
	if row = h.row(ctx, t, "acme"); row.GetConnectionState() != slackInstalled || len(row.GetMissingScopes()) != 0 {
		t.Errorf("after the reinstall = %+v", row)
	}

	// Disconnect: only an operator of the owner, revoking the token and
	// forgetting everything.
	if _, err = h.disconnect(asSlackIdentity(southOp), "acme", false); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a foreign operator's disconnect = %v, want permission denied", err)
	}
	if _, err = h.disconnect(viewer(), "acme", false); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer's disconnect = %v, want permission denied", err)
	}
	if h.slack.Revoked(acmeTeam) {
		t.Fatal("a refused disconnect revoked the token")
	}
	gone, err := h.disconnect(asSlackIdentity(northOp), "acme", false)
	if err != nil || !gone.Msg.GetRevoked() {
		t.Fatalf("disconnect = %+v, %v", gone, err)
	}
	if !h.slack.Revoked(acmeTeam) {
		t.Error("disconnect left the token working")
	}
	if _, ok := h.credentials(t)["acme.json"]; ok {
		t.Error("disconnect kept the credential")
	}
	if row = h.row(ctx, t, "acme"); row.GetConnectionState() != slackNotConnected || row.GetConnection() != nil {
		t.Errorf("after disconnect = %+v", row)
	}
	if _, err = h.disconnect(ctx, "acme", false); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("disconnecting what is not connected = %v", err)
	}
	if disconnected := h.recorded.Find("roster.slack_workspace.disconnected"); len(disconnected) != 1 {
		t.Errorf("disconnected recorded = %d, want 1", len(disconnected))
	}
}

// A disconnect Slack will not revoke keeps the connection, unless told to
// forget it anyway, and says which in the audit record.
func TestADisconnectSlackWillNotRevokeKeepsTheConnectionUnlessForced(t *testing.T) {
	h := newWorkspaceHarness(t)
	ctx := operator()
	begun, err := h.begin(ctx, "acme", accepted)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.finish(t, begun, "acme", acmeTeam); got.Code != http.StatusFound {
		t.Fatalf("install = %d", got.Code)
	}
	h.slack.Fail("auth.revoke", "fatal_error", 2)
	if _, err = h.disconnect(ctx, "acme", false); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("a refused revoke = %v, want unavailable", err)
	}
	if h.row(ctx, t, "acme").GetConnectionState() != slackInstalled {
		t.Error("a failed disconnect forgot the connection")
	}
	gone, err := h.disconnect(ctx, "acme", true)
	if err != nil || gone.Msg.GetRevoked() {
		t.Fatalf("a forced disconnect = %+v, %v", gone, err)
	}
	if h.row(ctx, t, "acme").GetConnectionState() != slackNotConnected {
		t.Error("a forced disconnect kept the connection")
	}
	recorded := h.recorded.Find("roster.slack_workspace.disconnected")
	if len(recorded) != 1 || !strings.Contains(fmt.Sprint(recorded[0]), "without revoking") {
		t.Errorf("the forced disconnect's record = %v", recorded)
	}

	// Created and never installed: nothing to revoke, and not an error.
	if _, err = h.begin(ctx, "globex", accepted); err != nil {
		t.Fatal(err)
	}
	gone, err = h.disconnect(ctx, "globex", false)
	if err != nil || gone.Msg.GetRevoked() || h.slack.Count("auth.revoke") != 2 {
		t.Errorf("disconnecting an App never installed = %+v, %v (revokes: %d)", gone, err, h.slack.Count("auth.revoke"))
	}
}

// The catalogue's install is refused for the wrong workspace the same way:
// the token is revoked before the refusal.
func TestACatalogueInstallIntoTheWrongWorkspaceIsRevoked(t *testing.T) {
	h := newWorkspaceHarness(t)
	if err := h.create(operator(), "sync", accepted); err != nil {
		t.Fatal(err)
	}
	_, done := h.install(t, "sync", "", globexTeam)
	code, _, body := done()
	if code != http.StatusConflict || !strings.Contains(body, "revoked") {
		t.Fatalf("a catalogue install into the wrong workspace = %d:\n%s", code, body)
	}
	if !h.slack.Revoked(globexTeam) {
		t.Error("the wrong workspace's token still works")
	}
	if _, ok := h.secret(t)["sync.slack_bot_token"]; ok {
		t.Error("the refused token was kept")
	}
}

func TestTheWorkspaceConfigurationTokenIsNeverKeptOrLogged(t *testing.T) {
	h := newWorkspaceHarness(t)
	ctx := operator()
	const second = "xoxe.xoxp-1-not-the-accepted-one"
	begun, err := h.begin(ctx, "acme", accepted)
	if err != nil {
		t.Fatal(err)
	}
	h.finish(t, begun, "acme", acmeTeam)
	before := connection.BotScopes
	connection.BotScopes = append(slices.Clone(before), "reactions:read")
	t.Cleanup(func() { connection.BotScopes = before })
	if _, err = h.begin(ctx, "acme", second); err == nil {
		t.Fatal("Slack accepted a token it does not know")
	} else if strings.Contains(err.Error(), second) {
		t.Errorf("the refusal echoes the token: %v", err)
	}
	if begun, err = h.begin(ctx, "acme", accepted); err != nil {
		t.Fatal(err)
	}
	h.finish(t, begun, "acme", acmeTeam)

	var everywhere bytes.Buffer
	for key, value := range h.credentials(t) {
		fmt.Fprintf(&everywhere, "%s=%s\n", key, value)
	}
	cm, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), "access-issuer-slack-workspaces", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range cm.Data {
		fmt.Fprintf(&everywhere, "%s=%s\n", key, value)
	}
	everywhere.WriteString(h.logs.String())
	for _, rec := range h.recorded.Records() {
		fmt.Fprintf(&everywhere, "%v\n", rec)
	}
	for _, secret := range []string{accepted, second} {
		if strings.Contains(everywhere.String(), secret) {
			t.Errorf("the configuration token %q turned up in a Secret, a ConfigMap, the logs or the audit records", secret)
		}
	}
	if !strings.Contains(everywhere.String(), "acme.json=") {
		t.Error("the harness did not read the Secret")
	}
	// The record is the public half: no secret, no bot token.
	if record := cm.Data["acme.json"]; strings.Contains(record, slackfake.Token(acmeTeam)) || strings.Contains(record, "client_secret") {
		t.Errorf("the record holds a credential: %s", record)
	}
}

func TestOnlyAnOperatorOfTheOwnerConnects(t *testing.T) {
	h := newWorkspaceHarness(t)
	for name, who := range map[string]context.Context{
		"a viewer":                 viewer(),
		"a foreign operator":       asSlackIdentity(southOp),
		"an operator of no owner":  asSlackIdentity(elsewhereOp),
		"the owner's viewer":       asSlackIdentity(northViewer),
		"another workspace's only": asSlackIdentity(southOp),
	} {
		if _, err := h.begin(who, "acme", accepted); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s connecting = %v, want permission denied", name, err)
		}
	}
	if _, err := h.begin(context.Background(), "acme", accepted); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous connect = %v", err)
	}
	// initech names no owner: the installation-wide role only.
	if _, err := h.begin(asSlackIdentity(northOp), "initech", accepted); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an owner's operator connecting an unowned workspace = %v", err)
	}
	if h.slack.Count("apps.manifest.create") != 0 {
		t.Error("a refused connect reached Slack")
	}
	if _, err := h.begin(asSlackIdentity(northOp), "acme", accepted); err != nil {
		t.Errorf("the owner's operator = %v", err)
	}
	// Without a store there is nowhere to keep a token.
	h.console.deps.SlackWorkspaces = nil
	if _, err := h.begin(operator(), "globex", accepted); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("connect without a store = %v", err)
	}
}

// Begin and callback are one flow: the state pins it to the browser and to
// this kind of flow, and to an operator of the workspace NOW.
func TestAWorkspaceInstallIsFinishedOnlyByTheBrowserThatStartedIt(t *testing.T) {
	h := newWorkspaceHarness(t)
	begun, err := h.begin(operator(), "acme", accepted)
	if err != nil {
		t.Fatal(err)
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")
	_, credential, _, _ := h.workspaces.Get(context.Background(), "acme")
	code := h.slack.Install(credential.AppID, acmeTeam)
	query := func(state string) url.Values { return url.Values{"code": {code}, "state": {state}} }
	callbackQuery := func(q url.Values, cookie string) int {
		return redirect(h.server.slackWorkspaceCallback, slackWorkspaceCallbackPath, q, cookie).Code
	}
	callback := func(state, cookie string) int { return callbackQuery(query(state), cookie) }

	set := begun.Header().Get("Set-Cookie")
	if !strings.Contains(set, "HttpOnly") || !strings.Contains(set, "Max-Age=600") {
		t.Errorf("flow cookie = %s", set)
	}
	catalogue, _ := h.server.state.IssueAs(access.Binding{Bind: slackCatalogueBind + "sync", Actor: "ada@north.example"})
	github, _ := h.server.state.IssueAs(access.Binding{Bind: "github-catalogue:sync", Actor: "ada@north.example"})
	noActor, _ := h.server.state.IssueAs(access.Binding{Bind: slackWorkspaceBind + "acme"})
	unknown, _ := h.server.state.IssueAs(access.Binding{Bind: slackWorkspaceBind + "nowhere", Actor: "ada@north.example"})
	for name, c := range map[string]struct{ got, want int }{
		"no cookie":                        {callback(state, ""), http.StatusBadRequest},
		"another browser's cookie":         {callback(state, "a-cookie-from-elsewhere"), http.StatusBadRequest},
		"a tampered state":                 {callback(state+"x", cookie), http.StatusBadRequest},
		"no state":                         {callbackQuery(url.Values{"code": {code}}, cookie), http.StatusBadRequest},
		"a github flow's state and cookie": {callback(github, github), http.StatusBadRequest},
		"the catalogue's state and cookie": {callback(catalogue, catalogue), http.StatusBadRequest},
		"a state with no operator":         {callback(noActor, noActor), http.StatusForbidden},
		"a workspace nothing is kept for":  {callback(unknown, unknown), http.StatusConflict},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", name, c.got, c.want)
		}
	}
	// The catalogue's callback refuses a workspace flow's state likewise.
	if got := redirect(h.server.slackCatalogueCallback, slackCatalogueCallbackPath, query(state), cookie).Code; got != http.StatusBadRequest {
		t.Errorf("a workspace state at the catalogue's callback = %d, want 400", got)
	}
	if h.slack.Count("oauth.v2.access") != 0 {
		t.Error("a refused callback spent the code at Slack")
	}
	if credential, _ := connection.DecodeCredential(h.credentials(t)["acme.json"]); credential.BotToken != "" {
		t.Error("a refused callback kept a token")
	}

	declined := url.Values{"error": {"access_denied"}, "state": {state}}
	if got := redirect(h.server.slackWorkspaceCallback, slackWorkspaceCallbackPath, declined, cookie); got.Code != http.StatusBadRequest ||
		!strings.Contains(got.Body.String(), "not approved") {
		t.Errorf("a declined install = %d:\n%s", got.Code, got.Body)
	}

	// The right operator's own callback is refused after the role is taken
	// away: a flow begun by an operator does not finish in another's
	// workspace.
	foreign := WithIdentity(context.Background(), southOp)
	request := httptest.NewRequest(http.MethodGet, slackWorkspaceCallbackPath+"?"+query(state).Encode(), nil).WithContext(foreign)
	request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: cookie})
	foreignGot := httptest.NewRecorder()
	h.server.slackWorkspaceCallback(foreignGot, request)
	if foreignGot.Code != http.StatusForbidden {
		t.Errorf("a foreign operator finishing = %d, want 403", foreignGot.Code)
	}

	if got := callback(state, cookie); got != http.StatusFound {
		t.Fatalf("the right browser = %d", got)
	}
	// A second use of the same state finds the cookie cleared by a real
	// browser; the code is spent either way.
	if strings.Contains(h.logs.String(), slackfake.Token(acmeTeam)) {
		t.Error("the bot token is in the logs")
	}
}

// What the controller reports is shown only to those who may view the
// workspace, each row saying whether the caller may operate it.
func TestTheStatusShowsEachCallerOnlyTheWorkspacesItMayView(t *testing.T) {
	h := newWorkspaceHarness(t)
	h.putReport(t, report("acme", true, nil))
	h.putReport(t, report("globex", false, nil))
	h.putReport(t, report("initech", true, nil))
	// A report for a workspace the policy has dropped belongs to nobody's
	// directory, so only the installation-wide role sees it.
	h.putReport(t, report("umbrella", true, nil))

	for _, c := range []struct {
		name            string
		who             access.Identity
		views, operates []string
	}{
		{"installation-wide operator", everywhere, []string{"acme", "globex", "initech", "umbrella"}, []string{"acme", "globex", "initech", "umbrella"}},
		{"installation-wide viewer", access.Identity{Role: access.RoleViewer}, []string{"acme", "globex", "initech", "umbrella"}, nil},
		{"owning operator", northOp, []string{"acme"}, []string{"acme"}},
		{"foreign operator", southOp, []string{"globex"}, []string{"globex"}},
		{"owning viewer", northViewer, []string{"acme"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var views, operates []string
			for _, row := range h.status(asSlackIdentity(c.who), t).GetWorkspaces() {
				views = append(views, row.GetWorkspace())
				if row.GetCanOperate() {
					operates = append(operates, row.GetWorkspace())
				}
				if !row.GetReported() && row.GetWorkspace() != "initech" && row.GetWorkspace() != "globex" && row.GetWorkspace() != "acme" {
					t.Errorf("%s has a report and is shown without", row.GetWorkspace())
				}
			}
			if !slices.Equal(views, c.views) || !slices.Equal(operates, c.operates) {
				t.Errorf("views %v operates %v, want %v and %v", views, operates, c.views, c.operates)
			}
		})
	}
	statusReq := connect.NewRequest(&directoryrosterv1.GetSlackStatusRequest{})
	if _, err := h.console.GetSlackStatus(asSlackIdentity(elsewhereOp), statusReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an operator of a directory that owns nothing = %v, want permission denied", err)
	}
	if _, err := h.console.GetSlackStatus(context.Background(), statusReq); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous = %v", err)
	}
}

func TestTheStatusSaysWhatTheControllerDid(t *testing.T) {
	h := newWorkspaceHarness(t)
	at := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	doc := status.Workspace{
		Workspace: "acme", Enabled: false,
		Tick: status.Tick{At: at, Outcome: status.OutcomeDryRun, Changes: 4, Held: 1},
		Channels: []status.Channel{{
			Name: "eng", ID: "C1", Private: true, Mode: "strict", State: status.ChannelOK,
			Members: []status.Member{
				{Person: "ann", Email: "ann@acme.example", UserID: "U1", State: status.StateOK},
				{Person: "bob", Email: "bob@acme.example", State: status.StateWillInvite, Action: status.ActionInvite},
				{Email: "cy@acme.example", UserID: "U3", State: status.StateWillRemove, Action: status.ActionRemove},
				{Email: "di@acme.example", UserID: "U4", State: status.StateHeld, Reason: "the directory cannot vouch"},
			},
			Breaker: &status.Breaker{Affected: 3, Total: 4, Fingerprint: "chan-fp"},
		}, {Name: "ops", State: status.ChannelWillCreate}},
		Leavers: []status.Leaver{{Email: "gone@acme.example", UserID: "U9", Channels: []string{"eng"}}},
		Breaker: &status.Breaker{Affected: 5, Total: 8, Fingerprint: "ws-fp"},
	}
	h.putReport(t, doc)
	if err := h.workspaces.PutConfirmation(context.Background(), connection.Confirmation{
		Workspace: "acme", Channel: "eng", Fingerprint: "chan-fp", By: "ada@north.example", At: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	// A confirmation a day old holds no more.
	if err := h.workspaces.PutConfirmation(context.Background(), connection.Confirmation{
		Workspace: "acme", Fingerprint: "ws-fp", By: "ada@north.example", At: time.Now().Add(-25 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	row := h.row(viewer(), t, "acme")
	if !row.GetReported() || row.GetActing() || row.GetTick().GetOutcome() != "dry-run" || row.GetTick().GetChanges() != 4 || row.GetTick().GetHeld() != 1 ||
		!row.GetTick().GetAt().AsTime().Equal(at) || row.GetCanOperate() {
		t.Errorf("row = %+v", row)
	}
	if b := row.GetBreaker(); b.GetFingerprint() != "ws-fp" || b.GetAffected() != 5 || b.GetTotal() != 8 {
		t.Errorf("breaker = %+v", b)
	}
	if row.GetRemovalConfirmation() != nil {
		t.Error("a day-old confirmation still holds")
	}
	if len(row.GetLeavers()) != 1 || row.GetLeavers()[0].GetEmail() != "gone@acme.example" {
		t.Errorf("leavers = %+v", row.GetLeavers())
	}
	if len(row.GetChannels()) != 2 {
		t.Fatalf("channels = %+v", row.GetChannels())
	}
	eng := row.GetChannels()[0]
	if eng.GetName() != "eng" || !eng.GetPrivate() || eng.GetMode() != "strict" || len(eng.GetMembers()) != 4 ||
		eng.GetBreaker().GetFingerprint() != "chan-fp" || eng.GetRemovalConfirmation().GetConfirmedBy() != "ada@north.example" {
		t.Errorf("eng = %+v", eng)
	}
	states := map[string]string{}
	for _, m := range eng.GetMembers() {
		states[m.GetEmail()] = m.GetState() + "/" + m.GetAction() + "/" + m.GetReason()
	}
	if states["bob@acme.example"] != "will-invite/invite/" || states["cy@acme.example"] != "will-remove/remove/" ||
		states["di@acme.example"] != "held//the directory cannot vouch" || states["ann@acme.example"] != "ok//" {
		t.Errorf("member states = %v", states)
	}
	if row.GetChannels()[1].GetState() != "will-create" {
		t.Errorf("ops = %+v", row.GetChannels()[1])
	}

	// A report this build cannot read is a failed pass with the reason, not
	// a workspace with nothing to say.
	if err := h.reports.Replace(context.Background(), map[string]string{"acme.json": `{"version":99}`}); err != nil {
		t.Fatal(err)
	}
	row = h.row(viewer(), t, "acme")
	if !row.GetReported() || row.GetTick().GetOutcome() != "failed" || !strings.Contains(row.GetTick().GetError(), "could not be read") {
		t.Errorf("an unreadable report = %+v", row)
	}
}

// The matrix of who may confirm which set: the fingerprint of the latest
// report for exactly that gate, by an operator of the workspace's owner.
func TestConfirmingSlackRemovalsIsForTheSetTheReportShows(t *testing.T) {
	h := newWorkspaceHarness(t)
	h.putReport(t, status.Workspace{
		Workspace: "acme", Enabled: true, Tick: status.Tick{At: time.Now(), Outcome: status.OutcomeHeld},
		Breaker: &status.Breaker{Affected: 5, Total: 8, Fingerprint: "ws-fp"},
		Channels: []status.Channel{
			{Name: "eng", State: status.ChannelOK, Breaker: &status.Breaker{Affected: 3, Total: 4, Fingerprint: "chan-fp"}},
			{Name: "ops", State: status.ChannelOK},
		},
	})
	confirm := func(ctx context.Context, workspace, channel, fingerprint string) error {
		_, err := h.console.ConfirmSlackRemovals(ctx, connect.NewRequest(
			&directoryrosterv1.ConfirmSlackRemovalsRequest{Workspace: workspace, Channel: channel, Fingerprint: fingerprint}))
		return err
	}
	denied := func(name string, err error, want connect.Code) {
		t.Helper()
		if connect.CodeOf(err) != want {
			t.Errorf("%s = %v, want %v", name, err, want)
		}
	}

	denied("a viewer", confirm(viewer(), "acme", "", "ws-fp"), connect.CodePermissionDenied)
	denied("the owner's viewer", confirm(asSlackIdentity(northViewer), "acme", "", "ws-fp"), connect.CodePermissionDenied)
	denied("a foreign operator", confirm(asSlackIdentity(southOp), "acme", "", "ws-fp"), connect.CodePermissionDenied)
	denied("anonymous", confirm(context.Background(), "acme", "", "ws-fp"), connect.CodeUnauthenticated)
	denied("a wrong fingerprint", confirm(operator(), "acme", "", "stale"), connect.CodeFailedPrecondition)
	denied("a channel's fingerprint for the workspace", confirm(operator(), "acme", "", "chan-fp"), connect.CodeFailedPrecondition)
	denied("the workspace's fingerprint for a channel", confirm(operator(), "acme", "eng", "ws-fp"), connect.CodeFailedPrecondition)
	denied("a channel with no breaker", confirm(operator(), "acme", "ops", "ws-fp"), connect.CodeFailedPrecondition)
	denied("a channel not in the report", confirm(operator(), "acme", "nope", "chan-fp"), connect.CodeFailedPrecondition)
	denied("a workspace with no report", confirm(operator(), "globex", "", "ws-fp"), connect.CodeFailedPrecondition)
	denied("a blank fingerprint", confirm(operator(), "acme", "", ""), connect.CodeInvalidArgument)
	denied("a channel with a dot", confirm(operator(), "acme", "a.b", "x"), connect.CodeInvalidArgument)
	if got, _ := h.workspaces.Confirmations(context.Background()); len(got) != 0 {
		t.Fatalf("a refused confirmation was kept: %v", got)
	}
	if len(h.recorded.Find("roster.slack_removals.confirmed")) != 0 {
		t.Fatal("a refused confirmation was audited")
	}

	// The owner's own operator confirms the workspace-wide set, and a
	// channel's own set, each kept where the controller reads it.
	if err := confirm(asSlackIdentity(northOp), "acme", "", "ws-fp"); err != nil {
		t.Fatalf("confirming the workspace set: %v", err)
	}
	if err := confirm(operator(), "acme", "eng", "chan-fp"); err != nil {
		t.Fatalf("confirming the channel set: %v", err)
	}
	kept, _ := h.workspaces.Confirmations(context.Background())
	if kept[connection.ConfirmationKey("acme", "")].Fingerprint != "ws-fp" || kept[connection.ConfirmationKey("acme", "eng")].Fingerprint != "chan-fp" {
		t.Errorf("confirmations kept = %v", kept)
	}
	row := h.row(viewer(), t, "acme")
	if row.GetRemovalConfirmation().GetFingerprint() != "ws-fp" || row.GetChannels()[0].GetRemovalConfirmation().GetFingerprint() != "chan-fp" {
		t.Errorf("the status does not show the confirmations: %+v", row)
	}
	if recorded := h.recorded.Find("roster.slack_removals.confirmed"); len(recorded) != 2 {
		t.Errorf("confirmations audited = %d, want 2", len(recorded))
	}

	// The set changes after the page was loaded: confirming the old one is
	// refused rather than confirming people nobody looked at.
	h.putReport(t, status.Workspace{
		Workspace: "acme", Enabled: true, Tick: status.Tick{At: time.Now(), Outcome: status.OutcomeHeld},
		Breaker: &status.Breaker{Affected: 6, Total: 8, Fingerprint: "ws-fp-2"},
	})
	denied("a stale report's fingerprint", confirm(operator(), "acme", "", "ws-fp"), connect.CodeFailedPrecondition)
	if err := confirm(operator(), "acme", "", "ws-fp-2"); err != nil {
		t.Errorf("confirming the new set: %v", err)
	}

	// No store, no confirmations.
	h.console.deps.SlackWorkspaces = nil
	denied("without a store", confirm(operator(), "acme", "", "ws-fp-2"), connect.CodeFailedPrecondition)
}

// Disconnecting a workspace forgets what was confirmed for it.
func TestDisconnectingForgetsTheWorkspacesConfirmations(t *testing.T) {
	h := newWorkspaceHarness(t)
	begun, err := h.begin(operator(), "acme", accepted)
	if err != nil {
		t.Fatal(err)
	}
	h.finish(t, begun, "acme", acmeTeam)
	if err = h.workspaces.PutConfirmation(context.Background(), connection.Confirmation{
		Workspace: "acme", Fingerprint: "ws-fp", By: "ada@north.example", At: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.disconnect(operator(), "acme", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.workspaces.Confirmations(context.Background()); len(got) != 0 {
		t.Errorf("confirmations left behind: %v", got)
	}
}

func report(workspace string, enabled bool, channels []status.Channel) status.Workspace {
	return status.Workspace{
		Workspace: workspace, Enabled: enabled, Channels: channels,
		Tick: status.Tick{At: time.Now(), Outcome: status.OutcomeInSync},
	}
}

func (h *wsHarness) putReport(t *testing.T, w status.Workspace) {
	t.Helper()
	document, err := status.Encode(w)
	if err != nil {
		t.Fatal(err)
	}
	read, err := h.reports.Reports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if read == nil {
		read = map[string]string{}
	}
	read[status.Key(w.Workspace)] = document
	if err = h.reports.Replace(context.Background(), read); err != nil {
		t.Fatal(err)
	}
}
