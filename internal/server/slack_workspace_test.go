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
	reports *kube.SlackStatus
}

// newConnectedWorkspaceHarness is the workspace harness with the three
// workspaces connected: acme owned by C0north's directory, globex by
// C0south's, initech by nobody's.
func newConnectedWorkspaceHarness(t *testing.T) *wsHarness {
	t.Helper()
	h := newWorkspaceHarness(t)
	seedSlackWorkspace(t, h.workspaces, "acme", "C0north", acmeTeam)
	seedSlackWorkspace(t, h.workspaces, "globex", "C0south", globexTeam)
	seedSlackWorkspace(t, h.workspaces, "initech", "", "T0789IJKL")
	return h
}

func newWorkspaceHarness(t *testing.T) *wsHarness {
	t.Helper()
	h := &wsHarness{slackHarness: newBareSlackHarness(t)}
	h.slack.AddTeam("T0789IJKL", "Initech")
	h.reports = kube.NewSlackStatus(h.client)
	if err := h.reports.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.console.deps.SlackStatus = h.reports
	return h
}

func (h *wsHarness) begin(ctx context.Context, workspace, token string) (*connect.Response[directoryrosterv1.BeginSlackWorkspaceConnectResponse], error) {
	return h.beginOwned(ctx, workspace, token, "")
}

// beginOwned is a connect that names the directory to own the workspace.
func (h *wsHarness) beginOwned(
	ctx context.Context, workspace, token, owner string,
) (*connect.Response[directoryrosterv1.BeginSlackWorkspaceConnectResponse], error) {
	return h.console.BeginSlackWorkspaceConnect(ctx, connect.NewRequest(
		&directoryrosterv1.BeginSlackWorkspaceConnectRequest{Workspace: workspace, ConfigurationToken: token, Owner: owner}))
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

// Not connected, created (owned by a directory the operator chose),
// installed (the team Slack reports is recorded), reinstalled into another
// team (revoked and refused), scopes grown (reconnected with a configuration
// token), disconnected (revoked): the whole life of a workspace's App.
func TestAWorkspaceIsConnectedRecordedRefusedForAnotherTeamUpgradedAndDisconnected(t *testing.T) {
	h := newWorkspaceHarness(t)
	ctx := operator()

	row := h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackNotConnected || row.GetTeamId() != "" || !row.GetCanOperate() || row.GetOwner() != "" {
		t.Errorf("before connecting = %+v", row)
	}
	page := h.status(ctx, t)
	if got := page.GetBotScopes(); !slices.Equal(got, connection.BotScopes) {
		t.Errorf("status scopes = %v", got)
	}
	// The installation-wide operator chooses among every connected
	// directory, or none.
	var choices []string
	for _, dir := range page.GetOwnerChoices() {
		choices = append(choices, dir.GetWorkspaceId()+"="+dir.GetPrimaryDomain())
	}
	if !slices.Equal(choices, []string{"C0north=north.example", "C0south=south.example"}) || !page.GetMayConnectWithoutOwner() {
		t.Errorf("owner choices = %v, without owner %v", choices, page.GetMayConnectWithoutOwner())
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
	if _, err := h.beginOwned(ctx, "acme", accepted, "C0nowhere"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("connect with an owner that is not a connected directory = %v, want invalid argument", err)
	}
	if h.slack.Count("apps.manifest.create") != 0 {
		t.Fatal("a refused connect reached Slack")
	}

	// Create: the manifest carries the roster's scopes and this console's
	// callback, and what is kept is "created, not installed", owned by the
	// directory chosen, with no team yet.
	begun, err := h.beginOwned(ctx, "acme", accepted, "C0north")
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
	if u := begun.Msg.GetUrl(); mustQuery(t, u, "redirect_uri") != "https://access.example"+slackWorkspaceCallbackPath ||
		mustQuery(t, u, "scope") != strings.Join(connection.BotScopes, ",") {
		t.Errorf("authorize URL = %s", u)
	}
	if parsed, _ := url.Parse(begun.Msg.GetUrl()); parsed.Query().Has("team") {
		t.Errorf("the first install preselects a team nobody recorded yet: %s", begun.Msg.GetUrl())
	}
	row = h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackCreated || row.GetConnection().GetAppId() != created.ID || row.GetConnection().GetBotUserId() != "" ||
		row.GetOwner() != "C0north" || row.GetOwnerDomain() != "north.example" || row.GetTeamId() != "" || !row.GetCanChangeOwner() {
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
	// A second connect without a token reuses the App: no second App, and
	// the owner chosen first is not changed by naming another.
	if _, err = h.beginOwned(ctx, "acme", "", "C0south"); err != nil {
		t.Fatalf("connect again: %v", err)
	}
	if len(h.slack.Apps) != 1 {
		t.Errorf("a second connect created another App: %d", len(h.slack.Apps))
	}
	if got := h.row(ctx, t, "acme").GetOwner(); got != "C0north" {
		t.Errorf("connecting again changed the owner to %q", got)
	}

	// The first install records the team Slack reports.
	begun, err = h.begin(ctx, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	got := h.finish(t, begun, "acme", acmeTeam)
	if got.Code != http.StatusFound || got.Location != "/console/#/slack" {
		t.Fatalf("the first install = %d %s:\n%s", got.Code, got.Location, got.Body)
	}
	row = h.row(ctx, t, "acme")
	if row.GetConnectionState() != slackInstalled || row.GetTeamId() != acmeTeam || row.GetOwner() != "C0north" ||
		row.GetConnection().GetBotUserId() != slackfake.BotID(acmeTeam) ||
		!slices.Equal(row.GetConnection().GetGrantedScopes(), connection.BotScopes) || row.GetConnection().GetConnectedBy() != "ada@north.example" ||
		row.GetNeedsConfigurationToken() || len(row.GetMissingScopes()) != 0 {
		t.Errorf("after install = %+v", row)
	}
	if credential, _ = connection.DecodeCredential(h.credentials(t)["acme.json"]); credential.BotToken != slackfake.Token(acmeTeam) ||
		credential.Record == nil || credential.Record.BotUserID != slackfake.BotID(acmeTeam) || credential.Record.TeamID != acmeTeam ||
		credential.Record.Owner != "C0north" {
		t.Errorf("credential after install = %+v", credential)
	}
	connected := h.recorded.Find("roster.slack_workspace.connected")
	if len(connected) != 1 || !strings.Contains(fmt.Sprint(connected[0]), "C0north") {
		t.Errorf("connected recorded = %v, want one naming the owner", connected)
	}

	// A later install must be the same team: the token for another is
	// revoked, not kept, and the refusal is recorded.
	begun, err = h.begin(ctx, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if mustQuery(t, begun.Msg.GetUrl(), "team") != acmeTeam {
		t.Errorf("a reinstall does not preselect the recorded team: %s", begun.Msg.GetUrl())
	}
	got = h.finish(t, begun, "acme", globexTeam)
	if got.Code != http.StatusConflict || !strings.Contains(got.Body, "revoked") || !strings.Contains(got.Body, `href="/console/#/slack"`) {
		t.Fatalf("an install into another team = %d:\n%s", got.Code, got.Body)
	}
	if !h.slack.Revoked(globexTeam) || h.slack.Revoked(acmeTeam) {
		t.Errorf("revoked: globex %v acme %v, want only globex", h.slack.Revoked(globexTeam), h.slack.Revoked(acmeTeam))
	}
	if row = h.row(ctx, t, "acme"); row.GetConnectionState() != slackInstalled || row.GetTeamId() != acmeTeam {
		t.Errorf("a refused install changed the connection: %+v", row)
	}
	if credential, _ = connection.DecodeCredential(h.credentials(t)["acme.json"]); credential.BotToken != slackfake.Token(acmeTeam) {
		t.Error("a refused install replaced the token")
	}
	if refused := h.recorded.Find("roster.slack_workspace.connect_refused"); len(refused) != 1 {
		t.Fatalf("refusals recorded = %d, want 1", len(refused))
	}
	if strings.Contains(h.logs.String(), slackfake.Token(globexTeam)) {
		t.Error("the refused token is in the logs")
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
	if row = h.row(ctx, t, "acme"); row.GetConnectionState() != slackNotConnected || row.GetConnection() != nil || row.GetOwner() != "" || row.GetTeamId() != "" {
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

// The catalogue's install is refused for another team than the one the
// workspace was first installed as, the same way: the token is revoked before
// the refusal.
func TestACatalogueInstallIntoTheWrongWorkspaceIsRevoked(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
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

// bothOp operates two connected directories, which is the one case a scoped
// operator has a choice to make.
var bothOp = access.Identity{Scopes: map[string]access.Role{"C0north": access.RoleOperator, "C0south": access.RoleOperator}}

// Who may connect a workspace nobody has connected yet, and who then owns it:
// the one rule for a Slack workspace and a GitHub organisation alike.
func TestConnectingAnUnconnectedWorkspaceFollowsTheOwnerRule(t *testing.T) {
	for _, c := range []struct {
		name  string
		who   context.Context
		owner string // what the request names
		// want is the code refused with, or OK; recorded is the owner kept.
		want     connect.Code
		recorded string
	}{
		{"the installation-wide operator chooses a directory", operator(), "C0south", 0, "C0south"},
		{"the installation-wide operator may choose none", operator(), "", 0, ""},
		{"the installation-wide operator cannot name a directory that is not connected", operator(), "C0nowhere", connect.CodeInvalidArgument, ""},
		{"an operator of one directory owns it without saying so", asSlackIdentity(northOp), "", 0, "C0north"},
		{"an operator of one directory may name it", asSlackIdentity(northOp), "C0north", 0, "C0north"},
		{"an operator of one directory cannot hand it to another", asSlackIdentity(northOp), "C0south", connect.CodePermissionDenied, ""},
		{"a foreign operator cannot name the other directory", asSlackIdentity(southOp), "C0north", connect.CodePermissionDenied, ""},
		{"an operator of several must choose", asSlackIdentity(bothOp), "", connect.CodeInvalidArgument, ""},
		{"an operator of several chooses among theirs", asSlackIdentity(bothOp), "C0south", 0, "C0south"},
		{"an operator of several cannot choose another", asSlackIdentity(bothOp), "C0nowhere", connect.CodePermissionDenied, ""},
		{"an operator of a directory that is not connected has nothing to own it with", asSlackIdentity(elsewhereOp), "", connect.CodePermissionDenied, ""},
		{"a viewer", viewer(), "", connect.CodePermissionDenied, ""},
		{"the owner's viewer", asSlackIdentity(northViewer), "C0north", connect.CodePermissionDenied, ""},
		{"nobody signed in", context.Background(), "", connect.CodeUnauthenticated, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newWorkspaceHarness(t)
			_, err := h.beginOwned(c.who, "acme", accepted, c.owner)
			if (err == nil) != (c.want == 0) || (err != nil && connect.CodeOf(err) != c.want) {
				t.Fatalf("connect = %v, want code %v (0 is success)", err, c.want)
			}
			if c.want != 0 {
				if h.slack.Count("apps.manifest.create") != 0 {
					t.Error("a refused connect reached Slack")
				}
				if _, _, found, _ := h.workspaces.Get(context.Background(), "acme"); found {
					t.Error("a refused connect left a record")
				}
				return
			}
			record, _, found, err := h.workspaces.Get(context.Background(), "acme")
			if err != nil || !found || record.Owner != c.recorded {
				t.Errorf("record = %+v (found %v, %v), want owner %q", record, found, err, c.recorded)
			}
		})
	}
}

// Once recorded, the owner decides who operates the workspace: its own
// directory's operator and the installation-wide operator, nobody else; and a
// workspace recorded with no owner is the installation-wide operator's alone.
func TestAConnectedWorkspaceIsOperatedByItsRecordedOwnerOnly(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
	for name, who := range map[string]context.Context{
		"a viewer":                viewer(),
		"a foreign operator":      asSlackIdentity(southOp),
		"an operator of no owner": asSlackIdentity(elsewhereOp),
		"the owner's viewer":      asSlackIdentity(northViewer),
	} {
		if _, err := h.begin(who, "acme", ""); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s reconnecting = %v, want permission denied", name, err)
		}
		if _, err := h.disconnect(who, "acme", false); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s disconnecting = %v, want permission denied", name, err)
		}
	}
	if _, err := h.begin(context.Background(), "acme", ""); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous connect = %v", err)
	}
	// initech was recorded with no owner: the installation-wide role only.
	if _, err := h.begin(asSlackIdentity(northOp), "initech", ""); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("an owner's operator reconnecting an unowned workspace = %v", err)
	}
	if h.slack.Count("apps.manifest.create") != 0 {
		t.Error("a refused connect reached Slack")
	}
	if _, err := h.begin(asSlackIdentity(northOp), "acme", ""); err != nil {
		t.Errorf("the owner's operator = %v", err)
	}
	if _, err := h.begin(operator(), "initech", ""); err != nil {
		t.Errorf("the installation-wide operator = %v", err)
	}
	// Without a store there is nowhere to keep a token.
	h.console.deps.SlackWorkspaces = nil
	if _, err := h.begin(operator(), "globex", accepted); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("connect without a store = %v", err)
	}
}

// Refresh: the operator of the workspace's owner, or the installation-wide
// operator, asks for a pass now; it is kept as a marker the controller
// compares with its last pass, shown on the status, and refused again within
// a minute. A viewer, a foreign operator and a workspace with nothing
// installed are refused.
func TestRequestingASlackPassIsForTheWorkspacesOperatorsAndRateLimited(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
	ask := func(ctx context.Context, workspace string) error {
		_, err := h.console.RequestSlackPass(ctx, connect.NewRequest(&directoryrosterv1.RequestSlackPassRequest{Workspace: workspace}))
		return err
	}
	for name, who := range map[string]context.Context{
		"a viewer of the owner":  asSlackIdentity(northViewer),
		"a foreign operator":     asSlackIdentity(southOp),
		"an installation viewer": viewer(),
		"nobody signed in":       context.Background(),
	} {
		if err := ask(who, "acme"); connect.CodeOf(err) != connect.CodePermissionDenied && connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s = %v, want refused", name, err)
		}
	}
	if err := ask(operator(), "not a key"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bad key = %v", err)
	}
	if requests, _ := h.workspaces.PassRequests(context.Background()); len(requests) != 0 {
		t.Fatalf("a refused request left a marker: %v", requests)
	}

	if err := ask(asSlackIdentity(northOp), "acme"); err != nil {
		t.Fatalf("the owner's operator = %v", err)
	}
	if err := ask(operator(), "acme"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("a second request within a minute = %v, want resource exhausted", err)
	}
	// Another workspace has its own limit; the installation-wide operator may ask.
	if err := ask(operator(), "globex"); err != nil {
		t.Errorf("the installation-wide operator = %v", err)
	}
	requests, err := h.workspaces.PassRequests(context.Background())
	if err != nil || len(requests) != 2 || requests["acme"].By != "someone@north.example" || requests["acme"].At.IsZero() {
		t.Fatalf("markers = %+v, %v", requests, err)
	}
	if got := h.row(operator(), t, "acme").GetPassRequestedAt(); got == nil || got.AsTime().Sub(requests["acme"].At).Abs() > time.Second {
		t.Errorf("the status says the pass was requested at %v, want %v", got, requests["acme"].At)
	}
	if got := h.row(operator(), t, "initech").GetPassRequestedAt(); got != nil {
		t.Errorf("a workspace nobody asked for shows a request: %v", got)
	}

	// Past the gap, a new request replaces the marker.
	old := requests["acme"]
	old.At = old.At.Add(-2 * connection.PassGap)
	raw, _ := connection.EncodePassRequest(old)
	cm, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), h.workspaces.ConfigMapName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data[connection.PassKey("acme")] = raw
	if _, err = h.client.API().CoreV1().ConfigMaps("access-issuer").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = ask(asSlackIdentity(northOp), "acme"); err != nil {
		t.Errorf("a request after the gap = %v", err)
	}

	// Disconnecting forgets the marker with the rest.
	if _, err = h.disconnect(operator(), "acme", true); err != nil {
		t.Fatal(err)
	}
	if requests, _ = h.workspaces.PassRequests(context.Background()); len(requests) != 1 || requests["globex"].Workspace == "" {
		t.Errorf("markers after disconnecting acme = %+v", requests)
	}
	h.console.deps.SlackWorkspaces = nil
	if err = ask(operator(), "globex"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("without a store = %v", err)
	}
}

// Only the installation-wide operator changes a recorded owner, to a
// connected directory or to none, and the change is audited.
func TestOnlyTheInstallationWideOperatorChangesAnOwner(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
	change := func(ctx context.Context, workspace, owner string) error {
		_, err := h.console.ChangeSlackWorkspaceOwner(ctx, connect.NewRequest(
			&directoryrosterv1.ChangeSlackWorkspaceOwnerRequest{Workspace: workspace, Owner: owner}))
		return err
	}
	for name, who := range map[string]context.Context{
		"the owner's operator":     asSlackIdentity(northOp),
		"the new owner's operator": asSlackIdentity(southOp),
		"an operator of several":   asSlackIdentity(bothOp),
		"a viewer":                 viewer(),
		"nobody signed in":         context.Background(),
	} {
		if err := change(who, "acme", "C0south"); connect.CodeOf(err) == 0 {
			t.Errorf("%s changed the owner", name)
		}
		if got := h.row(operator(), t, "acme").GetOwner(); got != "C0north" {
			t.Fatalf("after %s tried, the owner is %q", name, got)
		}
	}
	if len(h.recorded.Find("roster.slack_workspace.owner_changed")) != 0 {
		t.Error("a refused change was recorded")
	}
	if err := change(operator(), "acme", "C0nowhere"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an owner that is not a connected directory = %v", err)
	}
	if err := change(operator(), "nowhere", "C0south"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a workspace that is not connected = %v", err)
	}
	if err := change(operator(), "acme", "C0south"); err != nil {
		t.Fatalf("the installation-wide operator = %v", err)
	}
	row := h.row(operator(), t, "acme")
	if row.GetOwner() != "C0south" || row.GetOwnerDomain() != "south.example" {
		t.Errorf("after the change = %+v", row)
	}
	// The new owner now operates it, and the old one does not.
	if _, err := h.begin(asSlackIdentity(southOp), "acme", ""); err != nil {
		t.Errorf("the new owner's operator = %v", err)
	}
	if _, err := h.begin(asSlackIdentity(northOp), "acme", ""); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("the previous owner's operator = %v, want permission denied", err)
	}
	if err := change(operator(), "acme", ""); err != nil {
		t.Fatalf("removing the owner = %v", err)
	}
	if got := h.row(operator(), t, "acme").GetOwner(); got != "" {
		t.Errorf("after removing, the owner is %q", got)
	}
	changed := h.recorded.Find("roster.slack_workspace.owner_changed")
	if len(changed) != 2 || !strings.Contains(fmt.Sprint(changed[0]), "C0north") || !strings.Contains(fmt.Sprint(changed[0]), "C0south") ||
		!strings.Contains(fmt.Sprint(changed[1]), "none") {
		t.Errorf("owner changes recorded = %v", changed)
	}
}

// The same Slack team cannot be connected under two keys: the first install
// of the second is refused and its token revoked.
func TestOneSlackTeamCannotBeConnectedUnderTwoKeys(t *testing.T) {
	h := newWorkspaceHarness(t)
	ctx := operator()
	begun, err := h.beginOwned(ctx, "acme", accepted, "C0north")
	if err != nil {
		t.Fatal(err)
	}
	if got := h.finish(t, begun, "acme", acmeTeam); got.Code != http.StatusFound {
		t.Fatalf("first install = %d", got.Code)
	}
	if begun, err = h.beginOwned(ctx, "globex", accepted, "C0south"); err != nil {
		t.Fatal(err)
	}
	got := h.finish(t, begun, "globex", acmeTeam)
	if got.Code != http.StatusConflict || !strings.Contains(got.Body, "already connected as") || !strings.Contains(got.Body, "revoked") {
		t.Fatalf("a second key for the same team = %d:\n%s", got.Code, got.Body)
	}
	if row := h.row(ctx, t, "globex"); row.GetConnectionState() != slackCreated || row.GetTeamId() != "" {
		t.Errorf("globex after the refusal = %+v", row)
	}
	if refused := h.recorded.Find("roster.slack_workspace.connect_refused"); len(refused) != 1 {
		t.Errorf("refusals recorded = %d, want 1", len(refused))
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

// A callback that cannot finish says why, in the log and in the audit trail:
// a refusal nobody can see is one nobody can explain.
func TestEveryRefusedSlackCallbackIsLoggedAndAuditedWithItsReason(t *testing.T) {
	h := newWorkspaceHarness(t)
	begun, err := h.begin(operator(), "acme", accepted)
	if err != nil {
		t.Fatal(err)
	}
	cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")
	_, credential, _, _ := h.workspaces.Get(context.Background(), "acme")
	code := h.slack.Install(credential.AppID, acmeTeam)
	call := func(q url.Values, cookie string) int {
		return redirect(h.server.slackWorkspaceCallback, slackWorkspaceCallbackPath, q, cookie).Code
	}
	github, _ := h.server.state.IssueAs(access.Binding{Bind: "github-catalogue:sync", Actor: "ada@north.example"})
	noActor, _ := h.server.state.IssueAs(access.Binding{Bind: slackWorkspaceBind + "acme"})
	for name, c := range map[string]struct {
		got    int
		reason string
	}{
		"no cookie":                {call(url.Values{"code": {code}, "state": {state}}, ""), "flow cookie"},
		"another browser":          {call(url.Values{"code": {code}, "state": {state}}, "elsewhere"), "flow cookie"},
		"a tampered state":         {call(url.Values{"code": {code}, "state": {state + "x"}}, cookie), "state is not valid"},
		"no state":                 {call(url.Values{"code": {code}}, cookie), "no state"},
		"another flow's state":     {call(url.Values{"code": {code}, "state": {github}}, github), "another flow"},
		"a state with no operator": {call(url.Values{"code": {code}, "state": {noActor}}, noActor), "no operator"},
		"declined in Slack":        {call(url.Values{"error": {"access_denied"}, "state": {state}}, cookie), "not approved in Slack"},
	} {
		if c.got < 400 || c.got >= 500 {
			t.Errorf("%s = %d, want a 4xx", name, c.got)
		}
		found := false
		for _, rec := range h.recorded.Find("roster.slack_workspace.connect_refused") {
			found = found || strings.Contains(rec.GetOutcome().GetReason(), c.reason)
		}
		if !found {
			t.Errorf("%s: no audited refusal mentioning %q", name, c.reason)
		}
	}
	if logged := h.logs.String(); strings.Count(logged, "a Slack install callback was refused") < 7 {
		t.Errorf("refusals logged = %d, want one per refusal:\n%s", strings.Count(logged, "a Slack install callback was refused"), logged)
	}

	// Slack handing back no token is logged and audited too, without the code.
	h.slack.Install(credential.AppID, acmeTeam)
	if got := call(url.Values{"code": {"not-a-code"}, "state": {state}}, cookie); got != http.StatusConflict {
		t.Fatalf("an unknown code = %d", got)
	}
	found := false
	for _, rec := range h.recorded.Find("roster.slack_workspace.connect_refused") {
		found = found || strings.Contains(rec.GetOutcome().GetReason(), "oauth.v2.access")
	}
	if !found {
		t.Error("a failed code exchange was not audited")
	}
	if strings.Contains(h.logs.String(), "not-a-code") || strings.Contains(h.logs.String(), code) {
		t.Error("a code is in the logs")
	}
}

// What the controller reports is shown only to those who may view the
// workspace, each row saying whether the caller may operate it.
func TestTheStatusShowsEachCallerOnlyTheWorkspacesItMayView(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
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
	h := newConnectedWorkspaceHarness(t)
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
	h := newConnectedWorkspaceHarness(t)
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

// A team id is what Slack says it is, and a log line is read by people who
// trust it: the one a refused install writes must keep a forged record out of
// the log, whatever the id carries.
func TestARefusedInstallCannotForgeALogRecordThroughTheTeamSlackReports(t *testing.T) {
	h := newWorkspaceHarness(t)
	const forged = "T0EVIL\r\nlevel=ERROR msg=forged\tby=root"
	h.slack.AddTeam(forged, "Evil")

	begun, err := h.begin(operator(), "acme", accepted)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.finish(t, begun, "acme", acmeTeam); got.Code != http.StatusFound {
		t.Fatalf("the first install = %d:\n%s", got.Code, got.Body)
	}
	if begun, err = h.begin(operator(), "acme", ""); err != nil {
		t.Fatal(err)
	}
	if got := h.finish(t, begun, "acme", forged); got.Code != http.StatusConflict {
		t.Fatalf("an install into a team that is not the recorded one = %d:\n%s", got.Code, got.Body)
	}
	logged := h.logs.String()
	if !strings.Contains(logged, "a Slack install callback was refused") {
		t.Fatalf("the refusal was not logged:\n%s", logged)
	}
	for _, bad := range []string{"\r", "\t", "\\r", "\\n", "level=ERROR msg=forged"} {
		// The forged text may survive as inert characters inside one quoted
		// value, but never as a record or an escaped line break of its own.
		if bad == "level=ERROR msg=forged" {
			if strings.Contains(logged, "\nlevel=ERROR") || strings.Contains(logged, " level=ERROR msg=forged ") {
				t.Errorf("a forged record in the log:\n%s", logged)
			}
			continue
		}
		if strings.Contains(logged, bad) {
			t.Errorf("the log carries %q:\n%s", bad, logged)
		}
	}
	if !strings.Contains(logged, "T0EVILlevel=ERROR") {
		t.Errorf("the team id was not logged with its line breaks removed:\n%s", logged)
	}
}

// A channel the policy defines in git says which internal groups feed it, so
// the console's channel page can name them. A console or Slack Connect
// channel carries none: its groups are in its own record.
func TestAPolicyChannelNamesItsInternalGroups(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
	h.putReport(t, status.Workspace{
		Workspace: "acme", Enabled: true, Tick: status.Tick{At: time.Now(), Outcome: status.OutcomeInSync},
		Channels: []status.Channel{
			{Name: "infra-alerts", State: status.ChannelOK},
			{Name: "infra-alerts", State: status.ChannelOK, Console: true},
			{Name: "infra-alerts", State: status.ChannelOK, Shared: true, Host: "acme"},
			{Name: "unbound", State: status.ChannelOK},
		},
	})
	got := h.row(viewer(), t, "acme").GetChannels()
	want := [][]string{{"all:platform:engineer"}, nil, nil, nil}
	if len(got) != len(want) {
		t.Fatalf("channels = %+v", got)
	}
	for i, channel := range got {
		if !slices.Equal(channel.GetSources(), want[i]) {
			t.Errorf("channel %d (%s) sources = %v, want %v", i, channel.GetName(), channel.GetSources(), want[i])
		}
	}
}
