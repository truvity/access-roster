package slackapp_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
)

// world is two workspaces, acme and globex, each with its bot.
type world struct {
	fake         *slackfake.Slack
	acme, globex *slackapp.Client
	slept        []time.Duration
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{fake: slackfake.New(t)}
	w.fake.AddTeam("TACME", "acme")
	w.fake.AddTeam("TGLOBEX", "globex")
	sleep := func(_ context.Context, d time.Duration) error { w.slept = append(w.slept, d); return nil }
	opts := []slackapp.Option{slackapp.WithBaseURL(w.fake.URL()), slackapp.WithPageSize(2), slackapp.WithSleep(sleep)}
	w.acme = slackapp.New(slackfake.Token("TACME"), opts...)
	w.globex = slackapp.New(slackfake.Token("TGLOBEX"), opts...)
	return w
}

func TestAuthTestNamesTheWorkspace(t *testing.T) {
	w := newWorld(t)
	id, err := w.acme.AuthTest(context.Background())
	if err != nil || id.TeamID != "TACME" || id.UserID != slackfake.BotID("TACME") {
		t.Fatalf("got %+v, %v", id, err)
	}
	bad := slackapp.New("fake-wrong-token", slackapp.WithBaseURL(w.fake.URL()))
	if _, err := bad.AuthTest(context.Background()); !errors.Is(err, slackapp.ErrInvalidAuth) {
		t.Fatalf("err = %v, want invalid_auth", err)
	}
}

func TestLookupByEmail(t *testing.T) {
	w := newWorld(t)
	ann := w.fake.AddUser("TACME", "ann@acme.example")
	w.fake.Users[ann.ID].Guest = true
	tests := []struct {
		name, email string
		found, gst  bool
	}{
		{"member", "ann@acme.example", true, true},
		{"case-insensitive", "ANN@acme.example", true, true},
		{"no account is not an error", "nobody@acme.example", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, found, err := w.acme.LookupByEmail(context.Background(), tc.email)
			if err != nil || found != tc.found || u.IsGuest() != tc.gst {
				t.Fatalf("got %+v found=%v err=%v", u, found, err)
			}
		})
	}
	if _, _, err := w.globex.LookupByEmail(context.Background(), "ann@acme.example"); err != nil {
		t.Fatalf("other workspace: %v", err)
	}
	w.fake.Fail("users.lookupByEmail", "missing_scope", 1)
	if _, _, err := w.acme.LookupByEmail(context.Background(), "ann@acme.example"); !errors.Is(err, slackapp.ErrMissingScope) {
		t.Fatalf("err = %v", err)
	}
}

func TestUserInfoReadsTheAddress(t *testing.T) {
	w := newWorld(t)
	ann := w.fake.AddUser("TACME", "ann@acme.example")
	got, err := w.acme.UserInfo(context.Background(), ann.ID)
	if err != nil || got.Email() != "ann@acme.example" || got.IsAutomated() {
		t.Fatalf("got %+v err=%v", got, err)
	}
	bot, err := w.acme.UserInfo(context.Background(), slackfake.BotID("TACME"))
	if err != nil || !bot.IsAutomated() || bot.Email() != "" {
		t.Fatalf("bot %+v err=%v", bot, err)
	}
	if _, err := w.acme.UserInfo(context.Background(), "UNOBODY"); !errors.Is(err, slackapp.ErrUserNotFound) {
		t.Fatalf("unknown id: err = %v", err)
	}
	w.fake.Fail("users.info", "missing_scope", 1)
	if _, err := w.acme.UserInfo(context.Background(), ann.ID); !errors.Is(err, slackapp.ErrMissingScope) {
		t.Fatalf("missing scope: err = %v", err)
	}
}

func TestChannelsPaginateAndSkipArchivedAndForeignPrivate(t *testing.T) {
	w := newWorld(t)
	for i := range 5 {
		w.fake.AddChannel("TACME", fmt.Sprintf("pub-%d", i), false)
	}
	w.fake.AddChannel("TACME", "secret-mine", true, slackfake.BotID("TACME"))
	w.fake.AddChannel("TACME", "secret-other", true)
	old := w.fake.AddChannel("TACME", "old", false)
	w.fake.Channels[old.ID].Archived = true
	got, err := w.acme.Channels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	slices.Sort(names)
	want := []string{"general", "pub-0", "pub-1", "pub-2", "pub-3", "pub-4", "secret-mine"}
	if !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if n := w.fake.Count("conversations.list"); n != 4 {
		t.Errorf("pages = %d, want 4 (7 channels, 2 per page)", n)
	}
}

func TestMembersPaginateAndInfo(t *testing.T) {
	w := newWorld(t)
	var ids []string
	for i := range 5 {
		ids = append(ids, w.fake.AddUser("TACME", fmt.Sprintf("u%d@acme.example", i)).ID)
	}
	ch := w.fake.AddChannel("TACME", "team", false, ids...)
	got, err := w.acme.Members(context.Background(), ch.ID)
	if err != nil || !slices.Equal(got, ids) {
		t.Fatalf("members = %v, %v", got, err)
	}
	info, err := w.acme.ChannelInfo(context.Background(), ch.ID)
	if err != nil || info.Name != "team" || info.IsMember {
		t.Fatalf("info = %+v, %v", info, err)
	}
	if _, err := w.acme.ChannelInfo(context.Background(), "CNOPE"); !errors.Is(err, slackapp.ErrChannelNotFound) {
		t.Fatalf("err = %v", err)
	}
	secret := w.fake.AddChannel("TACME", "secret", true)
	if _, err := w.acme.Members(context.Background(), secret.ID); !errors.Is(err, slackapp.ErrChannelNotFound) {
		t.Fatalf("a private channel the bot is not in: err = %v", err)
	}
}

func TestCreateJoinAndNameTaken(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	c, err := w.acme.CreateChannel(ctx, "project", true)
	if err != nil || !c.IsPrivate || !c.IsMember {
		t.Fatalf("create = %+v, %v", c, err)
	}
	if _, err := w.acme.CreateChannel(ctx, "project", false); !errors.Is(err, slackapp.ErrNameTaken) {
		t.Fatalf("err = %v, want name_taken", err)
	}
	pub := w.fake.AddChannel("TACME", "open", false)
	joined, err := w.acme.JoinChannel(ctx, pub.ID)
	if err != nil || !joined.IsMember {
		t.Fatalf("join = %+v, %v", joined, err)
	}
	priv := w.fake.AddChannel("TACME", "closed", true)
	if _, err := w.acme.JoinChannel(ctx, priv.ID); !errors.Is(err, slackapp.ErrChannelNotFound) {
		t.Fatalf("joining private: %v", err)
	}
}

func TestInvite(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	bot := slackfake.BotID("TACME")
	a := w.fake.AddUser("TACME", "a@acme.example").ID
	b := w.fake.AddUser("TACME", "b@acme.example").ID
	c := w.fake.AddUser("TACME", "c@acme.example").ID
	foreign := w.fake.AddUser("TGLOBEX", "f@globex.example").ID

	ch := w.fake.AddChannel("TACME", "team", true, bot)
	if err := w.acme.Invite(ctx, ch.ID, []string{a, b}); err != nil {
		t.Fatal(err)
	}
	// One already in: the batch is refused, the rest still land.
	if err := w.acme.Invite(ctx, ch.ID, []string{a, c}); err != nil {
		t.Fatalf("already_in_channel must be success: %v", err)
	}
	if err := w.acme.Invite(ctx, ch.ID, []string{a}); err != nil {
		t.Fatalf("single already in: %v", err)
	}
	if got := w.fake.Members(ch.ID); !slices.Equal(got, []string{bot, a, b, c}) {
		t.Fatalf("members = %v", got)
	}
	if err := w.acme.Invite(ctx, ch.ID, []string{foreign}); !errors.Is(err, slackapp.ErrUserNotFound) {
		t.Fatalf("foreign user: %v", err)
	}
	// Not a member of the private channel: Slack says it does not exist.
	other := w.fake.AddChannel("TACME", "hidden", true)
	if err := w.acme.Invite(ctx, other.ID, []string{a}); !errors.Is(err, slackapp.ErrChannelNotFound) {
		t.Fatalf("outsider: %v", err)
	}
	// A public channel the bot has not joined.
	open := w.fake.AddChannel("TACME", "open", false)
	if err := w.acme.Invite(ctx, open.ID, []string{a}); !errors.Is(err, slackapp.ErrNotInChannel) {
		t.Fatalf("public non-member: %v", err)
	}
	// Batching: more than the limit is split.
	var many []string
	for i := range slackapp.InviteLimit + 1 {
		many = append(many, w.fake.AddUser("TACME", fmt.Sprintf("m%d@acme.example", i)).ID)
	}
	big := w.fake.AddChannel("TACME", "big", true, bot)
	before := w.fake.Count("conversations.invite")
	if err := w.acme.Invite(ctx, big.ID, many); err != nil {
		t.Fatal(err)
	}
	if n := w.fake.Count("conversations.invite") - before; n != 2 {
		t.Errorf("calls = %d, want 2 batches", n)
	}
	if len(w.fake.Members(big.ID)) != len(many)+1 {
		t.Errorf("members = %d", len(w.fake.Members(big.ID)))
	}
}

func TestKick(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	bot := slackfake.BotID("TACME")
	u := w.fake.AddUser("TACME", "u@acme.example").ID
	private := w.fake.AddChannel("TACME", "private", true, bot, u)
	public := w.fake.AddChannel("TACME", "public", false, bot, u)
	general, _ := w.fake.ChannelNamed("TACME", "general")
	hidden := w.fake.AddChannel("TACME", "hidden", true, u)

	tests := []struct {
		name    string
		channel string
		user    string
		want    error
	}{
		{"private channel", private.ID, u, nil},
		{"already gone is success", private.ID, u, nil},
		{"public is restricted", public.ID, u, slackapp.ErrRestricted},
		{"general", general.ID, u, slackapp.ErrCantKickFromGeneral},
		{"self", private.ID, bot, slackapp.ErrCantKickSelf},
		{"not a member of the channel", hidden.ID, u, slackapp.ErrChannelNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := w.acme.Kick(ctx, tc.channel, tc.user)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if slices.Contains(w.fake.Members(private.ID), u) {
		t.Error("user still in the private channel")
	}
	if !slices.Contains(w.fake.Members(public.ID), u) {
		t.Error("user was removed from a public channel")
	}
}

func TestInjectedFailuresAreTypedAndCarryTheMethod(t *testing.T) {
	w := newWorld(t)
	w.fake.Fail("conversations.create", "restricted_action", 1)
	_, err := w.acme.CreateChannel(context.Background(), "x", false)
	var api *slackapp.APIError
	if !errors.As(err, &api) || api.Method != "conversations.create" || api.Code != "restricted_action" {
		t.Fatalf("err = %#v", err)
	}
	if errors.Is(err, slackapp.ErrNameTaken) {
		t.Error("matched the wrong code")
	}
	if _, err := w.acme.CreateChannel(context.Background(), "x", false); err != nil {
		t.Fatalf("the failure was for one call: %v", err)
	}
}

func TestRateLimit(t *testing.T) {
	t.Run("retry then success", func(t *testing.T) {
		w := newWorld(t)
		w.fake.RateLimit("auth.test", "7", 2)
		if _, err := w.acme.AuthTest(context.Background()); err != nil {
			t.Fatal(err)
		}
		if want := []time.Duration{7 * time.Second, 7 * time.Second}; !slices.Equal(w.slept, want) {
			t.Fatalf("waits = %v, want %v", w.slept, want)
		}
		if n := w.fake.Count("auth.test"); n != 3 {
			t.Errorf("calls = %d", n)
		}
	})
	t.Run("exhaustion", func(t *testing.T) {
		w := newWorld(t)
		w.fake.RateLimit("auth.test", "3", -1)
		_, err := w.acme.AuthTest(context.Background())
		var rl *slackapp.RateLimitError
		if !errors.Is(err, slackapp.ErrRateLimited) || !errors.As(err, &rl) || rl.RetryAfter != 3*time.Second {
			t.Fatalf("err = %v", err)
		}
		if n := w.fake.Count("auth.test"); n != slackapp.DefaultRetries+1 {
			t.Errorf("calls = %d", n)
		}
	})
	t.Run("ratelimited body is the same", func(t *testing.T) {
		w := newWorld(t)
		w.fake.Fail("auth.test", "ratelimited", 1)
		if _, err := w.acme.AuthTest(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(w.slept) != 1 {
			t.Errorf("waits = %v", w.slept)
		}
	})
	t.Run("the wait ends with the context", func(t *testing.T) {
		w := newWorld(t)
		w.fake.RateLimit("auth.test", "50", -1)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		c := slackapp.New(slackfake.Token("TACME"), slackapp.WithBaseURL(w.fake.URL()))
		start := time.Now()
		_, err := c.AuthTest(ctx)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Fatalf("err = %v after %s", err, time.Since(start))
		}
	})
}

func TestTheTokenIsNotInErrorsOrLogs(t *testing.T) {
	w := newWorld(t)
	token := slackfake.Token("TACME")
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()
	w.fake.Fail("conversations.create", "name_taken", 1)
	w.fake.RateLimit("auth.test", "1", -1)
	_, e1 := w.acme.CreateChannel(ctx, "x", false)
	_, e2 := w.acme.AuthTest(ctx)
	dead := slackapp.New(token, slackapp.WithBaseURL("http://127.0.0.1:1"))
	_, e3 := dead.AuthTest(ctx)
	_, e4 := slackapp.New(token, slackapp.WithBaseURL(w.fake.URL()+"/nope")).AuthTest(ctx)
	for _, err := range []error{e1, e2, e3, e4} {
		if err == nil {
			t.Fatal("expected an error")
		}
		log.Error("call failed", "err", err)
		if strings.Contains(err.Error(), token) {
			t.Errorf("token in %q", err)
		}
	}
	if strings.Contains(logs.String(), token) {
		t.Error("token in logs")
	}
	for _, call := range w.fake.Calls() {
		for _, v := range call.Params {
			if slices.Contains(v, token) {
				t.Error("token sent as a parameter")
			}
		}
	}
}

func TestSlackConnectHandshake(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	ann := w.fake.AddUser("TACME", "ann@acme.example").ID
	bob := w.fake.AddUser("TGLOBEX", "bob@globex.example").ID

	ch, err := w.acme.CreateChannel(ctx, "shared-work", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.acme.Invite(ctx, ch.ID, []string{ann}); err != nil {
		t.Fatal(err)
	}
	// Host invites the other workspace's bot by user id.
	inviteID, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{UserID: slackfake.BotID("TGLOBEX")}, true)
	if err != nil || inviteID == "" {
		t.Fatalf("inviteShared = %q, %v", inviteID, err)
	}
	out, err := w.acme.ConnectInvites(ctx)
	if err != nil || len(out) != 1 || out[0].Direction != "outgoing" {
		t.Fatalf("host sees %+v, %v", out, err)
	}
	in, err := w.globex.ConnectInvites(ctx)
	if err != nil || len(in) != 1 || in[0].Direction != "incoming" || in[0].Invite.ID != inviteID ||
		in[0].Channel.Name != "shared-work" || in[0].Invite.InvitingTeam.ID != "TACME" {
		t.Fatalf("guest sees %+v, %v", in, err)
	}
	// Only the addressed workspace can accept.
	w.fake.AddTeam("TINITECH", "initech")
	stranger := slackapp.New(slackfake.Token("TINITECH"), slackapp.WithBaseURL(w.fake.URL()))
	if _, err := stranger.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: inviteID, ChannelName: "x"}); err == nil {
		t.Fatal("a stranger accepted")
	}
	// Name clash, then the real accept.
	w.fake.AddChannel("TGLOBEX", "shared-work", false)
	if _, err := w.globex.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: inviteID, ChannelName: "shared-work"}); !errors.Is(err, slackapp.ErrNameTaken) {
		t.Fatalf("clash: %v", err)
	}
	channelID, err := w.globex.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: inviteID, ChannelName: "from-acme", IsPrivate: true})
	if err != nil || channelID != ch.ID {
		t.Fatalf("accept = %q, %v", channelID, err)
	}
	if _, err := w.globex.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: inviteID, ChannelName: "again"}); err == nil {
		t.Fatal("accepted twice")
	}
	// Both sides see the channel, under their own names, as shared.
	for name, c := range map[string]*slackapp.Client{"shared-work": w.acme, "from-acme": w.globex} {
		list, err := c.Channels(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ch := range list {
			if ch.Name == name && ch.IsExtShared {
				found = slices.Equal(ch.SharedTeamIDs, []string{"TACME", "TGLOBEX"})
			}
		}
		if !found {
			t.Errorf("%s does not list %q as shared: %+v", name, name, list)
		}
	}
	// Pending invites are gone on both sides.
	if out, _ := w.acme.ConnectInvites(ctx); len(out) != 0 {
		t.Errorf("host still sees %+v", out)
	}
	// Inviting the same workspace again is refused.
	if _, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{UserID: bob}, true); !errors.Is(err, slackapp.ErrAlreadyInChannel) {
		t.Fatalf("re-invite: %v", err)
	}
}

func TestInviteSharedTargets(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.fake.AddUser("TGLOBEX", "bob@globex.example")
	ch, _ := w.acme.CreateChannel(ctx, "c", false)
	if _, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{}, true); err == nil {
		t.Error("no target accepted")
	}
	if _, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{Email: "a@x.example", UserID: "U1"}, true); err == nil {
		t.Error("two targets accepted")
	}
	_, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{Email: "not-an-address"}, true)
	if !errors.Is(err, &slackapp.APIError{Code: "invalid_email"}) {
		t.Errorf("bad address: %v", err)
	}
	id, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{Email: "bob@globex.example"}, false)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := w.globex.ConnectInvites(ctx)
	if len(in) != 1 || in[0].Invite.ID != id {
		t.Fatalf("by address, globex sees %+v", in)
	}
	calls := w.fake.Calls()
	last := calls[len(calls)-2] // the invite before the listing
	if last.Params.Get("external_limited") != "false" || last.Params.Get("emails") != "bob@globex.example" {
		t.Errorf("params = %v", last.Params)
	}
}

func TestConnectInvitesPaginate(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	for i := range 5 {
		ch, _ := w.acme.CreateChannel(ctx, fmt.Sprintf("c%d", i), false)
		if _, err := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{UserID: slackfake.BotID("TGLOBEX")}, true); err != nil {
			t.Fatal(err)
		}
	}
	in, err := w.globex.ConnectInvites(ctx)
	if err != nil || len(in) != 5 || w.fake.Count("conversations.listConnectInvites") != 3 {
		t.Fatalf("got %d invites in %d pages, %v", len(in), w.fake.Count("conversations.listConnectInvites"), err)
	}
}

func TestAcceptNeedsAPaidPlanOrTheTrial(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.fake.Teams["TGLOBEX"].Paid = false
	ch, _ := w.acme.CreateChannel(ctx, "c", false)
	id, _ := w.acme.InviteShared(ctx, ch.ID, slackapp.ConnectTarget{UserID: slackfake.BotID("TGLOBEX")}, true)
	if _, err := w.globex.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: id, ChannelName: "c"}); !errors.Is(err, &slackapp.APIError{Code: "not_paid"}) {
		t.Fatalf("err = %v", err)
	}
	if _, err := w.globex.AcceptSharedInvite(ctx, slackapp.AcceptParams{InviteID: id, ChannelName: "c", FreeTrialAccepted: true}); err != nil {
		t.Fatal(err)
	}
}

const manifest = `{"display_information":{"name":"acme-access-roster"},"oauth_config":{"scopes":{"bot":["channels:read","groups:write"]}}}`

func TestAppSetupFlow(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	setup := slackapp.NewSetup(slackapp.WithBaseURL(w.fake.URL()))

	if _, err := setup.CreateApp(ctx, "fake-wrong", manifest); !errors.Is(err, slackapp.ErrInvalidAuth) {
		t.Fatalf("wrong config token: %v", err)
	}
	_, err := setup.CreateApp(ctx, slackfake.ConfigToken, "{not json")
	var api *slackapp.APIError
	if !errors.As(err, &api) || api.Code != "invalid_manifest" || len(api.Details) != 1 || !strings.Contains(api.Details[0], "not valid JSON") {
		t.Fatalf("invalid manifest: %#v", err)
	}
	app, err := setup.CreateApp(ctx, slackfake.ConfigToken, manifest)
	if err != nil || app.AppID == "" || app.Credentials.ClientID == "" || app.Credentials.ClientSecret == "" ||
		app.Credentials.SigningSecret == "" || !strings.Contains(app.OAuthAuthorizeURL, app.Credentials.ClientID) {
		t.Fatalf("create = %+v, %v", app, err)
	}

	code := w.fake.Install(app.AppID, "TACME")
	_, err = setup.OAuthAccess(ctx, app.Credentials.ClientID, "fake-wrong", code, "https://console.example/cb")
	if !errors.Is(err, &slackapp.APIError{Code: "bad_client_secret"}) {
		t.Fatalf("bad secret: %v", err)
	}
	inst, err := setup.OAuthAccess(ctx, app.Credentials.ClientID, app.Credentials.ClientSecret, code, "https://console.example/cb")
	if err != nil {
		t.Fatal(err)
	}
	if inst.BotToken != slackfake.Token("TACME") || inst.TeamID != "TACME" || inst.TeamName != "acme" ||
		inst.BotUserID != slackfake.BotID("TACME") || inst.Scope != "channels:read,groups:write" {
		t.Fatalf("installation = %+v", inst)
	}
	_, err = setup.OAuthAccess(ctx, app.Credentials.ClientID, app.Credentials.ClientSecret, code, "")
	if !errors.Is(err, &slackapp.APIError{Code: "invalid_code"}) {
		t.Fatalf("a code works once: %v", err)
	}
	// The token it returns works as the workspace's bot.
	id, err := slackapp.New(inst.BotToken, slackapp.WithBaseURL(w.fake.URL())).AuthTest(ctx)
	if err != nil || id.TeamID != "TACME" {
		t.Fatalf("auth.test with the new token: %+v, %v", id, err)
	}

	// A later release wants another scope.
	required := []string{"channels:read", "groups:write", "conversations.connect:write"}
	missing := slackapp.MissingScopes(inst.Scope, required)
	if !slices.Equal(missing, []string{"conversations.connect:write"}) {
		t.Fatalf("missing = %v", missing)
	}
	updated := strings.Replace(manifest, `"groups:write"`, `"groups:write","conversations.connect:write"`, 1)
	changed, err := setup.UpdateApp(ctx, slackfake.ConfigToken, app.AppID, updated)
	if err != nil || !changed {
		t.Fatalf("update = %v, %v", changed, err)
	}
	if changed, err := setup.UpdateApp(ctx, slackfake.ConfigToken, app.AppID, updated); err != nil || changed {
		t.Fatalf("idempotent update = %v, %v", changed, err)
	}
	if _, err := setup.UpdateApp(ctx, slackfake.ConfigToken, "ANOPE", updated); !errors.Is(err, &slackapp.APIError{Code: "app_not_found"}) {
		t.Fatalf("unknown app: %v", err)
	}
	// Secrets are not recorded by the fake's call log either.
	for _, call := range w.fake.Calls() {
		if call.Params.Get("client_secret") != "" {
			t.Error("client secret sent as a form field")
		}
	}
}

func TestMissingScopes(t *testing.T) {
	tests := []struct {
		granted  string
		required []string
		want     []string
	}{
		{"a,b,c", []string{"a", "c"}, nil},
		{"a,b", []string{"c", "a", "d"}, []string{"c", "d"}},
		{"", []string{"a"}, []string{"a"}},
		{"a, b", []string{"b"}, nil},
		{"a", nil, nil},
	}
	for _, tc := range tests {
		if got := slackapp.MissingScopes(tc.granted, tc.required); !slices.Equal(got, tc.want) {
			t.Errorf("MissingScopes(%q, %v) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}
