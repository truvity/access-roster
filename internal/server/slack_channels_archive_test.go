package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// archiveRig is a harness whose acme workspace is connected to a fake Slack
// that holds one private channel the bot is in and one it is not.
type archiveRig struct {
	*connectHarness
	slack          *slackfake.Slack
	inside, hidden string
}

func newArchiveRig(t *testing.T) *archiveRig {
	t.Helper()
	h := newConnectHarness(t)
	fake := slackfake.New(t)
	fake.AddTeam(acmeTeam, "acme")
	h.console.deps.SlackAPI = []slackapp.Option{slackapp.WithBaseURL(fake.URL())}
	record := connection.Record{
		Workspace: "acme", TeamID: acmeTeam, Owner: "C0north", AppID: "A0acme", BotUserID: slackfake.BotID(acmeTeam),
		AuthorizeURL: "https://slack.com/oauth/v2/authorize?client_id=seeded", ManifestScopes: slices.Clone(connection.BotScopes),
		Scopes: slices.Clone(connection.BotScopes), ConnectedAt: time.Now().UTC(), ConnectedBy: "ada@north.example",
	}
	credential := connection.Credential{Workspace: "acme", AppID: "A0acme", ClientID: "client", ClientSecret: "secret", BotToken: slackfake.Token(acmeTeam)}
	if err := kube.NewSlackWorkspaces(h.client).Put(context.Background(), record, credential); err != nil {
		t.Fatal(err)
	}
	r := &archiveRig{connectHarness: h, slack: fake}
	r.inside = fake.AddChannel(acmeTeam, "eng", true, slackfake.BotID(acmeTeam)).ID
	r.hidden = fake.AddChannel(acmeTeam, "vault", true).ID
	return r
}

func (r *archiveRig) forget(t *testing.T, name string, archive bool) (*directoryrosterv1.DeleteSlackChannelResponse, error) {
	t.Helper()
	if err := r.createChannel(as(northOp), func() *directoryrosterv1.SlackChannelDefinition {
		d := chdef("acme", name, "partners@north.example")
		d.Private = true
		return d
	}()); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	request := &directoryrosterv1.DeleteSlackChannelRequest{Workspace: "acme", Name: name, Archive: archive}
	got, err := r.console.DeleteSlackChannel(as(northOp), connect.NewRequest(request))
	if err != nil {
		return nil, err
	}
	return got.Msg, nil
}

func TestForgettingAChannelArchivesItOnlyWhenAskedTo(t *testing.T) {
	r := newArchiveRig(t)
	r.reportOrdinary(t, "acme", []status.Channel{{Name: "eng", ID: r.inside, Console: true, Private: true, State: status.ChannelOK}})

	got, err := r.forget(t, "eng", false)
	if err != nil || got.GetArchived() || r.slack.Count("conversations.archive") != 0 || r.slack.Channel(r.inside).Archived {
		t.Fatalf("without the opt-in: %v %+v, archive calls %d", err, got, r.slack.Count("conversations.archive"))
	}
	if n := len(r.recorded.Find("roster.slack_channel.archived")); n != 0 {
		t.Errorf("%d archive records without the opt-in", n)
	}

	got, err = r.forget(t, "eng", true)
	if err != nil || !got.GetArchived() || !strings.Contains(got.GetNote(), "archived in Slack") {
		t.Fatalf("with the opt-in: %v %+v", err, got)
	}
	if !r.slack.Channel(r.inside).Archived || r.slack.Count("conversations.archive") != 1 {
		t.Error("the channel was not archived once")
	}
	if len(r.storedChannels(t)) != 0 {
		t.Error("the record is still kept")
	}
	found := r.recorded.Find("roster.slack_channel.archived")
	if len(found) != 1 || found[0].GetOutcome().GetResult().String() != "RESULT_SUCCESS" || found[0].GetTargets()[1].GetId() != "acme/eng" {
		t.Fatalf("archive records = %v", found)
	}
}

func TestAChannelTheBotIsNotInIsForgottenAndLeftForYouToArchive(t *testing.T) {
	r := newArchiveRig(t)
	r.reportOrdinary(t, "acme", []status.Channel{{Name: "vault", ID: r.hidden, Console: true, Private: true, State: status.ChannelOK}})

	got, err := r.forget(t, "vault", true)
	if err != nil || got.GetArchived() || !strings.Contains(got.GetNote(), "Archive it in Slack by hand") {
		t.Fatalf("got %+v, %v", got, err)
	}
	if len(r.storedChannels(t)) != 0 {
		t.Error("the record was not deleted")
	}
	if r.slack.Channel(r.hidden).Archived {
		t.Error("the channel was archived")
	}
	found := r.recorded.Find("roster.slack_channel.archived")
	if len(found) != 1 || found[0].GetOutcome().GetResult().String() == "RESULT_SUCCESS" {
		t.Errorf("want one failed archive record, got %v", found)
	}
}

func TestASlackConnectChannelIsNeverArchivedFromTheConsole(t *testing.T) {
	r := newArchiveRig(t)
	r.reportOrdinary(t, "acme", []status.Channel{{Name: "eng", ID: r.inside, Console: true, Shared: true, Host: "globex", State: status.ChannelOK}})
	if err := r.createChannel(as(northOp), chdef("acme", "eng", "partners@north.example")); err != nil {
		t.Fatal(err)
	}

	request := &directoryrosterv1.DeleteSlackChannelRequest{Workspace: "acme", Name: "eng", Archive: true}
	_, err := r.console.DeleteSlackChannel(as(northOp), connect.NewRequest(request))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "Slack Connect") {
		t.Fatalf("err = %v", err)
	}
	if r.slack.Count("conversations.archive") != 0 || len(r.storedChannels(t)) != 1 {
		t.Error("a refused request changed something")
	}
	// Forgetting the record without archiving is still allowed.
	if _, err = r.deleteChannel(as(northOp), "acme", "eng"); err != nil {
		t.Errorf("plain delete: %v", err)
	}
}
