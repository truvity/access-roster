package server

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

func chdef(workspace, name string, sources ...string) *directoryrosterv1.SlackChannelDefinition {
	return &directoryrosterv1.SlackChannelDefinition{Workspace: workspace, Name: name, Sources: sources}
}

func withMode(d *directoryrosterv1.SlackChannelDefinition, mode string) *directoryrosterv1.SlackChannelDefinition {
	d.Mode = mode
	return d
}

func withID(d *directoryrosterv1.SlackChannelDefinition, id string) *directoryrosterv1.SlackChannelDefinition {
	d.ChannelId = id
	return d
}

func (h *connectHarness) createChannel(ctx context.Context, d *directoryrosterv1.SlackChannelDefinition) error {
	_, err := h.console.CreateSlackChannel(ctx, connect.NewRequest(&directoryrosterv1.CreateSlackChannelRequest{Channel: d}))
	return err
}

func (h *connectHarness) updateChannel(ctx context.Context, d *directoryrosterv1.SlackChannelDefinition) error {
	_, err := h.console.UpdateSlackChannel(ctx, connect.NewRequest(&directoryrosterv1.UpdateSlackChannelRequest{Channel: d}))
	return err
}

func (h *connectHarness) deleteChannel(ctx context.Context, workspace, name string) (string, error) {
	got, err := h.console.DeleteSlackChannel(ctx, connect.NewRequest(&directoryrosterv1.DeleteSlackChannelRequest{Workspace: workspace, Name: name}))
	if err != nil {
		return "", err
	}
	return got.Msg.GetNote(), nil
}

func (h *connectHarness) listChannels(ctx context.Context, t *testing.T) *directoryrosterv1.ListSlackChannelsResponse {
	t.Helper()
	got, err := h.console.ListSlackChannels(ctx, connect.NewRequest(&directoryrosterv1.ListSlackChannelsRequest{}))
	if err != nil {
		t.Fatalf("ListSlackChannels: %v", err)
	}
	return got.Msg
}

func (h *connectHarness) storedChannels(t *testing.T) map[string]string {
	t.Helper()
	cm, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), "access-issuer-slack-workspaces", metav1.GetOptions{})
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for key, doc := range cm.Data {
		if _, _, ok := connection.ParseConsoleKey(key); ok {
			out[key] = doc
		}
	}
	return out
}

// reportOrdinary is a workspace's report listing the channels its bot sees.
func (h *connectHarness) reportOrdinary(t *testing.T, workspace string, channels []status.Channel, found ...status.Discovered) {
	t.Helper()
	raw, err := status.Encode(status.Workspace{Version: status.Version, Workspace: workspace, Enabled: true, Channels: channels, Discovered: found})
	if err != nil {
		t.Fatal(err)
	}
	h.reports[status.Key(workspace)] = raw
}

func TestAConsoleChannelIsCreatedEditedAndDeleted(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(northOp)

	want := chdef("acme", "eng", "partners@north.example")
	want.Private, want.Mode = true, "strict"
	if err := h.createChannel(ctx, want); err != nil {
		t.Fatalf("create: %v", err)
	}
	// What is kept is the versioned record the controller reads, with who and when.
	doc, ok := h.storedChannels(t)[connection.ConsoleKey("acme", "eng")]
	if !ok {
		t.Fatalf("no record kept: %v", h.storedChannels(t))
	}
	kept, err := connection.DecodeConsole(doc)
	if err != nil || kept.Workspace != "acme" || kept.Name != "eng" || !kept.Private || kept.Mode != "strict" ||
		!slices.Equal(kept.Sources, []string{"partners@north.example"}) || kept.CreatedBy != "someone@north.example" || kept.CreatedAt.IsZero() {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	if err = kept.Validate(h.console.deps.Authorizer.Policy().Declared()); err != nil {
		t.Errorf("the controller would refuse what was kept: %v", err)
	}
	// It is in the recovery copy beside the workspaces' records.
	secret, err := h.client.API().CoreV1().Secrets("access-issuer").Get(context.Background(), "access-issuer-slack-records", metav1.GetOptions{})
	if err != nil || len(secret.Data[connection.ConsoleKey("acme", "eng")]) == 0 {
		t.Errorf("the record is not mirrored: %v %v", secret, err)
	}

	// Edit mode and sources, and the ignore list.
	edited := chdef("acme", "eng", "partners@north.example", "devops@north.example")
	edited.Private, edited.Mode, edited.Ignore = true, "strict", []string{"boss@north.example"}
	if err = h.updateChannel(ctx, edited); err != nil {
		t.Fatalf("update: %v", err)
	}
	listed := h.listChannels(ctx, t)
	if len(listed.Channels) != 1 {
		t.Fatalf("listed %v", listed.Channels)
	}
	got := listed.Channels[0]
	if !got.CanOperate || got.State != sharedNotReported || len(got.Channel.Sources) != 2 || got.Channel.Mode != "strict" ||
		got.Channel.Ignore[0] != "boss@north.example" || got.CreatedBy == "" || got.UpdatedBy == "" || got.CreatedAt == nil {
		t.Errorf("listed = %+v", got)
	}
	// ... and back to extend, which the record stores as nothing.
	back := chdef("acme", "eng", "partners@north.example")
	back.Private = true
	if err = h.updateChannel(ctx, back); err != nil {
		t.Fatalf("update to extend: %v", err)
	}
	if strings.Contains(h.storedChannels(t)[connection.ConsoleKey("acme", "eng")], `"mode"`) {
		t.Errorf("extend is stored: %v", h.storedChannels(t))
	}

	note, err := h.deleteChannel(ctx, "acme", "eng")
	if err != nil || !strings.Contains(note, "stays in Slack") {
		t.Errorf("delete = %q, %v", note, err)
	}
	if len(h.storedChannels(t)) != 0 {
		t.Error("the record is still kept")
	}

	// Every change is on the trail, by the person, with the workspace, the
	// channel and each directory group that feeds it as targets, and never an
	// address as data.
	for _, action := range []string{"roster.slack_console_channel.created", "roster.slack_console_channel.updated", "roster.slack_console_channel.deleted"} {
		found := h.recorded.Find(action)
		if action == "roster.slack_console_channel.updated" {
			if len(found) != 2 {
				t.Fatalf("%s: %d records", action, len(found))
			}
		} else if len(found) != 1 {
			t.Fatalf("%s: %d records", action, len(found))
		}
		rec := found[0]
		targets := rec.GetTargets()
		if len(targets) < 3 || targets[0].GetId() != "acme" || targets[1].GetId() != "acme/eng" ||
			targets[2].GetType() != "directory_group" || !strings.HasSuffix(targets[2].GetId(), "@north.example") {
			t.Errorf("%s targets = %v", action, targets)
		}
		if rec.GetActor().GetId() == "" {
			t.Errorf("%s has no actor", action)
		}
		for name, v := range rec.GetData().AsMap() {
			if s, _ := v.(string); strings.Contains(s, "@") {
				t.Errorf("%s carries an address in data.%s: %q", action, name, s)
			}
		}
	}
	changes, _ := h.recorded.Find("roster.slack_console_channel.updated")[0].GetData().AsMap()["changes"].(string)
	for _, part := range []string{"sources: 1 -> 2 groups (1 added, 0 removed)", "ignore: 0 -> 1 entries"} {
		if !strings.Contains(changes, part) {
			t.Errorf("changes = %q, missing %q", changes, part)
		}
	}
	if strings.Contains(changes, "boss@") {
		t.Errorf("the ignore list is written out: %q", changes)
	}
	// An edit that changes nothing records nothing new.
	if err = h.createChannel(ctx, back); err != nil {
		t.Fatal(err)
	}
	n := len(h.recorded.Find("roster.slack_console_channel.updated"))
	if err = h.updateChannel(ctx, back); err != nil {
		t.Fatal(err)
	}
	if got := len(h.recorded.Find("roster.slack_console_channel.updated")); got != n {
		t.Errorf("a no-op edit was recorded: %d -> %d", n, got)
	}
}

func TestAConsoleChannelIsRefusedWhenItDoesNotValidate(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	strict := func(d *directoryrosterv1.SlackChannelDefinition) *directoryrosterv1.SlackChannelDefinition {
		d.Mode = "strict"
		return d
	}
	ignored := chdef("acme", "x", "partners@north.example")
	ignored.Ignore = []string{"a@north.example"}
	for _, c := range []struct {
		name string
		def  *directoryrosterv1.SlackChannelDefinition
		code connect.Code
		say  string
	}{
		{"a bad name", chdef("acme", "Not A Name", "partners@north.example"), connect.CodeInvalidArgument, "channel name"},
		{"an undeclared workspace", chdef("nowhere", "x", "partners@north.example"), connect.CodeInvalidArgument, "not a declared workspace"},
		{"no source", chdef("acme", "x"), connect.CodeInvalidArgument, "no directory group"},
		{"an internal group as the source", chdef("acme", "x", "all:partners"), connect.CodeInvalidArgument, "not a directory group address"},
		{"a source no directory holds", chdef("acme", "x", "nobody@north.example"), connect.CodeInvalidArgument, "not a group of a connected directory"},
		{"a source of a domain nobody serves", chdef("acme", "x", "x@nowhere.example"), connect.CodeInvalidArgument, "not a group of a connected directory"},
		{"another directory's group on an ordinary channel", chdef("acme", "x", "eng@south.example"), connect.CodeInvalidArgument, "another directory"},
		{"a policy channel's name", chdef("acme", "general", "partners@north.example"), connect.CodeInvalidArgument, "defined in git"},
		{"strict on a public channel", strict(chdef("acme", "x", "partners@north.example")), connect.CodeInvalidArgument, "private channels only"},
		{"ignore without strict", ignored, connect.CodeInvalidArgument, "only allowed with mode strict"},
		{"a mode that is neither", withMode(chdef("acme", "x", "partners@north.example"), "exact"), connect.CodeInvalidArgument, "neither extend nor strict"},
		{"a workspace with no owning directory", chdef("initech", "x", "partners@north.example"), connect.CodeFailedPrecondition, "no owning directory"},
		{"a channel id nobody discovered", withID(chdef("acme", "x", "partners@north.example"), "C0NEVERSAW"),
			connect.CodeInvalidArgument, "has not been discovered"},
	} {
		err := h.createChannel(ctx, c.def)
		wantCode(t, c.name, err, c.code)
		if c.say != "" && (err == nil || !strings.Contains(err.Error(), c.say)) {
			t.Errorf("%s: the refusal does not say %q: %v", c.name, c.say, err)
		}
	}
	if len(h.storedChannels(t)) != 0 {
		t.Errorf("a refused record was kept: %v", h.storedChannels(t))
	}
	if n := len(h.recorded.Records()); n != 0 {
		t.Errorf("refusals were recorded as changes: %d", n)
	}
	// A name already taken is refused, naming the workspace.
	if err := h.createChannel(ctx, chdef("acme", "eng", "partners@north.example")); err != nil {
		t.Fatal(err)
	}
	err := h.createChannel(ctx, chdef("acme", "eng", "devops@north.example"))
	wantCode(t, "a second record of the same name", err, connect.CodeAlreadyExists)
	// The same name in another workspace is another channel.
	if err = h.createChannel(ctx, chdef("globex", "eng", "eng@south.example")); err != nil {
		t.Errorf("the same name in another workspace: %v", err)
	}
}

// Slack Connect takes groups from any connected directory; an ordinary
// channel only its owner's.
func TestSourceScopeDiffersBetweenOrdinaryAndSharedChannels(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"partners@north.example", "eng@south.example"})); err != nil {
		t.Fatalf("a shared channel fed from both directories: %v", err)
	}
	wantCode(t, "a shared channel fed by an unknown group",
		h.create(ctx, def("other", "acme", []string{"globex"}, []string{"nobody@north.example"})), connect.CodeInvalidArgument)
	wantCode(t, "a shared channel fed by an internal group",
		h.create(ctx, def("third", "acme", []string{"globex"}, []string{"all:partners"})), connect.CodeInvalidArgument)
	if err := h.createChannel(ctx, chdef("globex", "eng", "eng@south.example")); err != nil {
		t.Fatalf("globex's own directory's group: %v", err)
	}
	wantCode(t, "globex fed by acme's directory", h.createChannel(ctx, chdef("globex", "x", "partners@north.example")), connect.CodeInvalidArgument)
}

// One channel is managed one way: not as a console channel and as a Slack
// Connect channel of the same host at once.
func TestAChannelIsManagedOneWay(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	if err := h.createChannel(ctx, chdef("acme", "eng", "partners@north.example")); err != nil {
		t.Fatal(err)
	}
	err := h.create(ctx, def("eng", "acme", []string{"globex"}, []string{"partners@north.example"}))
	wantCode(t, "a shared record over a console channel", err, connect.CodeAlreadyExists)
	if err = h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "a console record over a shared channel", h.createChannel(ctx, chdef("acme", "partners", "partners@north.example")), connect.CodeAlreadyExists)
	// ... but another host's shared channel of that name is another channel.
	if err = h.createChannel(ctx, chdef("globex", "partners", "eng@south.example")); err != nil {
		t.Errorf("a console channel in a workspace that does not host it: %v", err)
	}
}

func TestAConsoleChannelsWorkspaceAndVisibilityAreImmutable(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	d := chdef("acme", "eng", "partners@north.example")
	d.Private = true
	if err := h.createChannel(ctx, d); err != nil {
		t.Fatal(err)
	}
	before := h.storedChannels(t)[connection.ConsoleKey("acme", "eng")]
	flipped := chdef("acme", "eng", "partners@north.example")
	err := h.updateChannel(ctx, flipped)
	wantCode(t, "a change of visibility", err, connect.CodeInvalidArgument)
	if err == nil || !strings.Contains(err.Error(), "create a new record") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
	withID := chdef("acme", "eng", "partners@north.example")
	withID.Private, withID.ChannelId = true, "C0123ABCD"
	wantCode(t, "a change of channel id", h.updateChannel(ctx, withID), connect.CodeInvalidArgument)
	// Another workspace or name is another record: there is none to edit.
	wantCode(t, "an edit in another workspace", h.updateChannel(ctx, chdef("globex", "eng", "eng@south.example")), connect.CodeNotFound)
	wantCode(t, "an edit of another name", h.updateChannel(ctx, chdef("acme", "renamed", "partners@north.example")), connect.CodeNotFound)
	// An edit may not move the channel to another directory's groups.
	moved := chdef("acme", "eng", "eng@south.example")
	moved.Private = true
	wantCode(t, "an edit to another directory's group", h.updateChannel(ctx, moved), connect.CodeInvalidArgument)
	if h.storedChannels(t)[connection.ConsoleKey("acme", "eng")] != before || len(h.recorded.Find("roster.slack_console_channel.updated")) != 0 {
		t.Errorf("a refused edit changed the records or the trail: %v", h.storedChannels(t))
	}
}

func TestWhoMayManageConsoleChannels(t *testing.T) {
	// acme's directory is C0north, globex's C0south, initech has none.
	viewerEverywhere := access.Identity{Role: access.RoleViewer}
	for _, c := range []struct {
		name string
		who  access.Identity
		ws   string
		// create is the code a create is answered with.
		create connect.Code
	}{
		{"installation-wide operator", everywhere, "acme", 0},
		{"the owner's operator", northOp, "acme", 0},
		{"another directory's operator", southOp, "acme", connect.CodePermissionDenied},
		{"an unrelated operator", elsewhereOp, "acme", connect.CodePermissionDenied},
		{"the owner's operator in another workspace", northOp, "globex", connect.CodePermissionDenied},
		{"a scoped viewer", northViewer, "acme", connect.CodePermissionDenied},
		{"an installation-wide viewer", viewerEverywhere, "acme", connect.CodePermissionDenied},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newConnectHarness(t)
			source := map[string]string{"acme": "partners@north.example", "globex": "eng@south.example"}[c.ws]
			err := h.createChannel(as(c.who), chdef(c.ws, "eng", source))
			if c.create == 0 {
				if err != nil {
					t.Fatalf("create = %v, want allowed", err)
				}
			} else {
				wantCode(t, "create", err, c.create)
				if err = h.createChannel(as(everywhere), chdef(c.ws, "eng", source)); err != nil {
					t.Fatal(err)
				}
			}
			errUpdate := h.updateChannel(as(c.who), chdef(c.ws, "eng", source))
			_, errDelete := h.deleteChannel(as(c.who), c.ws, "eng")
			if c.create == 0 {
				if errUpdate != nil || errDelete != nil {
					t.Errorf("update = %v, delete = %v, want allowed", errUpdate, errDelete)
				}
				return
			}
			wantCode(t, "update", errUpdate, connect.CodePermissionDenied)
			wantCode(t, "delete", errDelete, connect.CodePermissionDenied)
			if len(h.storedChannels(t)) != 1 {
				t.Error("a refused delete removed the record")
			}
		})
	}
	// Somebody with no role at all is refused every call.
	h := newConnectHarness(t)
	_, err := h.console.ListSlackChannels(as(elsewhereOp), connect.NewRequest(&directoryrosterv1.ListSlackChannelsRequest{}))
	wantCode(t, "list by an unrelated operator", err, connect.CodePermissionDenied)
}

func TestConsoleChannelsAreListedByWhatTheCallerMaySee(t *testing.T) {
	h := newConnectHarness(t)
	for _, d := range []*directoryrosterv1.SlackChannelDefinition{
		chdef("acme", "a1", "partners@north.example"), chdef("globex", "g1", "eng@south.example"),
	} {
		if err := h.createChannel(as(everywhere), d); err != nil {
			t.Fatal(err)
		}
	}
	names := func(l *directoryrosterv1.ListSlackChannelsResponse) []string {
		var out []string
		for _, c := range l.Channels {
			out = append(out, c.Channel.Workspace+"/"+c.Channel.Name)
		}
		return out
	}
	viewer := h.listChannels(as(northViewer), t)
	if got := names(viewer); !slices.Equal(got, []string{"acme/a1"}) {
		t.Errorf("a viewer of acme sees %v", got)
	}
	for _, c := range viewer.Channels {
		if c.CanOperate {
			t.Errorf("a viewer may operate %s", c.Channel.Name)
		}
	}
	if len(viewer.SourceDirectories) != 0 {
		t.Errorf("a viewer is offered groups to choose from: %v", viewer.SourceDirectories)
	}
	// The groups offered to an operator are its workspaces' owners', and
	// nobody else's: an ordinary channel cannot use another directory's.
	north := h.listChannels(as(northOp), t)
	if len(north.SourceDirectories) != 1 || north.SourceDirectories[0].WorkspaceId != "C0north" {
		t.Fatalf("acme's operator is offered %+v", north.SourceDirectories)
	}
	var offered []string
	for _, g := range north.SourceDirectories[0].Groups {
		offered = append(offered, g.Email)
	}
	if want := []string{"all@north.example", "devops@north.example", "partners@north.example"}; !slices.Equal(offered, want) {
		t.Errorf("offered groups = %v, want %v", offered, want)
	}
	if !slices.Equal(north.SourceDirectories[0].Domains, []string{"north.example"}) {
		t.Errorf("domains = %v", north.SourceDirectories[0].Domains)
	}
	all := h.listChannels(as(everywhere), t)
	if len(all.Channels) != 2 || len(all.Workspaces) != 3 || len(all.SourceDirectories) != 2 {
		t.Errorf("the installation-wide operator sees %d channels, %d workspaces, %d directories", len(all.Channels), len(all.Workspaces), len(all.SourceDirectories))
	}
	for _, w := range north.Workspaces {
		if w.CanOperate != (w.Key == "acme") || (w.Key == "acme" && w.Owner != "C0north") {
			t.Errorf("acme's operator: workspace %+v", w)
		}
	}
	// The Slack Connect page is offered every directory's groups, grouped by directory.
	shared := h.list(as(northOp), t)
	if len(shared.SourceDirectories) != 2 {
		t.Errorf("a Slack Connect operator is offered %d directories, want every connected one", len(shared.SourceDirectories))
	}
	for _, w := range shared.Workspaces {
		if w.Key == "globex" && w.Owner != "C0south" {
			t.Errorf("globex's owner = %q", w.Owner)
		}
	}
}

func TestConsoleChannelStatesFollowTheWorkspacesReport(t *testing.T) {
	h := newConnectHarness(t)
	if err := h.createChannel(as(everywhere), chdef("acme", "eng", "partners@north.example")); err != nil {
		t.Fatal(err)
	}
	state := func() (string, string) {
		got := h.listChannels(as(everywhere), t).Channels[0]
		return got.State, got.Reason
	}
	if s, _ := state(); s != sharedNotReported {
		t.Errorf("before any report: %s", s)
	}
	for _, c := range []struct {
		report status.Channel
		want   string
	}{
		{status.Channel{State: status.ChannelOK}, sharedActive},
		{status.Channel{State: status.ChannelWillCreate}, sharedPending},
		{status.Channel{State: status.ChannelHeld, Reason: "the bot is not in this private channel"}, sharedHeld},
		{status.Channel{State: status.ChannelHeld, Reason: "the console channel's record is refused and not acted on: x"}, sharedInvalid},
	} {
		c.report.Name, c.report.Console, c.report.Mode = "eng", true, "extend"
		h.reportOrdinary(t, "acme", []status.Channel{c.report})
		if s, _ := state(); s != c.want {
			t.Errorf("report %s = %s, want %s", c.report.State, s, c.want)
		}
	}
	// A policy channel of the same name in the report is not this record's.
	h.reportOrdinary(t, "acme", []status.Channel{{Name: "eng", Mode: "extend", State: status.ChannelOK}})
	if s, _ := state(); s != sharedNotReported {
		t.Errorf("a policy channel's row answered for the record: %s", s)
	}
	// A record the policy in force no longer accepts is invalid whatever the report says.
	raw, _ := connection.EncodeConsole(reconcile.ConsoleChannel{Workspace: "acme", Name: "general", Sources: []string{"partners@north.example"}})
	cm, _ := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), "access-issuer-slack-workspaces", metav1.GetOptions{})
	cm.Data[connection.ConsoleKey("acme", "general")] = raw
	cm.Data[connection.ConsoleKey("acme", "broken")] = "{not json"
	if _, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	byName := map[string]*directoryrosterv1.SlackChannelRecord{}
	for _, c := range h.listChannels(as(everywhere), t).Channels {
		byName[c.Channel.Name] = c
	}
	if byName["general"].GetState() != sharedInvalid || !strings.Contains(byName["general"].GetReason(), "defined in git") {
		t.Errorf("a record that duplicates a policy channel = %+v", byName["general"])
	}
	if byName["broken"].GetState() != sharedInvalid {
		t.Errorf("broken = %+v", byName["broken"])
	}
	for _, c := range h.listChannels(as(northOp), t).Channels {
		if c.Channel.Name == "broken" {
			t.Error("a scoped operator is shown a record whose workspace cannot be read")
		}
	}
}

// An old Slack Connect record fed by internal groups is listed invalid with a
// message that says what to do, and is not acted on.
func TestALegacySharedRecordIsListedInvalid(t *testing.T) {
	h := newConnectHarness(t)
	if err := h.create(as(everywhere), def("ok", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	cm, _ := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), "access-issuer-slack-workspaces", metav1.GetOptions{})
	cm.Data[connection.SharedKey("legacy")] = `{"version":1,"name":"legacy","host":"acme","with":["globex"],"from":["all:partners"],"private":{}}`
	if _, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	find := func(who access.Identity) *directoryrosterv1.SlackSharedChannel {
		for _, c := range h.list(as(who), t).Channels {
			if c.Channel.Name == "legacy" {
				return c
			}
		}
		return nil
	}
	c := find(everywhere)
	if c == nil {
		t.Fatal("the legacy record is not listed")
	}
	if c.State != sharedInvalid || !strings.Contains(c.Reason, "internal groups") || !strings.Contains(c.Reason, "directory groups") {
		t.Errorf("the legacy record = %+v", c)
	}
	// It says whose it is, so its host's operator sees it and may edit it.
	if c.Channel.Host != "acme" || !slices.Equal(c.Channel.With, []string{"globex"}) || len(c.Channel.From) != 0 {
		t.Errorf("the legacy record's definition = %+v", c.Channel)
	}
	if mine := find(northOp); mine == nil || !mine.CanOperate {
		t.Fatalf("the legacy record is not offered for editing to its host's operator: %+v", mine)
	}
	// Editing it in directory groups makes it valid again.
	if err := h.update(as(northOp), def("legacy", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatalf("editing a legacy record: %v", err)
	}
	if after := find(northOp); after.State == sharedInvalid || len(after.Channel.From) != 1 {
		t.Errorf("after the edit = %+v", after)
	}
	if kept, err := connection.DecodeShared(h.stored(t)[connection.SharedKey("legacy")]); err != nil || len(kept.Sources) != 1 {
		t.Errorf("kept = %+v, %v", kept, err)
	}
}

func TestOrdinaryChannelsNobodyManagesAreDiscoveredAndManaged(t *testing.T) {
	h := newConnectHarness(t)
	h.reportOrdinary(t, "acme", nil,
		status.Discovered{ID: "C0OPEN0001", Name: "random", Members: 40},
		status.Discovered{ID: "G0PRIVATE1", Name: "secret", Private: true, Members: 3})
	h.reportOrdinary(t, "globex", nil, status.Discovered{ID: "C0GLOBEX01", Name: "lounge"})
	byName := func(l *directoryrosterv1.ListSlackChannelsResponse) map[string]*directoryrosterv1.SlackDiscoveredOrdinary {
		out := map[string]*directoryrosterv1.SlackDiscoveredOrdinary{}
		for _, d := range l.Discovered {
			out[d.Workspace+"/"+d.Name] = d
		}
		return out
	}
	got := byName(h.listChannels(as(everywhere), t))
	if len(got) != 3 || got["acme/secret"].GetChannelId() != "G0PRIVATE1" || !got["acme/secret"].Private || got["acme/random"].Members != 40 {
		t.Fatalf("discovered = %v", got)
	}
	// Whoever may not view a workspace is shown none of its channels, and
	// whoever may only view it may not manage them.
	for name, tc := range map[string]struct {
		id     access.Identity
		want   []string
		manage bool
	}{
		"the owner's operator": {northOp, []string{"acme/random", "acme/secret"}, true},
		"the owner's viewer":   {northViewer, []string{"acme/random", "acme/secret"}, false},
		"another directory":    {southOp, []string{"globex/lounge"}, true},
	} {
		d := byName(h.listChannels(as(tc.id), t))
		var seen []string
		for k, row := range d {
			seen = append(seen, k)
			if row.CanManage != tc.manage {
				t.Errorf("%s: %s can_manage = %v", name, k, row.CanManage)
			}
		}
		if slices.Sort(seen); !slices.Equal(seen, tc.want) {
			t.Errorf("%s sees %v, want %v", name, seen, tc.want)
		}
	}

	// Managing one writes a record that names its id, and it leaves the list.
	d := chdef("acme", "secret", "partners@north.example")
	d.Private, d.ChannelId = true, "  G0PRIVATE1 "
	if err := h.createChannel(as(northOp), d); err != nil {
		t.Fatalf("create: %v", err)
	}
	kept, err := connection.DecodeConsole(h.storedChannels(t)[connection.ConsoleKey("acme", "secret")])
	if err != nil || kept.ChannelID != "G0PRIVATE1" || !kept.Private {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	if _, still := byName(h.listChannels(as(everywhere), t))["acme/secret"]; still {
		t.Error("a managed channel is still discovered")
	}
	// The visibility seen is the visibility managed: never converted.
	public := chdef("acme", "random", "partners@north.example")
	public.Private, public.ChannelId = true, "C0OPEN0001"
	err = h.createChannel(as(northOp), public)
	wantCode(t, "a visibility other than the one seen", err, connect.CodeInvalidArgument)
	if err == nil || !strings.Contains(err.Error(), "never changes a channel's visibility") {
		t.Errorf("the refusal = %v", err)
	}
	// One id is managed once.
	again := chdef("acme", "secret-again", "partners@north.example")
	again.Private, again.ChannelId = true, "G0PRIVATE1"
	wantCode(t, "the same channel id twice", h.createChannel(as(northOp), again), connect.CodeAlreadyExists)
	// The id the host saw, and only there.
	elsewhere := chdef("globex", "random", "eng@south.example")
	elsewhere.ChannelId = "C0OPEN0001"
	wantCode(t, "an id another workspace saw", h.createChannel(as(everywhere), elsewhere), connect.CodeInvalidArgument)
}

// A report a pass behind a record just written does not offer the channel again.
func TestADiscoveredChannelAlreadyCoveredByARecordIsNotOffered(t *testing.T) {
	h := newConnectHarness(t)
	if err := h.createChannel(as(everywhere), chdef("acme", "random", "partners@north.example")); err != nil {
		t.Fatal(err)
	}
	h.reportOrdinary(t, "acme", nil, status.Discovered{ID: "C0OPEN0001", Name: "random"})
	if got := h.listChannels(as(everywhere), t).Discovered; len(got) != 0 {
		t.Errorf("discovered = %v", got)
	}
}

func TestWithoutAStoreNoConsoleChannelCanBeKept(t *testing.T) {
	h := newConnectHarness(t)
	h.console.deps.SlackChannels = nil
	wantCode(t, "create", h.createChannel(as(everywhere), chdef("acme", "x", "partners@north.example")), connect.CodeFailedPrecondition)
	if got := h.listChannels(as(everywhere), t); got.Available {
		t.Error("available with no store")
	}
}
