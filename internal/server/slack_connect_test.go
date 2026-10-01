package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// acme belongs to C0north's directory, globex to C0south's, initech to
// nobody's; one group feeds channels.
const connectTestPolicy = `
version: 1
groups:
  all:platform:engineer: { members: [team-platform@globex.example] }
  all:partners: { members: [partner@globex.example] }
slack:
  workspaces:
    acme:
      channels:
        general: { from: [all:platform:engineer] }
    globex: {}
    initech: {}
`

type connectHarness struct {
	console   *Console
	client    *kube.Client
	clientset *fake.Clientset
	recorded  *audittest.Recorder
	reports   map[string]string
}

type fixedReports struct{ docs map[string]string }

func (f fixedReports) Reports(context.Context) (map[string]string, error) { return f.docs, nil }

func newConnectHarness(t *testing.T) *connectHarness {
	t.Helper()
	declared, err := policy.Parse([]byte(connectTestPolicy))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	clientset := fake.NewClientset()
	client := kube.NewClient(clientset, "access-issuer", "access-issuer")
	h := &connectHarness{client: client, clientset: clientset, recorded: audittest.New(t), reports: map[string]string{}}
	workspaces := kube.NewSlackWorkspaces(client)
	h.console = &Console{deps: ConsoleDeps{
		Authorizer:      access.NewAuthorizer(set, nil, 0),
		SlackShared:     kube.NewSlackShared(client),
		SlackChannels:   kube.NewSlackChannels(client),
		Hub:             groupHub(t),
		SlackWorkspaces: workspaces,
		SlackStatus:     fixedReports{docs: h.reports},
		Audit:           h.recorded,
	}}
	// Connected, which is where each workspace's owner is recorded.
	seedSlackWorkspace(t, workspaces, "acme", "C0north", acmeTeam)
	seedSlackWorkspace(t, workspaces, "globex", "C0south", globexTeam)
	seedSlackWorkspace(t, workspaces, "initech", "", "T0789IJKL")
	return h
}

func as(id access.Identity) context.Context {
	if id.Email == "" {
		id.Email = "someone@north.example"
	}
	return WithIdentity(context.Background(), id)
}

func def(name, host string, with, from []string) *directoryrosterv1.SlackSharedChannelDefinition {
	return &directoryrosterv1.SlackSharedChannelDefinition{Name: name, Host: host, With: with, From: from}
}

func (h *connectHarness) create(ctx context.Context, d *directoryrosterv1.SlackSharedChannelDefinition) error {
	_, err := h.console.CreateSlackSharedChannel(ctx, connect.NewRequest(&directoryrosterv1.CreateSlackSharedChannelRequest{Channel: d}))
	return err
}

func (h *connectHarness) update(ctx context.Context, d *directoryrosterv1.SlackSharedChannelDefinition) error {
	_, err := h.console.UpdateSlackSharedChannel(ctx, connect.NewRequest(&directoryrosterv1.UpdateSlackSharedChannelRequest{Channel: d}))
	return err
}

func (h *connectHarness) del(ctx context.Context, name string) (string, error) {
	got, err := h.console.DeleteSlackSharedChannel(ctx, connect.NewRequest(&directoryrosterv1.DeleteSlackSharedChannelRequest{Name: name}))
	if err != nil {
		return "", err
	}
	return got.Msg.GetNote(), nil
}

func (h *connectHarness) list(ctx context.Context, t *testing.T) *directoryrosterv1.ListSlackSharedChannelsResponse {
	t.Helper()
	got, err := h.console.ListSlackSharedChannels(ctx, connect.NewRequest(&directoryrosterv1.ListSlackSharedChannelsRequest{}))
	if err != nil {
		t.Fatalf("ListSlackSharedChannels: %v", err)
	}
	return got.Msg
}

func (h *connectHarness) stored(t *testing.T) map[string]string {
	t.Helper()
	cm, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), "access-issuer-slack-workspaces", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return map[string]string{}
	}
	if err != nil {
		t.Fatalf("read the records: %v", err)
	}
	// The shared channels' records alone: the workspaces' own records sit in
	// the same ConfigMap and are not what these tests look at.
	shared := map[string]string{}
	for key, doc := range cm.Data {
		if _, ok := connection.ParseSharedKey(key); ok {
			shared[key] = doc
		}
	}
	return shared
}

func wantCode(t *testing.T, what string, err error, code connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Errorf("%s = %v, want %s", what, err, code)
	}
}

func TestASharedChannelIsCreatedEditedAndDeleted(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)

	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatalf("create: %v", err)
	}
	// What is kept is the versioned document the controller reads.
	doc, ok := h.stored(t)[connection.SharedKey("partners")]
	if !ok {
		t.Fatalf("no record kept: %v", h.stored(t))
	}
	kept, err := connection.DecodeShared(doc)
	if err != nil || kept.Host != "acme" || kept.Name != "partners" || !slices.Equal(kept.With, []string{"globex"}) {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	if err = kept.Validate(h.console.deps.Authorizer.Policy().Declared()); err != nil {
		t.Errorf("the controller would refuse what was kept: %v", err)
	}

	// Edit with, from and private.
	edited := def("partners", "acme", []string{"globex", "initech"}, []string{"partners@north.example", "eng@south.example"})
	edited.PrivatePerSide = map[string]bool{"acme": true, "globex": false, "initech": true}
	if err = h.update(ctx, edited); err != nil {
		t.Fatalf("update: %v", err)
	}
	listed := h.list(ctx, t)
	if len(listed.Channels) != 1 {
		t.Fatalf("listed %v", listed.Channels)
	}
	got := listed.Channels[0]
	if !got.CanOperate || got.State != sharedNotReported || len(got.Channel.With) != 2 || !got.Channel.PrivatePerSide["acme"] {
		t.Errorf("listed = %+v", got)
	}

	// Delete removes the record and says the channel stays.
	note, err := h.del(ctx, "partners")
	if err != nil || !strings.Contains(note, "stays in Slack") {
		t.Errorf("delete = %q, %v", note, err)
	}
	if _, still := h.stored(t)[connection.SharedKey("partners")]; still {
		t.Error("the record is still kept")
	}

	// Every change is on the trail, by the person, with host and channel.
	for _, action := range []string{"roster.slack_shared_channel.created", "roster.slack_shared_channel.updated", "roster.slack_shared_channel.deleted"} {
		found := h.recorded.Find(action)
		if len(found) != 1 {
			t.Fatalf("%s: %d records", action, len(found))
		}
		rec := found[0]
		// The workspace and channel first, then the directory groups that feed it.
		if len(rec.GetTargets()) < 3 || rec.GetTargets()[0].GetId() != "acme" || rec.GetTargets()[1].GetId() != "acme/partners" ||
			rec.GetTargets()[2].GetType() != "directory_group" {
			t.Errorf("%s targets = %v", action, rec.GetTargets())
		}
		if rec.GetActor().GetId() == "" {
			t.Errorf("%s has no actor", action)
		}
	}
	updated := h.recorded.Find("roster.slack_shared_channel.updated")[0].GetData().AsMap()
	changes, _ := updated["changes"].(string)
	for _, part := range []string{
		"with: globex -> globex,initech",
		"sources: 1 -> 2 groups (1 added, 0 removed)",
		"private: public -> acme=private,globex=public,initech=private",
	} {
		if !strings.Contains(changes, part) {
			t.Errorf("changes = %q, missing %q", changes, part)
		}
	}
}

func TestASharedChannelIsRefusedWhenItDoesNotValidate(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	for _, c := range []struct {
		name string
		def  *directoryrosterv1.SlackSharedChannelDefinition
	}{
		{"a bad name", def("Not A Name", "acme", []string{"globex"}, []string{"partners@north.example"})},
		{"an undeclared host", def("x", "nowhere", []string{"globex"}, []string{"partners@north.example"})},
		{"an undeclared guest", def("x", "acme", []string{"nowhere"}, []string{"partners@north.example"})},
		{"the host as a guest", def("x", "acme", []string{"acme"}, []string{"partners@north.example"})},
		{"no guest", def("x", "acme", nil, []string{"partners@north.example"})},
		{"no group", def("x", "acme", []string{"globex"}, nil)},
		{"an undeclared group", def("x", "acme", []string{"globex"}, []string{"nobody@north.example"})},
		{"a name the host already binds", def("general", "acme", []string{"globex"}, []string{"partners@north.example"})},
		{"per-side privacy missing a side", &directoryrosterv1.SlackSharedChannelDefinition{
			Name: "x", Host: "acme", With: []string{"globex"}, From: []string{"partners@north.example"}, PrivatePerSide: map[string]bool{"acme": true}}},
	} {
		wantCode(t, c.name, h.create(ctx, c.def), connect.CodeInvalidArgument)
	}
	if len(h.stored(t)) != 0 {
		t.Errorf("a refused record was kept: %v", h.stored(t))
	}
	if n := len(h.recorded.Records()); n != 0 {
		t.Errorf("refusals were recorded as changes: %d", n)
	}
	// A name already taken is refused, naming the host.
	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	err := h.create(ctx, def("partners", "globex", []string{"acme"}, []string{"partners@north.example"}))
	wantCode(t, "a second channel of the same name", err, connect.CodeAlreadyExists)
	if err != nil && !strings.Contains(err.Error(), "acme") {
		t.Errorf("the refusal does not name the host: %v", err)
	}
}

func TestACreateRefusalDoesNotNameAnotherHostsRecord(t *testing.T) {
	h := newConnectHarness(t)
	if err := h.create(as(everywhere), def("partners", "acme", []string{"initech"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	// globex's operator sees neither side of the record: the name is taken,
	// and that is all the refusal says.
	err := h.create(as(southOp), def("partners", "globex", []string{"initech"}, []string{"partners@north.example"}))
	wantCode(t, "a name another host's record holds", err, connect.CodeAlreadyExists)
	if err != nil && strings.Contains(err.Error(), "acme") {
		t.Errorf("the refusal names a host the caller may not see: %v", err)
	}
}

func TestAHostAndANameAreImmutable(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	before := h.stored(t)[connection.SharedKey("partners")]
	err := h.update(ctx, def("partners", "globex", []string{"acme"}, []string{"partners@north.example"}))
	wantCode(t, "a change of host", err, connect.CodeInvalidArgument)
	if err == nil || !strings.Contains(err.Error(), "create a new channel") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
	// A different name is a different record: there is none to edit.
	wantCode(t, "an edit of another name", h.update(ctx, def("renamed", "acme", []string{"globex"}, []string{"partners@north.example"})), connect.CodeNotFound)
	if h.stored(t)[connection.SharedKey("partners")] != before || len(h.stored(t)) != 1 {
		t.Errorf("a refused edit changed the records: %v", h.stored(t))
	}
	if n := len(h.recorded.Find("roster.slack_shared_channel.updated")); n != 0 {
		t.Errorf("%d updates recorded", n)
	}
	// An edit that changes nothing writes and records nothing new.
	if err = h.update(ctx, def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	if n := len(h.recorded.Find("roster.slack_shared_channel.updated")); n != 0 {
		t.Errorf("a no-op edit was recorded: %d", n)
	}
}

func TestWhoMayEditSharedChannels(t *testing.T) {
	// acme's directory is C0north, globex's C0south, initech has none.
	d := func(host string, with ...string) *directoryrosterv1.SlackSharedChannelDefinition {
		return def("partners", host, with, []string{"partners@north.example"})
	}
	viewerEverywhere := access.Identity{Role: access.RoleViewer}
	for _, c := range []struct {
		name string
		who  access.Identity
		host string
		with []string
		// create is the code a create of this channel is answered with.
		create connect.Code
		// hidden: the caller may not even see the record, so an edit or delete
		// is answered "no such channel", as for a name nobody holds.
		hidden bool
	}{
		{"installation-wide operator, acme hosts", everywhere, "acme", []string{"globex"}, 0, false},
		{"installation-wide operator, unowned host", everywhere, "initech", []string{"acme"}, 0, false},
		{"the host owner's operator", northOp, "acme", []string{"globex"}, 0, false},
		{"the guest owner's operator alone", southOp, "acme", []string{"globex"}, connect.CodePermissionDenied, false},
		{"an operator of an unrelated directory", elsewhereOp, "acme", []string{"globex"}, connect.CodePermissionDenied, true},
		{"a scoped operator, unowned host", northOp, "initech", []string{"acme"}, connect.CodePermissionDenied, false},
		{"a scoped viewer", northViewer, "acme", []string{"globex"}, connect.CodePermissionDenied, false},
		{"an installation-wide viewer", viewerEverywhere, "acme", []string{"globex"}, connect.CodePermissionDenied, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newConnectHarness(t)
			err := h.create(as(c.who), d(c.host, c.with...))
			if c.create == 0 {
				if err != nil {
					t.Fatalf("create = %v, want allowed", err)
				}
			} else {
				wantCode(t, "create", err, c.create)
			}
			// Whoever may not create may not edit or delete a record that
			// exists, which the installation-wide operator makes.
			if c.create != 0 {
				if err := h.create(as(everywhere), d(c.host, c.with...)); err != nil {
					t.Fatal(err)
				}
			}
			edited := def("partners", c.host, c.with, []string{"partners@north.example", "eng@south.example"})
			errUpdate := h.update(as(c.who), edited)
			_, errDelete := h.del(as(c.who), "partners")
			if c.create == 0 {
				if errUpdate != nil || errDelete != nil {
					t.Errorf("update = %v, delete = %v, want allowed", errUpdate, errDelete)
				}
				return
			}
			want := connect.CodePermissionDenied
			if c.hidden {
				want = connect.CodeNotFound
			}
			wantCode(t, "update", errUpdate, want)
			wantCode(t, "delete", errDelete, want)
			if _, still := h.stored(t)[connection.SharedKey("partners")]; !still {
				t.Error("a refused delete removed the record")
			}
		})
	}
}

func TestSharedChannelsAreListedByWhatTheCallerMaySee(t *testing.T) {
	h := newConnectHarness(t)
	for _, d := range []*directoryrosterv1.SlackSharedChannelDefinition{
		def("ab", "acme", []string{"globex"}, []string{"partners@north.example"}),
		def("ai", "acme", []string{"initech"}, []string{"partners@north.example"}),
		def("gi", "globex", []string{"initech"}, []string{"partners@north.example"}),
	} {
		if err := h.create(as(everywhere), d); err != nil {
			t.Fatal(err)
		}
	}
	names := func(l *directoryrosterv1.ListSlackSharedChannelsResponse) []string {
		var out []string
		for _, c := range l.Channels {
			out = append(out, c.Channel.Name)
		}
		return out
	}
	// A viewer sees what touches a workspace it may view, and cannot change it.
	viewer := h.list(as(northViewer), t)
	if got := names(viewer); !slices.Equal(got, []string{"ab", "ai"}) {
		t.Errorf("a viewer of acme sees %v, want the two channels acme takes part in", got)
	}
	for _, c := range viewer.Channels {
		if c.CanOperate {
			t.Errorf("a viewer may operate %s", c.Channel.Name)
		}
	}
	if len(viewer.SourceDirectories) != 0 {
		t.Errorf("a viewer is offered groups to choose from: %v", viewer.SourceDirectories)
	}
	// A guest owner's operator sees the channel, and may not operate it.
	south := h.list(as(southOp), t)
	for _, c := range south.Channels {
		if c.CanOperate != (c.Channel.Host == "globex") {
			t.Errorf("globex's operator: %s hosted by %s can_operate = %v", c.Channel.Name, c.Channel.Host, c.CanOperate)
		}
	}
	if got := names(south); !slices.Equal(got, []string{"ab", "gi"}) {
		t.Errorf("globex's operator sees %v", got)
	}
	all := h.list(as(everywhere), t)
	if len(all.Channels) != 3 || len(all.Workspaces) != 3 || len(all.SourceDirectories) != 2 {
		t.Errorf("the installation-wide operator sees %d channels, %d workspaces, %d directories", len(all.Channels), len(all.Workspaces), len(all.SourceDirectories))
	}
	for _, w := range all.Workspaces {
		if !w.CanOperate {
			t.Errorf("workspace %s is not operable by the installation-wide operator", w.Key)
		}
	}
	north := h.list(as(northOp), t)
	for _, w := range north.Workspaces {
		if w.CanOperate != (w.Key == "acme") {
			t.Errorf("acme's operator: workspace %s can_operate = %v", w.Key, w.CanOperate)
		}
	}
	// Someone with no role over any Slack workspace is refused the page.
	_, err := h.console.ListSlackSharedChannels(as(elsewhereOp), connect.NewRequest(&directoryrosterv1.ListSlackSharedChannelsRequest{}))
	wantCode(t, "list by an unrelated operator", err, connect.CodePermissionDenied)
}

func TestSharedChannelStatesFollowTheHostsReport(t *testing.T) {
	h := newConnectHarness(t)
	if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	state := func() (string, string) {
		got := h.list(as(everywhere), t).Channels[0]
		return got.State, got.Reason
	}
	report := func(channels ...status.Channel) {
		raw, err := status.Encode(status.Workspace{Version: status.Version, Workspace: "acme", Enabled: true, Channels: channels})
		if err != nil {
			t.Fatal(err)
		}
		h.reports[status.Key("acme")] = raw
	}
	if s, _ := state(); s != sharedNotReported {
		t.Errorf("before any report: %s", s)
	}
	for _, c := range []struct {
		report status.Channel
		want   string
	}{
		{status.Channel{State: status.ChannelOK}, sharedActive},
		{status.Channel{State: status.ChannelWaiting, Reason: "globex has not accepted"}, sharedWaiting},
		{status.Channel{State: status.ChannelWillCreate}, sharedPending},
		{status.Channel{State: status.ChannelHeld, Reason: "the bot is not in the channel"}, sharedHeld},
		{status.Channel{State: status.ChannelHeld, Reason: "the shared channel's definition is refused and not acted on: x"}, sharedInvalid},
	} {
		c.report.Name, c.report.Shared, c.report.Host, c.report.Mode = "partners", true, "acme", "extend"
		report(c.report)
		if s, _ := state(); s != c.want {
			t.Errorf("report %s = %s, want %s", c.report.State, s, c.want)
		}
	}
	// A record the policy in force no longer accepts is invalid whatever
	// the report says.
	raw, _ := connection.EncodeShared(reconcile.SharedChannel{Name: "stale", Host: "acme", With: []string{"gone"}, Sources: []string{"partners@north.example"}})
	cm, _ := h.client.API().CoreV1().ConfigMaps("access-issuer").Get(context.Background(), "access-issuer-slack-workspaces", metav1.GetOptions{})
	cm.Data[connection.SharedKey("stale")] = raw
	cm.Data[connection.SharedKey("broken")] = "{not json"
	if _, err := h.client.API().CoreV1().ConfigMaps("access-issuer").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	byName := map[string]*directoryrosterv1.SlackSharedChannel{}
	for _, c := range h.list(as(everywhere), t).Channels {
		byName[c.Channel.Name] = c
	}
	if byName["stale"].GetState() != sharedInvalid || !strings.Contains(byName["stale"].GetReason(), "gone") {
		t.Errorf("stale = %+v", byName["stale"])
	}
	if byName["broken"].GetState() != sharedInvalid {
		t.Errorf("broken = %+v", byName["broken"])
	}
	// An unreadable record is shown to the installation-wide role only.
	for _, c := range h.list(as(northOp), t).Channels {
		if c.Channel.Name == "broken" {
			t.Error("a scoped operator is shown a record whose host cannot be read")
		}
	}
}

// A conflict on the ConfigMap is retried, and the write that finally lands
// is decided against what the other writer left; one that outlasts the
// retries is refused cleanly, changing nothing.
func TestAConflictingWriteIsRetriedOrRefusedCleanly(t *testing.T) {
	conflict := func() error {
		return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "access-issuer-slack-workspaces", errors.New("the object has been modified"))
	}
	t.Run("retried", func(t *testing.T) {
		h := newConnectHarness(t)
		failures := 0
		h.clientset.PrependReactor("update", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
			if failures < 2 {
				failures++
				return true, nil, conflict()
			}
			return false, nil, nil
		})
		if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
			t.Fatalf("create = %v, want it retried", err)
		}
		if failures != 2 || len(h.recorded.Find("roster.slack_shared_channel.created")) != 1 {
			t.Errorf("failures = %d, recorded = %d", failures, len(h.recorded.Find("roster.slack_shared_channel.created")))
		}
	})
	t.Run("refused", func(t *testing.T) {
		h := newConnectHarness(t)
		h.clientset.PrependReactor("update", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, conflict()
		})
		err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"partners@north.example"}))
		wantCode(t, "create under endless conflict", err, connect.CodeAborted)
		if len(h.stored(t)) != 0 || len(h.recorded.Records()) != 0 {
			t.Errorf("a refused write left records %v, audit %d", h.stored(t), len(h.recorded.Records()))
		}
	})
	t.Run("the other writer's record is what an edit is decided against", func(t *testing.T) {
		h := newConnectHarness(t)
		if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
			t.Fatal(err)
		}
		// Between the edit's first read and its write, somebody deletes the
		// record: the retry finds nothing to edit, and says so.
		first := true
		h.clientset.PrependReactor("update", "configmaps", func(clienttesting.Action) (bool, runtime.Object, error) {
			if first {
				first = false
				// Through the tracker: the clientset is locked while a reactor runs.
				gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
				obj, err := h.clientset.Tracker().Get(gvr, "access-issuer", "access-issuer-slack-workspaces")
				if err != nil {
					t.Error(err)
					return false, nil, nil
				}
				cm, _ := obj.(*corev1.ConfigMap)
				delete(cm.Data, connection.SharedKey("partners"))
				if err = h.clientset.Tracker().Update(gvr, cm, "access-issuer"); err != nil {
					t.Error(err)
				}
				return true, nil, conflict()
			}
			return false, nil, nil
		})
		err := h.update(as(everywhere), def("partners", "acme", []string{"globex", "initech"}, []string{"partners@north.example"}))
		wantCode(t, "edit of a record deleted meanwhile", err, connect.CodeNotFound)
	})
}

func TestNoStoreIsRefusedPlainly(t *testing.T) {
	h := newConnectHarness(t)
	h.console.deps.SlackShared = nil
	wantCode(t, "create", h.create(as(everywhere), def("p", "acme", []string{"globex"}, []string{"partners@north.example"})), connect.CodeFailedPrecondition)
	if got := h.list(as(everywhere), t); got.Available {
		t.Error("available with no store")
	}
}

// ---------------------------------------------------------------- discovered channels

const (
	externalTeam = "T0EXTERN1"
	initechTeam  = "T0789IJKL"
)

func (h *connectHarness) report(t *testing.T, workspace, team string, found ...status.Discovered) {
	t.Helper()
	raw, err := status.Encode(status.Workspace{Version: status.Version, Workspace: workspace, Team: team, Enabled: true, DiscoveredShared: found})
	if err != nil {
		t.Fatal(err)
	}
	h.reports[status.Key(workspace)] = raw
}

// legacyReports is one channel made in acme, public there, shared with
// globex (private on its side) and a team that is not connected.
func (h *connectHarness) legacyReports(t *testing.T) {
	t.Helper()
	teams := []string{acmeTeam, globexTeam, externalTeam}
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LEGACY1", Name: "legacy", Members: 7, HostTeam: acmeTeam, Teams: teams})
	h.report(t, "globex", globexTeam, status.Discovered{ID: "C0LEGACY1", Name: "legacy-globex", Private: true, Members: 7, HostTeam: acmeTeam, Teams: teams})
}

func sideOf(row *directoryrosterv1.SlackDiscoveredChannel, workspace string) *directoryrosterv1.SlackDiscoveredSide {
	for _, s := range row.Sides {
		if s.Workspace == workspace {
			return s
		}
	}
	return nil
}

func TestDiscoveredChannelsAreMergedIntoOneRowAcrossWorkspaces(t *testing.T) {
	h := newConnectHarness(t)
	h.legacyReports(t)
	got := h.list(as(everywhere), t).Discovered
	if len(got) != 1 {
		t.Fatalf("discovered = %v", got)
	}
	row := got[0]
	if row.ChannelId != "C0LEGACY1" || row.HostWorkspace != "acme" || row.HostTeam != acmeTeam || row.ExternalTeams != 1 || row.Managed || !row.CanManage {
		t.Errorf("row = %+v", row)
	}
	if len(row.Sides) != 3 || row.Sides[0].Workspace != "acme" || row.Sides[1].Workspace != "globex" {
		t.Fatalf("sides = %v (the host first, then the listed sides, then the connected workspaces nothing places it in)", row.Sides)
	}
	if i := sideOf(row, "initech"); i == nil || i.Seen || i.Listed || i.Privacy != "unknown" {
		t.Errorf("initech side = %+v, want unknown and not listed", i)
	}
	if a := sideOf(row, "acme"); !a.Seen || a.Name != "legacy" || a.Privacy != "public" || a.Members != 7 {
		t.Errorf("acme side = %+v", a)
	}
	if g := sideOf(row, "globex"); !g.Seen || g.Name != "legacy-globex" || g.Privacy != "private" {
		t.Errorf("globex side = %+v", g)
	}
}

func TestADiscoveredSideTheBotCannotSeeIsUnknown(t *testing.T) {
	h := newConnectHarness(t)
	teams := []string{acmeTeam, globexTeam}
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LEGACY1", Name: "legacy", HostTeam: acmeTeam, Teams: teams})
	row := h.list(as(everywhere), t).Discovered[0]
	if g := sideOf(row, "globex"); g == nil || g.Seen || g.Privacy != "unknown" || g.Name != "" {
		t.Errorf("globex side = %+v, want unknown (the bot is not in it, or it is not shared)", g)
	}
}

// Slack names only the host among the teams a channel reaches when the
// host's own list is read, and a guest bot lists a private channel only once
// it is in it, or a public one it has not joined may not be listed at all:
// a guest side nobody saw leaves no trace in any report. It is still a
// connected workspace the channel may be shared with, so it is offered as an
// unknown side, never dropped as if the channel were not shared there.
func TestAGuestSideNoReportTracesIsOfferedAsUnknownNotDropped(t *testing.T) {
	h := newConnectHarness(t)
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LEGACY1", Name: "legacy", Members: 3, HostTeam: acmeTeam, Teams: []string{acmeTeam}})
	h.report(t, "globex", globexTeam)
	row := h.list(as(everywhere), t).Discovered[0]
	for _, ws := range []string{"globex", "initech"} {
		if side := sideOf(row, ws); side == nil || side.Seen || side.Listed || side.Privacy != "unknown" {
			t.Errorf("%s side = %+v, want an unknown side nothing places the channel in", ws, side)
		}
	}
	if a := sideOf(row, "acme"); a == nil || !a.Listed || !a.Seen {
		t.Errorf("the host side = %+v", a)
	}
	// Slack naming a pending guest places it, listed, though its bot cannot see it yet.
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LEGACY1", Name: "legacy", Members: 3, HostTeam: acmeTeam, Teams: []string{acmeTeam, globexTeam}})
	if side := sideOf(h.list(as(everywhere), t).Discovered[0], "globex"); side == nil || side.Seen || !side.Listed {
		t.Errorf("a side Slack names = %+v, want listed and unseen", side)
	}
	// A caller who may not view a workspace is offered no guess about it, and
	// told nothing of a side Slack names beyond that it is one.
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LEGACY1", Name: "legacy", Members: 3, HostTeam: acmeTeam, Teams: []string{acmeTeam}})
	north := h.list(as(northOp), t).Discovered[0]
	for _, s := range north.Sides {
		if s.Workspace != "acme" {
			t.Errorf("a scoped viewer is shown the side of %s", s.Workspace)
		}
	}
}

func TestAChannelHostedByATeamThatIsNotConnectedCannotBeManaged(t *testing.T) {
	h := newConnectHarness(t)
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0OTHER1", Name: "theirs", HostTeam: externalTeam, Teams: []string{externalTeam, acmeTeam}})
	row := h.list(as(everywhere), t).Discovered[0]
	if row.HostWorkspace != "" || row.CanManage || row.ExternalTeams != 1 {
		t.Errorf("row = %+v, want external and not manageable", row)
	}
	// acme's bot sees it, but acme is not its host: a record naming acme is refused.
	wantCode(t, "a record for an externally hosted channel", h.create(as(everywhere), &directoryrosterv1.SlackSharedChannelDefinition{
		Name: "theirs", Host: "acme", With: []string{"globex"}, From: []string{"partners@north.example"}, ChannelId: "C0OTHER1"}), connect.CodeInvalidArgument)
}

func TestOnlyTheHostsOperatorMayManageADiscoveredChannel(t *testing.T) {
	h := newConnectHarness(t)
	h.legacyReports(t)
	viewer := access.Identity{Role: access.RoleViewer}
	for name, tc := range map[string]struct {
		id     access.Identity
		manage bool
		sees   bool
	}{
		"installation operator":     {everywhere, true, true},
		"the host owner's operator": {northOp, true, true},
		"a guest owner's operator":  {southOp, false, true},
		"an installation viewer":    {viewer, false, true},
		"an unrelated operator":     {elsewhereOp, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			if !tc.sees {
				_, err := h.console.ListSlackSharedChannels(as(tc.id), connect.NewRequest(&directoryrosterv1.ListSlackSharedChannelsRequest{}))
				wantCode(t, "list", err, connect.CodePermissionDenied)
				return
			}
			got := h.list(as(tc.id), t).Discovered
			if len(got) != 1 || got[0].CanManage != tc.manage {
				t.Errorf("discovered = %+v, want can_manage %v", got, tc.manage)
			}
		})
	}
	// A guest's operator sees only its own side's details.
	south := h.list(as(southOp), t).Discovered[0]
	if a := sideOf(south, "acme"); a == nil || a.Seen || a.Name != "" {
		t.Errorf("a guest's operator sees the host side's details: %+v", a)
	}
	if g := sideOf(south, "globex"); !g.Seen || g.Name != "legacy-globex" {
		t.Errorf("globex side = %+v", g)
	}
	// ... and cannot take it under management by writing the record.
	err := h.create(as(southOp), &directoryrosterv1.SlackSharedChannelDefinition{
		Name: "legacy", Host: "acme", With: []string{"globex"}, From: []string{"partners@north.example"}, ChannelId: "C0LEGACY1"})
	wantCode(t, "create by a guest's operator", err, connect.CodePermissionDenied)
}

func TestManagingADiscoveredChannelWritesARecordThatNamesItsID(t *testing.T) {
	h := newConnectHarness(t)
	h.legacyReports(t)
	d := &directoryrosterv1.SlackSharedChannelDefinition{
		Name: "legacy", Host: "acme", With: []string{"globex"}, From: []string{"partners@north.example"}, ChannelId: "  C0LEGACY1 ",
		PrivatePerSide: map[string]bool{"acme": false, "globex": true},
	}
	if err := h.create(as(northOp), d); err != nil {
		t.Fatalf("create: %v", err)
	}
	kept, err := connection.DecodeShared(h.stored(t)[connection.SharedKey("legacy")])
	if err != nil || kept.ChannelID != "C0LEGACY1" || !kept.Private.PerSide["globex"] {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	if err = kept.Validate(h.console.deps.Authorizer.Policy().Declared()); err != nil {
		t.Errorf("the controller would refuse what was kept: %v", err)
	}
	listed := h.list(as(everywhere), t)
	if row := listed.Discovered[0]; !row.Managed || row.ManagedAs != "legacy" || row.CanManage {
		t.Errorf("row after managing = %+v", row)
	}
	if got := listed.Channels[0].Channel.ChannelId; got != "C0LEGACY1" {
		t.Errorf("the record's view lacks the id: %q", got)
	}

	// The id cannot change afterwards.
	d.ChannelId = "C0OTHER000"
	wantCode(t, "update with another id", h.update(as(northOp), d), connect.CodeInvalidArgument)
	d.ChannelId = ""
	wantCode(t, "update dropping the id", h.update(as(northOp), d), connect.CodeInvalidArgument)
}

func TestAnIDThatWasNotDiscoveredInTheHostIsRefused(t *testing.T) {
	h := newConnectHarness(t)
	h.legacyReports(t)
	base := func(id string) *directoryrosterv1.SlackSharedChannelDefinition {
		return &directoryrosterv1.SlackSharedChannelDefinition{
			Name: "legacy", Host: "acme", With: []string{"globex"}, From: []string{"partners@north.example"}, ChannelId: id}
	}
	wantCode(t, "an id nobody saw", h.create(as(everywhere), base("C0NEVERSAW")), connect.CodeInvalidArgument)
	wantCode(t, "not a channel id", h.create(as(everywhere), base("not an id")), connect.CodeInvalidArgument)
	// Seen by the guest only: the host is the one that must see it.
	h.report(t, "acme", acmeTeam)
	wantCode(t, "seen by a guest only", h.create(as(everywhere), base("C0LEGACY1")), connect.CodeInvalidArgument)
	if len(h.stored(t)) != 0 {
		t.Errorf("a record was kept: %v", h.stored(t))
	}
}

func TestADiscoveredChannelIsMarkedManagedByARecordOfTheSameHostAndName(t *testing.T) {
	h := newConnectHarness(t)
	h.legacyReports(t)
	if err := h.create(as(everywhere), def("legacy", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	if row := h.list(as(everywhere), t).Discovered[0]; !row.Managed || row.ManagedAs != "legacy" || row.CanManage {
		t.Errorf("row = %+v", row)
	}
}

// The live shape: hosted in acme, shared with globex and initech. The host's
// list names initech; globex's bot found its side by probing (host acme);
// initech's side is private and its bot is not in it, so nothing of it was
// seen. Every workspace whose report lists the channel is a listed side, with
// the privacy it reported; the one nobody saw stays unknown.
func TestAProbedGuestSideIsListedWithItsOwnPrivacy(t *testing.T) {
	h := newConnectHarness(t)
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LIVE1", Name: "shared-one", Members: 12, HostTeam: acmeTeam, Teams: []string{acmeTeam, initechTeam}})
	h.report(t, "globex", globexTeam,
		status.Discovered{ID: "C0LIVE1", Name: "shared-one", Private: true, Members: 12, HostTeam: acmeTeam, Teams: []string{acmeTeam}})
	h.report(t, "initech", initechTeam)
	row := h.list(as(everywhere), t).Discovered[0]
	if g := sideOf(row, "globex"); g == nil || !g.Listed || !g.Seen || g.Privacy != "private" || g.Members != 12 {
		t.Errorf("the probed side = %+v, want listed, seen and private", g)
	}
	if i := sideOf(row, "initech"); i == nil || !i.Listed || i.Seen || i.Privacy != "unknown" {
		t.Errorf("the invisible side = %+v, want listed, unseen and unknown", i)
	}
}

// A report that lists the channel makes its workspace a side by that fact,
// even when the report carries no team id (an older controller's) and the
// host's own list does not name it.
func TestAReportThatListsTheChannelPlacesItsWorkspaceWithoutATeamID(t *testing.T) {
	h := newConnectHarness(t)
	h.report(t, "acme", acmeTeam, status.Discovered{ID: "C0LIVE1", Name: "shared-one", Members: 12, HostTeam: acmeTeam, Teams: []string{acmeTeam, initechTeam}})
	h.report(t, "globex", "", status.Discovered{ID: "C0LIVE1", Name: "shared-one", Members: 12, HostTeam: acmeTeam, Teams: []string{acmeTeam}})
	row := h.list(as(everywhere), t).Discovered[0]
	if g := sideOf(row, "globex"); g == nil || !g.Listed || !g.Seen || g.Privacy != "public" {
		t.Errorf("the reporting side = %+v, want listed, seen and public", g)
	}
	if i := sideOf(row, "initech"); i == nil || !i.Listed || i.Privacy != "unknown" {
		t.Errorf("the named side = %+v", i)
	}
}
