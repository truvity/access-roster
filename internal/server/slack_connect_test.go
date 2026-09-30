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
      team_id: T0123ABCD
      owner: C0north
      domains: [acme.example]
      channels:
        general: { from: [all:platform:engineer] }
    globex:
      team_id: T0456EFGH
      owner: C0south
      domains: [globex.example]
    initech:
      team_id: T0789IJKL
      domains: [initech.example]
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
	h.console = &Console{deps: ConsoleDeps{
		Authorizer:  access.NewAuthorizer(set, nil, 0),
		SlackShared: kube.NewSlackShared(client),
		SlackStatus: fixedReports{docs: h.reports},
		Audit:       h.recorded,
	}}
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
	return cm.Data
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

	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
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
	edited := def("partners", "acme", []string{"globex", "initech"}, []string{"all:partners", "all:platform:engineer"})
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
		if len(rec.GetTargets()) != 2 || rec.GetTargets()[0].GetId() != "acme" || rec.GetTargets()[1].GetId() != "acme/partners" {
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
		"from: all:partners -> all:partners,all:platform:engineer",
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
		{"a bad name", def("Not A Name", "acme", []string{"globex"}, []string{"all:partners"})},
		{"an undeclared host", def("x", "nowhere", []string{"globex"}, []string{"all:partners"})},
		{"an undeclared guest", def("x", "acme", []string{"nowhere"}, []string{"all:partners"})},
		{"the host as a guest", def("x", "acme", []string{"acme"}, []string{"all:partners"})},
		{"no guest", def("x", "acme", nil, []string{"all:partners"})},
		{"no group", def("x", "acme", []string{"globex"}, nil)},
		{"an undeclared group", def("x", "acme", []string{"globex"}, []string{"all:nobody"})},
		{"a name the host already binds", def("general", "acme", []string{"globex"}, []string{"all:partners"})},
		{"per-side privacy missing a side", &directoryrosterv1.SlackSharedChannelDefinition{
			Name: "x", Host: "acme", With: []string{"globex"}, From: []string{"all:partners"}, PrivatePerSide: map[string]bool{"acme": true}}},
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
	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
		t.Fatal(err)
	}
	err := h.create(ctx, def("partners", "globex", []string{"acme"}, []string{"all:partners"}))
	wantCode(t, "a second channel of the same name", err, connect.CodeAlreadyExists)
	if err != nil && !strings.Contains(err.Error(), "acme") {
		t.Errorf("the refusal does not name the host: %v", err)
	}
}

func TestAHostAndANameAreImmutable(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	if err := h.create(ctx, def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
		t.Fatal(err)
	}
	before := h.stored(t)[connection.SharedKey("partners")]
	err := h.update(ctx, def("partners", "globex", []string{"acme"}, []string{"all:partners"}))
	wantCode(t, "a change of host", err, connect.CodeInvalidArgument)
	if err == nil || !strings.Contains(err.Error(), "create a new channel") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
	// A different name is a different record: there is none to edit.
	wantCode(t, "an edit of another name", h.update(ctx, def("renamed", "acme", []string{"globex"}, []string{"all:partners"})), connect.CodeNotFound)
	if h.stored(t)[connection.SharedKey("partners")] != before || len(h.stored(t)) != 1 {
		t.Errorf("a refused edit changed the records: %v", h.stored(t))
	}
	if n := len(h.recorded.Find("roster.slack_shared_channel.updated")); n != 0 {
		t.Errorf("%d updates recorded", n)
	}
	// An edit that changes nothing writes and records nothing new.
	if err = h.update(ctx, def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
		t.Fatal(err)
	}
	if n := len(h.recorded.Find("roster.slack_shared_channel.updated")); n != 0 {
		t.Errorf("a no-op edit was recorded: %d", n)
	}
}

func TestWhoMayEditSharedChannels(t *testing.T) {
	// acme's directory is C0north, globex's C0south, initech has none.
	d := func(host string, with ...string) *directoryrosterv1.SlackSharedChannelDefinition {
		return def("partners", host, with, []string{"all:partners"})
	}
	viewerEverywhere := access.Identity{Role: access.RoleViewer}
	for _, c := range []struct {
		name string
		who  access.Identity
		host string
		with []string
		// create is the code a create of this channel is answered with.
		create connect.Code
	}{
		{"installation-wide operator, acme hosts", everywhere, "acme", []string{"globex"}, 0},
		{"installation-wide operator, unowned host", everywhere, "initech", []string{"acme"}, 0},
		{"the host owner's operator", northOp, "acme", []string{"globex"}, 0},
		{"the guest owner's operator alone", southOp, "acme", []string{"globex"}, connect.CodePermissionDenied},
		{"an operator of an unrelated directory", elsewhereOp, "acme", []string{"globex"}, connect.CodePermissionDenied},
		{"a scoped operator, unowned host", northOp, "initech", []string{"acme"}, connect.CodePermissionDenied},
		{"a scoped viewer", northViewer, "acme", []string{"globex"}, connect.CodePermissionDenied},
		{"an installation-wide viewer", viewerEverywhere, "acme", []string{"globex"}, connect.CodePermissionDenied},
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
			edited := def("partners", c.host, c.with, []string{"all:partners", "all:platform:engineer"})
			errUpdate := h.update(as(c.who), edited)
			_, errDelete := h.del(as(c.who), "partners")
			if c.create == 0 {
				if errUpdate != nil || errDelete != nil {
					t.Errorf("update = %v, delete = %v, want allowed", errUpdate, errDelete)
				}
				return
			}
			wantCode(t, "update", errUpdate, connect.CodePermissionDenied)
			wantCode(t, "delete", errDelete, connect.CodePermissionDenied)
			if _, still := h.stored(t)[connection.SharedKey("partners")]; !still {
				t.Error("a refused delete removed the record")
			}
		})
	}
}

func TestSharedChannelsAreListedByWhatTheCallerMaySee(t *testing.T) {
	h := newConnectHarness(t)
	for _, d := range []*directoryrosterv1.SlackSharedChannelDefinition{
		def("ab", "acme", []string{"globex"}, []string{"all:partners"}),
		def("ai", "acme", []string{"initech"}, []string{"all:partners"}),
		def("gi", "globex", []string{"initech"}, []string{"all:partners"}),
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
	if len(viewer.Groups) != 0 {
		t.Errorf("a viewer is offered groups to choose from: %v", viewer.Groups)
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
	if len(all.Channels) != 3 || len(all.Workspaces) != 3 || len(all.Groups) != 2 {
		t.Errorf("the installation-wide operator sees %d channels, %d workspaces, %d groups", len(all.Channels), len(all.Workspaces), len(all.Groups))
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
	if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
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
	raw, _ := connection.EncodeShared(reconcile.SharedChannel{Name: "stale", Host: "acme", With: []string{"gone"}, From: []string{"all:partners"}})
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
		if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
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
		err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"all:partners"}))
		wantCode(t, "create under endless conflict", err, connect.CodeAborted)
		if len(h.stored(t)) != 0 || len(h.recorded.Records()) != 0 {
			t.Errorf("a refused write left records %v, audit %d", h.stored(t), len(h.recorded.Records()))
		}
	})
	t.Run("the other writer's record is what an edit is decided against", func(t *testing.T) {
		h := newConnectHarness(t)
		if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"all:partners"})); err != nil {
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
		err := h.update(as(everywhere), def("partners", "acme", []string{"globex", "initech"}, []string{"all:partners"}))
		wantCode(t, "edit of a record deleted meanwhile", err, connect.CodeNotFound)
	})
}

func TestNoStoreIsRefusedPlainly(t *testing.T) {
	h := newConnectHarness(t)
	h.console.deps.SlackShared = nil
	wantCode(t, "create", h.create(as(everywhere), def("p", "acme", []string{"globex"}, []string{"all:partners"})), connect.CodeFailedPrecondition)
	if got := h.list(as(everywhere), t); got.Available {
		t.Error("available with no store")
	}
}
