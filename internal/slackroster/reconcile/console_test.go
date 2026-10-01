package reconcile_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// consoleEnv is acme with one console channel fed by one directory group,
// whose members the directory lists.
func consoleEnv(c reconcile.ConsoleChannel, members ...string) *env {
	e := newEnv("acme")
	if c.Workspace == "" {
		c.Workspace = "acme"
	}
	if c.Name == "" {
		c.Name = "eng"
	}
	if c.Sources == nil {
		c.Sources = []string{"eng@acme.example"}
	}
	e.in.Console = append(e.in.Console, c)
	for _, m := range members {
		e.in.DirHolders[c.Sources[0]] = append(e.in.DirHolders[c.Sources[0]], rails.Holder{Email: m, Live: true})
	}
	return e
}

// A console channel is laid out like a policy channel: created when absent,
// its directory group's members invited, and reported as a console channel.
func TestAConsoleChannelIsCreatedAndItsGroupsMembersInvited(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Private: true}, "ann@acme.example").account("ann@acme.example", "U1")
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "create:eng", "invite:eng:U1")
	c := channelOf(t, dec, "eng")
	if !c.Console || c.Shared || c.Mode != "extend" || c.State != status.ChannelWillCreate {
		t.Errorf("channel = %+v", c)
	}
	if got := reconcile.Lookups(e.in); !slices.Equal(got, []string{"ann@acme.example"}) {
		t.Errorf("Lookups = %v", got)
	}
	// Policy holders of the same name never feed it: the sources are
	// directory groups, read from their own table.
	e.in.Holders["eng@acme.example"] = []rails.Holder{{Email: "intruder@acme.example", Live: true}}
	if got := reconcile.Lookups(e.in); !slices.Equal(got, []string{"ann@acme.example"}) {
		t.Errorf("Lookups with a policy group of the same name = %v", got)
	}
}

// A console channel in another workspace is not this workspace's.
func TestAConsoleChannelOfAnotherWorkspaceIsNotLaidOut(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Workspace: "globex"}, "ann@acme.example")
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec)
	if len(dec.Report.Channels) != 0 {
		t.Errorf("channels = %+v", dec.Report.Channels)
	}
}

// People are looked up by the owning directory's domains: a member of the
// group with an address in another domain has no path in this workspace, and
// is held, never guessed at.
func TestAConsoleChannelMemberWithNoPathHereIsHeld(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{}, "ann@acme.example", "gus@elsewhere.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng"}))
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "invite:eng:U1")
	if m := row(t, channelOf(t, dec, "eng"), "gus@elsewhere.example"); m.State != status.StateHeld || !strings.Contains(m.Reason, "no account path") {
		t.Errorf("row = %+v", m)
	}
}

// Extend only adds: whoever else is in the channel stays, whatever the
// directory says about them.
func TestAnExtendConsoleChannelNeverRemoves(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Private: true}, "ann@acme.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UX"}})).
		member("UX", "x@acme.example")
	dec := e.decide(t, vouch(gone(), "x@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec)
	if m := rowByUser(t, channelOf(t, dec, "eng"), "UX"); m.State != status.StateReported {
		t.Errorf("row = %+v, want a leaver reported, not removed", m)
	}
}

// Strict removes only on the directory's say-so, and what the directory is
// asked is about the DIRECTORY groups: somebody it still finds in the
// channel's group, or in a group that group nests, is never removed, however
// the holders list came out.
func TestAStrictConsoleChannelRemovesOnlyWhatTheDirectoryVouchesFor(t *testing.T) {
	t.Parallel()
	build := func() *env {
		e := consoleEnv(reconcile.ConsoleChannel{Private: true, Mode: policy.SlackModeStrict}, "ann@acme.example").account("ann@acme.example", "U1").
			channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UX"}})).
			member("UX", "x@acme.example")
		e.in.DirNested = map[string][]string{"eng@acme.example": {"nested@acme.example"}}
		return e
	}
	directory := func(groups ...string) rails.Vouch {
		return rails.Vouch{Authoritative: true, Found: true, DirectoryGroups: groups}
	}
	tests := map[string]struct {
		vouch rails.Vouch
		want  []string
	}{
		"in another group only":      {directory("other@acme.example"), []string{"remove:eng:UX"}},
		"in the group still":         {directory("eng@acme.example"), nil},
		"in a group it nests":        {directory("nested@acme.example"), nil},
		"gone from the directory":    {gone(), []string{"remove:eng:UX"}},
		"found, in an internal one":  {holds("eng@acme.example"), nil},
		"the directory cannot vouch": {rails.Vouch{Found: true}, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantKinds(t, build().decide(t, vouch(tc.vouch, "x@acme.example"), reconcile.Confirmed{}), tc.want...)
		})
	}
	// Asked about, so that the directory can vouch.
	if got := build().draft(t).Confirm(); !slices.Equal(got, []string{"x@acme.example"}) {
		t.Errorf("Confirm = %v", got)
	}
}

// A strict console channel never touches what a strict policy channel never
// touches, and honours its ignore list.
func TestAStrictConsoleChannelHonoursItsIgnoreListAndKeepsGuests(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Private: true, Mode: policy.SlackModeStrict, Ignore: []string{"boss@acme.example"}}, "ann@acme.example").
		account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UBOSS", "UGUEST", "UX"}})).
		memberOf(reconcile.Member{ID: "UBOSS", Email: "boss@acme.example", TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UGUEST", Email: "guest@acme.example", Guest: true, TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UX", Email: "x@acme.example", TeamID: "TACME"})
	dec := e.decide(t, vouch(gone(), "boss@acme.example", "x@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec, "remove:eng:UX")
	c := channelOf(t, dec, "eng")
	if m := rowByUser(t, c, "UBOSS"); m.State != status.StateIgnored {
		t.Errorf("boss = %+v", m)
	}
	if m := rowByUser(t, c, "UGUEST"); m.State != status.StateReported {
		t.Errorf("guest = %+v", m)
	}
}

// The breaker holds a console channel's removals past half of it, until an
// operator confirms exactly that set.
func TestAStrictConsoleChannelIsHeldByTheBreaker(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Private: true, Mode: policy.SlackModeStrict}, "ann@acme.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UX", "UY"}})).
		member("UX", "x@acme.example").member("UY", "y@acme.example")
	gones := vouch(gone(), "x@acme.example", "y@acme.example")
	dec := e.decide(t, gones, reconcile.Confirmed{})
	wantKinds(t, dec)
	if c := channelOf(t, dec, "eng"); c.Breaker == nil || c.Breaker.Confirmed {
		t.Errorf("breaker = %+v, want tripped", c.Breaker)
	}
	// An operator's confirmation of exactly that set lets it through.
	fp := channelOf(t, dec, "eng").Breaker.Fingerprint
	dec = e.decide(t, gones, reconcile.Confirmed{Channels: map[string]string{"eng": fp}})
	wantKinds(t, dec, "remove:eng:UX", "remove:eng:UY")
}

// A channel that exists, was not made by the bot, is taken over by name or
// by id, with the same visibility rules as a policy channel.
func TestAConsoleChannelTakesOverByNameOrIDAndNeverChangesVisibility(t *testing.T) {
	t.Parallel()
	byName := consoleEnv(reconcile.ConsoleChannel{Private: true}, "ann@acme.example").account("ann@acme.example", "U1").
		channel(reconcile.Channel{ID: "C1", Name: "eng", Private: true, BotIn: true, Creator: "UOTHER", Members: []string{"BACME"}})
	dec := byName.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "invite:eng:U1")
	if len(dec.Adopted) != 1 || dec.Adopted[0].ID != "C1" {
		t.Errorf("adopted = %+v", dec.Adopted)
	}
	byID := consoleEnv(reconcile.ConsoleChannel{Name: "renamed", ChannelID: "C0ELSEWHERE", Private: true}, "ann@acme.example").account("ann@acme.example", "U1").
		channel(reconcile.Channel{ID: "C0ELSEWHERE", Name: "other-name", Private: true, BotIn: true, Creator: "UOTHER", Members: []string{"BACME"}})
	wantKinds(t, byID.decide(t, nil, reconcile.Confirmed{}), "invite:renamed:U1")
	// Public in Slack, private in the record: held, never converted.
	mismatch := consoleEnv(reconcile.ConsoleChannel{Private: true}, "ann@acme.example").account("ann@acme.example", "U1").
		channel(reconcile.Channel{ID: "C1", Name: "eng", Private: false, BotIn: true, Creator: "UOTHER", Members: []string{"BACME"}})
	dec = mismatch.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec)
	if c := channelOf(t, dec, "eng"); c.State != status.ChannelHeld || !strings.Contains(c.Reason, "never changes visibility") {
		t.Errorf("channel = %+v", c)
	}
}

// A Slack Connect channel is fed by directory groups too, from the same
// table, and each person joins on the side that serves their address.
func TestASharedChannelIsFedByDirectoryGroups(t *testing.T) {
	t.Parallel()
	shared := reconcile.SharedChannel{Name: "joint", Host: "acme", With: []string{"globex"}, Sources: []string{"dir@acme.example"}}
	build := func(ws string) *env {
		e := newEnv(ws).shared(shared)
		e.in.DirHolders["dir@acme.example"] = []rails.Holder{{Email: "ann@acme.example", Live: true}, {Email: "bob@globex.example", Live: true}}
		// The policy's internal group of the same name feeds nothing here.
		e.in.Holders["dir@acme.example"] = []rails.Holder{{Email: "intruder@acme.example", Live: true}}
		return e
	}
	if got := reconcile.Lookups(build("acme").in); !slices.Equal(got, []string{"ann@acme.example"}) {
		t.Errorf("acme looks up %v", got)
	}
	if got := reconcile.Lookups(build("globex").in); !slices.Equal(got, []string{"bob@globex.example"}) {
		t.Errorf("globex looks up %v", got)
	}
}

// Whatever a Slack Connect record's strictness, nothing is removed: shared
// channels are extend.
func TestASharedChannelNeverRemoves(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").shared(reconcile.SharedChannel{Name: "joint", Host: "acme", With: []string{"globex"}, Sources: []string{"dir@acme.example"}}).
		account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "joint", Shared: true, Members: []string{"BACME", "U1", "UX"}, HostTeamID: "TACME"})).
		member("UX", "x@acme.example")
	e.in.DirHolders["dir@acme.example"] = []rails.Holder{{Email: "ann@acme.example", Live: true}}
	dec := e.decide(t, vouch(gone(), "x@acme.example"), reconcile.Confirmed{})
	for _, k := range kinds(dec) {
		if strings.HasPrefix(k, "remove:") {
			t.Errorf("a shared channel removed somebody: %v", kinds(dec))
		}
	}
}

// ------------------------------------------------------------------- validation

func TestAConsoleChannelIsValidatedAgainstThePolicy(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Groups: map[string]policy.Group{"g": {}},
		Slack: policy.Slack{Workspaces: map[string]policy.SlackWorkspace{
			"acme":   {Channels: map[string]policy.SlackChannel{"alerts": {From: []string{"g"}}, "legacy": {From: []string{"g"}, Adopt: "C0ADOPTED1"}}},
			"globex": {},
		}},
	}
	good := func() reconcile.ConsoleChannel {
		return reconcile.ConsoleChannel{Workspace: "acme", Name: "eng", Private: true, Mode: policy.SlackModeStrict, Sources: []string{"eng@acme.example"}}
	}
	if err := good().Validate(p); err != nil {
		t.Fatalf("a good record was refused: %v", err)
	}
	tests := map[string]struct {
		edit func(*reconcile.ConsoleChannel)
		want string
	}{
		"name uppercase":                {func(c *reconcile.ConsoleChannel) { c.Name = "Eng" }, "channel name"},
		"name empty":                    {func(c *reconcile.ConsoleChannel) { c.Name = "" }, "channel name"},
		"workspace undeclared":          {func(c *reconcile.ConsoleChannel) { c.Workspace = "hooli" }, "not a declared workspace"},
		"a policy channel of that name": {func(c *reconcile.ConsoleChannel) { c.Name = "alerts" }, "defined in git"},
		"a policy channel's adopted id": {func(c *reconcile.ConsoleChannel) { c.ChannelID = "C0ADOPTED1" }, "defined in git"},
		"not a channel id":              {func(c *reconcile.ConsoleChannel) { c.ChannelID = "nope" }, "not a Slack channel id"},
		"strict on a public channel":    {func(c *reconcile.ConsoleChannel) { c.Private = false }, "private channels only"},
		"a mode that is neither":        {func(c *reconcile.ConsoleChannel) { c.Mode = "exact" }, "neither extend nor strict"},
		"ignore without strict":         {func(c *reconcile.ConsoleChannel) { c.Mode, c.Ignore = "", []string{"x@acme.example"} }, "only allowed with mode strict"},
		"no sources":                    {func(c *reconcile.ConsoleChannel) { c.Sources = nil }, "no directory group"},
		"an internal group as a source": {func(c *reconcile.ConsoleChannel) { c.Sources = []string{"all:platform:engineer"} }, "not a directory group address"},
		"a source twice":                {func(c *reconcile.ConsoleChannel) { c.Sources = []string{"a@acme.example", "a@acme.example"} }, "twice"},
		"a source in capitals":          {func(c *reconcile.ConsoleChannel) { c.Sources = []string{"A@acme.example"} }, "not lowercase"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := good()
			tc.edit(&c)
			err := c.Validate(p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
	// "defined in git" is an error callers can recognise.
	c := good()
	c.Name = "alerts"
	if err := c.Validate(p); !errors.Is(err, reconcile.ErrDefinedInGit) {
		t.Errorf("Validate = %v, want ErrDefinedInGit", err)
	}
	// An extend record with an ignore list is refused only when ignore is set without strict.
	ok := good()
	ok.Mode, ok.Private = "", false
	if err := ok.Validate(p); err != nil {
		t.Errorf("an extend public channel was refused: %v", err)
	}
}

// ------------------------------------------------------------------- discovery

// Every channel the bot can see that nothing manages is discovered, by name;
// what a policy binding, a console record or a Slack Connect record manages
// is not, and neither are archived channels.
func TestEveryChannelNothingManagesIsDiscovered(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Name: "mine", Private: true}, "ann@acme.example").account("ann@acme.example", "U1").
		bind("alerts", extendCh("g")).bind("legacy", policy.SlackChannel{From: []string{"g"}, Adopt: "C0ADOPTED1"}).
		channel(ours(reconcile.Channel{ID: "C0MINE0001", Name: "mine", Private: true})).
		channel(reconcile.Channel{ID: "C0ALERTS01", Name: "alerts", BotIn: true}).
		channel(reconcile.Channel{ID: "C0ADOPTED1", Name: "renamed-in-slack", BotIn: true}).
		channel(reconcile.Channel{ID: "C0OPEN0001", Name: "random", NumMembers: 40}).
		channel(reconcile.Channel{ID: "G0PRIVATE1", Name: "secret", Private: true, BotIn: true, NumMembers: 3}).
		channel(reconcile.Channel{ID: "C0OLD00001", Name: "old", Archived: true}).
		channel(reconcile.Channel{ID: "C0GENERAL1", Name: "general", General: true, BotIn: true}).
		channel(reconcile.Channel{ID: "C0SHARED01", Name: "partners", Shared: true, HostTeamID: "TACME"})
	dec := e.decide(t, nil, reconcile.Confirmed{})
	var got []string
	for _, d := range dec.Report.Discovered {
		got = append(got, d.Name+":"+d.ID)
	}
	if want := []string{"random:C0OPEN0001", "secret:G0PRIVATE1"}; !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
	if d := dec.Report.Discovered[1]; !d.Private || d.Members != 3 {
		t.Errorf("the private channel = %+v", d)
	}
	if len(dec.Report.DiscoveredShared) != 1 || dec.Report.DiscoveredShared[0].Name != "partners" {
		t.Errorf("the shared channel is still discovered as shared: %+v", dec.Report.DiscoveredShared)
	}
	// Taken under management by a console record by id: gone from the list.
	e.in.Console = append(e.in.Console, reconcile.ConsoleChannel{Workspace: "acme", Name: "random", ChannelID: "C0OPEN0001", Sources: []string{"x@acme.example"}})
	for _, d := range e.decide(t, nil, reconcile.Confirmed{}).Report.Discovered {
		if d.ID == "C0OPEN0001" {
			t.Errorf("a managed channel is discovered: %+v", d)
		}
	}
}

// A workspace with more unmanaged channels than the report holds lists the
// first of them by name and counts the rest.
func TestDiscoveryIsCappedAndCountsWhatItLeftOut(t *testing.T) {
	t.Parallel()
	e := newEnv("acme")
	for i := range status.MaxDiscovered + 7 {
		id := "C0" + strings.Repeat("0", 6) + string(rune('A'+i%26)) + string(rune('A'+(i/26)%26)) + string(rune('A'+(i/676)%26))
		e.channel(reconcile.Channel{ID: id, Name: "chan-" + id})
	}
	dec := e.decide(t, nil, reconcile.Confirmed{})
	if len(dec.Report.Discovered) != status.MaxDiscovered || dec.Report.DiscoveredMore != 7 {
		t.Errorf("listed %d, more %d", len(dec.Report.Discovered), dec.Report.DiscoveredMore)
	}
	if !slices.IsSortedFunc(dec.Report.Discovered, func(a, b status.Discovered) int { return strings.Compare(a.Name, b.Name) }) {
		t.Error("discovered channels are not in name order")
	}
}
