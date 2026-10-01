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

// env is one workspace's input, built up by each test.
type env struct {
	in reconcile.Input
}

func newEnv(ws string) *env {
	team := map[string]string{"acme": "TACME", "globex": "TGLOBEX"}
	domain := map[string]string{"acme": "acme.example", "globex": "globex.example"}
	e := &env{in: reconcile.Input{
		Workspace: ws,
		Workspaces: map[string]policy.SlackWorkspace{
			"acme":   {},
			"globex": {},
		},
		// What is recorded and read at run time, not declared: each workspace
		// is owned by a directory, which serves the domains it is found by.
		Facts: map[string]reconcile.Facts{
			"acme":   {Team: "TACME", Owner: "C0acme", Domains: []string{domain["acme"]}},
			"globex": {Team: "TGLOBEX", Owner: "C0globex", Domains: []string{domain["globex"]}},
		},
		People:  map[string][]string{"jdoe": {"j.doe@acme.example", "john@globex.example"}},
		Holders: rails.Holders{},
		Bots:    map[string]string{"acme": "BACME", "globex": "BGLOBEX"},
		Observed: reconcile.Observed{
			TeamID: team[ws], BotUserID: "B" + strings.ToUpper(ws),
			Accounts: map[string]reconcile.Account{}, Members: map[string]reconcile.Member{},
		},
	}}
	return e
}

func (e *env) bind(name string, c policy.SlackChannel) *env {
	ws := e.in.Workspaces[e.in.Workspace]
	if ws.Channels == nil {
		ws.Channels = map[string]policy.SlackChannel{}
	}
	ws.Channels[name] = c
	e.in.Workspaces[e.in.Workspace] = ws
	return e
}

func (e *env) holders(group string, addrs ...string) *env {
	for _, a := range addrs {
		e.in.Holders[group] = append(e.in.Holders[group], rails.Holder{Email: a, Live: true})
	}
	return e
}

func (e *env) account(addr, id string) *env {
	e.in.Observed.Accounts[strings.ToLower(addr)] = reconcile.Account{ID: id, Found: true, TeamID: e.in.Observed.TeamID}
	return e
}

func (e *env) noAccount(addr string) *env {
	e.in.Observed.Accounts[strings.ToLower(addr)] = reconcile.Account{}
	return e
}

func (e *env) channel(c reconcile.Channel) *env {
	c.MembersKnown = true
	e.in.Observed.Channels = append(e.in.Observed.Channels, c)
	return e
}

func (e *env) member(id, email string) *env {
	e.in.Observed.Members[id] = reconcile.Member{ID: id, Email: email, TeamID: e.in.Observed.TeamID}
	return e
}

func (e *env) memberOf(m reconcile.Member) *env {
	e.in.Observed.Members[m.ID] = m
	return e
}

func (e *env) shared(s reconcile.SharedChannel) *env {
	e.in.Shared = append(e.in.Shared, s)
	return e
}

func (e *env) draft(t *testing.T) *reconcile.Draft {
	t.Helper()
	d, err := reconcile.Derive(e.in)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	return d
}

func (e *env) decide(t *testing.T, vouches map[string]rails.Vouch, confirmed reconcile.Confirmed) reconcile.Decision {
	t.Helper()
	return e.draft(t).Decide(vouches, confirmed)
}

// Vouches.
func gone() rails.Vouch { return rails.Vouch{Authoritative: true} }
func holds(groups ...string) rails.Vouch {
	return rails.Vouch{Authoritative: true, Found: true, Groups: groups}
}
func foundElsewhere() rails.Vouch { return rails.Vouch{Authoritative: true, Found: true} }

func vouch(v rails.Vouch, addrs ...string) map[string]rails.Vouch {
	out := map[string]rails.Vouch{}
	for _, a := range addrs {
		out[a] = v
	}
	return out
}

func merge(maps ...map[string]rails.Vouch) map[string]rails.Vouch {
	out := map[string]rails.Vouch{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// helpers to read a decision.

func kinds(d reconcile.Decision) []string {
	var out []string
	for i := range d.Actions {
		a := &d.Actions[i]
		s := string(a.Kind) + ":" + a.Channel
		if a.User != "" {
			s += ":" + a.User
		}
		out = append(out, s)
	}
	return out
}

func channelOf(t *testing.T, d reconcile.Decision, name string) status.Channel {
	t.Helper()
	for i := range d.Report.Channels {
		if d.Report.Channels[i].Name == name {
			return d.Report.Channels[i]
		}
	}
	t.Fatalf("no channel %q in %+v", name, d.Report.Channels)
	return status.Channel{}
}

func row(t *testing.T, c status.Channel, person string) status.Member {
	t.Helper()
	for _, m := range c.Members {
		if m.Person == person {
			return m
		}
	}
	t.Fatalf("no row for %q in %+v", person, c.Members)
	return status.Member{}
}

func rowByUser(t *testing.T, c status.Channel, id string) status.Member {
	t.Helper()
	for _, m := range c.Members {
		if m.UserID == id {
			return m
		}
	}
	t.Fatalf("no row for user %q in %+v", id, c.Members)
	return status.Member{}
}

func wantKinds(t *testing.T, d reconcile.Decision, want ...string) {
	t.Helper()
	got := kinds(d)
	if !slices.Equal(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
}

func inv(id string, incoming bool, host, channel, recipient string) reconcile.Invite {
	return reconcile.Invite{ID: id, Incoming: incoming, HostTeamID: host, ChannelName: channel, RecipientUserID: recipient}
}

func extendCh(groups ...string) policy.SlackChannel { return policy.SlackChannel{From: groups} }
func strictCh(groups ...string) policy.SlackChannel {
	return policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: groups}
}

func ours(ch reconcile.Channel) reconcile.Channel {
	ch.Creator = "BACME"
	ch.BotIn = true
	return ch
}

// ---------------------------------------------------------------- rule 1

// A person is looked up by the address in one of the workspace's domains:
// the directory's own if it is in-domain, else another address of the same
// person; with none, there is no account path, which is held.
func TestAPersonIsLookedUpByTheirAddressInTheWorkspacesDomains(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		workspace string
		holder    string
		lookup    string // empty: no path
	}{
		"the directory address is in-domain":                {"acme", "ann@acme.example", "ann@acme.example"},
		"the directory address is uppercased":               {"acme", "Ann@Acme.Example", "ann@acme.example"},
		"another address of the same person is in-domain":   {"acme", "john@globex.example", "j.doe@acme.example"},
		"the other workspace takes the other address":       {"globex", "j.doe@acme.example", "john@globex.example"},
		"a person not in people has one address only":       {"globex", "ann@acme.example", ""},
		"an address in no workspace's domain has no path":   {"acme", "x@elsewhere.example", ""},
		"the people table does not reach a foreign address": {"acme", "x@elsewhere.example", ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(tc.workspace).bind("eng", extendCh("g")).holders("g", tc.holder)
			lookups := reconcile.Lookups(e.in)
			if tc.lookup == "" {
				if len(lookups) != 0 {
					t.Fatalf("Lookups = %v, want none", lookups)
				}
				e.channel(reconcile.Channel{ID: "C1", Name: "eng", Creator: e.in.Observed.BotUserID, BotIn: true})
				d := e.decide(t, nil, reconcile.Confirmed{})
				m := channelOf(t, d, "eng").Members[0]
				if m.State != status.StateHeld || !strings.Contains(m.Reason, "no account path") {
					t.Errorf("row = %+v", m)
				}
				if len(d.Actions) != 0 || len(d.Held) != 1 || d.Held[0].Change != "invite" {
					t.Errorf("actions %v held %+v", d.Actions, d.Held)
				}
				return
			}
			if !slices.Equal(lookups, []string{tc.lookup}) {
				t.Errorf("Lookups = %v, want [%s]", lookups, tc.lookup)
			}
		})
	}
}

// The domains a person is looked up by are the OWNING directory's served
// domains, read at run time: serving another domain moves a person into the
// workspace, and a workspace with no owner holds every person, saying why.
func TestPeopleAreLookedUpByTheOwningDirectorysServedDomains(t *testing.T) {
	t.Parallel()
	t.Run("a domain the owner starts serving finds a person", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example", "bob@acme.example.org")
		if got := reconcile.Lookups(e.in); !slices.Equal(got, []string{"ann@acme.example"}) {
			t.Fatalf("Lookups = %v, want only the served domain's address", got)
		}
		facts := e.in.Facts["acme"]
		facts.Domains = []string{"acme.example", "Acme.Example.Org"}
		e.in.Facts["acme"] = facts
		if got := reconcile.Lookups(e.in); !slices.Equal(got, []string{"ann@acme.example", "bob@acme.example.org"}) {
			t.Fatalf("Lookups after the owner serves a second domain = %v", got)
		}
	})
	t.Run("a workspace with no owner holds its people", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example")
		e.in.Facts["acme"] = reconcile.Facts{Team: "TACME"}
		if got := reconcile.Lookups(e.in); len(got) != 0 {
			t.Fatalf("Lookups = %v, want none without an owner", got)
		}
		e.channel(reconcile.Channel{ID: "C1", Name: "eng", Creator: e.in.Observed.BotUserID, BotIn: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		m := channelOf(t, d, "eng").Members[0]
		if m.State != status.StateHeld || m.Reason != reconcile.NoOwner {
			t.Errorf("row = %+v, want held with %q", m, reconcile.NoOwner)
		}
		if len(d.Actions) != 0 {
			t.Errorf("actions = %v, want none", d.Actions)
		}
	})
	t.Run("an owner serving no domains is not an absent owner", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example")
		e.in.Facts["acme"] = reconcile.Facts{Team: "TACME", Owner: "C0acme"}
		e.channel(reconcile.Channel{ID: "C1", Name: "eng", Creator: e.in.Observed.BotUserID, BotIn: true})
		m := channelOf(t, e.decide(t, nil, reconcile.Confirmed{}), "eng").Members[0]
		if m.State != status.StateHeld || !strings.Contains(m.Reason, "no account path") {
			t.Errorf("row = %+v", m)
		}
	})
}

// ---------------------------------------------------------------- rule 2

func TestWantedMembersAreTheHoldersOfTheBoundGroupsOnePerPerson(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", extendCh("g1", "g2")).
		holders("g1", "ann@acme.example", "j.doe@acme.example", "gone@acme.example").
		holders("g2", "ann@acme.example", "john@globex.example")
	// a suspended holder is not wanted
	e.in.Holders["g1"] = append(e.in.Holders["g1"], rails.Holder{Email: "susp@acme.example", Live: false})
	if got := reconcile.Lookups(e.in); !slices.Equal(got, []string{"ann@acme.example", "gone@acme.example", "j.doe@acme.example"}) {
		t.Fatalf("Lookups = %v", got)
	}
	e.account("ann@acme.example", "U1").account("j.doe@acme.example", "U2").noAccount("gone@acme.example")
	e.channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Members: []string{"BACME"}}))
	d := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, d, "invite:eng:U1", "invite:eng:U2")
	c := channelOf(t, d, "eng")
	if len(c.Members) != 3 {
		t.Fatalf("rows = %+v", c.Members)
	}
	if got := d.Actions[1]; got.Person != "jdoe" || !slices.Equal(got.Groups, []string{"g1", "g2"}) {
		t.Errorf("the merged person = %+v", got)
	}
}

// ---------------------------------------------------------------- rule 5

func TestAChannelIsCreatedWhenAbsentAndItsPeopleInvitedInTheSamePass(t *testing.T) {
	t.Parallel()
	for _, private := range []bool{false, true} {
		e := newEnv("acme").bind("eng", policy.SlackChannel{Private: private, From: []string{"g"}}).holders("g", "ann@acme.example")
		e.account("ann@acme.example", "U1")
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "create:eng", "invite:eng:U1")
		if d.Actions[0].Private != private || d.Actions[1].ChannelID != "" {
			t.Errorf("private=%v: %+v", private, d.Actions)
		}
		if c := channelOf(t, d, "eng"); c.State != status.ChannelWillCreate || c.ID != "" {
			t.Errorf("channel = %+v", c)
		}
	}
}

func TestAdoptIsByIDAndNeverCreates(t *testing.T) {
	t.Parallel()
	adopt := func(private bool) policy.SlackChannel {
		return policy.SlackChannel{Private: private, From: []string{"g"}, Adopt: "C0123ABCD"}
	}
	t.Run("a public channel the bot is not in is joined, then filled", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", adopt(false)).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C0123ABCD", Name: "whatever"})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "adopt:eng", "invite:eng:U1")
		if d.Actions[0].ChannelID != "C0123ABCD" || d.Actions[1].ChannelID != "C0123ABCD" {
			t.Errorf("ids: %+v", d.Actions)
		}
		if c := channelOf(t, d, "eng"); c.State != status.ChannelWillAdopt || c.ID != "C0123ABCD" {
			t.Errorf("channel = %+v", c)
		}
	})
	t.Run("a channel the bot is already in needs no join", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", adopt(false)).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C0123ABCD", Name: "whatever", BotIn: true, Members: []string{"BACME", "U1"}})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d)
		if c := channelOf(t, d, "eng"); c.State != status.ChannelOK || row(t, c, "ann@acme.example").State != status.StateOK {
			t.Errorf("channel = %+v", c)
		}
	})
	t.Run("a private channel the bot cannot see is held, never created", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", adopt(true)).holders("g", "ann@acme.example").account("ann@acme.example", "U1")
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d)
		c := channelOf(t, d, "eng")
		if c.State != status.ChannelHeld || !strings.Contains(c.Reason, "invite the bot first") {
			t.Errorf("channel = %+v", c)
		}
		if row(t, c, "ann@acme.example").State != status.StateHeld || len(d.Held) != 1 || d.Held[0].Change != "adopt" {
			t.Errorf("rows %+v held %+v", c.Members, d.Held)
		}
	})
	t.Run("a private channel seen but with the bot outside is held", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", adopt(true)).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C0123ABCD", Name: "eng", Private: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d)
		if c := channelOf(t, d, "eng"); c.State != status.ChannelHeld || !strings.Contains(c.Reason, "invite the bot first") {
			t.Errorf("channel = %+v", c)
		}
	})
	t.Run("a visibility that disagrees with the policy is held, never changed", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", adopt(true)).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C0123ABCD", Name: "eng", BotIn: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d)
		if c := channelOf(t, d, "eng"); c.State != status.ChannelHeld || !strings.Contains(c.Reason, "public in Slack but the policy says private") {
			t.Errorf("channel = %+v", c)
		}
	})
	t.Run("a Slack Connect channel is not adopted as a plain one", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", adopt(false)).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C0123ABCD", Name: "eng", BotIn: true, Shared: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		if c := channelOf(t, d, "eng"); c.State != status.ChannelHeld || len(d.Actions) != 0 {
			t.Errorf("channel = %+v actions %v", c, d.Actions)
		}
	})
}

// A bound channel is an idempotent upsert: created when no channel of that
// name is visible, otherwise taken over BY NAME, with `adopt` only
// disambiguating. What is never done is held, with the reason.
func TestABoundChannelIsCreatedOrTakenOverByNameAndOurOwnIsManaged(t *testing.T) {
	t.Parallel()
	t.Run("an existing public channel the bot did not create is adopted by name: joined, then managed", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C9", Name: "eng", Creator: "USOMEONE"})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "adopt:eng", "invite:eng:U1")
		if c := channelOf(t, d, "eng"); c.State != status.ChannelWillAdopt || c.ID != "C9" {
			t.Errorf("channel = %+v", c)
		}
		if len(d.Held) != 0 || len(d.Adopted) != 1 || d.Adopted[0] != (reconcile.Adoption{Channel: "eng", ID: "C9", Joins: true}) {
			t.Errorf("held %+v adopted %+v", d.Held, d.Adopted)
		}
	})
	t.Run("a private channel the bot is in is adopted by name and managed, with nothing to join", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", policy.SlackChannel{Private: true, From: []string{"g"}}).holders("g", "ann@acme.example").
			account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C9", Name: "eng", Creator: "USOMEONE", Private: true, BotIn: true, Members: []string{"BACME"}})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "invite:eng:U1")
		if len(d.Held) != 0 || len(d.Adopted) != 1 || d.Adopted[0] != (reconcile.Adoption{Channel: "eng", ID: "C9", Private: true}) {
			t.Errorf("held %+v adopted %+v", d.Held, d.Adopted)
		}
	})
	t.Run("adopt is only a disambiguation: a channel under another name, by id", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", policy.SlackChannel{From: []string{"g"}, Adopt: "C9"}).holders("g", "ann@acme.example").
			account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C9", Name: "engineering", Creator: "USOMEONE", BotIn: true}).
			channel(reconcile.Channel{ID: "C8", Name: "eng", Creator: "USOMEONE", BotIn: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "invite:eng:U1")
		if d.Actions[0].ChannelID != "C9" || len(d.Adopted) != 1 || d.Adopted[0].ID != "C9" {
			t.Errorf("actions %+v adopted %+v: the id wins over a channel of the declared name", d.Actions, d.Adopted)
		}
	})
	t.Run("a visibility that disagrees with the declared one is held, never converted", func(t *testing.T) {
		t.Parallel()
		for name, c := range map[string]struct {
			declared policy.SlackChannel
			existing reconcile.Channel
			want     string
		}{
			"public in Slack, private declared": {
				policy.SlackChannel{Private: true, From: []string{"g"}},
				reconcile.Channel{ID: "C9", Name: "eng", Creator: "USOMEONE", BotIn: true}, "public in Slack but the policy says private"},
			"private in Slack, public declared": {
				extendCh("g"),
				reconcile.Channel{ID: "C9", Name: "eng", Creator: "USOMEONE", Private: true, BotIn: true}, "private in Slack but the policy says public"},
		} {
			e := newEnv("acme").bind("eng", c.declared).holders("g", "ann@acme.example").account("ann@acme.example", "U1").channel(c.existing)
			d := e.decide(t, nil, reconcile.Confirmed{})
			wantKinds(t, d)
			if got := channelOf(t, d, "eng"); got.State != status.ChannelHeld || !strings.Contains(got.Reason, c.want) {
				t.Errorf("%s: channel = %+v", name, got)
			}
			if len(d.Adopted) != 0 {
				t.Errorf("%s: adopted %+v a channel it holds", name, d.Adopted)
			}
		}
	})
	t.Run("an archived channel of that name is held, never unarchived or created again", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C9", Name: "eng", Creator: "USOMEONE", Archived: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d)
		got := channelOf(t, d, "eng")
		if got.State != status.ChannelHeld || !strings.Contains(got.Reason, "archived: unarchive it in Slack or rename it") {
			t.Errorf("channel = %+v", got)
		}
		if len(d.Held) != 1 || d.Held[0].Change != "adopt" || len(d.Adopted) != 0 {
			t.Errorf("held %+v adopted %+v", d.Held, d.Adopted)
		}
		// Likewise when it is named by id.
		e = newEnv("acme").bind("eng", policy.SlackChannel{From: []string{"g"}, Adopt: "C9"}).holders("g", "ann@acme.example").
			channel(reconcile.Channel{ID: "C9", Name: "eng", Archived: true})
		if got = channelOf(t, e.decide(t, nil, reconcile.Confirmed{}), "eng"); got.State != status.ChannelHeld || !strings.Contains(got.Reason, "archived") {
			t.Errorf("an archived channel named by id = %+v", got)
		}
	})
	t.Run("a Slack Connect channel of that name is not adopted as a plain one", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(reconcile.Channel{ID: "C9", Name: "eng", Creator: "USOMEONE", BotIn: true, Shared: true})
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d)
		if got := channelOf(t, d, "eng"); got.State != status.ChannelHeld || !strings.Contains(got.Reason, "Slack Connect") {
			t.Errorf("channel = %+v", got)
		}
	})
	t.Run("a channel the bot created is ours, not an adoption", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(ours(reconcile.Channel{ID: "C9", Name: "eng", Members: []string{"BACME"}}))
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "invite:eng:U1")
		if len(d.Adopted) != 0 {
			t.Errorf("adopted %+v a channel the bot made", d.Adopted)
		}
	})
	t.Run("a channel with no visible namesake is created", func(t *testing.T) {
		t.Parallel()
		d := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "create:eng", "invite:eng:U1")
	})
	t.Run("a channel the bot created last pass is ours", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
			channel(ours(reconcile.Channel{ID: "C9", Name: "eng", Members: []string{"BACME"}}))
		d := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, d, "invite:eng:U1")
		if d.Actions[0].ChannelID != "C9" {
			t.Errorf("action = %+v", d.Actions[0])
		}
	})
}

// ---------------------------------------------------------------- rule 6

func TestAPersonWithoutAnAccountIsHeldNeverAnError(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", extendCh("g")).
		holders("g", "new@acme.example", "off@acme.example", "robot@acme.example", "guest@acme.example", "other@acme.example", "ok@acme.example")
	e.noAccount("new@acme.example")
	e.in.Observed.Accounts["off@acme.example"] = reconcile.Account{ID: "U2", Found: true, Deleted: true, TeamID: "TACME"}
	e.in.Observed.Accounts["robot@acme.example"] = reconcile.Account{ID: "U3", Found: true, Bot: true, TeamID: "TACME"}
	e.in.Observed.Accounts["guest@acme.example"] = reconcile.Account{ID: "U4", Found: true, Guest: true, TeamID: "TACME"}
	e.in.Observed.Accounts["other@acme.example"] = reconcile.Account{ID: "U5", Found: true, TeamID: "TELSEWHERE"}
	e.account("ok@acme.example", "U6")
	e.channel(ours(reconcile.Channel{ID: "C1", Name: "eng"}))
	d := e.decide(t, nil, reconcile.Confirmed{})
	c := channelOf(t, d, "eng")
	for person, want := range map[string]struct {
		state  status.State
		reason string
	}{
		"new@acme.example":   {status.StateHeld, "no Slack account yet"},
		"off@acme.example":   {status.StateHeld, "deactivated"},
		"robot@acme.example": {status.StateHeld, "bot"},
		"other@acme.example": {status.StateHeld, "another workspace"},
		"guest@acme.example": {status.StateReported, "guests are never invited"},
		"ok@acme.example":    {status.StateWillInvite, ""},
	} {
		m := row(t, c, person)
		if m.State != want.state || !strings.Contains(m.Reason, want.reason) {
			t.Errorf("%s: %+v, want %v %q", person, m, want.state, want.reason)
		}
	}
	wantKinds(t, d, "invite:eng:U6")
	if len(d.Held) != 4 || d.Report.Tick.Held != 4 || d.Report.Tick.Changes != 1 {
		t.Errorf("held %+v tick %+v", d.Held, d.Report.Tick)
	}
}

// ---------------------------------------------------------------- rules 3, 4: mode

func TestExtendOnlyAddsWhateverIsInTheChannel(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", policy.SlackChannel{Private: true, From: []string{"g"}}).holders("g", "ann@acme.example").
		account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "UX", "UY"}})).
		member("UX", "extra@acme.example").member("UY", "extra2@acme.example")
	d := e.draft(t)
	dec := d.Decide(merge(vouch(gone(), "extra@acme.example", "extra2@acme.example")), reconcile.Confirmed{})
	for _, a := range dec.Actions {
		if a.Kind == status.ActionRemove {
			t.Errorf("an extend channel removed %+v", a)
		}
	}
	wantKinds(t, dec, "invite:eng:U1")
	if c := channelOf(t, dec, "eng"); c.Mode != "extend" {
		t.Errorf("mode = %q", c.Mode)
	}
}

func strictEnv() *env {
	return newEnv("acme").bind("eng", strictCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1")
}

func TestStrictRemovesExtrasTheDirectoryVouchesFor(t *testing.T) {
	t.Parallel()
	e := strictEnv().
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UX"}})).
		member("UX", "left@acme.example")
	d := e.draft(t)
	if got := d.Confirm(); !slices.Equal(got, []string{"left@acme.example"}) {
		t.Fatalf("Confirm = %v", got)
	}
	dec := d.Decide(vouch(gone(), "left@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec, "remove:eng:UX")
	c := channelOf(t, dec, "eng")
	if m := rowByUser(t, c, "UX"); m.State != status.StateWillRemove || m.Action != status.ActionRemove {
		t.Errorf("row = %+v", m)
	}
	if c.Mode != "strict" || dec.Actions[0].ChannelID != "C1" {
		t.Errorf("channel %+v action %+v", c, dec.Actions[0])
	}
	// a member removed because they lost the group, not because they left
	dec = d.Decide(vouch(foundElsewhere(), "left@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec, "remove:eng:UX")
}

func TestStrictRemovalRestsOnTheDirectoryOrDoesNotHappen(t *testing.T) {
	t.Parallel()
	e := strictEnv().
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UX"}})).
		member("UX", "left@acme.example")
	tests := map[string]struct {
		vouches map[string]rails.Vouch
		state   status.State
		reason  string
	}{
		"nobody asked":                     {nil, status.StateRetrying, "was not asked"},
		"the directory cannot vouch":       {vouch(rails.Vouch{Authoritative: false}, "left@acme.example"), status.StateRetrying, "cannot vouch"},
		"the directory still says a group": {vouch(holds("g"), "left@acme.example"), status.StateOK, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dec := e.decide(t, tc.vouches, reconcile.Confirmed{})
			wantKinds(t, dec)
			m := rowByUser(t, channelOf(t, dec, "eng"), "UX")
			if m.State != tc.state || !strings.Contains(m.Reason, tc.reason) {
				t.Errorf("row = %+v", m)
			}
			if tc.state == status.StateRetrying && dec.Report.Tick.Retrying != 1 {
				t.Errorf("tick = %+v", dec.Report.Tick)
			}
		})
	}
}

func TestStrictNeverTouchesBotsSelfDeletedGuestsForeignOrIgnored(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", policy.SlackChannel{
		Private: true, Mode: policy.SlackModeStrict, From: []string{"g"},
		Ignore: []string{"Boss@acme.example", "USPARE0001"},
	}).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true,
			Members: []string{"BACME", "U1", "UBOT", "UAPP", "UDEL", "UGUEST", "UFOREIGN", "UNOMAIL", "UBOSS", "UBOSS2", "USPARE0001", "UREAL"}})).
		memberOf(reconcile.Member{ID: "UBOT", Email: "", Bot: true, TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UAPP", Bot: true, TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UDEL", Email: "del@acme.example", Deleted: true, TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UGUEST", Email: "guest@acme.example", Guest: true, TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UFOREIGN", Email: "f@globex.example", TeamID: "TGLOBEX"}).
		memberOf(reconcile.Member{ID: "UNOMAIL", TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UBOSS", Email: "boss@acme.example", TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UBOSS2", Email: "BOSS@ACME.EXAMPLE", TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "USPARE0001", Email: "spare@acme.example", TeamID: "TACME"}).
		memberOf(reconcile.Member{ID: "UREAL", Email: "real@acme.example", TeamID: "TACME"})
	d := e.draft(t)
	// Ignored people are asked about only to report them gone; guests, other
	// workspaces' accounts and accounts with no address are never asked.
	if got := d.Confirm(); !slices.Equal(got, []string{"boss@acme.example", "real@acme.example", "spare@acme.example"}) {
		t.Fatalf("Confirm = %v", got)
	}
	dec := d.Decide(merge(vouch(gone(), "real@acme.example")), reconcile.Confirmed{})
	wantKinds(t, dec, "remove:eng:UREAL")
	c := channelOf(t, dec, "eng")
	want := map[string]status.State{
		"UGUEST": status.StateReported, "UFOREIGN": status.StateReported, "UNOMAIL": status.StateReported,
		"UBOSS": status.StateIgnored, "UBOSS2": status.StateIgnored, "USPARE0001": status.StateIgnored,
	}
	for id, state := range want {
		if m := rowByUser(t, c, id); m.State != state {
			t.Errorf("%s: %+v, want %v", id, m, state)
		}
	}
	for _, id := range []string{"UBOT", "UAPP", "UDEL", "BACME"} {
		for _, m := range c.Members {
			if m.UserID == id {
				t.Errorf("%s has a row: %+v", id, m)
			}
		}
	}
}

func TestIgnoreMatchesAnyAddressOfThePersonOrTheUserID(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: []string{"g"},
		Ignore: []string{"john@globex.example"}}).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "UJ"}})).
		member("UJ", "j.doe@acme.example")
	dec := e.decide(t, vouch(gone(), "j.doe@acme.example", "john@globex.example"), reconcile.Confirmed{})
	wantKinds(t, dec)
	if m := rowByUser(t, channelOf(t, dec, "eng"), "UJ"); m.State != status.StateIgnored {
		t.Errorf("row = %+v", m)
	}
}

func TestAMemberWhoIsWantedUnderAnotherAddressIsNotAnExtra(t *testing.T) {
	t.Parallel()
	// jdoe holds g under the globex address, looked up by the acme one; a
	// second account under the other address is the same person.
	e := newEnv("acme").bind("eng", strictCh("g")).holders("g", "john@globex.example").account("j.doe@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "U2"}})).
		member("U2", "john@globex.example")
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec)
}

// ---------------------------------------------------------------- rule 7

// breakerEnv is a strict channel of n members of whom the first `gone` left.
func breakerEnv(total, leaving int) (*env, []string) {
	e := newEnv("acme").bind("eng", strictCh("g"))
	members := []string{"BACME"}
	var addrs []string
	for i := range total {
		id := "U" + string(rune('A'+i))
		addr := "m" + string(rune('a'+i)) + "@acme.example"
		members = append(members, id)
		e.member(id, addr)
		if i >= total-leaving {
			addrs = append(addrs, addr)
		} else {
			e.holders("g", addr).account(addr, id)
		}
	}
	e.channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: members}))
	return e, addrs
}

func TestTheChannelBreakerHoldsRemovalsOverHalfUnlessTheExactSetIsConfirmed(t *testing.T) {
	t.Parallel()
	// 3 of 6 is exactly half: goes ahead.
	e, gone3 := breakerEnv(6, 3)
	dec := e.decide(t, vouch(gone(), gone3...), reconcile.Confirmed{})
	if len(dec.Actions) != 3 || dec.Report.Channels[0].Breaker != nil {
		t.Fatalf("half must pass: %v %+v", kinds(dec), dec.Report.Channels[0].Breaker)
	}

	// 4 of 6 trips.
	e, gone4 := breakerEnv(6, 4)
	dec = e.decide(t, vouch(gone(), gone4...), reconcile.Confirmed{})
	c := dec.Report.Channels[0]
	if len(dec.Actions) != 0 || c.Breaker == nil || c.Breaker.Affected != 4 || c.Breaker.Total != 6 || c.Breaker.Confirmed || c.Breaker.Fingerprint == "" {
		t.Fatalf("over half must hold: %v %+v", kinds(dec), c.Breaker)
	}
	for _, m := range c.Members {
		if m.State == status.StateWillRemove {
			t.Errorf("a held removal is still will-remove: %+v", m)
		}
	}
	// One hold per gate: the channel's, and the workspace's (here the same set).
	if len(dec.Held) != 2 || dec.Held[0].Change != "remove" || dec.Held[1].Change != "remove" {
		t.Errorf("held = %+v", dec.Held)
	}
	fp := c.Breaker.Fingerprint

	// One confirmation of the fingerprint satisfies every gate that
	// fingerprint covers: here the channel's and the workspace's are the same
	// set, so either place it was confirmed lets the removals go.
	for name, confirmed := range map[string]reconcile.Confirmed{
		"channel":   {Channels: map[string]string{"eng": fp}},
		"workspace": {Workspace: fp},
	} {
		dec = e.decide(t, vouch(gone(), gone4...), confirmed)
		if len(dec.Actions) != 4 || !dec.Report.Channels[0].Breaker.Confirmed || !dec.Report.Breaker.Confirmed || len(dec.Held) != 0 {
			t.Errorf("confirmed once at the %s: %v ch %+v ws %+v held %v", name, kinds(dec), dec.Report.Channels[0].Breaker, dec.Report.Breaker, dec.Held)
		}
	}

	// A confirmation of a different set does not.
	dec = e.decide(t, vouch(gone(), gone4...), reconcile.Confirmed{Channels: map[string]string{"eng": "0000"}, Workspace: "1111"})
	if len(dec.Actions) != 0 {
		t.Errorf("a confirmation of another set let removals through: %v", kinds(dec))
	}
	// The set changed (one fewer leaver still over half): the old fingerprint is void.
	dec = e.decide(t, vouch(gone(), gone4[:3]...), reconcile.Confirmed{Channels: map[string]string{"eng": fp}, Workspace: fp})
	if len(dec.Actions) != 3 {
		// 3 of 6 is half: passes by itself; the point is it is not the confirmed set.
		t.Errorf("reduced set: %v", kinds(dec))
	}
}

// A strict channel the roster adopted removes only after the usual
// vouching, and the first pass after adopting it is subject to the breaker
// like any other: taking a channel over is not a licence to empty it.
func TestAnAdoptedStrictChannelIsHeldToTheBreakerAndTheVouchingOnTheFirstPass(t *testing.T) {
	t.Parallel()
	// 4 of 6 would leave: over half.
	e, gone4 := breakerEnv(6, 4)
	e.in.Observed.Channels[0].Creator = "USOMEONE" // adopted, not made by the bot
	dec := e.decide(t, vouch(gone(), gone4...), reconcile.Confirmed{})
	c := dec.Report.Channels[0]
	if len(dec.Adopted) != 1 || len(dec.Actions) != 0 || c.Breaker == nil || c.Breaker.Affected != 4 || c.Breaker.Confirmed {
		t.Fatalf("adopted %+v actions %v breaker %+v: the first pass after adoption must trip the breaker", dec.Adopted, kinds(dec), c.Breaker)
	}

	// 3 of 6 is half and passes the breaker, and still needs the directory's word.
	e, gone3 := breakerEnv(6, 3)
	e.in.Observed.Channels[0].Creator = "USOMEONE"
	if dec = e.decide(t, nil, reconcile.Confirmed{}); len(dec.Actions) != 0 {
		t.Errorf("removals with no vouching from the directory: %v", kinds(dec))
	}
	if dec = e.decide(t, vouch(gone(), gone3...), reconcile.Confirmed{}); len(dec.Actions) != 3 || len(dec.Adopted) != 1 {
		t.Errorf("vouched removals in an adopted channel: %v adopted %+v", kinds(dec), dec.Adopted)
	}
}

func TestTheWorkspaceBreakerCountsPeopleAcrossChannels(t *testing.T) {
	t.Parallel()
	// Two strict channels over the same six accounts. Each removes three
	// (half of six, under its own breaker); together they remove all six.
	e := newEnv("acme").bind("a", strictCh("g")).bind("b", strictCh("g"))
	ids := []string{"U1", "U2", "U3", "U4", "U5", "U6"}
	var addrs []string
	for i, id := range ids {
		addr := "p" + strings.ToLower(id) + "@acme.example"
		addrs = append(addrs, addr)
		e.member(id, addr)
		_ = i
	}
	e.channel(ours(reconcile.Channel{ID: "CA", Name: "a", Private: true, Members: append([]string{"BACME"}, ids...)}))
	e.channel(ours(reconcile.Channel{ID: "CB", Name: "b", Private: true, Members: append([]string{"BACME"}, ids...)}))
	// The directory wants only the first three in a, and the last three in b:
	// use two groups.
	e.in.Workspaces["acme"] = policy.SlackWorkspace{Channels: map[string]policy.SlackChannel{
		"a": strictCh("ga"), "b": strictCh("gb"),
	}}
	e.holders("ga", addrs[:3]...).holders("gb", addrs[3:]...)
	for i, id := range ids {
		e.account(addrs[i], id)
	}
	vouches := map[string]rails.Vouch{}
	for _, a := range addrs[3:] {
		vouches[a] = holds("gb") // still hold gb: not a candidate for b, candidate for a
	}
	for _, a := range addrs[:3] {
		vouches[a] = holds("ga")
	}
	d := e.draft(t)
	dec := d.Decide(vouches, reconcile.Confirmed{})
	if dec.Report.Breaker == nil || dec.Report.Breaker.Affected != 6 || dec.Report.Breaker.Total != 6 {
		t.Fatalf("workspace breaker = %+v, actions %v", dec.Report.Breaker, kinds(dec))
	}
	if len(dec.Actions) != 0 {
		t.Errorf("removals went ahead over the workspace limit: %v", kinds(dec))
	}
	for _, c := range dec.Report.Channels {
		if c.Breaker != nil {
			t.Errorf("channel %s breaker should be under the limit: %+v", c.Name, c.Breaker)
		}
	}
	held := false
	for _, h := range dec.Held {
		held = held || (h.Channel == "" && h.Change == "remove")
	}
	if !held {
		t.Errorf("no workspace-level hold recorded: %+v", dec.Held)
	}
	// Confirming the workspace set lets all through.
	dec = d.Decide(vouches, reconcile.Confirmed{Workspace: dec.Report.Breaker.Fingerprint})
	if len(dec.Actions) != 6 || !dec.Report.Breaker.Confirmed {
		t.Errorf("confirmed workspace: %v %+v", kinds(dec), dec.Report.Breaker)
	}
}

// ---------------------------------------------------------------- rule 9

func TestALeaverStillInAChannelIsReportedNotActedOn(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", extendCh("g")).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Members: []string{"BACME", "U1", "ULEFT", "UOUT", "UPART"}})).
		member("ULEFT", "left@acme.example").
		member("UOUT", "someone@elsewhere.example").
		member("UPART", "part@acme.example")
	d := e.draft(t)
	if got := d.Confirm(); !slices.Equal(got, []string{"left@acme.example", "part@acme.example"}) {
		t.Fatalf("Confirm = %v (an address outside the workspace's domains is never asked)", got)
	}
	dec := d.Decide(merge(vouch(gone(), "left@acme.example"), vouch(foundElsewhere(), "part@acme.example")), reconcile.Confirmed{})
	wantKinds(t, dec)
	if len(dec.Report.Leavers) != 1 || dec.Report.Leavers[0].UserID != "ULEFT" || dec.Report.Leavers[0].Email != "left@acme.example" ||
		!slices.Equal(dec.Report.Leavers[0].Channels, []string{"eng"}) {
		t.Fatalf("leavers = %+v", dec.Report.Leavers)
	}
	if m := rowByUser(t, channelOf(t, dec, "eng"), "ULEFT"); m.State != status.StateReported {
		t.Errorf("row = %+v", m)
	}
	// Still in the directory, or not vouched: nobody is reported.
	dec = d.Decide(merge(vouch(rails.Vouch{Authoritative: false}, "left@acme.example")), reconcile.Confirmed{})
	if len(dec.Report.Leavers) != 0 {
		t.Errorf("an unvouched answer reported a leaver: %+v", dec.Report.Leavers)
	}
	dec = d.Decide(vouch(rails.Vouch{Authoritative: true, Found: true, Suspended: true}, "left@acme.example"), reconcile.Confirmed{})
	if len(dec.Report.Leavers) != 1 {
		t.Errorf("a suspended account is gone: %+v", dec.Report.Leavers)
	}
}

func TestALeaverInAStrictChannelIsRemovedNotOnlyReportedUnlessIgnored(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").bind("eng", policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: []string{"g"}, Ignore: []string{"keep@acme.example"}}).
		holders("g", "ann@acme.example").account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "ULEFT", "UKEEP"}})).
		member("ULEFT", "left@acme.example").member("UKEEP", "keep@acme.example")
	dec := e.decide(t, merge(vouch(gone(), "left@acme.example", "keep@acme.example")), reconcile.Confirmed{})
	wantKinds(t, dec, "remove:eng:ULEFT")
	if len(dec.Report.Leavers) != 1 || dec.Report.Leavers[0].UserID != "UKEEP" {
		t.Errorf("leavers = %+v", dec.Report.Leavers)
	}
}

// ---------------------------------------------------------------- rule 10

func TestAPartialReadFailsTheDecisionNeverReadsAsNoAccount(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*env){
		"an address was never looked up": func(e *env) { delete(e.in.Observed.Accounts, "ann@acme.example") },
		"a member nobody identified": func(e *env) {
			e.in.Observed.Channels[0].Members = append(e.in.Observed.Channels[0].Members, "UMYSTERY")
		},
		"the members of the channel were not read": func(e *env) { e.in.Observed.Channels[0].MembersKnown = false },
	}
	for name, cut := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := strictEnv().channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME"}}))
			cut(e)
			if _, err := reconcile.Derive(e.in); !errors.Is(err, reconcile.ErrIncomplete) {
				t.Fatalf("err = %v, want ErrIncomplete", err)
			}
		})
	}
}

// ---------------------------------------------------------------- rule 8

func sharedPlatform() reconcile.SharedChannel {
	return reconcile.SharedChannel{Name: "platform", Host: "acme", With: []string{"globex"}, From: []string{"g"}}
}

func TestSharedHostCreatesInvitesGuestBotThenItsOwnPeople(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").shared(sharedPlatform()).holders("g", "ann@acme.example", "bob@globex.example").account("ann@acme.example", "U1")
	if got := reconcile.Lookups(e.in); !slices.Equal(got, []string{"ann@acme.example"}) {
		t.Fatalf("the host looks up only its own people: %v", got)
	}
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "create:platform", "share-invite:platform", "invite:platform:U1")
	share := dec.Actions[1]
	if share.Guest != "globex" || share.GuestBot != "BGLOBEX" || share.Host != "acme" || !share.Shared {
		t.Errorf("share = %+v", share)
	}
	c := channelOf(t, dec, "platform")
	if !c.Shared || c.Host != "acme" || c.State != status.ChannelWillCreate || c.Mode != "extend" {
		t.Errorf("channel = %+v", c)
	}
	if len(c.Members) != 1 {
		t.Errorf("globex's person is not the host's row: %+v", c.Members)
	}
}

func TestSharedHostCreatesWithItsOwnSidesPrivacy(t *testing.T) {
	t.Parallel()
	s := sharedPlatform()
	s.Private = reconcile.Privacy{PerSide: map[string]bool{"acme": true, "globex": false}}
	e := newEnv("acme").shared(s).holders("g", "ann@acme.example").account("ann@acme.example", "U1")
	if a := e.decide(t, nil, reconcile.Confirmed{}).Actions[0]; !a.Private {
		t.Errorf("host side must be private: %+v", a)
	}
	e = newEnv("globex").shared(s).holders("g", "bob@globex.example").account("bob@globex.example", "U2")
	e.in.Observed.Invites = []reconcile.Invite{inv("I1", true, "TACME", "platform", "BGLOBEX")}
	dec := e.decide(t, nil, reconcile.Confirmed{})
	if a := dec.Actions[0]; a.Kind != status.ActionShareAccept || a.Private {
		t.Errorf("guest side is public: %+v", a)
	}
}

func TestSharedHostStateMachine(t *testing.T) {
	t.Parallel()
	existing := reconcile.Channel{ID: "C1", Name: "platform", Creator: "BACME", BotIn: true, Members: []string{"BACME"}}
	t.Run("already shared with the guest: nothing to send", func(t *testing.T) {
		t.Parallel()
		c := existing
		c.Shared, c.SharedTeamIDs = true, []string{"TACME", "TGLOBEX"}
		e := newEnv("acme").shared(sharedPlatform()).channel(c)
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec)
		if got := channelOf(t, dec, "platform"); got.State != status.ChannelOK {
			t.Errorf("channel = %+v", got)
		}
	})
	t.Run("an invitation pending: waiting, not sent again, not held", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").shared(sharedPlatform()).channel(existing)
		e.in.Observed.Invites = []reconcile.Invite{{ID: "I1", ChannelID: "C1", ChannelName: "platform", RecipientUserID: "BGLOBEX"}}
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec)
		c := channelOf(t, dec, "platform")
		if c.State != status.ChannelWaiting || !strings.Contains(c.Reason, "waiting for globex to accept") || len(dec.Held) != 0 || dec.Report.Tick.Waiting != 1 {
			t.Errorf("channel = %+v held %+v tick %+v", c, dec.Held, dec.Report.Tick)
		}
	})
	t.Run("the channel exists, shared with nobody, no invitation: invite with its id", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").shared(sharedPlatform()).channel(existing)
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec, "share-invite:platform")
		if dec.Actions[0].ChannelID != "C1" {
			t.Errorf("action = %+v", dec.Actions[0])
		}
	})
	t.Run("a guest whose bot is unknown is held", func(t *testing.T) {
		t.Parallel()
		e := newEnv("acme").shared(sharedPlatform()).channel(existing)
		delete(e.in.Bots, "globex")
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec)
		c := channelOf(t, dec, "platform")
		if c.State != status.ChannelHeld || len(dec.Held) != 1 || dec.Held[0].Change != "share-invite" {
			t.Errorf("channel = %+v held %+v", c, dec.Held)
		}
	})
	t.Run("several guests: each is handled on its own", func(t *testing.T) {
		t.Parallel()
		s := sharedPlatform()
		s.With = []string{"globex", "initech"}
		e := newEnv("acme").shared(s).channel(func() reconcile.Channel {
			c := existing
			c.Shared, c.SharedTeamIDs = true, []string{"TACME", "TGLOBEX"}
			return c
		}())
		e.in.Workspaces["initech"] = policy.SlackWorkspace{}
		e.in.Facts["initech"] = reconcile.Facts{Team: "TINITECH", Owner: "C0initech", Domains: []string{"initech.example"}}
		e.in.Bots["initech"] = "BINITECH"
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec, "share-invite:platform")
		if dec.Actions[0].Guest != "initech" {
			t.Errorf("action = %+v", dec.Actions[0])
		}
	})
	t.Run("a channel of that name the roster did not create is held", func(t *testing.T) {
		t.Parallel()
		c := existing
		c.Creator = "USOMEONE"
		e := newEnv("acme").shared(sharedPlatform()).channel(c)
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec)
		if got := channelOf(t, dec, "platform"); got.State != status.ChannelHeld {
			t.Errorf("channel = %+v", got)
		}
	})
}

func TestSharedGuestAcceptsOnlyTheHostsInvitationForThatChannel(t *testing.T) {
	t.Parallel()
	good := inv("I1", true, "TACME", "platform", "BGLOBEX")
	tests := map[string]struct {
		invites []reconcile.Invite
		accept  bool
	}{
		"the host's invitation":             {[]reconcile.Invite{good}, true},
		"another channel's invitation":      {[]reconcile.Invite{inv("I2", true, "TACME", "other", "BGLOBEX")}, false},
		"another team's invitation":         {[]reconcile.Invite{inv("I3", true, "TSTRANGER", "platform", "BGLOBEX")}, false},
		"an invitation to somebody else":    {[]reconcile.Invite{inv("I4", true, "TACME", "platform", "USOMEONE")}, false},
		"an outgoing invitation of our own": {[]reconcile.Invite{inv("I5", false, "TACME", "platform", "BGLOBEX")}, false},
		"the right one among others":        {[]reconcile.Invite{inv("I6", true, "TSTRANGER", "platform", "BGLOBEX"), good}, true},
		"no invitation yet":                 {nil, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv("globex").shared(sharedPlatform()).holders("g", "bob@globex.example").account("bob@globex.example", "U2")
			e.in.Observed.Invites = tc.invites
			dec := e.decide(t, nil, reconcile.Confirmed{})
			c := channelOf(t, dec, "platform")
			if tc.accept {
				wantKinds(t, dec, "share-accept:platform", "invite:platform:U2")
				a := dec.Actions[0]
				if a.InviteID != "I1" || a.Host != "acme" || a.Guest != "globex" || c.State != status.ChannelWillAccept {
					t.Errorf("accept = %+v channel %+v", a, c)
				}
				return
			}
			wantKinds(t, dec)
			if c.State != status.ChannelWaiting || len(dec.Held) != 0 || len(c.Members) != 0 {
				t.Errorf("not invited yet must be waiting, not held: %+v held %+v", c, dec.Held)
			}
		})
	}
}

func TestSharedGuestManagesItsOwnPeopleInTheAcceptedChannel(t *testing.T) {
	t.Parallel()
	e := newEnv("globex").shared(sharedPlatform()).holders("g", "ann@acme.example", "bob@globex.example", "cy@globex.example").
		account("bob@globex.example", "U2").account("cy@globex.example", "U3").
		channel(reconcile.Channel{ID: "C1", Name: "from-acme", Shared: true, BotIn: true, Members: []string{"BGLOBEX", "U2", "UHOST"}})
	e.in.Observed.Channels[0].Name = "platform"
	e.member("UHOST", "ann@acme.example")
	e.in.Observed.Members["UHOST"] = reconcile.Member{ID: "UHOST", Email: "ann@acme.example", TeamID: "TACME"}
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "invite:platform:U3")
	c := channelOf(t, dec, "platform")
	if row(t, c, "bob@globex.example").State != status.StateOK || len(c.Members) != 2 {
		t.Errorf("rows = %+v", c.Members)
	}
	// Host's people are never touched and never asked about.
	if got := e.draft(t).Confirm(); len(got) != 0 {
		t.Errorf("Confirm = %v", got)
	}
}

func TestSharedPeopleJoinFromTheHostElseTheFirstGuestElseAreHeld(t *testing.T) {
	t.Parallel()
	s := reconcile.SharedChannel{Name: "platform", Host: "acme", With: []string{"globex", "initech"}, From: []string{"g"}}
	workspaces := func(e *env) {
		e.in.Workspaces["initech"] = policy.SlackWorkspace{}
		e.in.Facts["initech"] = reconcile.Facts{Team: "TINITECH", Owner: "C0initech", Domains: []string{"initech.example"}}
		e.in.Bots["initech"] = "BINITECH"
		e.in.People["multi"] = []string{"m@globex.example", "m@initech.example"}
		e.in.People["both"] = []string{"b@acme.example", "b@globex.example"}
		e.in.People["late"] = []string{"l@initech.example"}
	}
	holdersFor := func(e *env) {
		e.holders("g", "m@initech.example", "b@globex.example", "l@initech.example", "x@nowhere.example")
	}
	// Which workspace looks up whom.
	want := map[string][]string{
		"acme":    {"b@acme.example"},
		"globex":  {"m@globex.example"},
		"initech": {"l@initech.example"},
	}
	for ws, lookups := range want {
		e := newEnv(ws).shared(s)
		workspaces(e)
		holdersFor(e)
		if got := reconcile.Lookups(e.in); !slices.Equal(got, lookups) {
			t.Errorf("%s looks up %v, want %v", ws, got, lookups)
		}
	}
	// The host reports the person nobody can reach.
	e := newEnv("acme").shared(s)
	workspaces(e)
	holdersFor(e)
	e.account("b@acme.example", "U1")
	dec := e.decide(t, nil, reconcile.Confirmed{})
	c := channelOf(t, dec, "platform")
	m := row(t, c, "x@nowhere.example")
	if m.State != status.StateHeld || !strings.Contains(m.Reason, "no account path in any workspace") {
		t.Errorf("unreachable person row = %+v", m)
	}
	// And the guests do not list them.
	e = newEnv("globex").shared(s)
	workspaces(e)
	holdersFor(e)
	e.account("m@globex.example", "U2")
	e.in.Observed.Invites = []reconcile.Invite{inv("I1", true, "TACME", "platform", "BGLOBEX")}
	dec = e.decide(t, nil, reconcile.Confirmed{})
	for _, r := range channelOf(t, dec, "platform").Members {
		if r.Person == "x@nowhere.example" {
			t.Errorf("a guest reported the unreachable person: %+v", r)
		}
	}
}

func TestSharedChannelsNeverRemove(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").shared(sharedPlatform()).holders("g", "ann@acme.example").account("ann@acme.example", "U1").
		channel(reconcile.Channel{ID: "C1", Name: "platform", Creator: "BACME", BotIn: true, Private: false, Shared: true,
			SharedTeamIDs: []string{"TACME", "TGLOBEX"}, Members: []string{"BACME", "U1", "UX"}}).
		member("UX", "extra@acme.example")
	d := e.draft(t)
	dec := d.Decide(vouch(gone(), "extra@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec)
	// but a leaver in it is still reported
	if len(dec.Report.Leavers) != 1 || dec.Report.Leavers[0].UserID != "UX" {
		t.Errorf("leavers = %+v", dec.Report.Leavers)
	}
}

// ---------------------------------------------------------------- ordering and the rest

func TestActionsAreOrderedCreateShareInviteRemove(t *testing.T) {
	t.Parallel()
	e := newEnv("acme").
		bind("zz-new", extendCh("g")).
		bind("aa-strict", strictCh("g")).
		shared(sharedPlatform()).
		holders("g", "ann@acme.example", "bob@acme.example").
		account("ann@acme.example", "U1").account("bob@acme.example", "U2").
		channel(ours(reconcile.Channel{ID: "C1", Name: "aa-strict", Private: true, Members: []string{"BACME", "U1", "UX"}})).
		member("UX", "left@acme.example")
	dec := e.decide(t, vouch(gone(), "left@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec,
		"create:zz-new", "create:platform",
		"share-invite:platform",
		"invite:aa-strict:U2", "invite:zz-new:U1", "invite:zz-new:U2", "invite:platform:U1", "invite:platform:U2",
		"remove:aa-strict:UX")
	if dec.Report.Tick.Changes != len(dec.Actions) || dec.Report.Workspace != "acme" {
		t.Errorf("tick %+v", dec.Report.Tick)
	}
}

func TestDecisionIsDeterministic(t *testing.T) {
	t.Parallel()
	build := func() reconcile.Decision {
		e := newEnv("acme").bind("a", extendCh("g")).bind("b", extendCh("g")).
			holders("g", "z@acme.example", "a@acme.example", "m@acme.example").
			account("z@acme.example", "U1").account("a@acme.example", "U2").account("m@acme.example", "U3")
		return e.decide(t, nil, reconcile.Confirmed{})
	}
	first := build()
	for range 20 {
		if got := build(); !slices.Equal(kinds(got), kinds(first)) {
			t.Fatalf("order changed: %v vs %v", kinds(got), kinds(first))
		}
	}
}

func TestHeldKeysDistinguishChannelPersonChangeAndReason(t *testing.T) {
	t.Parallel()
	a := reconcile.Held{Channel: "c", Person: "p", Change: "invite", Reason: "r"}
	for _, b := range []reconcile.Held{
		{Channel: "d", Person: "p", Change: "invite", Reason: "r"},
		{Channel: "c", Person: "q", Change: "invite", Reason: "r"},
		{Channel: "c", Person: "p", Change: "remove", Reason: "r"},
		{Channel: "c", Person: "p", Change: "invite", Reason: "s"},
	} {
		if a.Key() == b.Key() {
			t.Errorf("%+v and %+v share a key", a, b)
		}
	}
}

func TestDeriveRefusesAnUndeclaredWorkspace(t *testing.T) {
	t.Parallel()
	e := newEnv("acme")
	e.in.Workspace = "nope"
	if _, err := reconcile.Derive(e.in); err == nil {
		t.Error("an undeclared workspace was derived")
	}
}

// ---------------------------------------------------------------- shared definitions

func TestSharedChannelValidation(t *testing.T) {
	t.Parallel()
	base := func() policy.Policy {
		return policy.Policy{
			Groups: map[string]policy.Group{"g": {}},
			Slack: policy.Slack{Workspaces: map[string]policy.SlackWorkspace{
				"acme":    {Channels: map[string]policy.SlackChannel{"eng": {From: []string{"g"}}}},
				"globex":  {},
				"initech": {},
			}},
		}
	}
	good := func() reconcile.SharedChannel {
		return reconcile.SharedChannel{Name: "platform", Host: "acme", With: []string{"globex"}, From: []string{"g"}}
	}
	if err := good().Validate(base()); err != nil {
		t.Fatalf("a good definition was refused: %v", err)
	}
	ok := good()
	ok.With = []string{"globex", "initech"}
	ok.Private = reconcile.Privacy{PerSide: map[string]bool{"acme": true, "globex": false, "initech": true}}
	if err := ok.Validate(base()); err != nil {
		t.Fatalf("per-side privacy naming every side was refused: %v", err)
	}
	tests := map[string]struct {
		edit func(*reconcile.SharedChannel)
		want string
	}{
		"name uppercase":         {func(s *reconcile.SharedChannel) { s.Name = "Platform" }, "channel name"},
		"name too long":          {func(s *reconcile.SharedChannel) { s.Name = strings.Repeat("a", 81) }, "channel name"},
		"name empty":             {func(s *reconcile.SharedChannel) { s.Name = "" }, "channel name"},
		"host undeclared":        {func(s *reconcile.SharedChannel) { s.Host = "hooli" }, "host"},
		"name binds on the host": {func(s *reconcile.SharedChannel) { s.Name = "eng" }, "already binds"},
		"with empty":             {func(s *reconcile.SharedChannel) { s.With = nil }, "shares with no workspace"},
		"with undeclared":        {func(s *reconcile.SharedChannel) { s.With = []string{"hooli"} }, "not a declared workspace"},
		"host in with":           {func(s *reconcile.SharedChannel) { s.With = []string{"acme"} }, "also listed in with"},
		"with twice":             {func(s *reconcile.SharedChannel) { s.With = []string{"globex", "globex"} }, "twice"},
		"from empty":             {func(s *reconcile.SharedChannel) { s.From = nil }, "fed by no group"},
		"from undeclared":        {func(s *reconcile.SharedChannel) { s.From = []string{"nobody"} }, "not a declared group"},
		"per side misses a side": {func(s *reconcile.SharedChannel) {
			s.Private = reconcile.Privacy{PerSide: map[string]bool{"acme": true}}
		}, "names no value for globex"},
		"per side names a stranger": {func(s *reconcile.SharedChannel) {
			s.Private = reconcile.Privacy{PerSide: map[string]bool{"acme": true, "globex": true, "initech": true}}
		}, "neither the host nor in with"},
		"per side empty": {func(s *reconcile.SharedChannel) { s.Private = reconcile.Privacy{PerSide: map[string]bool{}} }, "names no value"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := good()
			tc.edit(&s)
			err := s.Validate(base())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestPrivacyIsOneValueOrPerSide(t *testing.T) {
	t.Parallel()
	if !(reconcile.Privacy{All: true}).IsPrivate("any") || (reconcile.Privacy{}).IsPrivate("any") {
		t.Error("the single value is not used for every side")
	}
	p := reconcile.Privacy{PerSide: map[string]bool{"acme": true}}
	if !p.IsPrivate("acme") || p.IsPrivate("globex") {
		t.Error("per-side values are not honoured")
	}
}

// An archived channel keeps its name, so a shared channel of that name is
// held on either side, like a bound one: never joined, unarchived or created
// again beside it.
func TestAnArchivedSharedChannelIsHeldOnBothSides(t *testing.T) {
	t.Parallel()
	archived := reconcile.Channel{ID: "C1", Name: "platform", Creator: "BACME", Archived: true, Shared: true}
	for side, e := range map[string]*env{
		"host":  newEnv("acme").shared(sharedPlatform()).holders("g", "ann@acme.example").account("ann@acme.example", "U1").channel(archived),
		"guest": newEnv("globex").shared(sharedPlatform()).holders("g", "bob@globex.example").account("bob@globex.example", "U2").channel(archived),
	} {
		if side == "guest" {
			e.in.Observed.Invites = []reconcile.Invite{inv("I1", true, "TACME", "platform", "BGLOBEX")}
		}
		dec := e.decide(t, nil, reconcile.Confirmed{})
		wantKinds(t, dec)
		got := channelOf(t, dec, "platform")
		if got.State != status.ChannelHeld || !strings.Contains(got.Reason, "archived: unarchive it in Slack or rename it") {
			t.Errorf("%s: channel = %+v", side, got)
		}
		if len(dec.Held) != 1 {
			t.Errorf("%s: held = %+v", side, dec.Held)
		}
	}
	// Not shared in Slack but archived, on the host side as well.
	plain := archived
	plain.Shared = false
	if dec := newEnv("acme").shared(sharedPlatform()).channel(plain).decide(t, nil, reconcile.Confirmed{}); len(dec.Actions) != 0 {
		t.Errorf("an archived plain channel of the host's name was acted on: %+v", dec.Actions)
	}
}
