package status_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

func sample() status.Workspace {
	return status.Workspace{
		Workspace: "acme",
		Enabled:   true,
		Tick:      status.Tick{At: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), Outcome: status.OutcomeHeld, Changes: 2, Held: 1, Retrying: 1, Waiting: 1},
		Channels: []status.Channel{
			{Name: "zeta", Mode: "extend", State: status.ChannelOK, Members: []status.Member{
				{Person: "b", Email: "b@acme.example", State: status.StateOK},
				{Person: "a", Email: "a@acme.example", UserID: "U1", State: status.StateWillInvite, Action: status.ActionInvite},
			}},
			{Name: "alpha", ID: "C1", Private: true, Mode: "strict", State: status.ChannelHeld, Reason: "invite the bot first",
				Breaker: &status.Breaker{Affected: 3, Total: 4, Fingerprint: "f00d"}},
			{Name: "shared", Shared: true, Host: "acme", Mode: "extend", State: status.ChannelWaiting, Reason: "globex has not accepted"},
		},
		Leavers: []status.Leaver{
			{Email: "z@acme.example", UserID: "U9", Channels: []string{"zeta", "alpha"}},
			{Email: "g@acme.example", UserID: "U8", Channels: []string{"alpha"}},
		},
		Breaker: &status.Breaker{Affected: 5, Total: 8, Fingerprint: "beef", Confirmed: true},
	}
}

func TestEncodeDecodeRoundTripsInAFixedOrder(t *testing.T) {
	t.Parallel()
	in := sample()
	raw, err := status.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := status.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != status.Version {
		t.Errorf("version = %d", out.Version)
	}
	var names []string
	for _, c := range out.Channels {
		names = append(names, c.Name)
	}
	if !reflect.DeepEqual(names, []string{"alpha", "shared", "zeta"}) {
		t.Errorf("channels not ordered: %v", names)
	}
	if out.Channels[2].Members[0].Person != "a" || out.Leavers[0].Email != "g@acme.example" ||
		!reflect.DeepEqual(out.Leavers[1].Channels, []string{"alpha", "zeta"}) {
		t.Errorf("members or leavers not ordered: %+v", out)
	}
	// The caller's own slices are not reordered.
	if in.Channels[0].Name != "zeta" || in.Channels[0].Members[0].Person != "b" {
		t.Errorf("Encode reordered the input")
	}
	again, _ := status.Encode(out)
	if again != raw {
		t.Errorf("encoding is not stable:\n%s\n%s", raw, again)
	}
	if !reflect.DeepEqual(out.Breaker, in.Breaker) || out.Tick != in.Tick || !out.Enabled {
		t.Errorf("round trip lost fields: %+v", out)
	}
}

func TestEncodeRefusesWhatItCannotKey(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"", "Acme", "_confirm", "a b", "-x", strings.Repeat("a", 41)} {
		if _, err := status.Encode(status.Workspace{Workspace: key}); err == nil {
			t.Errorf("Encode accepted the key %q", key)
		}
	}
	if _, err := status.Encode(status.Workspace{Workspace: "acme", Version: 9}); !errors.Is(err, status.ErrVersion) {
		t.Errorf("a foreign version: err = %v", err)
	}
}

func TestDecodeRefusesAnotherVersionAndGarbage(t *testing.T) {
	t.Parallel()
	if _, err := status.Decode(`{"version":2,"workspace":"acme"}`); !errors.Is(err, status.ErrVersion) {
		t.Errorf("version 2: err = %v", err)
	}
	if _, err := status.Decode(`{"workspace":"acme"}`); !errors.Is(err, status.ErrVersion) {
		t.Errorf("no version: err = %v", err)
	}
	if _, err := status.Decode(`not json`); err == nil {
		t.Error("garbage decoded")
	}
}

func TestKeysRoundTripAndAreNotOtherDocuments(t *testing.T) {
	t.Parallel()
	if status.Key("acme") != "acme.json" || status.ConfigMapName("rel") != "rel-slack-status" {
		t.Errorf("names: %s %s", status.Key("acme"), status.ConfigMapName("rel"))
	}
	if w, ok := status.WorkspaceOfKey("acme.json"); !ok || w != "acme" {
		t.Errorf("WorkspaceOfKey = %q %v", w, ok)
	}
	for _, key := range []string{"_confirm.acme.json", "acme", "Acme.json", ".json"} {
		if _, ok := status.WorkspaceOfKey(key); ok {
			t.Errorf("%q read as a workspace key", key)
		}
	}
}

func TestBreakerAndOutcomeMapRails(t *testing.T) {
	t.Parallel()
	if status.BreakerOf(nil) != nil {
		t.Error("nil breaker became non-nil")
	}
	b := status.BreakerOf(&rails.Breaker{Affected: 2, Total: 3, Fingerprint: "ab", Confirmed: true})
	if b.Affected != 2 || b.Total != 3 || b.Fingerprint != "ab" || !b.Confirmed {
		t.Errorf("BreakerOf = %+v", b)
	}
	for in, want := range map[rails.Outcome]status.Outcome{
		rails.OutcomeDryRun: status.OutcomeDryRun, rails.OutcomeApplied: status.OutcomeApplied,
		rails.OutcomeHeld: status.OutcomeHeld, rails.OutcomeRetrying: status.OutcomeRetrying,
		rails.OutcomeWaiting: status.OutcomeWaiting, rails.OutcomeInSync: status.OutcomeInSync,
	} {
		if got := status.OutcomeOf(in); got != want {
			t.Errorf("OutcomeOf(%v) = %s, want %s", in, got, want)
		}
	}
}

func TestDiscoveredSharedIsAdditiveAndEncodedInAFixedOrder(t *testing.T) {
	t.Parallel()
	in := sample()
	in.Team = "TACME"
	in.DiscoveredShared = []status.Discovered{
		{ID: "C2", Name: "zeta", Teams: []string{"TB", "TA"}},
		{ID: "C1", Name: "alpha", Private: true, Members: 3, HostTeam: "TA", Teams: []string{"TA", "TB"}, Managed: true},
	}
	raw, err := status.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := status.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Team != "TACME" || len(out.DiscoveredShared) != 2 || out.DiscoveredShared[0].Name != "alpha" || out.DiscoveredShared[1].Teams[0] != "TA" {
		t.Errorf("discovered = %+v", out.DiscoveredShared)
	}
	if in.DiscoveredShared[0].Name != "zeta" {
		t.Error("Encode reordered the caller's slice")
	}
	// A document from before the field decodes, with none.
	old, err := status.Decode(`{"version":1,"workspace":"acme","enabled":true,"tick":{"at":"2026-10-01T00:00:00Z","outcome":"in-sync","changes":0,"held":0}}`)
	if err != nil || len(old.DiscoveredShared) != 0 {
		t.Errorf("old document: %+v %v", old, err)
	}
}

func TestDiscoveredChannelsAndTheConsoleMarkAreAdditiveAndOrdered(t *testing.T) {
	t.Parallel()
	in := sample()
	in.Discovered = []status.Discovered{{ID: "C2", Name: "zeta"}, {ID: "G1", Name: "alpha", Private: true, Members: 3}}
	in.DiscoveredMore = 12
	in.Channels = append(in.Channels, status.Channel{Name: "club", Console: true, Mode: "strict", State: status.ChannelOK})
	raw, err := status.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := status.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Discovered) != 2 || out.Discovered[0].Name != "alpha" || !out.Discovered[0].Private || out.Discovered[0].Members != 3 || out.DiscoveredMore != 12 {
		t.Errorf("discovered = %+v more %d", out.Discovered, out.DiscoveredMore)
	}
	if in.Discovered[0].Name != "zeta" {
		t.Error("Encode reordered the caller's slice")
	}
	var club status.Channel
	for _, c := range out.Channels {
		if c.Name == "club" {
			club = c
		}
	}
	if !club.Console || club.Shared {
		t.Errorf("club = %+v", club)
	}
	// A document from before the fields decodes, with none, and a channel with
	// no console mark is not a console channel.
	old, err := status.Decode(`{"version":1,"workspace":"acme","enabled":true,` +
		`"tick":{"at":"2026-10-01T00:00:00Z","outcome":"in-sync","changes":0,"held":0},"channels":[{"name":"x","mode":"extend","state":"ok"}]}`)
	if err != nil || len(old.Discovered) != 0 || old.DiscoveredMore != 0 || old.Channels[0].Console {
		t.Errorf("old document: %+v %v", old, err)
	}
}

// The sides a host's tick probed round-trip, in a fixed order, and an old
// document with none still reads.
func TestGuestSidesRoundTripInAFixedOrder(t *testing.T) {
	w := status.Workspace{Workspace: "acme", GuestSides: []status.GuestSide{
		{Workspace: "initech", Discovered: status.Discovered{ID: "C2", Name: "b", Teams: []string{"T2", "T1"}}},
		{Workspace: "globex", Discovered: status.Discovered{ID: "C1", Name: "a"}},
	}}
	raw, err := status.Encode(w)
	if err != nil {
		t.Fatal(err)
	}
	got, err := status.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GuestSides) != 2 || got.GuestSides[0].Workspace != "globex" || got.GuestSides[1].Teams[0] != "T1" {
		t.Errorf("guest sides = %+v, want globex first and the teams sorted", got.GuestSides)
	}
	old, err := status.Decode(`{"version":1,"workspace":"acme","enabled":true,"tick":{}}`)
	if err != nil || len(old.GuestSides) != 0 {
		t.Errorf("a document with no guest sides = %+v, %v", old, err)
	}
}
