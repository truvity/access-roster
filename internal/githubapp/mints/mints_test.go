package mints_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubapp/mints"
)

var start = time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)

func at(minutes int) time.Time { return start.Add(time.Duration(minutes) * time.Minute) }

// A page reads the last requests newest first, however many were asked
// for, and each App's are its own.
func TestRecentIsNewestFirstAndPerApp(t *testing.T) {
	t.Parallel()
	ring := mints.New(0, start)
	ring.Add("release-bot", mints.Token{At: at(1), Subject: "ci", Outcome: "ok"})
	ring.Add("docs-bot", mints.Token{At: at(2), Subject: "ada@north.example", Outcome: "ok"})
	ring.Add("release-bot", mints.Token{At: at(3), Subject: "workflow", Outcome: "refused"})

	recent := ring.Recent("release-bot")
	if len(recent) != 2 {
		t.Fatalf("release-bot kept %d requests, want 2", len(recent))
	}
	if !recent[0].At.Equal(at(3)) || !recent[1].At.Equal(at(1)) {
		t.Errorf("not newest first: %v", []time.Time{recent[0].At, recent[1].At})
	}
	if docs := ring.Recent("docs-bot"); len(docs) != 1 || docs[0].Subject != "ada@north.example" {
		t.Errorf("docs-bot kept %v, want one of its own", docs)
	}
}

// An App nobody has asked for a token of has nothing kept, which is not
// an error and not an empty page: the caller says "nothing yet".
func TestAnAppWithNothingAskedForKeepsNothing(t *testing.T) {
	t.Parallel()
	ring := mints.New(0, start)
	if kept := ring.Recent("labeler"); len(kept) != 0 {
		t.Errorf("labeler kept %v, want nothing", kept)
	}
	if kept := ring.Recent(""); len(kept) != 0 {
		t.Errorf("an unnamed App kept %v, want nothing", kept)
	}
}

// The ring is bounded per App: the oldest goes, and a busy App never
// grows this process.
func TestTheOldestGoesOnceTheRingIsFull(t *testing.T) {
	t.Parallel()
	ring := mints.New(3, start)
	for i := range 6 {
		ring.Add("release-bot", mints.Token{At: at(i), Outcome: "ok"})
	}
	recent := ring.Recent("release-bot")
	if len(recent) != 3 {
		t.Fatalf("kept %d, want the ring's 3", len(recent))
	}
	if !recent[0].At.Equal(at(5)) || !recent[2].At.Equal(at(3)) {
		t.Errorf("kept the wrong three: %v", []time.Time{recent[0].At, recent[2].At})
	}
	if ring.PerAppKept() != 3 {
		t.Errorf("says it keeps %d, keeps 3", ring.PerAppKept())
	}
}

// A request against no App is nowhere to show: nothing is kept for it.
// The id in a refused request is whatever the caller sent.
func TestARequestAgainstNoAppIsNotKept(t *testing.T) {
	t.Parallel()
	ring := mints.New(0, start)
	ring.Add("", mints.Token{At: at(1), Outcome: "refused"})
	ring.Add("   ", mints.Token{At: at(2), Outcome: "refused"})
	if kept := ring.Recent(""); len(kept) != 0 {
		t.Errorf("kept %v against no App", kept)
	}
}

// A group's page asks one thing: when its grant was last USED. A refusal
// under that grant is not a use, and another group's mint is not this
// group's.
func TestLastMintedIsTheLastOKUnderThatGrant(t *testing.T) {
	t.Parallel()
	ring := mints.New(0, start)
	ring.Add("release-bot", mints.Token{At: at(1), Grant: "rung:platform", Outcome: "ok"})
	ring.Add("release-bot", mints.Token{At: at(2), Grant: "all:gitops:deployer", Outcome: "ok"})
	ring.Add("release-bot", mints.Token{At: at(3), Grant: "rung:platform", Outcome: "refused"})

	when, minted := ring.LastMinted("release-bot", "rung:platform")
	if !minted || !when.Equal(at(1)) {
		t.Errorf("last minted %v (%t), want %v", when, minted, at(1))
	}
	if _, minted = ring.LastMinted("release-bot", "rung:engineering"); minted {
		t.Error("a group that has minted nothing is reported as having minted")
	}
	if _, minted = ring.LastMinted("docs-bot", "rung:platform"); minted {
		t.Error("another App's mint counted as this one's")
	}
}

// A nil ring is a deployment that keeps none: every reader answers
// nothing rather than crashing the page.
func TestANilRingAnswersNothing(t *testing.T) {
	t.Parallel()
	var ring *mints.Ring
	ring.Add("release-bot", mints.Token{At: at(1)})
	if kept := ring.Recent("release-bot"); len(kept) != 0 {
		t.Errorf("a nil ring kept %v", kept)
	}
	if _, minted := ring.LastMinted("release-bot", "rung:platform"); minted {
		t.Error("a nil ring reports a mint")
	}
	if ring.PerAppKept() != 0 || !ring.Since().IsZero() {
		t.Error("a nil ring claims to keep something")
	}
}

// Tokens are minted concurrently and the page is read while they are.
func TestAddAndRecentAreSafeTogether(t *testing.T) {
	t.Parallel()
	ring := mints.New(0, start)
	var wait sync.WaitGroup
	for i := range 50 {
		wait.Add(2)
		go func() {
			defer wait.Done()
			ring.Add("release-bot", mints.Token{At: at(i), Outcome: "ok", Permissions: strings.Repeat("a", i)})
		}()
		go func() {
			defer wait.Done()
			ring.Recent("release-bot")
		}()
	}
	wait.Wait()
	if kept := ring.Recent("release-bot"); len(kept) != mints.PerApp {
		t.Errorf("kept %d, want the ring's %d", len(kept), mints.PerApp)
	}
}
