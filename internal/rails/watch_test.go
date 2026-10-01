package rails_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/rails"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Entries are sorted, leave out the kubelet's dot-files, and an absent or
// unnamed directory has none.
func TestEntriesListAMountedDirectoryWithoutItsBookkeeping(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "b.json", "{}")
	write(t, dir, "a.json", "{}")
	write(t, dir, "..data", "x")
	got := rails.Entries(dir, quiet())
	if len(got) != 2 || got[0] != "a.json" || got[1] != "b.json" {
		t.Errorf("entries = %v", got)
	}
	if rails.Entries("", quiet()) != nil || rails.Entries(filepath.Join(dir, "absent"), quiet()) != nil {
		t.Error("an empty or absent directory has entries")
	}
}

// The digest changes with a kept file's content or name, and with nothing
// else.
func TestDigestChangesOnlyWithWhatIsKept(t *testing.T) {
	dir := t.TempDir()
	keep := func(name string) bool { return !strings.HasPrefix(name, "_") }
	digest := func() [32]byte { return rails.Digest(quiet(), []string{dir}, keep) }
	write(t, dir, "a.json", "1")
	base := digest()
	if digest() != base {
		t.Fatal("the digest is not stable")
	}
	write(t, dir, "_reserved.json", "x")
	if digest() != base {
		t.Error("a file that is not kept changed the digest")
	}
	write(t, dir, "a.json", "2")
	if digest() == base {
		t.Error("changed content left the digest alone")
	}
}

// A request for a pass is kept when there is none, refused within the gap of
// the last, and kept again past it; an unreadable one is replaced.
func TestGateKeepsOneRequestPerGap(t *testing.T) {
	decode := func(raw string) (time.Time, error) { return time.Parse(time.RFC3339, raw) }
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	records := map[string]string{}
	if kept, last := rails.Gate(records, "k", at.Format(time.RFC3339), at, decode); !kept || !last.IsZero() {
		t.Fatalf("first = %v, %v", kept, last)
	}
	soon := at.Add(rails.PassGap - time.Second)
	if kept, last := rails.Gate(records, "k", soon.Format(time.RFC3339), soon, decode); kept || !last.Equal(at) {
		t.Errorf("within the gap = %v, %v", kept, last)
	}
	later := at.Add(rails.PassGap)
	if kept, _ := rails.Gate(records, "k", later.Format(time.RFC3339), later, decode); !kept {
		t.Error("past the gap was refused")
	}
	records["k"] = "garbage"
	if kept, _ := rails.Gate(records, "k", at.Format(time.RFC3339), at, decode); !kept {
		t.Error("an unreadable request was not replaced")
	}
}

// The watch wakes on a changed digest and on a request newer than the last
// one acted on, and on nothing else.
func TestWatchWakesOnAChangeAndOnANewerRequest(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a", "1")
	requests := map[string]time.Time{"o": time.Unix(100, 0)}
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	read := func() map[string]time.Time {
		<-mu
		defer func() { mu <- struct{}{} }()
		out := map[string]time.Time{}
		for k, v := range requests {
			out[k] = v
		}
		return out
	}
	set := func(at time.Time) {
		<-mu
		requests["o"] = at
		mu <- struct{}{}
	}
	wake := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		rails.Watch{
			Poll:     5 * time.Millisecond,
			Digest:   func() [32]byte { return rails.Digest(quiet(), []string{dir}, func(string) bool { return true }) },
			Requests: read, Changed: "something changed",
		}.Run(ctx, quiet(), wake)
	}()
	t.Cleanup(func() { cancel(); <-done })

	woke := func(within time.Duration) bool {
		select {
		case <-wake:
			return true
		case <-time.After(within):
			return false
		}
	}
	if woke(100 * time.Millisecond) {
		t.Fatal("woke with nothing changed")
	}
	write(t, dir, "a", "2")
	if !woke(5 * time.Second) {
		t.Fatal("did not wake on a changed file")
	}
	// A write is a truncate then the content, and a poll between them wakes
	// once more: let that settle and drain it.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-wake:
	default:
	}
	set(time.Unix(50, 0))
	if woke(100 * time.Millisecond) {
		t.Fatal("woke for an older request")
	}
	set(time.Unix(200, 0))
	if !woke(5 * time.Second) {
		t.Fatal("did not wake for a newer request")
	}
	if woke(100 * time.Millisecond) {
		t.Fatal("woke twice for one request")
	}
}

// A negative poll never wakes.
func TestWatchWithANegativePollReturnsAtOnce(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		rails.Watch{Poll: -1}.Run(context.Background(), quiet(), make(chan struct{}, 1))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a watch with a negative poll kept running")
	}
}
