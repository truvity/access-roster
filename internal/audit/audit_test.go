package audit_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/audit"
)

type refusingStore struct{}

func (refusingStore) Append(context.Context, audit.Event) (string, error) {
	return "", errors.New("the store is down")
}

func (refusingStore) List(context.Context, audit.Query) ([]audit.Event, string, error) {
	return nil, "", nil
}

// Every event is a log line before it is anything else: the log is the
// durable copy, and a store that refuses costs the stream an entry, never
// the caller its sign-in and never the record its existence.
func TestAnEventIsLoggedEvenWhenTheStoreRefuses(t *testing.T) {
	t.Parallel()
	var logged bytes.Buffer
	recorder := audit.NewLog(slog.New(slog.NewJSONHandler(&logged, nil)), refusingStore{})

	recorder.Record(context.Background(), audit.Event{
		Source: audit.SourceIssuer, Kind: "sign-in", Actor: "ada@north.example", Subject: "ada@north.example", Target: "argocd",
		Attributes: map[string]string{"provider": "google"},
	})

	out := logged.String()
	for _, want := range []string{`"audit":true`, `"kind":"sign-in"`, `"outcome":"ok"`, `"attr.provider":"google"`, "not stored"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %s:\n%s", want, out)
		}
	}
}

// A listing is newest first, filtered, and pages by cursor without
// repeating or skipping an event.
func TestTheMemoryStoreListsNewestFirstAndPagesWithoutGaps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := audit.NewMemory(100)
	base := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	for i := range 7 {
		kind := "sign-in"
		if i%2 == 1 {
			kind = "token.exchanged"
		}
		_, _ = store.Append(ctx, audit.Event{At: base.Add(time.Duration(i) * time.Minute), Source: audit.SourceIssuer, Kind: kind})
	}

	page, cursor, err := store.List(ctx, audit.Query{Kind: "sign-in", Limit: 2})
	if err != nil || len(page) != 2 || cursor == "" {
		t.Fatalf("first page = %d events, cursor %q, %v", len(page), cursor, err)
	}
	if !page[0].At.After(page[1].At) {
		t.Error("not newest first")
	}
	rest, cursor, _ := store.List(ctx, audit.Query{Kind: "sign-in", Limit: 2, Cursor: cursor})
	if len(rest) != 2 || cursor != "" {
		t.Errorf("second page = %d events, cursor %q; want the last two and the end", len(rest), cursor)
	}
	if rest[0].ID == page[1].ID {
		t.Error("the second page repeats the first page's last event")
	}

	// Capped: the oldest go first.
	small := audit.NewMemory(3)
	for i := range 5 {
		_, _ = small.Append(ctx, audit.Event{Kind: "k", Subject: string(rune('a' + i))})
	}
	all, _, _ := small.List(ctx, audit.Query{})
	if len(all) != 3 || all[2].Subject != "c" {
		t.Errorf("a capped store kept %+v, want the newest three", all)
	}
}

// Only the service may record as itself; a reporter naming one of its
// sources would be forging, say, a sign-in.
func TestTheServicesOwnSourcesAreReserved(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"issuer", "Directory", " console "} {
		if !audit.Reserved(source) {
			t.Errorf("%q is not reserved", source)
		}
	}
	if audit.Reserved("github-roster") {
		t.Error("a reporter's own name is reserved")
	}
}
