package valkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/valkey"
)

// Every replica writes into one stream and reads the same history back:
// newest first, filtered, paged, and capped so the stream is never what
// fills the store.
func TestTheAuditStreamIsOneHistoryCappedAndPaged(t *testing.T) {
	t.Parallel()
	server := miniredis.RunT(t)
	ctx := context.Background()
	open := func() *valkey.Audit {
		return valkey.NewAudit(redis.NewClient(&redis.Options{Addr: server.Addr()}), "access-issuer", 1000, time.Hour)
	}
	one, two := open(), open()

	base := time.Now().UTC().Add(-time.Minute)
	for i := range 6 {
		writer := one
		if i%2 == 1 {
			writer = two
		}
		kind := "sign-in"
		if i%3 == 0 {
			kind = "workspace.connected"
		}
		event := audit.Event{At: base.Add(time.Duration(i) * time.Second), Source: "issuer", Kind: kind, Subject: "ada@north.example"}
		if _, err := writer.Append(ctx, event); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	all, cursor, err := one.List(ctx, audit.Query{})
	if err != nil || len(all) != 6 || cursor != "" {
		t.Fatalf("List = %d events, cursor %q, %v; want all six from both writers", len(all), cursor, err)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID <= all[i].ID {
			t.Fatalf("not newest first: %s then %s", all[i-1].ID, all[i].ID)
		}
	}

	page, cursor, err := two.List(ctx, audit.Query{Kind: "sign-in", Limit: 2})
	if err != nil || len(page) != 2 || cursor == "" {
		t.Fatalf("filtered page = %d, cursor %q, %v", len(page), cursor, err)
	}
	rest, cursor, _ := two.List(ctx, audit.Query{Kind: "sign-in", Limit: 2, Cursor: cursor})
	if len(rest) != 2 || cursor != "" || rest[0].ID >= page[1].ID {
		t.Errorf("second page = %+v, cursor %q; want the remaining two, older, and the end", rest, cursor)
	}

	// Since ends a listing at the first older entry.
	recent, _, _ := one.List(ctx, audit.Query{Since: base.Add(4 * time.Second)})
	if len(recent) != 2 {
		t.Errorf("since = %d events, want the last two", len(recent))
	}
}
