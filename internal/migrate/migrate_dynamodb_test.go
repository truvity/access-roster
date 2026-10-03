package migrate_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/migrate"
	"github.com/truvity/access-roster/internal/port"
	dynamoport "github.com/truvity/access-roster/internal/port/dynamodb"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/store"
)

// dynamoDest opens a fresh DynamoDB table on the endpoint hack/dynamodb-conformance.sh
// names, with the in-process Sealer (a DynamoDB table holds no Sealer).
func dynamoDest(t *testing.T) (*store.Stores, *dynamoport.Store) {
	t.Helper()
	url := os.Getenv("ACCESS_ROSTER_DYNAMODB_URL")
	if url == "" {
		t.Skip("ACCESS_ROSTER_DYNAMODB_URL is not set: no DynamoDB to migrate into")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	tbl, err := dynamoport.Open(context.Background(), dynamoport.Config{Table: "ar-migrate-" + hex.EncodeToString(b), Endpoint: url, Create: true})
	if err != nil {
		t.Fatal(err)
	}
	set := tbl.Set()
	set.Sealer = memory.New().Set().Sealer
	return portSide(set, store.AdapterDynamoDB), tbl
}

// Memory into DynamoDB and back: every domain item and every login is copied and
// read back equal through the exporters, a session keeps the lifetime it had, and
// the way back is the rollback.
func TestMemoryToDynamoDBCopiesAndVerifies(t *testing.T) {
	dst, tbl := dynamoDest(t)
	src := portSide(memory.New().Set(), store.AdapterMemory)
	seed(t, src)
	session, token := seedLogins(t, src)

	report, err := migrate.Run(ctx, side("memory", src), side("dynamodb", dst), stopped)
	if err != nil || !report.OK || report.Totals.Mismatched != 0 || report.Totals.Conflicts != 0 {
		t.Fatalf("Run = %v\n%s", err, report.JSON())
	}
	if report.Totals.Copied < seededItems {
		t.Errorf("copied %d, want at least %d", report.Totals.Copied, seededItems)
	}
	if s := step(t, report, "issuer", "index"); s.Source != 3 || s.Verified != 3 {
		t.Errorf("issuer index = %+v, want the three session sets", s)
	}
	noSecrets(t, report)

	// A refresh token copied across works on the destination, its session is found
	// by person, and the 5 minute code kept what was left of it.
	sessions := issuer.NewSessions(issuer.NewPortState(dst.Ports.State, dst.Ports.Index), sessionLifetime, 0)
	if got, ok, err := sessions.ByRefreshToken(ctx, token); err != nil || !ok || got.ID != session.ID {
		t.Fatalf("ByRefreshToken on DynamoDB = %+v, %v, %v", got, ok, err)
	}
	if listed, err := sessions.List(ctx, issuer.Query{Identity: "ada@north.example"}); err != nil || len(listed) != 1 {
		t.Fatalf("the person's sessions on DynamoDB = %+v, %v", listed, err)
	}
	var ttl time.Duration
	err = dst.Ports.State.(port.StateExporter).ExportState(ctx, "issuer:code:", func(x port.Exported) error {
		ttl = x.TTL
		return nil
	})
	if err != nil || ttl <= 4*time.Minute || ttl > 5*time.Minute+10*time.Second {
		t.Errorf("a 5 minute code has %s left on DynamoDB (%v): its lifetime was not carried", ttl, err)
	}
	tbl.Advance(sessionLifetime + time.Hour)
	if _, ok, _ := sessions.ByRefreshToken(ctx, token); ok {
		t.Error("a copied session outlived its lifetime")
	}
	tbl.Advance(-(sessionLifetime + time.Hour))

	// A re-run has nothing left to do.
	report, err = migrate.Run(ctx, side("memory", src), side("dynamodb", dst), stopped)
	if err != nil || report.Totals.Copied != 0 || report.Totals.New != 0 || report.Totals.Present != report.Totals.Source {
		t.Fatalf("the re-run = %v\n%s", err, report.JSON())
	}

	// The way back: DynamoDB is a source (the exporters) as well as a destination.
	back := portSide(memory.New().Set(), store.AdapterMemory)
	report, err = migrate.Run(ctx, side("dynamodb", dst), side("memory-again", back), stopped)
	if err != nil || !report.OK || report.Totals.Mismatched != 0 || report.Totals.Copied < seededItems {
		t.Fatalf("DynamoDB back to memory = %v\n%s", err, report.JSON())
	}
}
