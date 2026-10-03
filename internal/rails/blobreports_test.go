package rails_test

import (
	"context"
	"maps"
	"testing"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/rails"
)

// plainBlob is a Blob with none of the optional capabilities, which is what
// an adapter without a one-write replacement presents.
type plainBlob struct{ port.Blob }

// A reconciler's reports are replaced as a whole: what it no longer reports on
// leaves, whichever way the adapter writes.
func TestReportsAreReplacedAsAWholeAndReadBack(t *testing.T) {
	t.Parallel()
	for name, blob := range map[string]port.Blob{
		"an adapter that replaces in one write": memory.New().Blobs(),
		"an adapter with only Write and Delete": plainBlob{memory.New().Blobs()},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			reports := rails.NewBlobReports(blob, "reports/github/")
			other := rails.NewBlobReports(blob, "reports/slack/")

			if got, err := reports.Reports(ctx); err != nil || len(got) != 0 {
				t.Fatalf("no reports yet = %v, %v", got, err)
			}
			if err := other.Replace(ctx, map[string]string{"w.json": "slack"}); err != nil {
				t.Fatal(err)
			}
			first := map[string]string{"acme.json": `{"a":1}`, "globex.json": `{"g":1}`}
			if err := reports.Replace(ctx, first); err != nil {
				t.Fatal(err)
			}
			if got, _ := reports.Reports(ctx); !maps.Equal(got, first) {
				t.Fatalf("Reports = %v, want %v", got, first)
			}
			second := map[string]string{"acme.json": `{"a":2}`}
			if err := reports.Replace(ctx, second); err != nil {
				t.Fatal(err)
			}
			if got, _ := reports.Reports(ctx); !maps.Equal(got, second) {
				t.Fatalf("Reports after a replacement = %v, want only %v", got, second)
			}
			if got, _ := other.Reports(ctx); !maps.Equal(got, map[string]string{"w.json": "slack"}) {
				t.Errorf("another family's reports changed: %v", got)
			}
		})
	}
}
