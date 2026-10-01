package server

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/hub"
)

// groupHub is a hub over two directories that hold groups, for the tests of
// everything fed by a directory group: C0north serves north.example, and
// holds `partners` (ann, bob), `devops` (cy) and `all`, whose members are
// `partners` and dee, so that ann and bob reach `all` through a nested group;
// C0south serves south.example and holds `eng` (eve) and `loop`, a pair of
// groups that name each other.
func groupHub(t *testing.T) *hub.Hub {
	t.Helper()
	h := hub.New(hub.NewMemoryStore(), hub.NewMemorySnapshots(), hub.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	north := fake.New("C0north", "north.example").
		WithAccount("admin@north.example", "Admin", "North").
		WithAccount("ann@north.example", "Ann", "A").WithAccount("bob@north.example", "Bob", "B").
		WithAccount("cy@north.example", "Cy", "C").WithAccount("dee@north.example", "Dee", "D").
		WithGroup("partners@north.example", "ann@north.example", "bob@north.example").
		WithGroup("devops@north.example", "cy@north.example").
		WithGroup("all@north.example", "partners@north.example", "dee@north.example")
	south := fake.New("C0south", "south.example").
		WithAccount("admin@south.example", "Admin", "South").
		WithAccount("eve@south.example", "Eve", "E").
		WithGroup("eng@south.example", "eve@south.example").
		WithGroup("loop-a@south.example", "loop-b@south.example", "eve@south.example").
		WithGroup("loop-b@south.example", "loop-a@south.example")
	for _, tenant := range []struct {
		id, domain string
		directory  *fake.Backend
	}{{"C0north", "north.example", north}, {"C0south", "south.example", south}} {
		if _, err := h.Adopt(context.Background(), hub.Workspace{ID: tenant.id, Admin: "admin@" + tenant.domain}, tenant.directory); err != nil {
			t.Fatalf("Adopt %s: %v", tenant.id, err)
		}
	}
	h.Wait()
	return h
}
