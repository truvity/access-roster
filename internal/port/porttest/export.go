package porttest

import (
	"errors"
	"maps"
	"testing"

	"github.com/truvity/access-roster/internal/port"
)

// ExportEnv is one [port.Export] adapter under test, fresh for every call of
// the factory.
type ExportEnv struct {
	Export port.Export
	// Read is what a consumer of the store would read at the target.
	Read func(t *testing.T, target port.ExportTarget) (map[string]string, bool)
}

// RunExport runs the assertions of the Export port (docs/decisions/0034):
// replace is exactly the properties, patch keeps the others and creates the
// key, a Put of nothing is refused, a namespace is a separate place, an
// identical Put is harmless and a Delete of what is absent is not an error.
func RunExport(t *testing.T, factory func(t *testing.T) ExportEnv) {
	t.Helper()
	cases := []struct {
		name string
		run  func(t *testing.T, e ExportEnv)
	}{
		{"export/replace-is-exact", exportReplaceExact},
		{"export/patch-keeps-the-rest", exportPatchKeeps},
		{"export/patch-creates", exportPatchCreates},
		{"export/identical-put", exportIdentical},
		{"export/refuses-nothing-and-bad-paths", exportRefuses},
		{"export/namespaces-are-separate", exportNamespaces},
		{"export/delete", exportDelete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, factory(t)) })
	}
}

func mustExport(t *testing.T, e ExportEnv, target port.ExportTarget, props map[string]string, mode port.ExportMode) {
	t.Helper()
	if err := e.Export.Put(ctx(), target, props, mode); err != nil {
		t.Fatalf("Put %s: %v", target, err)
	}
}

func wantExport(t *testing.T, e ExportEnv, target port.ExportTarget, want map[string]string) {
	t.Helper()
	got, ok := e.Read(t, target)
	if !ok || !maps.Equal(got, want) {
		t.Fatalf("%s holds %v (found %v), want %v", target, got, ok, want)
	}
}

func exportReplaceExact(t *testing.T, e ExportEnv) {
	target := port.ExportTarget{Path: "access-roster-backup/github-apps"}
	mustExport(t, e, target, map[string]string{"a.json": "1", "b.json": "2"}, port.ExportReplace)
	mustExport(t, e, target, map[string]string{"b.json": "3"}, port.ExportReplace)
	wantExport(t, e, target, map[string]string{"b.json": "3"})
}

func exportPatchKeeps(t *testing.T, e ExportEnv) {
	target := port.ExportTarget{Path: "arc/truvity"}
	mustExport(t, e, target, map[string]string{"other": "kept", "github-app-id": "1"}, port.ExportReplace)
	mustExport(t, e, target, map[string]string{"github-app-id": "2", "github-private-key": "k"}, port.ExportPatch)
	wantExport(t, e, target, map[string]string{"other": "kept", "github-app-id": "2", "github-private-key": "k"})
}

func exportPatchCreates(t *testing.T, e ExportEnv) {
	target := port.ExportTarget{Path: "slack-apps/alerts"}
	mustExport(t, e, target, map[string]string{"bot_token": "xoxb"}, port.ExportPatch)
	wantExport(t, e, target, map[string]string{"bot_token": "xoxb"})
}

func exportIdentical(t *testing.T, e ExportEnv) {
	target := port.ExportTarget{Path: "slack-apps/deadman"}
	props := map[string]string{"bot_token": "xoxb"}
	for range 3 {
		mustExport(t, e, target, props, port.ExportPatch)
		mustExport(t, e, target, props, port.ExportReplace)
	}
	wantExport(t, e, target, props)
}

func exportRefuses(t *testing.T, e ExportEnv) {
	target := port.ExportTarget{Path: "x/y"}
	mustExport(t, e, target, map[string]string{"k": "v"}, port.ExportReplace)
	if err := e.Export.Put(ctx(), target, map[string]string{}, port.ExportReplace); !errors.Is(err, port.ErrNoProperties) {
		t.Fatalf("a Put of nothing: %v, want ErrNoProperties", err)
	}
	wantExport(t, e, target, map[string]string{"k": "v"})
	for _, path := range []string{"", "/x", "x/", "x//y", "../x", "x/./y", "x y", "x?y"} {
		err := e.Export.Put(ctx(), port.ExportTarget{Path: path}, map[string]string{"k": "v"}, port.ExportReplace)
		if !errors.Is(err, port.ErrUnsupported) {
			t.Errorf("a Put to %q: %v, want ErrUnsupported", path, err)
		}
	}
	if err := e.Export.Put(ctx(), target, map[string]string{"k": "v"}, 0); !errors.Is(err, port.ErrUnsupported) {
		t.Errorf("a Put with no mode: %v, want ErrUnsupported", err)
	}
}

func exportNamespaces(t *testing.T, e ExportEnv) {
	kernel := port.ExportTarget{Namespace: "kernel", Path: "arc/truvity"}
	devel := port.ExportTarget{Namespace: "devel", Path: "arc/truvity"}
	mustExport(t, e, kernel, map[string]string{"github-app-id": "1"}, port.ExportPatch)
	mustExport(t, e, devel, map[string]string{"github-app-id": "2"}, port.ExportPatch)
	wantExport(t, e, kernel, map[string]string{"github-app-id": "1"})
	wantExport(t, e, devel, map[string]string{"github-app-id": "2"})
}

func exportDelete(t *testing.T, e ExportEnv) {
	target := port.ExportTarget{Path: "gone/soon"}
	if err := e.Export.Delete(ctx(), target); err != nil {
		t.Fatalf("Delete of an absent target: %v", err)
	}
	mustExport(t, e, target, map[string]string{"k": "v"}, port.ExportReplace)
	if err := e.Export.Delete(ctx(), target); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, ok := e.Read(t, target); ok {
		t.Fatalf("%s still holds %v", target, got)
	}
}
