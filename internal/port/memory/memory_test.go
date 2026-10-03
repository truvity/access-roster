package memory_test

import (
	"context"
	"testing"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/port/porttest"
)

func TestConformance(t *testing.T) {
	porttest.Run(t, func(*testing.T) porttest.Env {
		s := memory.New()
		s.Allow("workload-token", "system:serviceaccount:ns:sa", "access-roster")
		return porttest.Env{
			Set:          s.Set(),
			Advance:      s.Advance,
			BlobPrefixes: []string{"reports/", "snapshots/"},
			Proof: func() porttest.Proof {
				return porttest.Proof{Token: "workload-token", Subject: "system:serviceaccount:ns:sa", Audience: "access-roster"}
			},
		}
	})
}

func TestExportConformance(t *testing.T) {
	porttest.RunExport(t, func(*testing.T) porttest.ExportEnv {
		e := memory.NewExport()
		return porttest.ExportEnv{
			Export: e,
			Read: func(_ *testing.T, target port.ExportTarget) (map[string]string, bool) {
				return e.Get(target)
			},
		}
	})
}

func TestAnIdenticalExportMakesNoWrite(t *testing.T) {
	e := memory.NewExport()
	target := port.ExportTarget{Path: "slack-apps/alerts"}
	for range 3 {
		if err := e.Put(context.Background(), target, map[string]string{"bot_token": "x"}, port.ExportPatch); err != nil {
			t.Fatal(err)
		}
	}
	if e.Writes() != 1 {
		t.Fatalf("%d writes for three identical puts, want 1", e.Writes())
	}
}
