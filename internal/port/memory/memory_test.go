package memory_test

import (
	"testing"

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
