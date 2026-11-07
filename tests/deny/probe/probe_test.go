package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/tests/deny/internal/spec"
)

// entry drops a peer it refuses right after accept, without reading the request. The client sees that as EOF, a
// reset, a broken pipe or, when the close arrives before the transport has registered the request, as net/http's own
// "server closed idle connection", which wraps none of them. All four are the one refusal, "dropped", and none of them
// may be read as a broken installation (it failed a run of the deny matrix on 2026-11-07).
func TestAHTTPPeerThatIsDroppedAfterAcceptIsRefusedNotBroken(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "entry.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	for i := 0; i < 2000; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r := probeHTTP(ctx, spec.Target{ID: "entry -> entry", Socket: sock})
		cancel()
		if r.Outcome != spec.Guard {
			t.Fatalf("try %d: outcome %v (%s), want the connection dropped as a refusal", i, r.Outcome, r.Detail)
		}
	}
}
