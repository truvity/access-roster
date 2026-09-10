package valkey_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/valkey"
)

// The property Oleg asked for, in the form of a test: a client whose
// server goes away and comes back must work again **without the process
// being restarted**.
//
// On 2026-09-10 two services dialled a Valkey address for half an hour
// after the pod behind it had moved, and a human had to restart them.
// Whether that was cluster-mode pinning or a client that never
// re-resolves is exactly what this test answers, so that "it recovers on
// its own" is a fact rather than a belief.
//
// Needs a Valkey and docker; set VALKEY_TEST_CONTAINER to the container
// name and VALKEY_TEST_ADDR to its address.
func TestTheClientRecoversWhenTheServerComesBack(t *testing.T) {
	container, addr := os.Getenv("VALKEY_TEST_CONTAINER"), os.Getenv("VALKEY_TEST_ADDR")
	if container == "" || addr == "" {
		t.Skip("set VALKEY_TEST_CONTAINER and VALKEY_TEST_ADDR")
	}

	ctx := context.Background()

	// Non-cluster on purpose: it is what the fleet runs since this
	// outage. In cluster mode the client learns NODE addresses from
	// CLUSTER SLOTS and talks to those, so a pod that moves takes the
	// client with it and the Service -- the one mechanism whose whole
	// job is to survive that -- is used once, as a seed, and then
	// bypassed. Here the configured address is dialled on every
	// reconnect, so a new address is simply the next dial.
	{
		store, err := valkey.OpenState(ctx, valkey.Config{Address: addr, Prefix: "reconnect-test"})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = store.Close() }()

		if err := store.Ping(ctx); err != nil {
			t.Fatalf("ping before: %v", err)
		}

		if out, err := exec.Command("docker", "stop", container).CombinedOutput(); err != nil {
			t.Fatalf("stop: %v %s", err, out)
		}

		down, cancel := context.WithTimeout(ctx, 3*time.Second)
		if err := store.Ping(down); err == nil {
			t.Error("ping succeeded while the server was stopped")
		}
		cancel()

		if out, err := exec.Command("docker", "start", container).CombinedOutput(); err != nil {
			t.Fatalf("start: %v %s", err, out)
		}

		// The whole test: no reconstruction, no restart, just time.
		deadline := time.Now().Add(30 * time.Second)
		for {
			probe, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := store.Ping(probe)
			cancel()

			if err == nil {
				t.Log("recovered without a restart")

				break
			}

			if time.Now().After(deadline) {
				t.Fatalf("still failing 30s after the server returned: %v", err)
			}

			time.Sleep(500 * time.Millisecond)
		}
	}
}
