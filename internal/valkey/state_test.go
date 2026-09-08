package valkey_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/valkey"
)

// Both implementations are the same contract, so they are tested by the
// same expectations. The memory one is right for a local run and a single
// replica; the shared one is what makes a login survive the browser
// coming back to a different pod. A difference between them would show up
// only in a deployment, only sometimes.
func TestBothStatesBehaveTheSame(t *testing.T) {
	t.Parallel()

	for name, open := range map[string]func(*testing.T) (issuer.State, func(time.Duration)){
		"memory": func(t *testing.T) (issuer.State, func(time.Duration)) {
			t.Helper()
			now := time.Now()
			state := issuer.NewMemoryState()
			state.SetClock(func() time.Time { return now })
			return state, func(d time.Duration) { now = now.Add(d) }
		},
		"valkey": func(t *testing.T) (issuer.State, func(time.Duration)) {
			t.Helper()
			server := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: server.Addr()})
			t.Cleanup(func() { _ = client.Close() })
			return valkey.NewState(client, "test"), server.FastForward
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			state, advance := open(t)

			// Absent is an answer, not an error: an expired login and one
			// that never existed are the same thing to whoever asks.
			if _, found, err := state.Get(ctx, "nothing"); err != nil || found {
				t.Errorf("an unknown key = %v, %v", found, err)
			}

			if err := state.Set(ctx, "request", []byte("a login"), time.Hour); err != nil {
				t.Fatalf("Set: %v", err)
			}
			value, found, err := state.Get(ctx, "request")
			if err != nil || !found || string(value) != "a login" {
				t.Fatalf("Get = %q, %v, %v", value, found, err)
			}

			// Claiming is atomic: two replicas minting the same short user
			// code at the same moment must not both believe they own it.
			claimed, err := state.SetIfAbsent(ctx, "code", []byte("first"), time.Hour)
			if err != nil || !claimed {
				t.Fatalf("the first claim = %v, %v", claimed, err)
			}
			claimed, err = state.SetIfAbsent(ctx, "code", []byte("second"), time.Hour)
			if err != nil || claimed {
				t.Errorf("a second claim of the same code = %v, %v", claimed, err)
			}
			if value, _, _ = state.Get(ctx, "code"); string(value) != "first" {
				t.Errorf("the loser overwrote the winner: %q", value)
			}

			// Everything expires on its own. Nothing sweeps, so a store
			// whose sweeper stopped is not a thing that can happen.
			advance(2 * time.Hour)
			if _, found, err = state.Get(ctx, "request"); err != nil || found {
				t.Errorf("after its lifetime = %v, %v; want it gone", found, err)
			}
			// And an expired claim is free again.
			if claimed, err = state.SetIfAbsent(ctx, "code", []byte("later"), time.Hour); err != nil || !claimed {
				t.Errorf("an expired claim was still held: %v, %v", claimed, err)
			}

			if err = state.Delete(ctx, "code"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, found, _ = state.Get(ctx, "code"); found {
				t.Error("delete did not")
			}
			// Deleting what is already gone is the state being asked for.
			if err = state.Delete(ctx, "code"); err != nil {
				t.Errorf("a second delete: %v", err)
			}
		})
	}
}

// A value with no lifetime would sit in a shared store until somebody
// noticed, which is how a cache becomes a database nobody meant to run.
func TestTheSharedStateRefusesAValueWithNoLifetime(t *testing.T) {
	t.Parallel()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	state := valkey.NewState(client, "test")

	if err := state.Set(context.Background(), "forever", []byte("x"), 0); err == nil {
		t.Error("a value with no lifetime was stored")
	}
	if _, err := state.SetIfAbsent(context.Background(), "forever", []byte("x"), 0); err == nil {
		t.Error("a claim with no lifetime was stored")
	}
}
