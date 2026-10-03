package legacy_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/port/memory"
)

// The issuer's State, built over the ports, behaves as it always did over the
// Valkey and over memory, on either adapter. The keys are the issuer's own.
func TestTheIssuersStateOverThePortsBehavesAsItAlwaysDid(t *testing.T) {
	t.Parallel()
	for name, open := range map[string]func(*testing.T) (issuer.State, func(time.Duration)){
		"memory adapter": func(*testing.T) (issuer.State, func(time.Duration)) {
			s := memory.New()
			return issuer.NewPortState(s, s), s.Advance
		},
		"legacy adapter": func(t *testing.T) (issuer.State, func(time.Duration)) {
			f := newFixture(t)
			return issuer.NewPortState(f.ports.State, f.ports.Index), f.redis.FastForward
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			state, advance := open(t)

			if _, found, err := state.Get(ctx, "issuer:request:none"); err != nil || found {
				t.Errorf("an unknown key = %v, %v", found, err)
			}
			if err := state.Set(ctx, "issuer:request:r", []byte("a login"), time.Hour); err != nil {
				t.Fatal(err)
			}
			if value, found, err := state.Get(ctx, "issuer:request:r"); err != nil || !found || string(value) != "a login" {
				t.Fatalf("Get = %q, %v, %v", value, found, err)
			}
			if won, err := state.SetIfAbsent(ctx, "issuer:code:c", []byte("first"), time.Hour); err != nil || !won {
				t.Fatalf("the first claim = %v, %v", won, err)
			}
			if won, err := state.SetIfAbsent(ctx, "issuer:code:c", []byte("second"), time.Hour); err != nil || won {
				t.Fatalf("the second claim = %v, %v", won, err)
			}
			if value, _, _ := state.Get(ctx, "issuer:code:c"); string(value) != "first" {
				t.Errorf("the code is %q, want the first claim's", value)
			}
			if err := state.Set(ctx, "issuer:nottl", []byte("x"), 0); err == nil {
				t.Error("a value with no lifetime was stored")
			}
			if err := state.Delete(ctx, "issuer:request:r"); err != nil {
				t.Fatal(err)
			}
			if err := state.Delete(ctx, "issuer:request:r"); err != nil {
				t.Errorf("deleting what is gone: %v", err)
			}

			if members, err := state.Members(ctx, "issuer:sessions-of:ada"); err != nil || len(members) != 0 {
				t.Errorf("a set nobody wrote = %v, %v", members, err)
			}
			for _, id := range []string{"b", "a"} {
				if err := state.Add(ctx, "issuer:sessions-of:ada", id, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			members, _ := state.Members(ctx, "issuer:sessions-of:ada")
			slices.Sort(members)
			if !slices.Equal(members, []string{"a", "b"}) {
				t.Errorf("members = %v", members)
			}
			if err := state.Remove(ctx, "issuer:sessions-of:ada", "a"); err != nil {
				t.Fatal(err)
			}

			advance(2 * time.Hour)
			if _, found, _ := state.Get(ctx, "issuer:code:c"); found {
				t.Error("an expired claim was still there")
			}
			if members, _ := state.Members(ctx, "issuer:sessions-of:ada"); len(members) != 0 {
				t.Errorf("an expired set still has %v", members)
			}
		})
	}
}
