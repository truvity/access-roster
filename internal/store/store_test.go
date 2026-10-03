package store_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestTheDefaultAdapterIsTheLegacyOne(t *testing.T) {
	cfg, err := store.FromServe(&config.Serve{IssuerURL: "https://i.example"})
	if err != nil || cfg.Adapter != store.AdapterLegacy || cfg.Kube != store.KubeNone {
		t.Fatalf("FromServe = %+v, %v; want legacy and no cluster", cfg, err)
	}
	st, err := store.Open(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Usable || st.Shared || st.Backend == nil {
		t.Errorf("with no Valkey the legacy ports are not usable and nothing is shared: %+v", st)
	}
}

func TestAClusterStoreRequiresTheCluster(t *testing.T) {
	cfg, err := store.FromServe(&config.Serve{IssuerURL: "https://i.example", Store: "kubernetes"})
	if err != nil || cfg.Kube != store.KubeRequired {
		t.Fatalf("FromServe = %+v, %v", cfg, err)
	}
	if _, err = store.Open(context.Background(), cfg, quiet); err == nil || !strings.Contains(err.Error(), "not running in a cluster") {
		t.Fatalf("Open outside a cluster = %v, want the refusal a hub gave before the ports", err)
	}
}

func TestARecoveryOnlyIssuerGoesOnWithoutTheCluster(t *testing.T) {
	enabled := true
	cfg, err := store.FromServe(&config.Serve{
		IssuerURL: "https://i.example", InCluster: true, Recovery: &config.Recovery{Enabled: &enabled},
	})
	if err != nil || cfg.Kube != store.KubeOptional {
		t.Fatalf("FromServe = %+v, %v", cfg, err)
	}
	st, err := store.Open(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatalf("Open = %v, want a warning and no cluster", err)
	}
	if st.Backend.Kube != nil {
		t.Error("a client appeared outside a cluster")
	}
}

func TestValkeyMakesTheLegacyPortsSharedAndReadinessFollowsIt(t *testing.T) {
	server := miniredis.RunT(t)
	t.Setenv("TEST_VALKEY_PASSWORD", "")
	cfg, err := store.FromServe(&config.Serve{
		IssuerURL: "https://i.example", Release: "rel",
		Valkey: &config.Valkey{Address: server.Addr(), Cluster: ptr(false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if !st.Usable || !st.Shared || st.Name() != "valkey" || st.Readiness() == nil {
		t.Fatalf("stores = %+v", st)
	}
	if _, err = st.Ports.State.Put(context.Background(), "tok.j", []byte("x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	// Under the installation's prefix, as the issuer's own state has always been.
	if got, err := server.Get("rel:issuer:token:j"); err != nil || got != "x" {
		t.Fatalf("Valkey holds %q, %v under rel:", got, err)
	}
}

func TestTheMemoryAdapterKeepsNothingAndRefusesWhatWouldContradictIt(t *testing.T) {
	cfg, err := store.FromServe(&config.Serve{IssuerURL: "https://i.example", Ports: &config.Ports{Adapter: "memory"}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Usable || st.Shared || st.Backend != nil || st.Name() != "memory" {
		t.Errorf("stores = %+v", st)
	}
	for name, f := range map[string]*config.Serve{
		"a cluster store": {Store: "kubernetes", Ports: &config.Ports{Adapter: "memory"}},
		"a valkey":        {Valkey: &config.Valkey{Address: "v:6379"}, Ports: &config.Ports{Adapter: "memory"}},
	} {
		if _, err = store.FromServe(f); err == nil {
			t.Errorf("the memory adapter was combined with %s", name)
		}
	}
	if _, err = store.Open(context.Background(), store.Config{Adapter: "nats"}, quiet); err == nil {
		t.Error("an adapter that does not exist opened")
	}
}

func ptr[T any](v T) *T { return &v }
