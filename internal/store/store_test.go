package store_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/port"
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
	if _, err = store.Open(context.Background(), store.Config{Adapter: "cassandra"}, quiet); err == nil {
		t.Error("an adapter that does not exist opened")
	}
}

func ptr[T any](v T) *T { return &v }

// A one-shot tick runs when its lease is shared with the controller's, or
// when the operator opted in; otherwise it is refused with the reason.
func TestRequireSharedLease(t *testing.T) {
	for name, c := range map[string]struct {
		shared, unsafeLocal, refused bool
	}{
		"a shared State":              {shared: true},
		"a shared State and the flag": {shared: true, unsafeLocal: true},
		"no shared State, the flag":   {unsafeLocal: true},
		"no shared State, no flag":    {refused: true},
	} {
		err := store.RequireSharedLease(c.shared, c.unsafeLocal)
		if (err != nil) != c.refused {
			t.Errorf("%s: %v", name, err)
		}
		if c.refused && (!errors.Is(err, store.ErrLocalLease) || !strings.Contains(err.Error(), "B3")) {
			t.Errorf("%s: the refusal does not say why: %v", name, err)
		}
	}
}

// A Blob or a Sealer composes with any State adapter: the legacy one with
// no Valkey keeps what it had, and the two ports are the configured ones.
func TestABlobAndASealerComposeWithTheLegacyState(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "eu-west-1")
	f := &config.Serve{IssuerURL: "https://i.example", Ports: &config.Ports{
		Blob:   &config.PortsBlob{Adapter: "s3", S3: &config.PortsBlobS3{Bucket: "b", Endpoint: "http://127.0.0.1:1", PathStyle: true}},
		Sealer: &config.PortsSealer{Adapter: "kms", KMS: &config.PortsSealerKMS{KeyID: "alias/ar", Endpoint: "http://127.0.0.1:1"}},
	}}
	cfg, err := store.FromServe(f)
	if err != nil || cfg.Adapter != store.AdapterLegacy || cfg.Blob == nil || cfg.Sealer == nil {
		t.Fatalf("FromServe = %+v, %v", cfg, err)
	}
	st, err := store.Open(context.Background(), cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Adapter != store.AdapterLegacy || st.Backend == nil {
		t.Errorf("the State is no longer the legacy one: %+v", st)
	}
	// The port answers from S3, not from the legacy Blob: an unreachable
	// endpoint is the store being down, where the legacy one has no Valkey
	// and would answer ErrUnsupported or ErrNotFound.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err = st.Ports.Blob.Read(ctx, "reports/x"); !errors.Is(err, port.ErrUnavailable) {
		t.Errorf("Blob.Read = %v, want the S3 adapter's ErrUnavailable", err)
	}
	if _, err = st.Ports.Sealer.Wrap(ctx, []byte("k"), "b"); !errors.Is(err, port.ErrUnavailable) {
		t.Errorf("Sealer.Wrap = %v, want the KMS adapter's ErrUnavailable", err)
	}
}

func TestABlobOrSealerWithoutSettingsIsRefused(t *testing.T) {
	for name, cfg := range map[string]store.Config{
		"s3 with no bucket": {Adapter: store.AdapterMemory, Blob: &config.PortsBlob{Adapter: "s3"}},
		"an unknown blob":   {Adapter: store.AdapterMemory, Blob: &config.PortsBlob{Adapter: "gcs"}},
		"kms with no key":   {Adapter: store.AdapterMemory, Sealer: &config.PortsSealer{Adapter: "kms"}},
	} {
		if _, err := store.Open(context.Background(), cfg, quiet); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
