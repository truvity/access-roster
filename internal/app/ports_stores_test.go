package app_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/app"
	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/portstore/portstoretest"
	"github.com/truvity/access-roster/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func serveConfig(t *testing.T, change ...func(*config.Serve)) app.Config {
	t.Helper()
	cfg, err := app.FromConfig(issuerFile(t, append([]func(*config.Serve){func(f *config.Serve) { f.Demo = false }}, change...)...))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// `legacy` keeps the ConfigMap and Secret stores, and with `store: memory`
// there are none of the domain stores a cluster would hold: unchanged.
func TestTheLegacyAdapterKeepsTheDomainStoresItAlwaysHad(t *testing.T) {
	kept, err := app.OpenStoresForTest(context.Background(), serveConfig(t), &store.Stores{Adapter: store.AdapterLegacy}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if kept.GitHubOrgs || kept.GitHubLinks || kept.SlackShared || kept.Credentials != nil {
		t.Errorf("legacy with store: memory kept %+v, want only the memory workspaces", kept)
	}
}

// Any other adapter keeps them on the ports, and every replica of the service
// sees the same stores, the same sealed credentials and the same session key.
func TestAnyOtherAdapterKeepsTheDomainStoresOnThePorts(t *testing.T) {
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) {
		open := func() app.KeptForTest {
			st := &store.Stores{Ports: e.Open(t), Adapter: store.AdapterNATS, Shared: true, Usable: true}
			kept, err := app.OpenStoresForTest(context.Background(), serveConfig(t), st, quiet)
			if err != nil {
				t.Fatal(err)
			}
			return kept
		}
		a, b := open(), open()
		if !a.GitHubOrgs || !a.GitHubLinks || !a.SlackShared || a.Credentials == nil {
			t.Fatalf("kept %+v, want every domain store", a)
		}
		if !bytes.Equal(a.SessionKey, b.SessionKey) || len(a.SessionKey) == 0 {
			t.Error("two replicas signed sessions with different keys")
		}
		ctx := context.Background()
		if err := a.Workspaces.Put(ctx, hub.Workspace{ID: "C01", Backend: "google"}); err != nil {
			t.Fatal(err)
		}
		if err := a.Credentials.Save(ctx, "C01", backend.Credential{Type: backend.CredentialOAuth, Admin: "a@b.example", Data: []byte("refresh")}); err != nil {
			t.Fatal(err)
		}
		if list, err := b.Workspaces.List(ctx); err != nil || len(list) != 1 {
			t.Fatalf("the other replica lists %v, %v", list, err)
		}
		if cred, found, err := b.Credentials.Load(ctx, "C01"); err != nil || !found || string(cred.Data) != "refresh" {
			t.Fatalf("the other replica loads %+v, %v, %v", cred, found, err)
		}
	})
}

type noSealer struct{}

func (noSealer) Wrap(context.Context, []byte, string) (port.Wrapped, error) {
	return port.Wrapped{}, port.ErrUnsupported
}

func (noSealer) Unwrap(context.Context, port.Wrapped, string) ([]byte, error) {
	return nil, port.ErrUnsupported
}

// An adapter with no Sealer (the legacy one's, and NATS's without ports.sealer)
// stops the start naming the setting, instead of failing on the first
// credential an operator connects.
func TestAnAdapterWithNoSealerStopsTheStartNamingTheSetting(t *testing.T) {
	set := portstoretest.Envs(t)[2].Open(t)
	set.Sealer = noSealer{}
	_, err := app.OpenStoresForTest(context.Background(), serveConfig(t), &store.Stores{Ports: set, Adapter: store.AdapterNATS}, quiet)
	if err == nil || !strings.Contains(err.Error(), "ports.sealer") {
		t.Errorf("err = %v, want a refusal that names ports.sealer", err)
	}
}

// A demonstration has fixed stores of its own and keeps them whatever the
// adapter.
func TestADemonstrationKeepsItsFixedStores(t *testing.T) {
	kept, err := app.OpenStoresForTest(context.Background(), serveConfig(t, func(f *config.Serve) { f.Demo = true }),
		&store.Stores{Ports: portstoretest.Envs(t)[0].Open(t), Adapter: store.AdapterMemory, Usable: true}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if kept.GitHubOrgs {
		t.Error("a demonstration had domain stores on the ports")
	}
}
