package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/port"
	natsport "github.com/truvity/access-roster/internal/port/nats"
	"github.com/truvity/access-roster/internal/store"
)

func TestTheNATSAdapterSharesStateAndTheTriggerAcrossStores(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(20 * time.Second) {
		t.Fatal("the test server did not start")
	}
	t.Cleanup(srv.Shutdown)

	ports := &config.Ports{Adapter: "nats", NATS: &config.NATS{URL: srv.ClientURL(), Replicas: 1}}
	open := func() *store.Stores {
		cfg, err := store.FromServe(&config.Serve{IssuerURL: "https://i.example", Ports: ports})
		if err != nil || cfg.Adapter != store.AdapterNATS || cfg.Kube != store.KubeNone {
			t.Fatalf("FromServe = %+v, %v", cfg, err)
		}
		st, err := store.Open(context.Background(), cfg, quiet)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Close)
		return st
	}
	a, b := open(), open()
	if !a.Usable || !a.Shared || a.Name() != "nats" || a.Readiness() == nil {
		t.Fatalf("stores = %+v", a)
	}
	if state, shared := a.LeaseState(); !shared || state != a.Ports.State {
		t.Fatalf("LeaseState shared=%v: a lease must be exclusive across replicas", shared)
	}
	ctx := context.Background()
	if _, err = a.Ports.State.Create(ctx, "lease.t", []byte("a"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Ports.State.Create(ctx, "lease.t", []byte("b"), time.Minute); !errors.Is(err, port.ErrExists) {
		t.Fatalf("the second replica took a held lease: %v", err)
	}
	got := make(chan string, 1)
	stop := b.Ports.Trigger.Subscribe(func(target string) { got <- target })
	defer stop()
	if err = a.Ports.Trigger.Notify(ctx, "github.acme"); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-got:
		if target != "github.acme" {
			t.Fatalf("delivered %q", target)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a notification did not reach the other replica")
	}
}

func TestTheNATSAdapterRefusesWhatWouldContradictIt(t *testing.T) {
	if _, err := store.FromServe(&config.Serve{
		Valkey: &config.Valkey{Address: "v:6379"}, Ports: &config.Ports{Adapter: "nats", NATS: &config.NATS{URL: "nats://n:4222"}},
	}); err == nil {
		t.Error("the nats adapter was combined with a valkey")
	}
	for name, c := range map[string]store.Config{
		"no server":                {Adapter: store.AdapterNATS},
		"a token and a creds file": {Adapter: store.AdapterNATS, NATS: natsConfig("nats://127.0.0.1:1", "t", "c")},
	} {
		if _, err := store.Open(context.Background(), c, quiet); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func natsConfig(url, token, creds string) natsport.Config {
	return natsport.Config{URL: url, TokenFile: token, CredsFile: creds}
}
