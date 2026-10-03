package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/store"
)

func TestTheDynamoDBSettingsReachTheAdapter(t *testing.T) {
	ports := &config.Ports{Adapter: "dynamodb", DynamoDB: &config.DynamoDB{Table: "ar", Region: "eu-west-1", Endpoint: "http://localstack:4566", Create: true}}
	cfg, err := store.FromServe(&config.Serve{IssuerURL: "https://i.example", Ports: ports})
	if err != nil || cfg.Adapter != store.AdapterDynamoDB || cfg.Kube != store.KubeNone {
		t.Fatalf("FromServe = %+v, %v", cfg, err)
	}
	if d := cfg.DynamoDB; d.Table != "ar" || d.Region != "eu-west-1" || d.Endpoint != "http://localstack:4566" || !d.Create {
		t.Errorf("DynamoDB = %+v", d)
	}
	// Create is off unless the file turns it on: production binds to the table
	// the infrastructure code made.
	cfg = store.FromRoster(&config.Roster{Ports: &config.Ports{Adapter: "dynamodb", DynamoDB: &config.DynamoDB{Table: "ar"}}})
	if cfg.Adapter != store.AdapterDynamoDB || cfg.DynamoDB.Create || cfg.Kube != store.KubeRequired {
		t.Errorf("FromRoster = %+v", cfg)
	}
	// The table holds the shared state, so a Valkey beside it would contradict it.
	_, err = store.FromServe(&config.Serve{IssuerURL: "https://i.example", Ports: ports, Valkey: &config.Valkey{Address: "v:6379"}})
	if err == nil {
		t.Error("the dynamodb adapter was combined with a valkey")
	}
	// An adapter with no table is refused when it opens, naming the key.
	if _, err = store.Open(context.Background(), store.Config{Adapter: store.AdapterDynamoDB}, quiet); err == nil {
		t.Error("the dynamodb adapter opened with no table")
	}
}

// With a DynamoDB endpoint (ACCESS_ROSTER_DYNAMODB_URL, which hack/dynamodb-conformance.sh
// sets), two stores opened on one table share State and the Trigger, and are Shared and Usable.
func TestTheDynamoDBAdapterSharesStateAndTheTriggerAcrossStores(t *testing.T) {
	url := os.Getenv("ACCESS_ROSTER_DYNAMODB_URL")
	if url == "" {
		t.Skip("ACCESS_ROSTER_DYNAMODB_URL is not set: no DynamoDB to open")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	ports := &config.Ports{Adapter: "dynamodb", DynamoDB: &config.DynamoDB{Table: "ar-store-" + hex.EncodeToString(b), Endpoint: url, Create: true}}
	open := func() *store.Stores {
		cfg, err := store.FromServe(&config.Serve{IssuerURL: "https://i.example", Ports: ports})
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(context.Background(), cfg, quiet)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Close)
		return st
	}
	a, c := open(), open() // the second finds the table the first made
	if !a.Usable || !a.Shared || a.Name() != "dynamodb" || a.Readiness() == nil {
		t.Fatalf("stores = %+v", a)
	}
	if state, shared := a.LeaseState(); !shared || state != a.Ports.State {
		t.Fatalf("LeaseState shared=%v: a lease must be exclusive across replicas", shared)
	}
	ctx := context.Background()
	if _, err := a.Ports.State.Create(ctx, "lease.t", []byte("a"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ports.State.Create(ctx, "lease.t", []byte("b"), time.Minute); !errors.Is(err, port.ErrExists) {
		t.Fatalf("the second replica took a held lease: %v", err)
	}
	got := make(chan string, 1)
	stop := c.Ports.Trigger.Subscribe(func(target string) { got <- target })
	defer stop()
	if err := a.Ports.Trigger.Notify(ctx, "github.acme"); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-got:
		if target != "github.acme" {
			t.Fatalf("delivered %q", target)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a notification did not cross to the other store")
	}
}
