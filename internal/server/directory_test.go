package server_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/truvity/access-roster/backend/fake"
	directoryv1 "github.com/truvity/access-roster/gen/directory/v1"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/server"
)

// serve wires a hub over one fake tenant behind a real Connect client, so
// that these tests exercise the join — routing, freshness, mapping — and
// not just the hub.
func serve(t *testing.T) (directoryv1connect.DirectoryServiceClient, *fake.Backend, *hub.Hub) {
	t.Helper()
	b := fake.New("C0test", "example.com").
		WithAccount("alice@example.com", "Alice", "Ant").
		WithAccount("bob@example.com", "Bob", "Bee").
		WithGroup("platform@example.com", "alice@example.com")

	h := hub.New(hub.NewMemoryStore(), hub.NewMemorySnapshots(), hub.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := h.Adopt(context.Background(), hub.Workspace{ID: "C0test", Admin: "admin@example.com"}, b); err != nil {
		t.Fatalf("Adopt: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(directoryv1connect.NewDirectoryServiceHandler(server.NewDirectory(h)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return directoryv1connect.NewDirectoryServiceClient(srv.Client(), srv.URL), b, h
}

func TestDescribeOverTheWire(t *testing.T) {
	t.Parallel()
	client, _, _ := serve(t)

	got, err := client.Describe(context.Background(), connect.NewRequest(&directoryv1.DescribeRequest{}))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	msg := got.Msg
	if len(msg.GetDomains()) != 1 || msg.GetDomains()[0] != "example.com" {
		t.Errorf("domains = %v", msg.GetDomains())
	}
	if len(msg.GetServed()) != 1 {
		t.Fatalf("served = %v", msg.GetServed())
	}
	served := msg.GetServed()[0]
	if !served.GetAuthoritative() || served.GetWorkspaceId() != "C0test" || served.GetBackend() != "fake" {
		t.Errorf("served = %+v", served)
	}
	if served.GetSnapshotAt() == nil {
		t.Error("served domain carries no snapshot_at")
	}
}

func TestResolveUserOverTheWire(t *testing.T) {
	t.Parallel()
	client, b, _ := serve(t)
	ctx := context.Background()

	got, err := client.ResolveUser(ctx, connect.NewRequest(&directoryv1.ResolveUserRequest{
		Email: "alice@example.com",
	}))
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !got.Msg.GetInDomain() || !got.Msg.GetFound() || !got.Msg.GetAuthoritative() {
		t.Errorf("alice = %+v", got.Msg)
	}
	if len(got.Msg.GetGroups()) != 1 {
		t.Errorf("groups = %v", got.Msg.GetGroups())
	}

	// A suspended account, after a refresh: gone, and authoritatively so.
	b.Suspend("alice@example.com")
	if _, err = client.Probe(ctx, connect.NewRequest(&directoryv1.ProbeRequest{})); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	got, err = client.ResolveUser(ctx, connect.NewRequest(&directoryv1.ResolveUserRequest{
		Email:  "alice@example.com",
		MaxAge: durationpb.New(0),
	}))
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !got.Msg.GetSuspended() || !got.Msg.GetAuthoritative() {
		t.Errorf("suspended alice = %+v", got.Msg)
	}
}

func TestOutOfDomainIsNoOpinionOverTheWire(t *testing.T) {
	t.Parallel()
	client, _, _ := serve(t)

	got, err := client.GetAccount(context.Background(), connect.NewRequest(&directoryv1.GetAccountRequest{
		Email: "stranger@elsewhere.example",
	}))
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	acc := got.Msg.GetAccount()
	if acc.GetInDomain() || acc.GetFound() || acc.GetAuthoritative() {
		t.Errorf("account = %+v, want no opinion", acc)
	}
}

func TestRevokedCredentialHoldsOverTheWire(t *testing.T) {
	t.Parallel()
	client, b, _ := serve(t)
	ctx := context.Background()

	b.Fail(fake.OpProbe, nil)
	probe, err := client.Probe(ctx, connect.NewRequest(&directoryv1.ProbeRequest{}))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if probe.Msg.GetHealthy() || probe.Msg.GetDetail() == "" {
		t.Errorf("probe = %+v, want an unhealthy answer with a reason", probe.Msg)
	}

	got, err := client.ResolveUser(ctx, connect.NewRequest(&directoryv1.ResolveUserRequest{
		Email: "alice@example.com",
	}))
	if err != nil {
		t.Fatalf("ResolveUser after a revoked credential: %v", err)
	}
	if got.Msg.GetAuthoritative() {
		t.Error("a revoked credential must cost authority")
	}
	if !got.Msg.GetFound() {
		t.Error("the last snapshot is still served")
	}
}

func TestGroupsOverTheWire(t *testing.T) {
	t.Parallel()
	client, _, _ := serve(t)
	ctx := context.Background()

	one, err := client.GetGroup(ctx, connect.NewRequest(&directoryv1.GetGroupRequest{
		Email: "platform@example.com",
	}))
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if !one.Msg.GetFound() || one.Msg.GetGroup().GetDomain() != "example.com" {
		t.Errorf("group = %+v", one.Msg)
	}

	all, err := client.ListGroups(ctx, connect.NewRequest(&directoryv1.ListGroupsRequest{}))
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(all.Msg.GetGroups()) != 1 || len(all.Msg.GetServed()) != 1 {
		t.Errorf("listing = %+v", all.Msg)
	}
}

func TestMalformedAddressIsInvalidArgument(t *testing.T) {
	t.Parallel()
	client, _, _ := serve(t)

	_, err := client.ResolveUser(context.Background(), connect.NewRequest(&directoryv1.ResolveUserRequest{
		Email: "not-an-address",
	}))
	if err == nil {
		t.Fatal("want an error")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want invalid_argument", got)
	}
}

func TestPointReadDoesNotTriggerAFullPass(t *testing.T) {
	t.Parallel()
	client, b, _ := serve(t)
	before := b.Calls(fake.OpAccounts)

	// max_age zero means "fetch now"; the cheapest path that satisfies it
	// is one account read, never a pass over the whole directory.
	_, err := client.ResolveUser(context.Background(), connect.NewRequest(&directoryv1.ResolveUserRequest{
		Email:  "alice@example.com",
		MaxAge: durationpb.New(0),
	}))
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if b.Calls(fake.OpAccounts) != before {
		t.Error("a point lookup read the whole directory")
	}
	if b.Calls(fake.OpAccount) == 0 {
		t.Error("a point lookup with max_age did not read the account live")
	}
}
