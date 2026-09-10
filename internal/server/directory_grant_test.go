package server_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/backend/fake"
	directoryv1 "github.com/truvity/access-roster/gen/directory/v1"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/server"
)

// serveTwoTenants is [serve] with a second company, which is the case
// per-consumer grants exist for: one hub reading two directories, and a
// consumer that should see exactly one of them (INF-679).
func serveTwoTenants(t *testing.T, grant *server.Grant) directoryv1connect.DirectoryServiceClient {
	t.Helper()

	first := fake.New("C0first", "example.com").
		WithAccount("alice@example.com", "Alice", "Ant").
		WithGroup("platform@example.com", "alice@example.com").
		WithGroup("team-eng@example.com", "alice@example.com")
	second := fake.New("C0second", "other.example").
		WithAccount("carol@other.example", "Carol", "Cat").
		WithGroup("platform@other.example", "carol@other.example")

	h := hub.New(hub.NewMemoryStore(), hub.NewMemorySnapshots(), hub.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tenant := range []struct {
		id, admin string
		backend   *fake.Backend
	}{
		{"C0first", "admin@example.com", first},
		{"C0second", "admin@other.example", second},
	} {
		if _, err := h.Adopt(context.Background(),
			hub.Workspace{ID: tenant.id, Admin: tenant.admin}, tenant.backend); err != nil {
			t.Fatalf("Adopt %s: %v", tenant.id, err)
		}
	}
	h.Wait()

	mux := http.NewServeMux()
	mux.Handle(directoryv1connect.NewDirectoryServiceHandler(server.NewDirectory(h)))
	// The grant normally arrives from the guard, which is not in this
	// test's way: what is under test is what the handlers do with one.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(server.WithGrant(r.Context(), grant)))
	}))
	t.Cleanup(srv.Close)

	return directoryv1connect.NewDirectoryServiceClient(srv.Client(), srv.URL)
}

// Discovery itself is scoped. Without this a consumer granted one
// directory still learns the shape of every company the hub serves,
// which is most of what the grant was for.
func TestDescribeShowsOnlyTheGrantedDirectory(t *testing.T) {
	t.Parallel()

	full := serveTwoTenants(t, nil)
	got, err := full.Describe(context.Background(), connect.NewRequest(&directoryv1.DescribeRequest{}))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(got.Msg.GetDomains()) != 2 {
		t.Fatalf("an ungranted consumer sees %v, want both domains", got.Msg.GetDomains())
	}

	scoped := serveTwoTenants(t, &server.Grant{Domains: []string{"example.com"}})
	got, err = scoped.Describe(context.Background(), connect.NewRequest(&directoryv1.DescribeRequest{}))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(got.Msg.GetDomains()) != 1 || got.Msg.GetDomains()[0] != "example.com" {
		t.Errorf("a scoped consumer sees %v, want only its own domain", got.Msg.GetDomains())
	}
	if len(got.Msg.GetServed()) != 1 {
		t.Errorf("served = %v, want only the granted domain", got.Msg.GetServed())
	}
}

// An address outside the grant answers exactly as an address in a domain
// this hub does not serve. A refusal would confirm the domain exists,
// which is the fact the grant is there to withhold — and consumers
// already read the unserved answer fail-safe.
func TestOutsideTheGrantIsIndistinguishableFromUnserved(t *testing.T) {
	t.Parallel()

	client := serveTwoTenants(t, &server.Grant{Domains: []string{"example.com"}})

	outside, err := client.ResolveUser(context.Background(),
		connect.NewRequest(&directoryv1.ResolveUserRequest{Email: "carol@other.example"}))
	if err != nil {
		t.Fatalf("ResolveUser outside the grant returned an error rather than an answer: %v", err)
	}
	if outside.Msg.GetInDomain() || outside.Msg.GetFound() || len(outside.Msg.GetGroups()) != 0 {
		t.Errorf("outside the grant = %+v, want the unserved-domain answer", outside.Msg)
	}

	unserved, err := client.ResolveUser(context.Background(),
		connect.NewRequest(&directoryv1.ResolveUserRequest{Email: "nobody@nowhere.example"}))
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if unserved.Msg.GetInDomain() != outside.Msg.GetInDomain() ||
		unserved.Msg.GetFound() != outside.Msg.GetFound() ||
		unserved.Msg.GetAuthoritative() != outside.Msg.GetAuthoritative() {
		t.Errorf("a withheld domain answers %+v and an unserved one %+v — the difference tells a consumer the domain exists",
			outside.Msg, unserved.Msg)
	}

	inside, err := client.ResolveUser(context.Background(),
		connect.NewRequest(&directoryv1.ResolveUserRequest{Email: "alice@example.com"}))
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !inside.Msg.GetFound() {
		t.Error("the granted domain stopped answering")
	}
}

// ListGroups is the enumeration a scoped consumer must not have across
// companies: naming no domain lists its own directory, not the hub's.
func TestListGroupsStaysInsideTheGrant(t *testing.T) {
	t.Parallel()

	client := serveTwoTenants(t, &server.Grant{Domains: []string{"example.com"}})

	all, err := client.ListGroups(context.Background(), connect.NewRequest(&directoryv1.ListGroupsRequest{}))
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	for _, group := range all.Msg.GetGroups() {
		if group.GetDomain() != "example.com" {
			t.Errorf("listing every group returned %q from outside the grant", group.GetEmail())
		}
	}
	if len(all.Msg.GetGroups()) == 0 {
		t.Error("listing every group returned nothing inside the grant either")
	}

	other, err := client.ListGroups(context.Background(),
		connect.NewRequest(&directoryv1.ListGroupsRequest{Domain: "other.example"}))
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(other.Msg.GetGroups()) != 0 || len(other.Msg.GetServed()) != 0 {
		t.Errorf("naming another company's domain returned %+v, want the unserved answer", other.Msg)
	}
}

// A group outside the grant is absent from what an address holds, so a
// consumer cannot learn a group exists by resolving somebody in it.
func TestAGroupGrantNarrowsWhatAnAddressHolds(t *testing.T) {
	t.Parallel()

	client := serveTwoTenants(t, &server.Grant{
		Domains: []string{"example.com"},
		Groups:  []string{"team-*"},
	})

	got, err := client.ResolveUser(context.Background(),
		connect.NewRequest(&directoryv1.ResolveUserRequest{Email: "alice@example.com"}))
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !got.Msg.GetFound() {
		t.Fatal("the address stopped resolving")
	}
	for _, group := range got.Msg.GetGroups() {
		if group != "team-eng@example.com" {
			t.Errorf("resolved groups included %q, which is outside the grant", group)
		}
	}
	if len(got.Msg.GetGroups()) != 1 {
		t.Errorf("resolved groups = %v, want only the granted one", got.Msg.GetGroups())
	}

	group, err := client.GetGroup(context.Background(),
		connect.NewRequest(&directoryv1.GetGroupRequest{Email: "platform@example.com"}))
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if group.Msg.GetFound() {
		t.Error("a group outside the grant was found, which tells the consumer it exists")
	}
}
