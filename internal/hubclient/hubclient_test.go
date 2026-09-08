package hubclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryv1 "github.com/truvity/access-roster/gen/directory/v1"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/internal/hubclient"
)

// hub is a stand-in for the real one, so that a test can say what it
// answered and see what was asked.
type hub struct {
	directoryv1connect.UnimplementedDirectoryServiceHandler
	answer *directoryv1.ResolveUserResponse
	fail   error

	asked      string
	authorized string
	maxAge     time.Duration
}

func (h *hub) ResolveUser(
	_ context.Context, request *connect.Request[directoryv1.ResolveUserRequest],
) (*connect.Response[directoryv1.ResolveUserResponse], error) {
	h.asked = request.Msg.GetEmail()
	h.authorized = request.Header().Get("Authorization")
	h.maxAge = request.Msg.GetMaxAge().AsDuration()
	if h.fail != nil {
		return nil, h.fail
	}
	return connect.NewResponse(h.answer), nil
}

func serve(t *testing.T, backing *hub) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(directoryv1connect.NewDirectoryServiceHandler(backing))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func tokenFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write the token: %v", err)
	}
	return path
}

// The answer the issuer acts on: who the person is in, whether they are
// live, and whether any of it may be trusted.
func TestTheHubsAnswerReachesTheIssuer(t *testing.T) {
	t.Parallel()

	backing := &hub{answer: &directoryv1.ResolveUserResponse{
		Groups: []string{"platform@north.example"}, InDomain: true, Found: true, Authoritative: true,
	}}
	client, err := hubclient.New(hubclient.Options{
		BaseURL: serve(t, backing), TokenFile: tokenFile(t, "a-projected-token"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := client.ResolveUser(context.Background(), "ada@north.example")
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if !got.Found || got.Suspended || !got.Authoritative || len(got.Groups) != 1 {
		t.Errorf("standing = %+v", got)
	}
	if backing.asked != "ada@north.example" {
		t.Errorf("the hub was asked about %q", backing.asked)
	}
	// The hub admits nobody without one, so a missing header is a call
	// that fails at the far end for a reason nobody here would guess.
	if backing.authorized != "Bearer a-projected-token" {
		t.Errorf("authorization = %q, want the projected token, trimmed", backing.authorized)
	}
	// No max_age asked for: the hub's own freshness policy is better
	// informed than a guess from here, and forcing a live read on every
	// sign-in turns one directory's slowness into everybody's.
	if backing.maxAge != 0 {
		t.Errorf("max_age = %v, want the hub's own policy", backing.maxAge)
	}
}

// An address in no served domain is not a refusal and not a person the
// hub denies: it is a domain nobody here answers for. It must arrive as
// "not found", never as a reason to remove anything.
func TestAnAddressInNoServedDomainIsNotFound(t *testing.T) {
	t.Parallel()

	backing := &hub{answer: &directoryv1.ResolveUserResponse{InDomain: false, Authoritative: false}}
	client, err := hubclient.New(hubclient.Options{
		BaseURL: serve(t, backing), TokenFile: tokenFile(t, "t"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := client.ResolveUser(context.Background(), "stranger@elsewhere.example")
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if got.Found || got.Authoritative || len(got.Groups) != 0 {
		t.Errorf("standing = %+v, want no opinion at all", got)
	}
}

// "I could not ask" must be distinguishable from "the directory says
// nothing": the issuer holds a last-known standing for a hold window, and
// it can only do that if a failure is an error rather than an empty
// answer.
func TestAFailureIsAnErrorRatherThanAnEmptyAnswer(t *testing.T) {
	t.Parallel()

	backing := &hub{fail: connect.NewError(connect.CodeUnavailable, http.ErrServerClosed)}
	client, err := hubclient.New(hubclient.Options{
		BaseURL: serve(t, backing), TokenFile: tokenFile(t, "t"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err = client.ResolveUser(context.Background(), "ada@north.example"); err == nil {
		t.Fatal("an unreachable hub came back as an answer")
	}

	// A token that cannot be read is the same class of thing, and says
	// which file it was: a projected volume that is not mounted is the
	// likeliest cause and the least guessable.
	missing, err := hubclient.New(hubclient.Options{
		BaseURL: serve(t, backing), TokenFile: filepath.Join(t.TempDir(), "absent"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = missing.ResolveUser(context.Background(), "ada@north.example")
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("a missing token file = %v, want it named", err)
	}
}

// A hub address is not optional: a client without one would fail on every
// login with a message about a URL rather than about configuration.
func TestTheHubsAddressIsRequired(t *testing.T) {
	t.Parallel()

	if _, err := hubclient.New(hubclient.Options{}); err == nil {
		t.Error("a client with no hub address was accepted")
	}
}
