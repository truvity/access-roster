package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/backend/google"
	"github.com/truvity/access-roster/internal/app"
	"github.com/truvity/access-roster/internal/connector"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/server"
)

// fakeConnector stands in for a second backend the console could connect
// -- Entra, say -- without this repo implementing one. It carries its own
// Kind and implements server.CredentialReopener, the same optional
// contract Google's connector implements, so a test can register it
// without touching anything Google-specific.
type fakeConnector struct{ kind string }

func (f fakeConnector) Kind() string { return f.kind }

func (f fakeConnector) AuthURL(string) (string, error) {
	return "", errors.New("fakeConnector: no consent flow")
}

func (f fakeConnector) Exchange(context.Context, string, string) (hub.Workspace, backend.Backend, error) {
	return hub.Workspace{}, nil, errors.New("fakeConnector: no consent flow")
}

// OpenStored implements server.CredentialReopener. The stored data is
// taken as the tenant id, the same shape fake.Backend.Credential hands a
// store to write down.
func (f fakeConnector) OpenStored(_ context.Context, cred backend.Credential) (backend.Backend, error) {
	return fake.New(string(cred.Data)), nil
}

var (
	_ server.Connector          = fakeConnector{}
	_ server.CredentialReopener = fakeConnector{}
)

// A stored google workspace -- the only kind this build could reopen
// before the fix -- must still reopen after it: the dispatch changed, not
// what it dispatches to.
func TestOpenStoredReopensAStoredGoogleWorkspace(t *testing.T) {
	t.Parallel()

	connectors := []server.Connector{
		connector.NewGoogle(func() (google.OAuthClient, error) {
			return google.OAuthClient{ID: "client-id", Secret: "client-secret", BaseURL: "https://example.invalid"}, nil
		}),
	}
	cred := backend.Credential{
		Type:  backend.CredentialOAuth,
		Admin: "admin@example.com",
		Data:  []byte("a-refresh-token"),
	}

	b, err := app.OpenStoredForTest(context.Background(), connectors, "google", cred)
	if err != nil {
		t.Fatalf("openStored(google): %v", err)
	}
	if b.Kind() != "google" {
		t.Errorf("Kind() = %q, want %q", b.Kind(), "google")
	}
}

// A second, registered backend kind must reopen too -- the whole point
// of dispatching through the connector list instead of a hardcoded
// "google" check.
func TestOpenStoredReopensARegisteredSecondBackend(t *testing.T) {
	t.Parallel()

	connectors := []server.Connector{
		connector.NewGoogle(func() (google.OAuthClient, error) {
			return google.OAuthClient{}, errors.New("not used by this test")
		}),
		fakeConnector{kind: "fake"},
	}
	cred := backend.Credential{
		Type:  backend.CredentialServiceAccountKey,
		Admin: "admin@acme.example",
		Data:  []byte("acme-tenant"),
	}

	b, err := app.OpenStoredForTest(context.Background(), connectors, "fake", cred)
	if err != nil {
		t.Fatalf("openStored(fake): %v", err)
	}
	if b.Kind() != "fake" {
		t.Errorf("Kind() = %q, want %q", b.Kind(), "fake")
	}
	tenant, err := b.Tenant(context.Background())
	if err != nil {
		t.Fatalf("Tenant(): %v", err)
	}
	if tenant.ID != "acme-tenant" {
		t.Errorf("tenant id = %q, want %q", tenant.ID, "acme-tenant")
	}
}

// A kind no connector registered must still be refused -- an unknown
// backend is an error naming it, never a widened acceptance.
func TestOpenStoredRefusesAnUnregisteredKind(t *testing.T) {
	t.Parallel()

	connectors := []server.Connector{
		connector.NewGoogle(func() (google.OAuthClient, error) {
			return google.OAuthClient{}, errors.New("not used by this test")
		}),
	}
	cred := backend.Credential{
		Type:  backend.CredentialOAuth,
		Admin: "admin@example.com",
		Data:  []byte("a-refresh-token"),
	}

	_, err := app.OpenStoredForTest(context.Background(), connectors, "entra", cred)
	if err == nil {
		t.Fatal("openStored(entra) succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "entra") {
		t.Errorf("error %q does not name the refused kind", err.Error())
	}
	if !strings.Contains(err.Error(), "google") {
		t.Errorf("error %q does not name what this build does connect", err.Error())
	}
}
