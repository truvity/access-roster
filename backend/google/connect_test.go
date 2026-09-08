package google

import (
	"context"
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/truvity/access-roster/backend"
)

// Two parameters decide whether this works at all, and both fail silently
// if they are missing: without offline access no refresh token is issued,
// and without a forced screen a second consent returns none — which is
// exactly the reconnect case, where the workspace would keep working for
// an hour and then stop.
func TestAuthURLAsksForAGrantThatCanBeRenewed(t *testing.T) {
	t.Parallel()

	client := OAuthClient{ID: "id.apps", Secret: "shh", BaseURL: "https://hub.example"}
	raw := client.AuthURL("state-123")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query := parsed.Query()
	if got := query.Get("access_type"); got != "offline" {
		t.Errorf("access_type = %q, want offline: no refresh token without it", got)
	}
	if got := query.Get("prompt"); got != "consent" {
		t.Errorf("prompt = %q, want consent: a silent re-consent returns no refresh token", got)
	}
	if got := query.Get("state"); got != "state-123" {
		t.Errorf("state = %q", got)
	}
	if got := query.Get("redirect_uri"); got != "https://hub.example/connect/google/callback" {
		t.Errorf("redirect_uri = %q", got)
	}

	scopes := strings.Fields(query.Get("scope"))
	for _, want := range append([]string{"openid", "email"}, Scopes...) {
		if !slices.Contains(scopes, want) {
			t.Errorf("scope %q was not asked for", want)
		}
	}
	// Nothing beyond read-only and identity: the consent screen an
	// administrator sees is the whole of what this hub can ever do.
	for _, got := range scopes {
		if got != "openid" && got != "email" && !strings.HasSuffix(got, ".readonly") {
			t.Errorf("scope %q is neither identity nor read-only", got)
		}
	}
}

// A refresh token is worth nothing without the client it was minted for,
// and a client is worth nothing without a token. Both halves are refused
// before any network call, so a misconfiguration is a startup error
// rather than a puzzling failure at the first read.
func TestOpenWithTokenRefusesHalfACredential(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := OAuthClient{ID: "id.apps", Secret: "shh"}

	if _, err := OpenWithToken(ctx, OAuthClient{}, "a-token", "admin@example.com"); err == nil {
		t.Error("opening with no OAuth client was accepted")
	}
	if _, err := OpenWithToken(ctx, client, "", "admin@example.com"); err == nil {
		t.Error("opening with no refresh token was accepted")
	}

	opened, err := OpenWithToken(ctx, client, "a-token", "Admin@Example.com")
	if err != nil {
		t.Fatalf("OpenWithToken: %v", err)
	}
	if opened.Admin() != "admin@example.com" {
		t.Errorf("admin = %q, want it lower-cased", opened.Admin())
	}
	cred := opened.Credential()
	if cred.Type != backend.CredentialOAuth || string(cred.Data) != "a-token" {
		t.Errorf("credential = %+v", cred)
	}
	// The credential is what a store writes down; handing out the
	// backend's own slice would let a caller change it underneath.
	cred.Data[0] = 'X'
	if again := opened.Credential(); string(again.Data) != "a-token" {
		t.Errorf("the credential was handed out by reference: %q", again.Data)
	}
}

// A consent that returns no refresh token works for an hour and then
// stops. Saying so while the operator is still looking at the screen that
// caused it is the only useful moment.
func TestConsentRefusesAGrantThatCannotBeRenewed(t *testing.T) {
	t.Parallel()

	if _, err := Consent(context.Background(), OAuthClient{ID: "a", Secret: "b"}, ""); err == nil {
		t.Error("a callback with no code was accepted")
	}
}

// The console shows which account a credential acts as, and for a consent
// grant that is whoever pressed the button. It comes from the id token
// Google returns beside the refresh token.
func TestTheConsentingAccountIsRead(t *testing.T) {
	t.Parallel()

	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"Integrations@North.Example","sub":"1"}`))
	token := (&oauth2.Token{}).WithExtra(map[string]any{
		"id_token": "header." + payload + ".signature",
	})
	if got := consentingAccount(token); got != "integrations@north.example" {
		t.Errorf("account = %q, want it lower-cased", got)
	}

	// Anything unreadable is empty rather than a guess: Consent turns
	// that into a refusal naming the missing scopes.
	for _, bad := range []any{nil, "", "not-a-jwt", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".c"} {
		extra := map[string]any{}
		if bad != nil {
			extra["id_token"] = bad
		}
		if got := consentingAccount((&oauth2.Token{}).WithExtra(extra)); got != "" {
			t.Errorf("id_token %v yielded %q, want empty", bad, got)
		}
	}
}

// Signing a person in and granting this hub access to a company are
// different flows, and the difference has to survive: the sign-in asks
// for nothing but an address, and returns to an endpoint that has to be
// reachable by somebody who is nobody yet.
func TestSignInAsksForNothingButAnAddress(t *testing.T) {
	t.Parallel()

	client := OAuthClient{ID: "id.apps", Secret: "shh", BaseURL: "https://hub.example"}
	parsed, err := url.Parse(client.SignInURL("state-9"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query := parsed.Query()

	if got := query.Get("redirect_uri"); got != "https://hub.example/login/google/callback" {
		t.Errorf("redirect_uri = %q, want the sign-in callback", got)
	}
	if got := strings.Fields(query.Get("scope")); !slices.Equal(got, SignInScopes) {
		t.Errorf("scope = %v, want only %v: a person grants nothing on their company's behalf", got, SignInScopes)
	}
	for _, scope := range query["scope"] {
		if strings.Contains(scope, "admin.directory") {
			t.Errorf("signing in asked for a directory scope: %q", scope)
		}
	}
	// No offline access and no forced screen: nothing is stored, so there
	// is no refresh token to want, and somebody who signed in a minute ago
	// should not be asked again.
	if query.Get("access_type") == "offline" || query.Get("prompt") == "consent" {
		t.Errorf("sign-in asked for a stored grant: access_type=%q prompt=%q",
			query.Get("access_type"), query.Get("prompt"))
	}
	if got := query.Get("state"); got != "state-9" {
		t.Errorf("state = %q", got)
	}

	// The two redirect URIs are derived from one base, so they cannot
	// disagree — a mismatched one fails late, in a cloud console's own
	// words, naming nothing useful.
	if client.ConsentRedirect() == client.SignInRedirect() {
		t.Error("the two flows share a redirect URI")
	}

	if _, err = Identify(context.Background(), client, ""); err == nil {
		t.Error("a callback with no code was accepted")
	}
}
