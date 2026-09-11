package identity_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truvity/access-roster/identity"
)

// A workload proven by its cluster and a person proven by the issuer
// arrive as the SAME type, and a handler cannot tell which anchor was
// used. That is the point: the right anchor is decided by how far away
// the caller is, and that can change without the handler changing.
func TestBothAnchorsYieldOneCaller(t *testing.T) {
	t.Parallel()

	cluster := &identity.Cluster{
		Review: func(context.Context, string, []string) (string, error) {
			return "system:serviceaccount:builds:runner", nil
		},
		Audience: "the-service",
		Name:     "devel",
		Groups:   []string{"devel:k8s:admin"},
	}

	who, err := cluster.Verify(context.Background(), "a-token")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if who.Subject != "devel:k8s:builds:runner" {
		t.Errorf("subject = %q, want the cluster-qualified form", who.Subject)
	}
	if who.Email != "" {
		t.Errorf("email = %q, want none for a workload", who.Email)
	}
	if !who.HasAny("devel:k8s:admin", "something-else") {
		t.Errorf("groups = %v", who.Groups)
	}
}

// Without an audience a review accepts every projected token in the
// cluster, which is not a narrower check but no check at all. It has to
// be a refusal to configure rather than a permissive default.
func TestAClusterWithNoAudienceVerifiesNothing(t *testing.T) {
	t.Parallel()

	cluster := &identity.Cluster{Review: func(context.Context, string, []string) (string, error) {
		return "system:serviceaccount:builds:runner", nil
	}}
	if _, err := cluster.Verify(context.Background(), "a-token"); !errors.Is(err, identity.ErrUnverified) {
		t.Errorf("err = %v, want nothing verified without an audience", err)
	}
}

// The API server authenticates people too. A person arriving through the
// workload door would bypass every rule an installation applies to
// people.
func TestOnlyAServiceAccountIsAWorkload(t *testing.T) {
	t.Parallel()

	cluster := &identity.Cluster{
		Review:   func(context.Context, string, []string) (string, error) { return "alice@example.com", nil },
		Audience: "the-service",
	}
	if _, err := cluster.Verify(context.Background(), "a-token"); !errors.Is(err, identity.ErrUnverified) {
		t.Errorf("err = %v, want a refusal", err)
	}
}

// Middleware establishes the caller and passes the request on rather
// than refusing it, because a listener serves pages that run before
// anybody is established. Require is what refuses.
func TestMiddlewareEstablishesAndRequireRefuses(t *testing.T) {
	t.Parallel()

	verifier := stub{who: identity.Verified{Subject: "ada@north.example", Email: "ada@north.example", Groups: []string{"platform"}}}
	establish := identity.Middleware(verifier)

	reached := false
	open := establish(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		if _, ok := identity.FromContext(r.Context()); ok {
			t.Error("nobody presented a token, yet somebody was established")
		}
	}))
	open.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !reached {
		t.Error("a request with no token did not reach the handler")
	}

	// With a token, the caller is there.
	signed := httptest.NewRequest(http.MethodGet, "/", nil)
	signed.Header.Set(identity.HeaderAuthorization, "Bearer a-token")
	establish(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		who, ok := identity.FromContext(r.Context())
		if !ok || who.Email != "ada@north.example" {
			t.Errorf("caller = %+v, %v", who, ok)
		}
	})).ServeHTTP(httptest.NewRecorder(), signed)

	// Require refuses an unestablished caller, and one without the group.
	guarded := establish(identity.Require("operator")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a caller without the group reached the handler")
	})))

	anonymous := httptest.NewRecorder()
	guarded.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d, want 401", anonymous.Code)
	}

	wrongGroup := httptest.NewRecorder()
	guarded.ServeHTTP(wrongGroup, signed)
	if wrongGroup.Code != http.StatusForbidden {
		t.Errorf("wrong group = %d, want 403", wrongGroup.Code)
	}
	// And it must not say which group would have worked.
	if body := wrongGroup.Body.String(); contains(body, "operator") {
		t.Errorf("the refusal names the group: %q", body)
	}
}

// A verifier that could not REACH the issuer stops the chain. Trying the
// next one would turn an outage into "your token is bad", and the caller
// would go and authenticate again for nothing.
func TestAnUnreachableIssuerDoesNotFallThrough(t *testing.T) {
	t.Parallel()

	broken := stub{err: errors.New("the key set is unreachable")}
	after := stub{who: identity.Verified{Subject: "somebody"}}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(identity.HeaderAuthorization, "Bearer a-token")

	identity.Middleware(broken, after)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := identity.FromContext(r.Context()); ok {
			t.Error("a later verifier answered after the first could not check")
		}
	})).ServeHTTP(httptest.NewRecorder(), request)
}

// WhoAmI answers rather than refuses when nobody is established: signed
// out is something a console has to render, and a 401 would make it
// indistinguishable from a service that is broken.
func TestWhoAmIAnswersEitherWay(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	identity.WhoAmI("dev").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, identity.WhoAmIPath, nil))
	if recorder.Code != http.StatusOK || !contains(recorder.Body.String(), `"signed-out"`) {
		t.Errorf("signed out = %d %q", recorder.Code, recorder.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, identity.WhoAmIPath, nil)
	request = request.WithContext(identity.WithVerified(request.Context(),
		identity.Verified{Subject: "ada@north.example", Email: "ada@north.example", Groups: []string{"platform"}}))
	signedIn := httptest.NewRecorder()
	identity.WhoAmI("dev").ServeHTTP(signedIn, request)
	for _, want := range []string{`"signed-in"`, "ada@north.example", "platform", "dev"} {
		if !contains(signedIn.Body.String(), want) {
			t.Errorf("whoami = %q, want it to carry %q", signedIn.Body.String(), want)
		}
	}
}

type stub struct {
	who identity.Verified
	err error
}

func (s stub) Verify(context.Context, string) (identity.Verified, error) {
	if s.err != nil {
		return identity.Verified{}, s.err
	}
	return s.who, nil
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
