package issuer_test

import (
	"context"
	"testing"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// Reusing an authorization code ends the session it opened.
//
// RFC 6749 4.1.2: a code used more than once must be denied and SHOULD
// revoke the tokens already issued from it. Denying alone leaves the
// first redemption working while telling us the code was stolen —
// conformance saw it as a resource endpoint answering 200 where it
// wanted a 4xx.
//
// PKCE already defeats most code interception here, so this is defence
// in depth. It is also the cheap half: the code is presented twice, and
// that is all the signal needed.
func TestReusingACodeEndsTheSessionItOpened(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	shared := issuer.NewMemoryState()
	iss := issuer.New(issuer.Config{URL: "https://issuer.example"}, set, &fakeDirectory{
		standing: map[string]issuer.Standing{
			"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"directory-admins@north.example"}},
		},
	}, shared)

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, shared)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	// A sign-in, a code, and the first redemption.
	request, err := storage.CreateAuthRequestForTest(ctx, "ada@north.example", "console")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	if err = storage.SaveAuthCode(ctx, request, "the-code"); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	found, err := storage.AuthRequestByCode(ctx, "the-code")
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}

	if _, _, _, err = storage.CreateAccessAndRefreshTokens(ctx, found, ""); err != nil {
		t.Fatalf("CreateAccessAndRefreshTokens: %v", err)
	}

	open, err := iss.Sessions().List(ctx, issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(open) != 1 {
		t.Fatalf("sessions after the first redemption = %d, want 1", len(open))
	}

	// The library deletes the request once the code is spent, which is
	// what makes a second presentation recognisable.
	if err = storage.DeleteAuthRequest(ctx, request); err != nil {
		t.Fatalf("DeleteAuthRequest: %v", err)
	}

	// The second presentation: denied, and the session goes with it.
	if _, err = storage.AuthRequestByCode(ctx, "the-code"); err == nil {
		t.Error("a reused code was accepted")
	}

	open, err = iss.Sessions().List(ctx, issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(open) != 0 {
		t.Errorf("sessions after the reuse = %d, want 0: the tokens that code issued are in doubt", len(open))
	}
}
