package issuer_test

import (
	"context"
	"testing"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// Revocation has to reach the shared state, whichever replica answers.
//
// The session index is per-process: it only ever knows the sessions the
// replica that recorded them holds. Taking a hit there as proof that
// revocation is done would leave the token itself valid at every replica
// — a security control that reports success and leaves access in place,
// which is worse than one that fails.
func TestRevocationReachesTheSharedStateEitherWay(t *testing.T) {
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

	for _, recorded := range []bool{false, true} {
		name := "a session this replica never saw"
		if recorded {
			name = "a session this replica recorded"
		}
		t.Run(name, func(t *testing.T) {
			id, expires, err := storage.CreateAccessToken(ctx, tokenRequest{
				subject: "ada@north.example", clientID: "console",
			})
			if err != nil {
				t.Fatalf("CreateAccessToken: %v", err)
			}
			if expires.IsZero() {
				t.Fatal("the token has no expiry")
			}
			if recorded {
				if _, err := iss.Sessions().Record(context.Background(), issuer.Opened{
					Identity: "ada@north.example", ClientID: "console", How: issuer.HowCode, Token: id,
				}); err != nil {
					t.Fatalf("record: %v", err)
				}
			}

			if oidcErr := storage.RevokeToken(ctx, id, "", "console"); oidcErr != nil {
				t.Fatalf("RevokeToken: %v", oidcErr)
			}
			// The token is what every replica resolves against, so it is
			// the thing that has to be gone.
			if _, found, err := shared.Get(ctx, "issuer:token:"+id); err != nil || found {
				t.Errorf("%s: the token survived revocation (found=%v)", name, found)
			}
		})
	}
}

// tokenRequest is the smallest thing the storage will issue against.
type tokenRequest struct {
	subject  string
	clientID string
}

func (r tokenRequest) GetSubject() string    { return r.subject }
func (r tokenRequest) GetAudience() []string { return []string{r.clientID} }
func (r tokenRequest) GetScopes() []string   { return []string{"openid"} }
func (r tokenRequest) GetClientID() string   { return r.clientID }
