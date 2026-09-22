package issuer_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/truvity/access-roster/internal/issuer"
)

// The console reads another service as the person signed in with a token
// minted here: the exchange's decision, the issuer's key, and no longer than
// asked for.
func TestMintForSignsWhatAnExchangeWouldDecide(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example":    live("directory-admins@north.example", "engineering@north.example"),
		"nobody@north.example": live(),
	}}
	iss := newIssuer(t, dir)
	key, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, key, issuer.NewMemoryState())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	token, expires, err := storage.MintFor(ctx, "Ada@North.Example", "aws:1111:power", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(expires); left > 5*time.Minute || left < 4*time.Minute {
		t.Errorf("expires in %s, want the five minutes asked for", left)
	}
	// Every algorithm the issuer may sign with, so this does not have to be
	// edited each time the default key type changes.
	signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256, jose.ES256, jose.ES384, jose.ES512,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := signed.Verify(key.Key().(crypto.Signer).Public())
	if err != nil {
		t.Fatalf("the token is not signed with the issuer's key: %v", err)
	}
	var claims struct {
		Issuer   string   `json:"iss"`
		Subject  string   `json:"sub"`
		Audience []string `json:"aud"`
		Groups   []string `json:"groups"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://issuer.example" || claims.Subject != "ada@north.example" ||
		!slices.Equal(claims.Audience, []string{"aws:1111:power"}) || !slices.Contains(claims.Groups, "rung:platform") {
		t.Errorf("claims = %+v", claims)
	}

	if _, _, err = storage.MintFor(ctx, "nobody@north.example", "aws:1111:power", time.Minute); !errors.Is(err, issuer.ErrRefused) {
		t.Errorf("somebody the client does not admit = %v, want a refusal", err)
	}
	if _, _, err = storage.MintFor(ctx, "", "aws:1111:power", time.Minute); !errors.Is(err, issuer.ErrNoPerson) {
		t.Errorf("no address = %v, want ErrNoPerson", err)
	}
}
