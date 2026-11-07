package jwtbcp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/tests/jwtbcp"
)

func profile(t *testing.T, alg jose.SignatureAlgorithm, curve elliptic.Curve, typ string) jwtbcp.Profile {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jwtbcp.Profile{
		SpareRSA: rk, RSAPinned: typ == "",
		Alg: alg, Key: k, KID: "k1", Typ: typ, Now: now,
		Claims: map[string]any{
			"iss": "https://issuer.example.com", "aud": "client-1", "sub": "s", "iat": now.Add(-time.Minute).Unix(),
			"exp": now.Add(time.Hour).Unix(),
		},
		IssuerClaim: "iss", AudienceClaim: "aud", CheckExp: true,
	}
}

// The vectors are only worth anything if each one breaks what it says it breaks. A vector of the rules that are about
// claims must carry a signature that verifies, or a verifier that refuses it may be refusing the signature and its own
// claim check is not tested; and a vector of the rules about the signature or the header must be refused by a
// strict reference verifier, or it is not a vector.
func TestEachVectorBreaksOnlyWhatItNames(t *testing.T) {
	for _, p := range []jwtbcp.Profile{
		profile(t, jose.ES384, elliptic.P384(), "at+jwt"),
		profile(t, jose.ES256, elliptic.P256(), ""),
	} {
		strict := func(token string) error {
			tok, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{p.Alg})
			if err != nil {
				return err
			}
			if len(tok.Signatures) != 1 {
				return errMultiple
			}
			// The key set holds the spare RSA key too; the reference verifier pins the algorithm and finds the key by kid.
			set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.Public(), p.Spare()}}
			keys := set.Key(tok.Signatures[0].Header.KeyID)
			if len(keys) == 0 {
				return errNoKey
			}
			_, err = tok.Verify(keys[0])
			return err
		}
		if err := strict(jwtbcp.Valid(t, p)); err != nil {
			t.Fatalf("the valid token does not verify: %v", err)
		}
		vectors := jwtbcp.Negative(t, p)
		if len(vectors) < 50 {
			t.Fatalf("only %d vectors", len(vectors))
		}
		seen := map[string]bool{}
		rules := map[jwtbcp.Rule]int{}
		for _, v := range vectors {
			if seen[v.Name] {
				t.Errorf("two vectors are called %q", v.Name)
			}
			seen[v.Name] = true
			rules[v.Rule]++
			err := strict(v.Token)
			switch v.Rule {
			case jwtbcp.RuleTyp, jwtbcp.RuleIss, jwtbcp.RuleAud, jwtbcp.RuleTime:
				if err != nil {
					t.Errorf("%s: %q should carry a valid signature but the reference refuses it: %v", v.Rule, v.Name, err)
				}
			default:
				// crit and b64 are refused by go-jose too; the rest fail on the algorithm or the signature.
				if err == nil {
					t.Errorf("%s: %q is accepted by the reference verifier", v.Rule, v.Name)
				}
			}
		}
		want := []jwtbcp.Rule{jwtbcp.RuleFormat, jwtbcp.RuleAlg, jwtbcp.RuleKey, jwtbcp.RuleIss, jwtbcp.RuleAud, jwtbcp.RuleTime}
		if p.Typ != "" {
			want = append(want, jwtbcp.RuleTyp)
		}
		for _, r := range want {
			if rules[r] == 0 {
				t.Errorf("no vector of the rule %s", r)
			}
		}
		if p.Typ == "" && rules[jwtbcp.RuleTyp] != 0 {
			t.Errorf("a typ vector for a verifier that requires no type")
		}
	}
}

type constErr string

func (e constErr) Error() string { return string(e) }

const (
	errMultiple = constErr("more than one signature")
	errNoKey    = constErr("no key of that id")
)
