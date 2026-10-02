package verify_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/verify"
)

const (
	awsAccount  = "111122223333"
	awsAudience = "https://access.example.com"
)

// fakeAWS stands in for one account's outbound identity federation issuer:
// a key set at /.well-known/jwks.json holding a P-384 and an RSA key, which
// a test can rotate.
type fakeAWS struct {
	*httptest.Server

	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetches int
}

func newFakeAWS(t *testing.T) *fakeAWS {
	t.Helper()

	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	fake := &fakeAWS{ec: ec, rsa: rsaKey}
	fake.keys = []jose.JSONWebKey{
		{Key: ec.Public(), KeyID: "ec-1", Algorithm: "ES384", Use: "sig"},
		{Key: rsaKey.Public(), KeyID: "rsa-1", Algorithm: "RS256", Use: "sig"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fake.fetches++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: fake.keys})
	})
	fake.Server = httptest.NewServer(mux)
	t.Cleanup(fake.Close)

	return fake
}

func (f *fakeAWS) fetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func (f *fakeAWS) publish(keys ...jose.JSONWebKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = keys
}

// tokenOpts shapes one minted token. The zero value is a good ES384 token.
type tokenOpts struct {
	alg     jose.SignatureAlgorithm
	kid     string
	signer  any
	claims  map[string]any
	awsNS   map[string]any
	dropKey string // top-level claim to remove
}

func (f *fakeAWS) mint(t *testing.T, o tokenOpts) string {
	t.Helper()

	if o.alg == "" {
		o.alg = jose.ES384
	}
	if o.signer == nil {
		if o.alg == jose.RS256 {
			o.signer = f.rsa
		} else {
			o.signer = f.ec
		}
	}
	if o.kid == "" {
		o.kid = map[jose.SignatureAlgorithm]string{jose.ES384: "ec-1", jose.RS256: "rsa-1"}[o.alg]
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: o.alg, Key: o.signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", o.kid),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ns := map[string]any{"aws_account": awsAccount, "source_region": "eu-west-1", "org_id": "o-abc1234567"}
	for k, v := range o.awsNS {
		ns[k] = v
	}
	full := map[string]any{
		"iss":                        f.URL,
		"sub":                        "arn:aws:iam::111122223333:role/otel-writer",
		"aud":                        awsAudience,
		"iat":                        time.Now().Unix(),
		"exp":                        time.Now().Add(5 * time.Minute).Unix(),
		"jti":                        "abc",
		"https://sts.amazonaws.com/": ns,
	}
	for k, v := range o.claims {
		full[k] = v
	}
	if o.dropKey != "" {
		delete(full, o.dropKey)
	}
	raw, err := jwt.Signed(sig).Claims(full).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func (f *fakeAWS) verifier() *verify.AWSAccount {
	return &verify.AWSAccount{
		Account:    awsAccount,
		Name:       "apps",
		Issuer:     f.URL,
		Audience:   awsAudience,
		Client:     f.Client(),
		KeyRefresh: time.Nanosecond,
	}
}

func refused(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("verified, want a refusal mentioning %q", want)
	}
	if errors.Is(err, issuer.ErrUnverified) {
		t.Fatalf("got ErrUnverified (falls through to the next verifier), want a final refusal: %v", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want it to mention %q", err, want)
	}
}

func TestAnAWSRoleProvesItselfWithEitherAlgorithm(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)

	for _, alg := range []jose.SignatureAlgorithm{jose.ES384, jose.RS256} {
		proof, err := fake.verifier().Verify(context.Background(),
			fake.mint(t, tokenOpts{alg: alg, awsNS: map[string]any{
				"lambda_source_function_arn": "arn:aws:lambda:eu-west-1:111122223333:function:ingest",
			}}), verify.TypeJWT)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		role := proof.AWS
		if role == nil || role.Account != awsAccount || role.Name != "otel-writer" || role.Path != "/" ||
			role.OrgID != "o-abc1234567" || !strings.HasSuffix(role.Function, ":function:ingest") {
			t.Fatalf("%s: proof = %+v", alg, role)
		}
		if got := proof.Subject(); got != "aws:"+awsAccount+":role/otel-writer" {
			t.Errorf("%s: subject = %q", alg, got)
		}
	}
}

func TestAudienceMayBeAListOrAString(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)

	_, err := fake.verifier().Verify(context.Background(),
		fake.mint(t, tokenOpts{claims: map[string]any{"aud": []string{"other", awsAudience}}}), "")
	if err != nil {
		t.Fatalf("a list holding the audience: %v", err)
	}
}

func TestARoleWithAPathKeepsItAsPartOfTheSubject(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)

	proof, err := fake.verifier().Verify(context.Background(), fake.mint(t, tokenOpts{
		claims: map[string]any{"sub": "arn:aws:iam::111122223333:role/service/telemetry/otel-writer"},
	}), verify.TypeJWT)
	if err != nil {
		t.Fatal(err)
	}
	if proof.AWS.Path != "/service/telemetry/" || proof.AWS.Name != "otel-writer" {
		t.Errorf("proof = %+v", proof.AWS)
	}
	if got, want := proof.Subject(), "aws:"+awsAccount+":role/service/telemetry/otel-writer"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
}

func TestRefusals(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	otherEC, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)

	cases := map[string]struct {
		opts tokenOpts
		want string
	}{
		"wrong audience":  {tokenOpts{claims: map[string]any{"aud": "https://elsewhere.example"}}, "another audience"},
		"bad signature":   {tokenOpts{signer: otherEC}, "did not verify"},
		"unpublished key": {tokenOpts{kid: "ec-9"}, "does not publish"},
		"expired": {tokenOpts{claims: map[string]any{
			"iat": old.Add(-time.Hour).Unix(), "exp": old.Unix(),
		}}, "expired"},
		"older than maxAge though exp allows": {tokenOpts{claims: map[string]any{
			"iat": old.Unix(), "exp": time.Now().Add(50 * time.Minute).Unix(),
		}}, "older than"},
		"issued in the future": {tokenOpts{claims: map[string]any{
			"iat": time.Now().Add(time.Hour).Unix(),
		}}, "future"},
		"not yet valid": {tokenOpts{claims: map[string]any{
			"nbf": time.Now().Add(time.Hour).Unix(),
		}}, "not valid yet"},
		"no expiry":              {tokenOpts{dropKey: "exp"}, "no expiry"},
		"no iat":                 {tokenOpts{dropKey: "iat"}, "no issue time"},
		"account claim mismatch": {tokenOpts{awsNS: map[string]any{"aws_account": "444455556666"}}, "claims account"},
		"role in another account": {tokenOpts{claims: map[string]any{
			"sub": "arn:aws:iam::444455556666:role/otel-writer",
		}}, "is in account"},
		"wrong alg (ES256 not offered by AWS)": {tokenOpts{alg: jose.HS256, signer: []byte("0123456789abcdef0123456789abcdef")}, "accepted algorithm"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := fake.verifier().Verify(context.Background(), fake.mint(t, tc.opts), verify.TypeJWT)
			refused(t, err, tc.want)
		})
	}
}

func TestMalformedSubjects(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)

	for name, sub := range map[string]string{
		"assumed-role session":  "arn:aws:sts::111122223333:assumed-role/otel-writer/i-0123",
		"user":                  "arn:aws:iam::111122223333:user/alice",
		"root":                  "arn:aws:iam::111122223333:root",
		"federated user":        "arn:aws:sts::111122223333:federated-user/bob",
		"other partition":       "arn:aws-cn:iam::111122223333:role/otel-writer",
		"empty":                 "",
		"not an arn":            "otel-writer",
		"short account":         "arn:" + "aws:iam::1234:role/otel-writer",
		"empty role":            "arn:aws:iam::111122223333:role/",
		"empty path element":    "arn:aws:iam::111122223333:role/a//b",
		"trailing slash":        "arn:aws:iam::111122223333:role/a/",
		"illegal character":     "arn:aws:iam::111122223333:role/otel writer",
		"glob character":        "arn:aws:iam::111122223333:role/otel-*",
		"suffix after the role": "arn:aws:iam::111122223333:role/otel-writer:extra",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := fake.verifier().Verify(context.Background(),
				fake.mint(t, tokenOpts{claims: map[string]any{"sub": sub}}), verify.TypeJWT)
			if err == nil || errors.Is(err, issuer.ErrUnverified) {
				t.Fatalf("sub %q: err = %v, want a final refusal", sub, err)
			}
		})
	}

	// The refusal of the session form says why, so an operator who sees
	// it knows what AWS sent.
	_, err := fake.verifier().Verify(context.Background(), fake.mint(t, tokenOpts{
		claims: map[string]any{"sub": "arn:aws:sts::111122223333:assumed-role/otel-writer/s"},
	}), verify.TypeJWT)
	refused(t, err, "assumed-role session")
}

func TestParseAWSRoleARN(t *testing.T) {
	t.Parallel()

	role, err := verify.ParseAWSRoleARN("arn:aws:iam::111122223333:role/a/b/c.d_e+f=g,h@i-j")
	if err != nil {
		t.Fatal(err)
	}
	if role.Path != "/a/b/" || role.Name != "c.d_e+f=g,h@i-j" || role.Account != awsAccount {
		t.Errorf("role = %+v", role)
	}
	if _, err = verify.ParseAWSRoleARN("arn:aws:iam::111122223333:role/" + strings.Repeat("x", 65)); err == nil {
		t.Error("a 65-character role name was accepted")
	}
}

func TestAnotherIssuersTokenIsNotThisVerifiersToCall(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	other := newFakeAWS(t)

	_, err := fake.verifier().Verify(context.Background(), other.mint(t, tokenOpts{}), verify.TypeJWT)
	if !errors.Is(err, issuer.ErrUnverified) {
		t.Fatalf("wrong iss: err = %v, want ErrUnverified so the next verifier may try it", err)
	}
	for _, token := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err = fake.verifier().Verify(context.Background(), token, verify.TypeJWT); !errors.Is(err, issuer.ErrUnverified) {
			t.Errorf("%q: err = %v, want ErrUnverified", token, err)
		}
	}
	// A subject token type this verifier does not answer for.
	if _, err = fake.verifier().Verify(context.Background(), fake.mint(t, tokenOpts{}),
		"urn:ietf:params:oauth:token-type:saml2"); !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("token type: err = %v", err)
	}
}

// Recognised by its issuer and then refused is final, however it fails,
// including a token that claims `alg: none`.
func TestAnUnsignedTokenClaimingTheRightIssuerIsRefused(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	enc := base64.RawURLEncoding.EncodeToString
	payload, _ := json.Marshal(map[string]any{
		"iss": fake.URL, "sub": "arn:aws:iam::111122223333:role/otel-writer", "aud": awsAudience,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"https://sts.amazonaws.com/": map[string]any{"aws_account": awsAccount},
	})
	token := enc([]byte(`{"alg":"none","kid":"ec-1"}`)) + "." + enc(payload) + "."

	_, err := fake.verifier().Verify(context.Background(), token, verify.TypeJWT)
	refused(t, err, "accepted algorithm")
}

func TestARowCanNarrowTheAlgorithms(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()
	v.Algs = []string{"ES384"}

	if _, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{}), ""); err != nil {
		t.Fatalf("ES384: %v", err)
	}
	_, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{alg: jose.RS256}), "")
	refused(t, err, "accepted algorithm")
}

func TestAKeyPublishedForAnotherAlgorithmDoesNotVerify(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	fake.publish(jose.JSONWebKey{Key: fake.ec.Public(), KeyID: "ec-1", Algorithm: "RS256", Use: "sig"})

	_, err := fake.verifier().Verify(context.Background(), fake.mint(t, tokenOpts{}), "")
	refused(t, err, "published for")
}

func TestOrganizationIsRequiredWhenTheRowSaysSo(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()
	v.OrgID = "o-abc1234567"
	if _, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{}), ""); err != nil {
		t.Fatalf("matching org: %v", err)
	}

	_, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{awsNS: map[string]any{"org_id": "o-other"}}), "")
	refused(t, err, "organization")
	_, err = v.Verify(context.Background(), fake.mint(t, tokenOpts{awsNS: map[string]any{"org_id": ""}}), "")
	refused(t, err, "organization")
}

func TestMaxAgeIsConfigurable(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()
	v.MaxAge = time.Hour
	three := time.Now().Add(-3 * time.Minute)
	tok := fake.mint(t, tokenOpts{claims: map[string]any{"iat": three.Unix()}})
	if _, err := v.Verify(context.Background(), tok, ""); err != nil {
		t.Fatal(err)
	}
	v.MaxAge = time.Minute
	_, err := v.Verify(context.Background(), tok, "")
	refused(t, err, "older than")
}

// AWS rotates the keys behind an account's issuer. A token signed with a
// key the cache has not seen makes the verifier fetch the set again.
func TestKeyRotation(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()

	if _, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{}), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{}), ""); err != nil {
		t.Fatal(err)
	}
	if got := fake.fetchCount(); got != 1 {
		t.Fatalf("fetches = %d, want the second token served from the cache", got)
	}

	next, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake.publish(
		jose.JSONWebKey{Key: next.Public(), KeyID: "ec-2", Algorithm: "ES384", Use: "sig"},
		jose.JSONWebKey{Key: fake.rsa.Public(), KeyID: "rsa-1", Algorithm: "RS256", Use: "sig"},
	)
	time.Sleep(2 * time.Millisecond) // past KeyRefresh

	if _, err = v.Verify(context.Background(), fake.mint(t, tokenOpts{signer: next, kid: "ec-2"}), ""); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	// The retired key no longer verifies once the set has been refreshed.
	time.Sleep(2 * time.Millisecond)
	_, err = v.Verify(context.Background(), fake.mint(t, tokenOpts{}), "")
	refused(t, err, "does not publish")
}

// A caller cannot make this service hammer AWS by naming keys that do
// not exist.
func TestUnknownKeysDoNotRefetchWithinTheRefreshWindow(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()
	v.KeyRefresh = time.Hour

	for range 5 {
		_, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{kid: "nope"}), "")
		refused(t, err, "does not publish")
	}
	if got := fake.fetchCount(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestAnUnreachableKeySetIsNotTheCallersFault(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()
	tok := fake.mint(t, tokenOpts{})
	fake.Close()

	_, err := v.Verify(context.Background(), tok, "")
	if err == nil || errors.Is(err, issuer.ErrUnverified) || strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("err = %v, want an operator-side failure that is neither a fall-through nor a verdict on the token", err)
	}
}

func TestAnExplicitKeySetLocationIsHonoured(t *testing.T) {
	t.Parallel()
	fake := newFakeAWS(t)
	v := fake.verifier()
	v.JWKSURI = fake.URL + "/elsewhere" // 404: proves an explicit URI is honoured
	_, err := v.Verify(context.Background(), fake.mint(t, tokenOpts{}), "")
	if err == nil || errors.Is(err, issuer.ErrUnverified) {
		t.Fatalf("err = %v", err)
	}
}

func writeAWSFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aws.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAWSFederation(t *testing.T) {
	t.Parallel()

	good := `
audience: https://access.example.com
maxAge: 2m
accounts:
  - account: "111122223333"
    name: apps
    issuer: https://abc123-def456-ghi789-jkl012.tokens.sts.global.api.aws
    orgId: o-abc1234567
    algs: [ES384]
  - account: "444455556666"
    name: data
    issuer: https://zzz.tokens.sts.global.api.aws/
    jwksUri: https://keys.example.com/jwks.json
`
	f, err := verify.LoadAWSFederation(writeAWSFile(t, good))
	if err != nil {
		t.Fatal(err)
	}
	vs := f.Verifiers(nil)
	if len(vs) != 2 || vs[0].MaxAge != 2*time.Minute || vs[0].Audience != "https://access.example.com" ||
		vs[0].OrgID != "o-abc1234567" || len(vs[0].Algs) != 1 ||
		vs[1].Issuer != "https://zzz.tokens.sts.global.api.aws" {
		t.Fatalf("verifiers = %+v", vs)
	}

	if f, err = verify.LoadAWSFederation(""); err != nil || len(f.Accounts) != 0 {
		t.Fatalf("no file: %v %v", f, err)
	}
	if f, err = verify.LoadAWSFederation(writeAWSFile(t, "")); err != nil || len(f.Accounts) != 0 {
		t.Fatalf("empty file: %v %v", f, err)
	}

	row := func(extra string) string {
		return "audience: a\naccounts:\n  - account: \"111122223333\"\n    name: apps\n    issuer: https://x.example\n" + extra
	}
	for name, body := range map[string]string{
		"no audience":       "accounts:\n  - {account: \"111122223333\", name: a, issuer: \"https://x.example\"}\n",
		"short account":     strings.Replace(row(""), "111122223333", "1234", 1),
		"http issuer":       strings.Replace(row(""), "https://x", "http://x", 1),
		"no name":           strings.Replace(row(""), "name: apps", "name: \"\"", 1),
		"bad alg":           row("    algs: [ES256]\n"),
		"unknown key":       row("    orgid: o-1\n"),
		"maxAge too long":   "maxAge: 2h\n" + row(""),
		"duplicate account": row("") + "  - {account: \"111122223333\", name: b, issuer: \"https://y.example\"}\n",
		"duplicate issuer":  row("") + "  - {account: \"444455556666\", name: b, issuer: \"https://x.example/\"}\n",
		"duplicate name":    row("") + "  - {account: \"444455556666\", name: apps, issuer: \"https://y.example\"}\n",
		"http jwksUri":      row("    jwksUri: http://x.example/k\n"),
	} {
		if _, err := verify.LoadAWSFederation(writeAWSFile(t, body)); err == nil {
			t.Errorf("%s: loaded, want a start-up failure", name)
		}
	}
	if _, err := verify.LoadAWSFederation(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing file loaded")
	}
}
