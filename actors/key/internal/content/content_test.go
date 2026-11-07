package content_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/actors/key/internal/content"
)

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

const goodHead = `{"alg":"ES384","kid":"k1","typ":"at+jwt"}`
const goodBody = `{"iss":"https://idp.example.com","aud":"app","iat":1000,"exp":1300,"sub":"alice"}`

func TestJWSSigningInput(t *testing.T) {
	ok := b64(goodHead) + "." + b64(goodBody)
	if err := content.JWSSigningInput([]byte(ok), "k1"); err != nil {
		t.Fatalf("a valid input was refused: %v", err)
	}
	cases := map[string]string{
		"wrong kid":      ok,
		"alg ES256":      b64(`{"alg":"ES256","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody),
		"alg none":       b64(`{"alg":"none","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody),
		"bad typ":        b64(`{"alg":"ES384","kid":"k1","typ":"JOSE"}`) + "." + b64(goodBody),
		"extra header":   b64(`{"alg":"ES384","kid":"k1","typ":"JWT","jku":"x"}`) + "." + b64(goodBody),
		"duplicate alg":  b64(`{"alg":"ES256","alg":"ES384","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody),
		"no aud":         b64(goodHead) + "." + b64(`{"iss":"i","iat":1,"exp":2}`),
		"aud array":      b64(goodHead) + "." + b64(`{"iss":"i","aud":["a"],"iat":1,"exp":2}`),
		"no iss":         b64(goodHead) + "." + b64(`{"aud":"a","iat":1,"exp":2}`),
		"float iat":      b64(goodHead) + "." + b64(`{"iss":"i","aud":"a","iat":1.5,"exp":2}`),
		"string exp":     b64(goodHead) + "." + b64(`{"iss":"i","aud":"a","iat":1,"exp":"2"}`),
		"exp equals iat": b64(goodHead) + "." + b64(`{"iss":"i","aud":"a","iat":5,"exp":5}`),
		"payload array":  b64(goodHead) + "." + b64(`[1]`),
		"trailing json":  b64(goodHead) + "." + b64(goodBody+` {}`),
		"padding":        b64(goodHead) + "=." + b64(goodBody),
		"three parts":    ok + ".AAAA",
		"not a jws":      "hello world",
		"empty":          "",
		"compact w/ sig": ok + "." + b64("sig"),
	}
	for name, in := range cases {
		kid := "k1"
		if name == "wrong kid" {
			kid = "k2"
		}
		if err := content.JWSSigningInput([]byte(in), kid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := content.JWSSigningInput([]byte(strings.Repeat("a", content.MaxLen+1)), "k1"); err == nil {
		t.Error("oversize content accepted")
	}
}

// verifies: REQ-KEYS-264, REQ-KEYS-266
// The RS256 purpose signs a JWS signing input whose header is exactly alg RS256, the key's kid and typ JWT: not typ
// at+jwt (an RS256 key signs ID tokens only), not another alg, not an extra member, and the payload is the one every
// token has. A kid is a thumbprint that may begin with '-' or '_' (one in thirty-two does), and is accepted. Neither
// rule takes the other's input.
func TestJWSSigningInputRS256(t *testing.T) {
	const head = `{"alg":"RS256","kid":"k1","typ":"JWT"}`
	ok := b64(head) + "." + b64(goodBody)
	if err := content.JWSSigningInputRS256([]byte(ok), "k1"); err != nil {
		t.Fatalf("a valid input was refused: %v", err)
	}
	for _, kid := range []string{"-0123456789abcdefghijklmnopqrstuvwxyzABCDE", "_0123456789abcdefghijklmnopqrstuvwxyzABCDE", "a-b_c"} {
		in := b64(`{"alg":"RS256","kid":"`+kid+`","typ":"JWT"}`) + "." + b64(goodBody)
		if err := content.JWSSigningInputRS256([]byte(in), kid); err != nil {
			t.Errorf("kid %q refused: %v", kid, err)
		}
	}
	cases := map[string]struct{ in, path string }{
		"at+jwt":           {b64(`{"alg":"RS256","kid":"k1","typ":"at+jwt"}`) + "." + b64(goodBody), "content.header.typ"},
		"AT+JWT":           {b64(`{"alg":"RS256","kid":"k1","typ":"AT+JWT"}`) + "." + b64(goodBody), "content.header.typ"},
		"typ jwt lower":    {b64(`{"alg":"RS256","kid":"k1","typ":"jwt"}`) + "." + b64(goodBody), "content.header.typ"},
		"no typ":           {b64(`{"alg":"RS256","kid":"k1","x":"y"}`) + "." + b64(goodBody), "content.header.typ"},
		"alg ES384":        {b64(goodHead) + "." + b64(goodBody), "content.header.alg"},
		"alg ES384 + JWT":  {b64(`{"alg":"ES384","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"alg PS256":        {b64(`{"alg":"PS256","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"alg HS256":        {b64(`{"alg":"HS256","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"alg none":         {b64(`{"alg":"none","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"alg rs256":        {b64(`{"alg":"rs256","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"alg RS256 padded": {b64(`{"alg":"RS256 ","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"alg is an array":  {b64(`{"alg":["RS256"],"kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header.alg"},
		"wrong kid":        {b64(`{"alg":"RS256","kid":"k2","typ":"JWT"}`) + "." + b64(goodBody), "content.header.kid"},
		"no kid":           {b64(`{"alg":"RS256","kid":"","typ":"JWT"}`) + "." + b64(goodBody), "content.header.kid"},
		"extra jku":        {b64(`{"alg":"RS256","kid":"k1","typ":"JWT","jku":"x"}`) + "." + b64(goodBody), "content.header"},
		"extra crit":       {b64(`{"alg":"RS256","kid":"k1","typ":"JWT","crit":["b64"]}`) + "." + b64(goodBody), "content.header"},
		"two members":      {b64(`{"alg":"RS256","kid":"k1"}`) + "." + b64(goodBody), "content.header"},
		"duplicate alg":    {b64(`{"alg":"ES384","alg":"RS256","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody), "content.header"},
		"no aud":           {b64(head) + "." + b64(`{"iss":"i","iat":1,"exp":2}`), "content.payload.aud"},
		"exp equals iat":   {b64(head) + "." + b64(`{"iss":"i","aud":"a","iat":5,"exp":5}`), "content.payload.exp"},
		"three parts":      {ok + ".AAAA", "content"},
		"a checkpoint":     {"example.com/log\n42\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n", "content.header"},
		"empty":            {"", "content"},
	}
	for name, c := range cases {
		err := content.JWSSigningInputRS256([]byte(c.in), "k1")
		var ce *content.ErrContent
		if !errors.As(err, &ce) || ce.Path != c.path {
			t.Errorf("%s: err = %v, want a refusal at %s", name, err, c.path)
		}
	}
	if err := content.JWSSigningInputRS256([]byte(strings.Repeat("a", content.MaxLen+1)), "k1"); err == nil {
		t.Error("oversize content accepted")
	}
	// Neither purpose signs the other's input.
	esJWT := b64(`{"alg":"ES384","kid":"k1","typ":"JWT"}`) + "." + b64(goodBody)
	for name, in := range map[string]string{"at+jwt": b64(goodHead) + "." + b64(goodBody), "JWT": esJWT} {
		if err := content.JWSSigningInputRS256([]byte(in), "k1"); err == nil {
			t.Errorf("the RS256 rule signs an ES384 %s input", name)
		}
	}
	if err := content.JWSSigningInput([]byte(ok), "k1"); err == nil {
		t.Error("the ES384 rule signs an RS256 input")
	}
}

func TestCheckpoint(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	good := "example.com/log\n42\n" + root + "\n"
	if err := content.Checkpoint([]byte(good)); err != nil {
		t.Fatalf("a valid checkpoint was refused: %v", err)
	}
	if err := content.Checkpoint([]byte(good + "ext line\n")); err != nil {
		t.Fatalf("an extension line was refused: %v", err)
	}
	if err := content.Checkpoint([]byte("example.com/log\n0\n" + root + "\n")); err != nil {
		t.Fatalf("size 0 was refused: %v", err)
	}
	bad := map[string]string{
		"no final newline": strings.TrimSuffix(good, "\n"),
		"two lines":        "example.com/log\n42\n",
		"empty origin":     "\n42\n" + root + "\n",
		"leading zero":     "example.com/log\n042\n" + root + "\n",
		"negative size":    "example.com/log\n-1\n" + root + "\n",
		"text size":        "example.com/log\nabc\n" + root + "\n",
		"short root":       "example.com/log\n42\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"url root":         "example.com/log\n42\n" + strings.Repeat("_", 43) + "=\n",
		"blank extension":  good + "\n",
		"crlf":             "example.com/log\r\n42\r\n" + root + "\r\n",
		"not text":         "\xff\xfe",
		"empty":            "",
	}
	for name, in := range bad {
		if err := content.Checkpoint([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
