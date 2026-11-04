package content_test

import (
	"encoding/base64"
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
