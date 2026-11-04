package clientauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeSource struct {
	secrets map[string][]byte
	err     error
	asked   atomic.Int64
}

func (f *fakeSource) Secret(_ context.Context, id string) ([]byte, bool, error) {
	f.asked.Add(1)
	if f.err != nil {
		return nil, false, f.err
	}
	s, ok := f.secrets[id]
	return s, ok, nil
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func TestParse(t *testing.T) {
	for _, c := range []struct {
		name                   string
		authorization, id, sec string
		want                   Credentials
		present                bool
		err                    error
	}{
		{name: "nothing"},
		{name: "a public client names itself only", id: "sluis-cli"},
		{name: "basic", authorization: basic("app", "s3cret"), want: Credentials{"app", "s3cret", Basic}, present: true},
		{name: "basic, scheme in any case", authorization: "bAsIc " + strings.TrimPrefix(basic("app", "s3cret"), "Basic "), want: Credentials{"app", "s3cret", Basic}, present: true},
		// REQ-CLIENT-002: reserved characters are form-URL-encoded before the base64 (RFC 6749 section 2.3.1).
		{name: "basic with reserved characters", authorization: basic("app", "a:b c+d%e/f=g&h"), want: Credentials{"app", "a:b c+d%e/f=g&h", Basic}, present: true},
		{name: "basic with the same id in the body", authorization: basic("app", "s"), id: "app", want: Credentials{"app", "s", Basic}, present: true},
		{name: "post", id: "app", sec: "s3cret", want: Credentials{"app", "s3cret", Post}, present: true},
		{name: "post keeps the characters as sent", id: "app", sec: "a+b%20c", want: Credentials{"app", "a+b%20c", Post}, present: true},
		{name: "both methods", authorization: basic("app", "zq-secret-1"), id: "app", sec: "zq-secret-1", present: true, err: ErrBothMethods},
		{name: "basic names another client than the body", authorization: basic("app", "s"), id: "other", present: true, err: ErrMalformed},
		{name: "a secret with no id", sec: "zq-secret-1", present: true, err: ErrMalformed},
		{name: "another scheme", authorization: "Bearer abc", present: true, err: ErrMalformed},
		{name: "no scheme", authorization: "abc", present: true, err: ErrMalformed},
		{name: "bad base64", authorization: "Basic !!!", present: true, err: ErrMalformed},
		{name: "no colon", authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("app")), present: true, err: ErrMalformed},
		{name: "empty secret", authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("app:")), present: true, err: ErrMalformed},
		{name: "empty id", authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(":s")), present: true, err: ErrMalformed},
		{name: "bad percent-encoding", authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("app:%zz")), present: true, err: ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, present, err := Parse(c.authorization, c.id, c.sec)
			if !errors.Is(err, c.err) || present != c.present || got != c.want {
				t.Errorf("Parse = (%+v, %v, %v), want (%+v, %v, %v)", redact(got), present, err, redact(c.want), c.present, c.err)
			}
			if err != nil && c.sec != "" && strings.Contains(err.Error(), c.sec) {
				t.Errorf("an error shows the secret: %v", err)
			}
		})
	}
}

// redact keeps a failure message from printing a secret.
func redact(c Credentials) Credentials {
	if c.Secret != "" {
		c.Secret = "<set>"
	}
	return c
}

func TestAuthenticate(t *testing.T) {
	src := &fakeSource{secrets: map[string][]byte{"app": []byte("right horse"), "blank": nil}}
	a, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		cred Credentials
		want bool
	}{
		{"the right secret", Credentials{"app", "right horse", Basic}, true},
		{"the right secret by post", Credentials{"app", "right horse", Post}, true},
		{"a wrong secret", Credentials{"app", "wrong horse", Basic}, false},
		{"a prefix of the secret", Credentials{"app", "right", Basic}, false},
		{"the secret and more", Credentials{"app", "right horse!", Basic}, false},
		{"an unknown client", Credentials{"nobody", "right horse", Basic}, false},
		{"a client with an empty secret", Credentials{"blank", "x", Basic}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := a.Authenticate(context.Background(), c.cred)
			if err != nil || got != c.want {
				t.Errorf("Authenticate = %v, %v; want %v", got, err, c.want)
			}
		})
	}
}

// REQ-EXCH-019: a wrong secret, an unknown client and a client with no secret take one path. Each fetches a secret
// once and compares once, so neither the call count nor the work tells them apart.
func TestREQ_EXCH_019_AnUnknownClientAndAWrongSecretShareOnePath(t *testing.T) {
	src := &fakeSource{secrets: map[string][]byte{"app": []byte("right horse")}}
	a, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	var compared atomic.Int64
	a.compare = func(p, s []byte) bool {
		compared.Add(1)
		return equal(p, s)
	}
	for _, id := range []string{"app", "nobody", "also-nobody"} {
		src.asked.Store(0)
		compared.Store(0)
		ok, err := a.Authenticate(context.Background(), Credentials{id, "wrong horse", Basic})
		if err != nil || ok {
			t.Fatalf("%s: %v, %v", id, ok, err)
		}
		if src.asked.Load() != 1 || compared.Load() != 1 {
			t.Errorf("%s: %d fetches and %d comparisons, want 1 and 1", id, src.asked.Load(), compared.Load())
		}
	}
}

func TestASourceThatFailsIsAnOutageNotARefusal(t *testing.T) {
	boom := errors.New("down")
	a, _ := New(&fakeSource{err: boom})
	ok, err := a.Authenticate(context.Background(), Credentials{"app", "s", Basic})
	if ok || !errors.Is(err, boom) {
		t.Errorf("Authenticate = %v, %v", ok, err)
	}
}

func TestTheComparisonIsOverFixedSizeDigests(t *testing.T) {
	if !equal([]byte("a"), []byte("a")) || equal([]byte("a"), []byte("b")) || equal([]byte("a"), []byte("aa")) || equal(nil, []byte("a")) {
		t.Error("equal is wrong")
	}
}

func TestNewRefusesNoSource(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) succeeded")
	}
}
