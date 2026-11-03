//nolint:lll // fixtures are one-line documents
package cloudflare_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/truvity/sluis/storage/cloudflare"
)

func storedDoc(id string, expires time.Time) []byte {
	return fmt.Appendf(nil, `{"schema":"cloudflare/v1","access_key_id":%q,"secret_access_key":"secret-%s","endpoint":"https://acct.r2.example.test","expires_on":%q}`,
		id, id, expires.UTC().Format(time.RFC3339))
}

// source is a document that changes when the test says, counting its reads.
type source struct {
	doc   []byte
	err   error
	reads int
}

func (s *source) read(context.Context) ([]byte, error) {
	s.reads++
	return s.doc, s.err
}

func TestParseStoredR2(t *testing.T) {
	exp := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	got, err := cloudflare.ParseStoredR2(storedDoc("k1", exp))
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != "k1" || got.SecretAccessKey != "secret-k1" || !got.ExpiresOn.Equal(exp) || got.Endpoint == "" {
		t.Fatalf("parsed %+v", got)
	}
	for name, raw := range map[string]string{
		"not json":     `nope`,
		"other schema": `{"schema":"s3-credentials/v1","access_key_id":"a","secret_access_key":"b","expires_on":"2026-10-09T12:00:00Z"}`,
		"token preset": `{"schema":"cloudflare/v1","token":"t","expires_on":"2026-10-09T12:00:00Z"}`,
		"no secret":    `{"schema":"cloudflare/v1","access_key_id":"a","expires_on":"2026-10-09T12:00:00Z"}`,
		"bad expiry":   `{"schema":"cloudflare/v1","access_key_id":"a","secret_access_key":"b","expires_on":"tomorrow"}`,
	} {
		if _, err := cloudflare.ParseStoredR2([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), `"b"`) || strings.Contains(err.Error(), `"t"`) {
			t.Errorf("%s: the error carries a value: %v", name, err)
		}
	}
	// A field this version does not know is not breaking.
	if _, err := cloudflare.ParseStoredR2([]byte(`{"schema":"cloudflare/v1","access_key_id":"a","secret_access_key":"b","expires_on":"2026-10-09T12:00:00Z","new":"x"}`)); err != nil {
		t.Fatalf("an unknown field was refused: %v", err)
	}
}

func TestStoredProviderRereadsBeforeExpiry(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDoc("k1", now.Add(10*time.Minute))}
	p, err := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "/sluis/main/external/cloudflare/r2", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != "k1" || c.SecretAccessKey != "secret-k1" || !c.CanExpire {
		t.Fatalf("credentials %+v", c)
	}
	// Ten minutes left: read again after the recheck, a minute.
	if want := now.Add(cloudflare.DefaultRecheck); !c.Expires.Equal(want) {
		t.Fatalf("expires %s, want %s", c.Expires, want)
	}

	// Close to its end: read again before the margin, never sooner than half
	// the time left.
	src.doc = storedDoc("k1", now.Add(90*time.Second))
	c, _ = p.Retrieve(context.Background())
	if want := now.Add(60 * time.Second); !c.Expires.Equal(want) {
		t.Fatalf("expires %s, want %s (margin)", c.Expires, want)
	}
	src.doc = storedDoc("k1", now.Add(20*time.Second))
	c, _ = p.Retrieve(context.Background())
	if want := now.Add(10 * time.Second); !c.Expires.Equal(want) {
		t.Fatalf("expires %s, want %s (half the time left)", c.Expires, want)
	}

	// A rotated document is picked up at the next read.
	src.doc = storedDoc("k2", now.Add(15*time.Minute))
	if c, _ = p.Retrieve(context.Background()); c.AccessKeyID != "k2" {
		t.Fatalf("rotated credential not read: %s", c.AccessKeyID)
	}
}

func TestStoredProviderRefusesExpired(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDoc("k1", now.Add(-time.Second))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "/etc/audit/sluis/external/cloudflare/r2", Now: func() time.Time { return now }})
	_, err := p.Retrieve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "/etc/audit/sluis/external/cloudflare/r2") {
		t.Fatalf("an expired document: %v", err)
	}
}

func TestStoredProviderKeepsAGoodCredentialThroughAFailedRead(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	src := &source{doc: storedDoc("k1", now.Add(10*time.Minute))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "x", Now: clock})
	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.err = errors.New("throttled")
	c, err := p.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "k1" || !c.Expires.Equal(now.Add(10*time.Second)) {
		t.Fatalf("a failed read with a good credential held: %+v, %v", c, err)
	}
	// Past the margin the failure is the answer.
	now = now.Add(10*time.Minute - 10*time.Second)
	if _, err := p.Retrieve(context.Background()); err == nil || !strings.Contains(err.Error(), "throttled") {
		t.Fatalf("a failed read with the credential running out: %v", err)
	}
}

func TestStoredProviderReauthenticate(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDoc("k1", now.Add(10*time.Minute))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "x", Now: func() time.Time { return now }})
	cache := aws.NewCredentialsCache(p)
	if c, err := cache.Retrieve(context.Background()); err != nil || c.AccessKeyID != "k1" {
		t.Fatalf("%+v %v", c, err)
	}
	// The same document after a 403, the credential past its settling: nothing
	// replaced, the request is not sent again.
	now = now.Add(cloudflare.DefaultSettle)
	if replaced, err := p.Reauthenticate(context.Background()); err != nil || replaced {
		t.Fatalf("unchanged document: replaced=%v err=%v", replaced, err)
	}
	// Within MinReauth the document is not read again.
	src.doc = storedDoc("k2", now.Add(15*time.Minute))
	reads := src.reads
	if replaced, _ := p.Reauthenticate(context.Background()); replaced || src.reads != reads {
		t.Fatal("read again within MinReauth")
	}
	now = now.Add(cloudflare.MinReauth)
	if replaced, err := p.Reauthenticate(context.Background()); err != nil || !replaced {
		t.Fatalf("rotated document: replaced=%v err=%v", replaced, err)
	}
	cache.Invalidate()
	if c, _ := cache.Retrieve(context.Background()); c.AccessKeyID != "k2" {
		t.Fatalf("after a reauthentication: %s", c.AccessKeyID)
	}
}

func storedDocSecret(id, secret string, expires time.Time) []byte {
	return fmt.Appendf(nil, `{"schema":"cloudflare/v1","access_key_id":%q,"secret_access_key":%q,"endpoint":"https://acct.r2.example.test","expires_on":%q}`,
		id, secret, expires.UTC().Format(time.RFC3339))
}

// A credential rotated in place keeps its access key id and changes its
// secret: that is a replacement, and the request is sent again.
func TestStoredProviderReauthenticateSameIDNewSecret(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDocSecret("k1", "s1", now.Add(time.Hour))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "x", Now: func() time.Time { return now }})
	cloudflare.SetSleep(p, func(context.Context, time.Duration) error { t.Fatal("waited for a replaced credential"); return nil })
	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(cloudflare.DefaultSettle)
	src.doc = storedDocSecret("k1", "s2", now.Add(time.Hour))
	if replaced, err := p.Reauthenticate(context.Background()); err != nil || !replaced {
		t.Fatalf("same id, new secret: replaced=%v err=%v", replaced, err)
	}
	if c, _ := p.Retrieve(context.Background()); c.AccessKeyID != "k1" || c.SecretAccessKey != "s2" {
		t.Fatal("the new secret is not handed out")
	}
}

// A credential read moments ago and refused is one the store may not accept
// yet (R2 refuses a token Cloudflare has just created): the refusal is waited
// out once, up to Settle after the credential was first read, and the request
// is sent again. Every request refused meanwhile waits for the same moment.
func TestStoredProviderReauthenticateWaitsForANewCredential(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDoc("k1", now.Add(time.Hour))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "x", Now: func() time.Time { return now }})
	var waited []time.Duration
	cloudflare.SetSleep(p, func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil })
	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The rotation is read: k2, just created.
	now = now.Add(cloudflare.DefaultRecheck)
	src.doc = storedDoc("k2", now.Add(time.Hour))
	if c, _ := p.Retrieve(context.Background()); c.AccessKeyID != "k2" {
		t.Fatalf("rotated credential not read: %s", c.AccessKeyID)
	}
	// Refused 100 ms later, the document unchanged.
	now = now.Add(100 * time.Millisecond)
	reads := src.reads
	if replaced, err := p.Reauthenticate(context.Background()); err != nil || !replaced {
		t.Fatalf("a new credential refused: replaced=%v err=%v", replaced, err)
	}
	if src.reads != reads+1 {
		t.Fatalf("the document was read %d times, want once", src.reads-reads)
	}
	// A second request refused within MinReauth: not read again, waits too.
	now = now.Add(400 * time.Millisecond)
	if replaced, err := p.Reauthenticate(context.Background()); err != nil || !replaced || src.reads != reads+1 {
		t.Fatalf("a second refusal: replaced=%v err=%v reads=%d", replaced, err, src.reads-reads)
	}
	if want := []time.Duration{cloudflare.DefaultSettle - 100*time.Millisecond, cloudflare.DefaultSettle - 500*time.Millisecond}; fmt.Sprint(waited) != fmt.Sprint(want) {
		t.Fatalf("waited %v, want %v", waited, want)
	}
	// Once it has settled, a refusal is the answer.
	now = now.Add(cloudflare.DefaultSettle)
	if replaced, err := p.Reauthenticate(context.Background()); err != nil || replaced {
		t.Fatalf("a settled credential refused: replaced=%v err=%v", replaced, err)
	}
	if len(waited) != 2 {
		t.Fatalf("waited again for a settled credential: %v", waited)
	}
}

func TestStoredProviderReauthenticateWaitEndsWithTheContext(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDoc("k1", now.Add(time.Hour))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "x", Now: func() time.Time { return now }, Settle: time.Hour})
	if _, err := p.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if replaced, err := p.Reauthenticate(ctx); replaced || !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled wait: replaced=%v err=%v", replaced, err)
	}
	// A negative Settle waits for nothing.
	q, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{Read: src.read, Source: "x", Now: func() time.Time { return now }, Settle: -1})
	cloudflare.SetSleep(q, func(context.Context, time.Duration) error { t.Fatal("waited with a negative Settle"); return nil })
	if _, err := q.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if replaced, err := q.Reauthenticate(context.Background()); err != nil || replaced {
		t.Fatalf("negative Settle: replaced=%v err=%v", replaced, err)
	}
}

func TestSameEndpoint(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"https://acct.r2.example.test", "https://acct.r2.example.test", true},
		{"HTTPS://Acct.R2.Example.Test/", "https://acct.r2.example.test", true},
		{"https://acct.r2.example.test", "https://acct.eu.r2.example.test", false},
		{"https://acct.r2.example.test", "http://acct.r2.example.test", false},
		{"", "https://acct.r2.example.test", false},
		{"acct.r2.example.test", "acct.r2.example.test", false},
	} {
		if got := cloudflare.SameEndpoint(c.a, c.b); got != c.same {
			t.Errorf("SameEndpoint(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// The endpoint is checked at every read: a rotated document that points at
// another store is refused, and the credential held from the right one is kept
// while it is good, as for any read that fails.
func TestStoredProviderRefusesAnotherEndpointAtEveryRead(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	src := &source{doc: storedDoc("k1", now.Add(10*time.Minute))}
	p, _ := cloudflare.NewStoredProvider(cloudflare.StoredConfig{
		Read: src.read, Source: "/sluis/main/external/cloudflare/r2", Endpoint: "https://ACCT.r2.example.test/", Now: func() time.Time { return now },
	})
	if c, err := p.Retrieve(context.Background()); err != nil || c.AccessKeyID != "k1" {
		t.Fatalf("the matching endpoint: %+v %v", c, err)
	}
	src.doc = []byte(strings.Replace(string(storedDoc("k2", now.Add(15*time.Minute))), "acct.r2", "other.r2", 1))
	c, err := p.Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "k1" || !c.Expires.Equal(now.Add(10*time.Second)) {
		t.Fatalf("a rotation to another endpoint with a good credential held: %+v, %v", c, err)
	}
	if replaced, err := p.Reauthenticate(context.Background()); replaced || err == nil {
		t.Fatalf("after a 403: replaced=%v err=%v", replaced, err)
	}
	now = now.Add(10*time.Minute - 10*time.Second)
	_, err = p.Retrieve(context.Background())
	if err == nil {
		t.Fatal("another endpoint was accepted once the held credential ran out")
	}
	for _, want := range []string{"/sluis/main/external/cloudflare/r2", "https://other.r2.example.test", "https://ACCT.r2.example.test/"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "secret-k2") {
		t.Errorf("the refusal carries the secret: %v", err)
	}
	// A document with no endpoint is refused as well.
	p, _ = cloudflare.NewStoredProvider(cloudflare.StoredConfig{
		Read: func(context.Context) ([]byte, error) {
			return []byte(`{"schema":"cloudflare/v1","access_key_id":"a","secret_access_key":"b","expires_on":"2099-01-01T00:00:00Z"}`), nil
		},
		Source: "x", Endpoint: "https://acct.r2.example.test",
	})
	if _, err := p.Retrieve(context.Background()); err == nil {
		t.Fatal("a document without an endpoint was accepted")
	}
}
