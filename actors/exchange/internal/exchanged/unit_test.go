package exchanged

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPairwiseSubIs256BitsOfBase64URLWithoutPadding(t *testing.T) {
	sub := pairwiseSub(make([]byte, 48))
	if len(sub) != 43 || strings.ContainsAny(sub, "=+/") {
		t.Errorf("sub = %q", sub)
	}
}

func TestNarrowKeepsTheHeldNamesOfThePairsTheAudienceRequires(t *testing.T) {
	held := []string{"dev:app:user", "dev:app:admin", "dev:other:admin", "acme:app:user", "dev:app:user", "bad", "dev:app:"}
	got := narrow(held, []string{"dev:app:operator", "*:x:y", "worse"})
	if strings.Join(got, ",") != "dev:app:admin,dev:app:user" {
		t.Errorf("narrow = %v", got)
	}
	if got := narrow(held, nil); got == nil || len(got) != 0 {
		t.Errorf("narrow with no requires = %#v, want an empty slice", got)
	}
}

func TestLifetimeIsTheEarliestOfTheFour(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, c := range []struct {
		name              string
		issuer, clientCap time.Duration
		subjectLeft       time.Duration
		wantLife          int64
		wantOK            bool
	}{
		{"issuer", 10 * time.Minute, 0, time.Hour, 600, true},
		{"client cap", 10 * time.Minute, time.Minute, time.Hour, 60, true},
		{"subject", 10 * time.Minute, 0, 5 * time.Second, 5, true},
		{"built-in maximum", 5 * time.Hour, 0, 5 * time.Hour, 3600, true},
		{"nothing left", time.Hour, 0, 500 * time.Millisecond, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			iat, exp, ok := lifetime(now, c.issuer, c.clientCap, now.Add(c.subjectLeft))
			if ok != c.wantOK || (ok && exp-iat != c.wantLife) {
				t.Errorf("lifetime = %d, %v; want %d, %v", exp-iat, ok, c.wantLife, c.wantOK)
			}
		})
	}
}

func TestCacheTTL(t *testing.T) {
	for _, c := range []struct {
		header []string
		want   time.Duration
	}{
		{nil, 5 * time.Minute},
		{[]string{"public, max-age=600"}, 10 * time.Minute},
		{[]string{"max-age=0"}, 0},
		{[]string{"no-store"}, 0},
		{[]string{"no-cache"}, 0},
		{[]string{"max-age=60", "no-store"}, 0},
		{[]string{"max-age=junk"}, 0},
		{[]string{"max-age=9999999999"}, 24 * time.Hour},
		{[]string{"MAX-AGE=\"120\""}, 2 * time.Minute},
	} {
		if got := cacheTTL(c.header); got != c.want {
			t.Errorf("cacheTTL(%v) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestCheckURL(t *testing.T) {
	for _, c := range []struct {
		url  string
		dev  bool
		want bool
	}{
		{"https://token.example.com/keys", false, true},
		{"http://127.0.0.1:8080/keys", true, true},
		{"http://[::1]/keys", true, true},
		{"http://127.0.0.1/keys", false, false},
		{"http://localhost/keys", true, false},
		{"http://10.0.0.1/keys", true, false},
		{"https://user:pw@example.com/", false, false},
		{"https://example.com/#frag", false, false},
		{"ftp://example.com/", false, false},
		{"/keys", false, false},
	} {
		if _, err := CheckURL(c.url, c.dev); (err == nil) != c.want {
			t.Errorf("CheckURL(%q, %v) = %v", c.url, c.dev, err)
		}
	}
}

func TestAddressesThatAnIssuerKeyEndpointMustNeverReach(t *testing.T) {
	for _, c := range []struct {
		ip      string
		dev     bool
		blocked bool
	}{
		{"169.254.169.254", true, true}, {"10.1.2.3", true, true}, {"192.0.2.1", false, false}, {"100.64.0.1", true, true},
		{"198.18.0.1", true, true}, {"0.0.0.0", true, true}, {"::ffff:10.0.0.1", true, true}, {"fe80::1", true, true},
		{"127.0.0.1", true, false}, {"127.0.0.1", false, true},
	} {
		ip := netip.MustParseAddr(c.ip)
		if got := blockedAddress(ip, c.dev); got != c.blocked {
			t.Errorf("blockedAddress(%s, dev=%v) = %v", c.ip, c.dev, got)
		}
	}
}
