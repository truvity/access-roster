package issuerapp

import (
	"testing"

	"github.com/truvity/access-roster/internal/config"
)

func ptr[T any](v T) *T { return &v }

// A cookie's Secure flag has to match the scheme the browser will use,
// and the service is told its own public URL, so that is where the
// default comes from. It used to default to false: an installation that
// simply did not set secureCookies served its session cookie without
// the flag, and a proxy could then carry it over a plain-http hop.
//
// The override stays, in both directions — a TLS terminator that is not
// in the URL needs true, and a local https:// listener with a self-signed
// certificate is not the case this protects.
//
// There is no row for an unset URL: issuerURL is required, so the
// default is always decided by a scheme somebody wrote down.
func TestSecureCookiesFollowsTheIssuerScheme(t *testing.T) {
	for _, tc := range []struct {
		name      string
		issuerURL string
		override  *bool
		want      bool
	}{
		{"https is the deployed case", "https://access.example", nil, true},
		{"http is the laptop", "http://localhost:8080", nil, false},
		{"an override turns it on", "http://in-cluster:8080", ptr(true), true},
		{"an override turns it off", "https://access.example", ptr(false), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := FromConfig(&config.Serve{IssuerURL: tc.issuerURL, SecureCookies: tc.override})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.secureCookies != tc.want {
				t.Errorf("secureCookies = %v, want %v", cfg.secureCookies, tc.want)
			}
		})
	}
}
