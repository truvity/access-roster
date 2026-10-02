// Package lambdaext is the AWS Lambda extension that sends a function's
// OpenTelemetry data to an OTLP endpoint with the function role's identity.
//
// The function exports to a proxy on 127.0.0.1 and holds no credential. The
// proxy asks STS for an identity token for the role the function already
// runs as, trades it at the access-roster issuer for a short-lived access
// token, and forwards each export with that token as a bearer. Everything is
// fail-open: nothing here may block, slow or crash an invocation.
package lambdaext

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvIssuer        = "ACCESS_ROSTER_ISSUER"
	EnvAudience      = "ACCESS_ROSTER_AUDIENCE"
	EnvOTLPAudience  = "ACCESS_ROSTER_OTLP_AUDIENCE"
	EnvOTLPEndpoint  = "ACCESS_ROSTER_OTLP_ENDPOINT"
	EnvListen        = "ACCESS_ROSTER_LISTEN"
	EnvSTSDuration   = "ACCESS_ROSTER_STS_DURATION_SECONDS"
	EnvSTSAlgorithm  = "ACCESS_ROSTER_STS_ALGORITHM"
	EnvTokenFile     = "ACCESS_ROSTER_TOKEN_FILE"
	defaultListen    = "127.0.0.1:4318"
	defaultAlgorithm = "ES384"
	defaultOTLPAud   = "otlp"
	defaultDuration  = 300
)

// Config is the extension's settings, all from the environment.
type Config struct {
	// Issuer is the access-roster issuer's base URL.
	Issuer string
	// Audience is the audience asked of STS for the identity token. The
	// issuer's AWS verifier decides what it must be; the function role's
	// policy pins it with sts:IdentityTokenAudience.
	Audience string
	// OTLPAudience is the audience (and exchange client id) of the access
	// token the OTLP endpoint accepts.
	OTLPAudience string
	// Endpoint is the upstream OTLP/HTTP base URL, https.
	Endpoint string
	// Listen is the proxy's address.
	Listen string
	// Duration and Algorithm are asked of STS.
	Duration  int32
	Algorithm string
	// TokenFile, when set, receives each access token (0600, atomically).
	TokenFile string
}

// LoadConfig reads the environment through getenv. The error names every
// missing or invalid setting at once.
func LoadConfig(getenv func(string) string) (Config, error) {
	get := func(name, fallback string) string {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			return v
		}
		return fallback
	}
	c := Config{
		Issuer:       strings.TrimRight(get(EnvIssuer, ""), "/"),
		Audience:     get(EnvAudience, ""),
		OTLPAudience: get(EnvOTLPAudience, defaultOTLPAud),
		Endpoint:     strings.TrimRight(get(EnvOTLPEndpoint, ""), "/"),
		Listen:       get(EnvListen, defaultListen),
		Algorithm:    get(EnvSTSAlgorithm, defaultAlgorithm),
		TokenFile:    get(EnvTokenFile, ""),
		Duration:     defaultDuration,
	}
	var problems []error
	for _, required := range []struct{ name, value string }{
		{EnvIssuer, c.Issuer}, {EnvAudience, c.Audience}, {EnvOTLPEndpoint, c.Endpoint},
	} {
		if required.value == "" {
			problems = append(problems, fmt.Errorf("%s is not set", required.name))
		}
	}
	if raw := get(EnvSTSDuration, ""); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 60 || n > 3600 {
			problems = append(problems, fmt.Errorf("%s must be 60..3600, got %q", EnvSTSDuration, raw))
		} else {
			c.Duration = int32(n) //nolint:gosec // bounded above
		}
	}
	if c.Endpoint != "" {
		if err := checkUpstream(c.Endpoint); err != nil {
			problems = append(problems, err)
		}
	}
	return c, errors.Join(problems...)
}

// checkUpstream refuses a plain-http upstream that is not loopback: the
// bearer token would cross the network in the clear.
func checkUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s is not a URL: %q", EnvOTLPEndpoint, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("%s must be https, got %q", EnvOTLPEndpoint, raw)
}

// refreshMargin is how long before expiry a token is replaced: a third of
// its life, so a function that exports rarely still finds a fresh one.
func refreshMargin(lifetime time.Duration) time.Duration {
	return max(lifetime/3, time.Second)
}
