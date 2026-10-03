package issuer

import (
	"context"
	"net/http"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/op"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/truvity/access-roster/gen/accessissuer/v1/accessissuerv1connect"
)

// What the issuer counts, beyond the signing keys (keyring_metrics.go) and the
// HTTP listener's own request counts (internal/telemetry). With no collector
// named the global provider is a no-op and every record costs nothing.
//
// No label here is personal data, and none is unbounded. A person, an email, a
// group, a session or a token never is one. A client id is: the policy declares
// every client, [clientLabel] refuses an id it does not, and a deployment has
// tens of clients, not thousands.
type issuerInstruments struct {
	tokens   metric.Int64Counter
	failures metric.Int64Counter
	logins   metric.Int64Counter
	reuse    metric.Int64Counter
}

var issuerMetrics = newIssuerInstruments()

func newIssuerInstruments() issuerInstruments {
	meter := otel.Meter(keyRingMeterName)
	// Instrument creation fails only on an invalid name, which these are not;
	// a failed one is a no-op instrument, never a stopped issuer.
	tokens, _ := meter.Int64Counter("access_issuer.tokens.issued",
		metric.WithDescription("Access tokens signed, by client id (declared clients only; anything else is `other`) and grant type."))
	failures, _ := meter.Int64Counter("access_issuer.login.failures",
		metric.WithDescription("Sign-ins that did not complete, by reason: a fixed set, see docs/operations/telemetry.md."))
	logins, _ := meter.Int64Counter("access_issuer.login.successes",
		metric.WithDescription("Sign-ins that completed, by how the person was proved: a directory's kind, `recovery` or `browser_session`."))
	reuse, _ := meter.Int64Counter("access_issuer.reuse_detected",
		metric.WithDescription("A credential presented that was already spent, by kind: an authorization code (its session is ended) "+
			"or a refresh token outside the grace window (spent or unknown: the two are not told apart)."))
	return issuerInstruments{tokens, failures, logins, reuse}
}

// The reasons a sign-in fails: the whole set, so the label stays bounded and an
// alert can name one.
const (
	// LoginBadState is a callback or recovery whose state is missing, forged,
	// expired, or not from this browser.
	LoginBadState = "bad_state"
	// LoginUnknownProvider is a start or callback for a directory this issuer
	// does not offer.
	LoginUnknownProvider = "unknown_provider"
	// LoginProviderFailed is the directory's own token exchange failing, or its
	// authorization URL not being buildable.
	LoginProviderFailed = "provider_failed"
	// LoginDirectoryRefused is the directory saying no to this address.
	LoginDirectoryRefused = "directory_refused"
	// LoginDirectoryUnreachable is the directory (or the hub) not answering.
	LoginDirectoryUnreachable = "directory_unreachable"
	// LoginNotEntitled is a person signed in who is not in a group the
	// application requires.
	LoginNotEntitled = "not_entitled"
	// LoginRecoveryRefused is a recovery proof that did not verify.
	LoginRecoveryRefused = "recovery_refused"
	// LoginUnaudited is a sign-in refused because the audit trail could not be
	// written.
	LoginUnaudited = "unaudited"
	// LoginNotWaiting is an authorization request that is no longer waiting to
	// be completed.
	LoginNotWaiting = "not_waiting"
	// LoginBadRequest is a form or a start that is not well formed.
	LoginBadRequest = "bad_request"
)

// recordLoginFailure counts one sign-in that did not complete.
func recordLoginFailure(ctx context.Context, reason string) {
	issuerMetrics.failures.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// recordLoginSuccess counts one sign-in that completed.
func recordLoginSuccess(ctx context.Context, method string) {
	issuerMetrics.logins.Add(ctx, 1, metric.WithAttributes(attribute.String("method", method)))
}

// recordReuse counts one spent credential presented again.
func recordReuse(ctx context.Context, kind string) {
	issuerMetrics.reuse.Add(ctx, 1, metric.WithAttributes(attribute.String("kind", kind)))
}

// recordToken counts one access token signed.
func (s *Storage) recordToken(ctx context.Context, request op.TokenRequest) {
	issuerMetrics.tokens.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_id", s.clientLabel(clientOf(request))),
		attribute.String("grant_type", grantTypeOf(request)),
	))
}

// clientLabel is a client id as a label: the id when the policy declares it,
// `none` when the request names no client (a workload's exchange), and `other`
// for anything else, so that a request naming a client nobody declared cannot
// mint a series.
func (s *Storage) clientLabel(id string) string {
	switch {
	case id == "":
		return "none"
	case s.iss == nil:
		return "other"
	}
	if _, ok := s.iss.Policy().Client(id); ok {
		return id
	}
	return "other"
}

// grantTypeOf is the OAuth grant a token request came from.
func grantTypeOf(request op.TokenRequest) string {
	switch request.(type) {
	case *refreshRequest:
		return "refresh_token"
	case op.TokenExchangeRequest:
		return "token_exchange"
	case *authRequest:
		return "authorization_code"
	default:
		return "client_credentials"
	}
}

// Route is the name of the endpoint a request to the issuer's listener is for,
// from a small FIXED set: it is the `route` label of the request metrics and
// the name of the span, and a raw path never is, because a path carries
// callback codes and, on the console, names. Anything not listed is `other`.
func Route(r *http.Request) string {
	path := r.URL.Path
	switch path {
	case "/.well-known/openid-configuration":
		return "discovery"
	case "/keys":
		return "jwks"
	case "/authorize":
		return "authorize"
	case "/authorize/callback":
		return "authorize_callback"
	case "/oauth/token":
		return "token"
	case "/userinfo":
		return "userinfo"
	case "/oauth/introspect":
		return "introspect"
	case "/revoke":
		return "revoke"
	case "/end_session":
		return "end_session"
	case "/device_authorization":
		return "device_authorization"
	case "/login":
		return "login_chooser"
	case "/login/recovery":
		return "login_recovery"
	case "/logout":
		return "logout"
	case "/signed-out":
		return "signed_out"
	case "/account":
		return "account"
	case GrantsPath:
		return "grants"
	}
	switch {
	case strings.HasPrefix(path, "/login/") && strings.HasSuffix(path, "/start"):
		return "login_start"
	case strings.HasPrefix(path, "/login/") && strings.HasSuffix(path, "/callback"):
		return "login_callback"
	case strings.HasPrefix(path, "/"+accessissuerv1connect.SessionServiceName+"/"):
		return "sessions_rpc"
	case strings.HasPrefix(path, "/connect/"):
		return "connect_callback"
	case strings.HasPrefix(path, "/console/assets/"):
		return "console_assets"
	case strings.HasPrefix(path, "/console/") || path == "/console":
		// A Connect call is a POST to `/console/<package.Service>/<Method>`.
		if r.Method == http.MethodPost && strings.Count(strings.TrimPrefix(path, "/console/"), "/") == 1 &&
			strings.Contains(strings.TrimPrefix(path, "/console/"), ".") {
			return "console_rpc"
		}
		return "console"
	}
	return "other"
}
