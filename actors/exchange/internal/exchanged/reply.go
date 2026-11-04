package exchanged

import (
	"encoding/json"

	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

//nolint:gosec // G101: these are the registered names of RFC 8693, not credentials
const (
	// tokenTypeAccess is the identifier of an access token (RFC 8693 section 3).
	tokenTypeAccess = "urn:ietf:params:oauth:token-type:access_token"
	// tokenTypeJWT is the identifier of a JWT (RFC 8693 section 3).
	tokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// grantTokenExchange is the grant type of RFC 8693 section 2.1.
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// descriptions are the error_description of each code: a fixed text, never built from the request (contracts.md,
// "OAuth and OpenID Connect endpoints"). An unknown and a refused audience have the one text.
var descriptions = map[string]string{
	codeInvalidRequest:   "The request or the subject token is not acceptable.",
	codeInvalidClient:    "Client authentication failed.",
	codeInvalidTarget:    "A token for the requested audience cannot be issued.",
	codeInvalidScope:     "The requested scope is not supported.",
	codeUnsupportedGrant: "The grant type is not supported.",
}

// reply makes the HttpReply of the token endpoint: JSON that no cache keeps (RFC 6749 section 5.1).
func reply(status int32, body any, extra ...*typev2alpha1.Header) *typev2alpha1.HttpReply {
	b, err := json.Marshal(body)
	if err != nil {
		// Unreachable: the bodies are strings and numbers.
		b = []byte(`{"error":"server_error"}`)
		status = 500
	}
	return &typev2alpha1.HttpReply{
		Status: status,
		Headers: append([]*typev2alpha1.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Cache-Control", Value: "no-store"},
			{Name: "Pragma", Value: "no-cache"},
		}, extra...),
		Body: b,
	}
}

// errorReply is the answer to a request that is refused (RFC 6749 section 5.2, RFC 8693 section 2.2.2). An
// invalid_client is a 401, and every 401 carries WWW-Authenticate (RFC 9110 section 15.5.2; contracts.md "OAuth and
// OpenID Connect endpoints"), as session's does.
func errorReply(r *refused) *typev2alpha1.HttpReply {
	body := struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}{r.code, descriptions[r.code]}
	if r.code != codeInvalidClient {
		return reply(400, body)
	}
	return reply(401, body, &typev2alpha1.Header{Name: "WWW-Authenticate", Value: `Basic realm="sluis", charset="UTF-8"`})
}

// successReply is the answer to an exchange (RFC 8693 section 2.2.1). It carries no refresh token (REQ-EXCH-010) and
// no scope: the access token carries the claims of ADR 0020 and nothing else.
func successReply(token string, expiresIn int64) *typev2alpha1.HttpReply {
	return reply(200, struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int64  `json:"expires_in"`
	}{token, tokenTypeAccess, "Bearer", expiresIn})
}
