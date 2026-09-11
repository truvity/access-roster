package issuerapp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

// signInEntry is where the console sends a browser that has no session:
// this issuer's authorization endpoint, with the console as the client
// (INF-701).
//
// The console is a client of the issuer like any other application, and
// that is the whole design — one door, and the console holds nothing
// special. What it needs from the flow is not the code but the SESSION
// the flow establishes: completing an authorization at the issuer sets
// the browser's session cookie, and the console then reads it the way it
// reads anybody's ([signedIn]). So the code that comes back is never
// redeemed, and the console strips it from the URL.
//
// Not redeeming it is deliberate rather than lazy. Redeeming would mean
// holding a token the console has no use for — it reads the directory
// and the policy in this same process — and either a client secret to
// keep or a PKCE verifier to carry across the redirect. The code expires
// unused, which costs one unused entry in the store for its lifetime.
//
// A challenge is still sent because a public client is a native one and
// the library requires it. The verifier is generated and discarded with
// the request, which is safe precisely because nothing will redeem the
// code: a verifier nobody kept is a code nobody can use.
//
// Empty when there is no console mounted or no client declared for it,
// and then the console falls back to a sign-in page of its own.
func signInEntry(issuerURL, clientID, mount string) func() string {
	issuerURL = strings.TrimSuffix(strings.TrimSpace(issuerURL), "/")
	clientID = strings.TrimSpace(clientID)
	mount = strings.TrimSuffix(strings.TrimSpace(mount), "/")
	if issuerURL == "" || clientID == "" || mount == "" {
		return nil
	}
	return func() string {
		query := url.Values{
			"client_id":     {clientID},
			"response_type": {"code"},
			"scope":         {"openid"},
			"redirect_uri":  {issuerURL + mount + "/"},
			// One per redirect, and neither is checked on the way back:
			// this console does not process the response, it reads the
			// session the response left behind.
			"state":                 {random()},
			"code_challenge":        {challenge(random())},
			"code_challenge_method": {"S256"},
		}
		return issuerURL + "/authorize?" + query.Encode()
	}
}

// random is 32 bytes of entropy, URL-safe.
func random() string {
	buf := make([]byte, 32)
	// rand.Read on crypto/rand cannot fail; it panics on a broken system
	// rather than returning a short read.
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// challenge is the S256 transformation RFC 7636 asks for.
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
