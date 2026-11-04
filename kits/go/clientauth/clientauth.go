// Package clientauth authenticates a client of the token endpoint by its secret (RFC 6749 section 2.3): the
// credentials of a request, read from the Authorization header (client_secret_basic) or from the request body
// (client_secret_post), and the check of a secret against the one the installation holds.
//
// The check has one path. A client that is unknown, a client that has no secret and a client whose secret is wrong
// all fetch a secret, hash both sides to a fixed length and compare them with subtle.ConstantTimeCompare, so the
// answer and the work the kit does are the same (REQ-EXCH-019). That is a structural claim, tested by counting the
// fetches and the comparisons; a measurement of the timing, REQ-CLIENT-015's test, does not exist yet. What the
// kit cannot equalise is its caller's source: store@ answers a secret it holds in memory sooner than one it must read
// from the secret source (a cold cache), and answers a client with no secret without reading the source at all, so
// the time of the fetch can differ between these cases. REQ-CLIENT-015's timing test has to measure that, and until
// it exists the claim is only the structural one. A secret is never logged, returned in an error or kept after the
// call.
package clientauth

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Method says how a client authenticated.
type Method string

// The methods of RFC 6749 section 2.3.1 that the token endpoint accepts. private_key_jwt is later (#912).
const (
	Basic Method = "client_secret_basic"
	Post  Method = "client_secret_post"
)

// Credentials are what a request presents. The type has no String method that prints the secret, and it is not
// meant to be formatted.
type Credentials struct {
	ClientID string
	Secret   string
	Method   Method
}

var (
	// ErrBothMethods says a request used two authentication methods (RFC 6749 section 2.3: "The client MUST NOT use
	// more than one authentication method in each request"). It is an invalid request.
	ErrBothMethods = errors.New("clientauth: two authentication methods in one request")
	// ErrMalformed says the credentials cannot be read: a scheme other than Basic, bad base64 or percent-encoding,
	// no colon, an empty id or secret, or a client_secret with no client_id. It is a failed authentication.
	ErrMalformed = errors.New("clientauth: malformed client credentials")
)

// Parse reads the credentials of a token request from the Authorization header, the `client_id` parameter and the
// `client_secret` parameter. present is false when the request uses no method at all.
//
// For HTTP Basic the id and the secret are each decoded as application/x-www-form-urlencoded after the base64 is
// decoded (RFC 6749 section 2.3.1, "The client identifier is encoded using the application/x-www-form-urlencoded
// encoding algorithm ... the encoded value is used as the username"), so a secret with reserved characters works
// (REQ-CLIENT-002). A `client_id` parameter beside Basic must name the same client.
func Parse(authorization, clientID, clientSecret string) (c Credentials, present bool, err error) {
	switch {
	case authorization != "" && clientSecret != "":
		return Credentials{}, true, ErrBothMethods
	case authorization != "":
		id, secret, err := parseBasic(authorization)
		if err != nil || (clientID != "" && clientID != id) {
			return Credentials{}, true, ErrMalformed
		}
		return Credentials{ClientID: id, Secret: secret, Method: Basic}, true, nil
	case clientSecret != "":
		if clientID == "" {
			return Credentials{}, true, ErrMalformed
		}
		return Credentials{ClientID: clientID, Secret: clientSecret, Method: Post}, true, nil
	}
	return Credentials{}, false, nil
}

// parseBasic reads `Basic <base64(id ":" secret)>` (RFC 7617 section 2).
func parseBasic(h string) (id, secret string, err error) {
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", ErrMalformed
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", "", ErrMalformed
	}
	rawID, rawSecret, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", ErrMalformed
	}
	if id, err = url.QueryUnescape(rawID); err != nil {
		return "", "", ErrMalformed
	}
	if secret, err = url.QueryUnescape(rawSecret); err != nil {
		return "", "", ErrMalformed
	}
	if id == "" || secret == "" {
		return "", "", ErrMalformed
	}
	return id, secret, nil
}

// SecretSource gives the secret of a client. found is false when the client has none, whether it is unknown, a
// public client or one whose secret is not provisioned: the caller must not tell these apart. err is an outage of
// the source, never "not found".
type SecretSource interface {
	Secret(ctx context.Context, clientID string) (secret []byte, found bool, err error)
}

// An Authenticator checks credentials against a SecretSource.
type Authenticator struct {
	src SecretSource
	// dummy stands in for the secret of a client that has none, so that the comparison runs all the same. It is
	// random per process and never equal to anything a client sends.
	dummy [sha512.Size384]byte
	// compare is the one comparison. Tests in this package replace it to count the calls.
	compare func(presented, stored []byte) bool
}

// New returns an Authenticator over src.
func New(src SecretSource) (*Authenticator, error) {
	if src == nil {
		return nil, errors.New("clientauth: a SecretSource is required")
	}
	a := &Authenticator{src: src, compare: equal}
	if _, err := rand.Read(a.dummy[:]); err != nil {
		return nil, fmt.Errorf("clientauth: random source: %w", err)
	}
	return a, nil
}

// equal compares two secrets in constant time. Both are hashed first (SHA-384), so the comparison is over fixed-size
// values and takes the same time whatever the lengths are.
func equal(presented, stored []byte) bool {
	p, s := sha512.Sum384(presented), sha512.Sum384(stored)
	return subtle.ConstantTimeCompare(p[:], s[:]) == 1
}

// Authenticate says whether the credentials name a client and carry its secret. A false answer is the same for a
// wrong secret, an unknown client and a client with no secret. An error is an outage of the source: the caller fails
// closed.
func (a *Authenticator) Authenticate(ctx context.Context, c Credentials) (bool, error) {
	stored, found, err := a.src.Secret(ctx, c.ClientID)
	if err != nil {
		return false, err
	}
	if !found || len(stored) == 0 {
		// An empty secret is no secret: it must never authenticate.
		stored, found = a.dummy[:], false
	}
	ok := a.compare([]byte(c.Secret), stored)
	return ok && found, nil
}
