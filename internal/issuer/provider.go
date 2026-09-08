package issuer

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// Provider assembles the OpenID surface over the storage: discovery, the
// JWKS, the token endpoint with its grants, revocation and end-session.
//
// Everything protocol-shaped comes from the library. What this repository
// contributes is the storage beneath it, the policy that decides, and one
// endpoint the library does not have — dynamic client registration, whose
// rule (a ServiceAccount token, a per-namespace host pattern) is ours
// anyway.
func Provider(iss *Issuer, storage op.Storage) (*op.Provider, error) {
	var cryptoKey [32]byte
	if _, err := rand.Read(cryptoKey[:]); err != nil {
		return nil, fmt.Errorf("generate the crypto key: %w", err)
	}

	config := &op.Config{
		CryptoKey: cryptoKey,
		// S256 only: a code challenge a network observer can replay is
		// not a challenge, and every client we issue to can do S256.
		CodeMethodS256: true,
		// A public client authenticates at the token endpoint by posting
		// its id; a confidential one uses Basic. Private-key JWT stays
		// off until a client needs it.
		AuthMethodPost:          true,
		AuthMethodPrivateKeyJWT: false,
		GrantTypeRefreshToken:   true,
		SupportedScopes: []string{
			"openid", "profile", "email", "offline_access",
		},
		SupportedClaims: []string{
			"sub", "aud", "exp", "iat", "iss", "email", "email_verified", "name", "groups",
		},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     iss.Config().TokenLifetime,
			PollInterval: 5,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
		// Back-channel logout is not served: the proxy does not consume
		// it, and a revoked session dies at the proxy's next refresh.
		BackChannelLogoutSupported: false,
	}

	options := []op.Option{
		// The library's default token path is /oauth/token; the reference
		// documents /token, and a relying party reads discovery anyway.
		op.WithCustomTokenEndpoint(op.NewEndpoint("/token")),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint("/end_session")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("/revoke")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("/keys")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("/device_authorization")),
	}
	if iss.Config().AllowInsecure {
		options = append(options, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(config, storage, op.StaticIssuer(iss.Config().URL), options...)
	if err != nil {
		return nil, fmt.Errorf("open the provider: %w", err)
	}
	return provider, nil
}

// Handler is the provider as an http.Handler, which is all a deployment
// needs to serve it, with its discovery document corrected.
func Handler(iss *Issuer, storage op.Storage) (http.Handler, error) {
	provider, err := Provider(iss, storage)
	if err != nil {
		return nil, err
	}
	return truthfulDiscovery(provider), nil
}

// discoveryPath is where a relying party looks first.
const discoveryPath = "/.well-known/openid-configuration"

// servedResponseTypes is what this issuer will actually honour. Every
// client declares `code` and nothing else: the implicit and hybrid flows
// put tokens in a redirect, which is the thing PKCE exists to stop
// needing.
var servedResponseTypes = []string{"code"}

// servedGrantTypes is the same correction one field along, and it is the
// one that matters more. A relying party reads `grant_types_supported`
// and picks; offered `implicit`, a library will happily use it, and the
// refusal arrives in a browser redirect where nobody sees the reason.
//
// The list is what this issuer implements: the code flow and its refresh,
// token exchange for CI and workloads, the device flow for the CLIs, and
// the JWT profile a service account uses to assert itself.
var servedGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"urn:ietf:params:oauth:grant-type:token-exchange",
	"urn:ietf:params:oauth:grant-type:jwt-bearer",
	"urn:ietf:params:oauth:grant-type:device_code",
}

// truthfulDiscovery corrects the one place the library over-promises.
//
// It composes `response_types_supported` from a hardcoded list rather
// than from what the storage will accept, so discovery advertises the
// implicit flow that every client here refuses. A relying party that
// believes the metadata and tries it gets an error it was told would not
// happen; worse, a reader auditing the issuer sees a flow we deliberately
// do not serve. Metadata that lies is a defect in a service whose whole
// job is to be trusted, so it is rewritten on the way out.
func truthfulDiscovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			next.ServeHTTP(w, r)
			return
		}

		recorder := &captured{header: http.Header{}}
		next.ServeHTTP(recorder, r)

		var doc map[string]any
		if recorder.status != http.StatusOK || json.Unmarshal(recorder.body.Bytes(), &doc) != nil {
			// Whatever went wrong upstream is upstream's answer to give.
			copyHeader(w.Header(), recorder.header)
			w.WriteHeader(recorder.status)
			_, _ = w.Write(recorder.body.Bytes())
			return
		}
		doc["response_types_supported"] = servedResponseTypes
		doc["grant_types_supported"] = servedGrantTypes

		corrected, err := json.Marshal(doc)
		if err != nil {
			http.Error(w, "discovery could not be rendered", http.StatusInternalServerError)
			return
		}
		copyHeader(w.Header(), recorder.header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(corrected)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(corrected)
	})
}

func copyHeader(dst, src http.Header) {
	for name, values := range src {
		if name == "Content-Length" {
			continue
		}
		dst[name] = values
	}
}

// captured buffers a response so that it can be corrected before it is
// sent.
type captured struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (c *captured) Header() http.Header { return c.header }

func (c *captured) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(p)
}

func (c *captured) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}
