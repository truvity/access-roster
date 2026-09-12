package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/truvity/access-roster/internal/logsafe"
)

// Back-Channel Logout tells a relying party, server to server, that a
// session it holds has ended.
//
// WHY THIS ONE, of the three optional logout mechanisms. Session
// Management and Front-Channel Logout both work by loading something
// from this origin inside the application's page -- a polled iframe, or
// one hidden iframe per client at sign-out. Browsers block third-party
// cookies by default now, so both fail quietly in exactly the case they
// exist for. This is an HTTP POST between two servers and does not care
// what a browser allows. It is also the only one that can reach a PROXY,
// which is what actually holds the session for a console with no OpenID
// flow of its own.
//
// WHAT IT BUYS. Revoking a session is immediate here and invisible
// there: a relying party holding a valid access token keeps serving
// until it next refreshes, which is up to the client's `ttl_cap`. A
// logout token closes that window instead of bounding it.
//
// OPT-IN, per client. A client that declares no `backchannel_logout_uri`
// is never contacted, so serving this changes nothing for one that has
// not asked for it.
const backChannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutToken is the JWT a client is sent. The shape is fixed by the
// specification and every field here is required by it, except `sub` and
// `sid` of which at least one must appear -- both do, because a client
// may key its session store on either.
type logoutToken struct {
	Issuer    string         `json:"iss"`
	Audience  string         `json:"aud"`
	IssuedAt  int64          `json:"iat"`
	JWTID     string         `json:"jti"`
	Subject   string         `json:"sub,omitempty"`
	SessionID string         `json:"sid,omitempty"`
	Events    map[string]any `json:"events"`
	// NOTE: there is deliberately no `nonce`. The specification forbids
	// it, because a logout token that carries one can be mistaken for an
	// ID token by a relying party that checks too little.
}

// announceLogout tells every client that asked to be told. Errors are
// logged and not returned: the sign-out has already happened, and a
// relying party that cannot be reached must not turn a completed
// sign-out into a failed one.
//
// Sequential on purpose. The number of clients is small, the calls are
// short, and a failure that blocks is easier to read in a log than a
// fan-out that interleaves.
func (s *Storage) announceLogout(ctx context.Context, log *slog.Logger, ended []Session) {
	if len(ended) == 0 {
		return
	}

	for i := range ended {
		one := &ended[i]

		declared, ok := s.iss.Policy().Client(one.ClientID)
		if !ok || strings.TrimSpace(declared.BackChannelLogout) == "" {
			continue
		}

		if err := s.postLogoutToken(ctx, declared.BackChannelLogout, one); err != nil {
			log.WarnContext(ctx, "a client could not be told its session ended",
				"client_id", logsafe.Value(one.ClientID), "error", logsafe.Error(err))

			continue
		}

		log.InfoContext(ctx, "told a client its session ended",
			"client_id", logsafe.Value(one.ClientID))
	}
}

// postLogoutToken mints one token and delivers it.
func (s *Storage) postLogoutToken(ctx context.Context, where string, session *Session) error {
	token, err := s.mintLogoutToken(session)
	if err != nil {
		return err
	}

	form := url.Values{"logout_token": {token}}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, where,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Short: this runs while somebody is waiting for a sign-out page, and
	// a relying party that cannot answer in a few seconds is one whose
	// session will die at its next refresh anyway.
	client := &http.Client{Timeout: 5 * time.Second}

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()

	// The specification asks for 200, and says a 2xx is acceptable.
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("answered %d", response.StatusCode)
	}

	return nil
}

// mintLogoutToken signs one logout token for one session.
func (s *Storage) mintLogoutToken(session *Session) (string, error) {
	if s.key == nil {
		return "", fmt.Errorf("no signing key")
	}

	claims := logoutToken{
		Issuer:   s.iss.Config().URL,
		Audience: session.ClientID,
		IssuedAt: time.Now().Unix(),
		JWTID:    uuid.NewString(),
		Subject:  session.Identity,
		// The SAME `sid` the relying party's ID token carried, which is
		// this per-client session (INF-681) and not the browser sign-in
		// it hangs off. A relying party matches a logout token to its
		// session by that value; naming the sign-in instead was a token
		// that verified and matched nothing. Empty for a client whose ID
		// token carried none -- `openid` alone opens no session here --
		// and then `sub` carries it alone, which the specification
		// allows.
		SessionID: session.ID,
		Events:    map[string]any{backChannelEvent: map[string]any{}},
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: s.key.SignatureAlgorithm(), Key: s.key.Key()},
		// `typ: logout+jwt` is required, and it is the one thing that
		// stops a relying party mistaking this for an ID token.
		(&jose.SignerOptions{}).
			WithType("logout+jwt").
			WithHeader("kid", s.key.ID()),
	)
	if err != nil {
		return "", err
	}

	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return signed.CompactSerialize()
}
