package issuer

import (
	"context"
	"errors"
	"strings"
)

// NewSessionsServiceForTest builds the contract over a stubbed verifier,
// so the authorization rules can be tested without minting real tokens.
func NewSessionsServiceForTest(
	sessions *Sessions,
	verify func(ctx context.Context, bearer string) (string, []string, error),
) *SessionsService {
	return &SessionsService{sessions: sessions, verify: verify}
}

// NewSessionsServiceWithSSOForTest is the same with the sign-in store
// attached, which is what "sign this browser out" acts on.
func NewSessionsServiceWithSSOForTest(
	sessions *Sessions,
	sso *SSO,
	verify func(ctx context.Context, bearer string) (string, []string, error),
) *SessionsService {
	return &SessionsService{sessions: sessions, sso: sso, verify: verify}
}

// ErrUnverifiedForTest is what a stub verifier refuses with.
var ErrUnverifiedForTest = errors.New("unverified")

// CutForTest and SplitForTest keep the test file free of imports it only
// needs for string handling.
func CutForTest(s, sep string) (string, string, bool) { return strings.Cut(s, sep) }
func SplitForTest(s, sep string) []string             { return strings.Split(s, sep) }
