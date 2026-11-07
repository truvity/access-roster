//go:build sluis_test

package sessiond

import (
	"context"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// Reasons is the closed list of reasons for the tests of package sessiond_test.
var Reasons = reasons

// The steps of the passkey ceremonies, for the tests of package sessiond_test. The RPCs that call them come with the pages.

// Credentials the ceremonies return, as the tests read them.
type PasskeyRecord = sessionv2alpha1.StaffPasskey

var (
	ErrPasskeysOff    = errPasskeysOff
	ErrPasskeyReplay  = errPasskeyReplay
	ErrPasskeyClone   = errPasskeyClone
	ErrPasskeyTaken   = errPasskeyTaken
	ErrPasskeyBadID   = errPasskeyBadID
	ErrPasskeyExpired = errPasskeyExpired
	ErrPasskeyHeld    = errPasskeyHeld
	ErrPasskeyResp    = errPasskeyResponse
)

func (s *Service) RegisterBegin(ctx context.Context, tenant, subject, account string, grant []byte) ([]byte, []byte, error) {
	return s.registerBegin(ctx, tenant, subject, account, grant)
}

func (s *Service) RegisterFinish(ctx context.Context, tenant string, sealed, body, grant []byte) (*PasskeyRecord, error) {
	return s.registerFinish(ctx, tenant, sealed, body, grant)
}

func (s *Service) AssertBegin(ctx context.Context) ([]byte, []byte, error) { return s.assertBegin(ctx) }

// AssertFinish verifies the response and, as the sign-in does once policy has allowed it, writes the counter.
func (s *Service) AssertFinish(ctx context.Context, tenant string, sealed, body, grant []byte) (*PasskeyRecord, error) {
	l, err := s.assertFinish(ctx, tenant, sealed, body)
	if err != nil {
		return nil, err
	}
	if err := s.touchPasskey(ctx, tenant, grant, l); err != nil {
		return nil, err
	}
	return l.next, nil
}

// AMROfClass is the amr a passkey of the class adds to a token.
func AMROfClass(class string) []string { return amrOf(class) }
