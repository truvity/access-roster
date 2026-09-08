package issuer

import (
	"context"
	"errors"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// device is one device authorization in flight: a terminal has asked for
// a token and is polling while a person types the user code into a
// browser somewhere else.
type device struct {
	ClientID string    `json:"clientID"`
	UserCode string    `json:"userCode"`
	Scopes   []string  `json:"scopes,omitempty"`
	Expires  time.Time `json:"expires"`

	Done     bool      `json:"done,omitempty"`
	Denied   bool      `json:"denied,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	AuthTime time.Time `json:"authTime,omitempty"`
}

// Devices holds device authorizations. Their codes are low-entropy by
// design — a person has to read one aloud or type it — so they must be
// short-lived and swept, or the chance of two colliding stops being
// negligible.
type Devices struct {
	state State
	now   func() time.Time
}

// NewDevices returns device authorizations over a shared state, because a
// terminal polls whichever replica answers and the browser approving it
// reaches another.
func NewDevices(state State) *Devices {
	if state == nil {
		state = NewMemoryState()
	}
	return &Devices{state: state, now: time.Now}
}

// SetClock replaces the clock. For tests.
func (d *Devices) SetClock(now func() time.Time) { d.now = now }

func deviceKey(code string) string   { return "issuer:device:" + code }
func userCodeKey(code string) string { return "issuer:usercode:" + code }

// StoreDeviceAuthorization implements [op.DeviceAuthorizationStorage].
func (d *Devices) StoreDeviceAuthorization(
	ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string,
) error {
	ttl := time.Until(expires)
	if ttl <= 0 {
		return errors.New("that device authorization has already expired")
	}
	// Claimed atomically, because two replicas minting the same short
	// code at the same moment must not both believe they own it. The
	// codes are low-entropy by design — a person reads one aloud — so a
	// check-then-set would collide often enough to matter.
	claimed, err := d.state.SetIfAbsent(ctx, userCodeKey(userCode), []byte(deviceCode), ttl)
	if err != nil {
		return err
	}
	if !claimed {
		// The library's contract: say so and it will try another code.
		return op.ErrDuplicateUserCode
	}
	return setJSON(ctx, d.state, deviceKey(deviceCode), &device{
		ClientID: clientID, UserCode: userCode, Scopes: scopes, Expires: expires,
	}, ttl)
}

// GetDeviceAuthorizatonState implements [op.DeviceAuthorizationStorage].
// The spelling is the library's.
func (d *Devices) GetDeviceAuthorizatonState(
	ctx context.Context, clientID, deviceCode string,
) (*op.DeviceAuthorizationState, error) {
	flow, err := getJSON[device](ctx, d.state, deviceKey(deviceCode))
	if err != nil {
		return nil, err
	}
	if flow == nil || flow.ClientID != clientID {
		return nil, errors.New("no such device authorization")
	}
	return &op.DeviceAuthorizationState{
		ClientID: flow.ClientID,
		Audience: []string{flow.ClientID},
		Scopes:   flow.Scopes,
		Expires:  flow.Expires,
		Done:     flow.Done,
		Denied:   flow.Denied,
		Subject:  flow.Subject,
		AMR:      []string{"pwd"},
		AuthTime: flow.AuthTime,
	}, nil
}

// Approve completes a device flow for an identity, which is what the
// issuer's own device page calls once the person at the browser has
// signed in and confirmed the code they were shown.
func (d *Devices) Approve(userCode, subject string) error {
	return d.settle(userCode, subject, false)
}

// Deny completes a device flow as refused, which is what happens when
// the person says no — a distinct answer from letting it time out,
// because it tells the waiting terminal to stop now.
func (d *Devices) Deny(userCode string) error {
	return d.settle(userCode, "", true)
}

func (d *Devices) settle(userCode, subject string, denied bool) error {
	ctx := context.Background()
	deviceCode, found, err := d.state.Get(ctx, userCodeKey(userCode))
	if err != nil {
		return err
	}
	if !found {
		return errors.New("no such user code")
	}
	key := deviceKey(string(deviceCode))
	flow, err := getJSON[device](ctx, d.state, key)
	if err != nil {
		return err
	}
	if flow == nil {
		return errors.New("no such device authorization")
	}
	if d.now().After(flow.Expires) {
		return errors.New("this code has expired")
	}
	flow.Done, flow.Denied, flow.Subject, flow.AuthTime = true, denied, subject, d.now()
	return setJSON(ctx, d.state, key, flow, time.Until(flow.Expires))
}

// Nothing sweeps. Every flow is stored for exactly as long as it is
// valid and disappears on its own, which is also what keeps low-entropy
// user codes from colliding as they accumulate — a sweeper that stops is
// a store that fills with codes nobody can use.
