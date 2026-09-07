package issuer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// device is one device authorization in flight: a terminal has asked for
// a token and is polling while a person types the user code into a
// browser somewhere else.
type device struct {
	clientID string
	userCode string
	scopes   []string
	expires  time.Time

	done     bool
	denied   bool
	subject  string
	authTime time.Time
}

// Devices holds device authorizations. Their codes are low-entropy by
// design — a person has to read one aloud or type it — so they must be
// short-lived and swept, or the chance of two colliding stops being
// negligible.
type Devices struct {
	mu     sync.Mutex
	byCode map[string]*device // device code → flow
	byUser map[string]string  // user code → device code
	now    func() time.Time
}

// NewDevices returns an empty set of device authorizations.
func NewDevices() *Devices {
	return &Devices{byCode: map[string]*device{}, byUser: map[string]string{}, now: time.Now}
}

// StoreDeviceAuthorization implements [op.DeviceAuthorizationStorage].
func (d *Devices) StoreDeviceAuthorization(
	_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, taken := d.byUser[userCode]; taken {
		// The library's contract: say so and it will try another code.
		return op.ErrDuplicateUserCode
	}
	d.byCode[deviceCode] = &device{clientID: clientID, userCode: userCode, scopes: scopes, expires: expires}
	d.byUser[userCode] = deviceCode
	return nil
}

// GetDeviceAuthorizatonState implements [op.DeviceAuthorizationStorage].
// The spelling is the library's.
func (d *Devices) GetDeviceAuthorizatonState(
	_ context.Context, clientID, deviceCode string,
) (*op.DeviceAuthorizationState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	flow, ok := d.byCode[deviceCode]
	if !ok || flow.clientID != clientID {
		return nil, errors.New("no such device authorization")
	}
	return &op.DeviceAuthorizationState{
		ClientID: flow.clientID,
		Audience: []string{flow.clientID},
		Scopes:   flow.scopes,
		Expires:  flow.expires,
		Done:     flow.done,
		Denied:   flow.denied,
		Subject:  flow.subject,
		AMR:      []string{"pwd"},
		AuthTime: flow.authTime,
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
	d.mu.Lock()
	defer d.mu.Unlock()

	deviceCode, ok := d.byUser[userCode]
	if !ok {
		return errors.New("no such user code")
	}
	flow, ok := d.byCode[deviceCode]
	if !ok {
		return errors.New("no such device authorization")
	}
	if d.now().After(flow.expires) {
		return errors.New("this code has expired")
	}
	flow.done, flow.denied, flow.subject, flow.authTime = true, denied, subject, d.now()
	return nil
}

// Sweep drops expired flows and returns how many, which is what keeps
// low-entropy user codes from colliding as they accumulate.
func (d *Devices) Sweep() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	gone := 0
	for code := range d.byCode {
		if flow := d.byCode[code]; now.After(flow.expires) {
			delete(d.byUser, flow.userCode)
			delete(d.byCode, code)
			gone++
		}
	}
	return gone
}
