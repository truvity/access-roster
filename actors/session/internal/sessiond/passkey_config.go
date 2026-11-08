package sessiond

import (
	"context"
	"errors"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// errPasskeysOff says the installation has no passkey configuration: no FrontHost named default, or no SignInMethods.
// Passkeys are then off: nothing registers and nothing signs in with one.
var errPasskeysOff = errors.New("sessiond: passkeys are off")

// PasskeyConfig is the passkey configuration of the boundary: the relying party and what a passkey sign-in states.
type PasskeyConfig struct {
	host    *configv2alpha1.FrontHost
	methods *configv2alpha1.SignInMethods
}

// Passkeys reads the passkey configuration. It lists the kinds and does not Get one, because a boundary with passkeys off
// is asked by every request that names the passkey acr, and a Get of a document that is not there is a refusal that store@
// audits each time (ADR 0005). errPasskeysOff says the boundary has no FrontHost named default or no SignInMethods.
func (c *Config) Passkeys(ctx context.Context) (*PasskeyConfig, error) {
	out := &PasskeyConfig{}
	hosts, _, err := c.fronts.List(ctx, "", store.PageSize(200))
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if h.ID == singletonID {
			out.host = h.Value
		}
	}
	ms, _, err := c.methods.List(ctx, "", store.PageSize(2))
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if m.ID == singletonID {
			out.methods = m.Value
		}
	}
	if out.host == nil || out.methods == nil {
		return nil, errPasskeysOff
	}
	return out, nil
}

// RegistrationClient is the client whose admission a passkey registration is decided on: the one SignInMethods names (owner
// decision 10 of 2026-11-08). The set is refused at load when it names none that signs people in, so an empty answer or an
// unknown client here is a configuration that changed under a running instance, and the registration is refused.
func (p *PasskeyConfig) RegistrationClient() string { return p.methods.GetRegistrationClient() }
