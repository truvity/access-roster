package hub

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Declared is one workspace the deployment owns, as the overlay file
// states it. It is deliberately thin: an id the deployment may know, a
// backend, an admin to act as, and where the credential is mounted.
// Everything else — the domains, the tenant's own id — is discovered,
// because a value maintained by hand is a value that drifts.
type Declared struct {
	// ID is the backend's tenant id. Optional: the credential opens
	// exactly one tenant and that tenant knows its own id, so the hub
	// discovers it. Supplying it turns the adoption into a check, which
	// is worth doing where a wrong credential would be quiet.
	ID string `yaml:"id,omitempty"`
	// Backend names the implementation that reads it.
	Backend string `yaml:"backend"`
	// Admin is the account the credential impersonates.
	Admin string `yaml:"admin"`
	// KeyFile is where the service-account key is mounted.
	KeyFile string `yaml:"keyFile"`
	// Serve narrows the tenant to a subset of its domains. Optional:
	// empty serves every domain discovery returns. A domain named here
	// that the tenant does not own routes nothing and is reported as
	// such, which is what makes a domain moving between tenants safe to
	// declare ahead of the move.
	Serve []string `yaml:"serve,omitempty"`
	// SyncGroups narrows the tenant to a subset of its groups. Optional:
	// empty keeps every group in the served domains. Unlike Serve there
	// is no discovery to check it against at start, so a group named here
	// that the tenant does not hold simply never appears.
	SyncGroups []string `yaml:"syncGroups,omitempty"`
}

// Overlay is the declared layer of workspaces.
type Overlay struct {
	Workspaces []Declared `yaml:"workspaces"`
}

// ParseOverlay reads the declared workspaces. Unknown keys are an error:
// a renamed field must fail a rollout rather than silently declare
// nothing, which is the failure this file exists to prevent.
func ParseOverlay(data []byte) (Overlay, error) {
	var out Overlay
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil {
		return Overlay{}, fmt.Errorf("parse the workspace overlay: %w", err)
	}
	for i, ws := range out.Workspaces {
		switch {
		case ws.Backend == "":
			return Overlay{}, fmt.Errorf("workspace %d: backend is required", i)
		case ws.Admin == "":
			return Overlay{}, fmt.Errorf("workspace %d (%s): admin is required", i, ws.Backend)
		case ws.KeyFile == "":
			return Overlay{}, fmt.Errorf("workspace %d (%s): keyFile is required", i, ws.Backend)
		}
	}
	return out, nil
}

// LoadOverlay reads the declared workspaces from a file. A path that does
// not exist is not an error — a deployment that declares nothing is the
// ordinary standalone case — but a file that exists and cannot be read or
// parsed is, because the alternative is starting up with less access than
// the deployment asked for and no sign of it.
func LoadOverlay(path string) (Overlay, error) {
	if path == "" {
		return Overlay{}, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path is deployment configuration, not input
	if os.IsNotExist(err) {
		return Overlay{}, nil
	}
	if err != nil {
		return Overlay{}, fmt.Errorf("read the workspace overlay: %w", err)
	}
	return ParseOverlay(data)
}
