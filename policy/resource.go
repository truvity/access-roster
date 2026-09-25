package policy

import (
	"fmt"
	"net/url"
	"strings"
)

// Resource is something a token may be minted FOR, as distinct from the
// client that asks for it.
//
// Every other audience in this file is a client's id, because until now
// the two were the same thing: a person signs in to Argo CD, and the
// token is for Argo CD. That holds wherever the application a person
// reaches and the software asking on their behalf are one.
//
// It stops holding the moment they are not. A Model Context Protocol
// client is somebody's editor; what it wants a token for is a service
// somewhere else. Minting `aud` as the client's id there says "this
// token is for the editor", which is not true and not useful: a service
// pinning `aud` to decide whether a token was meant for it would have to
// pin the name of every editor that might call.
//
// So a resource is declared, a client asks for it by name with the
// `resource` parameter (RFC 8707), and `aud` is the resource. The two
// gates then compose, which is the point: [Client.Requires] says who may
// use this client, and [Resource.Requires] says who may reach this
// service, and a caller has to satisfy both.
type Resource struct {
	// DisplayName is what a person is told they are granting access to.
	// Shown on the sign-in page beside the client's own name, and public
	// in the same way.
	DisplayName string `yaml:"display_name,omitempty"`
	// Description is one line under it.
	Description string `yaml:"description,omitempty"`
	// Requires lists internal groups, any one of which admits a caller to
	// this resource. Mandatory, and checked in addition to the client's:
	// the client says who is asking, this says what may be asked for.
	Requires []string `yaml:"requires,omitempty"`
	// TTLCap caps the lifetime of tokens minted for this resource, as
	// `ttl_cap` does on a client. The shorter of the two applies.
	TTLCap Duration `yaml:"ttl_cap,omitempty"`
}

// Admits reports whether a caller holds a group this resource requires.
func (r Resource) Admits(result Result) bool {
	for _, name := range r.Requires {
		if result.Has(name) {
			return true
		}
	}
	return false
}

// Title is what a person is shown this resource as, given its id.
func (r Resource) Title(id string) string {
	if name := strings.TrimSpace(r.DisplayName); name != "" {
		return name
	}
	return id
}

// validate refuses a resource whose id is not something RFC 8707 allows,
// or whose gate is missing.
func (r Resource) validate(id string, groups map[string]Group) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	if len(r.Requires) == 0 {
		return fmt.Errorf("resource %q requires no group, so nobody may reach it", id)
	}
	for _, name := range r.Requires {
		if _, ok := groups[name]; !ok {
			return fmt.Errorf("resource %q requires %q, which is not a declared group", id, name)
		}
	}
	return nil
}

// validateResourceID holds an id to what RFC 8707 says a resource
// indicator is: an absolute URI, and no fragment.
//
// The fragment matters more than it looks. A client sends this value as a
// query parameter and the issuer compares it byte for byte, so an id that
// could carry a fragment is an id two parties can spell differently while
// believing they agree.
func validateResourceID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("a resource with no id")
	}
	parsed, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("resource %q is not a URI: %w", id, err)
	}
	if !parsed.IsAbs() {
		return fmt.Errorf("resource %q is not an absolute URI; a resource indicator names a service, so it carries a scheme", id)
	}
	if parsed.Fragment != "" || strings.Contains(id, "#") {
		return fmt.Errorf("resource %q carries a fragment, which RFC 8707 does not allow: "+
			"a client and this issuer could then spell the same resource differently", id)
	}
	return nil
}
