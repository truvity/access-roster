package server

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// The declared consumers of the API listener, with their grants
// (INF-679).
//
// A list of subjects fits in an environment variable; a grant does not,
// and squeezing one in would produce a syntax nobody can read in a
// Deployment. So a deployment that scopes its consumers mounts a file,
// exactly as it already mounts the policy and the workspace overlay.
//
// The two spellings are never both in force: a file replaces the list
// rather than adding to it, because two sources for who may call would
// be one place to add a consumer and another place to forget to.

// Consumer is one declared caller. The grant is inline, so the
// declaration reads as one row per consumer rather than two tables that
// have to be joined by eye.
type Consumer struct {
	// Namespace and ServiceAccount name the caller as the deployment
	// knows it; the subject the API server returns is derived from them.
	Namespace      string `yaml:"namespace"`
	ServiceAccount string `yaml:"serviceAccount"`
	// Workspaces, Domains, Groups and Reads are the grant. All empty is
	// full read, which is what an entry that names only a consumer
	// means -- and what every entry meant before grants existed.
	Workspaces []string `yaml:"workspaces,omitempty"`
	Domains    []string `yaml:"domains,omitempty"`
	Groups     []string `yaml:"groups,omitempty"`
	Reads      []Read   `yaml:"reads,omitempty"`
}

// ConsumerFile is the mounted document.
type ConsumerFile struct {
	Consumers []Consumer `yaml:"consumers"`
}

// LoadConsumers reads the declared consumers. An empty path is no file,
// which is not the same as an empty file: the first leaves the
// environment list in force, the second declares that nobody may call.
func LoadConsumers(path string) (*ConsumerFile, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec // the path is deployment configuration, not input
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read the consumers file: %w", err)
	}

	var file ConsumerFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse the consumers file: %w", err)
	}

	for i := range file.Consumers {
		if err := file.Consumers[i].validate(); err != nil {
			return nil, err
		}
	}

	return &file, nil
}

// Grant is this consumer's, or nil for full read. Nil rather than an
// empty struct so that the whole request path can test one thing.
func (c Consumer) Grant() *Grant {
	grant := &Grant{
		Consumer:   c.Namespace + "/" + c.ServiceAccount,
		Workspaces: c.Workspaces,
		Domains:    lower(c.Domains),
		Groups:     c.Groups,
		Reads:      c.Reads,
	}
	if grant.Everything() {
		return nil
	}

	return grant
}

// validate refuses a consumer that cannot be admitted or a grant that
// cannot mean what it says. Both are start-up failures: a hub that
// ignored a malformed grant would run with a wider one than the
// deployment declared.
func (c Consumer) validate() error {
	if c.Namespace == "" || c.ServiceAccount == "" {
		return fmt.Errorf("a consumer needs both a namespace and a serviceAccount, got %q/%q", c.Namespace, c.ServiceAccount)
	}

	grant := &Grant{Consumer: c.Namespace + "/" + c.ServiceAccount, Groups: c.Groups, Reads: c.Reads}

	return grant.Validate()
}

// lower normalises domains once, at load, so that no comparison on the
// request path has to remember to.
func lower(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}

	return out
}
