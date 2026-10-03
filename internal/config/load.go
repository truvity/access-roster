package config

import (
	"path"

	policyconfig "github.com/truvity/policy/config"

	accessroster "github.com/truvity/access-roster"
)

// schemaFor reads the committed schema of one binary: the one embedded in the
// release, which is the one the chart's tests and a deployer's CI validate
// against.
func schemaFor(name string) []byte {
	b, err := accessroster.ConfigSchemas.ReadFile(path.Join("schemas/config", name+".schema.json"))
	if err != nil {
		// Unreachable: the files are embedded at build time, so a missing one
		// fails to compile rather than at run time.
		panic(err)
	}
	return b
}

// Validate checks a decoded document against one binary's schema. The chart's
// tests call it on what the chart renders, which is what stops the two
// drifting.
func Validate(name string, doc any) error {
	return policyconfig.Validate(doc, schemaFor(name))
}

func load[T any](file, name string) (*T, error) {
	var c T
	if err := policyconfig.Load(file, schemaFor(name), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadIssuer reads and validates access-issuer's configuration. Defaults that
// depend on the other keys, and the checks that need what the issuer knows, are
// the assembling packages': this reads the file and holds it to its schema.
func LoadIssuer(file string) (*Issuer, error) { return load[Issuer](file, "access-issuer") }

// LoadGitHubRoster reads and validates github-roster's configuration.
func LoadGitHubRoster(file string) (*GitHubRoster, error) {
	return load[GitHubRoster](file, "github-roster")
}

// LoadSlackRoster reads and validates slack-roster's configuration.
func LoadSlackRoster(file string) (*SlackRoster, error) {
	return load[SlackRoster](file, "slack-roster")
}

// Secret reads the environment variable the configuration names. An unset or
// empty variable is an error naming the variable, never quoting anything.
func Secret(name string) (string, error) { return policyconfig.Secret(name) }
