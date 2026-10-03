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

// LoadServe reads and validates the configuration of `access-roster serve`. Defaults that
// depend on the other keys, and the checks that need what the issuer knows, are
// the assembling packages': this reads the file and holds it to its schema.
func LoadServe(file string) (*Serve, error) { return load[Serve](file, "serve") }

// LoadControllerGitHub reads and validates the configuration of
// `access-roster controller github`.
func LoadControllerGitHub(file string) (*ControllerGitHub, error) {
	return load[ControllerGitHub](file, "controller-github")
}

// LoadControllerSlack reads and validates the configuration of
// `access-roster controller slack`.
func LoadControllerSlack(file string) (*ControllerSlack, error) {
	return load[ControllerSlack](file, "controller-slack")
}

// Secret reads the environment variable the configuration names. An unset or
// empty variable is an error naming the variable, never quoting anything.
func Secret(name string) (string, error) { return policyconfig.Secret(name) }
