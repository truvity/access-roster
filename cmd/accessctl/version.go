package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/truvity/access-roster/internal/version"
)

// versionCommand prints this build's own identity: the version this
// binary was built from — `dev` for one built without the release
// workflow's ldflags (internal/version.Version's own default).
//
// It is the one command that touches nothing: no config file, no
// session, no network call — so it works with an empty HOME, signed in
// or not, issuer reachable or not.
func versionCommand(args []string) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := flags.Bool("json", false, "print {version} as JSON")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() > 0 {
		return badUsage("unexpected %q: version takes no arguments", flags.Arg(0))
	}

	if !*asJSON {
		_, _ = fmt.Fprintf(stdout, "accessctl %s\n", version.String())
		return nil
	}
	return json.NewEncoder(stdout).Encode(versionAnswer{Version: version.String()})
}

// versionAnswer is `--json`: what a script reads. Only `version` is
// stamped today (.goreleaser.yaml's ldflags write nothing else into
// internal/version) — a commit or a build date would join it here, by
// name, the day something stamps one.
type versionAnswer struct {
	Version string `json:"version"`
}
