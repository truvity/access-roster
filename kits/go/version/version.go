// Package version holds the one release version of every sluis artefact (ADR 0013, One version).
// The release build sets Version with
//
//	-ldflags "-X github.com/truvity/sluis/v2/kits/go/version.Version=<version>"
//
// and a development build keeps the default.
package version

import "runtime"

// Version is the release version, or "0.0.0-dev" for a development build.
var Version = "0.0.0-dev"

// String returns the version and the Go runtime that built the binary, for a version command.
func String() string {
	return Version + " (" + runtime.Version() + ")"
}
