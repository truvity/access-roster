// Package version carries the build's identity, so that an operator
// looking at a console can say which build they are looking at without
// asking a cluster.
package version

// Version is the release this binary was built from. The release
// workflow stamps it from the git tag; a development build says so.
var Version = "dev"

// String returns the version.
func String() string { return Version }
