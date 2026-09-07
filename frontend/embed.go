// Package frontend embeds the built console, so that the hub is one binary
// with no static-file deployment beside it and the SPA is same-origin with
// the API it calls.
//
// dist/ is committed: `go build` must work without a Node toolchain, and
// CI builds the service without one. Rebuild it with `just console` after
// changing anything under frontend/src.
package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the built console, rooted so that index.html is at the top.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Only reachable if the embed directive and this path disagree,
		// which the build would already have caught.
		panic(err)
	}
	return sub
}
