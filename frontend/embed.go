// Package frontend embeds the built console, so that the hub is one binary
// with no static-file deployment beside it and the SPA is same-origin with
// the API it calls.
//
// dist/ is BUILT, not committed, and `just build` builds it first.
//
// It used to be committed so that `go build` needed no Node toolchain.
// That cost 29 MB of history -- about seventy per cent of this
// repository -- because a minified bundle is a new blob on every
// dependency bump. And it bought a silent failure: a committed artifact
// can go stale while everything still compiles, which is how v0.14.0
// shipped a console reading a protobuf field the server no longer sent.
//
// Absent, the embed below is a COMPILE ERROR -- `pattern all:dist: no
// matching files found`. Loud beats stale.
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
