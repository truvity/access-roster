//go:build sluis_test

package main

import (
	"os"

	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// withTestCaller lets a test of another package run this binary as an ordinary user: SLUIS_TEST_CALLER names the
// actor that the test's own uid stands for. It exists only in a build with the tag sluis_test, as the name-resolver seam
// of the rpc kit does, so a normal build cannot rename its callers.
func withTestCaller(cfg rpc.ServerConfig) rpc.ServerConfig {
	name := os.Getenv("SLUIS_TEST_CALLER")
	if name == "" {
		return cfg
	}
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	return rpc.WithNameResolver(cfg, func(uid uint32) (string, uint32, bool) { return name, 0, uid == self })
}
