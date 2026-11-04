//go:build sluis_test

package main

import (
	"context"
	"errors"
	"os"

	"github.com/truvity/sluis/v2/kits/conformance/kit/echo"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

func serve(ctx context.Context, f cli.Flags) error {
	if f.Socket == "" {
		return cli.Usage(errors.New("--socket is required"))
	}
	cfg := rpc.ServerConfig{
		Actor:    "echo",
		Boundary: f.Boundary,
		Socket:   f.Socket,
		Mode:     0o600,
		// Any caller that got through the resolver may call: the test has no call graph.
		Allow: func(rpc.Peer, string) bool { return true },
	}
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	cfg = rpc.WithNameResolver(cfg, func(uid uint32) (string, uint32, bool) {
		return "harness", 0, uid == self
	})
	return rpc.Serve(ctx, cfg, echo.Handler(cfg))
}
