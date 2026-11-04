// Command echo serves and calls the EchoService of the cross-language test of the kits. It is test-only.
//
//	go run ./kits/conformance/kit/cmd/echo serve --socket /tmp/e.sock
//	go run ./kits/conformance/kit/cmd/echo call  --socket /tmp/e.sock
//
// "serve" answers any caller that runs under the uid of the server's own process, as the actor "harness": a test
// runs both ends as one user, so the registry's pinned uids do not apply. "call" checks a server of either
// language and exits 0 when every case passes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/truvity/sluis/v2/kits/conformance/kit/echo"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "call" {
		os.Exit(call(os.Args[2:]))
	}
	cli.Main("echo", cli.Commands{Serve: serve}, nil)
}

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

func call(args []string) int {
	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	socket := fs.String("socket", "", "the socket of the server")
	if err := fs.Parse(args); err != nil || *socket == "" {
		fmt.Fprintln(os.Stderr, "usage: echo call --socket PATH")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := echo.Call(ctx, *socket); err != nil {
		fmt.Fprintln(os.Stderr, "echo call: FAIL:", err)
		return 1
	}
	fmt.Println("echo call: ok")
	return 0
}
