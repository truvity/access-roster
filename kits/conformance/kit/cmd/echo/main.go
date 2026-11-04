// Command echo serves and calls the EchoService of the cross-language test of the kits. It is test-only.
//
//	go run -tags sluis_test ./kits/conformance/kit/cmd/echo serve --socket /tmp/e.sock
//	go run -tags sluis_test ./kits/conformance/kit/cmd/echo call  --socket /tmp/e.sock
//
// "serve" needs the tag sluis_test: it answers any caller that runs under the uid of the server's own process, as
// the actor "harness", and that name resolver is in a tagged build only. A test runs both ends as one user, so the
// registry's pinned uids do not apply. "call" needs no tag: it checks a server of either language and exits 0 when
// every case passes.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/truvity/sluis/v2/kits/conformance/kit/echo"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "call" {
		os.Exit(call(os.Args[2:]))
	}
	cli.Main("echo", cli.Commands{Serve: serve}, nil)
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
