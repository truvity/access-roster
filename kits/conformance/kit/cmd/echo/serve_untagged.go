//go:build !sluis_test

package main

import (
	"context"
	"errors"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// serve needs the name-resolver seam of the rpc kit, which only a build with the tag sluis_test contains: the echo
// server runs as an ordinary user, whose uid is not an actor uid.
func serve(context.Context, cli.Flags) error {
	return cli.Usage(errors.New("echo serve needs a build with -tags sluis_test"))
}
