// Command software is the software key driver of key@: the key-store port over P-384 keys held in files. It is
// for the local installation, for CI and for a smoke installation without cards, and it refuses production.
//
//	software serve --socket PATH --state-dir DIR --environment development|staging|production
//	software check --state-dir DIR
//	software conformance --socket PATH
//	software version
package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/truvity/sluis/v2/drivers/key/software/internal/driver"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

func main() {
	cli.Main("software", cli.Commands{Serve: serve, Check: check, Conformance: conformance}, flags)
}

func flags(fs *flag.FlagSet) {
	fs.String("state-dir", "", "the directory of the key files (mode 0700, owned by the driver's user)")
	fs.String("environment", "", "development, staging or production (required; production is refused)")
}

func value(f cli.Flags, name string) string {
	if fl := f.Extra.Lookup(name); fl != nil {
		return fl.Value.String()
	}
	return ""
}

func serve(ctx context.Context, f cli.Flags) error {
	env := value(f, "environment")
	if env == "" {
		return cli.Usage(errors.New("--environment is required"))
	}
	// The floor comes before anything is opened: no socket, no key.
	if err := driver.Floor(env); err != nil {
		return err
	}
	if f.Socket == "" {
		return cli.Usage(errors.New("--socket is required"))
	}
	dir := value(f, "state-dir")
	if dir == "" {
		return cli.Usage(errors.New("--state-dir is required"))
	}
	cfg := rpc.ServerConfig{
		Actor:    driver.Name,
		Boundary: f.Boundary,
		Socket:   f.Socket,
		Mode:     0o600,
		Allow:    rpc.OwnerOnly(driver.Owner()),
	}
	return driver.Run(ctx, driver.Options{Environment: env, StateDir: dir}, cfg)
}

func check(_ context.Context, f cli.Flags) error {
	dir := value(f, "state-dir")
	if dir == "" {
		return cli.Usage(errors.New("--state-dir is required"))
	}
	// An environment given to check is held to the same floor as serve: a check must not pass what serve refuses.
	if env := value(f, "environment"); env != "" {
		if err := driver.Floor(env); err != nil {
			return err
		}
	}
	return driver.Check(dir)
}

func conformance(ctx context.Context, f cli.Flags) error {
	if f.Socket == "" {
		return cli.Usage(errors.New("--socket is required"))
	}
	return driver.Conformance(ctx, f.Socket, os.Stdout)
}
