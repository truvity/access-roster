// Command key is key@: it holds a boundary's keys, and seals, opens, signs and makes keyed hashes for the actors
// of its boundary (ADR 0006).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"strings"

	"github.com/truvity/sluis/v2/actors/key/internal/keyd"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

// flags holds the flags of key@ beyond the common ones.
type flags struct {
	runDir, storeSocket, driverSocket, transportSocket, node string
}

func (f *flags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.runDir, "run-dir", "", "the directory with one subdirectory per caller, /run/sluis/key/<boundary>")
	fs.StringVar(&f.storeSocket, "store-socket", "", "the socket of store@, /run/sluis/store/<boundary>.sock")
	fs.StringVar(&f.driverSocket, "driver-socket", "", "the socket of the key-store driver, <run-dir>/driver/key-store.sock")
	fs.StringVar(&f.transportSocket, "transport-socket", "", "the emit socket of the audit transport, /run/sluis/audit/<boundary>/emit.sock")
	fs.StringVar(&f.node, "node", "", "the recipient label base of this node: node-1 locally, the board's short name on a board")
}

func (f *flags) server(c cli.Flags) (*keyd.Server, error) {
	var missing []string
	for name, v := range map[string]string{
		"boundary": c.Boundary, "run-dir": f.runDir, "store-socket": f.storeSocket,
		"driver-socket": f.driverSocket, "node": f.node,
	} {
		if v == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return nil, cli.Usage(fmt.Errorf("required: %s", strings.Join(missing, ", ")))
	}
	s, err := keyd.New(keyd.Config{
		Boundary: c.Boundary, RunDir: f.runDir, StoreSocket: f.storeSocket,
		DriverSocket: f.driverSocket, Node: f.node,
		Auditor: auditor(f.transportSocket),
	})
	if err != nil {
		return nil, cli.Usage(err)
	}
	return s, nil
}

func main() {
	var f flags
	cli.Main("key", commands(&f), f.add)
}

func commands(f *flags) cli.Commands {
	return cli.Commands{
		Serve: func(ctx context.Context, c cli.Flags) error {
			s, err := f.server(c)
			if err != nil {
				return err
			}
			return s.Run(ctx)
		},
		Check: func(ctx context.Context, c cli.Flags) error {
			s, err := f.server(c)
			if err != nil {
				return err
			}
			if err := s.Check(ctx); err != nil {
				slog.Error("check failed", "err", err)
				return cli.Refused(err.Error())
			}
			return nil
		},
	}
}
