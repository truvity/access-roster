// Command writer is the audit writer (ADR 0028, 0029): it seals the audit messages of its project into a tiled log in
// the audit blob and has key@ sign a checkpoint for every batch. It serves no socket of its own: it is a client of
// the audit transport, store@, key@, policy and the blob driver, so it takes no --socket-gid.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/truvity/sluis/v2/actors/writer/internal/writerd"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

// flags holds the flags of the writer beyond the common ones. A socket not named is the default of the socket layout
// (PLAN.md): the paths below /run/sluis are fixed by the registry, so a unit names none.
type flags struct {
	instance, storeSocket, keySocket, policySocket, blobSocket, transportSocket string
}

func (f *flags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.instance, "instance", "", "the name of this writer in the entries it stamps: the node's short name; the host name by default")
	fs.StringVar(&f.storeSocket, "store-socket", "", "the socket of store@; /run/sluis/store/<boundary>.sock by default")
	fs.StringVar(&f.keySocket, "key-socket", "", "the socket of key@ for the writer; /run/sluis/key/<boundary>/writer/key.sock by default")
	fs.StringVar(&f.policySocket, "policy-socket", "", "the socket of policy; /run/sluis/policy/<boundary>.sock by default")
	fs.StringVar(&f.blobSocket, "blob-socket", "", "the socket of the blob driver; /run/sluis/writer/<boundary>/blob.sock by default")
	fs.StringVar(&f.transportSocket, "transport-socket", "", "the receive socket of the audit transport; /run/sluis/audit/<boundary>/receive.sock by default")
}

func (f *flags) config(c cli.Flags) (writerd.Config, error) {
	if c.Boundary == "" {
		return writerd.Config{}, cli.Usage(fmt.Errorf("required: --boundary"))
	}
	if strings.ContainsAny(c.Boundary, "/ ") {
		return writerd.Config{}, cli.Usage(fmt.Errorf("--boundary is not a name"))
	}
	or := func(v, def string) string {
		if v != "" {
			return v
		}
		return def
	}
	run := "/run/sluis"
	b := c.Boundary
	return writerd.Config{
		Boundary:        b,
		Instance:        or(f.instance, hostname()),
		StoreSocket:     or(f.storeSocket, filepath.Join(run, "store", b+".sock")),
		KeySocket:       or(f.keySocket, filepath.Join(run, "key", b, "writer", "key.sock")),
		PolicySocket:    or(f.policySocket, filepath.Join(run, "policy", b+".sock")),
		BlobSocket:      or(f.blobSocket, filepath.Join(run, "writer", b, "blob.sock")),
		TransportSocket: or(f.transportSocket, filepath.Join(run, "audit", b, "receive.sock")),
	}, nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "node-1"
	}
	return strings.ToLower(h)
}

func main() {
	var f flags
	cli.Main("writer", commands(&f), f.add)
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

func (f *flags) server(c cli.Flags) (*writerd.Server, error) {
	cfg, err := f.config(c)
	if err != nil {
		return nil, err
	}
	s, err := writerd.New(cfg)
	if err != nil {
		return nil, cli.Usage(err)
	}
	return s, nil
}
