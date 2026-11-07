// Command ca is the X.509 certificate authority. In the first working version it makes one certificate: the token
// certificate, which the node's intermediate gives to the token-signing key (ADR 0023). It holds no key and serves no
// socket; it asks key@ to sign.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/truvity/sluis/v2/actors/ca/internal/cad"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// flags holds the flags beyond the common ones. A flag left empty takes the socket layout of the plan.
type flags struct {
	storeSocket, transportSocket, keySocket string
}

func (f *flags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.storeSocket, "store-socket", "", "the socket of store@ (default /run/sluis/store/<boundary>.sock)")
	fs.StringVar(&f.transportSocket, "transport-socket", "", "the emit socket of the audit transport (default /run/sluis/audit/<boundary>/emit.sock)")
	fs.StringVar(&f.keySocket, "key-socket", "", "the socket of key@ for this actor (default /run/sluis/key/<boundary>/ca/key.sock)")
}

func (f *flags) worker(c cli.Flags) (*cad.Worker, error) {
	if c.Boundary == "" {
		return nil, cli.Usage(fmt.Errorf("required: --boundary"))
	}
	orDefault := func(v, def string) string {
		if v != "" {
			return v
		}
		return def
	}
	storeSocket := orDefault(f.storeSocket, filepath.Join("/run/sluis/store", c.Boundary+".sock"))
	transportSocket := orDefault(f.transportSocket, filepath.Join("/run/sluis/audit", c.Boundary, "emit.sock"))
	keySocket := orDefault(f.keySocket, filepath.Join("/run/sluis/key", c.Boundary, cad.Actor, "key.sock"))

	sh, surl := rpc.Dial(storeSocket)
	th, turl := rpc.Dial(transportSocket)
	kh, kurl := rpc.Dial(keySocket)
	em, err := audit.New(audit.Config{
		Actor: cad.Actor, Boundary: c.Boundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...),
	})
	if err != nil {
		return nil, cli.Usage(err)
	}
	w, err := cad.New(cad.Options{
		Boundary: c.Boundary,
		Store:    storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...),
		Keys:     keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...),
		Audit:    em,
	})
	if err != nil {
		return nil, cli.Usage(err)
	}
	return w, nil
}

func main() {
	var f flags
	cli.Main(cad.Actor, commands(&f), f.add)
}

func commands(f *flags) cli.Commands {
	return cli.Commands{
		Serve: func(ctx context.Context, c cli.Flags) error {
			w, err := f.worker(c)
			if err != nil {
				return err
			}
			return w.Run(ctx)
		},
		Check: func(ctx context.Context, c cli.Flags) error {
			w, err := f.worker(c)
			if err != nil {
				return err
			}
			if bad := w.Check(ctx); len(bad) > 0 {
				slog.Error("check failed", "paths", bad)
				return cli.Refused(bad...)
			}
			return nil
		},
	}
}
