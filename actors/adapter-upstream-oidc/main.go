// Command adapter-upstream-oidc is the adapter of the generic OpenID Connect upstream: it federates sign-in to an
// upstream provider and returns the verified assertion to session (ADR 0025, "The upstream contract").
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/truvity/sluis/v2/actors/adapter-upstream-oidc/internal/upstreamd"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// flags holds the flags beyond the common ones. A flag left empty takes the socket layout of the plan: the sockets
// are named by the boundary.
type flags struct {
	storeSocket, transportSocket, keySocket, credentialsDir string
}

func (f *flags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.storeSocket, "store-socket", "", "the socket of store@ (default /run/sluis/store/<boundary>.sock)")
	fs.StringVar(&f.transportSocket, "transport-socket", "", "the emit socket of the audit transport (default /run/sluis/audit/<boundary>/emit.sock)")
	fs.StringVar(&f.keySocket, "key-socket", "", "the socket of key@ for this actor (default /run/sluis/key/<boundary>/adapter-upstream-oidc/key.sock)")
	fs.StringVar(&f.credentialsDir, "credentials-dir", "", "the directory of the client secrets (default $CREDENTIALS_DIRECTORY)")
}

func (f *flags) service(c cli.Flags) (*upstreamd.Service, error) {
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
	keySocket := orDefault(f.keySocket, filepath.Join("/run/sluis/key", c.Boundary, upstreamd.Actor, "key.sock"))
	credentials := orDefault(f.credentialsDir, os.Getenv("CREDENTIALS_DIRECTORY"))

	hc, url := rpc.Dial(storeSocket)
	cfg, err := upstreamd.NewConfig(storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...))
	if err != nil {
		return nil, err
	}
	th, turl := rpc.Dial(transportSocket)
	kh, kurl := rpc.Dial(keySocket)
	em, err := audit.New(audit.Config{
		Actor: upstreamd.Actor, Boundary: c.Boundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...),
		Keys:      keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...),
	})
	if err != nil {
		return nil, cli.Usage(err)
	}
	return upstreamd.New(upstreamd.Options{
		Boundary: c.Boundary, Config: cfg, Secrets: upstreamd.CredentialDir(credentials), Audit: em,
	})
}

func main() {
	var f flags
	cli.Main(upstreamd.Actor, commands(&f), f.add)
}

func commands(f *flags) cli.Commands {
	return cli.Commands{
		Serve: func(ctx context.Context, c cli.Flags) error {
			if c.Socket == "" {
				return cli.Usage(fmt.Errorf("required: --socket"))
			}
			s, err := f.service(c)
			if err != nil {
				return err
			}
			return s.Serve(ctx, c.Socket)
		},
		Check: func(ctx context.Context, c cli.Flags) error {
			s, err := f.service(c)
			if err != nil {
				return err
			}
			if bad := s.Check(ctx); len(bad) > 0 {
				slog.Error("check failed", "paths", bad)
				return cli.Refused(bad...)
			}
			return nil
		},
	}
}
