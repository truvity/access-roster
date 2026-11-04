// Command exchange serves the token exchange grant of RFC 8693 that entry routes to it: it checks the subject token,
// asks policy whether the person's token may become a token for the audience, and has signer sign it (ADR 0022,
// "Proofs and the exchange").
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/truvity/sluis/v2/actors/exchange/internal/exchanged"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// flags holds the flags beyond the common ones. A flag left empty takes the socket layout of the plan: the sockets
// are named by the boundary.
type flags struct {
	storeSocket, transportSocket, keySocket, policySocket, signerSocket string
}

func (f *flags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.storeSocket, "store-socket", "", "the socket of store@ (default /run/sluis/store/<boundary>.sock)")
	fs.StringVar(&f.transportSocket, "transport-socket", "", "the emit socket of the audit transport (default /run/sluis/audit/<boundary>/emit.sock)")
	fs.StringVar(&f.keySocket, "key-socket", "", "the socket of key@ for this actor (default /run/sluis/key/<boundary>/exchange/key.sock)")
	fs.StringVar(&f.policySocket, "policy-socket", "", "the socket of policy (default /run/sluis/policy/<boundary>.sock)")
	fs.StringVar(&f.signerSocket, "signer-socket", "", "the socket of signer (default /run/sluis/signer/<boundary>.sock)")
}

func (f *flags) service(c cli.Flags) (*exchanged.Service, error) {
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
	keySocket := orDefault(f.keySocket, filepath.Join("/run/sluis/key", c.Boundary, exchanged.Actor, "key.sock"))
	policySocket := orDefault(f.policySocket, filepath.Join("/run/sluis/policy", c.Boundary+".sock"))
	signerSocket := orDefault(f.signerSocket, filepath.Join("/run/sluis/signer", c.Boundary+".sock"))

	sh, surl := rpc.Dial(storeSocket)
	st := storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...)
	cfg, err := exchanged.NewConfig(st)
	if err != nil {
		return nil, err
	}
	th, turl := rpc.Dial(transportSocket)
	kh, kurl := rpc.Dial(keySocket)
	keys := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)
	em, err := audit.New(audit.Config{
		Actor: exchanged.Actor, Boundary: c.Boundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...),
		Keys:      keys,
	})
	if err != nil {
		return nil, cli.Usage(err)
	}
	// The person behind a token is read from the kinds of session through store@ and key@ (exchanged.StoreDirectory).
	dir, err := exchanged.NewStoreDirectory(cfg, st, keys, nil)
	if err != nil {
		return nil, err
	}
	ph, purl := rpc.Dial(policySocket)
	gh, gurl := rpc.Dial(signerSocket)
	return exchanged.New(exchanged.Options{
		Boundary: c.Boundary, Config: cfg,
		Directory: dir,
		Policy:    policyv2alpha1connect.NewPolicyServiceClient(ph, purl, rpc.ClientOptions()...),
		Signer:    signerv2alpha1connect.NewSignerServiceClient(gh, gurl, rpc.ClientOptions()...),
		Keys:      keys,
		Audit:     em,
	})
}

func main() {
	var f flags
	cli.Main(exchanged.Actor, commands(&f), f.add)
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
