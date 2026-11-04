// Command session is the actor that signs people in and issues their tokens: it serves the authorize, callback and
// token endpoints that entry routes to it (ADR 0017, ADR 0018).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"path/filepath"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
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

// flags holds the flags beyond the common ones. A flag left empty takes the socket layout of the plan: an actor's
// socket is /run/sluis/<actor>/<boundary>.sock, and key@ opens one socket for each caller.
type flags struct {
	storeSocket, keySocket, policySocket, signerSocket, upstreamSocket, transportSocket, upstreamName string
}

func (f *flags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.storeSocket, "store-socket", "", "the socket of store@ (default /run/sluis/store/<boundary>.sock)")
	fs.StringVar(&f.keySocket, "key-socket", "", "the socket of key@ for this actor (default /run/sluis/key/<boundary>/session/key.sock)")
	fs.StringVar(&f.policySocket, "policy-socket", "", "the socket of policy (default /run/sluis/policy/<boundary>.sock)")
	fs.StringVar(&f.signerSocket, "signer-socket", "", "the socket of signer (default /run/sluis/signer/<boundary>.sock)")
	fs.StringVar(&f.upstreamSocket, "upstream-socket", "", "the socket of adapter-upstream-oidc (default /run/sluis/adapter-upstream-oidc/<boundary>.sock)")
	fs.StringVar(&f.transportSocket, "transport-socket", "", "the emit socket of the audit transport (default /run/sluis/audit/<boundary>/emit.sock)")
	fs.StringVar(&f.upstreamName, "upstream", "", "the name of the Upstream to sign people in at (default: the only one the boundary declares)")
}

func (f *flags) service(c cli.Flags) (*sessiond.Service, error) {
	if c.Boundary == "" {
		return nil, cli.Usage(fmt.Errorf("required: --boundary"))
	}
	orDefault := func(v, def string) string {
		if v != "" {
			return v
		}
		return def
	}
	run := "/run/sluis"
	dial := func(socket string) (connect.HTTPClient, string) { return rpc.Dial(socket) }
	sh, surl := dial(orDefault(f.storeSocket, filepath.Join(run, "store", c.Boundary+".sock")))
	st := storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...)
	cfg, err := sessiond.NewConfig(st)
	if err != nil {
		return nil, err
	}
	kh, kurl := dial(orDefault(f.keySocket, filepath.Join(run, "key", c.Boundary, sessiond.Actor, "key.sock")))
	keys := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)
	ph, purl := dial(orDefault(f.policySocket, filepath.Join(run, "policy", c.Boundary+".sock")))
	gh, gurl := dial(orDefault(f.signerSocket, filepath.Join(run, "signer", c.Boundary+".sock")))
	uh, uurl := dial(orDefault(f.upstreamSocket, filepath.Join(run, "adapter-upstream-oidc", c.Boundary+".sock")))
	th, turl := dial(orDefault(f.transportSocket, filepath.Join(run, "audit", c.Boundary, "emit.sock")))
	em, err := audit.New(audit.Config{
		Actor: sessiond.Actor, Boundary: c.Boundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(th, turl, rpc.ClientOptions()...),
		Keys:      keys,
	})
	if err != nil {
		return nil, cli.Usage(err)
	}
	return sessiond.New(sessiond.Options{
		Boundary: c.Boundary, Config: cfg, Store: st, Keys: keys,
		Policy:       policyv2alpha1connect.NewPolicyServiceClient(ph, purl, rpc.ClientOptions()...),
		Signer:       signerv2alpha1connect.NewSignerServiceClient(gh, gurl, rpc.ClientOptions()...),
		Upstream:     integrationv2alpha1connect.NewUpstreamServiceClient(uh, uurl, rpc.ClientOptions()...),
		Audit:        em,
		UpstreamName: f.upstreamName,
	})
}

func main() {
	var f flags
	cli.Main(sessiond.Actor, commands(&f), f.add)
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
