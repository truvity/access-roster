// Package driver is the software key driver of key@: the key-store port, sluis.port.keystore.v2alpha1, served
// over keys held in files (ADR 0006, "Floors in code"; ADR 0011, "The local installation").
//
// It exists for the local installation, for CI and for a smoke installation without cards. It refuses
// production, and it has no audit emitter: a driver is private to its owner, and key@ audits what it asks for.
package driver

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/software/internal/keystore"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// Name is the registry name of the driver's user; its owner is key.
const Name = "driver-key-software"

// The environments of an installation. The flag is required: nothing defaults to development.
const (
	Development = "development"
	Staging     = "staging"
	Production  = "production"
)

// RefusedInProduction is what the driver prints when it is started in production.
const RefusedInProduction = "software key driver refused in production"

// Floor is the floor in code (ADR 0006): the driver does not run in production. It returns an error that exits 3
// for production, and a usage error for a value that is not an environment.
func Floor(environment string) error {
	switch environment {
	case Development, Staging:
		return nil
	case Production:
		return cli.Refused(RefusedInProduction)
	default:
		return cli.Usage(errors.New("--environment must be development, staging or production"))
	}
}

// Options are what Run needs besides the server configuration.
type Options struct {
	Environment string
	StateDir    string
}

// Owner returns the actor that owns the driver: key. The driver's socket serves nobody else.
func Owner() string {
	owner, _ := registry.DriverOwner(Name)
	return owner
}

// Run applies the floor, opens the state directory and serves the key-store port with cfg until ctx ends. The
// floor comes first: in production nothing is opened and no key is read.
func Run(ctx context.Context, opts Options, cfg rpc.ServerConfig) error {
	if err := Floor(opts.Environment); err != nil {
		return err
	}
	if opts.Environment == Staging {
		slog.Warn("software keys in staging: anyone who can read the volume has the keys", "environment", Staging)
	}
	st, err := keystore.Open(opts.StateDir)
	if err != nil {
		var pe *keystore.ProblemsError
		if errors.As(err, &pe) {
			return cli.Refused(pe.Problems...)
		}
		return err
	}
	slog.Info("software key driver starting", "environment", opts.Environment, "boundary", cfg.Boundary,
		"purposes", st.Present())
	path, h := keystorev2alpha1connect.NewKeyStoreServiceHandler(&Service{store: st}, rpc.HandlerOptions(cfg)...)
	return rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h})
}

// Check verifies the state directory and the keys in it. It reads, and writes nothing.
func Check(dir string) error {
	if _, problems := keystore.Check(dir); len(problems) > 0 {
		return cli.Refused(problems...)
	}
	return nil
}

// Service implements the key-store port over a keystore.Store.
type Service struct {
	keystorev2alpha1connect.UnimplementedKeyStoreServiceHandler
	store *keystore.Store
}

// NewService returns the service over a store, for a test that serves it itself.
func NewService(s *keystore.Store) *Service { return &Service{store: s} }

// The reasons of the refusals of the port (a closed list).
const (
	reasonPurpose   = "purpose"
	reasonAlgorithm = "algorithm"
	reasonDigest    = "digest"
	reasonPeer      = "peer_public"
	reasonAbsent    = "absent"
	reasonStore     = "store"
)

// refuse logs a refusal, with the method and the reason and no value, and returns it.
func refuse(ctx context.Context, method string, code connect.Code, reason, field string) *connect.Error {
	caller := ""
	if p, ok := rpc.PeerFromContext(ctx); ok {
		caller = p.Name
	}
	slog.Warn("refused", "method", method, "code", code.String(), "reason", reason, "field", field, "caller", caller)
	return refusal.New(code, reason, field)
}

// Capabilities says what the store can do.
func (*Service) Capabilities(context.Context, *connect.Request[keystorev2alpha1.CapabilitiesRequest]) (*connect.Response[keystorev2alpha1.CapabilitiesResponse], error) {
	return connect.NewResponse(&keystorev2alpha1.CapabilitiesResponse{
		Store: "software", Attests: false, Algorithms: []string{keystore.ES384, keystore.ECDHP384},
	}), nil
}

// Ensure makes the key of a purpose when it is absent and returns its public key.
func (s *Service) Ensure(ctx context.Context, req *connect.Request[keystorev2alpha1.EnsureRequest]) (*connect.Response[keystorev2alpha1.EnsureResponse], error) {
	purpose, algorithm := req.Msg.GetPurpose(), req.Msg.GetAlgorithm()
	want, ok := keystore.AlgorithmFor(purpose)
	if !ok {
		return nil, refuse(ctx, "Ensure", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if algorithm != keystore.ES384 && algorithm != keystore.ECDHP384 {
		return nil, refuse(ctx, "Ensure", connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	if algorithm != want {
		// An existing key has another algorithm, or the purpose is not for this one: the key is never replaced.
		return nil, refuse(ctx, "Ensure", connect.CodeFailedPrecondition, reasonAlgorithm, "algorithm")
	}
	spki, created, err := s.store.Ensure(purpose, algorithm)
	if err != nil {
		return nil, s.failed(ctx, "Ensure", err)
	}
	if created {
		slog.Info("key made", "purpose", purpose, "algorithm", algorithm)
	}
	return connect.NewResponse(&keystorev2alpha1.EnsureResponse{SpkiDer: spki, Created: created}), nil
}

// Sign signs a digest with the key of a purpose, in place.
func (s *Service) Sign(ctx context.Context, req *connect.Request[keystorev2alpha1.KeyStoreSignRequest]) (*connect.Response[keystorev2alpha1.KeyStoreSignResponse], error) {
	purpose := req.Msg.GetPurpose()
	if _, ok := keystore.AlgorithmFor(purpose); !ok {
		return nil, refuse(ctx, "Sign", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if req.Msg.GetAlgorithm() != keystore.ES384 {
		return nil, refuse(ctx, "Sign", connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	sig, err := s.store.Sign(purpose, req.Msg.GetDigest())
	if err != nil {
		return nil, s.failed(ctx, "Sign", err)
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStoreSignResponse{SignatureDer: sig}), nil
}

// PublicKey returns the public key of a purpose.
func (s *Service) PublicKey(ctx context.Context, req *connect.Request[keystorev2alpha1.KeyStorePublicKeyRequest]) (*connect.Response[keystorev2alpha1.KeyStorePublicKeyResponse], error) {
	purpose := req.Msg.GetPurpose()
	if _, ok := keystore.AlgorithmFor(purpose); !ok {
		return nil, refuse(ctx, "PublicKey", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	spki, err := s.store.PublicKey(purpose)
	if err != nil {
		return nil, s.failed(ctx, "PublicKey", err)
	}
	return connect.NewResponse(&keystorev2alpha1.KeyStorePublicKeyResponse{SpkiDer: spki}), nil
}

// Ecdh derives the shared secret of the key-agreement key with a peer.
func (s *Service) Ecdh(ctx context.Context, req *connect.Request[keystorev2alpha1.EcdhRequest]) (*connect.Response[keystorev2alpha1.EcdhResponse], error) {
	purpose := req.Msg.GetPurpose()
	if _, ok := keystore.AlgorithmFor(purpose); !ok {
		return nil, refuse(ctx, "Ecdh", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	secret, err := s.store.Ecdh(purpose, req.Msg.GetPeerPublic())
	if err != nil {
		return nil, s.failed(ctx, "Ecdh", err)
	}
	return connect.NewResponse(&keystorev2alpha1.EcdhResponse{SharedSecret: secret}), nil
}

// failed maps an error of the store to its refusal.
func (*Service) failed(ctx context.Context, method string, err error) *connect.Error {
	switch {
	case errors.Is(err, keystore.ErrAbsent):
		return refuse(ctx, method, connect.CodeNotFound, reasonAbsent, "purpose")
	case errors.Is(err, keystore.ErrAlgorithm):
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonAlgorithm, "purpose")
	case errors.Is(err, keystore.ErrDigest):
		return refuse(ctx, method, connect.CodeInvalidArgument, reasonDigest, "digest")
	case errors.Is(err, keystore.ErrPeer):
		return refuse(ctx, method, connect.CodeInvalidArgument, reasonPeer, "peer_public")
	}
	slog.Error("store failed", "method", method, "error", err.Error())
	return refusal.New(connect.CodeInternal, reasonStore, "")
}
