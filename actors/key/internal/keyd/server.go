// Package keyd is key@: it holds a boundary's keys (ADR 0006). It seals, opens, signs and makes keyed hashes
// after three checks on every call: who the caller is (the transport), the caller's rule for the purpose and the
// operation (the registry), and the grant where D-5 of the plan requires one.
//
// Data keys are made here, in software, and kept only wrapped, as DataKeyWrap items in store@. Authority keys
// stay in the key store behind its driver; key@ signs through it after it has checked the content.
package keyd

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Built-in limits that a KeyPlan may shorten and never lengthen (ADR 0006, "Floors in code").
const (
	defaultCacheTTL = 15 * time.Minute
	maxCacheTTL     = time.Hour
	// DefaultRewrapEvery is the period of the rewrap pass (ADR 0006, "Keys per board").
	DefaultRewrapEvery = 60 * time.Second
)

// Config is the configuration of one key@.
type Config struct {
	Boundary     string
	RunDir       string // /run/sluis/key/<boundary>: one directory per caller below it
	StoreSocket  string // /run/sluis/store/<boundary>.sock
	DriverSocket string // /run/sluis/key/<boundary>/driver/key-store.sock
	// TransportSocket is the emit socket of the audit transport, /run/sluis/audit/<boundary>/emit.sock. The check
	// command reaches it; the Auditor is what emits.
	TransportSocket string
	// Bootstrap is the path of the bootstrap file, /etc/sluis/bootstrap.d/<boundary>.yaml. key@ reads its publishers
	// block and nothing else: the public keys that sign config. They are the trust anchor of the KeyPlan, which key@
	// verifies itself instead of taking it from store@ (REQ-KEYS-075).
	Bootstrap string
	// StateDir is key@'s own durable local state, /var/lib/sluis-state/<boundary>/key: the board's state directory or the
	// local volume, 0700 and key@'s alone. It holds the highest KeyPlan seq verified, so that a restart does not forget it
	// (signed_state.go).
	StateDir string
	Node     string // the name of the node in logs and audit facts: node-1 locally, the board's short name on a board
	Auditor  Auditor
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// RewrapEvery is the period of the rewrap pass; 0 means DefaultRewrapEvery.
	RewrapEvery time.Duration
	// RefusalBurst and RefusalWindow set the rate limit of the audit facts of refusals (refuse.go): per caller and
	// reason, the first RefusalBurst refusals of a RefusalWindow are facts one by one and the rest are one summary. 0 means 10
	// and one minute. The transport's guard uses the same two numbers.
	RefusalBurst  int
	RefusalWindow time.Duration
	// RefusalHourly is the most facts of one caller and reason (of one peer uid and reason at the guard) in an hour; 0 means 60.
	RefusalHourly int
	// RefusalTotal is the most facts of one limiter (each caller's handlers, and each socket's guard) in an hour over all
	// its keys; 0 means 120. What is past it is counted in one shared summary.
	RefusalTotal int
	// Out receives what the check command reports for a person or a script; nil means os.Stdout.
	Out io.Writer
	// PinReleaseScale multiplies the polling periods of the PIN release (pinrelease.go); 0 means 1. Tests run it fast.
	PinReleaseScale float64
	// PinSleep, when set, replaces the wait between the polls of the PIN release: tests move a clock in it and count
	// the waits. It returns true when the wait ended on a signal on wake, and ctx's error when ctx ended.
	PinSleep func(ctx context.Context, d time.Duration, wake <-chan struct{}) (bool, error)
}

// purposeKey is the public half of an authority key that the key store holds for a purpose of the KeyPlan.
type purposeKey struct {
	algorithm string // ES384 or ECDH-P384
	spki      []byte
	keyID     string // RFC 7638 thumbprint
	pub       *ecdsa.PublicKey
}

// Server is key@.
type Server struct {
	// refusals rate limits the audit facts of the refusals of the handlers, a limiter for each caller (refuse.go); Serve closes
	// them, with their pending counts, on the way out and makes new ones.
	refusals atomic.Pointer[refusalLimiters]
	cfg      Config
	now      func() time.Time
	st       storev2alpha1connect.StoreServiceClient
	driver   keystorev2alpha1connect.KeyStoreServiceClient
	wraps    *store.Client[*keyv2alpha1.DataKeyWrap]
	certs    *store.Client[*keyv2alpha1.KeyCertificate]
	// revocations is the create-only kind of revoked targets (revocation.go).
	revocations *store.Client[*keyv2alpha1.KeyRevocation]
	// ring is the token keys of every node, which a declaration may name (declaration.go).
	ring *store.Client[*signerv2alpha1.SigningRing]
	// declarations is the highest key revocation declaration taken (declaration.go).
	declarations declarations
	// adminAllow decides from the peer's uid who may use the admin socket (admin.go): root.
	adminAllow func(uid uint32) bool
	// pinReqs and pinRels are the temp kinds of the PIN release between boards (pinrelease.go).
	pinReqs *store.Client[*keyv2alpha1.PinReleaseRequest]
	pinRels *store.Client[*keyv2alpha1.PinRelease]
	pins    pinState

	// The KeyPlan and the Boundary are verified here and never taken as decoded items from store@ (signed_kind.go).
	publishers []signedconfig.Publisher // the publisher keys of the bootstrap file
	plan       *signedKind[*configv2alpha1.KeyPlan]
	boundary   *signedKind[*configv2alpha1.Boundary]
	saveMark   bool // this process writes the marks (the serving process; the check command only reads them)

	// serverConfig, when set, adjusts the ServerConfig of each socket. Tests use it to name their caller; a
	// normal build has no way to set it, and the name resolver it would set exists only under the sluis_test tag.
	serverConfig func(rpc.ServerConfig) rpc.ServerConfig

	// Set by Init, read-only afterwards.
	environment   string
	defaultTenant string
	keys          map[string]purposeKey // the asymmetric purposes of the KeyPlan
	recipient     string                // this node's label
	wrappingPub   *ecdh.PublicKey
	wrappingID    string // the RFC 7638 thumbprint of this node's wrapping key: its id in the KeyPlan

	reported sync.Map // the recipient problems already audited, so that a pass repeats none

	cache   *cache
	loadMu  sync.Mutex // one data key is loaded or made at a time
	tenants sync.Map   // the tenants whose keys this node has used: the rewrap pass visits them
	limits  *limiters
}

// New dials store@ and the driver and returns a key@ that has not started.
func New(cfg Config) (*Server, error) {
	if cfg.Boundary == "" || cfg.RunDir == "" || cfg.StoreSocket == "" || cfg.DriverSocket == "" || cfg.Node == "" || cfg.Bootstrap == "" || cfg.StateDir == "" {
		return nil, errors.New("keyd: boundary, run-dir, store-socket, driver-socket, bootstrap, state-dir and node are required")
	}
	if cfg.Auditor == nil {
		return nil, errors.New("keyd: no auditor")
	}
	if !validNode(cfg.Node) {
		return nil, errors.New("keyd: node is not a valid label")
	}
	raw, err := os.ReadFile(cfg.Bootstrap)
	if err != nil {
		return nil, errors.New("keyd: the bootstrap file cannot be read")
	}
	pubs, err := signedconfig.ParsePublishers(raw)
	if err != nil {
		return nil, fmt.Errorf("keyd: the bootstrap file: %w", err)
	}
	hc, url := rpc.Dial(cfg.StoreSocket)
	st := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
	dc, durl := rpc.Dial(cfg.DriverSocket)
	driver := keystorev2alpha1connect.NewKeyStoreServiceClient(dc, durl, rpc.ClientOptions()...)
	s, err := newServer(cfg, st, driver)
	if err != nil {
		return nil, err
	}
	s.publishers = pubs
	return s, nil
}

func newServer(cfg Config, st storev2alpha1connect.StoreServiceClient, driver keystorev2alpha1connect.KeyStoreServiceClient) (*Server, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	// DataKeyWrap is tenant-scoped, and the boundary's own purposes have no tenant.
	ws, err := store.New(st, "DataKeyWrap", func() *keyv2alpha1.DataKeyWrap { return &keyv2alpha1.DataKeyWrap{} }, store.OptionalTenant())
	if err != nil {
		return nil, err
	}
	certs, err := store.New(st, "KeyCertificate", func() *keyv2alpha1.KeyCertificate { return &keyv2alpha1.KeyCertificate{} })
	if err != nil {
		return nil, err
	}
	rev, err := store.New(st, "KeyRevocation", func() *keyv2alpha1.KeyRevocation { return &keyv2alpha1.KeyRevocation{} }, store.OptionalTenant())
	if err != nil {
		return nil, err
	}
	reqs, err := store.New(st, kindPinRequest, func() *keyv2alpha1.PinReleaseRequest { return &keyv2alpha1.PinReleaseRequest{} })
	if err != nil {
		return nil, err
	}
	rels, err := store.New(st, kindPinRelease, func() *keyv2alpha1.PinRelease { return &keyv2alpha1.PinRelease{} })
	if err != nil {
		return nil, err
	}
	ring, err := store.New(st, signingRingKind, func() *signerv2alpha1.SigningRing { return &signerv2alpha1.SigningRing{} })
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, now: now, st: st, revocations: rev, ring: ring, driver: driver, wraps: ws, certs: certs, pinReqs: reqs, pinRels: rels,
		adminAllow: rootOnly,
		plan:       &signedKind[*configv2alpha1.KeyPlan]{kind: keyPlanKind, label: "KeyPlan", op: "keyplan", reason: reasonKeyPlan, markFile: planMarkFile, decode: decodeKeyPlan},
		boundary:   &signedKind[*configv2alpha1.Boundary]{kind: boundaryKind, label: "Boundary", op: "boundary", reason: reasonBoundary, markFile: boundaryMarkFile, decode: decodeBoundary},
		limits:     newLimiters(now)}
	srv.refusals.Store(srv.newRefusalLimiters())
	return srv, nil
}

// validNode reports whether node is a lower-case address part of reasonable length (pinrelease.ValidNode).
func validNode(node string) bool {
	return pinrelease.ValidNode(node)
}

// recipientLabel is the recipient part of a wrap's id and of its certificate's id: the lower-case base32, without
// padding, of the thumbprint's 32 bytes (52 characters, which fit the id rules of an address). It depends on the
// listed id alone, so that every node derives the same label for a recipient and the store cannot choose it: a
// certificate is used only under the label of its own key, and a stray certificate for the same key is ignored.
func recipientLabel(id string) string {
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return ""
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// checkRunDir refuses a run directory, or a per-caller directory below it, that is missing or that group or
// world can write to (ADR 0006, "Exclusive card access"). The platform makes them; key@ does not.
func (s *Server) checkRunDir() error {
	dirs := []string{s.cfg.RunDir}
	for _, c := range registry.CallersOf("key") {
		dirs = append(dirs, filepath.Join(s.cfg.RunDir, c))
	}
	for _, d := range dirs {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("run directory %s is missing", d)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("run directory %s is writable by group or world", d)
		}
	}
	return nil
}

// loadConfig reads Boundary and KeyPlan, the config kinds key@ needs (D-17: one item, id "default"), each from the signed
// document that key@ verifies itself. A missing or refused document means no start.
func (s *Server) loadConfig(ctx context.Context) (*configv2alpha1.Boundary, *configv2alpha1.KeyPlan, error) {
	b, err := fetchVerified(ctx, s, s.boundary)
	if err != nil {
		return nil, nil, fmt.Errorf("boundary/default: %w", err)
	}
	plan, err := fetchVerified(ctx, s, s.plan)
	if err != nil {
		return nil, nil, fmt.Errorf("keyplan/default: %w", err)
	}
	return b, plan, nil
}

// checkFloor applies the floors in code to the driver and the environment (ADR 0006, "Floors in code"): the
// software driver refuses to start in production and warns in staging.
func (s *Server) checkFloor(ctx context.Context, environment string) error {
	caps, err := s.driver.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		return fmt.Errorf("key-store driver capabilities: %w", err)
	}
	switch environment {
	case "development", "staging", "production":
	default:
		return errors.New("boundary/default: environment is not development, staging or production")
	}
	if caps.Msg.GetStore() == "software" {
		switch environment {
		case "production":
			return errors.New(errSoftwareInProduction)
		case "staging":
			slog.Warn("software key driver in staging: its keys are not hardware-held")
		}
	}
	return nil
}

// errSoftwareInProduction is the refusal of the floor.
const errSoftwareInProduction = "software key driver refused in production"

// cacheTTL reads the KeyPlan's time to live. Unset (nil or zero) is the default. A value below zero or above the
// built-in maximum is refused, and so is the KeyPlan: "A longer value is refused when the configuration loads"
// (ADR 0006, "The cache"; "Floors in code": a KeyPlan may shorten a limit and never lengthen it past the maximum).
func cacheTTL(plan *configv2alpha1.KeyPlan) (time.Duration, error) {
	if plan.GetCacheTtl() == nil {
		return defaultCacheTTL, nil
	}
	ttl := plan.GetCacheTtl().AsDuration()
	switch {
	case ttl == 0:
		return defaultCacheTTL, nil
	case ttl < 0 || ttl > maxCacheTTL:
		return 0, fmt.Errorf("keyplan/default: cache_ttl is outside 0 to %s", maxCacheTTL)
	}
	return ttl, nil
}
