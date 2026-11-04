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
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Built-in limits that a KeyPlan may shorten and never lengthen (ADR 0006, "Floors in code").
const (
	defaultCacheTTL = 15 * time.Minute
	maxCacheTTL     = time.Hour
	// DefaultRewrapEvery is the period of the rewrap pass (ADR 0006, "Keys per board").
	DefaultRewrapEvery = 60 * time.Second
	// recipientHashChars is the length of the hash part of a recipient label.
	recipientHashChars = 16
)

// Config is the configuration of one key@.
type Config struct {
	Boundary     string
	RunDir       string // /run/sluis/key/<boundary>: one directory per caller below it
	StoreSocket  string // /run/sluis/store/<boundary>.sock
	DriverSocket string // /run/sluis/key/<boundary>/driver/key-store.sock
	Node         string // the recipient label base: node-1 locally, the board's short name on a board
	Auditor      Auditor
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// RewrapEvery is the period of the rewrap pass; 0 means DefaultRewrapEvery.
	RewrapEvery time.Duration
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
	cfg     Config
	now     func() time.Time
	st      storev2alpha1connect.StoreServiceClient
	driver  keystorev2alpha1connect.KeyStoreServiceClient
	wraps   wrapStore
	certs   *store.Client[*keyv2alpha1.KeyCertificate]
	boundCl *store.Client[*configv2alpha1.Boundary]
	planCl  *store.Client[*configv2alpha1.KeyPlan]

	// serverConfig, when set, adjusts the ServerConfig of each socket. Tests use it to name their caller; a
	// normal build has no way to set it, and the name resolver it would set exists only under the sluis_test tag.
	serverConfig func(rpc.ServerConfig) rpc.ServerConfig

	// Set by Init, read-only afterwards.
	environment   string
	defaultTenant string
	keys          map[string]purposeKey // the asymmetric purposes of the KeyPlan
	recipient     string                // this node's label
	wrappingPub   *ecdh.PublicKey

	cache   *cache
	loadMu  sync.Mutex // one data key is loaded or made at a time
	tenants sync.Map   // the tenants whose keys this node has used: the rewrap pass visits them
	limits  *limiters
}

// New dials store@ and the driver and returns a key@ that has not started.
func New(cfg Config) (*Server, error) {
	if cfg.Boundary == "" || cfg.RunDir == "" || cfg.StoreSocket == "" || cfg.DriverSocket == "" || cfg.Node == "" {
		return nil, errors.New("keyd: boundary, run-dir, store-socket, driver-socket and node are required")
	}
	if cfg.Auditor == nil {
		return nil, errors.New("keyd: no auditor")
	}
	if !validNode(cfg.Node) {
		return nil, errors.New("keyd: node is not a valid label")
	}
	hc, url := rpc.Dial(cfg.StoreSocket)
	st := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
	dc, durl := rpc.Dial(cfg.DriverSocket)
	driver := keystorev2alpha1connect.NewKeyStoreServiceClient(dc, durl, rpc.ClientOptions()...)
	return newServer(cfg, st, driver)
}

func newServer(cfg Config, st storev2alpha1connect.StoreServiceClient, driver keystorev2alpha1connect.KeyStoreServiceClient) (*Server, error) {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ws, err := newWrapStore(st)
	if err != nil {
		return nil, err
	}
	certs, err := store.New(st, "KeyCertificate", func() *keyv2alpha1.KeyCertificate { return &keyv2alpha1.KeyCertificate{} })
	if err != nil {
		return nil, err
	}
	bnd, err := store.New(st, "Boundary", func() *configv2alpha1.Boundary { return &configv2alpha1.Boundary{} })
	if err != nil {
		return nil, err
	}
	plan, err := store.New(st, "KeyPlan", func() *configv2alpha1.KeyPlan { return &configv2alpha1.KeyPlan{} })
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, now: now, st: st, driver: driver, wraps: ws, certs: certs, boundCl: bnd, planCl: plan,
		limits: newLimiters(now)}, nil
}

// validNode reports whether node can be the base of a recipient label: a lower-case address part that leaves
// room for the hash.
func validNode(node string) bool {
	return len(node) <= 128-1-recipientHashChars && store.ValidateID(node) == nil && !strings.Contains(node, "/")
}

// recipientLabel is <node>- plus the first 16 characters of the lower-case base32 of SHA-256(SPKI DER). It fits
// the id rules of an address.
func recipientLabel(node string, spki []byte) string {
	sum := sha256.Sum256(spki)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return node + "-" + strings.ToLower(enc[:recipientHashChars])
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

// loadConfig reads Boundary and KeyPlan, the config kinds key@ needs (D-17: one item, id "default"). A missing
// document means no start.
func (s *Server) loadConfig(ctx context.Context) (*configv2alpha1.Boundary, *configv2alpha1.KeyPlan, error) {
	b, err := s.boundCl.Get(ctx, "", "default")
	if err != nil {
		return nil, nil, fmt.Errorf("boundary/default: %w", err)
	}
	p, err := s.planCl.Get(ctx, "", "default")
	if err != nil {
		return nil, nil, fmt.Errorf("keyplan/default: %w", err)
	}
	return b.Value, p.Value, nil
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

// cacheTTL applies the built-in maximum to the KeyPlan's time to live.
func cacheTTL(plan *configv2alpha1.KeyPlan) time.Duration {
	ttl := plan.GetCacheTtl().AsDuration()
	switch {
	case plan.GetCacheTtl() == nil || ttl <= 0:
		return defaultCacheTTL
	case ttl > maxCacheTTL:
		slog.Warn("KeyPlan cache_ttl is above the built-in maximum and is clamped", "max", maxCacheTTL.String())
		return maxCacheTTL
	}
	return ttl
}
