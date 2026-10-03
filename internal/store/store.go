// Package store builds the storage ports once, from configuration, for the
// apps to be handed: the one place that knows which adapter backs them.
//
// Everything else names the interfaces of internal/port. The adapter is
// chosen by the `ports.adapter` key of the configuration file: `legacy`
// (the default, today's ConfigMaps, Secrets and Valkey, unchanged) or
// `memory`.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/legacy"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/port/observe"
	"github.com/truvity/access-roster/internal/valkey"
)

// The adapters `ports.adapter` names.
const (
	AdapterLegacy = "legacy"
	AdapterMemory = "memory"
)

// KubeNeed says how much a process needs the namespace's objects.
type KubeNeed int

// How much a process needs the cluster.
const (
	// KubeNone opens nothing: a hub with `store: memory`.
	KubeNone KubeNeed = iota
	// KubeOptional tries, and goes on without when this is not a cluster: an
	// issuer proving recovery against one it may not be running in.
	KubeOptional
	// KubeRequired stops the start when this is not a cluster.
	KubeRequired
)

// Config is what Open needs.
type Config struct {
	Adapter string
	// Release prefixes the objects' names and the Valkey keys.
	Release string
	// Valkey is where the shared cache is; an empty address is none.
	Valkey valkey.Config
	Kube   KubeNeed
}

// FromServe reads the configuration of `access-roster serve`.
func FromServe(f *config.Serve) (Config, error) {
	c := Config{
		Adapter: adapterOf(f.Ports),
		Release: orDefault(f.Release, "access-roster"),
		Valkey:  valkeyOf(f.Release, f.Valkey),
	}
	var err error
	if c.Valkey.Password, err = secretOf(f.Valkey); err != nil {
		return Config{}, err
	}
	switch {
	case f.Store == "kubernetes":
		c.Kube = KubeRequired
	case f.InCluster && f.Recovery != nil && f.Recovery.Enabled != nil && *f.Recovery.Enabled:
		c.Kube = KubeOptional
	}
	if c.Adapter == AdapterMemory {
		switch {
		case f.Store == "kubernetes":
			return Config{}, errors.New("ports.adapter: memory keeps nothing, so it cannot back store: kubernetes")
		case f.Valkey != nil && f.Valkey.Address != "":
			return Config{}, errors.New("ports.adapter: memory keeps nothing, so it cannot be combined with valkey.address")
		}
		c.Kube = KubeNone
	}
	return c, nil
}

// FromRoster reads what the two controllers share. A controller's reports
// and links are objects in its namespace, so it requires the cluster.
func FromRoster(f *config.Roster) Config {
	c := Config{Adapter: adapterOf(f.Ports), Release: orDefault(f.Release, "access-roster"), Kube: KubeRequired}
	if c.Adapter == AdapterMemory {
		c.Kube = KubeNone
	}
	return c
}

func adapterOf(p *config.Ports) string {
	if p == nil || p.Adapter == "" {
		return AdapterLegacy
	}
	return p.Adapter
}

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func valkeyOf(release string, v *config.Valkey) valkey.Config {
	c := valkey.Config{Cluster: true, Prefix: orDefault(release, "access-roster")}
	if v != nil {
		c.Address = v.Address
		c.TLS = v.TLS
		if v.Cluster != nil {
			c.Cluster = *v.Cluster
		}
	}
	return c
}

func secretOf(v *config.Valkey) (string, error) {
	if v == nil || v.PasswordEnv == "" {
		return "", nil
	}
	password, err := config.Secret(v.PasswordEnv)
	if err != nil {
		return "", fmt.Errorf("valkey.passwordEnv: %w", err)
	}
	return password, nil
}

// Stores is the ports, built once.
type Stores struct {
	// Ports is every port, over the chosen adapter.
	Ports port.Set
	// Backend is today's storage as it was opened, for the domain stores that
	// have not moved onto the ports yet (the ConfigMaps and Secrets of a
	// connected workspace, an organisation's credential, a person's link).
	// It is nil with the memory adapter, which has none.
	Backend *legacy.Backend
	// Adapter is the adapter's name.
	Adapter string
	// Shared is true when the state is one every replica sees: a Valkey.
	Shared bool
	// Usable is whether the State, Index and snapshot Blob ports work at all:
	// the memory adapter, and the legacy one with a Valkey. Without them a
	// caller keeps its own process-local store, as it always has.
	Usable bool

	pinger any
	close  func()
}

// Name says where state lives, for a log line and the console's page.
func (s *Stores) Name() string {
	switch {
	case s.Shared:
		return "valkey"
	default:
		return "memory"
	}
}

// LeaseState is the State the controllers take their tick leases from, and
// whether it is shared by every replica. A lease is only exclusive across
// processes when the State is: the legacy adapter keeps leases in Valkey, so
// without one a controller holds its leases in its own memory and a second
// replica would not be kept off (docs/design/ports.md, "The legacy adapter").
func (s *Stores) LeaseState() (state port.State, shared bool) {
	if s.Shared {
		return s.Ports.State, true
	}
	if s.Adapter == AdapterMemory {
		return s.Ports.State, false
	}
	return memory.New().Set().State, false
}

// ErrLocalLease is the refusal of a one-shot tick whose lease would not exclude
// the running controller.
var ErrLocalLease = errors.New("the tick leases are held in this process only, so a running controller " +
	"would not be kept off the same target and both could act on it (duplicate invites or removals): " +
	"this is safe once a shared State exists (docs/decisions/0029, B3). Scale the controller to 0 and " +
	"pass --unsafe-local-lease to run the tick anyway")

// RequireSharedLease refuses a one-shot tick when its lease State is not
// shared with the controller's, unless the operator opted in.
func RequireSharedLease(shared, unsafeLocal bool) error {
	if shared || unsafeLocal {
		return nil
	}
	return ErrLocalLease
}

// Readiness is what readiness should ask: the Valkey, or nothing.
func (s *Stores) Readiness() any { return s.pinger }

// Close releases what Open opened.
func (s *Stores) Close() {
	if s != nil && s.close != nil {
		s.close()
	}
}

// Open builds the ports for the adapter the configuration names.
func Open(ctx context.Context, cfg Config, log *slog.Logger) (*Stores, error) {
	switch cfg.Adapter {
	case AdapterMemory:
		log.WarnContext(ctx, "the storage ports are in memory: a restart loses every login in progress, "+
			"snapshot and report", "adapter", AdapterMemory)
		return &Stores{Ports: observe.Set(memory.New().Set()), Adapter: AdapterMemory, Usable: true}, nil
	case AdapterLegacy:
		return openLegacy(ctx, cfg, log)
	}
	return nil, fmt.Errorf("ports.adapter: %q is neither %q nor %q", cfg.Adapter, AdapterLegacy, AdapterMemory)
}

func openLegacy(ctx context.Context, cfg Config, log *slog.Logger) (*Stores, error) {
	backend := &legacy.Backend{}
	st := &Stores{Backend: backend, Adapter: AdapterLegacy}

	if cfg.Kube != KubeNone {
		client, err := kube.InCluster(cfg.Release)
		switch {
		case err == nil:
			backend.Kube = client
			backend.ReviewToken = client.ReviewToken
		case cfg.Kube == KubeRequired:
			return nil, err
		default:
			log.WarnContext(ctx, "the namespace's objects are not available", "error", err)
		}
	}

	if cfg.Valkey.Address != "" {
		shared, err := valkey.OpenState(ctx, cfg.Valkey)
		if err != nil {
			return nil, err
		}
		backend.Valkey = shared
		st.Shared, st.Usable, st.pinger = true, true, shared
		st.close = func() { _ = shared.Close() }
		log.InfoContext(ctx, "sharing state in Valkey",
			"cache", "valkey", "address", cfg.Valkey.Address, "cluster", cfg.Valkey.Cluster)
	}
	// Observed once, here, where the adapter is chosen: every caller crosses
	// the same seam, so every call is timed and counted without each of them
	// knowing.
	st.Ports = observe.Set(backend.Ports(legacy.Options{}))
	return st, nil
}
