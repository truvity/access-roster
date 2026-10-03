// Package store builds the storage ports once, from configuration, for the
// apps to be handed: the one place that knows which adapter backs them.
//
// Everything else names the interfaces of internal/port. The adapter is
// chosen by the `ports.adapter` key of the configuration file: `legacy`
// (the default, today's ConfigMaps, Secrets and Valkey, unchanged), `memory`,
// `nats` or `dynamodb`.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	dynamoport "github.com/truvity/access-roster/internal/port/dynamodb"
	"github.com/truvity/access-roster/internal/port/kmsseal"
	"github.com/truvity/access-roster/internal/port/legacy"
	"github.com/truvity/access-roster/internal/port/memory"
	natsport "github.com/truvity/access-roster/internal/port/nats"
	"github.com/truvity/access-roster/internal/port/observe"
	"github.com/truvity/access-roster/internal/port/s3blob"
	"github.com/truvity/access-roster/internal/valkey"
)

// The adapters `ports.adapter` names.
const (
	AdapterLegacy = "legacy"
	AdapterMemory = "memory"
	AdapterNATS   = "nats"
	// AdapterDynamoDB keeps State, the session index and the trigger in one
	// DynamoDB table.
	AdapterDynamoDB = "dynamodb"
)

// The adapters `ports.blob.adapter` and `ports.sealer.adapter` name. Each
// replaces one port and composes with any `ports.adapter`.
const (
	BlobS3    = "s3"
	SealerKMS = "kms"
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
	// Blob and Sealer replace the port of the same name; nil keeps what
	// Adapter brings.
	Blob   *config.PortsBlob
	Sealer *config.PortsSealer
	// NATS is the bucket of the `nats` adapter.
	NATS natsport.Config
	// DynamoDB is the table of the `dynamodb` adapter.
	DynamoDB dynamoport.Config
}

// validatePorts refuses a Blob or Sealer the file names but this build has no
// adapter for, or names without its settings. The schema says the same; this is
// the check for a Config that was not read from a file.
func (c Config) validatePorts() error {
	if b := c.Blob; b != nil {
		if b.Adapter != BlobS3 {
			return fmt.Errorf("ports.blob.adapter: %q is not %q", b.Adapter, BlobS3)
		}
		if b.S3 == nil || b.S3.Bucket == "" {
			return errors.New("ports.blob.s3.bucket: required with ports.blob.adapter: s3")
		}
	}
	if s := c.Sealer; s != nil {
		if s.Adapter != SealerKMS {
			return fmt.Errorf("ports.sealer.adapter: %q is not %q", s.Adapter, SealerKMS)
		}
		if s.KMS == nil || s.KMS.KeyID == "" {
			return errors.New("ports.sealer.kms.keyId: required with ports.sealer.adapter: kms")
		}
	}
	return nil
}

// compose replaces the Blob and the Sealer the base adapter brought with the
// ones configured. It runs before the set is observed, so the replacements are
// timed and counted like every other port.
func (c Config) compose(ctx context.Context, set port.Set, log *slog.Logger) (port.Set, error) {
	if err := c.validatePorts(); err != nil {
		return port.Set{}, err
	}
	if b := c.Blob; b != nil {
		blob, err := s3blob.New(ctx, s3blob.Config{
			Bucket: b.S3.Bucket, Prefix: b.S3.Prefix, Region: b.S3.Region, KMSKey: b.S3.KMSKey,
			Endpoint: b.S3.Endpoint, PathStyle: b.S3.PathStyle,
		})
		if err != nil {
			return port.Set{}, fmt.Errorf("ports.blob: %w", err)
		}
		set.Blob = blob
		log.InfoContext(ctx, "blobs are kept in S3", "adapter", BlobS3, "bucket", b.S3.Bucket, "prefix", b.S3.Prefix)
	}
	if s := c.Sealer; s != nil {
		sealer, err := kmsseal.New(ctx, kmsseal.Config{KeyID: s.KMS.KeyID, Region: s.KMS.Region, Endpoint: s.KMS.Endpoint})
		if err != nil {
			return port.Set{}, fmt.Errorf("ports.sealer: %w", err)
		}
		set.Sealer = sealer
		log.InfoContext(ctx, "secrets are sealed by KMS", "adapter", SealerKMS)
	}
	return set, nil
}

// FromServe reads the configuration of `access-roster serve`.
func FromServe(f *config.Serve) (Config, error) {
	c := Config{
		Adapter: adapterOf(f.Ports),
		Release: orDefault(f.Release, "access-roster"),
		Valkey:  valkeyOf(f.Release, f.Valkey),
		Blob:    blobOf(f.Ports),
		Sealer:  sealerOf(f.Ports),
		NATS:    natsOf(f.Ports),

		DynamoDB: dynamoOf(f.Ports),
	}
	var err error
	if (c.Adapter == AdapterNATS || c.Adapter == AdapterDynamoDB) && f.Valkey != nil && f.Valkey.Address != "" {
		return Config{}, fmt.Errorf("ports.adapter: %s holds the shared state, so it cannot be combined with valkey.address", c.Adapter)
	}
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
	c := Config{
		Adapter: adapterOf(f.Ports), Release: orDefault(f.Release, "access-roster"), Kube: KubeRequired,
		Blob: blobOf(f.Ports), Sealer: sealerOf(f.Ports), NATS: natsOf(f.Ports), DynamoDB: dynamoOf(f.Ports),
	}
	if c.Adapter == AdapterMemory {
		c.Kube = KubeNone
	}
	return c
}

// natsOf reads the bucket's settings; natsport.Open refuses an incomplete or
// contradictory set, naming it, when the adapter is the chosen one.
func natsOf(p *config.Ports) natsport.Config {
	if p == nil || p.NATS == nil {
		return natsport.Config{}
	}
	n := p.NATS
	return natsport.Config{
		URL: n.URL, Bucket: n.Bucket, Replicas: n.Replicas,
		TokenFile: n.TokenFile, CredsFile: n.CredsFile, CAFile: n.CAFile,
		NoCreate: n.Create != nil && !*n.Create,
	}
}

// dynamoOf reads the table's settings; dynamoport.Open refuses an incomplete
// set, naming it, when the adapter is the chosen one.
func dynamoOf(p *config.Ports) dynamoport.Config {
	if p == nil || p.DynamoDB == nil {
		return dynamoport.Config{}
	}
	d := p.DynamoDB
	return dynamoport.Config{Table: d.Table, Region: d.Region, Endpoint: d.Endpoint, Create: d.Create}
}

func adapterOf(p *config.Ports) string {
	if p == nil || p.Adapter == "" {
		return AdapterLegacy
	}
	return p.Adapter
}

func blobOf(p *config.Ports) *config.PortsBlob {
	if p == nil {
		return nil
	}
	return p.Blob
}

func sealerOf(p *config.Ports) *config.PortsSealer {
	if p == nil {
		return nil
	}
	return p.Sealer
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
	// Backend is today's storage as it was opened: what the `legacy` adapter
	// is made of, and, with any adapter, the cluster's own objects that stay the
	// cluster's (the token review, the declared OAuth client). The domain stores
	// (a connected workspace and its credential, an organisation, a person's
	// link, the Slack records) are on Ports for every adapter but `legacy`
	// (internal/portstore), and in the ConfigMaps and Secrets this reaches for
	// `legacy`. It is nil with the memory adapter, which has none.
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
	case s.Adapter == AdapterNATS:
		return "nats"
	case s.Adapter == AdapterDynamoDB:
		return "dynamodb"
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
		set, err := cfg.compose(ctx, memory.New().Set(), log)
		if err != nil {
			return nil, err
		}
		return &Stores{Ports: observe.Set(set), Adapter: AdapterMemory, Usable: true}, nil
	case AdapterLegacy:
		return openLegacy(ctx, cfg, log)
	case AdapterNATS:
		return openNATS(ctx, cfg, log)
	case AdapterDynamoDB:
		return openDynamoDB(ctx, cfg, log)
	}
	return nil, fmt.Errorf("ports.adapter: %q is none of %q, %q, %q, %q", cfg.Adapter, AdapterLegacy, AdapterMemory, AdapterNATS, AdapterDynamoDB)
}

// openNATS holds State, the session index and the trigger in the bucket.
// Blob, Sealer and Identity are the legacy adapter's over the namespace's
// objects (so reports and snapshots are what they are today, and a sealed
// value is refused, not sealed under a key no restart could open), unless
// `ports.blob` and `ports.sealer` name adapters of their own.
func openNATS(ctx context.Context, cfg Config, log *slog.Logger) (*Stores, error) {
	backend := &legacy.Backend{}
	st := &Stores{Backend: backend, Adapter: AdapterNATS, Shared: true, Usable: true}
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
	bucket, err := natsport.Open(ctx, cfg.NATS)
	if err != nil {
		return nil, fmt.Errorf("ports.nats: %w", err)
	}
	st.pinger = bucket
	st.close = bucket.Close
	rest := backend.Ports(legacy.Options{})
	set := bucket.Set()
	set.Blob, set.Sealer, set.Identity = rest.Blob, rest.Sealer, rest.Identity
	if set, err = cfg.compose(ctx, set, log); err != nil {
		st.Close()
		return nil, err
	}
	st.Ports = observe.Set(set)
	log.InfoContext(ctx, "keeping state in NATS JetStream", "adapter", AdapterNATS,
		"bucket", cfg.NATS.Bucket, "serverTTL", bucket.ServerTTL())
	return st, nil
}

// openDynamoDB holds State, the session index and the trigger in the table,
// and takes Blob, Sealer and Identity from the legacy adapter exactly as the
// NATS adapter does.
func openDynamoDB(ctx context.Context, cfg Config, log *slog.Logger) (*Stores, error) {
	backend := &legacy.Backend{}
	st := &Stores{Backend: backend, Adapter: AdapterDynamoDB, Shared: true, Usable: true}
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
	table, err := dynamoport.Open(ctx, cfg.DynamoDB)
	if err != nil {
		return nil, fmt.Errorf("ports.dynamodb: %w", err)
	}
	st.pinger = table
	st.close = table.Close
	rest := backend.Ports(legacy.Options{})
	set := table.Set()
	set.Blob, set.Sealer, set.Identity = rest.Blob, rest.Sealer, rest.Identity
	if set, err = cfg.compose(ctx, set, log); err != nil {
		st.Close()
		return nil, err
	}
	st.Ports = observe.Set(set)
	log.InfoContext(ctx, "keeping state in DynamoDB", "adapter", AdapterDynamoDB,
		"table", cfg.DynamoDB.Table, "region", cfg.DynamoDB.Region, "create", cfg.DynamoDB.Create)
	return st, nil
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
	set, err := cfg.compose(ctx, backend.Ports(legacy.Options{}), log)
	if err != nil {
		st.Close()
		return nil, err
	}
	st.Ports = observe.Set(set)
	return st, nil
}
