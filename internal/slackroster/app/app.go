// Package app assembles the Slack controller from its configuration: the
// policy's slack table, the console it reads with its own ServiceAccount
// token, the report it writes, and the credentials and records mounted
// beside it.
//
// A package rather than the body of main, for the reason the service's
// equivalents are: this is where the decisions a deployment can get wrong
// are made, and main() cannot be tested.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/portstore"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/apply"
	"github.com/truvity/access-roster/internal/slackroster/controller"
	"github.com/truvity/access-roster/internal/store"
	"github.com/truvity/access-roster/internal/telemetry"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
)

// Config is what a deployment decides. It is built from the configuration
// file, which is what the chart renders.
type Config struct {
	release string
	// stores says which adapter backs the storage ports.
	stores         store.Config
	policyDir      string
	console        string
	tokenFile      string
	credentialsDir string
	recordsDir     string
	interval       time.Duration
	enabled        map[string]bool
	logLevel       slog.Level
	// audit is the audit installation the controller records to, with its
	// own identity; without one it only logs what it did.
	audit audit.Config
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// Load reads the configuration file, holds it to its schema, and builds the
// settings from it.
func Load(file string) (Config, error) {
	f, err := config.LoadControllerSlack(file)
	if err != nil {
		return Config{}, err
	}
	return FromConfig(f)
}

// FromConfig builds the settings from a configuration already read. What a
// schema cannot say is checked here, before anything starts.
func FromConfig(f *config.ControllerSlack) (Config, error) {
	c := Config{
		release:        orDefault(f.Release, "access-roster"),
		stores:         store.FromRoster(&f.Roster),
		policyDir:      f.PolicyDir,
		console:        strings.TrimSuffix(f.ConsoleURL, "/"),
		tokenFile:      orDefault(f.TokenFile, "/var/run/secrets/slack-roster/token"),
		credentialsDir: orDefault(f.CredentialsDir, "/var/run/slack-roster/credentials"),
		recordsDir:     orDefault(f.RecordsDir, "/var/run/slack-roster/workspaces"),
		enabled:        map[string]bool{},
		// The instance is the pod, which is its hostname in a cluster.
		audit: audit.Config{Version: version.String()},
	}
	c.audit.Instance, _ = os.Hostname()
	if a := f.Audit; a != nil {
		c.audit.Writer = a.Writer
		c.audit.TokenFile = a.TokenFile
	}
	for _, workspace := range f.EnabledWorkspaces {
		if workspace = strings.TrimSpace(workspace); workspace != "" {
			c.enabled[workspace] = true
		}
	}
	c.interval = 15 * time.Minute
	if f.Interval != nil {
		c.interval = f.Interval.D()
	}
	if c.interval <= 0 {
		return Config{}, fmt.Errorf("interval %q is not a positive duration", c.interval)
	}
	level := "info"
	if f.Log != nil && f.Log.Level != "" {
		level = f.Log.Level
	}
	if err := c.logLevel.UnmarshalText([]byte(level)); err != nil {
		return Config{}, fmt.Errorf("log.level: %w", err)
	}
	switch {
	case c.policyDir == "":
		return Config{}, errors.New("policyDir is required: the bindings are the policy's slack table")
	case c.console == "":
		return Config{}, errors.New("consoleURL is required: who holds a group is the console's to answer")
	}
	return c, nil
}

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

// App is an assembled controller.
type App struct {
	controller *controller.Controller
	trail      *audit.Trail
	log        *slog.Logger
	// sharedLease is whether the tick leases are held in a State shared with
	// every other runner.
	sharedLease bool
	// fatal carries the one error that ends the process from outside a
	// pass: the audit installation refusing the catalogue after the start.
	fatal chan error
}

// Tick runs one workspace's tick once, under its lease, and returns: the
// workspace's key. It is what `access-roster tick slack` runs, and the shape
// of a function that lives for one invocation. A workspace another runner
// holds is left to it.
func (a *App) Tick(ctx context.Context, target string, unsafeLocal bool) error {
	if err := store.RequireSharedLease(a.sharedLease, unsafeLocal); err != nil {
		return err
	}
	ran, _, err := a.controller.RunTarget(ctx, target)
	if err == nil && !ran {
		a.log.InfoContext(ctx, "the workspace is leased to another runner: nothing to do", "workspace", target)
	}
	return err
}

// Close closes the audit emitter, which delivers what its queue holds within
// its timeout and drops the rest, saying so. Nothing survives the process.
func (a *App) Close() error { return a.trail.Close() }

// The report store reads back what it wrote, so a restarted controller does
// not record every hold and leaver again.
var _ controller.StatusReader = (*rails.BlobReports)(nil)

// New assembles the controller.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	declared, err := policy.LoadDeclared(cfg.policyDir)
	if err != nil {
		return nil, err
	}
	// Validated with the service's own loader: a controller acting on a
	// policy the service would refuse is acting on a different model.
	set, err := policy.NewSet(declared)
	if err != nil {
		return nil, fmt.Errorf("the policy: %w", err)
	}
	if len(declared.Slack.Workspaces) == 0 {
		log.WarnContext(ctx, "the policy declares no Slack workspace: every pass will do nothing")
	}
	for workspace := range cfg.enabled {
		if _, bound := declared.Slack.Workspaces[workspace]; !bound {
			return nil, fmt.Errorf("enabledWorkspaces names %s, which the policy does not declare", workspace)
		}
	}

	stores, err := store.Open(ctx, cfg.stores, log)
	if err != nil {
		return nil, err
	}
	// Any adapter but `legacy` keeps the console's records and the workspaces'
	// credentials on the State port (sealed), and the controller reads them
	// there, not from mounted files; the hand-off of a Slack Connect share and
	// the cache of who a member is live there too.
	var (
		records controller.RecordSource
		handoff controller.Handoff
		members apply.MemberCache
	)
	if stores.Adapter != store.AdapterLegacy {
		base := portstore.New(stores.Ports)
		if err = base.CheckSealer(ctx); err != nil {
			stores.Close()
			return nil, fmt.Errorf("ports.adapter %s: %w", stores.Adapter, err)
		}
		records = portstore.NewSlackSource(base)
		handoff = portstore.NewHandoff(base, stores.Ports.Trigger)
		members = portstore.NewUserCache(base)
	}

	// Every call to the console carries this pod's own projected token,
	// read fresh each time: the kubelet rotates it under the pod.
	bearer := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			token, err := os.ReadFile(cfg.tokenFile)
			if err != nil {
				return nil, fmt.Errorf("read this pod's ServiceAccount token: %w", err)
			}
			req.Header().Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
			return next(ctx, req)
		}
	}))
	// And one client span per call, with the traceparent carried to the
	// console, so a tick's trace continues into the console's own spans.
	console := append([]connect.ClientOption{bearer}, telemetry.ConnectClientOptions()...)
	web := &http.Client{Timeout: 30 * time.Second}

	log.InfoContext(ctx, "the Slack controller is assembled",
		"workspaces", len(declared.Slack.Workspaces), "enabled", slices.Sorted(maps.Keys(cfg.enabled)),
		"interval", cfg.interval, "console", cfg.console, "policy", set.Digest())
	// A refusal found after the start is fatal the way one at the start is:
	// the process ends rather than running with records nobody accepts.
	fatal := make(chan error, 1)
	cfg.audit.Log = log
	cfg.audit.OnFatal = func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	trail, err := audit.Open(ctx, cfg.audit)
	if err != nil {
		return nil, err
	}
	leaseState, shared := stores.LeaseState()
	if !shared {
		log.InfoContext(ctx, "no shared state backs the tick leases, so they are held in this process: run one replica",
			"adapter", stores.Adapter)
	}
	return &App{
		log:         log,
		sharedLease: shared,
		trail:       trail,
		fatal:       fatal,
		controller: controller.New(controller.Config{
			Interval: cfg.interval, Enabled: cfg.enabled, CredentialsDir: cfg.credentialsDir, RecordsDir: cfg.recordsDir,
		}, controller.Deps{
			Log:     log,
			Access:  directoryrosterv1connect.NewAccessServiceClient(web, cfg.console, console...),
			Audit:   trail,
			Status:  rails.NewBlobReports(stores.Ports.Blob, "reports/slack/"),
			Leases:  &rails.Leases{State: leaseState, Holder: rails.NewHolder(), Log: log},
			Trigger: stores.Ports.Trigger,
			Policy:  declared,
			Digest:  set.Digest(),
			Records: records,
			Handoff: handoff,
			Members: members,
		}),
	}, nil
}

// Run passes until the context is done, or the audit installation refuses
// the catalogue after the start, which ends the process the way a refusal
// at the start would have.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.controller.Run(ctx) }()
	select {
	case err := <-a.fatal:
		cancel()
		<-done
		return fmt.Errorf("audit: %w", err)
	case err := <-done:
		return err
	}
}
