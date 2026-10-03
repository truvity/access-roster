// Package app assembles the GitHub controller from its configuration: the
// policy's GitHub table, the console it reads with its own ServiceAccount
// token, the report it writes, and the credentials mounted beside it.
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
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/controller"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/store"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
)

// Config is what a deployment decides. It is built from the configuration
// file, which is what the chart renders.
type Config struct {
	release string
	// stores says which adapter backs the storage ports.
	stores     store.Config
	policyDir  string
	console    string
	tokenFile  string
	appsDir    string
	recordsDir string
	interval   time.Duration
	enabled    map[string]bool
	logLevel   slog.Level
	// audit is the audit installation the controller records to, with its
	// own identity; without one it only logs what it did.
	audit audit.Config
	// catalogueFile is the GitHub App catalogue's grants, read ONLY so
	// this controller can tell its own "internal groups are declared but
	// nothing consumes them" warning about a group a grant names: this
	// process reconciles GitHub team membership from the policy's GitHub
	// table and mints no installation tokens itself, so the catalogue is
	// otherwise none of its business. Empty is an empty catalogue (see
	// [catalogue.Load]), which is also what a deployment that has not
	// wired this file to this controller yet gets: the warning then
	// names every GitHub-derived group a grant elsewhere actually
	// consumes, exactly as it did before this field existed.
	catalogueFile string
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// Load reads the configuration file, holds it to its schema, and builds the
// settings from it.
func Load(file string) (Config, error) {
	f, err := config.LoadControllerGitHub(file)
	if err != nil {
		return Config{}, err
	}
	return FromConfig(f)
}

// FromConfig builds the settings from a configuration already read. What a
// schema cannot say is checked here, before anything starts.
func FromConfig(f *config.ControllerGitHub) (Config, error) {
	c := Config{
		release:    orDefault(f.Release, "access-roster"),
		stores:     store.FromRoster(&f.Roster),
		policyDir:  f.PolicyDir,
		console:    strings.TrimSuffix(f.ConsoleURL, "/"),
		tokenFile:  orDefault(f.TokenFile, "/var/run/secrets/github-roster/token"),
		appsDir:    orDefault(f.AppsDir, "/var/run/github-roster/apps"),
		recordsDir: orDefault(f.RecordsDir, "/var/run/github-roster/records"),
		enabled:    map[string]bool{},
		// The instance is the pod, which is its hostname in a cluster.
		audit: audit.Config{Version: version.String()},
		// Named exactly as the merged deployment's own is (internal/app),
		// so the two never disagree about where the same catalogue file
		// is mounted from.
		catalogueFile: f.CatalogueFile,
	}
	c.audit.Instance, _ = os.Hostname()
	if a := f.Audit; a != nil {
		c.audit.Writer = a.Writer
		c.audit.TokenFile = a.TokenFile
	}
	for _, org := range f.EnabledOrgs {
		if org = strings.TrimSpace(org); org != "" {
			c.enabled[org] = true
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
		return Config{}, errors.New("policyDir is required: the bindings are the policy's github table")
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
	// fatal carries the one error that ends the process from outside a
	// pass: the audit installation refusing the catalogue after the start.
	fatal chan error
}

// Close closes the audit emitter, which delivers what its queue holds within
// its timeout and drops the rest, saying so. Nothing survives the process.
func (a *App) Close() error { return a.trail.Close() }

// The report store reads back what it wrote, so a restarted controller does
// not record every held and reported row again.
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
	// A malformed catalogue does NOT stop this controller: unlike the
	// service that mints installation tokens from it, this one only
	// reads the catalogue's grants to keep the warning below honest, and
	// a bad file there is not a reason to stop reconciling GitHub team
	// membership. An empty path is an empty catalogue either way (see
	// [catalogue.Load]), so a deployment that has not wired this file to
	// this controller gets exactly the warning it always got.
	apps, catalogueErr := catalogue.Load(cfg.catalogueFile)
	if catalogueErr != nil {
		log.WarnContext(ctx, "the GitHub App catalogue could not be read: "+
			"internal groups it grants may be reported as unconsumed",
			"file", cfg.catalogueFile, "error", catalogueErr)
		apps = &catalogue.Catalogue{}
	}
	if unconsumed := declared.Unconsumed(apps.GrantGroups()...); len(unconsumed) > 0 {
		log.WarnContext(ctx, "internal groups are declared but nothing consumes them",
			"groups", unconsumed)
	}
	if len(declared.GitHub) == 0 {
		log.WarnContext(ctx, "the policy binds no GitHub organisation: every pass will do nothing")
	}
	for org := range cfg.enabled {
		if _, bound := declared.GitHub[org]; !bound {
			return nil, fmt.Errorf("enabledOrgs names %s, which the policy does not bind", org)
		}
	}

	stores, err := store.Open(ctx, cfg.stores, log)
	if err != nil {
		return nil, err
	}
	// A person's link is still a Secret entry the domain store keeps; the
	// memory adapter has none, and the controller checks no link then.
	var links controller.LinkStore
	if stores.Backend != nil && stores.Backend.Kube != nil {
		links = kube.NewGitHubLinks(stores.Backend.Kube)
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
	web := &http.Client{Timeout: 30 * time.Second}

	log.InfoContext(ctx, "the GitHub controller is assembled",
		"organisations", len(declared.GitHub), "enabled", keys(cfg.enabled), "interval", cfg.interval, "console", cfg.console,
		"policy", set.Digest())
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
	return &App{
		log:   log,
		trail: trail,
		fatal: fatal,
		controller: controller.New(controller.Config{Interval: cfg.interval, Enabled: cfg.enabled, AppsDir: cfg.appsDir, RecordsDir: cfg.recordsDir}, controller.Deps{
			Log:      log,
			GitHub:   web,
			Access:   directoryrosterv1connect.NewAccessServiceClient(web, cfg.console, bearer),
			Audit:    trail,
			Console:  directoryrosterv1connect.NewGitHubServiceClient(web, cfg.console, bearer),
			Policy:   set.Digest(),
			Status:   rails.NewBlobReports(stores.Ports.Blob, "reports/github/"),
			Links:    links,
			Bindings: declared.GitHub,
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

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
