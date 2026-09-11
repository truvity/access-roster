// Package rosterapp assembles the whole of access-roster as ONE process:
// the directory connectors, the snapshot and its refresher, the policy,
// the OpenID provider, the login page and the console.
//
// It exists because the split into two services stopped earning its keep
// (INF-691). The hub was built as a directory of record that several
// things could ask; the issuer became its only consumer, and the split
// then cost — on every single login — a ConnectRPC call, a TokenReview,
// a NetworkPolicy hop, a second store, and a class of failure where the
// two halves disagree about the same person.
//
// What this package does is wiring, and deliberately nothing else. The
// two halves are still assembled by their own packages, with their own
// decisions and their own tests; this joins them: the issuer's directory
// is a function call, the console is mounted on the issuer's origin, one
// /readyz answers for both stores, and one process runs the loops.
package rosterapp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/truvity/access-roster/internal/app"
	"github.com/truvity/access-roster/internal/health"
	"github.com/truvity/access-roster/internal/hublocal"
	"github.com/truvity/access-roster/internal/issuerapp"
)

// Config is both halves' configuration. Each is read from the
// environment by its own package, so the chart remains the one place
// that decides anything, and neither half grows a second way to be
// configured.
type Config struct {
	Directory app.Config
	Issuer    issuerapp.Config
}

// LogLevel is the level the process should log at. It is the issuer's,
// because both read the same LOG_LEVEL and the issuer is the half that
// owns the origin.
func (c Config) LogLevel() slog.Level { return c.Issuer.LogLevel() }

// Load reads the configuration from the environment.
func Load() (Config, error) {
	directory, err := app.Load()
	if err != nil {
		return Config{}, err
	}
	issuer, err := issuerapp.Load()
	if err != nil {
		return Config{}, err
	}
	return Config{Directory: directory, Issuer: issuer}, nil
}

// App is the assembled service.
type App struct {
	directory *app.App
	issuer    *issuerapp.App
	log       *slog.Logger
}

// Handler is everything served on the public port: the OpenID surface
// and the login page at the origin root, the console under /console/.
func (a *App) Handler() http.Handler { return a.issuer.Handler() }

// HealthHandler is liveness and readiness for both halves.
func (a *App) HealthHandler() http.Handler { return a.issuer.HealthHandler() }

// Close releases what New opened.
func (a *App) Close() {
	if a.directory != nil {
		a.directory.Close()
	}
}

// New assembles the service. The directory half is built first: the
// issuer is given a door to it rather than an address for it, so there
// is no issuer to build until the directory exists.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}
	directory, err := app.New(ctx, cfg.Directory, log)
	if err != nil {
		return nil, err
	}
	// Freshness stays the hub's own decision, which is why no maximum age
	// is passed: a login that forced a live read on every sign-in would
	// turn one corporate directory's slowness into everybody's.
	deps := issuerapp.Deps{
		Directory: hublocal.New(directory.Hub(), 0),
		Console:   directory.ConsoleHandler(),
		Ready:     []health.Dependency{directory.Readiness()},
		// The SAME policy, loaded once. Both halves read POLICY_DIR, so
		// they would ordinarily agree — but their fallbacks differ, and
		// two halves that can disagree about the policy is the class of
		// failure this merge existed to end. Found by running it: with
		// DEMO=1 the directory built a demonstration policy and the
		// issuer refused to start on an empty path.
		Policy: directory.Policy(),
		// And the console learns who is signed in from the issuer's own
		// browser session, once the issuer exists. Without this the
		// merged deployment would need either a proxy in front of the
		// console — running an OpenID flow against a service in this very
		// process — or the console's own login, which is the second door
		// an installation with a gateway deliberately turns off.
		UseSignedIn:    directory.ConsoleServer().UseSignedIn,
		UseSignInEntry: directory.ConsoleServer().UseSignInEntry,
		UseIssuerURL:   directory.ConsoleServer().UseIssuerURL,
	}
	assembled, err := issuerapp.New(ctx, cfg.Issuer, deps, log)
	if err != nil {
		directory.Close()
		return nil, err
	}
	log.InfoContext(ctx, "access-roster assembled as one service: a login makes no network "+
		"call except to the corporate directory")
	return &App{directory: directory, issuer: assembled, log: log}, nil
}

// Run serves the listeners and drives the directory's loops until the
// context is done.
func (a *App) Run(ctx context.Context) error {
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return a.issuer.Run(gctx) })
	group.Go(func() error { return a.directory.RunLoops(gctx) })
	if err := group.Wait(); err != nil {
		return fmt.Errorf("access-roster: %w", err)
	}
	return nil
}
