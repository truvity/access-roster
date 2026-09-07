// Command directory-roster is the directory hub: one deployment holding
// every corporate-directory credential so that its consumers hold none.
//
// It serves two listeners. The API listener carries DirectoryService for
// consumers on the cluster network. The console listener carries the
// operator services, the login routes and the consent callback, behind an
// authenticating gateway or behind the hub's own sign-in.
//
// Run it with DEMO=1 for two demonstration tenants held in memory, which
// is how the use-cases are walked through before a directory is connected.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/google"
	"github.com/truvity/access-roster/frontend"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/server"
	"github.com/truvity/access-roster/internal/settings"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Default().Error("directory-roster stopped", "error", err)
		os.Exit(1)
	}
}

// config is the whole of the hub's configuration. The chart sets it; the
// defaults are what a laptop needs.
type config struct {
	apiPort     int
	consolePort int
	healthPort  int

	freshness hub.Config

	demo            bool
	publicURL       string
	adminEnabled    bool
	adminPassword   string
	sessionLifetime time.Duration
	secureCookies   bool
	forwardedHeader string
	forwardedIssuer string
	policyPath      string
	overlayPath     string
	holdWindow      time.Duration
	logLevel        slog.Level
}

func load() (config, error) {
	c := config{
		apiPort:         envInt("API_PORT", 8080),
		consolePort:     envInt("CONSOLE_PORT", 8081),
		healthPort:      envInt("HEALTH_PORT", 7070),
		demo:            envBool("DEMO", false),
		publicURL:       strings.TrimSuffix(envString("PUBLIC_URL", ""), "/"),
		adminEnabled:    envBool("ADMIN_ENABLED", true),
		adminPassword:   envString("ADMIN_PASSWORD", ""),
		secureCookies:   envBool("SECURE_COOKIES", false),
		forwardedHeader: envString("FORWARDED_EMAIL_HEADER", ""),
		forwardedIssuer: envString("FORWARDED_ISSUER", ""),
		policyPath:      envString("POLICY_DIR", ""),
		overlayPath:     envString("OVERLAY_FILE", ""),
	}
	var err error
	if c.freshness.RefreshInterval, err = envDuration("REFRESH_INTERVAL", hub.DefaultRefreshInterval); err != nil {
		return config{}, err
	}
	if c.freshness.FreshnessWindow, err = envDuration("FRESHNESS_WINDOW", hub.DefaultFreshnessWindow); err != nil {
		return config{}, err
	}
	if c.freshness.ProbeInterval, err = envDuration("PROBE_INTERVAL", hub.DefaultProbeInterval); err != nil {
		return config{}, err
	}
	if c.sessionLifetime, err = envDuration("SESSION_LIFETIME", 12*time.Hour); err != nil {
		return config{}, err
	}
	if c.holdWindow, err = envDuration("HOLD_WINDOW", 4*time.Hour); err != nil {
		return config{}, err
	}
	if c.publicURL == "" {
		c.publicURL = fmt.Sprintf("http://localhost:%d", c.consolePort)
	}
	if err = c.logLevel.UnmarshalText([]byte(envString("LOG_LEVEL", "info"))); err != nil {
		return config{}, fmt.Errorf("LOG_LEVEL: %w", err)
	}
	return c, nil
}

func run() error {
	cfg, err := load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.logLevel}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	directory := hub.New(hub.NewMemoryStore(), hub.NewMemorySnapshots(), cfg.freshness, log)

	declared, err := declaredPolicy(cfg.policyPath, cfg.demo)
	if err != nil {
		return err
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		return err
	}
	authorizer := access.NewAuthorizer(set, directory, cfg.holdWindow)

	sessionKey, err := access.NewSessionKey()
	if err != nil {
		return err
	}
	sessions, err := access.NewSessions(sessionKey, cfg.sessionLifetime, cfg.secureCookies)
	if err != nil {
		return err
	}

	admin := server.AdminAccount{}
	if cfg.adminEnabled {
		password := cfg.adminPassword
		if password == "" {
			if password, err = generatedPassword(); err != nil {
				return err
			}
			announceAdminPassword(password)
		}
		admin = server.NewAdminAccount(password)
	}

	var connectors []server.Connector
	loginSources := []string{}
	if cfg.demo {
		connectors = append(connectors, seedDemo(ctx, directory, cfg.publicURL, log))
	}
	if err := adoptDeclared(ctx, directory, cfg.overlayPath, log); err != nil {
		return err
	}
	if cfg.forwardedHeader != "" {
		loginSources = append(loginSources, "forwarded:"+cfg.forwardedIssuer)
	}
	if cfg.adminEnabled {
		loginSources = append(loginSources, "admin")
	}

	store := settings.NewMemory(settings.OAuthClient{})
	console, err := server.NewConsole(ctx, server.ConsoleDeps{
		Hub:          directory,
		Authorizer:   authorizer,
		Settings:     store,
		State:        access.NewStateCodec(sessionKey, 10*time.Minute),
		Connectors:   connectors,
		AdminEnabled: cfg.adminEnabled,
		LoginSources: loginSources,
		CacheBackend: "memory",
		SecureCookie: cfg.secureCookies,
		PublicURL:    cfg.publicURL,
	})
	if err != nil {
		return err
	}

	consoleServer := server.NewConsoleServer(server.ConsoleServerDeps{
		Console:    console,
		Authorizer: authorizer,
		Sessions:   sessions,
		State:      access.NewStateCodec(sessionKey, 10*time.Minute),
		Connectors: connectors,
		Hub:        directory,
		Admin:      admin,
		Forwarded: server.ForwardedIdentity{
			Issuer:      cfg.forwardedIssuer,
			EmailHeader: cfg.forwardedHeader,
		},
		Log: log,
		UI:  frontend.FS(),
	})

	apiMux := http.NewServeMux()
	apiMux.Handle(directoryv1connect.NewDirectoryServiceHandler(server.NewDirectory(directory)))

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	healthMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	log.InfoContext(ctx, "directory-roster starting",
		"api", cfg.apiPort, "console", cfg.consolePort, "health", cfg.healthPort,
		"demo", cfg.demo, "admin", cfg.adminEnabled, "public", cfg.publicURL,
		"version", version.String(), "policy", policySource(cfg.policyPath, cfg.demo))

	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(gctx, cfg.apiPort, apiMux, "api", log) })
	group.Go(func() error { return serve(gctx, cfg.consolePort, consoleServer.Handler(), "console", log) })
	group.Go(func() error { return serve(gctx, cfg.healthPort, healthMux, "health", log) })
	group.Go(func() error { return directory.Run(gctx) })
	return group.Wait()
}

// serve runs one listener until the context is done, then drains it.
func serve(ctx context.Context, port int, handler http.Handler, name string, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.WarnContext(ctx, "listener did not drain", "listener", name, "error", err)
		}
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s listener: %w", name, err)
	}
	return nil
}

// builtinPolicy is what a hub with no declared policy starts from: the two
// groups it is a relying party of, empty. Nobody is in them, so nobody but
// the break-glass admin can act until an operator attaches the first
// directory group in the console — which is day one, exactly as the
// runbook describes it.
const builtinPolicy = `
version: 1
groups:
  hub-operators: {}
  hub-viewers: {}
claims:
  hub-operators: { groups: [hub:operator] }
  hub-viewers: { groups: [hub:viewer] }
lifetimes:
  default: 12h
`

// declaredPolicy reads the deployment's policy. With none, a
// demonstration run gets one rich enough to watch every mechanic work,
// and anything else gets the built-in two groups.
func declaredPolicy(path string, demonstration bool) (policy.Policy, error) {
	switch {
	case path != "":
		return policy.LoadDeclared(path)
	case demonstration:
		return policy.Parse([]byte(demo.Policy))
	default:
		return policy.Parse([]byte(builtinPolicy))
	}
}

// adoptDeclared brings up the workspaces the deployment owns.
//
// A declared workspace that cannot be adopted stops the process rather
// than being skipped. The deployment asked for a directory; starting
// without it means answering "no opinion" about every address in it,
// which reads to a consumer exactly like a tenant that was removed. A
// hub that refuses to start is visible in one place; a hub that quietly
// serves less than it was configured to is visible nowhere.
func adoptDeclared(ctx context.Context, directory *hub.Hub, path string, log *slog.Logger) error {
	overlay, err := hub.LoadOverlay(path)
	if err != nil {
		return err
	}
	for i := range overlay.Workspaces {
		declared := &overlay.Workspaces[i]
		reader, err := openBackend(ctx, declared)
		if err != nil {
			return fmt.Errorf("declared workspace %q: %w", declared.Backend+"/"+declared.Admin, err)
		}
		adopted, err := directory.Adopt(ctx, hub.Workspace{
			ID:         declared.ID,
			Admin:      declared.Admin,
			Credential: hub.CredentialServiceAccountKey,
			Declared:   true,
		}, reader)
		if err != nil {
			return fmt.Errorf("adopt declared workspace %q: %w", declared.Admin, err)
		}
		log.InfoContext(ctx, "declared workspace adopted",
			"workspace", adopted.ID, "backend", adopted.Backend,
			"admin", adopted.Admin, "domains", adopted.Domains)
	}
	return nil
}

// backendOpeners is how a build declares which directories it can read.
//
// It is a registry rather than a switch so that adding a backend is a
// registration next to the backend itself, and so that a build without
// one fails by naming exactly what it lacks. The map is empty today: the
// hub reads real directories from its 1.0, and until then a deployment
// that declares a workspace is told so at start rather than left to
// discover it from a console with nothing in it.
var backendOpeners = map[string]func(ctx context.Context, d *hub.Declared) (backend.Backend, error){
	"google": func(ctx context.Context, d *hub.Declared) (backend.Backend, error) {
		key, err := os.ReadFile(d.KeyFile) //nolint:gosec // the path is deployment configuration, not input
		if err != nil {
			return nil, fmt.Errorf("read the service-account key: %w", err)
		}
		return google.Open(ctx, key, d.Admin)
	},
}

// openBackend builds the reader for a declared workspace.
//
// A backend this build does not carry is an error naming what was asked
// for. The alternative — ignoring the entry — is how a deployment ends up
// believing it reads a directory it has never once opened.
func openBackend(ctx context.Context, declared *hub.Declared) (backend.Backend, error) {
	open, ok := backendOpeners[declared.Backend]
	if !ok {
		known := slices.Sorted(maps.Keys(backendOpeners))
		if len(known) == 0 {
			return nil, fmt.Errorf("this build reads no directory backend yet, and %q was declared", declared.Backend)
		}
		return nil, fmt.Errorf("unknown backend %q; this build reads %v", declared.Backend, known)
	}
	return open(ctx, declared)
}

// seedDemo adopts the demonstration tenants and returns their connector.
func seedDemo(ctx context.Context, directory *hub.Hub, publicURL string, log *slog.Logger) *demo.Connector {
	connector := demo.NewConnector(publicURL)
	tenants := demo.Tenants(time.Now())
	for i := range tenants {
		tenant := &tenants[i]
		connector.Adopt(tenant.Workspace.ID, tenant.Backend)
		if _, err := directory.Adopt(ctx, tenant.Workspace, tenant.Backend); err != nil {
			log.WarnContext(ctx, "demonstration tenant could not be adopted",
				"workspace", tenant.Workspace.ID, "error", err)
		}
	}
	log.InfoContext(ctx, "demonstration tenants adopted; no credential and no network is involved")
	return connector
}

// policySource says where the policy came from, for the startup line.
func policySource(path string, demonstration bool) string {
	switch {
	case path != "":
		return path
	case demonstration:
		return "demonstration"
	default:
		return "built-in"
	}
}

func generatedPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate the admin password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// announceAdminPassword prints the generated password once. The built
// service writes it to a Secret instead, and shows it nowhere.
func announceAdminPassword(password string) {
	fmt.Fprintf(os.Stderr, "\n  break-glass admin password (generated for this run): %s\n"+
		"  Sign in at /login. Turn the account off once a rule grants operator to a real identity.\n\n",
		password)
}

func envString(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if v, err := strconv.Atoi(envString(name, "")); err == nil {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	if v, err := strconv.ParseBool(envString(name, "")); err == nil {
		return v
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := envString(name, "")
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}
