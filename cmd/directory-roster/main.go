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
	"github.com/truvity/access-roster/internal/connector"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/server"
	"github.com/truvity/access-roster/internal/settings"
	"github.com/truvity/access-roster/internal/valkey"
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
	store           string
	release         string
	oauthSecretName string
	valkey          valkey.Config
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
		store:           envString("STORE", "memory"),
		release:         envString("RELEASE_NAME", "directory-roster"),
		oauthSecretName: envString("OAUTH_CLIENT_SECRET_NAME", ""),
	}
	c.valkey = valkey.Config{
		Address:  envString("VALKEY_ADDRESS", ""),
		Password: envString("VALKEY_PASSWORD", ""),
		TLS:      envBool("VALKEY_TLS", false),
		Cluster:  envBool("VALKEY_CLUSTER", true),
		Prefix:   envString("RELEASE_NAME", "directory-roster"),
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
	switch c.store {
	case storeMemory, storeKubernetes:
	default:
		return config{}, fmt.Errorf("STORE: %q is neither %q nor %q", c.store, storeMemory, storeKubernetes)
	}
	return c, nil
}

// The two places the hub can keep what a console changed.
const (
	// storeMemory keeps nothing: a restart is a fresh installation. It is
	// what a local run and the demonstration want, and it is the default
	// so that neither needs a cluster.
	storeMemory = "memory"
	// storeKubernetes keeps it in the hub's own namespace, which is what
	// a deployment wants: a workspace connected in the console has no
	// other home.
	storeKubernetes = "kubernetes"
)

// openSnapshots decides where snapshots live.
//
// In memory unless a Valkey is configured, and the difference matters at
// more than one replica: two hubs each holding their own snapshots answer
// the same question two ways and read the same directory twice, and a
// directory's API quota is per tenant, not per reader. So a deployment
// running more than one replica without a Valkey is a mistake worth
// saying out loud, rather than one that shows up as somebody's quota.
func openSnapshots(ctx context.Context, cfg config, log *slog.Logger) (hub.SnapshotStore, func(), error) {
	if cfg.valkey.Address == "" {
		log.InfoContext(ctx, "keeping snapshots in memory: correct for one replica, "+
			"wasteful and inconsistent for more", "cache", "memory")
		return hub.NewMemorySnapshots(), func() {}, nil
	}
	shared, err := valkey.Open(ctx, cfg.valkey)
	if err != nil {
		return nil, nil, err
	}
	log.InfoContext(ctx, "sharing snapshots and the refresh lease",
		"cache", "valkey", "address", cfg.valkey.Address, "cluster", cfg.valkey.Cluster)
	return shared, func() { _ = shared.Close() }, nil
}

// stores is everything the hub writes down, and where.
type stores struct {
	workspaces  hub.Store
	credentials hub.CredentialStore
	settings    settings.Store
	sessionKey  []byte
	// adminPassword reads the break-glass password, creating one on
	// first start. Nil when nothing is kept, which is when a generated
	// one is printed for the run instead.
	adminPassword func(ctx context.Context) (string, error)
	adminSecret   string
}

// openStores builds them, and says plainly in the log which was chosen.
// The memory store losing everything on restart is correct for a
// prototype and catastrophic for a deployment, so it is never silent.
func openStores(ctx context.Context, cfg config, log *slog.Logger) (stores, error) {
	if cfg.store == storeMemory {
		key, err := access.NewSessionKey()
		if err != nil {
			return stores{}, err
		}
		log.WarnContext(ctx, "keeping state in memory: a restart loses every connected workspace, "+
			"the memberships added here and every session", "store", storeMemory)
		return stores{
			workspaces: hub.NewMemoryStore(),
			settings:   settings.NewMemory(settings.OAuthClient{}),
			sessionKey: key,
		}, nil
	}

	client, err := kube.InCluster(cfg.release)
	if err != nil {
		return stores{}, err
	}
	key, err := client.SessionKey(ctx, access.NewSessionKey)
	if err != nil {
		return stores{}, err
	}
	log.InfoContext(ctx, "keeping state in this namespace",
		"store", storeKubernetes, "namespace", client.Namespace(),
		"sessionKeySecret", client.SessionKeyName(),
		"oauthClientSecret", cfg.oauthSecretName)
	return stores{
		workspaces:  kube.NewWorkspaces(client),
		credentials: kube.NewCredentials(client),
		settings:    kube.NewSettings(client, cfg.oauthSecretName),
		sessionKey:  key,
		adminPassword: func(ctx context.Context) (string, error) {
			return client.AdminPassword(ctx, generatedPassword)
		},
		adminSecret: client.AdminPasswordName(),
	}, nil
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

	kept, err := openStores(ctx, cfg, log)
	if err != nil {
		return err
	}
	snapshots, closeSnapshots, err := openSnapshots(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeSnapshots()

	directory := hub.New(kept.workspaces, snapshots, cfg.freshness, log)
	if kept.credentials != nil {
		directory.UseCredentials(kept.credentials)
	}

	declared, err := declaredPolicy(cfg.policyPath, cfg.demo)
	if err != nil {
		return err
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		return err
	}
	authorizer := access.NewAuthorizer(set, directory, cfg.holdWindow)

	sessionKey := kept.sessionKey
	sessions, err := access.NewSessions(sessionKey, cfg.sessionLifetime, cfg.secureCookies)
	if err != nil {
		return err
	}

	var admin *server.AdminAccount
	if cfg.adminEnabled {
		password := cfg.adminPassword
		switch {
		case password != "":
		case kept.adminPassword != nil:
			// Kept in a Secret, and read from there on every start: a
			// recovery account whose password changes on every rollout is
			// not a recovery account. It is never printed — an operator
			// reads it with kubectl, an access they must already have.
			if password, err = kept.adminPassword(ctx); err != nil {
				return err
			}
			log.InfoContext(ctx, "the break-glass account is on; its password is in a Secret",
				"secret", kept.adminSecret, "key", "password")
		default:
			if password, err = generatedPassword(); err != nil {
				return err
			}
			announceAdminPassword(password)
		}
		admin = server.NewAdminAccount(password)
	}

	oauthClient := func() (google.OAuthClient, error) {
		stored, err := kept.settings.OAuthClient(context.Background())
		if err != nil {
			return google.OAuthClient{}, err
		}
		if !stored.Configured() {
			return google.OAuthClient{}, errors.New(
				"no OAuth client is registered yet: add one in Settings, or declare it in the deployment")
		}
		return google.OAuthClient{
			ID:          stored.ID,
			Secret:      stored.Secret,
			RedirectURL: cfg.publicURL + google.CallbackPath,
		}, nil
	}

	connectors := []server.Connector{connector.NewGoogle(oauthClient)}
	loginSources := []string{}
	if cfg.demo {
		connectors = append(connectors, seedDemo(ctx, directory, cfg.publicURL, log))
	}
	adopted, err := adoptDeclared(ctx, directory, cfg.overlayPath, log)
	if err != nil {
		return err
	}
	if err = reopenStored(ctx, directory, kept, adopted, oauthClient, log); err != nil {
		return err
	}
	if cfg.forwardedHeader != "" {
		loginSources = append(loginSources, "forwarded:"+cfg.forwardedIssuer)
	}
	if cfg.adminEnabled {
		loginSources = append(loginSources, "admin")
	}

	console, err := server.NewConsole(ctx, server.ConsoleDeps{
		Hub:          directory,
		Authorizer:   authorizer,
		Settings:     kept.settings,
		State:        access.NewStateCodec(sessionKey, 10*time.Minute),
		Connectors:   connectors,
		AdminEnabled: cfg.adminEnabled,
		LoginSources: loginSources,
		CacheBackend: cacheName(cfg),
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
func adoptDeclared(
	ctx context.Context, directory *hub.Hub, path string, log *slog.Logger,
) (map[string]bool, error) {
	adopted := map[string]bool{}
	overlay, err := hub.LoadOverlay(path)
	if err != nil {
		return nil, err
	}
	for i := range overlay.Workspaces {
		declared := &overlay.Workspaces[i]
		reader, err := openBackend(ctx, declared)
		if err != nil {
			return nil, fmt.Errorf("declared workspace %q: %w", declared.Backend+"/"+declared.Admin, err)
		}
		ws, err := directory.Adopt(ctx, hub.Workspace{
			ID:         declared.ID,
			Admin:      declared.Admin,
			Credential: hub.CredentialServiceAccountKey,
			Serve:      declared.Serve,
			Declared:   true,
		}, reader)
		if err != nil {
			return nil, fmt.Errorf("adopt declared workspace %q: %w", declared.Admin, err)
		}
		adopted[ws.ID] = true
		log.InfoContext(ctx, "declared workspace adopted",
			"workspace", ws.ID, "backend", ws.Backend,
			"admin", ws.Admin, "domains", ws.Domains, "served", ws.Served())
	}
	return adopted, nil
}

// reopenStored brings back what a console added before the last restart.
//
// Three cases, and the middle one is the reason this is not a loop over
// the store. A workspace the deployment declares was already opened
// above. A workspace that was declared when it was last written and is
// not any more has been taken out of the values: its record is stale, and
// leaving it would be a directory nobody could disconnect, so it is
// deleted. Everything else was connected in the console and is opened
// from the credential stored beside it.
//
// A credential that cannot be read does not stop the hub. The workspace
// stays, with no reader, and the console shows it as unhealthy with the
// reason — which is the same state as a directory that is refusing the
// credential, and is already handled everywhere downstream. Refusing to
// start would take every other directory down with it.
func reopenStored(
	ctx context.Context, directory *hub.Hub, kept stores, adopted map[string]bool,
	client func() (google.OAuthClient, error), log *slog.Logger,
) error {
	if kept.credentials == nil {
		return nil
	}
	list, err := kept.workspaces.List(ctx)
	if err != nil {
		return fmt.Errorf("read the stored workspaces: %w", err)
	}
	for i := range list {
		ws := &list[i]
		if adopted[ws.ID] {
			continue
		}
		if ws.Declared {
			log.InfoContext(ctx, "forgetting a workspace the deployment no longer declares",
				"workspace", ws.ID, "admin", ws.Admin)
			if err = kept.workspaces.Delete(ctx, ws.ID); err != nil {
				return fmt.Errorf("forget declared workspace %s: %w", ws.ID, err)
			}
			continue
		}

		cred, found, err := kept.credentials.Load(ctx, ws.ID)
		if err != nil || !found {
			log.WarnContext(ctx, "a connected workspace has no usable credential; "+
				"it will answer for nothing until it is reconnected",
				"workspace", ws.ID, "backend", ws.Backend, "error", err)
			continue
		}
		reader, err := openStored(ctx, ws.Backend, cred, client)
		if err != nil {
			log.WarnContext(ctx, "a connected workspace could not be reopened; "+
				"it will answer for nothing until it is reconnected",
				"workspace", ws.ID, "backend", ws.Backend, "error", err)
			continue
		}
		if err = directory.Attach(ctx, ws.ID, reader); err != nil {
			return fmt.Errorf("attach workspace %s: %w", ws.ID, err)
		}
		log.InfoContext(ctx, "connected workspace reopened",
			"workspace", ws.ID, "backend", ws.Backend, "credential", cred.Type,
			"admin", cred.Admin, "served", ws.Served())
	}
	return nil
}

// openStored turns a stored credential back into a reader.
func openStored(
	ctx context.Context, kind string, cred backend.Credential, client func() (google.OAuthClient, error),
) (backend.Backend, error) {
	if kind != "google" {
		return nil, fmt.Errorf("this build cannot reopen a %q workspace", kind)
	}
	switch cred.Type {
	case backend.CredentialOAuth:
		oauth, err := client()
		if err != nil {
			return nil, err
		}
		return google.OpenWithToken(ctx, oauth, string(cred.Data), cred.Admin)
	case backend.CredentialServiceAccountKey:
		return google.Open(ctx, cred.Data, cred.Admin)
	default:
		return nil, fmt.Errorf("unknown credential kind %q", cred.Type)
	}
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

// cacheName is what the console shows for where snapshots live.
func cacheName(cfg config) string {
	if cfg.valkey.Address == "" {
		return "memory"
	}
	return "valkey"
}
