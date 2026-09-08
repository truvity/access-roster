// Package issuerapp assembles the token service from its configuration:
// the policy, the door to the hub, the signing key, the verifiers that
// turn somebody else's token into a proof, and the OpenID surface over
// all of it.
//
// A package rather than the body of main, for the reason the hub's
// equivalent is: this is where the decisions a deployment can get wrong
// are made, and main() cannot be tested.
package issuerapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/truvity/access-roster/internal/hubclient"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/verify"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
)

// The two places the signing key can live.
const (
	// storeMemory generates one per process: every restart invalidates
	// every token it signed, which is right for a local run and an outage
	// anywhere else.
	storeMemory = "memory"
	// storeKubernetes reads it from a Secret, shared by every replica.
	storeKubernetes = "kubernetes"
)

// Config is what a deployment decides. It is read from the environment,
// which is what the chart sets.
type Config struct {
	port       int
	healthPort int

	issuerURL     string
	allowInsecure bool

	hubAddress   string
	hubTokenFile string

	policyPath string

	store    string
	release  string
	audience string

	tokenLifetime   time.Duration
	refreshLifetime time.Duration
	holdWindow      time.Duration

	logLevel slog.Level
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// Load reads the configuration from the environment.
func Load() (Config, error) {
	c := Config{
		port:          envInt("PORT", 8080),
		healthPort:    envInt("HEALTH_PORT", 7070),
		issuerURL:     strings.TrimSuffix(envString("ISSUER_URL", ""), "/"),
		allowInsecure: envBool("ALLOW_INSECURE", false),
		hubAddress:    envString("HUB_ADDRESS", ""),
		hubTokenFile:  envString("HUB_TOKEN_FILE", ""),
		policyPath:    envString("POLICY_DIR", ""),
		store:         envString("STORE", storeMemory),
		release:       envString("RELEASE_NAME", "access-issuer"),
		audience:      envString("EXCHANGE_AUDIENCE", ""),
	}
	var err error
	if c.tokenLifetime, err = envDuration("TOKEN_LIFETIME", issuer.DefaultTokenLifetime); err != nil {
		return Config{}, err
	}
	if c.refreshLifetime, err = envDuration("REFRESH_LIFETIME", issuer.DefaultRefreshLifetime); err != nil {
		return Config{}, err
	}
	if c.holdWindow, err = envDuration("HOLD_WINDOW", issuer.DefaultHoldWindow); err != nil {
		return Config{}, err
	}
	if err = c.logLevel.UnmarshalText([]byte(envString("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("LOG_LEVEL: %w", err)
	}

	switch {
	case c.issuerURL == "":
		// Every relying party's trust is anchored on this string, and it
		// goes into every token. A default would be a value nobody chose
		// baked into an installation's whole estate.
		return Config{}, errors.New("ISSUER_URL is required: it is baked into every token and every relying party")
	case c.hubAddress == "":
		return Config{}, errors.New("HUB_ADDRESS is required: this service asks the hub about every person")
	case c.store != storeMemory && c.store != storeKubernetes:
		return Config{}, fmt.Errorf("STORE: %q is neither %q nor %q", c.store, storeMemory, storeKubernetes)
	}
	if c.audience == "" {
		c.audience = c.release
	}
	return c, nil
}

// App is an assembled issuer.
type App struct {
	handler http.Handler
	health  http.Handler
	issuer  *issuer.Issuer
	cfg     Config
	log     *slog.Logger
}

// Handler is the OpenID surface: discovery, keys, authorize, token,
// exchange, revocation, the device flow.
func (a *App) Handler() http.Handler { return a.handler }

// HealthHandler is liveness and readiness.
func (a *App) HealthHandler() http.Handler { return a.health }

// Issuer is the decision core, for a caller that drives it directly.
func (a *App) Issuer() *issuer.Issuer { return a.issuer }

// New assembles the issuer.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}

	declared, err := policy.LoadDeclared(cfg.policyPath)
	if err != nil {
		return nil, err
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		return nil, err
	}

	directory, err := hubclient.New(hubclient.Options{
		BaseURL: cfg.hubAddress, TokenFile: cfg.hubTokenFile,
	})
	if err != nil {
		return nil, err
	}

	core := issuer.New(issuer.Config{
		URL:             cfg.issuerURL,
		TokenLifetime:   cfg.tokenLifetime,
		RefreshLifetime: cfg.refreshLifetime,
		HoldWindow:      cfg.holdWindow,
		AllowInsecure:   cfg.allowInsecure,
	}, set, directory)

	key, err := signingKey(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	verifiers, err := openVerifiers(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	storage, err := issuer.NewStorage(core, verifiers, nil, key)
	if err != nil {
		return nil, err
	}
	handler, err := issuer.Handler(core, storage)
	if err != nil {
		return nil, err
	}

	health := http.NewServeMux()
	health.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	health.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	log.InfoContext(ctx, "access-issuer assembled",
		"issuer", cfg.issuerURL, "hub", cfg.hubAddress, "store", cfg.store,
		"exchangeAudience", cfg.audience, "port", cfg.port, "health", cfg.healthPort,
		"tokenLifetime", cfg.tokenLifetime, "refreshLifetime", cfg.refreshLifetime,
		"holdWindow", cfg.holdWindow, "version", version.String())
	if cfg.allowInsecure {
		log.WarnContext(ctx, "the issuer URL may be plaintext: every token this service signs is a "+
			"bearer credential, and an issuer reached over http can be impersonated by anyone on the path")
	}
	return &App{handler: handler, health: health, issuer: core, cfg: cfg, log: log}, nil
}

// Run serves the two listeners until the context is done.
func (a *App) Run(ctx context.Context) error {
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(gctx, a.cfg.port, a.handler, "issuer", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.healthPort, a.health, "health", a.log) })
	return group.Wait()
}

// signingKey reads the key a deployment keeps, or generates one.
func signingKey(ctx context.Context, cfg Config, log *slog.Logger) (*issuer.SigningKey, error) {
	if cfg.store == storeMemory {
		log.WarnContext(ctx, "generating a signing key for this process: every restart invalidates "+
			"every token it signed, and two replicas would sign with two keys", "store", storeMemory)
		return nil, nil //nolint:nilnil // nil means "generate one", which is the storage's contract
	}
	client, err := kube.InCluster(cfg.release)
	if err != nil {
		return nil, err
	}
	stored, err := client.SigningKey(ctx, func() ([]byte, error) {
		fresh, genErr := issuer.NewSigningKey()
		if genErr != nil {
			return nil, genErr
		}
		return fresh.PEM(), nil
	})
	if err != nil {
		return nil, err
	}
	key, err := issuer.ParseSigningKey(stored)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "signing with the key this installation keeps",
		"secret", client.SigningKeyName(), "kid", key.ID())
	return key, nil
}

// openVerifiers builds what can turn somebody else's token into a proof.
//
// A deployment with none can still sign people in; it simply exchanges
// nothing, and says so, because an exchange endpoint that refuses
// everything with "unverified" is indistinguishable from one that is
// misconfigured.
func openVerifiers(ctx context.Context, cfg Config, log *slog.Logger) (issuer.Verifiers, error) {
	if cfg.store != storeKubernetes {
		log.WarnContext(ctx, "no proof can be verified: token exchange will refuse everything")
		return nil, nil
	}
	client, err := kube.InCluster(cfg.release)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "workload tokens are verified against this cluster", "audience", cfg.audience)
	return issuer.Verifiers{&verify.Workload{Review: client.ReviewToken, Audience: cfg.audience}}, nil
}

// serve runs one listener until the context is done, then drains it.
func serve(ctx context.Context, port int, handler http.Handler, name string, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
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
	log.InfoContext(ctx, "listening", "listener", name, "port", port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s listener: %w", name, err)
	}
	return nil
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	if value, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(name))); err == nil {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return value, nil
}
