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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/truvity/access-roster/backend/google"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/health"
	"github.com/truvity/access-roster/internal/hubclient"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/valkey"
	"github.com/truvity/access-roster/internal/verify"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
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

	inCluster         bool
	release           string
	oauthClientID     string
	oauthClientSecret string
	secureCookies     bool
	oauthSecretFile   string
	oauthIDFile       string
	recoveryEnabled   bool
	recoveryAccount   string
	cluster           string
	recoveryAudience  string
	clientSecretsDir  string
	clustersPath      string
	valkey            valkey.Config
	audience          string
	githubOwners      []string
	consoleOrigin     string
	signingKeyFile    string

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
		port:              envInt("PORT", 8080),
		healthPort:        envInt("HEALTH_PORT", 7070),
		issuerURL:         strings.TrimSuffix(envString("ISSUER_URL", ""), "/"),
		allowInsecure:     envBool("ALLOW_INSECURE", false),
		hubAddress:        envString("HUB_ADDRESS", ""),
		hubTokenFile:      envString("HUB_TOKEN_FILE", ""),
		policyPath:        envString("POLICY_DIR", ""),
		inCluster:         envBool("IN_CLUSTER", false),
		oauthClientID:     envString("OAUTH_CLIENT_ID", ""),
		oauthClientSecret: envString("OAUTH_CLIENT_SECRET", ""),
		secureCookies:     envBool("SECURE_COOKIES", false),
		oauthSecretFile:   envString("OAUTH_CLIENT_SECRET_FILE", ""),
		oauthIDFile:       envString("OAUTH_CLIENT_ID_FILE", ""),
		recoveryEnabled:   envBool("RECOVERY_ENABLED", false),
		githubOwners:      envList("GITHUB_OWNERS"),
		consoleOrigin:     envString("CONSOLE_ORIGIN", ""),
		recoveryAccount:   envString("RECOVERY_SERVICE_ACCOUNT", ""),
		// Names this cluster in a ServiceAccount's subject. A pod cannot
		// discover it, and the same namespace and name exist on every
		// cluster, so an installation that leaves it empty keeps the older
		// unqualified subject rather than an invented one.
		cluster:          envString("CLUSTER", ""),
		recoveryAudience: envString("RECOVERY_AUDIENCE", ""),
		clientSecretsDir: envString("CLIENT_SECRETS_DIR", ""),
		clustersPath:     envString("CLUSTERS_FILE", ""),
		valkey: valkey.Config{
			Address:  envString("VALKEY_ADDRESS", ""),
			Password: envString("VALKEY_PASSWORD", ""),
			TLS:      envBool("VALKEY_TLS", false),
			Cluster:  envBool("VALKEY_CLUSTER", true),
			Prefix:   envString("RELEASE_NAME", "access-issuer"),
		},
		signingKeyFile: envString("SIGNING_KEY_FILE", ""),
		release:        envString("RELEASE_NAME", "access-issuer"),
		audience:       envString("EXCHANGE_AUDIENCE", ""),
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

	// Every relying party's trust is anchored on this string, and it goes
	// into every token. A default would be a value nobody chose baked
	// into an installation's whole estate.
	if c.issuerURL == "" {
		return Config{}, errors.New("ISSUER_URL is required: it is baked into every token and every relying party")
	}
	if c.audience == "" {
		c.audience = c.release
	}
	return c, nil
}

// Deps are the things a caller supplies instead of letting this package
// build them. Both are how the merged service is assembled (INF-691):
// one process holds the directory, so the issuer calls it rather than
// dialling it, and the console is served from the issuer's own origin
// instead of a listener of its own.
//
// A zero Deps is the split deployment: the directory is reached over the
// network at HUB_ADDRESS, and nothing is mounted under /console/.
type Deps struct {
	// Directory answers "who is this address". Nil builds a network
	// client, and then HUB_ADDRESS is required.
	Directory issuer.Directory
	// Ready are dependencies the caller's half of the process needs
	// answering for, added to this one's on /readyz. The merged service
	// has one readiness endpoint and two stores behind it.
	Ready []health.Dependency
	// Console is the operator UI, written as if it were at the root of an
	// origin. It is mounted under /console/ with the prefix stripped,
	// which is exactly what the gateway used to do for it.
	Console http.Handler
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
func New(ctx context.Context, cfg Config, deps Deps, log *slog.Logger) (*App, error) {
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

	directory := deps.Directory
	if directory == nil {
		if cfg.hubAddress == "" {
			return nil, errors.New(
				"HUB_ADDRESS is required: this service asks the directory about every person, " +
					"and no directory was supplied in-process")
		}
		if directory, err = hubclient.New(hubclient.Options{
			BaseURL: cfg.hubAddress, TokenFile: cfg.hubTokenFile,
		}); err != nil {
			return nil, err
		}
	}

	// The shared store first: the issuer's session index lives in it, so
	// there is no issuer to build until it is open.
	shared, err := openState(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	core := issuer.New(issuer.Config{
		URL:             cfg.issuerURL,
		TokenLifetime:   cfg.tokenLifetime,
		RefreshLifetime: cfg.refreshLifetime,
		HoldWindow:      cfg.holdWindow,
		AllowInsecure:   cfg.allowInsecure,
	}, set, directory, shared)

	key, err := signingKey(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	if err = readClient(&cfg); err != nil {
		return nil, err
	}
	verifiers, err := openVerifiers(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	storage, err := issuer.NewStorage(core, verifiers, clientSecrets(cfg, log), key, shared)
	if err != nil {
		return nil, err
	}
	signIn, err := openSignIn(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	handler, err := issuer.HandlerWithSignIn(core, storage, issuer.SignInDeps{
		Providers:     signIn,
		Recovery:      openRecovery(ctx, cfg, log),
		State:         access.NewStateCodec(key.Derive("access-roster/sign-in-state"), signInWindow),
		ConsoleOrigin: cfg.consoleOrigin,
		Secure:        cfg.secureCookies,
		Log:           log,
	})
	if err != nil {
		return nil, err
	}
	handler = mount(handler, deps.Console)

	// Readiness follows the state store; liveness does not. An issuer
	// that cannot reach it can neither mint nor find a session, and
	// reporting ready through that is how a moved Valkey became a
	// fifteen-second hang at every callback on 2026-09-10.
	healthMux := health.Mux(0, append([]health.Dependency{
		health.Follow("the session store", shared),
	}, deps.Ready...)...)

	log.InfoContext(ctx, "access-issuer assembled",
		"issuer", cfg.issuerURL, "directory", directorySource(deps, cfg), "inCluster", cfg.inCluster,
		"exchangeAudience", cfg.audience, "port", cfg.port, "health", cfg.healthPort,
		"tokenLifetime", cfg.tokenLifetime, "refreshLifetime", cfg.refreshLifetime,
		"holdWindow", cfg.holdWindow, "version", version.String())
	if cfg.allowInsecure {
		log.WarnContext(ctx, "the issuer URL may be plaintext: every token this service signs is a "+
			"bearer credential, and an issuer reached over http can be impersonated by anyone on the path")
	}
	return &App{handler: handler, health: healthMux, issuer: core, cfg: cfg, log: log}, nil
}

// directorySource says where the answer about a person comes from, in a
// word an operator can act on: the address of another service, or this
// process.
func directorySource(deps Deps, cfg Config) string {
	if deps.Directory != nil {
		return "in-process"
	}
	return cfg.hubAddress
}

// mount puts the console under /console/ on the issuer's own origin.
//
// Same origin is the point, not a convenience: the console's session
// pages then call the issuer with the browser's own cookie and no bearer
// in JavaScript, and discovery keeps the origin ROOT, which is where
// every relying party's `iss` says it is. The console's handler is
// written as if it were at a root, so the prefix is stripped here —
// exactly what the gateway's URLRewrite used to do for it.
func mount(issuerHandler, console http.Handler) http.Handler {
	if console == nil {
		return issuerHandler
	}
	mux := http.NewServeMux()
	// "/console" without the trailing slash is a DIFFERENT page to a
	// browser: the bundle references its assets relatively so that one
	// build serves at any mount point, and "./assets/..." on a page at
	// "/console" resolves against the root — where every asset asks the
	// issuer and gets a 404.
	mux.HandleFunc("GET /console", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console/", http.StatusFound)
	})
	mux.Handle("/console/", http.StripPrefix("/console", console))
	// The admin-consent callback stays at the origin ROOT, because it is
	// the one flow that runs before anybody can be signed in: the
	// operator who connects the FIRST directory is by definition one no
	// directory can vouch for yet. Its redirect URI is registered with
	// the corporate IdP, so moving it would mean re-registering it in
	// every tenant.
	mux.Handle("/connect/", console)
	mux.Handle("/", issuerHandler)
	return mux
}

// Run serves the two listeners until the context is done.
func (a *App) Run(ctx context.Context) error {
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(gctx, a.cfg.port, a.handler, "issuer", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.healthPort, a.health, "health", a.log) })
	return group.Wait()
}

// clientSecrets resolves a confidential client's secret from the files
// the deployment mounted, one per client id.
//
// From FILES and not from the API, for the same reason the signing key
// comes from one: this service holds no RBAC to read a Secret, so a
// compromise of it cannot become a read of every credential in its
// namespace. The chart projects each declared client's Secret to a file
// named after the client.
//
// Read per call rather than once at start, so that rotating a client's
// Secret takes effect when the kubelet refreshes the mount instead of
// needing a restart.
func clientSecrets(cfg Config, log *slog.Logger) func(string) (string, bool) {
	if cfg.clientSecretsDir == "" {
		return nil
	}
	return func(clientID string) (string, bool) {
		// A client id is a path SEGMENT here. One containing a separator
		// would read a file the deployment never mounted, so it is
		// refused rather than cleaned: there is no reading of "../" that
		// the author could have meant.
		if clientID == "" || strings.ContainsAny(clientID, `/\`) || clientID == "." || clientID == ".." {
			return "", false
		}
		raw, err := os.ReadFile(filepath.Join(cfg.clientSecretsDir, clientID)) //nolint:gosec // the id is checked above and the directory is deployment configuration
		if err != nil {
			log.Warn("a declared client's secret could not be read; that client cannot authenticate",
				"client", clientID, "error", err)
			return "", false
		}
		return strings.TrimSpace(string(raw)), true
	}
}

// openRecovery builds the way in that needs no directory, or nothing.
//
// Out of a cluster there is no API server to prove access to, so there is
// nothing to build: unlike the hub, this service has no password shape to
// fall back on, and inventing one would be inventing a standing
// credential for a service whose whole point is not to hold any.
func openRecovery(ctx context.Context, cfg Config, log *slog.Logger) issuer.Recovery {
	if !cfg.recoveryEnabled {
		return nil
	}
	if !cfg.inCluster || cfg.recoveryAccount == "" || cfg.recoveryAudience == "" {
		log.WarnContext(ctx, "recovery is asked for but cannot be built: it proves access to "+
			"a cluster, and this service is not running in one with an account and audience named")
		return nil
	}
	client, err := kube.InCluster(cfg.release)
	if err != nil {
		log.WarnContext(ctx, "recovery could not be built", "error", err)
		return nil
	}
	namespace := client.Namespace()
	log.InfoContext(ctx, "recovery sign-in is available: a token for this account signs in "+
		"without a directory, and the policy's service_account matchers decide what it gets",
		"namespace", namespace, "account", cfg.recoveryAccount, "audience", cfg.recoveryAudience)
	return &issuer.TokenRecovery{
		Review:    client.ReviewToken,
		Namespace: namespace,
		Account:   cfg.recoveryAccount,
		Audience:  cfg.recoveryAudience,
		Subjects:  []string{kube.ServiceAccountSubject(namespace, cfg.recoveryAccount)},
		Cluster:   cfg.cluster,
	}
}

// signInWindow is how long a person has to finish signing in, and the
// life of the state that carries their half-finished request.
const signInWindow = 10 * time.Minute

// openSignIn builds the directories a person may prove themselves with.
//
// A deployment with none issues tokens to machines and to nobody else,
// which is a real posture — a cluster's workload exchange with no human
// login — and says so rather than serving a chooser with no buttons.
func openSignIn(ctx context.Context, cfg Config, log *slog.Logger) ([]issuer.SignIn, error) {
	if cfg.oauthClientID == "" || cfg.oauthClientSecret == "" {
		log.WarnContext(ctx, "nobody can sign in: no OAuth client is configured, so this issuer "+
			"serves token exchange and nothing else")
		return nil, nil
	}
	client := google.OAuthClient{
		ID:      cfg.oauthClientID,
		Secret:  cfg.oauthClientSecret,
		BaseURL: cfg.issuerURL,
	}
	log.InfoContext(ctx, "people sign in with Google", "redirect", client.SignInRedirect())
	return []issuer.SignIn{&googleSignIn{client: client}}, nil
}

// googleSignIn adapts the backend's client to what the issuer's pages
// need. It is three lines because the issuer's half of a login is three
// things: where to send them, what came back, and nothing else.
type googleSignIn struct{ client google.OAuthClient }

func (g *googleSignIn) Kind() string { return "google" }

func (g *googleSignIn) URL(state string) (string, error) { return g.client.SignInURL(state), nil }

func (g *googleSignIn) Identify(ctx context.Context, code string) (string, error) {
	return google.Identify(ctx, g.client, code)
}

// signingKey reads the key this installation was given.
//
// It is a mounted file, not a Secret this service reads through the API,
// and that is deliberate twice over. The issuer needs no permission to
// read Secrets at all — the one credential it holds arrives the way every
// other credential in this estate arrives, from cert-manager or from
// external-secrets, and this service only opens the file. And it does not
// mint one: a key generated here would be a different key in every
// replica and after every restart, and a service that creates its own
// credential is an exception to how everything else here gets one.
//
// No file configured means a local run, which generates one and says so.
func signingKey(ctx context.Context, cfg Config, log *slog.Logger) (*issuer.SigningKey, error) {
	if cfg.signingKeyFile == "" {
		log.WarnContext(ctx, "generating a signing key for this process: every restart invalidates "+
			"every token it signed, and two replicas would sign with two keys. "+
			"A deployment sets SIGNING_KEY_FILE")
		return issuer.NewSigningKey()
	}
	encoded, err := os.ReadFile(cfg.signingKeyFile) //nolint:gosec // the path is deployment configuration
	if err != nil {
		// Starting without it would mean signing with a key nobody else
		// has, which is worse than not starting: the tokens would look
		// fine and verify nowhere.
		return nil, fmt.Errorf("read the signing key: %w — a deployment provides it as a Secret, "+
			"issued by cert-manager or delivered by external-secrets, mounted at that path", err)
	}
	key, err := issuer.ParseSigningKey(encoded)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "signing with the key this installation was given",
		"file", cfg.signingKeyFile, "kid", key.ID())
	return key, nil
}

// readClient takes the OAuth client from the files a Secret is mounted
// at, for the same reason the signing key comes from one: a credential in
// an environment variable is a credential in every process listing and
// every crash dump. The variables stay for a local run.
//
// The ID comes from the same Secret as the secret, rather than from a
// chart value, so that both halves of one credential travel together and
// the hub and this service read it the same way. It is not itself a
// secret -- every browser sent to the provider carries it -- but a client
// whose halves are configured in two places is a client that can be half
// rotated.
func readClient(cfg *Config) error {
	for _, from := range []struct {
		path string
		into *string
		what string
	}{
		{cfg.oauthIDFile, &cfg.oauthClientID, "id"},
		{cfg.oauthSecretFile, &cfg.oauthClientSecret, "secret"},
	} {
		if from.path == "" {
			continue
		}
		raw, err := os.ReadFile(from.path) //nolint:gosec // the path is deployment configuration
		if err != nil {
			return fmt.Errorf("read the OAuth client %s: %w", from.what, err)
		}
		*from.into = strings.TrimSpace(string(raw))
	}
	return nil
}

// openState decides where a login in progress lives.
//
// In memory unless a Valkey is configured, and at more than one replica
// that difference is not a nicety: a browser starts at /authorize on one
// replica, comes back from the provider at another, and the client
// redeems the code at a third. Each of those is a coin toss that looks
// like an intermittent failure, so a deployment running more than one
// replica without a Valkey is a mistake worth saying out loud.
func openState(ctx context.Context, cfg Config, log *slog.Logger) (issuer.State, error) {
	if cfg.valkey.Address == "" {
		log.WarnContext(ctx, "keeping logins in progress in memory: correct for one replica, "+
			"and at more than one a browser that comes back to a different pod finds nothing",
			"state", "memory")
		return issuer.NewMemoryState(), nil
	}
	shared, err := valkey.OpenState(ctx, cfg.valkey)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "sharing logins in progress",
		"state", "valkey", "address", cfg.valkey.Address, "cluster", cfg.valkey.Cluster)
	return shared, nil
}

// openVerifiers builds what can turn somebody else's token into a proof.
//
// A deployment with none can still sign people in; it simply exchanges
// nothing, and says so, because an exchange endpoint that refuses
// everything with "unverified" is indistinguishable from one that is
// misconfigured.
func openVerifiers(ctx context.Context, cfg Config, log *slog.Logger) (issuer.Verifiers, error) {
	var verifiers issuer.Verifiers

	// Clusters, by their own published key set and NEVER by asking them
	// (INF-692). The other way to check a ServiceAccount token is a
	// TokenReview, which means holding a kubeconfig for every cluster
	// whose workloads may exchange — inside the service whose whole point
	// is to hold almost no credential. A key set is public, so a remote
	// cluster's workload proves itself exactly the way a GitHub job does,
	// and adding a cluster is one row naming a URL.
	//
	// This service's OWN cluster is a row like any other. There is no
	// special case for it, because a special case is a second code path
	// that only one installation exercises.
	federation, err := verify.LoadFederation(cfg.clustersPath)
	if err != nil {
		return nil, err
	}
	for _, cluster := range federation.Verifiers(cfg.audience, nil) {
		verifiers = append(verifiers, cluster)
	}
	if len(federation.Clusters) > 0 {
		log.InfoContext(ctx, "workload tokens are verified against each cluster's own key set",
			"clusters", federation.Names(), "audience", cfg.audience)
	} else {
		log.InfoContext(ctx, "no workload token can be verified: no cluster's key set is declared")
	}

	// GitHub, only when this installation has said whose repositories it
	// runs jobs for. There is no default and there cannot be one: anybody
	// may run a workflow in their own repository and get a valid token
	// from GitHub, so an empty list would admit every repository there is
	// rather than none.
	if len(cfg.githubOwners) > 0 {
		log.InfoContext(ctx, "CI tokens are verified against GitHub",
			"owners", cfg.githubOwners, "audience", cfg.issuerURL)
		verifiers = append(verifiers, &verify.GitHub{
			Owners: cfg.githubOwners,
			// The audience a workflow must request is this issuer's own
			// URL. A token minted for a cloud provider is a valid GitHub
			// token, and one audience per relying party is what keeps it
			// from being replayed here.
			Audience: cfg.issuerURL,
		})
	} else {
		log.InfoContext(ctx, "no CI token can be verified: GITHUB_OWNERS names no organisation")
	}

	// An exchange endpoint that refuses everything with "unverified" is
	// indistinguishable from one that is misconfigured, so a deployment
	// that can verify nothing says so rather than looking broken later.
	if len(verifiers) == 0 {
		log.WarnContext(ctx, "no proof can be verified: token exchange will refuse everything")
	}

	return verifiers, nil
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

// envList reads a comma-separated setting, dropping the empty entries a
// templated values file leaves behind.
func envList(name string) []string {
	var out []string

	for _, item := range strings.Split(os.Getenv(name), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}

	return out
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
