// Package app assembles the directory hub from its configuration: the
// stores, the snapshot cache, the backends, the policy, the connectors,
// the recovery path and the three listeners.
//
// It is a package rather than the body of main because this is where the
// service's behaviour is decided — which store, which shape of recovery,
// who may call the API listener, what URL the OAuth redirects are built
// from — and every one of those is somewhere a deployment can be quietly
// wrong. Four of them were, and none of it was reachable by a test while
// it lived in main().
//
// The API listener carries DirectoryService for consumers on the cluster
// network. The console listener carries the operator services, the login
// routes and the consent callback, behind an authenticating gateway or
// behind the hub's own sign-in. DEMO=1 gives two tenants held in memory,
// which need no credential and no network.
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/google"
	"github.com/truvity/access-roster/frontend"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/audit/sinkrpc"
	"github.com/truvity/access-roster/internal/connector"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/health"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/s3audit"
	"github.com/truvity/access-roster/internal/server"
	"github.com/truvity/access-roster/internal/settings"
	"github.com/truvity/access-roster/internal/valkey"
	"github.com/truvity/access-roster/internal/version"
	"github.com/truvity/access-roster/policy"
)

// Config is the whole of the hub's configuration. The chart sets it from
// the values; the defaults are what a laptop needs.
//
// Read from the environment, and that is the contract worth testing: four
// of these were being read here and set nowhere, which is invisible until
// a deployment behaves differently from every local run.
type Config struct {
	apiPort     int
	consolePort int
	healthPort  int

	freshness hub.Config

	demo      bool
	publicURL string
	// publicRootURL is the host's root, never carrying route.pathPrefix
	// (INF-687) even where publicURL does: the bootstrap surface -- the
	// admin-consent callback, and this hub's own sign-in when it runs
	// one -- stays at the domain root on its own HTTPRoute. Empty falls
	// back to publicURL in the console, which is exactly right wherever
	// no prefix is configured.
	publicRootURL     string
	recoveryEnabled   bool
	recoveryAccount   string
	recoveryAudience  string
	apiAudience       string
	consumersPath     string
	loginDirectory    bool
	adminPassword     string
	sessionLifetime   time.Duration
	secureCookies     bool
	forwardedHeader   string
	forwardedIssuer   string
	signOutURL        string
	forwardedAudience string
	policyPath        string
	overlayPath       string
	store             string
	release           string
	oauthSecretName   string
	oauthIDKey        string
	oauthSecretKey    string
	valkey            valkey.Config
	auditEvents       int64
	auditS3           s3audit.Config
	// auditForwardedForTrustedHops is how many of the deployment's own
	// proxies append to X-Forwarded-For; zero records the peer.
	auditForwardedForTrustedHops int
	holdWindow                   time.Duration
	logLevel                     slog.Level
	// githubRunnerTiers are the tiers an operator may create a runner App
	// for, from GITHUB_RUNNER_TIERS, comma-separated. Empty keeps none.
	githubRunnerTiers []string
	// githubCatalogue is every GitHub App the deployment declares, from
	// the file GITHUB_APPS_CATALOGUE_FILE names. Empty declares none.
	githubCatalogue *catalogue.Catalogue
}

// Load reads the configuration from the environment.
func Load() (Config, error) {
	c := Config{
		apiPort:           envInt("API_PORT", 8080),
		consolePort:       envInt("CONSOLE_PORT", 8081),
		healthPort:        envInt("HEALTH_PORT", 7070),
		demo:              envBool("DEMO", false),
		publicURL:         strings.TrimSuffix(envString("PUBLIC_URL", ""), "/"),
		publicRootURL:     strings.TrimSuffix(envString("PUBLIC_ROOT_URL", ""), "/"),
		recoveryEnabled:   envBool("RECOVERY_ENABLED", true),
		recoveryAccount:   envString("RECOVERY_SERVICE_ACCOUNT", "directory-roster-recovery"),
		recoveryAudience:  envString("RECOVERY_AUDIENCE", "directory-roster-recovery"),
		apiAudience:       envString("API_AUDIENCE", "directory-roster"),
		consumersPath:     envString("CONSUMERS_FILE", ""),
		loginDirectory:    envBool("LOGIN_DIRECTORY", true),
		adminPassword:     envString("ADMIN_PASSWORD", ""),
		forwardedHeader:   envString("FORWARDED_EMAIL_HEADER", ""),
		forwardedIssuer:   envString("FORWARDED_ISSUER", ""),
		signOutURL:        envString("SIGN_OUT_URL", ""),
		forwardedAudience: envString("FORWARDED_AUDIENCE", ""),
		policyPath:        envString("POLICY_DIR", ""),
		overlayPath:       envString("OVERLAY_FILE", ""),
		store:             envString("STORE", "memory"),
		release:           envString("RELEASE_NAME", "directory-roster"),
		oauthSecretName:   envString("OAUTH_CLIENT_SECRET_NAME", ""),
		oauthIDKey:        envString("OAUTH_CLIENT_ID_KEY", ""),
		oauthSecretKey:    envString("OAUTH_CLIENT_SECRET_KEY", ""),
	}
	c.auditEvents = int64(envInt("AUDIT_MAX_EVENTS", audit.DefaultMemoryEvents))
	c.auditForwardedForTrustedHops = envInt("AUDIT_FORWARDED_FOR_TRUSTED_HOPS", 0)
	if c.auditForwardedForTrustedHops < 0 {
		c.auditForwardedForTrustedHops = 0
	}
	c.auditS3 = s3audit.Config{
		Bucket: envString("AUDIT_S3_BUCKET", ""),
		Region: envString("AUDIT_S3_REGION", ""),
		Prefix: envString("AUDIT_S3_PREFIX", s3audit.DefaultPrefix),
		Writer: envString("POD_NAME", ""),
	}
	c.valkey = valkey.Config{
		Address:  envString("VALKEY_ADDRESS", ""),
		Password: envString("VALKEY_PASSWORD", ""),
		TLS:      envBool("VALKEY_TLS", false),
		Cluster:  envBool("VALKEY_CLUSTER", true),
		Prefix:   envString("RELEASE_NAME", "directory-roster"),
	}
	// Secure follows the scheme the BROWSER will use, which the service
	// knows because it is told its own public URL. Defaulting to false
	// meant an installation that merely forgot to say so served session
	// cookies a proxy could strip onto a plain-http hop, and the alert
	// CodeQL raised was about that default rather than about this line.
	// SECURE_COOKIES still overrides, in either direction, for the local
	// http listener and for a TLS terminator that is not in the URL.
	c.secureCookies = envBool("SECURE_COOKIES", strings.HasPrefix(c.publicRootURL, "https://"))

	var err error
	if c.auditS3.FlushInterval, err = envDuration("AUDIT_S3_FLUSH_INTERVAL", s3audit.DefaultFlushInterval); err != nil {
		return Config{}, err
	}
	if c.freshness.RefreshInterval, err = envDuration("REFRESH_INTERVAL", hub.DefaultRefreshInterval); err != nil {
		return Config{}, err
	}
	if c.freshness.FreshnessWindow, err = envDuration("FRESHNESS_WINDOW", hub.DefaultFreshnessWindow); err != nil {
		return Config{}, err
	}
	if c.freshness.ProbeInterval, err = envDuration("PROBE_INTERVAL", hub.DefaultProbeInterval); err != nil {
		return Config{}, err
	}
	if c.sessionLifetime, err = envDuration("SESSION_LIFETIME", 12*time.Hour); err != nil {
		return Config{}, err
	}
	if c.holdWindow, err = envDuration("HOLD_WINDOW", 4*time.Hour); err != nil {
		return Config{}, err
	}
	if c.publicURL == "" {
		c.publicURL = fmt.Sprintf("http://localhost:%d", c.consolePort)
	}
	if err = c.logLevel.UnmarshalText([]byte(envString("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("LOG_LEVEL: %w", err)
	}
	switch c.store {
	case storeMemory, storeKubernetes:
	default:
		return Config{}, fmt.Errorf("STORE: %q is neither %q nor %q", c.store, storeMemory, storeKubernetes)
	}
	for _, tier := range strings.Split(envString("GITHUB_RUNNER_TIERS", ""), ",") {
		tier = strings.TrimSpace(tier)
		switch {
		case tier == "" || slices.Contains(c.githubRunnerTiers, tier):
		case !runnerapp.ValidTier(tier):
			return Config{}, fmt.Errorf("GITHUB_RUNNER_TIERS: %q is not a tier: lower-case letters, digits and dashes, at most 16", tier)
		default:
			c.githubRunnerTiers = append(c.githubRunnerTiers, tier)
		}
	}
	// A malformed catalogue stops the service: an App created from a wrong
	// declaration holds the wrong permissions, and nothing here can change
	// them afterwards.
	if c.githubCatalogue, err = catalogue.Load(envString("GITHUB_APPS_CATALOGUE_FILE", "")); err != nil {
		return Config{}, fmt.Errorf("GITHUB_APPS_CATALOGUE_FILE: %w", err)
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
func openSnapshots(ctx context.Context, cfg Config, log *slog.Logger) (hub.SnapshotStore, func(), error) {
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

// openAudit builds the one writer of the whole service's audit trail: in
// S3, the durable record the console also reads, and never in Valkey
// (decided 2026-09-13). Without a bucket it is kept in memory, which is one
// replica's own and gone on restart: right for a laptop and for tests, and
// said loudly anywhere else.
//
// What it returns is the writer's side of the AuditSinkService contract;
// the service records and reads through the client side of it, in process
// (sinkrpc.InProcess). A writer in another process would be the same
// contract behind the generated client, and nothing that records would
// change.
func openAudit(ctx context.Context, cfg Config, log *slog.Logger) (directoryrosterv1connect.AuditSinkServiceHandler, func(), error) {
	if cfg.auditS3.Bucket == "" {
		log.WarnContext(ctx, "keeping the audit trail in memory: one replica's own, gone on restart, and NOT a record; "+
			"set audit.s3.bucket for a durable trail", "audit", "memory")
		return audit.NewMemoryWriter(int(cfg.auditEvents)), func() {}, nil
	}
	trail, err := s3audit.Open(ctx, cfg.auditS3, log)
	if err != nil {
		return nil, nil, err
	}
	log.InfoContext(ctx, "keeping the audit trail in S3", "audit", "s3",
		"bucket", cfg.auditS3.Bucket, "prefix", cfg.auditS3.Prefix, "flushInterval", cfg.auditS3.FlushInterval)
	return trail, func() {
		// What is queued is written before the process goes, within a
		// bound: a shutdown that cannot reach S3 still ends, and every
		// event it could not write is already a log line.
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		if closeErr := trail.Close(closing); closeErr != nil {
			log.ErrorContext(ctx, "the audit trail could not be written before shutdown; those events are in the log only",
				"error", closeErr)
		}
	}, nil
}

// openRecovery builds the way in for the day the ordinary one is broken.
//
// In a cluster there is already an authority that says who is trusted —
// the API server — so recovery proves access to it and the hub keeps no
// credential at all: nothing to rotate, nothing to leak, nothing to find
// in an etcd backup, and an audit trail that names who recovered rather
// than "admin". Anywhere else there is nothing to prove access to, so a
// generated password is what is left, and it is printed once.
func openRecovery(ctx context.Context, cfg Config, kept stores, log *slog.Logger) (server.Recovery, error) {
	if !cfg.recoveryEnabled {
		log.InfoContext(ctx, "no recovery sign-in: this hub can only be entered through the directory")
		return nil, nil //nolint:nilnil // no recovery is a configuration, not a failure
	}
	if kept.reviewToken == nil {
		password := cfg.adminPassword
		if password == "" {
			generated, err := generatedPassword()
			if err != nil {
				return nil, err
			}
			password = generated
			announceRecoveryPassword(password)
		}
		return server.NewPasswordRecovery(password), nil
	}

	subject := kube.ServiceAccountSubject(kept.namespace, cfg.recoveryAccount)
	log.InfoContext(ctx, "recovery is by cluster access; nothing is stored",
		"serviceAccount", cfg.recoveryAccount, "audience", cfg.recoveryAudience, "subject", subject)
	return &server.TokenRecovery{
		Review:    kept.reviewToken,
		Namespace: kept.namespace,
		Account:   cfg.recoveryAccount,
		Audience:  cfg.recoveryAudience,
		Subjects:  []string{subject},
	}, nil
}

// consumers builds the API listener's guard.
//
// The listener answers everything the hub knows about every company it
// serves, so who may call it is not a detail. Outside a cluster there is
// nothing to verify a token against and the listener is open — a
// development posture, said out loud at start rather than discovered. In
// a cluster it admits exactly the ServiceAccounts the deployment names,
// and a deployment that names none admits nobody, because a hub that
// answered everyone by default would be one forgotten value away from
// serving a directory to the whole cluster.
func consumers(
	ctx context.Context, cfg Config, kept stores, declared *server.ConsumerFile, log *slog.Logger,
) *server.Consumers {
	if kept.reviewToken == nil {
		log.WarnContext(ctx, "the API listener is unauthenticated: nothing here can verify a "+
			"ServiceAccount token, so anything that can reach it gets every account and group "+
			"this hub reads", "port", cfg.apiPort)
		return nil
	}
	// One spelling for who may call: the mounted file (INF-679). It
	// replaced a comma-separated environment list, which could name a
	// consumer and could not describe what that consumer may ask -- and
	// keeping both would have been one place to add a consumer and
	// another place to forget to.
	allowed := make([]string, 0)
	grants := map[string]*server.Grant{}
	if declared != nil {
		for i := range declared.Consumers {
			consumer := &declared.Consumers[i]
			subject := kube.ServiceAccountSubject(consumer.Namespace, consumer.ServiceAccount)
			allowed = append(allowed, subject)
			if grant := consumer.Grant(); grant != nil {
				grants[subject] = grant
			}
		}
	}
	if len(allowed) == 0 {
		log.WarnContext(ctx, "the API listener admits nobody: no consumers are declared", "port", cfg.apiPort)
	} else {
		// The scoped ones by name: a grant an operator cannot see at
		// start is one they have to reconstruct from a ConfigMap when a
		// consumer says it cannot see something.
		scoped := make([]string, 0, len(grants))
		for subject := range grants {
			scoped = append(scoped, subject)
		}
		sort.Strings(scoped)
		log.InfoContext(ctx, "the API listener admits the declared consumers",
			"audience", cfg.apiAudience, "consumers", allowed, "scoped", scoped)
	}
	return &server.Consumers{
		Review:   kept.reviewToken,
		Audience: cfg.apiAudience,
		Allowed:  allowed,
		Grants:   grants,
		Log:      log,
	}
}

// stores is everything the hub writes down, and where.
type stores struct {
	workspaces  hub.Store
	credentials hub.CredentialStore
	settings    settings.Store
	sessionKey  []byte
	// reviewToken asks the cluster's API server who a token
	// authenticates. Nil outside a cluster, which is what selects the
	// password shape of recovery.
	reviewToken func(ctx context.Context, token string, audiences []string) (string, error)
	namespace   string
	// github is where the GitHub controller reports. Nil with the memory
	// store, which has nowhere a separate process could write to.
	github *kube.GitHubStatus
	// githubOrgs is where connected GitHub organisations are kept. Nil
	// with the memory store, for the same reason.
	githubOrgs *kube.GitHubOrgs
	// githubLinks is where people's linked GitHub accounts are kept. Nil
	// with the memory store, for the same reason.
	githubLinks *kube.GitHubLinks
	// githubRunnerApps is where runner Apps are kept. Nil with the memory
	// store, for the same reason.
	githubRunnerApps *kube.GitHubRunnerApps
	// githubCatalogueApps is where catalogue Apps are kept. Nil with the
	// memory store, for the same reason.
	githubCatalogueApps *kube.GitHubCatalogueApps
}

// openStores builds them, and says plainly in the log which was chosen.
// The memory store losing everything on restart is correct for a
// prototype and catastrophic for a deployment, so it is never silent.
func openStores(ctx context.Context, cfg Config, log *slog.Logger) (stores, error) {
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
	// The report the GitHub controller writes into is created HERE, by the
	// service, so that the controller's Role can name the one object it
	// updates: `create` cannot be narrowed to a name. Cheap and idempotent,
	// so it is done whether or not a controller is deployed, and a failure
	// is a warning — the directory works without it.
	github := kube.NewGitHubStatus(client)
	if err = github.Ensure(ctx); err != nil {
		log.WarnContext(ctx, "the GitHub status report could not be created; the GitHub page will show bindings only",
			"configMap", github.Name(), "error", err)
	}
	// And the two objects connecting an organisation writes into, empty,
	// so the controller's Secret volume always has a Secret behind it.
	githubOrgs := kube.NewGitHubOrgs(client)
	if err = githubOrgs.Ensure(ctx); err != nil {
		log.WarnContext(ctx, "the objects GitHub organisations are connected into could not be created",
			"configMap", githubOrgs.ConfigMapName(), "secret", githubOrgs.SecretName(), "error", err)
	}
	// And the Secret people's links are written into, so the controller's
	// Role can name an object that exists.
	githubLinks := kube.NewGitHubLinks(client)
	if err = githubLinks.Ensure(ctx); err != nil {
		log.WarnContext(ctx, "the Secret GitHub accounts are linked into could not be created",
			"secret", githubLinks.Name(), "error", err)
	}
	// And the Secret runner Apps are kept in, so a deployment copying it
	// finds it before the first App is created.
	githubRunnerApps := kube.NewGitHubRunnerApps(client)
	if err = githubRunnerApps.Ensure(ctx); err != nil {
		log.WarnContext(ctx, "the Secret runner Apps are kept in could not be created",
			"secret", githubRunnerApps.SecretName(), "error", err)
	}
	// And the Secret catalogue Apps are kept in, for the same reason.
	githubCatalogueApps := kube.NewGitHubCatalogueApps(client)
	if err = githubCatalogueApps.Ensure(ctx); err != nil {
		log.WarnContext(ctx, "the Secret catalogue Apps are kept in could not be created",
			"secret", githubCatalogueApps.SecretName(), "error", err)
	}
	// Each connection's credential carries its record, so the GitHub Apps
	// Secret alone restores every organisation: put back a record a
	// restore left missing, and copy records into credentials written
	// before they carried one.
	if changed, err := githubOrgs.ReconcileRecords(ctx); err != nil {
		log.WarnContext(ctx, "the GitHub connections' records and credentials could not be reconciled",
			"configMap", githubOrgs.ConfigMapName(), "secret", githubOrgs.SecretName(), "error", err)
	} else if len(changed) > 0 {
		log.InfoContext(ctx, "reconciled GitHub connection records with their credentials", "keys", changed)
	}
	// Workspace credentials are one Secret, each entry carrying its
	// workspace's record, for the same reason. An older release kept one
	// Secret per workspace: those move in, and records a restore left
	// missing come back before the stored workspaces are reopened. A
	// failure warns rather than stops: an unmoved credential is still read
	// where it is.
	workspaces := kube.NewWorkspaces(client)
	credentials := kube.NewCredentials(client)
	if err = credentials.Ensure(ctx); err != nil {
		log.WarnContext(ctx, "the Secret workspace credentials are kept in could not be created",
			"secret", credentials.SecretName(), "error", err)
	}
	if moved, err := credentials.Migrate(ctx, workspaces); err != nil {
		log.WarnContext(ctx, "not every workspace credential could be moved into one Secret; the rest are read where they are",
			"secret", credentials.SecretName(), "moved", moved, "error", err)
	} else if len(moved) > 0 {
		log.InfoContext(ctx, "moved workspace credentials into one Secret",
			"secret", credentials.SecretName(), "workspaces", moved)
	}
	if restored, err := credentials.RestoreRecords(ctx, workspaces); err != nil {
		log.WarnContext(ctx, "workspace records missing beside their credentials could not be restored",
			"secret", credentials.SecretName(), "restored", restored, "error", err)
	} else if len(restored) > 0 {
		log.InfoContext(ctx, "restored workspace records from their credentials", "workspaces", restored)
	}
	return stores{
		github:      github,
		githubOrgs:  githubOrgs,
		githubLinks: githubLinks,
		// runner Apps are created only for declared tiers, but the store
		// is kept either way: an App created before a tier was dropped
		// stays visible, so it can be disconnected.
		githubRunnerApps: githubRunnerApps,
		// Likewise an App whose entry the catalogue no longer declares.
		githubCatalogueApps: githubCatalogueApps,
		workspaces:          workspaces,
		credentials:         credentials,
		settings: kube.NewSettings(client, kube.DeclaredClient{
			Name:      cfg.oauthSecretName,
			IDKey:     cfg.oauthIDKey,
			SecretKey: cfg.oauthSecretKey,
		}),
		sessionKey:  key,
		reviewToken: client.ReviewToken,
		namespace:   client.Namespace(),
	}, nil
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// App is an assembled hub: three handlers and the background loops.
type App struct {
	api     http.Handler
	console http.Handler
	health  http.Handler
	ready   health.Dependency
	server  *server.ConsoleServer
	policy  *policy.Set
	hub     *hub.Hub
	cfg     Config
	log     *slog.Logger
	close   func()
	audit   audit.Recorder
	// catalogueApps is where created catalogue Apps are kept, nil where
	// the deployment keeps no state in Kubernetes.
	catalogueApps server.GitHubCatalogueApps
}

// Audit is the service's one recorder, for the half assembled after this
// one: both halves write one history.
func (a *App) Audit() audit.Recorder { return a.audit }

// AuditRequests puts what an audit event keeps of each request into the
// context of everything next serves, with this deployment's decision on
// X-Forwarded-For. The merged service wraps the issuer's whole origin in
// it, so a token exchange records where it came from as a console call
// does.
func (a *App) AuditRequests(next http.Handler) http.Handler {
	return server.AuditRequests(a.cfg.auditForwardedForTrustedHops, next)
}

// APIHandler is the DirectoryService listener, guarded.
func (a *App) APIHandler() http.Handler { return a.api }

// ConsoleHandler is the operator listener: services, login, the SPA.
func (a *App) ConsoleHandler() http.Handler { return a.console }

// HealthHandler is liveness and readiness.
func (a *App) HealthHandler() http.Handler { return a.health }

// Hub is the directory hub itself, for a caller that drives it directly.
func (a *App) Hub() *hub.Hub { return a.hub }

// ConsoleServer is the console's own server, for a caller that has to
// finish wiring it after both halves exist.
func (a *App) ConsoleServer() *server.ConsoleServer { return a.server }

// Policy is the policy in force, for a caller that has to act on the
// SAME one.
//
// The merged service loads it once and hands it to both halves
// (INF-691). Two halves loading it independently is precisely the class
// of failure the merge existed to end: they read the same file today,
// but their fallbacks differ, so a deployment that configured neither
// would run a directory answering from a built-in policy and an issuer
// refusing to start — or worse, two policies that agree until one of
// them is changed.
func (a *App) Policy() *policy.Set { return a.policy }

// GitHubCatalogue is every GitHub App the deployment declares, for the
// half that mints their installation tokens under its grants.
func (a *App) GitHubCatalogue() *catalogue.Catalogue { return a.cfg.githubCatalogue }

// GitHubCatalogueApps is where created catalogue Apps and their keys are
// kept, or nil where the deployment keeps none: what the issuer half
// reads an App's key from to mint a token.
func (a *App) GitHubCatalogueApps() server.GitHubCatalogueApps { return a.catalogueApps }

// Readiness is the snapshot store as a dependency, for a caller that
// assembles a health endpoint of its own. The merged service has one
// /readyz answering for both halves, and a half that cannot read a
// snapshot cannot answer anything.
func (a *App) Readiness() health.Dependency { return a.ready }

// RunLoops drives the refresher and the probes, and serves nothing.
//
// It is what the merged service runs (INF-691): one process, one set of
// listeners, and this half contributing its background work rather than
// three listeners of its own.
func (a *App) RunLoops(ctx context.Context) error { return a.hub.Run(ctx) }

// Close releases what New opened.
func (a *App) Close() {
	if a.close != nil {
		a.close()
	}
}

// New assembles the hub. The caller runs it with [App.Run] and releases
// it with [App.Close].
func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}
	kept, err := openStores(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	snapshots, closeSnapshots, err := openSnapshots(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	auditWriter, closeAudit, err := openAudit(ctx, cfg, log)
	if err != nil {
		closeSnapshots()
		return nil, err
	}
	closeStores := func() { closeAudit(); closeSnapshots() }
	auditSink := sinkrpc.InProcess(auditWriter)
	// The pod's name, as the S3 writer's keys use: a log line's event id
	// then names the replica that recorded it.
	recorder := audit.NewLog(log, auditSink, cfg.auditS3.Writer)

	directory := hub.New(kept.workspaces, snapshots, cfg.freshness, log)
	if kept.credentials != nil {
		directory.UseCredentials(kept.credentials)
	}

	declared, err := declaredPolicy(cfg.policyPath, cfg.demo)
	if err != nil {
		return nil, err
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		return nil, err
	}

	// A name is a convention, not a rule, so this is said and not
	// refused: the policy works either way, and an installation mid-
	// rename holds both shapes at once. What the convention buys is that
	// a reader tells a grant from an identity by looking, and the place
	// to notice a name that broke it is here, at load, rather than in a
	// token six months later.
	if odd := declared.UnconventionalGroups(); len(odd) > 0 {
		log.WarnContext(ctx, "some group names are neither a grant nor an identity",
			"groups", odd,
			"grant", "<scope>:<thing>:<role>",
			"identity", "rung:<name>, emp:<slug>")
	}

	// A grant naming a group the policy does not declare would read as
	// though somebody may ask for a token, and nobody could.
	if undeclared := cfg.githubCatalogue.UndeclaredGroups(set.HasGroup); len(undeclared) > 0 {
		return nil, fmt.Errorf("GITHUB_APPS_CATALOGUE_FILE: grants name groups the policy does not declare: %s",
			strings.Join(undeclared, "; "))
	}

	authorizer := access.NewAuthorizer(set, directory, cfg.holdWindow)

	sessionKey := kept.sessionKey
	sessions, err := access.NewSessions(sessionKey, cfg.sessionLifetime, cfg.secureCookies)
	if err != nil {
		return nil, err
	}

	recovery, err := openRecovery(ctx, cfg, kept, log)
	if err != nil {
		return nil, err
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
		return google.OAuthClient{ID: stored.ID, Secret: stored.Secret, BaseURL: cfg.publicURL}, nil
	}

	connectors := []server.Connector{connector.NewGoogle(oauthClient)}
	loginSources := []string{}
	if cfg.demo {
		connectors = append(connectors, seedDemo(ctx, directory, cfg.publicURL, log))
	}
	if !cfg.loginDirectory {
		log.InfoContext(ctx, "the hub's own sign-in is off: the ways in are a gateway that "+
			"forwards an identity, and recovery. Connecting a directory is unaffected")
	}
	adopted, err := adoptDeclared(ctx, directory, cfg.overlayPath, log)
	if err != nil {
		return nil, err
	}
	if err = reopenStored(ctx, directory, kept, adopted, oauthClient, log); err != nil {
		return nil, err
	}
	// And from here the hub can open a workspace on its own. Reopening at
	// start covers what existed at start; this covers a workspace another
	// replica connected a minute ago, which start-up cannot know about.
	if kept.credentials != nil {
		directory.UseReopener(func(ctx context.Context, ws hub.Workspace, cred backend.Credential) (backend.Backend, error) {
			return openStored(ctx, ws.Backend, cred, oauthClient)
		})
	}
	// Two forwarded paths, reported apart: an operator reading the start-up
	// line should be able to tell a console that VERIFIES a gateway's token
	// from one that TRUSTS a gateway's header, because the second is only
	// as strong as whatever keeps other pods off this port.
	if cfg.forwardedIssuer != "" {
		loginSources = append(loginSources, "forwarded-bearer:"+cfg.forwardedIssuer)
	}
	if cfg.forwardedHeader != "" {
		loginSources = append(loginSources, "forwarded-header:"+cfg.forwardedHeader)
	}
	if cfg.recoveryEnabled {
		loginSources = append(loginSources, "recovery")
	}
	if cfg.loginDirectory {
		loginSources = append(loginSources, "directory")
	}

	console, err := server.NewConsole(ctx, server.ConsoleDeps{
		Hub:          directory,
		Authorizer:   authorizer,
		Settings:     kept.settings,
		State:        access.NewStateCodec(sessionKey, 10*time.Minute),
		Connectors:   connectors,
		Recovery:     recovery,
		LoginSources: loginSources,
		CacheBackend: cacheName(cfg),
		SecureCookie: cfg.secureCookies,
		PublicURL:    cfg.publicURL,
		RootURL:      cfg.publicRootURL,
		IssuerURL:    cfg.forwardedIssuer,
		SignIn:       cfg.loginDirectory,
		GitHub:       githubReports(kept.github, cfg.demo),
		GitHubOrgs:   githubConnections(kept.githubOrgs, cfg.demo),
		// Typed nils again: an interface holding a nil store is not nil.
		GitHubLinkApp:       githubLinkApp(kept.githubOrgs, cfg.demo),
		GitHubLinks:         githubLinks(kept.githubLinks, cfg.demo),
		GitHubConfirmations: githubConfirmations(kept.githubOrgs),
		GitHubRunnerApps:    githubRunnerApps(kept.githubRunnerApps),
		GitHubRunnerTiers:   cfg.githubRunnerTiers,
		GitHubCatalogue:     cfg.githubCatalogue,
		GitHubCatalogueApps: githubCatalogueApps(kept.githubCatalogueApps),
		Audit:               recorder,
		AuditSink:           auditSink,
	})
	if err != nil {
		return nil, err
	}

	consoleServer := server.NewConsoleServer(server.ConsoleServerDeps{
		Console:    console,
		Authorizer: authorizer,
		Sessions:   sessions,
		State:      access.NewStateCodec(sessionKey, 10*time.Minute),
		Connectors: connectors,
		Hub:        directory,
		Recovery:   recovery,
		Forwarded: server.ForwardedIdentity{
			Issuer:      cfg.forwardedIssuer,
			Audience:    cfg.forwardedAudience,
			EmailHeader: cfg.forwardedHeader,
		},
		SignIn:     cfg.loginDirectory,
		SignOutURL: cfg.signOutURL,
		// Where this console sits on its origin, read from the address it
		// is published at rather than configured twice. The handlers
		// never see the prefix — the gateway strips it, and so does the
		// merged process — but every link they hand a browser has to
		// carry it.
		Mount:                   mountOf(cfg.publicURL),
		ForwardedForTrustedHops: cfg.auditForwardedForTrustedHops,
		Log:                     log,
		UI:                      frontend.FS(),
	})

	apiMux := http.NewServeMux()
	apiMux.Handle(directoryv1connect.NewDirectoryServiceHandler(server.NewDirectory(directory)))
	// Loaded before the listener is built: a malformed grant is a
	// start-up failure, because a hub that ignored one would run with a
	// wider grant than the deployment declared.
	declaredConsumers, err := server.LoadConsumers(cfg.consumersPath)
	if err != nil {
		return nil, err
	}
	apiHandler := consumers(ctx, cfg, kept, declaredConsumers, log).Middleware(apiMux)

	// Readiness follows the snapshot store; liveness does not. A hub
	// that cannot read a snapshot cannot answer anything, and saying
	// ready through that is how a moved Valkey became a half-hour of
	// hanging requests on 2026-09-10 with every pod green.
	ready := health.Follow("the snapshot store", snapshots)
	healthMux := health.Mux(0, ready)

	// "the directory", not the old service name: in the merged process
	// this is one half of one deployment, and a line naming a service
	// reads as a second one having started.
	log.InfoContext(ctx, "the directory is assembled",
		"api", cfg.apiPort, "console", cfg.consolePort, "health", cfg.healthPort,
		"demo", cfg.demo, "recovery", recoveryKind(recovery), "public", cfg.publicURL,
		"signIn", cfg.loginDirectory, "cache", cacheName(cfg), "store", cfg.store,
		"version", version.String(), "policy", policySource(cfg.policyPath, cfg.demo))

	return &App{
		api:     apiHandler,
		console: consoleServer.Handler(),
		health:  healthMux,
		ready:   ready,
		server:  consoleServer,
		policy:  set,
		hub:     directory,
		cfg:     cfg,
		log:     log,
		close:   closeStores,
		audit:   recorder,

		catalogueApps: githubCatalogueApps(kept.githubCatalogueApps),
	}, nil
}

// Run serves the three listeners and drives the hub's background loops
// until the context is done.
func (a *App) Run(ctx context.Context) error {
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(gctx, a.cfg.apiPort, a.api, "api", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.consolePort, a.console, "console", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.healthPort, a.health, "health", a.log) })
	group.Go(func() error { return a.hub.Run(gctx) })
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

// mountOf is the path part of the address the console is published at:
// "/console" from https://access.example/console, and empty from
// https://console.example, which is a console with an origin to itself.
//
// An unparseable address yields no prefix, which is the standalone shape
// and the one that was right before any of this existed.
func mountOf(publicURL string) string {
	parsed, err := url.Parse(publicURL)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(parsed.Path, "/")
}

// builtinPolicy is what a hub with no declared policy starts from: the two
// groups it is a relying party of, empty. Nobody is in them, so nobody but
// the break-glass admin can act until an operator attaches the first
// directory group in the console — which is day one, exactly as the
// runbook describes it.
const builtinPolicy = `
version: 1
groups:
  all:access-roster:operator: {}
  all:access-roster:viewer: {}
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
			SyncGroups: declared.SyncGroups,
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

// announceRecoveryPassword prints the generated password once. It is only
// reached outside a cluster: in one, recovery proves cluster access and
// there is no password to print.
func announceRecoveryPassword(password string) {
	fmt.Fprintf(os.Stderr, "\n  recovery password (generated for this run): %s\n"+
		"  Sign in at /login, under Recovery sign-in.\n\n",
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
func cacheName(cfg Config) string {
	if cfg.valkey.Address == "" {
		return "memory"
	}
	return "valkey"
}

// recoveryKind names the shape of the recovery path for the startup line.
func recoveryKind(r server.Recovery) string {
	if r == nil {
		return "none"
	}
	return r.Kind()
}

// githubReports is the store as the console's interface, or nil. A typed
// nil stored in an interface is not nil, and the console reads nil as
// "this deployment keeps no reports" — so the conversion is explicit.
//
// A demonstration run with no Kubernetes gets the demonstration report
// instead, so the GitHub page can be walked through like every other.
func githubReports(store *kube.GitHubStatus, demonstration bool) server.GitHubReports {
	switch {
	case store != nil:
		return store
	case demonstration:
		return fixedReports(demo.GitHubReports(time.Now()))
	default:
		return nil
	}
}

// fixedReports is a report that never changes.
type fixedReports map[string]string

func (r fixedReports) Reports(context.Context) (map[string]string, error) { return r, nil }

// githubConnections is the store as the console's interface, or nil — for
// the same typed-nil reason as githubReports. A demonstration run with no
// Kubernetes shows its one organisation connected, and connects nothing.
func githubConnections(store *kube.GitHubOrgs, demonstration bool) server.GitHubConnections {
	switch {
	case store != nil:
		return store
	case demonstration:
		return demoConnections{record: demo.GitHubConnection(time.Now())}
	default:
		return nil
	}
}

// githubRunnerApps is the store as the console's interface, or nil.
func githubRunnerApps(store *kube.GitHubRunnerApps) server.GitHubRunnerApps {
	if store == nil {
		return nil
	}
	return store
}

// githubCatalogueApps is the store as the console's interface, or nil.
func githubCatalogueApps(store *kube.GitHubCatalogueApps) server.GitHubCatalogueApps {
	if store == nil {
		return nil
	}
	return store
}

// githubLinkApp is the store as the console's interface, or nil. A
// demonstration run shows a link App already created.
func githubLinkApp(store *kube.GitHubOrgs, demonstration bool) server.GitHubLinkApp {
	switch {
	case store != nil:
		return store
	case demonstration:
		return demoLinkApp{app: demo.GitHubLinkApp(time.Now())}
	default:
		return nil
	}
}

// githubLinks is the store as the console's interface, or nil. A
// demonstration run shows a few links, and links nobody.
func githubLinks(store *kube.GitHubLinks, demonstration bool) server.GitHubLinks {
	switch {
	case store != nil:
		return store
	case demonstration:
		return demoLinks{links: demo.GitHubLinks(time.Now())}
	default:
		return nil
	}
}

// demoLinkApp is a fixed link App that nobody can authorize.
type demoLinkApp struct{ app link.App }

func (d demoLinkApp) LinkApp(context.Context) (link.App, bool, error) { return d.app, true, nil }

func (demoLinkApp) LinkAppCredential(context.Context) (link.AppCredential, bool, error) {
	return link.AppCredential{}, false, nil
}

func (demoLinkApp) PutLinkApp(context.Context, link.App, link.AppCredential) error {
	return errDemoConnect
}

func (demoLinkApp) DeleteLinkApp(context.Context) error { return errDemoConnect }

// demoLinks are fixed links.
type demoLinks struct{ links []link.Link }

func (d demoLinks) List(context.Context) ([]link.Link, error) { return d.links, nil }

func (demoLinks) Claim(context.Context, link.Link, time.Time) ([]link.Link, error) {
	return nil, errDemoConnect
}

func (demoLinks) Invalidate(context.Context, string, time.Time) (int, error) {
	return 0, errDemoConnect
}

func (demoLinks) Adopt(context.Context, []link.Link) ([]link.Link, map[int64]string, error) {
	return nil, nil, errDemoConnect
}

// githubConfirmations is the store as the console's interface, or nil. A
// demonstration run confirms nothing: there is nothing to remove.
func githubConfirmations(store *kube.GitHubOrgs) server.GitHubConfirmations {
	if store == nil {
		return nil
	}
	return store
}

// errDemoConnect is what a demonstration run says when asked to change a
// connection: there is no GitHub organisation behind it.
var errDemoConnect = errors.New("a demonstration run connects and disconnects nothing: there is no GitHub organisation behind it")

// demoConnections is one fixed, connected organisation.
type demoConnections struct{ record connection.Record }

func (d demoConnections) List(context.Context) ([]connection.Record, error) {
	return []connection.Record{d.record}, nil
}

func (demoConnections) Credential(context.Context, string) (connection.Credential, bool, error) {
	return connection.Credential{}, false, nil
}

func (demoConnections) Put(context.Context, connection.Record, connection.Credential) error {
	return errDemoConnect
}

func (demoConnections) Delete(context.Context, string) error { return errDemoConnect }
