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
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/connector"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubapp/mints"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/health"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
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
	// even where publicURL does: the bootstrap surface -- the
	// admin-consent callback, and this hub's own sign-in when it runs
	// one -- stays at the domain root on its own HTTPRoute. Empty falls
	// back to publicURL in the console, which is exactly right wherever
	// no prefix is configured.
	publicRootURL    string
	recoveryEnabled  bool
	recoveryAccount  string
	recoveryAudience string
	apiAudience      string
	consumersPath    string
	loginDirectory   bool
	adminPassword    string
	sessionLifetime  time.Duration
	// absoluteLifetime caps the console's own session the same way it caps
	// a per-client one in the issuer: read from the SAME environment
	// variable the issuer's config reads (ABSOLUTE_LIFETIME), because the
	// two run in one process and one pod sets it once. See
	// issuer.DefaultAbsoluteLifetime for why 24h.
	absoluteLifetime  time.Duration
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
	// audit is the audit installation this service connects to, if any.
	audit audit.Config
	// auditQuery is its query service, for the console's Audit page, and
	// auditAudience the client whose audience the page's tokens carry.
	auditQuery    string
	auditAudience string
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
	c.audit = audit.Config{
		Writer:    envString("AUDIT_WRITER_URL", ""),
		TokenFile: envString("AUDIT_TOKEN_FILE", ""),
		Instance:  envString("POD_NAME", ""),
		Version:   version.String(),
	}
	c.auditQuery = envString("AUDIT_QUERY_URL", "")
	c.auditAudience = envString("AUDIT_AUDIENCE", "audit")
	c.auditForwardedForTrustedHops = envInt("AUDIT_FORWARDED_FOR_TRUSTED_HOPS", 0)
	if c.auditForwardedForTrustedHops < 0 {
		c.auditForwardedForTrustedHops = 0
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
	// Defaulted and never refused here: ABSOLUTE_LIFETIME's own validation
	// (positive, at least TOKEN_LIFETIME) runs once, in issuerapp.Load,
	// which the same pod always loads beside this. A value that failed it
	// never reaches here in a real deployment; a test building [Config]
	// directly gets the ordinary 24h default rather than a second copy of
	// a check it may not care about.
	if c.absoluteLifetime, err = envDuration("ABSOLUTE_LIFETIME", 24*time.Hour); err != nil {
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
	// The console's secret-store view was removed in v1.30.0. Refuse start-up
	// if an old configuration tries to activate it, with a message pointing
	// to the decision and the migration.
	if smf := envString("SECRET_MANAGERS_FILE", ""); smf != "" {
		return Config{}, errors.New(
			"SECRET_MANAGERS_FILE is no longer read: the console's secret-store " +
				"view was removed in v1.30.0 — see " +
				"docs/decisions/0002-mission-boundary-tokens-and-memberships.md",
		)
	}
	// A demonstration run declares its own tiers and catalogue, unless the
	// run declares some: the Apps page is otherwise the two Apps this
	// service makes for itself, and half the page cannot be walked through.
	if c.demo {
		if len(c.githubRunnerTiers) == 0 {
			c.githubRunnerTiers = demo.GitHubRunnerTiers()
		}
		if len(c.githubCatalogue.Apps) == 0 {
			c.githubCatalogue = demo.GitHubCatalogue()
		}
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
	// One spelling for who may call: the mounted file. It
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
	// relabel moves objects an older release labelled to the current
	// keys; see [kube.Client.RelabelLegacy]. Nil with the memory store.
	relabel func(context.Context) ([]string, error)
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
	// First, before anything lists by label: objects an older release
	// wrote carry the label keys it used, and the stores below read only
	// the current ones. A workspace record left under the old keys is a
	// workspace this process would not see, so a failure here stops the
	// start rather than serving a directory with workspaces missing.
	moved, err := client.RelabelLegacy(ctx)
	if err != nil {
		return stores{}, fmt.Errorf("move objects an older release labelled to the current label keys: %w", err)
	}
	if len(moved) > 0 {
		log.InfoContext(ctx, "moved objects an older release labelled to the current label keys", "objects", moved)
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
		relabel:     client.RelabelLegacy,
	}, nil
}

// legacyLabelSweep is how often the relabel runs again after start-up.
const legacyLabelSweep = time.Minute

// sweepLegacyLabels repeats the start-up relabel until ctx is done.
//
// A rolling upgrade runs replicas of the older release beside this one,
// and they keep writing objects under the old keys — a probe rewrites
// every workspace record — which this process would then not list. The
// sweep moves them within a minute. After the upgrade it finds nothing,
// at the cost of two List calls a minute.
func sweepLegacyLabels(ctx context.Context, relabel func(context.Context) ([]string, error), log *slog.Logger) error {
	if relabel == nil {
		return nil
	}
	tick := time.NewTicker(legacyLabelSweep)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			moved, err := relabel(ctx)
			if err != nil {
				log.WarnContext(ctx, "objects an older release labelled could not be moved to the current label keys",
					"objects", moved, "error", err)
			} else if len(moved) > 0 {
				log.InfoContext(ctx, "moved objects an older release labelled to the current label keys",
					"objects", moved)
			}
		}
	}
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// App is an assembled hub: three handlers and the background loops.
type App struct {
	// fatal carries the one error that ends the process from outside a
	// request: the audit installation refusing the catalogue after the start.
	fatal   chan error
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
	// githubMints is the last installation tokens asked of each App: made
	// here, read by the console's Apps pages, written by the half that
	// mints them. Nil where the deployment declares no App.
	githubMints *mints.Ring
	// relabel is the legacy label sweep's work, nil where the deployment
	// keeps no state in Kubernetes.
	relabel func(context.Context) ([]string, error)
}

// Audit is the service's one recorder, for the half assembled after this
// one: both halves write one history.
func (a *App) Audit() audit.Recorder { return a.audit }

// AuditQuery is the audit installation's query service and the audience
// the console's tokens for it carry, or an empty URL when none is
// connected. The merged service wires it to the issuer, which mints them.
func (a *App) AuditQuery() (queryURL, audience string) { return a.cfg.auditQuery, a.cfg.auditAudience }

// AuditRequests puts what an audit record keeps of each request into the
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
// The merged service loads it once and hands it to both halves.
// Two halves loading it independently is precisely the class
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

// GitHubMints is the ring of recent installation token requests, for the
// half that mints them to write into. The console reads the same ring:
// an App's page shows what this service minted without asking the audit
// trail for a listing narrowed to one App, which is a scan.
func (a *App) GitHubMints() *mints.Ring { return a.githubMints }

// Readiness is the snapshot store as a dependency, for a caller that
// assembles a health endpoint of its own. The merged service has one
// /readyz answering for both halves, and a half that cannot read a
// snapshot cannot answer anything.
func (a *App) Readiness() health.Dependency { return a.ready }

// RunLoops drives the refresher and the probes, and serves nothing.
//
// It is what the merged service runs: one process, one set of
// listeners, and this half contributing its background work rather than
// three listeners of its own.
func (a *App) RunLoops(ctx context.Context) error {
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return a.hub.Run(gctx) })
	group.Go(func() error { return sweepLegacyLabels(gctx, a.relabel, a.log) })
	return group.Wait()
}

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
	// The audit trail is an installation of this service's own, in its
	// namespace; without one, every record is a log line and nothing more.
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
	recorder, err := audit.Open(ctx, cfg.audit)
	if err != nil {
		closeSnapshots()
		return nil, err
	}
	closeStores := func() {
		if err := recorder.Close(); err != nil {
			log.WarnContext(ctx, "the audit emitter could not be closed cleanly; what its queue held is dropped",
				"error", err)
		}
		closeSnapshots()
	}

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
	sessions, err := access.NewSessions(sessionKey, cappedSessionLifetime(cfg.sessionLifetime, cfg.absoluteLifetime), cfg.secureCookies)
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

	// A demonstration run's Apps are signed for with a key made here, so
	// nothing outside this process ever accepts it.
	var demoAppKey string
	if cfg.demo {
		if demoAppKey, err = demo.GitHubAppKey(); err != nil {
			return nil, fmt.Errorf("a key for the demonstration Apps: %w", err)
		}
	}

	// The last installation tokens asked of each App, kept beside the half
	// that mints them so that an App's page need not ask the audit trail
	// for a listing narrowed to one App -- which is a scan of every hour's
	// objects, and outlived a gateway's patience. Only where an App is
	// declared: nothing else can mint one.
	var githubMints *mints.Ring
	if cfg.githubCatalogue != nil && len(cfg.githubCatalogue.Apps) > 0 {
		githubMints = mints.New(0, time.Now())
		if cfg.demo {
			demo.SeedGitHubMints(githubMints, time.Now())
		}
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
		GitHubOrgs:   githubConnections(kept.githubOrgs, cfg.demo, demoAppKey),
		// Typed nils again: an interface holding a nil store is not nil.
		GitHubLinkApp:       githubLinkApp(kept.githubOrgs, cfg.demo),
		GitHubLinks:         githubLinks(kept.githubLinks, cfg.demo),
		GitHubConfirmations: githubConfirmations(kept.githubOrgs),
		GitHubRunnerApps:    githubRunnerApps(kept.githubRunnerApps, cfg.demo, demoAppKey),
		GitHubRunnerTiers:   cfg.githubRunnerTiers,
		GitHubCatalogue:     cfg.githubCatalogue,
		GitHubCatalogueApps: githubCatalogueApps(kept.githubCatalogueApps, cfg.demo, demoAppKey),
		GitHubMints:         githubMints,
		GitHubHTTP:          demoGitHub(cfg.demo && kept.githubCatalogueApps == nil),
		Audit:               recorder,
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
		fatal:   fatal,
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

		catalogueApps: githubCatalogueApps(kept.githubCatalogueApps, cfg.demo, demoAppKey),
		githubMints:   githubMints,
		relabel:       kept.relabel,
	}, nil
}

// Run serves the three listeners and drives the hub's background loops
// until the context is done.
func (a *App) Run(ctx context.Context) error {
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(gctx, a.cfg.apiPort, a.api, "api", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.consolePort, a.console, "console", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.healthPort, a.health, "health", a.log) })
	group.Go(func() error { return a.RunLoops(gctx) })
	group.Go(func() error {
		select {
		case err := <-a.fatal:
			return fmt.Errorf("audit: %w", err)
		case <-gctx.Done():
			return nil
		}
	})
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

// cappedSessionLifetime is how long the console's OWN session cookie is
// issued for: SESSION_LIFETIME, or the absolute session limit, whichever
// is shorter.
//
// This cookie is issued once, at sign-in, with a fixed expiry -- unlike a
// per-client refresh token it never slides -- so its issue time already
// IS its auth_time, and capping it at the limit is exactly capping the
// lifetime it is issued for. Zero or negative means no limit, which a
// deployment can only reach by way of a bug: issuerapp.Load refuses that
// value outright, but this package has no such check of its own (see
// [Config.absoluteLifetime]), so a caller with a broken value is still
// answered sanely rather than capping every session to nothing.
func cappedSessionLifetime(session, absolute time.Duration) time.Duration {
	if absolute > 0 && absolute < session {
		return absolute
	}
	return session
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
func githubConnections(store *kube.GitHubOrgs, demonstration bool, key string) server.GitHubConnections {
	switch {
	case store != nil:
		return store
	case demonstration:
		return demoConnections{record: demo.GitHubConnection(time.Now()), key: key}
	default:
		return nil
	}
}

// githubRunnerApps is the store as the console's interface, or nil. A
// demonstration run shows one tier's App created and one left to create.
func githubRunnerApps(store *kube.GitHubRunnerApps, demonstration bool, key string) server.GitHubRunnerApps {
	switch {
	case store != nil:
		return store
	case demonstration:
		return demoRunnerApps{records: demo.GitHubRunnerApps(time.Now()), key: key}
	default:
		return nil
	}
}

// githubCatalogueApps is the store as the console's interface, or nil. A
// demonstration run shows Apps created from its catalogue, one of them
// edited on GitHub since.
func githubCatalogueApps(store *kube.GitHubCatalogueApps, demonstration bool, key string) server.GitHubCatalogueApps {
	switch {
	case store != nil:
		return store
	case demonstration:
		return demoCatalogueApps{records: demo.GitHubCatalogueApps(time.Now()), key: key}
	default:
		return nil
	}
}

// demoRunnerApps are fixed runner Apps that nobody can create or forget.
type demoRunnerApps struct {
	records []runnerapp.Record
	key     string
}

func (demoRunnerApps) Put(context.Context, runnerapp.Record, string) error { return errDemoConnect }

func (d demoRunnerApps) List(context.Context) ([]runnerapp.Record, error) { return d.records, nil }

func (d demoRunnerApps) PrivateKey(_ context.Context, tier, org string) (string, bool, error) {
	for i := range d.records {
		if d.records[i].Tier == tier && d.records[i].Org == org {
			return d.key, true, nil
		}
	}
	return "", false, nil
}

func (demoRunnerApps) Delete(context.Context, string, string) error { return errDemoConnect }

// demoCatalogueApps are fixed catalogue Apps, with a key this process
// made: the console asks the demonstration's GitHub about them as it would
// ask the real one.
type demoCatalogueApps struct {
	records []catalogueapp.Record
	key     string
}

func (demoCatalogueApps) Put(context.Context, catalogueapp.Record, string) error {
	return errDemoConnect
}

func (d demoCatalogueApps) List(context.Context) ([]catalogueapp.Record, error) {
	return d.records, nil
}

func (d demoCatalogueApps) Get(_ context.Context, id string) (catalogueapp.Record, string, bool, error) {
	for i := range d.records {
		if d.records[i].ID == id {
			return d.records[i], d.key, true, nil
		}
	}
	return catalogueapp.Record{}, "", false, nil
}

func (demoCatalogueApps) Delete(context.Context, string) error { return errDemoConnect }

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

// demoGitHub is the demonstration's GitHub, or nil for the real one: the
// console asks it about the demonstration's Apps exactly as it asks GitHub
// about real ones, so the Apps page shows an App matching its declaration
// beside one an owner edited since.
func demoGitHub(demonstration bool) *http.Client {
	if !demonstration {
		return nil
	}
	return &http.Client{Transport: demo.GitHubAPI(), Timeout: 10 * time.Second}
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

// demoConnections is one fixed, connected organisation, with a key the
// console asks the demonstration's GitHub about the App with.
type demoConnections struct {
	record connection.Record
	key    string
}

func (d demoConnections) List(context.Context) ([]connection.Record, error) {
	return []connection.Record{d.record}, nil
}

func (d demoConnections) Credential(_ context.Context, org string) (connection.Credential, bool, error) {
	if org != d.record.Org {
		return connection.Credential{}, false, nil
	}
	return connection.Credential{
		Org: d.record.Org, AppID: d.record.AppID, InstallationID: d.record.InstallationID, PrivateKey: d.key,
	}, true, nil
}

func (demoConnections) Put(context.Context, connection.Record, connection.Credential) error {
	return errDemoConnect
}

func (demoConnections) Delete(context.Context, string) error { return errDemoConnect }
