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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/truvity/sluis/storage/awsotel"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/errgroup"

	"github.com/truvity/sluis/backend/google"
	"github.com/truvity/sluis/internal/access"
	"github.com/truvity/sluis/internal/audit"
	"github.com/truvity/sluis/internal/clientcreds"
	"github.com/truvity/sluis/internal/config"
	"github.com/truvity/sluis/internal/health"
	"github.com/truvity/sluis/internal/httpsec"
	"github.com/truvity/sluis/internal/issuer"
	"github.com/truvity/sluis/internal/lazy"
	"github.com/truvity/sluis/internal/port"
	"github.com/truvity/sluis/internal/port/memory"
	"github.com/truvity/sluis/internal/rails"
	"github.com/truvity/sluis/internal/recoverygate"
	"github.com/truvity/sluis/internal/refusal"
	"github.com/truvity/sluis/internal/secrets"
	"github.com/truvity/sluis/internal/secretstore"
	"github.com/truvity/sluis/internal/signer"
	"github.com/truvity/sluis/internal/store"
	"github.com/truvity/sluis/internal/telemetry"
	"github.com/truvity/sluis/internal/verify"
	"github.com/truvity/sluis/internal/version"
	"github.com/truvity/sluis/policy"
	"github.com/truvity/sluis/storage/keys"
)

// Config is what a deployment decides. It is built from the configuration
// file, which is what the chart renders.
type Config struct {
	// LazySigningKeys opens the KMS signing modes (signingKey.kms and
	// signingKey.kmsWrapped) when something first needs a key, and not as the
	// issuer is assembled: opening reads the state secret and calls KMS, which
	// a function that starts in many environments at once must not do in each.
	// Unset, the keys are open when New returns and a fault in them stops the
	// start, which is what a service that serves for long wants. See
	// [deferredSigning] for which request pays.
	LazySigningKeys bool

	port       string
	healthPort string

	issuerURL     string
	allowInsecure bool

	// policy is the policy document, when this issuer is assembled on its
	// own; the merged service hands its halves one [policy.Set] instead.
	policy *config.PolicyDocument

	inCluster     bool
	release       string
	oauthClientID string
	secureCookies bool
	// hsts is the Strict-Transport-Security policy: see [config.HSTS].
	hsts httpsec.HSTS
	// oauthProvider names the OAuth client's secrets:
	// providers/google/<provider>/client-id and .../client-secret.
	oauthProvider    string
	recoveryEnabled  bool
	recoveryAccount  string
	cluster          string
	recoveryAudience string
	// recoveryGeneration is `recovery.generation`: which decision to have
	// recovery on a disable from the console covers (internal/recoverygate).
	recoveryGeneration string
	// recoveryPassword is whether the recovery account's password sign-in may be
	// offered: recovery is not turned off. It is the hub's rule (on unless
	// `recovery.enabled: false`), not the token door's, which needs the account
	// and audience named; the door also needs a verifier, which a cluster
	// install has none of unless it names one.
	recoveryPassword bool
	// recoveryVerifier names the recovery account's SRP verifier
	// (`recovery.verifierSecret`), read from layout v5's fixed address instead
	// when the secrets are layout v5's.
	recoveryVerifier string
	// conformanceEnabled is `conformance.enabled`, and conformanceVerifier names
	// the account's SRP verifier (`conformance.verifierSecret`).
	conformanceEnabled  bool
	conformanceVerifier string
	// secrets delivers every secret this document names, by name: the
	// stores' source, set at New.
	secrets secrets.Source
	// v5 is the installation's secrets on layout v5, nil on v4: the state
	// secret is then read from internal/oidc/state-secret whatever name the
	// document gives it.
	v5 *secretstore.StoresV5
	// clusters and aws are whom the token exchange trusts: the policy
	// document's exchange.clusters and exchange.aws.
	clusters []config.FederatedCluster
	aws      config.AWSFederation
	// consoleAWSAudience is the audience an AWS role's token must carry to be a
	// bearer at the console, distinct from the exchange's.
	consoleAWSAudience string
	consoleClientID    string
	audience           string
	githubOwners       []string
	githubOwnerIDs     []string
	githubRepositoryID []string
	consoleOrigin      string
	signingKeyFile     string
	// additionalSigningKeyFiles are every OTHER algorithm this
	// installation signs with at once, one file per algorithm, beside the
	// primary [Config.signingKeyFile] -- see [signer.KeyRings] and the
	// chart's `signingKey.additional`.
	additionalSigningKeyFiles []string
	// kmsKeys, when set, replace signingKeyFile: AWS KMS keys, oldest
	// first, the last signing. kmsStateSecret names what the sign-in state
	// derives from, since a KMS key has no private bytes of its own.
	kmsKeys        []string
	kmsAdditional  []config.SigningKeyKMSAlg
	kmsRegion      string
	kmsStateSecret string
	// kmsWrapped, when set, replaces signingKeyFile: key pairs KMS generates
	// and wraps under one symmetric key (the `kms-wrapped` adapter).
	kmsWrapped *config.SigningKeyKMSWrapped
	// keys says which key serves which purpose; instance is bound into the
	// default encryption context. The wrapped ring wraps under `keys.sign`.
	keys     *keys.Config
	instance string
	// verifyOnly are public keys published and never signed with.
	verifyOnly []config.SigningKeyVerifyOnly

	tokenLifetime    time.Duration
	refreshLifetime  time.Duration
	absoluteLifetime time.Duration
	holdWindow       time.Duration
	// agentLifetimes are `lifetimes.agent`, held to
	// [issuer.CheckAgentLifetimes] at load.
	agentLifetimes issuer.AgentLifetimes

	// keyActivationDelay, keyOverlap and keyPollInterval govern live
	// signing-key rotation; see [signer.KeyRingConfig] and
	// [watchSigningKey].
	keyActivationDelay time.Duration
	keyOverlap         time.Duration
	keyPollInterval    time.Duration

	logLevel slog.Level

	// groupsScoping is how far this installation has moved toward
	// per-audience `groups` scoping -- see [issuer.GroupsScopingMode].
	// Validated by [issuer.CheckGroupsScopingMode] below, so a [Config]
	// past [Load] never carries a value that check refuses.
	groupsScoping issuer.GroupsScopingMode
}

// LogLevel is the level the process should log at.
func (c Config) LogLevel() slog.Level { return c.logLevel }

// FromConfig builds the process's settings from the service document and the
// policy document, which the caller has already held to their schemas and
// checks. What a schema cannot say
// is checked here, before anything starts: lifetimes that contradict each
// other, a rotation schedule that cannot work, a scoping mode this build does
// not know.
func FromConfig(f *config.Serve, p *config.PolicyDocument) (Config, error) {
	c := Config{
		port:       listenOr(f.Listen, ":8080"),
		healthPort: listenOr(f.Probes, ":7070"),
		issuerURL:  strings.TrimSuffix(f.IssuerURL, "/"),

		allowInsecure: f.AllowInsecure,
		policy:        p,
		inCluster:     f.InCluster,
		release:       orDefault(f.Release, "sluis"),
		consoleOrigin: "",
		// Names this cluster in a ServiceAccount's subject. A pod cannot
		// discover it, and the same namespace and name exist on every
		// cluster, so an installation that leaves it empty keeps the older
		// unqualified subject rather than an invented one.
		cluster: f.Cluster,
	}
	c.keys = f.Keys
	c.instance = orDefault(f.Instance, c.release)
	c.githubOwners = p.GitHubOwners()
	c.githubOwnerIDs = p.GitHubOwnerIDs()
	c.githubRepositoryID = p.GitHubRepositoryIDs()
	c.clusters = p.Clusters()
	c.aws = p.AWS()
	if f.Console != nil {
		c.consoleOrigin = f.Console.Origin
		c.consoleClientID = f.Console.Client
		c.consoleAWSAudience = strings.TrimSpace(f.Console.AWSAudience)
	}
	if f.Exchange != nil {
		c.audience = f.Exchange.Audience
	}
	c.recoveryPassword = true
	if r := f.Recovery; r != nil {
		c.recoveryEnabled = r.Enabled != nil && *r.Enabled
		c.recoveryPassword = r.Enabled == nil || *r.Enabled
		c.recoveryAccount = r.ServiceAccount
		c.recoveryAudience = r.Audience
		c.recoveryGeneration = r.Generation
		c.recoveryVerifier = r.VerifierSecret
	}
	if cf := f.Conformance; cf != nil {
		c.conformanceEnabled = cf.Enabled
		c.conformanceVerifier = cf.VerifierSecret
	}
	var err error
	if o := f.OAuthClient; o != nil {
		c.oauthClientID = o.ID
		c.oauthProvider = o.Provider
	}
	// What the storage ports need is read from the same file by [store.FromServe]
	// at start; read here too so a bad value (an unset password variable)
	// is refused with the rest of the configuration.
	if _, err = store.FromServe(f); err != nil {
		return Config{}, err
	}
	if k := f.SigningKey; k != nil {
		c.signingKeyFile = k.File
		if k.KMS != nil {
			if k.File != "" {
				return Config{}, errors.New("signingKey.file and signingKey.kms are exclusive: " +
					"a key is a file or a KMS key, not both")
			}
			if len(k.KMS.Keys) == 0 || k.KMS.StateSecret == "" {
				return Config{}, errors.New("signingKey.kms needs keys and stateSecret")
			}
			c.kmsKeys = k.KMS.Keys
			c.kmsAdditional = k.KMS.Additional
			c.kmsRegion = k.KMS.Region
			c.kmsStateSecret = k.KMS.StateSecret
		}
		if k.KMSWrapped != nil {
			if k.File != "" || k.KMS != nil {
				return Config{}, errors.New("signingKey.kmsWrapped is exclusive with signingKey.file and signingKey.kms: " +
					"a key is a file, a KMS key or a KMS-wrapped key pair")
			}
			c.kmsWrapped = k.KMSWrapped
		}
		// The files the deployment expects, named exactly: a deployment
		// naming them is a deployment a missing mount fails LOUDLY for, at
		// start, rather than one that silently signs with fewer algorithms
		// than its policy assumes.
		c.additionalSigningKeyFiles = k.AdditionalFiles
	}
	// Secure follows the scheme the BROWSER will use, which the service
	// knows because it is told its own public URL. Defaulting to false
	// meant an installation that merely forgot to say so served session
	// cookies a proxy could strip onto a plain-http hop, and the alert
	// CodeQL raised was about that default rather than about this line.
	// secureCookies still overrides, in either direction, for the local
	// http listener and for a TLS terminator that is not in the URL.
	if err = f.ValidateSecureCookies(); err != nil {
		return Config{}, err
	}
	c.secureCookies = strings.HasPrefix(c.issuerURL, "https://")
	if f.SecureCookies != nil {
		c.secureCookies = *f.SecureCookies
	}

	if c.hsts, err = f.HSTS.Policy(c.issuerURL); err != nil {
		return Config{}, err
	}

	l := f.Lifetimes
	if l == nil {
		l = &config.Lifetimes{}
	}
	c.tokenLifetime = dur(l.Token, issuer.DefaultTokenLifetime)
	c.refreshLifetime = dur(l.Refresh, issuer.DefaultRefreshLifetime)
	c.absoluteLifetime = dur(l.Absolute, issuer.DefaultAbsoluteLifetime)
	c.holdWindow = dur(l.Hold, issuer.DefaultHoldWindow)
	// Refused here rather than defaulted, unlike an unset lifetimes.token or
	// lifetimes.refresh: those treat unset as "use the default", but a
	// deployment that sets lifetimes.absolute to zero has said something
	// specific and wrong -- a session that ends before or the instant it
	// begins is not a limit, it is a login that can never complete -- and
	// defaulting past that would hide the mistake instead of refusing it.
	if c.absoluteLifetime <= 0 {
		return Config{}, errors.New(
			"lifetimes.absolute must be positive: a session has to end SOMETIME after sign-in, not before it")
	}
	// And it must be able to outlive at least one access token, or a token
	// minted at the very start of a session would already be past the
	// limit that is meant to end the SESSION, not pre-empt its first
	// token.
	if c.absoluteLifetime < c.tokenLifetime {
		return Config{}, fmt.Errorf(
			"lifetimes.absolute (%s) must be at least lifetimes.token (%s): "+
				"an access token cannot outlive the session that grants it",
			c.absoluteLifetime, c.tokenLifetime)
	}
	// The agent class's own. Unset is the default; a value the file states
	// is checked as stated, so a zero is refused rather than defaulted.
	agent := l.Agent
	if agent == nil {
		agent = &config.AgentLifetimes{}
	}
	c.agentLifetimes = issuer.AgentLifetimes{
		Refresh:  dur(agent.Refresh, issuer.DefaultAgentRefresh),
		Absolute: dur(agent.Absolute, issuer.DefaultAgentAbsolute),
		Access:   dur(agent.Access, issuer.DefaultAgentAccess),
	}
	if err = issuer.CheckAgentLifetimes(c.agentLifetimes); err != nil {
		return Config{}, err
	}
	k := f.SigningKey
	if k == nil {
		k = &config.SigningKey{}
	}
	c.keyActivationDelay = dur(k.ActivationDelay, signer.DefaultKeyActivationDelay)
	// Overlap defaults to this deployment's OWN token lifetime plus a margin
	// for clock skew, rather than the package's constant: the whole point of
	// the setting is that it must cover whatever this installation actually
	// mints, and a fixed default cannot know the token lifetime was raised.
	// The clock-skew margin accounts for differences between the issuer and
	// verifiers' clocks.
	c.keyOverlap = dur(k.Overlap, 0)
	if c.keyOverlap <= 0 {
		c.keyOverlap = c.tokenLifetime + signer.KeyOverlapSkew
	}
	c.keyPollInterval = dur(k.PollInterval, signer.DefaultKeyPollInterval)
	c.verifyOnly = k.VerifyOnly
	// The activation delay must be longer than the poll interval so that a
	// newly published key has at least one complete poll cycle to be seen
	// and re-read before any replica signs with it.
	if c.keyActivationDelay < c.keyPollInterval {
		return Config{}, fmt.Errorf("signingKey.activationDelay (%v) must be at least signingKey.pollInterval (%v)", c.keyActivationDelay, c.keyPollInterval)
	}
	if c.kmsWrapped != nil {
		if _, err = c.wrappedConfig(); err != nil {
			return Config{}, err
		}
	}
	level := "info"
	if f.Log != nil && f.Log.Level != "" {
		level = f.Log.Level
	}
	if err = c.logLevel.UnmarshalText([]byte(level)); err != nil {
		return Config{}, fmt.Errorf("log.level: %w", err)
	}
	// Checked here, at load, rather than left to [issuer.Config.withDefaults]
	// to default quietly: an installation that asks for something this
	// build does not recognise must be told so, not silently downgraded
	// to report. See [issuer.CheckGroupsScopingMode].
	c.groupsScoping = issuer.GroupsScopingMode(orDefault(f.GroupsScoping, string(issuer.GroupsScopingReport)))
	if err = issuer.CheckGroupsScopingMode(c.groupsScoping); err != nil {
		return Config{}, fmt.Errorf("groupsScoping: %w", err)
	}

	// Every relying party's trust is anchored on this string, and it goes
	// into every token. A default would be a value nobody chose baked
	// into an installation's whole estate.
	if c.issuerURL == "" {
		return Config{}, errors.New("issuerURL is required: it is baked into every token and every relying party")
	}
	if c.consoleAWSAudience == "" {
		c.consoleAWSAudience = strings.TrimSuffix(c.issuerURL, "/") + "/console"
	}
	if c.audience == "" {
		c.audience = c.release
	}
	return c, nil
}

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func listenOr(a *config.Address, fallback string) string {
	if a != nil && a.Address != "" {
		return a.Address
	}
	return fallback
}

// dur reads a duration the file may leave unset.
func dur(d *config.Duration, fallback time.Duration) time.Duration {
	if d == nil {
		return fallback
	}
	return d.D()
}

// Deps are the things a caller supplies instead of letting this package
// build them. Both are how the merged service is assembled:
// one process holds the directory, so the issuer calls it rather than
// dialling it, and the console is served from the issuer's own origin
// instead of a listener of its own.
//
// Directory is REQUIRED. It was optional while the hub was a service of
// its own, reached over the network at HUB_ADDRESS; the merge folded it
// into this process and nothing has dialled it since. What was left was
// a branch that could not run, two settings nothing set, and a network
// client with no caller -- config that reads as a supported deployment
// and is not one.
type Deps struct {
	// KMS is the client for signingKey.kms. Nil builds one from the AWS
	// default credential chain; a test supplies a fake.
	KMS signer.KMSAPI
	// Keys is the key service behind `keys` (the sign key of the wrapped ring).
	// Nil opens the one `keys.adapter` names; a test supplies the local one.
	Keys keys.Backend
	// Stores is the storage ports, built once from configuration and shared
	// with the directory half. Nil is a process with no shared state and no
	// cluster: logins in progress are kept in this process, and recovery is
	// off.
	Stores *store.Stores
	// Directory answers "who is this address", in this process.
	Directory issuer.Directory
	// Policy is the policy in force. Supplying it is how the merged
	// service guarantees both halves act on the SAME one: they read the
	// same file, but their fallbacks differ, and two halves that can
	// disagree about the policy is the class of failure the merge existed
	// to end. Nil loads it from policyDir, which is the split shape.
	Policy *policy.Set
	// UseSignInEntry is called with a function saying where to send a
	// browser that has NO session. Together with UseSignedIn it is the
	// whole of how the console authenticates on one origin: one says how
	// to come by a session, the other reads it.
	UseSignInEntry func(func() string)
	// UseSignedIn is called with a reader of the issuer's own browser
	// session, once this half exists. It is how the console on this
	// origin learns who is signed in without a proxy in front of it and
	// without a login of its own.
	UseSignedIn func(func(http.ResponseWriter, *http.Request) (access.Principal, bool))
	// Audit is the service's recorder, shared with the directory half so
	// both write one history. Nil records to this process's log alone.
	Audit audit.Recorder
	// UseWorkloads is called with a reader of ServiceAccount bearers,
	// verified against the same cluster key sets token exchange uses. It
	// is how a controller beside this issuer reads the console's API with
	// its own projected token. Nil is never called with, and a deployment
	// federating no cluster hands it nothing.
	UseWorkloads func(func(*http.Request) (access.Principal, bool))
	// UseBearers is called with a reader of the access tokens this issuer
	// signed for the CLI (`sluisctl`), as a person's bearer: how a laptop
	// reaches the console's backup service with its own sign-in.
	UseBearers func(func(*http.Request) (access.Principal, bool))
	// RecoveryGate is the switch the console throws to turn recovery off, shared
	// with the console so that both halves of the process agree at once. Nil
	// builds one over the stores.
	RecoveryGate *recoverygate.Gate
	// UseRecoveryEnder is called with the function that ends every sign-in and
	// client session recovery opened, and reports how many: the sweep after the
	// switch is thrown. Nil is never called with.
	UseRecoveryEnder func(func(ctx context.Context) (signIns, sessions int, err error))
	// UseIssuerURL is called with this issuer's own URL, so the console
	// can tell a browser where the SessionService is.
	//
	// The console used to learn that from the proxy in front of it, and
	// on one origin there is no proxy -- so without this it concluded it
	// had no issuer and hid its sessions pages on the deployment where
	// they work best.
	UseIssuerURL func(string)
	// Ready are dependencies the caller's half of the process needs
	// answering for, added to this one's on /readyz. The merged service
	// has one readiness endpoint and two stores behind it.
	Ready []health.Dependency
	// Console is the operator UI, written as if it were at the root of an
	// origin. It is mounted under /console/ with the prefix stripped,
	// which is exactly what the gateway used to do for it.
	Console http.Handler
	// GitHubApps are the catalogue Apps this issuer mints installation
	// tokens for, under the catalogue's grants: the directory half's
	// catalogue and the Secret it keeps each App's key in. Nil mints none,
	// and every such request is refused as naming an App that cannot.
	GitHubApps *issuer.GitHubApps
	// Around wraps everything this issuer serves on its port, the console
	// included. It is applied to the one handler both [App.Handler] and
	// [App.Run] use, so what a caller tests through the first is what the
	// second serves. The merged service puts what an audit event keeps of
	// each request into its context here. Nil wraps nothing.
	Around func(http.Handler) http.Handler
}

// App is an assembled issuer.
type App struct {
	// kms is set when the primary key lives in AWS KMS; Run polls it.
	kms []*signer.KMSKeyRefs
	// wrapped is set when the keys are KMS-wrapped; Run keeps them rotating.
	wrapped bool
	// state is the shared state the secret fingerprint lives in.
	state issuer.State
	// generated are the clients whose secret the issuer makes; creds is what
	// the token endpoint reads and credStore where the records live.
	generated []string
	creds     *clientcreds.Resolver
	credStore port.Secrets
	// leases serialises writers of one client's record.
	leases  *rails.Leases
	handler http.Handler
	health  http.Handler
	issuer  *issuer.Issuer
	storage *issuer.Storage
	// keys are the signer's rings: rotation is fed to them, not to the issuer.
	// Nil until the keys are open, which [App.Run] sees to.
	keys *signer.KeyRings
	// lazyKeys, where the KMS keys are opened on first use.
	lazyKeys *deferredSigning
	cfg      Config
	log      *slog.Logger
}

// useKeys keeps what Run drives of the open keys.
func (a *App) useKeys(set *signingSet) {
	a.keys, a.kms, a.wrapped = set.rings, set.kmsRefs, set.wrapped != nil
}

// MintFor signs a short-lived access token for a person signed in to this
// service, for one declared client: how the console reads another service
// as that person. See [issuer.Storage.MintFor].
func (a *App) MintFor(ctx context.Context, email, audience string, lifetime time.Duration) (string, time.Time, error) {
	return a.storage.MintFor(ctx, email, audience, lifetime)
}

// Handler is the OpenID surface: discovery, keys, authorize, token,
// exchange, revocation, the device flow.
func (a *App) Handler() http.Handler { return a.handler }

// HealthHandler is liveness and readiness.
func (a *App) HealthHandler() http.Handler { return a.health }

// Issuer is the decision core, for a caller that drives it directly.
func (a *App) Issuer() *issuer.Issuer { return a.issuer }

// catalogueGrantGroups is the groups a GitHub App catalogue's grants name,
// for policy.Policy.Unconsumed's catalogueGroups parameter -- nil when
// this issuer mints no catalogue Apps' tokens at all (apps nil) or its
// catalogue is empty (a nil Catalogue field), which is the ordinary shape
// for a deployment that declares no GitHub Apps.
func catalogueGrantGroups(apps *issuer.GitHubApps) []string {
	if apps == nil || apps.Catalogue == nil {
		return nil
	}
	return apps.Catalogue.GrantGroups()
}

// New assembles the issuer.
func New(ctx context.Context, cfg Config, deps Deps, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}

	var err error

	set := deps.Policy
	if set == nil {
		if cfg.policy == nil {
			return nil, errors.New("a policy is required: name the policy document with policy.file")
		}
		declared := cfg.policy.Policy
		if set, err = policy.NewSet(declared); err != nil {
			return nil, err
		}
		// deps.GitHubApps' catalogue, when this issuer mints installation
		// tokens under one, names groups this package cannot otherwise
		// see any reference to: a grant is what actually consumes such a
		// group, exactly as a client's Requires would. Without a
		// catalogue (deps.GitHubApps nil, or a nil Catalogue within it —
		// see [issuer.GitHubApps]) nothing is added here, and this
		// behaves exactly as it always did.
		if unconsumed := declared.Unconsumed(catalogueGrantGroups(deps.GitHubApps)...); len(unconsumed) > 0 {
			log.WarnContext(ctx, "internal groups are declared but nothing consumes them",
				slog.Any("groups", unconsumed))
		}
	}

	// A resource's absolute_cap against this installation's own limit: a
	// longer one needs the resource to say it is read-only. Refused here
	// because policy alone cannot know lifetimes.absolute, and a row that
	// could never be honoured should stop the service, not be clamped.
	warnBroadAWSMatchers(ctx, set, log)
	rows := set.Resources()
	for i := range rows {
		if err = rows[i].CheckAbsoluteCap(rows[i].ID, cfg.absoluteLifetime); err != nil {
			return nil, err
		}
	}
	warnAgentClasses(ctx, set, cfg.absoluteLifetime, log)

	directory := deps.Directory
	if directory == nil {
		return nil, errors.New(
			"a directory is required: this service asks it about every person, and it is " +
				"supplied in-process -- there is no longer a network hub to dial")
	}

	// The shared store first: the issuer's session index lives in it, so
	// there is no issuer to build until it is open.
	stores := deps.Stores
	if stores == nil {
		stores = &store.Stores{}
	}
	cfg.secrets, cfg.v5 = stores.Secrets, stores.V5
	shared := openState(ctx, stores, log)

	core := issuer.New(issuer.Config{
		URL:              cfg.issuerURL,
		TokenLifetime:    cfg.tokenLifetime,
		RefreshLifetime:  cfg.refreshLifetime,
		AbsoluteLifetime: cfg.absoluteLifetime,
		HoldWindow:       cfg.holdWindow,
		Agent:            cfg.agentLifetimes,
		AllowInsecure:    cfg.allowInsecure,
		HSTS:             cfg.hsts,
		GroupsScoping:    cfg.groupsScoping,
	}, set, directory, shared)
	// The service's one audit trail, opened by the directory half. A
	// split deployment with none still validates every record and logs it.
	if deps.Audit != nil {
		core.UseAudit(deps.Audit)
	} else {
		trail, err := audit.Open(ctx, audit.Config{Log: log})
		if err != nil {
			return nil, err
		}
		core.UseAudit(trail)
	}

	if deps.GitHubApps != nil {
		core.UseGitHubApps(*deps.GitHubApps)
	}
	// The recovery sign-in can be turned off at run time from the console
	// (docs/decisions/0075). One gate is shared by the issuer's pages, sessions
	// and refreshes and the console's own; without one given, this issuer reads
	// the same record itself.
	recoveryGate := deps.RecoveryGate
	if recoveryGate == nil {
		recoveryGate = recoverygate.New(stores.RecoveryState(), cfg.recoveryGeneration, recoverygate.WithLog(log))
	}
	core.UseRecoveryGate(recoveryGate)
	core.UseConformance(cfg.conformanceEnabled)

	if err := applySigningPlan(ctx, &cfg, stores.Plan); err != nil {
		return nil, err
	}
	additionalKeys, err := additionalSigningKeys(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	kmsMode := cfg.kmsWrapped != nil || len(cfg.kmsKeys) > 0
	if cfg.kmsWrapped == nil && len(cfg.kmsKeys) > 0 {
		log.WarnContext(ctx, "signingKey.kms (direct asymmetric KMS signing) is deprecated and goes in a later release: "+
			"move to the wrapped ring (signingKey.kmsWrapped with keys.sign), keeping the old public keys under "+
			"signingKey.verifyOnly for the overlap (docs/concepts/sluis/signing-on-aws.md)")
		for _, f := range additionalKeys {
			log.WarnContext(ctx, "signingKey.kms is set but this algorithm is still signed by a file key",
				slog.Any("algorithm", f.SignatureAlgorithm()), slog.String("kid", f.ID()))
		}
	}
	// build opens the signing keys: the primary key, the rings over it and its
	// neighbours, and the rotation each mode runs. The KMS modes read the state
	// secret here and call KMS.
	build := func(ctx context.Context) (*signingSet, error) {
		var (
			key     *signer.SigningKey
			kmsRefs []*signer.KMSKeyRefs
			kmsRest []*signer.SigningKey
			kmsMore []*signer.SigningKey
			wrapped *signer.WrappedSigning
			err     error
		)
		switch {
		case cfg.kmsWrapped != nil:
			wrapped, key, kmsMore, err = wrappedSigningKeys(ctx, cfg, deps, stores, shared, log)
		case len(cfg.kmsKeys) > 0:
			kmsRefs, kmsRest, key, kmsMore, err = kmsSigningKeys(ctx, cfg, deps.KMS, log)
		default:
			key, err = signingKey(ctx, cfg, log)
		}
		if err != nil {
			return nil, err
		}
		// Each KMS algorithm's newest key is its ring's primary, beside any files
		// (a file and a KMS key for the same algorithm clash, as two files do).
		rings, err := signer.NewKeyRings(key, slices.Concat(additionalKeys, kmsMore), shared, signer.KeyRingConfig{}, nil)
		if err != nil {
			return nil, fmt.Errorf("adopt the signing keys: %w", err)
		}
		// The delays a deployment named, or their defaults: NewKeyRings seeded the
		// ring before either was known, so this is applied before the poller in
		// Run starts feeding it anything more.
		rings.Configure(signer.KeyRingConfig{
			ActivationDelay: cfg.keyActivationDelay,
			Overlap:         cfg.keyOverlap,
		})
		if wrapped != nil {
			// The wrapped schedule's own pre-publish and retention, which default to
			// the two settings above.
			wc, wcErr := cfg.wrappedConfig()
			if wcErr != nil {
				return nil, wcErr
			}
			rings.Configure(signer.KeyRingConfig{ActivationDelay: wc.Prepublish, Overlap: wc.Retain})
			rings.UseWrapped(wrapped)
		}
		// The earlier KMS keys, in order: refreshed if the installation knows
		// them, never newly adopted.
		for _, extra := range kmsRest {
			if err = rings.RotateKnown(ctx, extra); err != nil {
				return nil, fmt.Errorf("adopt a KMS signing key: %w", err)
			}
		}
		return newSigningSet(key, rings, kmsRefs, wrapped), nil
	}
	var (
		opened   *signingSet      // the open keys; nil while they are opened on first use
		lazyKeys *deferredSigning // set instead, when they are
		ring     signer.Ring
		dir      signer.Directory
	)
	if kmsMode && cfg.LazySigningKeys {
		algs, algErr := configuredKMSAlgorithms(cfg, additionalKeys)
		if algErr != nil {
			return nil, algErr
		}
		lazyKeys = newDeferredSigning(algs, build, log)
		ring, dir = lazyKeys, lazyKeys
	} else {
		if opened, err = build(ctx); err != nil {
			return nil, err
		}
		ring, dir = opened.rings, opened.rings
	}
	verifiers, clusters, err := openVerifiers(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	generated := generatedClients(set)
	if err = checkGeneratedSecrets(generated, stores); err != nil {
		return nil, err
	}
	var input clientcreds.Input
	if cfg.secrets != nil {
		input = cfg.secrets
	}
	creds := clientcreds.NewResolver(stores.ClientSecretPort(), input, log)
	// Only a generated client's record is consulted; the policy in force says
	// which, so a client returned to a named input secret is served by it.
	creds.UseGenerated(func(id string) bool {
		c, ok := set.Client(id)
		return ok && c.SecretGenerated()
	})
	secretsAdmin, leases := newClientSecretManager(set, stores, creds, log)
	if stores.ClientSecretPort() != nil {
		core.UseClientSecrets(secretsAdmin)
	}
	storage, err := issuer.NewStorage(core, verifiers, creds,
		signer.New(ring, signer.LimitsFor(core.Config().TokenLifetime)), dir, shared)
	if err != nil {
		return nil, err
	}
	verifyOnlyKeys, err := loadVerifyOnly(cfg.verifyOnly, log)
	if err != nil {
		return nil, err
	}
	storage.UseVerifyOnly(verifyOnlyKeys, nil)
	// So the storage's own log lines -- a reused authorization code, the
	// groups-scoping report -- carry this deployment's level and
	// attributes rather than depending on [slog.SetDefault] alone.
	storage.UseLog(log)
	if deps.UseRecoveryEnder != nil {
		// The sweep that follows the console's turn-off of recovery: it ends what
		// recovery opened and tells the clients that asked to be told.
		deps.UseRecoveryEnder(func(ctx context.Context) (int, int, error) {
			ended, err := core.EndRecovery(ctx)
			storage.AnnounceEnded(ctx, log, ended.Ended)

			return ended.SignIns, ended.Sessions, err
		})
	}
	signIn, err := openSignIn(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	// The state secret's fingerprint is checked at the first sign-in, not as
	// the process starts. Where the keys are opened on first use the secret is
	// read then too, with the keys it seeds.
	var stateKey access.KeyFunc
	if lazyKeys != nil {
		stateKey = lazyKeys.stateKey
		if kmsMode {
			signIn = gateSignIns(signIn, newLazyStateSecretGate(shared, lazyKeys.stateSeed, leases))
		}
	} else {
		stateKey = access.StaticKey(opened.stateKey)
		if kmsMode {
			signIn = gateSignIns(signIn, newStateSecretGate(shared, opened.seed, leases))
		}
	}
	password, err := openPassword(ctx, cfg, stores, set, stateKey, log)
	if err != nil {
		return nil, err
	}
	signInDeps := issuer.SignInDeps{
		Providers:     signIn,
		Recovery:      openRecovery(ctx, cfg, stores, log),
		Password:      password,
		State:         access.NewStateCodecWith(stateKey, signInWindow),
		ConsoleOrigin: cfg.consoleOrigin,
		// Where an old /account bookmark is sent. Empty when this
		// deployment serves no console, and then the route is not served
		// at all rather than redirecting somebody to a 404.
		ConsoleMount: consoleMount(deps),
		// Signing out leads back to signing in, where there is a console
		// to sign in to. Not `/login`: its buttons carry the id of a
		// pending authorization request, so visiting it without one is a
		// page that looks like a sign-in and cannot finish. The console's
		// front page sends an unauthenticated browser through
		// `/authorize`, which MAKES that request — so this is the address
		// that actually reaches a working sign-in.
		//
		// Empty where no console is mounted, and then the signed-out page
		// is the honest ending.
		AfterSignOut: afterSignOut(deps),
		Secure:       cfg.secureCookies,
		Log:          log,
	}
	handler, err := issuer.HandlerWithSignIn(core, storage, signInDeps)
	if err != nil {
		return nil, err
	}
	handler = mount(handler, deps.Console)
	if deps.UseSignInEntry != nil {
		// The console becomes a client of this issuer: one door, and it
		// holds nothing special. Empty when no client is declared for it,
		// and then the console keeps a sign-in page of its own.
		deps.UseSignInEntry(signInEntry(cfg.issuerURL, cfg.consoleClientID, consoleMount(deps)))
	}
	if deps.UseIssuerURL != nil {
		// Same origin, so the browser reaches the SessionService with the
		// SSO cookie it already holds: no bearer in JavaScript, no CORS.
		deps.UseIssuerURL(cfg.issuerURL)
	}
	if deps.UseSignedIn != nil {
		// The console is on this origin and in this process, so it reads
		// the browser's issuer session directly rather than being told by
		// a proxy that ran an OpenID flow against this very service.
		//
		// The reader is built from the same sign-in dependencies as the
		// issuer's handler: what it ends -- a sign-in past the absolute
		// limit, a person the directory no longer admits -- it ends the
		// way the issuer's own pages do.
		deps.UseSignedIn(signedIn(issuer.SignedInReader(core, storage, signInDeps)))
	}
	if deps.UseWorkloads != nil {
		// The SAME verifiers token exchange uses, and only the clusters and AWS accounts:
		// a CI job has no business reading the console's API, and a
		// second copy of the cluster rows would be a second place for one
		// installation's trust to be configured.
		if read := workloadBearer(clusters, log); read != nil {
			deps.UseWorkloads(read)
		}
	}

	if deps.UseBearers != nil {
		deps.UseBearers(personBearer(issuer.BearerReader(core, storage, issuer.CLIAudiences)))
	}

	// Readiness follows the state store; liveness does not. An issuer
	// that cannot reach it can neither mint nor find a session, and
	// reporting ready through that is how a moved Valkey became a
	// fifteen-second hang at every callback on 2026-09-10.
	healthMux := health.Mux(0, append([]health.Dependency{
		health.Follow("the session store", stores.Readiness()),
	}, deps.Ready...)...)

	log.InfoContext(ctx, "sluis assembled",
		slog.String("issuer", cfg.issuerURL), slog.String("directory", directorySource(deps, cfg)), slog.Bool("in_cluster", cfg.inCluster),
		slog.String("exchange_audience", cfg.audience), slog.String("port", cfg.port), slog.String("health", cfg.healthPort),
		slog.Duration("token_lifetime", cfg.tokenLifetime), slog.Duration("refresh_lifetime", cfg.refreshLifetime),
		slog.Duration("hold_window", cfg.holdWindow), slog.String("version", version.String()))
	if cfg.allowInsecure {
		log.WarnContext(ctx, "the issuer URL may be plaintext: every token this service signs is a "+
			"bearer credential, and an issuer reached over http can be impersonated by anyone on the path")
		if issuer.LoopbackURL(cfg.issuerURL) {
			log.WarnContext(ctx, "the issuer URL is on loopback: client document fetches and back-channel posts are not held away from private addresses")
		}
	}
	// While the restore function holds the oidc table's maintenance flag the
	// issuer signs nobody in and issues nothing; what a relying party needs to
	// verify the tokens it holds keeps answering.
	// A migration freeze (`sluis maintenance on`) also serves the token exchange
	// and a refresh that is not rotated, read-only: the deploy that ends the
	// freeze signs in through this issuer.
	handler = stores.Maintenance().MiddlewareFrozen(servesInMaintenance, servesInFreeze, handler)
	if deps.Around != nil {
		handler = deps.Around(handler)
	}
	// Outermost, so that the span covers everything the listener answers and
	// the request metrics see the status the client got. The route is a fixed
	// set of names (issuer.Route), never the path.
	handler = telemetry.HTTPHandler(handler, "access-issuer", issuer.Route)
	// Outside even that, so that every answer the listener gives -- a
	// refusal above all -- names the request it answers, and the audit trail
	// and the log record the same id.
	//
	// Inside it, the cap on what a request may carry. Here and not on the
	// listener alone, because a Lambda serves this handler and has no
	// listener of ours: the cap and the headers are the handler's.
	handler = refusal.Middleware(httpsec.LimitBody(handler, httpsec.MaxRequestBody))
	app := &App{handler: handler, health: healthMux, issuer: core, storage: storage,
		cfg: cfg, log: log, state: shared, lazyKeys: lazyKeys,
		generated: generated, creds: creds, credStore: stores.ClientSecretPort(), leases: leases}
	if opened != nil {
		app.useKeys(opened)
	}
	return app, nil
}

// directorySource says where the answer about a person comes from. There
// is one answer now, and it is logged rather than dropped because an
// operator reading the startup line should not have to know that.
func directorySource(Deps, Config) string { return "in-process" }

// consoleMount is where the console sits when there is one. It is a
// constant because the mount is not configurable: the issuer owns the
// origin ROOT — discovery must sit there — and the console takes this
// path beside it.
// afterSignOut is where a person lands once their sign-in has ended: the
// console's front page where one is mounted, so that signing out leads
// back to signing in rather than to a page they have to leave.
func afterSignOut(deps Deps) string {
	mount := consoleMount(deps)
	if mount == "" {
		return ""
	}

	return mount + "/"
}

func consoleMount(deps Deps) string {
	if deps.Console == nil {
		return ""
	}
	return "/console"
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
	// The bare origin is where a person lands who typed the hostname: the
	// issuer has no page of its own there, and the console is the one
	// thing on this origin a person came for. Only the exact path: every
	// other route, the issuer's included, keeps its own handler, and "GET"
	// here is GET and HEAD.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console/", http.StatusFound)
	})
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

// Run serves the two listeners until the context is done, alongside the
// background poll that lets the signing key rotate without a restart.
func (a *App) Run(ctx context.Context) error {
	// Settled as the listeners start, and not in New, so that assembling the
	// issuer reads no secret (a Lambda assembles it and never runs it: its
	// schedule settles them). A first deploy has its secrets as soon as it
	// serves; a client that fails here does not stop the issuer: it is logged
	// and tried again, and the input secret serves it meanwhile.
	a.reconcileGenerated(ctx)
	// A service that serves for long opens its keys before it serves, so that a
	// fault in them stops the start, and rotation has rings to drive.
	if a.lazyKeys != nil {
		set, err := a.lazyKeys.get(ctx)
		if err != nil {
			return err
		}
		a.useKeys(set)
	}
	group, gctx := errgroup.WithContext(ctx)
	group.Go(func() error { return serve(gctx, a.cfg.port, a.handler, "issuer", a.log) })
	group.Go(func() error { return serve(gctx, a.cfg.healthPort, a.health, "health", a.log) })
	if a.kms != nil {
		group.Go(func() error {
			watchKMSKeys(gctx, a.kms, a.cfg.keyPollInterval, a.keys, a.log, func(c context.Context) error {
				return checkStateSecret(c, a.state, a.kms[0].Seed)
			})
			return nil
		})
	}
	if a.credStore != nil {
		group.Go(func() error {
			a.watchClientSecrets(gctx, a.log)
			return nil
		})
	}
	if a.wrapped {
		group.Go(func() error {
			ticker := time.NewTicker(a.cfg.keyPollInterval)
			defer ticker.Stop()
			for {
				a.keys.Maintain(gctx)
				select {
				case <-gctx.Done():
					return nil
				case <-ticker.C:
				}
			}
		})
	}
	group.Go(func() error {
		paths := append([]string{a.cfg.signingKeyFile}, a.cfg.additionalSigningKeyFiles...)
		watchSigningKey(gctx, paths, a.cfg.keyPollInterval, a.keys, a.log)
		return nil
	})
	return group.Wait()
}

// openRecovery builds the way in that needs no directory, or nothing.
//
// Out of a cluster there is no API server to prove access to, so there is
// nothing to build: unlike the hub, this service has no password shape to
// fall back on, and inventing one would be inventing a standing
// credential for a service whose whole point is not to hold any.
func openRecovery(ctx context.Context, cfg Config, st *store.Stores, log *slog.Logger) issuer.Recovery {
	if !cfg.recoveryEnabled {
		return nil
	}
	if !cfg.inCluster || cfg.recoveryAccount == "" || cfg.recoveryAudience == "" {
		// Info: where the console is merged in (a Lambda, a single binary) the
		// same recovery.enabled turns on the console's own password recovery,
		// which needs no cluster; only this issuer's token form does.
		log.InfoContext(ctx, "the issuer's own recovery sign-in is not built: it proves access to "+
			"a cluster, and this service is not running in one with an account and audience named; "+
			"the console's recovery (a password outside a cluster) is unaffected")
		return nil
	}
	namespace, ok := clusterNamespace(st)
	if !ok {
		log.WarnContext(ctx, "recovery could not be built: the namespace's objects are not available")
		return nil
	}
	log.InfoContext(ctx, "recovery sign-in is available: a token for this account signs in "+
		"without a directory, and the policy's service_account matchers decide what it gets",
		slog.String("namespace", namespace), slog.String("account", cfg.recoveryAccount), slog.String("audience", cfg.recoveryAudience))
	return &issuer.TokenRecovery{
		Review:    st.Ports.Identity.Verify,
		Namespace: namespace,
		Account:   cfg.recoveryAccount,
		Audience:  cfg.recoveryAudience,
		Subjects:  []string{access.ServiceAccountSubject(namespace, cfg.recoveryAccount)},
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
//
// The Google client's id and secret are not read here. They are read when a
// browser is first sent to Google (`/authorize` reaching the sign-in) or comes
// back, and again after [lazy.TTL], so a start reads no secret and a rotated
// client takes effect without one.
func openSignIn(ctx context.Context, cfg Config, log *slog.Logger) ([]issuer.SignIn, error) {
	if cfg.oauthProvider == "" {
		log.WarnContext(ctx, "nobody can sign in: no OAuth client is configured, so this issuer "+
			"serves token exchange and nothing else")
		return nil, nil
	}
	if cfg.secrets == nil {
		return nil, errors.New("oauthClient.provider: no secrets source is configured")
	}
	client := lazy.New(lazy.TTL, func(ctx context.Context) (google.OAuthClient, error) {
		out := google.OAuthClient{ID: cfg.oauthClientID, BaseURL: cfg.issuerURL}
		var err error
		if out.ID == "" {
			if out.ID, err = cfg.secrets.Get(ctx, secrets.ProviderClientID(cfg.oauthProvider)); err != nil {
				return google.OAuthClient{}, fmt.Errorf("read the OAuth client id: %w", err)
			}
		}
		if out.Secret, err = cfg.secrets.Get(ctx, secrets.ProviderClientSecret(cfg.oauthProvider)); err != nil {
			return google.OAuthClient{}, fmt.Errorf("read the OAuth client secret: %w", err)
		}
		if out.ID == "" || out.Secret == "" {
			return google.OAuthClient{}, errors.New("the OAuth client id and secret must not be empty")
		}
		return out, nil
	})
	log.InfoContext(ctx, "people sign in with Google; the client is read at the first sign-in",
		slog.String("redirect", google.OAuthClient{BaseURL: cfg.issuerURL}.SignInRedirect()))
	return []issuer.SignIn{&googleSignIn{client: client}}, nil
}

// googleSignIn adapts the backend's client to what the issuer's pages
// need. It is three lines because the issuer's half of a login is three
// things: where to send them, what came back, and nothing else.
type googleSignIn struct {
	client *lazy.Value[google.OAuthClient]
}

func (g *googleSignIn) Kind() string { return "google" }

func (g *googleSignIn) URL(state string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return g.URLContext(ctx, state)
}

// URLContext implements [issuer.ContextSignIn].
func (g *googleSignIn) URLContext(ctx context.Context, state string) (string, error) {
	client, err := g.client.Get(ctx)
	if err != nil {
		return "", err
	}
	return client.SignInURL(state), nil
}

// Identify is refused: a Google sign-in is checked against the state it was
// started with (its nonce), which only [googleSignIn.IdentifyAccount] is given.
func (g *googleSignIn) Identify(context.Context, string) (string, error) {
	return "", errors.New("the Google sign-in needs the callback's state to check its nonce")
}

// IdentifyAccount implements [issuer.AccountSignIn]: the ID token must carry the
// nonce of state, and the account's `sub` is what the issuer pins the address to.
func (g *googleSignIn) IdentifyAccount(ctx context.Context, code, state string) (email, subject string, err error) {
	client, err := g.client.Get(ctx)
	if err != nil {
		return "", "", err
	}
	account, err := google.IdentifyAccount(ctx, client, code, state)
	return account.Email, account.Subject, err
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
func signingKey(ctx context.Context, cfg Config, log *slog.Logger) (*signer.SigningKey, error) {
	if cfg.signingKeyFile == "" {
		log.WarnContext(ctx, "generating a signing key for this process: every restart invalidates "+
			"every token it signed, and two replicas would sign with two keys. "+
			"A deployment sets signingKey.file")
		return signer.NewSigningKey()
	}
	encoded, err := os.ReadFile(cfg.signingKeyFile) //nolint:gosec // the path is deployment configuration
	if err != nil {
		// Starting without it would mean signing with a key nobody else
		// has, which is worse than not starting: the tokens would look
		// fine and verify nowhere.
		return nil, fmt.Errorf("read the signing key: %w — a deployment provides it as a Secret, "+
			"issued by cert-manager or delivered by external-secrets, mounted at that path", err)
	}
	key, err := signer.ParseSigningKey(encoded)
	if err != nil {
		return nil, err
	}
	log.InfoContext(ctx, "signing with the key this installation was given",
		slog.String("file", cfg.signingKeyFile), slog.String("kid", key.ID()))
	return key, nil
}

// additionalSigningKeys reads every OTHER algorithm this installation
// signs with at once, beside the primary [signingKey] — one file per
// algorithm, named in signingKey.additionalFiles, matching the chart's
// `signingKey.additional`.
//
// Read eagerly, at start, and not lazily on first use: [issuer.NewStorage]
// needs every configured algorithm in hand before it can refuse a policy
// naming one that has no key (requirement 2), and a deployment whose
// mount is broken should fail before it serves a single request rather
// than the first time somebody reaches a client that names it.
func additionalSigningKeys(ctx context.Context, cfg Config, log *slog.Logger) ([]*signer.SigningKey, error) {
	out := make([]*signer.SigningKey, 0, len(cfg.additionalSigningKeyFiles))
	for _, path := range cfg.additionalSigningKeyFiles {
		encoded, err := os.ReadFile(path) //nolint:gosec // the path is deployment configuration
		if err != nil {
			return nil, fmt.Errorf("read an additional signing key: %w — a deployment provides it as a "+
				"Secret, issued by cert-manager or delivered by external-secrets, mounted at that path", err)
		}
		key, err := signer.ParseSigningKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		log.InfoContext(ctx, "signing with an additional key this installation was given",
			slog.String("file", path), slog.Any("algorithm", key.SignatureAlgorithm()), slog.String("kid", key.ID()))
		out = append(out, key)
	}
	return out, nil
}

// watchSigningKey re-reads every mounted key file on an interval and
// feeds every version this replica reads to the storage's key rings — see
// [signer.KeyRings] for the schedule that turns that into rotation with no
// restart, one file routed to its OWN algorithm's track (requirement six
// of live rotation: rotating one never disturbs another's). It runs
// until ctx is done, which happens together with the two listeners in
// [App.Run].
//
// A local run with no file configured has nothing to poll: the one key
// [signingKey] generated for it is the only key there will ever be.
//
// A read or parse failure after the first is logged and the previous key
// kept, never returned: a Secret Kubernetes is mid-projecting can be
// observed for an instant while `..data` is being swapped, and a poller
// that failed loudly over a read that would have succeeded thirty seconds
// later would turn a non-event into an incident. The same is true of a
// path that names an algorithm nothing was configured for at start
// ([signer.KeyRings.Rotate] refuses it) — logged and skipped, not fatal,
// because the deployment is already running with what it started with.
func watchSigningKey(ctx context.Context, paths []string, interval time.Duration, keys *signer.KeyRings, log *slog.Logger) {
	paths = nonEmpty(paths)
	if len(paths) == 0 {
		return
	}
	if interval <= 0 {
		interval = signer.DefaultKeyPollInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, path := range paths {
				pollSigningKeyFile(ctx, path, keys, log)
			}
		}
	}
}

// pollSigningKeyFile is one file, one poll tick: read, parse and hand to
// the storage's key rings, which route it to the track for its own
// algorithm. Split out of [watchSigningKey] so that one bad file's
// `continue` cannot accidentally skip the others sharing its tick.
func pollSigningKeyFile(ctx context.Context, path string, keys *signer.KeyRings, log *slog.Logger) {
	encoded, err := os.ReadFile(path) //nolint:gosec // the path is deployment configuration
	if err != nil {
		log.WarnContext(ctx, "could not re-read a signing key; keeping the previous one",
			slog.String("file", path), slog.Any("error", err))
		return
	}
	key, err := signer.ParseSigningKey(encoded)
	if err != nil {
		log.WarnContext(ctx, "a re-read signing key could not be parsed; keeping the previous one",
			slog.String("file", path), slog.Any("error", err))
		return
	}
	if err := keys.Rotate(ctx, key); err != nil {
		log.WarnContext(ctx, "a re-read signing key could not be adopted", slog.String("file", path), slog.Any("error", err))
	}
}

// nonEmpty drops blank paths, which is what a primary [Config.signingKeyFile]
// left unset by a local run looks like once joined with the additional
// ones.
func nonEmpty(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if path != "" {
			out = append(out, path)
		}
	}
	return out
}

// readStateSecret reads the sign-in state's secret the document names, and
// parses it.
func readStateSecret(ctx context.Context, cfg Config, name, key string) ([]byte, error) {
	if cfg.v5 != nil {
		raw, _, err := cfg.v5.OIDC().StateSecret().Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("read %s (%s/state-secret): %w", key, cfg.v5.OIDC().Prefix(), err)
		}
		seed, err := parseStateSecret(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		return seed, nil
	}
	if cfg.secrets == nil {
		return nil, fmt.Errorf("%s: no secrets source is configured", key)
	}
	raw, err := cfg.secrets.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	seed, err := parseStateSecret([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return seed, nil
}

// openState decides where a login in progress lives.
//
// In memory unless a Valkey is configured, and at more than one replica
// that difference is not a nicety: a browser starts at /authorize on one
// replica, comes back from the provider at another, and the client
// redeems the code at a third. Each of those is a coin toss that looks
// like an intermittent failure, so a deployment running more than one
// replica without a Valkey is a mistake worth saying out loud.
func openState(ctx context.Context, st *store.Stores, log *slog.Logger) issuer.State {
	if !st.Usable {
		log.WarnContext(ctx, "keeping logins in progress in memory: correct for one replica, "+
			"and at more than one a browser that comes back to a different pod finds nothing",
			slog.String("state", "memory"))
		return issuer.NewMemoryState()
	}
	log.InfoContext(ctx, "keeping logins in progress in the state ports",
		slog.String("state", st.Name()), slog.String("adapter", st.Adapter))
	return issuer.NewPortState(st.Ports.State, st.Ports.Index)
}

// openVerifiers builds what can turn somebody else's token into a proof.
//
// A deployment with none can still sign people in; it simply exchanges
// nothing, and says so, because an exchange endpoint that refuses
// everything with "unverified" is indistinguishable from one that is
// misconfigured.
//
// The clusters and the AWS accounts are also returned on their own: they are the
// two kinds of proof the console accepts as a bearer, from a workload in a
// federated cluster or a Lambda function's role calling its API.
func openVerifiers(ctx context.Context, cfg Config, log *slog.Logger) (all, clusters issuer.Verifiers, err error) {
	var verifiers issuer.Verifiers

	// Clusters, by their own published key set and NEVER by asking them.
	// The other way to check a ServiceAccount token is a
	// TokenReview, which means holding a kubeconfig for every cluster
	// whose workloads may exchange — inside the service whose whole point
	// is to hold almost no credential. A key set is public, so a remote
	// cluster's workload proves itself exactly the way a GitHub job does,
	// and adding a cluster is one row naming a URL.
	//
	// This service's OWN cluster is a row like any other. There is no
	// special case for it, because a special case is a second code path
	// that only one installation exercises.
	federation := verify.Federation{}
	for _, row := range cfg.clusters {
		federation.Clusters = append(federation.Clusters, verify.FederatedCluster{Name: row.Name, Issuer: row.Issuer, JWKSURI: row.JWKSURI})
	}
	for _, cluster := range federation.Verifiers(cfg.audience, nil) {
		verifiers = append(verifiers, cluster)
		clusters = append(clusters, cluster)
	}
	if len(federation.Clusters) > 0 {
		log.InfoContext(ctx, "workload tokens are verified against each cluster's own key set",
			slog.Any("clusters", federation.Names()), slog.String("audience", cfg.audience))
	} else {
		log.InfoContext(ctx, "no workload token can be verified: no cluster's key set is declared")
	}

	// AWS accounts, by each account's own published key set. Like a
	// cluster, an account is a row naming where its keys are; unlike one
	// there is no default, because any AWS account can mint a valid token
	// for a role of its own.
	awsFederation := awsFederationOf(cfg.aws)
	for _, account := range awsFederation.Verifiers(nil) {
		verifiers = append(verifiers, account)
	}
	// And a role may present its token to the console directly, as a
	// ServiceAccount does: a Lambda controller has no projected token. By the
	// console's OWN audience, so that a token minted for token exchange is no
	// bearer here and the reverse: each door is one decision.
	if len(awsFederation.Accounts) > 0 {
		if cfg.consoleAWSAudience == awsFederation.Audience {
			return nil, nil, fmt.Errorf("console.awsAudience %q is the AWS federation file's audience: "+
				"the console and the token exchange are two doors and each takes its own", cfg.consoleAWSAudience)
		}
		for _, account := range consoleAWSVerifiers(awsFederation, cfg.consoleAWSAudience, nil) {
			clusters = append(clusters, account)
		}
		log.InfoContext(ctx, "AWS role tokens are bearers at the console by their own audience",
			slog.String("audience", cfg.consoleAWSAudience))
	}
	if len(awsFederation.Accounts) > 0 {
		log.InfoContext(ctx, "AWS role tokens are verified against each account's own key set",
			slog.Any("accounts", awsFederation.Names()), slog.String("audience", awsFederation.Audience))
	} else {
		log.InfoContext(ctx, "no AWS role token can be verified: no account is declared")
	}

	// GitHub, only when this installation has said whose repositories it
	// runs jobs for. There is no default and there cannot be one: anybody
	// may run a workflow in their own repository and get a valid token
	// from GitHub, so an empty list would admit every repository there is
	// rather than none.
	if len(cfg.githubOwners) > 0 {
		log.InfoContext(ctx, "CI tokens are verified against GitHub",
			slog.Any("owners", cfg.githubOwners), slog.String("audience", cfg.issuerURL))
		verifiers = append(verifiers, &verify.GitHub{
			Owners:        cfg.githubOwners,
			OwnerIDs:      cfg.githubOwnerIDs,
			RepositoryIDs: cfg.githubRepositoryID,
			// The audience a workflow must request is this issuer's own
			// URL. A token minted for a cloud provider is a valid GitHub
			// token, and one audience per relying party is what keeps it
			// from being replayed here.
			Audience: cfg.issuerURL,
		})
	} else {
		log.InfoContext(ctx, "no CI token can be verified: github.owners names no organisation")
	}

	// An exchange endpoint that refuses everything with "unverified" is
	// indistinguishable from one that is misconfigured, so a deployment
	// that can verify nothing says so rather than looking broken later.
	if len(verifiers) == 0 {
		log.WarnContext(ctx, "no proof can be verified: token exchange will refuse everything")
	}

	return verifiers, clusters, nil
}

// serve runs one listener until the context is done, then drains it.
func serve(ctx context.Context, addr string, handler http.Handler, name string, log *slog.Logger) error {
	// Bounded in what it reads and how long it waits: see [httpsec].
	srv := httpsec.NewServer(addr, refusal.Middleware(handler))
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.WarnContext(ctx, "listener did not drain", slog.String("listener", name), slog.Any("error", err))
		}
	}()
	log.InfoContext(ctx, "listening", slog.String("listener", name), slog.String("address", addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s listener: %w", name, err)
	}
	return nil
}

// configuredKMSAlgorithms are the algorithms the KMS modes sign with, the first
// the installation's default, known from the configuration alone so that the
// keys need not be open to answer discovery. A clash between two keys of one
// algorithm is refused here, at assembly, as it is when the rings are built.
func configuredKMSAlgorithms(cfg Config, files []*signer.SigningKey) ([]jose.SignatureAlgorithm, error) {
	var algs []jose.SignatureAlgorithm
	if cfg.kmsWrapped != nil {
		wcfg, err := cfg.wrappedConfig()
		if err != nil {
			return nil, err
		}
		algs = slices.Clone(wcfg.Algorithms)
	} else {
		algs = []jose.SignatureAlgorithm{jose.ES384}
		for _, a := range cfg.kmsAdditional {
			if jose.SignatureAlgorithm(a.Alg) != jose.RS256 || len(a.Keys) == 0 {
				return nil, fmt.Errorf("signingKey.kms.additional: %q needs alg RS256 and keys", a.Alg)
			}
			algs = append(algs, jose.SignatureAlgorithm(a.Alg))
		}
	}
	for _, f := range files {
		algs = append(algs, f.SignatureAlgorithm())
	}
	seen := map[jose.SignatureAlgorithm]bool{}
	for _, alg := range algs {
		if seen[alg] {
			return nil, fmt.Errorf("issuer: two signing keys both sign %s; each configured algorithm needs exactly one key", alg)
		}
		seen[alg] = true
	}
	return algs, nil
}

// kmsSigningKeys reads every KMS key in signingKey.kms at start, in order.
//
// The LAST is returned as the primary, the only key ever recorded as new; the
// earlier ones are returned apart and fed through RotateKnown, which refreshes
// a key the installation already knows and never adopts one it does not. So
// state lost without tombstones cannot make a replica start by signing with
// the oldest key. Only ever append a key.
//
// A key the role cannot read stops the start, with the missing permission
// named; starting without it would sign with fewer keys than the deployment
// declared.
func kmsSigningKeys(
	ctx context.Context, cfg Config, api signer.KMSAPI, log *slog.Logger,
) (refs []*signer.KMSKeyRefs, earlier []*signer.SigningKey, primary *signer.SigningKey, more []*signer.SigningKey, err error) {
	seed, err := readStateSecret(ctx, cfg, cfg.kmsStateSecret, "signingKey.kms.stateSecret")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if api == nil {
		var loaders []func(*awsconfig.LoadOptions) error
		if cfg.kmsRegion != "" {
			loaders = append(loaders, awsconfig.WithRegion(cfg.kmsRegion))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loaders...)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("load the AWS configuration for signingKey.kms: %w", err)
		}
		api = kms.NewFromConfig(awsCfg, func(o *kms.Options) { o.TracerProvider, o.MeterProvider = awsotel.Providers() })
	}
	sets := []*signer.KMSKeyRefs{{Alg: jose.ES384, API: api, Refs: cfg.kmsKeys, Seed: seed}}
	for _, a := range cfg.kmsAdditional {
		if jose.SignatureAlgorithm(a.Alg) != jose.RS256 || len(a.Keys) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("signingKey.kms.additional: %q needs alg RS256 and keys", a.Alg)
		}
		sets = append(sets, &signer.KMSKeyRefs{Alg: jose.SignatureAlgorithm(a.Alg), API: api, Refs: a.Keys, Seed: seed})
	}
	seen := map[string]string{}
	for n, set := range sets {
		keys, err := set.Load(ctx)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		for i, key := range keys {
			if prev, dup := seen[key.ID()]; dup {
				return nil, nil, nil, nil, fmt.Errorf("signingKey.kms: %q and %q are the same key", prev, set.Refs[i])
			}
			seen[key.ID()] = set.Refs[i]
			log.InfoContext(ctx, "signing with an AWS KMS key",
				slog.String("key", set.Refs[i]), slog.String("kid", key.ID()), slog.Any("algorithm", key.SignatureAlgorithm()), slog.Bool("active", i == len(keys)-1))
		}
		// The LAST of each list is that algorithm's ring primary; the rest are
		// only ever refreshed.
		last := len(keys) - 1
		earlier = append(earlier, keys[:last]...)
		if n == 0 {
			primary = keys[last]
		} else {
			more = append(more, keys[last])
		}
	}
	return sets, earlier, primary, more, nil
}

// watchKMSKeys re-reads every KMS key's public half on an interval and feeds
// it to the key rings, the KMS twin of [watchSigningKey]. Each key is read on
// its own, so one that fails does not hide the others, and a failure keeps the
// previous key as a file read that fails does. Re-reading is what notices an
// alias moved to another key: it reads as a new kid and is scheduled as one.
func watchKMSKeys(
	ctx context.Context, sets []*signer.KMSKeyRefs, interval time.Duration, keys *signer.KeyRings, log *slog.Logger,
	checkSecret func(context.Context) error,
) {
	if interval <= 0 {
		interval = signer.DefaultKeyPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-written if the record lapsed; a mismatch is logged, not fatal.
			if err := checkSecret(ctx); err != nil {
				log.WarnContext(ctx, "the KMS state secret check failed", slog.Any("error", err))
			}
			for _, refs := range sets {
				pollKMSRefs(ctx, refs, keys, log)
			}
		}
	}
}

// pollKMSRefs re-reads one algorithm's list.
func pollKMSRefs(ctx context.Context, refs *signer.KMSKeyRefs, keys *signer.KeyRings, log *slog.Logger) {
	for i, ref := range refs.Refs {
		one := signer.KMSKeyRefs{Alg: refs.Alg, API: refs.API, Refs: []string{ref}, Seed: refs.Seed}
		loaded, err := one.Load(ctx)
		if err != nil {
			log.WarnContext(ctx, "could not re-read a KMS signing key; keeping the previous one",
				slog.String("key", ref), slog.Any("error", err))
			continue
		}
		// List order is age: only the LAST key may be newly recorded. The
		// earlier ones are re-read to refresh a key the ring holds, and a
		// retired one is never brought back by being listed.
		rotate := keys.RotateKnown
		if i == len(refs.Refs)-1 {
			rotate = keys.Rotate
		}
		if err := rotate(ctx, loaded[0]); err != nil {
			log.WarnContext(ctx, "a re-read KMS signing key could not be adopted", slog.String("key", ref), slog.Any("error", err))
		}
	}
}

// applySigningPlan makes the registry's resolved signing adapter the one that
// is used. The legacy `signingKey` keys already resolve to it (file by
// default, kms when `signingKey.kms` is written), so a deployment that
// names no adapter runs exactly as before; the choice differs only when a
// preset or `adapters.signing` names one, and then it must agree with what
// `signingKey` says rather than be ignored.
func applySigningPlan(ctx context.Context, cfg *Config, plan port.Table) error {
	choice, ok := plan[port.ConcernSigning]
	if !ok {
		return nil
	}
	desc, found := port.Default.Lookup(port.ConcernSigning, choice.Adapter)
	if !found || desc.Factory == nil {
		return fmt.Errorf("adapters: the signing adapter %q cannot be built", choice.Adapter)
	}
	// The adapter named with no settings of its own, over the legacy
	// `signingKey.<adapter>` block that already says everything: nothing to build.
	var built any
	configured := choice.Adapter == "kms" && len(cfg.kmsKeys) > 0 || choice.Adapter == "kms-wrapped" && cfg.kmsWrapped != nil
	if len(choice.Settings) > 0 || !configured {
		var err error
		if built, err = desc.Factory(ctx, choice.Settings); err != nil {
			return fmt.Errorf("adapters.signing: %w", err)
		}
	}
	switch choice.Adapter {
	case "kms-wrapped":
		k, _ := built.(*port.KMSWrappedSigning)
		if cfg.signingKeyFile != "" || len(cfg.kmsKeys) > 0 {
			return errors.New("the signing adapter is kms-wrapped and signingKey.file or signingKey.kms is set: " +
				"a key is a file, a KMS key or a KMS-wrapped key pair, not several")
		}
		if cfg.kmsWrapped == nil && k != nil {
			w, err := wrappedFromPort(k)
			if err != nil {
				return fmt.Errorf("adapters.signing: %w", err)
			}
			cfg.kmsWrapped = w
		}
		if _, err := cfg.wrappedConfig(); err != nil {
			return err
		}
	case "kms":
		k, _ := built.(*port.KMSSigning)
		if cfg.signingKeyFile != "" {
			return errors.New("the signing adapter is kms and signingKey.file is set: a key is a file or a KMS key, not both")
		}
		if cfg.kmsWrapped != nil {
			return errors.New("the signing adapter is kms and signingKey.kmsWrapped is set: a key is a KMS key or a KMS-wrapped key pair, not both")
		}
		if len(cfg.kmsKeys) == 0 && k != nil {
			cfg.kmsKeys, cfg.kmsRegion, cfg.kmsStateSecret = k.Keys, k.Region, k.StateSecret
			for _, a := range k.Additional {
				cfg.kmsAdditional = append(cfg.kmsAdditional, config.SigningKeyKMSAlg{Alg: a.Alg, Keys: a.Keys})
			}
		}
	case "file":
		if len(cfg.kmsKeys) > 0 {
			return errors.New("the signing adapter is file and signingKey.kms is set: a key is a file or a KMS key, not both")
		}
		if cfg.kmsWrapped != nil {
			return errors.New("the signing adapter is file and signingKey.kmsWrapped is set: a key is a file or a KMS-wrapped key pair, not both")
		}
	}
	return nil
}

// wrappedFromPort is the adapter's settings as the file's `signingKey.kmsWrapped`.
func wrappedFromPort(k *port.KMSWrappedSigning) (*config.SigningKeyKMSWrapped, error) {
	out := &config.SigningKeyKMSWrapped{KeyID: k.KeyID, Region: k.Region, StateSecret: k.StateSecret, Algorithms: k.Algorithms}
	for name, v := range map[string]struct {
		in  string
		out **config.Duration
	}{
		"rotateEvery": {k.RotateEvery, &out.RotateEvery},
		"prepublish":  {k.Prepublish, &out.Prepublish},
		"retain":      {k.Retain, &out.Retain},
	} {
		if v.in == "" {
			continue
		}
		d, err := time.ParseDuration(v.in)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		cd := config.Duration(d)
		*v.out = &cd
	}
	return out, nil
}

// wrappedConfig resolves `signingKey.kmsWrapped` against the rest of the
// configuration: the algorithms default to ES384 and RS256, the rotation to
// every 24h, the pre-publish to half the rotation and never shorter than
// `signingKey.activationDelay` ([signer.WrappedPrepublishDefault]), and the
// retention to `signingKey.overlap` (the token lifetime plus a skew margin), and
// then the schedule is held to what makes it safe (see
// [signer.WrappedConfig.Validate]).
func (c Config) wrappedConfig() (signer.WrappedConfig, error) {
	k := c.kmsWrapped
	rotateEvery := dur(k.RotateEvery, signer.DefaultWrappedRotateEvery)
	out := signer.WrappedConfig{
		RotateEvery: rotateEvery,
		Prepublish:  dur(k.Prepublish, signer.WrappedPrepublishDefault(rotateEvery, c.keyActivationDelay)),
		Retain:      dur(k.Retain, c.keyOverlap),
		Interval:    c.keyPollInterval,
	}
	if k.StateSecret == "" {
		return out, errors.New("signingKey.kmsWrapped.stateSecret is required")
	}
	if _, _, err := c.signKeys(); err != nil {
		return out, err
	}
	algs := k.Algorithms
	if len(algs) == 0 {
		algs = []string{string(jose.ES384), string(jose.RS256)}
	}
	for _, a := range algs {
		out.Algorithms = append(out.Algorithms, jose.SignatureAlgorithm(a))
	}
	if out.Prepublish < c.keyPollInterval {
		return out, fmt.Errorf("signingKey.kmsWrapped.prepublish (%v) must be at least signingKey.pollInterval (%v)", out.Prepublish, c.keyPollInterval)
	}
	return out, out.Validate(c.tokenLifetime)
}

// signKeys is the `keys` block the wrapped ring wraps under, and the warnings
// to log about how it was spelled. `keys.sign` is the key. The deprecated
// `signingKey.kmsWrapped.keyId` is mapped onto it when it is an alias and no
// `keys.sign` is set; an ARN or an id is refused, as `keys` refuses them.
func (c Config) signKeys() (keys.Config, []string, error) {
	var warnings []string
	legacy := strings.TrimSpace(c.kmsWrapped.KeyID)
	if legacy != "" {
		warnings = append(warnings, "signingKey.kmsWrapped.keyId is deprecated and goes in a later release: "+
			"name the symmetric key as keys.sign (keys: {adapter: kms, sign: "+legacy+"})")
	}
	if c.keys != nil {
		if _, ok := c.keys.Keys[keys.Sign]; ok {
			if legacy != "" {
				warnings = append(warnings, "signingKey.kmsWrapped.keyId is ignored: keys.sign is set")
			}
			return *c.keys, warnings, nil
		}
	}
	if legacy == "" {
		return keys.Config{}, nil, errors.New("signingKey.kmsWrapped needs the key that wraps the signing keys: " +
			"set keys.sign (keys: {adapter: kms, sign: alias/<name>})")
	}
	if !strings.HasPrefix(legacy, "alias/") {
		return keys.Config{}, nil, fmt.Errorf("signingKey.kmsWrapped.keyId %q is not an alias: name the key by alias as keys.sign "+
			"(keys: {adapter: kms, sign: alias/<name>}); an id or an ARN is no longer accepted", legacy)
	}
	out := keys.Config{Adapter: "kms", Keys: map[keys.Purpose]keys.Entry{keys.Sign: {Key: legacy}}}
	if c.keys != nil {
		// Other purposes stay; only the sign key is mapped.
		out.Adapter = c.keys.Adapter
		for p, e := range c.keys.Keys {
			out.Keys[p] = e
		}
		out.Keys[keys.Sign] = keys.Entry{Key: legacy}
	}
	return out, warnings, out.Validate()
}

// signKey opens the key behind `keys.sign`; the signer opens it.
func signKey(ctx context.Context, cfg Config, deps Deps, log *slog.Logger) (*keys.Key, error) {
	kc, warnings, err := cfg.signKeys()
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		log.WarnContext(ctx, "signing key configuration warning", slog.String("warning", w))
	}
	return signer.OpenSignKey(ctx, kc, cfg.kmsWrapped.Region, cfg.instance, deps.Keys)
}

// wrappedSigningKeys opens the KMS-wrapped signing at start: the client, the
// state secret, the lease that serialises key generation, and the key each
// algorithm signs with (read from the shared state, or generated now). The
// first algorithm's key is the primary.
func wrappedSigningKeys(
	ctx context.Context, cfg Config, deps Deps, stores *store.Stores, state issuer.State, log *slog.Logger,
) (*signer.WrappedSigning, *signer.SigningKey, []*signer.SigningKey, error) {
	wcfg, err := cfg.wrappedConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	seed, err := readStateSecret(ctx, cfg, cfg.kmsWrapped.StateSecret, "signingKey.kmsWrapped.stateSecret")
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := signKey(ctx, cfg, deps, log)
	if err != nil {
		return nil, nil, nil, err
	}
	// The lease is on the State port, as every controller's is: a Create with a
	// lifetime. Without a shared store (a local run) it is this process's own.
	leaseState := port.State(memory.New())
	if stores != nil && stores.Usable {
		leaseState = stores.Ports.State
	}
	leases := &rails.Leases{State: leaseState, Holder: rails.NewHolder(), Log: log, Maintenance: stores.Maintenance()}
	lease := func(ctx context.Context, alg jose.SignatureAlgorithm, fn func(context.Context) error) (bool, error) {
		var inner error
		ran, err := leases.Do(ctx, "signing-keygen", string(alg), func(lctx context.Context) { inner = fn(lctx) })
		if err != nil {
			return false, err
		}
		return ran, inner
	}
	ws, err := signer.NewWrappedSigning(wcfg, key, seed, lease, log)
	if err != nil {
		return nil, nil, nil, err
	}
	primary, more, err := ws.Bootstrap(ctx, state)
	if err != nil {
		return nil, nil, nil, err
	}
	log.InfoContext(ctx, "signing with wrapped keys", slog.Any("purpose", keys.Sign), slog.Any("context", key.Context()), slog.Any("algorithms", wcfg.Algorithms),
		slog.Duration("rotate_every", wcfg.RotateEvery), slog.Duration("prepublish", wcfg.Prepublish), slog.Duration("retain", wcfg.Retain),
		slog.String("kid", primary.ID()), slog.Any("algorithm", primary.SignatureAlgorithm()))
	return ws, primary, more, nil
}

// parseStateSecret reads the state secret ([secrets.ParseStateSecret]).
func parseStateSecret(raw []byte) ([]byte, error) { return secrets.ParseStateSecret(raw) }

// checkStateSecret publishes a short HMAC fingerprint of the state secret in
// the shared state and refuses to start when it differs from the one already
// there: replicas with different secrets would each reject the other's
// sign-in state. The fingerprint reveals nothing of the secret.
func checkStateSecret(ctx context.Context, state issuer.State, seed []byte) error {
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("sluis/kms-state-secret-fingerprint"))
	fingerprint := []byte(hex.EncodeToString(mac.Sum(nil)[:8]))
	const key = "issuer:kms:state-secret-fingerprint"
	won, err := state.SetIfAbsent(ctx, key, fingerprint, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("record the state secret's fingerprint: %w", err)
	}
	if won {
		return nil
	}
	stored, _, err := state.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("read the state secret's fingerprint: %w", err)
	}
	if !hmac.Equal(stored, fingerprint) {
		return errors.New("signingKey.kms.stateSecret differs from the secret other replicas use " +
			"(fingerprint mismatch): every replica needs the same file. To rotate it deliberately, " +
			"delete the shared state key " + key)
	}
	return nil
}

// BroadAWSMatchers names the groups whose `aws` matchers admit every role of
// their account: one with no `role`, or a bare `*`. That is a rule somebody may
// have meant, and one that grows by itself with the account, so it is said at
// start and never refused (an existing policy may rely on it).
func BroadAWSMatchers(set *policy.Set) []string {
	var out []string
	declared := set.Declared()
	names := make([]string, 0, len(declared.Groups))
	for name := range declared.Groups {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, m := range declared.Groups[name].Matchers {
			if m.AWS != nil && (m.AWS.Role == "" || m.AWS.Role == "*") {
				out = append(out, name+" (account "+m.AWS.Account+")")
			}
		}
	}
	return out
}

func warnBroadAWSMatchers(ctx context.Context, set *policy.Set, log *slog.Logger) {
	if broad := BroadAWSMatchers(set); len(broad) > 0 {
		log.WarnContext(ctx, "aws matchers with no role (or a bare *) admit EVERY role of the account, "+
			"including roles created later: name the role unless that is meant", slog.Any("groups", broad))
	}
}

// LengtheningResources lists, sorted, the resources whose `absolute_cap`
// lengthens the installation's `lifetimes.absolute` under the read-only
// exception that docs/decisions/0040-agent-class-sessions.md deprecates.
func LengtheningResources(set *policy.Set, absolute time.Duration) []string {
	var out []string
	rows := set.Resources()
	for i := range rows {
		if rows[i].LengthensAbsolute(absolute) {
			out = append(out, rows[i].ID)
		}
	}
	return out
}

// warnAgentClasses says at start what the policy declares about session
// classes that is accepted but probably not meant: an agent client that
// also describes a browser-facing application, and a read-only resource
// still lengthening the absolute limit, which agent class replaces.
func warnAgentClasses(ctx context.Context, set *policy.Set, absolute time.Duration, log *slog.Logger) {
	if clients := set.BrowserFacingAgents(); len(clients) > 0 {
		log.WarnContext(ctx, "clients declare session: agent and also signed_out or backchannel_logout_uri, "+
			"which describe an application a person uses in a browser: an agent chain lives a month and "+
			"is meant for software that holds its own refresh token", slog.Any("clients", clients))
	}
	if resources := LengtheningResources(set, absolute); len(resources) > 0 {
		log.WarnContext(ctx, "resources carry read_only and an absolute_cap longer than lifetimes.absolute; "+
			"that lengthening is deprecated and a later minor release refuses it: mark the clients that need "+
			"a longer chain session: agent, then remove absolute_cap from these resources or lower it to at "+
			"most lifetimes.absolute (docs/decisions/0040-agent-class-sessions.md)",
			slog.Any("resources", resources), slog.String("absolute", absolute.String()))
	}
}

// consoleAWSVerifiers are the AWS accounts' verifiers for the console door: the
// same rows as token exchange's, with the console's own audience.
func consoleAWSVerifiers(f verify.AWSFederation, audience string, client *http.Client) []*verify.AWSAccount {
	f.Audience = audience
	return f.Verifiers(client)
}

// awsFederationOf is the policy document's exchange.aws as the verifiers take
// it. The rows were held to their rules when the document was loaded.
func awsFederationOf(a config.AWSFederation) verify.AWSFederation {
	out := verify.AWSFederation{Audience: strings.TrimSpace(a.Audience)}
	if a.MaxAge != nil {
		out.MaxAge = a.MaxAge.D()
	}
	for _, row := range a.Accounts {
		out.Accounts = append(out.Accounts, verify.AWSAccountRow{
			Account: row.Account, Name: row.Name, Issuer: strings.TrimSuffix(row.Issuer, "/"),
			JWKSURI: row.JWKSURI, OrgID: row.OrgID, Algs: row.Algs,
		})
	}
	return out
}

// loadVerifyOnly reads the public keys `signingKey.verifyOnly` names. A file that
// is unreadable, not a public key (a private key included) or not for the
// algorithm it says stops the start, naming the entry and never the content.
func loadVerifyOnly(entries []config.SigningKeyVerifyOnly, log *slog.Logger) ([]issuer.VerifyOnlyKey, error) {
	var out []issuer.VerifyOnlyKey
	ids := map[string]bool{}
	for i, e := range entries {
		raw, err := os.ReadFile(e.File) //nolint:gosec // the path is the deployment's configuration
		if err != nil {
			return nil, fmt.Errorf("signingKey.verifyOnly[%d]: read %s: %w", i, e.File, err)
		}
		if e.Until == "" {
			return nil, fmt.Errorf("signingKey.verifyOnly[%d].until is required: a key published for good is not an overlap", i)
		}
		until, err := time.Parse(time.RFC3339, e.Until)
		if err != nil {
			return nil, fmt.Errorf("signingKey.verifyOnly[%d].until: %q is not an RFC 3339 time", i, e.Until)
		}
		key, err := issuer.ParseVerifyOnlyKey(raw, e.KeyID, e.Alg, until)
		if err != nil {
			return nil, fmt.Errorf("signingKey.verifyOnly[%d] (%s): %w", i, e.File, err)
		}
		if ids[key.ID] {
			return nil, fmt.Errorf("signingKey.verifyOnly[%d]: kid %q is named twice", i, key.ID)
		}
		ids[key.ID] = true
		if !time.Now().Before(key.Until) {
			log.WarnContext(context.Background(), "a verify-only signing key is past its `until` and is not published", slog.String("kid", key.ID))
		}
		out = append(out, key)
	}
	return out, nil
}
