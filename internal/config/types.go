// Package config is what each process of this repository is configured with:
// four documents, each read from one file and validated against a JSON Schema
// before anything starts.
//
//   - three service documents, one per process: `serve`, `controller-github`
//     and `controller-slack`, saying how the process runs: listeners,
//     storage, signing, lifetimes;
//   - one policy document, `policy`, saying what the installation decides:
//     the access model's tables, whom the token exchange trusts, which Apps an
//     operator may make, what each controller may change, and what is copied
//     out. Every service document names it (`policy.file`).
//
// Each document carries `apiVersion`. This build writes v2 and reads v2 and v1:
// a v1 document (one with no apiVersion) is converted as it is loaded, so a
// deployment moves on its own schedule. Configuration and policy are immutable
// for an instance: a change is a new instance (a rollout on Kubernetes, a new
// configuration layer on Lambda). What stays live is credentials and state.
//
// Layering happens only when a policy is rendered (`sluisctl policy render`,
// [Render]); a process loads exactly one policy document.
//
// Secrets are never in a document. Telemetry is not here at all; it is
// OpenTelemetry's own environment (OTEL_*).
//
// The types are written by hand and the schemas are generated from schema/
// into schemas/config/, which is committed; a test holds the two files to one
// another, and a second holds each type to its schema. The decision is
// docs/decisions/0032-one-configuration-file-one-binary-one-chart.md and, for
// the shared rules, truvity/policy 0002 and 0006.
package config

import (
	"github.com/truvity/sluis/internal/config/duration"
	"github.com/truvity/sluis/storage/keys"
)

// Duration is a time span as the file spells it: a Go duration string such as
// "30s", "2m" or "168h".
type Duration = duration.Duration

type (
	// Address is a TCP listener: host:port, an empty host binding every
	// interface. It is the shared shape of truvity/policy's fragments/listen.json
	// and probes.json.
	Address struct {
		Address string `json:"address"`
	}

	// Log is the shared shape of truvity/policy's fragments/log.json.
	Log struct {
		Level string `json:"level,omitempty"`
	}

	// Lifetimes are how long what the issuer hands out lives. A pointer is
	// "not set": zero is a value a file can state, and the absolute lifetime
	// refuses it.
	Lifetimes struct {
		Token    *Duration `json:"token,omitempty"`
		Refresh  *Duration `json:"refresh,omitempty"`
		Absolute *Duration `json:"absolute,omitempty"`
		Hold     *Duration `json:"hold,omitempty"`
		Session  *Duration `json:"session,omitempty"`
		// Agent is `lifetimes.agent`: how long the refresh chains of clients
		// the policy marks `session: agent` live.
		Agent *AgentLifetimes `json:"agent,omitempty"`
	}

	// HSTS is what the issuer and the console say about
	// Strict-Transport-Security on a response that arrived over https.
	HSTS struct {
		// MaxAge is how long a browser keeps the rule. Unset is a year;
		// zero sends no header.
		MaxAge *Duration `json:"maxAge,omitempty"`
		// IncludeSubDomains extends the rule to the host's subdomains.
		// Unset is false: a service on an apex or parent domain would pin
		// every sibling subdomain to https.
		IncludeSubDomains *bool `json:"includeSubDomains,omitempty"`
	}

	// AgentLifetimes are the agent class's own lifetimes
	// (docs/decisions/0040-agent-class-sessions.md): its idle limit, its
	// absolute limit from `auth_time`, and the mandatory cap on its access
	// and ID tokens. A pointer is "not set", which is the default.
	AgentLifetimes struct {
		Refresh  *Duration `json:"refresh,omitempty"`
		Absolute *Duration `json:"absolute,omitempty"`
		Access   *Duration `json:"access,omitempty"`
	}

	// Freshness is how the directory's snapshot is kept current.
	Freshness struct {
		RefreshInterval *Duration `json:"refreshInterval,omitempty"`
		FreshnessWindow *Duration `json:"freshnessWindow,omitempty"`
		ProbeInterval   *Duration `json:"probeInterval,omitempty"`
	}

	// Exchange is what the token exchange verifies workloads against.
	Exchange struct {
		Audience string `json:"audience,omitempty"`
	}

	// Recovery is the sign-in that needs no directory. A pointer for Enabled:
	// unset is the hub's default (on) and the issuer's (off), as it has always
	// been.
	Recovery struct {
		Enabled        *bool  `json:"enabled,omitempty"`
		ServiceAccount string `json:"serviceAccount,omitempty"`
		Audience       string `json:"audience,omitempty"`
		// LoginSecret (`passwordSecret`) names the recovery password, for a hub that is not
		// in a cluster: `recovery/password` in the layout.
		LoginSecret string `json:"passwordSecret,omitempty"`
		// VerifierSecret (`verifierSecret`) names the recovery account's SRP
		// verifier (`recovery/verifier`): a salt and a verifier, not the
		// password (docs/decisions/0076). Outside a cluster it is what the
		// password sign-in checks against; unset derives one from the password
		// at start, where the secrets are not layout v5's.
		VerifierSecret string `json:"verifierSecret,omitempty"`
		// Generation names this configuration's decision to have recovery on.
		// An operator who signs in through the identity provider may disable
		// recovery from the console; that is recorded in the State against the
		// generation in force, and a record covers only that generation. So a
		// redeploy of the SAME document keeps recovery disabled, and the way
		// back is a deliberate change of this value (any other string).
		// Unset is the generation "".
		Generation string `json:"generation,omitempty"`
	}

	// Conformance is the test account of the OpenID conformance harness: a
	// non-privileged subject that signs in with a username and password, only
	// to clients the policy marks `harness`, and only while Enabled
	// (docs/decisions/0076). Off unless the document turns it on.
	Conformance struct {
		Enabled bool `json:"enabled,omitempty"`
		// VerifierSecret (`verifierSecret`) names the account's SRP verifier
		// (`conformance/verifier`).
		VerifierSecret string `json:"verifierSecret,omitempty"`
	}

	// Forwarded is a sign-in an authenticating proxy in front of the console
	// has already done.
	Forwarded struct {
		Issuer      string `json:"issuer,omitempty"`
		Audience    string `json:"audience,omitempty"`
		EmailHeader string `json:"emailHeader,omitempty"`
	}

	// Login is how a person signs in to the console.
	Login struct {
		Directory  *bool      `json:"directory,omitempty"`
		SignOutURL string     `json:"signOutURL,omitempty"`
		Forwarded  *Forwarded `json:"forwarded,omitempty"`
	}

	// Console is where the console is published, for the sign-in that starts
	// there.
	Console struct {
		Origin string `json:"origin,omitempty"`
		Client string `json:"client,omitempty"`
		// AWSAudience is the audience an AWS role's web identity token must be
		// minted for to be a bearer at the console: its OWN, distinct from
		// `exchange`'s, so a token for one door is no proof at the other.
		AWSAudience string `json:"awsAudience,omitempty"`
		// Backup connects the console's Backups page to the backup module and
		// the restore function (docs/decisions/0071). Unset has no page.
		Backup *ConsoleBackup `json:"backup,omitempty"`
	}

	// ConsoleBackup is where the backup module and the restore function are
	// when the console calls them as the caller class `console`: a Lambda
	// function (through its `live-console` alias) or a Kubernetes Service each.
	// The console only reads from them.
	ConsoleBackup struct {
		// Function and URL name the backup module: exactly one of the two.
		Function string `json:"function,omitempty"`
		URL      string `json:"url,omitempty"`
		// RestoreFunction and RestoreURL name the restore function: at most one
		// of the two. Without either the page says there is none.
		RestoreFunction string `json:"restoreFunction,omitempty"`
		RestoreURL      string `json:"restoreURL,omitempty"`
		// Audience is the audience of the projected token a Service call
		// carries; each module's name when unset.
		Audience string `json:"audience,omitempty"`
		// TokenFile is where that token is mounted.
		TokenFile string `json:"tokenFile,omitempty"`
	}

	// OAuthClient is the client registered once with the directory backend.
	// Its secret is a file or a declared variable, never a value.
	OAuthClient struct {
		ID string `json:"id,omitempty"`
		// Provider names the client's two secrets,
		// providers/google/<provider>/client-id and .../client-secret. The
		// id may instead be ID, which is not a secret.
		Provider   string `json:"provider,omitempty"`
		SecretName string `json:"secretName,omitempty"`
		IDKey      string `json:"idKey,omitempty"`
		SecretKey  string `json:"secretKey,omitempty"`
	}

	// SigningKey is where the issuer's keys are and how they rotate.
	SigningKey struct {
		File            string    `json:"file,omitempty"`
		AdditionalFiles []string  `json:"additionalFiles,omitempty"`
		PollInterval    *Duration `json:"pollInterval,omitempty"`
		ActivationDelay *Duration `json:"activationDelay,omitempty"`
		Overlap         *Duration `json:"overlap,omitempty"`
		// KMS signs with AWS KMS keys instead of a file. Exclusive with File.
		KMS *SigningKeyKMS `json:"kms,omitempty"`
		// KMSWrapped signs with key pairs KMS generates and wraps under one
		// symmetric key, rotated automatically. Exclusive with File and KMS.
		KMSWrapped *SigningKeyKMSWrapped `json:"kmsWrapped,omitempty"`
		// VerifyOnly are public keys published in the JWKS and never signed
		// with, for a bounded overlap (a cutover from file keys to KMS ones).
		VerifyOnly []SigningKeyVerifyOnly `json:"verifyOnly,omitempty"`
	}

	// SigningKeyVerifyOnly is one public key published and never signed with.
	SigningKeyVerifyOnly struct {
		// File is a PEM public key (or a certificate's) or a JWK. A private key
		// is refused at start.
		File string `json:"file"`
		// KeyID is the `kid` the old tokens carry. Unset is the RFC 7638
		// thumbprint, which is what a file signer derived for the key.
		KeyID string `json:"kid,omitempty"`
		// Alg is the key's algorithm. Unset follows the key.
		Alg string `json:"alg,omitempty"`
		// Until is an RFC 3339 instant after which the key is not published.
		Until string `json:"until,omitempty"`
	}

	// SigningKeyKMSWrapped is the `kms-wrapped` signing adapter's settings: one
	// symmetric KMS key, the algorithms signed with, and the rotation schedule.
	SigningKeyKMSWrapped struct {
		// KeyID is DEPRECATED: the symmetric application key. `keys.sign`
		// replaces it; an alias given here is mapped onto `keys.sign` with a
		// warning for one release.
		KeyID  string `json:"keyId,omitempty"`
		Region string `json:"region,omitempty"`
		// StateSecret names the sign-in state's secret, as for `kms`.
		StateSecret string `json:"stateSecret,omitempty"`
		// Algorithms are ES384 and/or RS256, the first the default. Unset is
		// ES384 and RS256.
		Algorithms []string `json:"algorithms,omitempty"`
		// RotateEvery is how often a new key pair is generated. Default 24h.
		RotateEvery *Duration `json:"rotateEvery,omitempty"`
		// Prepublish is how long a new key is published before it signs.
		// Default half of RotateEvery (12h), and never shorter than
		// `signingKey.activationDelay`.
		Prepublish *Duration `json:"prepublish,omitempty"`
		// Retain is how long a superseded key stays published. Default
		// `signingKey.overlap`, which is `lifetimes.token` plus a skew margin.
		Retain *Duration `json:"retain,omitempty"`
	}

	// SigningKeyKMS is the AWS KMS source of the primary signing key.
	SigningKeyKMS struct {
		Keys        []string `json:"keys,omitempty"`
		Region      string   `json:"region,omitempty"`
		StateSecret string   `json:"stateSecret,omitempty"`
		// Additional is every OTHER algorithm signed at once, each on its own
		// ordered key list, beside Keys (ES384).
		Additional []SigningKeyKMSAlg `json:"additional,omitempty"`
	}

	// SigningKeyKMSAlg is one more algorithm's KMS keys.
	SigningKeyKMSAlg struct {
		Alg  string   `json:"alg"`
		Keys []string `json:"keys"`
	}

	// Valkey is the shared store for logins in progress and snapshots.
	Valkey struct {
		Address     string `json:"address,omitempty"`
		LoginSecret string `json:"passwordSecret,omitempty"`
		TLS         bool   `json:"tls,omitempty"`
		Cluster     *bool  `json:"cluster,omitempty"`
	}

	// OpenBaoAuth is how the service logs in to OpenBao inside each namespace
	// it writes to: the kubernetes or the jwt auth method, as a role, with a
	// token read from a file.
	OpenBaoAuth struct {
		Method    string `json:"method,omitempty"`
		Mount     string `json:"mount,omitempty"`
		Role      string `json:"role,omitempty"`
		TokenFile string `json:"tokenFile,omitempty"`
	}

	// Platform is the answers to the questions that pick a preset: what the
	// installation has to build on (docs/concepts/sluis/ports.md, "Adapters").
	Platform struct {
		AWS        bool   `json:"aws,omitempty"`
		Kubernetes bool   `json:"kubernetes,omitempty"`
		OpenBao    bool   `json:"openbao,omitempty"`
		Runtime    string `json:"runtime,omitempty"`
		Replicas   int    `json:"replicas,omitempty"`
	}

	// AdapterChoice names the adapter of one concern and its settings.
	AdapterChoice struct {
		Adapter  string         `json:"adapter"`
		Settings map[string]any `json:"settings,omitempty"`
	}

	// Ports chooses the adapter behind the storage ports of
	// docs/concepts/sluis/ports.md.
	//
	// Adapter picks the State, Index and Trigger (and, unless overridden below,
	// the Blob). Blob replaces one port with an adapter that composes with any
	// of them: State legacy with Blob s3 is valid.
	Ports struct {
		Adapter string     `json:"adapter,omitempty"`
		Blob    *PortsBlob `json:"blob,omitempty"`
		// DynamoDB is the table of the `dynamodb` adapter.
		DynamoDB *DynamoDB `json:"dynamodb,omitempty"`
	}

	// DynamoDB is where the `dynamodb` adapter keeps State, the transitional
	// Index and the Trigger: a table per module (layout v5). Credentials are
	// the platform's (Pod Identity, IRSA, a Lambda role), never configured.
	DynamoDB struct {
		// Tables is the table of each module, by module name. The single
		// table of layout v4 (`table`) was removed in v1.77.1.
		Tables   map[string]string `json:"tables,omitempty"`
		Region   string            `json:"region,omitempty"`
		Endpoint string            `json:"endpoint,omitempty"`
		Create   bool              `json:"create,omitempty"`
	}

	// PortsBlob names the adapter behind the Blob port.
	PortsBlob struct {
		Adapter string       `json:"adapter,omitempty"`
		S3      *PortsBlobS3 `json:"s3,omitempty"`
	}

	// PortsBlobS3 is where the S3 Blob adapter keeps its objects. Credentials
	// are the platform's (Pod Identity, IRSA, a Lambda role), never configured;
	// an S3-compatible endpoint with no such identity names them by address
	// (CredentialsRef), never by value.
	PortsBlobS3 struct {
		Bucket    string `json:"bucket,omitempty"`
		Prefix    string `json:"prefix,omitempty"`
		Region    string `json:"region,omitempty"`
		KMSKey    string `json:"kmsKey,omitempty"`
		Endpoint  string `json:"endpoint,omitempty"`
		PathStyle bool   `json:"pathStyle,omitempty"`
		// Checksum is the integrity header of every upload: sha256 (the
		// default, x-amz-checksum-sha256), md5 (Content-MD5) or none, for a
		// store that refuses SHA-256.
		Checksum string `json:"checksum,omitempty"`
		// CredentialsRef is the internal address (`internal/<module>/<name>`) of
		// the s3-credentials/v1 document the installation's secrets store
		// holds for Endpoint, or `external/cloudflare/<preset>`, the
		// cloudflare/v1 document the Cloudflare module rotates for an R2 preset
		// with `store: external`. It needs Endpoint and the ssm secrets source.
		CredentialsRef string `json:"credentialsRef,omitempty"`
		// Credentials makes sluis mint its own R2 credentials from a
		// `cloudflare.presets` entry instead of reading a static document. It
		// is exclusive with CredentialsRef, which stays the simple default
		// and needs no `cloudflare` section.
		Credentials *PortsBlobCredentials `json:"credentials,omitempty"`
	}

	// PortsBlobCredentials names the preset an S3-compatible store's
	// credentials are minted from.
	PortsBlobCredentials struct {
		// Preset is a key of `cloudflare.presets` with an `endpoint` (an R2
		// preset).
		Preset string `json:"preset"`
	}

	// Secrets is how the secrets a document names are delivered: `env`
	// (SLUIS_SECRET_<NAME>), `file` (<root>/<name>, read on every use) or
	// `ssm` (<root>/internal/config/<name>, read at once and again after
	// `refresh`). See internal/secrets.
	Secrets struct {
		Source   string    `json:"source"`
		Root     string    `json:"root,omitempty"`
		Region   string    `json:"region,omitempty"`
		Endpoint string    `json:"endpoint,omitempty"`
		Refresh  *Duration `json:"refresh,omitempty"`
		// KMSKeyID is `ssm`'s customer-managed key for the parameters the
		// service writes (credentials, exports). Unset is the AWS-managed key.
		KMSKeyID string `json:"kmsKeyId,omitempty"`
		// Layout is the storage layout of an `ssm` installation, and must be
		// `v5` (ADR 0072), module first: the only layout. `v4` (ADR 0041), and
		// with it an empty layout, were removed in v1.77.1.
		Layout string `json:"layout,omitempty"`
		// Grace is how long a rotated client secret's previous value is still
		// accepted (default 24h). It is the overlap of a
		// rotation: the previous revision of the document, while the current
		// one is younger than this.
		Grace *Duration `json:"grace,omitempty"`
		// ReadCache is how long one process keeps a decrypted document it read
		// from the `ssm` store (default 5m; 0s turns the cache off). A write
		// through the process drops the copy at once; a document that carries
		// its own expiry is not kept past it. SLUIS_SECRETS_READ_CACHE_TTL
		// overrides it.
		ReadCache *Duration `json:"readCache,omitempty"`
	}

	// PolicyRef names the one policy document a process decides by: the
	// canonical document `sluisctl policy render` writes. It is read once, at
	// start; a change is a new instance.
	PolicyRef struct {
		File string `json:"file,omitempty"`
	}

	// Directory is the corporate directories the deployment declares, which
	// the service adopts at start (the console connects the others).
	Directory struct {
		Workspaces []DirectoryWorkspace `json:"workspaces,omitempty"`
	}

	// DirectoryWorkspace is one declared workspace. It is deliberately thin:
	// an id the deployment may know, a backend, an admin to act as, and where
	// the credential is. Everything else, the domains and the tenant's own
	// id, is discovered.
	DirectoryWorkspace struct {
		ID         string   `json:"id,omitempty"`
		Backend    string   `json:"backend"`
		Admin      string   `json:"admin"`
		KeySecret  string   `json:"keySecret"`
		Serve      []string `json:"serve,omitempty"`
		SyncGroups []string `json:"syncGroups,omitempty"`
	}

	// Audit is the audit installation this process records to.
	Audit struct {
		Writer                  string `json:"writer,omitempty"`
		TokenFile               string `json:"tokenFile,omitempty"`
		QueryURL                string `json:"queryURL,omitempty"`
		Audience                string `json:"audience,omitempty"`
		ForwardedForTrustedHops int    `json:"forwardedForTrustedHops,omitempty"`
	}

	// RosterConsole is how a controller authenticates to the console.
	RosterConsole struct {
		Auth *RosterConsoleAuth `json:"auth,omitempty"`
	}

	// RosterConsoleAuth chooses the proof; `aws` is the function role's web
	// identity token.
	RosterConsoleAuth struct {
		AWS *RosterConsoleAWS `json:"aws,omitempty"`
	}

	// RosterConsoleAWS is the AWS proof.
	RosterConsoleAWS struct {
		// Audience is the one the issuer's AWS federation file names.
		Audience string `json:"audience"`
	}

	// RosterAudit is the audit installation a controller records to.
	RosterAudit struct {
		Writer    string `json:"writer,omitempty"`
		TokenFile string `json:"tokenFile,omitempty"`
	}
)

// Serve is the configuration of `sluis serve`: the issuer, the console
// and the directory hub, which run as one process.
type Serve struct {
	// APIVersion is the document's version: v2. A document without one is v1,
	// which [Load] converts.
	APIVersion    string `json:"apiVersion"`
	IssuerURL     string `json:"issuerURL"`
	Release       string `json:"release,omitempty"`
	Cluster       string `json:"cluster,omitempty"`
	AllowInsecure bool   `json:"allowInsecure,omitempty"`
	Demo          bool   `json:"demo,omitempty"`
	InCluster     bool   `json:"inCluster,omitempty"`
	// Instance names this installation in the default encryption context of
	// `keys` ({instance, purpose}). Unset is `release`.
	Instance string `json:"instance,omitempty"`
	// Keys says which key serves which purpose (`keys.sign` wraps the signing
	// key ring). Unset leaves every purpose to its older setting.
	Keys *keys.Config `json:"keys,omitempty"`

	Listen *Address `json:"listen,omitempty"`
	Probes *Address `json:"probes,omitempty"`
	Log    *Log     `json:"log,omitempty"`

	Store string `json:"store,omitempty"`
	Ports *Ports `json:"ports,omitempty"`
	// Platform, Preset and Adapters choose the adapters by name, per concern.
	// Absent, the `ports` keys decide, exactly as before they existed.
	Platform *Platform `json:"platform,omitempty"`
	Preset   string    `json:"preset,omitempty"`
	// Adapters maps a concern (state, secrets, blobs, signing, trigger,
	// schedule, audit) to the adapter that replaces the preset's.
	Adapters map[string]AdapterChoice `json:"adapters,omitempty"`
	// Policy names the policy document. Unset is the built-in two groups, or
	// the demonstration policy under `demo`.
	Policy        *PolicyRef `json:"policy,omitempty"`
	PublicURL     string     `json:"publicURL,omitempty"`
	PublicRootURL string     `json:"publicRootURL,omitempty"`
	SecureCookies *bool      `json:"secureCookies,omitempty"`
	GroupsScoping string     `json:"groupsScoping,omitempty"`
	// HSTS tunes the Strict-Transport-Security header; unset sends the
	// defaults on every https response.
	HSTS *HSTS `json:"hsts,omitempty"`

	// Secrets says how the secrets this document names are delivered.
	Secrets *Secrets `json:"secrets,omitempty"`

	Lifetimes   *Lifetimes   `json:"lifetimes,omitempty"`
	Freshness   *Freshness   `json:"freshness,omitempty"`
	Directory   *Directory   `json:"directory,omitempty"`
	Exchange    *Exchange    `json:"exchange,omitempty"`
	Recovery    *Recovery    `json:"recovery,omitempty"`
	Conformance *Conformance `json:"conformance,omitempty"`
	Login       *Login       `json:"login,omitempty"`
	Console     *Console     `json:"console,omitempty"`
	OAuthClient *OAuthClient `json:"oauthClient,omitempty"`
	SigningKey  *SigningKey  `json:"signingKey,omitempty"`
	Valkey      *Valkey      `json:"valkey,omitempty"`
	Audit       *Audit       `json:"audit,omitempty"`
	// Cloudflare is sluis as the STS for Cloudflare API tokens and R2
	// credentials: the accounts it mints in and the presets it mints.
	Cloudflare *Cloudflare `json:"cloudflare,omitempty"`

	// legacy is what a v1 document named by file, and [PolicyFor] reads it in
	// place of a policy document: set only by the v1 converter.
	legacy *legacyPolicy
}

// Roster is what the two controllers share.
type Roster struct {
	// APIVersion is the document's version: v2. A document without one is v1,
	// which [Load] converts.
	APIVersion string `json:"apiVersion"`
	Release    string `json:"release,omitempty"`
	// Policy names the policy document: the bindings are its github or slack
	// table, and its `controllers` section is what the controller may change.
	Policy     *PolicyRef `json:"policy"`
	ConsoleURL string     `json:"consoleURL"`
	TokenFile  string     `json:"tokenFile,omitempty"`
	// Console says how the controller proves itself to the console when the
	// pod's token file is not the way (AWS Lambda).
	Console    *RosterConsole `json:"console,omitempty"`
	RecordsDir string         `json:"recordsDir,omitempty"`
	Interval   *Duration      `json:"interval,omitempty"`
	Log        *Log           `json:"log,omitempty"`
	Ports      *Ports         `json:"ports,omitempty"`
	// Platform, Preset and Adapters choose the adapters by name, per concern, as
	// they do in the serve configuration; the Lambda controllers need them for
	// the audit sink (`sqs`) and the state they share with the service.
	Platform *Platform                `json:"platform,omitempty"`
	Preset   string                   `json:"preset,omitempty"`
	Adapters map[string]AdapterChoice `json:"adapters,omitempty"`
	Audit    *RosterAudit             `json:"audit,omitempty"`
	// GitHub, Slack and Google say where those modules are when they are not
	// in the controller's process.
	GitHub *ModuleRoute `json:"github,omitempty"`
	Slack  *ModuleRoute `json:"slack,omitempty"`
	Google *ModuleRoute `json:"google,omitempty"`
	// Secrets says how the secrets the module reads are delivered, for a
	// module that runs as a function of its own (the one service document's
	// `secrets` is what a controller inside it uses).
	Secrets *Secrets `json:"secrets,omitempty"`
	// Probes is where /healthz and /readyz answer.
	Probes *Address `json:"probes,omitempty"`

	// legacy is what a v1 document named by file: set only by the v1
	// converter.
	legacy *legacyPolicy
}

// ControllerGitHub is the configuration of `sluis controller github`.
type ControllerGitHub struct {
	Roster
	AppsDir string `json:"appsDir,omitempty"`
}

// ControllerSlack is the configuration of `sluis controller slack`.
type ControllerSlack struct {
	Roster
	CredentialsDir string `json:"credentialsDir,omitempty"`
}

// Sluis is the one service document: the process that serves the issuer, the
// console and the directory hub and, beside them, runs the controllers it
// names. Every key of [Serve] is a key of it, at the top level, and
// `controllers` is what it adds. apiVersion is v3 (`sluis.truvity.github.io/
// sluis/v3`); a v2 `serve` document, or a v1 one, loads as a Sluis with no
// controllers.
//
// A controller shares what the process already says: the release, the policy,
// the storage ports and adapters, the audit installation, the log level and
// the probes. Its own section holds what is its own, and a section that is
// absent is a controller that is off.
type Sluis struct {
	Serve
	// GitHub, Slack and Google say where those modules are when they are not in
	// this process: `<module>.remote`, shaped as `cloudflare.remote`.
	GitHub *ModuleRoute `json:"github,omitempty"`
	Slack  *ModuleRoute `json:"slack,omitempty"`
	Google *ModuleRoute `json:"google,omitempty"`
	// Outline says where the Outline module is: the console calls it for the
	// Outline pages, and this process never runs it (docs/decisions/0077).
	Outline     *ModuleRoute `json:"outline,omitempty"`
	Controllers *Controllers `json:"controllers,omitempty"`
}

// Controllers are the controllers the one process runs. A nil one is off.
type Controllers struct {
	GitHub *GitHubController `json:"github,omitempty"`
	Slack  *SlackController  `json:"slack,omitempty"`
}

// ControllerCommon is what both controllers' sections share.
type ControllerCommon struct {
	// ConsoleURL is the console's API. Unset is the document's `publicURL`.
	ConsoleURL string `json:"consoleURL,omitempty"`
	TokenFile  string `json:"tokenFile,omitempty"`
	// Console says how the controller proves itself to the console when the
	// pod's token file is not the way (AWS Lambda).
	Console    *RosterConsole `json:"console,omitempty"`
	RecordsDir string         `json:"recordsDir,omitempty"`
	Interval   *Duration      `json:"interval,omitempty"`
}

// GitHubController is `controllers.github`.
type GitHubController struct {
	ControllerCommon
	AppsDir string `json:"appsDir,omitempty"`
}

// SlackController is `controllers.slack`.
type SlackController struct {
	ControllerCommon
	CredentialsDir string `json:"credentialsDir,omitempty"`
}

// roster is what the controller's own section and the process's shared keys
// make, as the split controller's document would have said it.
func (s *Sluis) roster(c *ControllerCommon) Roster {
	r := Roster{
		APIVersion: APIVersion("controller-github"), Release: s.Release, Policy: s.Policy,
		ConsoleURL: c.ConsoleURL, TokenFile: c.TokenFile, Console: c.Console,
		RecordsDir: c.RecordsDir, Interval: c.Interval, Log: s.Log, Ports: s.Ports,
		Platform: s.Platform, Preset: s.Preset, Adapters: s.Adapters,
		GitHub: s.GitHub, Slack: s.Slack, Google: s.Google,
		legacy: s.legacy,
	}
	if r.ConsoleURL == "" {
		r.ConsoleURL = s.PublicURL
	}
	if s.Audit != nil {
		r.Audit = &RosterAudit{Writer: s.Audit.Writer, TokenFile: s.Audit.TokenFile}
	}
	return r
}

// GitHubController is the split GitHub controller's document that this one
// says, or nil when `controllers.github` is absent. The controller's assembly
// reads it as it reads the document of `sluis controller github`.
func (s *Sluis) GitHubController() *ControllerGitHub {
	if s.Controllers == nil || s.Controllers.GitHub == nil {
		return nil
	}
	g := s.Controllers.GitHub
	r := s.roster(&g.ControllerCommon)
	r.APIVersion = APIVersion("controller-github")
	return &ControllerGitHub{Roster: r, AppsDir: g.AppsDir}
}

// SlackController is [Sluis.GitHubController] for Slack.
func (s *Sluis) SlackController() *ControllerSlack {
	if s.Controllers == nil || s.Controllers.Slack == nil {
		return nil
	}
	g := s.Controllers.Slack
	r := s.roster(&g.ControllerCommon)
	r.APIVersion = APIVersion("controller-slack")
	return &ControllerSlack{Roster: r, CredentialsDir: g.CredentialsDir}
}

// SecretsLayoutV5 is the one value of [Secrets].Layout.
const SecretsLayoutV5 = "v5"
