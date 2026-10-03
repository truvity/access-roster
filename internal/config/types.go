// Package config is what each binary of this repository is configured with:
// one typed configuration per binary, read from one file and validated against
// a JSON Schema before anything starts.
//
// The file is the whole of the configuration. Secrets are the one thing the
// environment adds, and only the ones the file names: a field that holds a
// secret holds the NAME of the environment variable, never a value, and the
// process reads exactly the variables the file names. Telemetry is not here at
// all; it is OpenTelemetry's own environment (OTEL_*).
//
// The types are written by hand and the schemas are generated from schema/
// into schemas/config/, which is committed; a test holds the two files to one
// another, and a second holds each type to its schema. The decision is
// docs/decisions/0032-one-configuration-file-one-binary-one-chart.md and, for
// the shared rules, truvity/policy 0002 and 0006.
package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a time span as the file spells it: a Go duration string such as
// "30s", "2m" or "168h".
type Duration time.Duration

// D returns the span as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalJSON reads a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("a duration is a string such as \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes a duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

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
	}

	// Freshness is how the directory's snapshot is kept current.
	Freshness struct {
		RefreshInterval *Duration `json:"refreshInterval,omitempty"`
		FreshnessWindow *Duration `json:"freshnessWindow,omitempty"`
		ProbeInterval   *Duration `json:"probeInterval,omitempty"`
	}

	// Exchange is what the token exchange verifies workloads against.
	Exchange struct {
		Audience     string `json:"audience,omitempty"`
		ClustersFile string `json:"clustersFile,omitempty"`
		AWSFile      string `json:"awsFile,omitempty"`
	}

	// Recovery is the sign-in that needs no directory. A pointer for Enabled:
	// unset is the hub's default (on) and the issuer's (off), as it has always
	// been.
	Recovery struct {
		Enabled        *bool  `json:"enabled,omitempty"`
		ServiceAccount string `json:"serviceAccount,omitempty"`
		Audience       string `json:"audience,omitempty"`
	}

	// API is the directory API listener's guard.
	API struct {
		Audience      string `json:"audience,omitempty"`
		ConsumersFile string `json:"consumersFile,omitempty"`
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
	}

	// OAuthClient is the client registered once with the directory backend.
	// Its secret is a file or a declared variable, never a value.
	OAuthClient struct {
		ID         string `json:"id,omitempty"`
		IDFile     string `json:"idFile,omitempty"`
		SecretFile string `json:"secretFile,omitempty"`
		SecretEnv  string `json:"secretEnv,omitempty"`
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
	}

	// Valkey is the shared store for logins in progress and snapshots.
	Valkey struct {
		Address     string `json:"address,omitempty"`
		PasswordEnv string `json:"passwordEnv,omitempty"`
		TLS         bool   `json:"tls,omitempty"`
		Cluster     *bool  `json:"cluster,omitempty"`
	}

	// Export is one copy of a secret the console keeps, made out of the service
	// into a secret store a consumer reads (docs/decisions/0034). Source names
	// what is copied, Path where, and the fields beside them say which.
	Export struct {
		// Name identifies the export in the log, the metrics and its lease.
		// Empty is the source and what it names.
		Name string `json:"name,omitempty"`
		// Source is slack-app, github-app, runner-app or bundle.
		Source string `json:"source"`
		// App is the catalogue id of a slack-app or a github-app.
		App string `json:"app,omitempty"`
		// Tier and Org name a runner-app.
		Tier string `json:"tier,omitempty"`
		Org  string `json:"org,omitempty"`
		// Bundle names a bundle.
		Bundle string `json:"bundle,omitempty"`
		// Namespace is the OpenBao namespace written to; empty is the
		// adapter's.
		Namespace string `json:"namespace,omitempty"`
		// Path is the key under the KV mount.
		Path string `json:"path"`
		// Properties maps a property of the source to the property written.
		Properties map[string]string `json:"properties,omitempty"`
		// Interval is how often the copy is made again with nothing changed.
		Interval *Duration `json:"interval,omitempty"`
	}

	// PortsExport names the adapter behind the Export port.
	PortsExport struct {
		Adapter string              `json:"adapter,omitempty"`
		OpenBao *PortsExportOpenBao `json:"openbao,omitempty"`
	}

	// PortsExportOpenBao is the OpenBao KV mount the `openbao` Export adapter
	// writes to and how it logs in. No credential is configured: the login
	// presents a token the platform provides, read from a file.
	PortsExportOpenBao struct {
		Address   string       `json:"address,omitempty"`
		CAFile    string       `json:"caFile,omitempty"`
		Mount     string       `json:"mount,omitempty"`
		Namespace string       `json:"namespace,omitempty"`
		Auth      *OpenBaoAuth `json:"auth,omitempty"`
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

	// Ports chooses the adapter behind the storage ports of
	// docs/design/ports.md.
	//
	// Adapter picks the State, Index and Trigger (and, unless overridden below,
	// the Blob and Sealer). Blob and Sealer each replace one port with an
	// adapter that composes with any of them: State legacy with Blob s3 is
	// valid.
	Ports struct {
		Adapter string       `json:"adapter,omitempty"`
		Blob    *PortsBlob   `json:"blob,omitempty"`
		Sealer  *PortsSealer `json:"sealer,omitempty"`
		NATS    *NATS        `json:"nats,omitempty"`
		// DynamoDB is the table of the `dynamodb` adapter.
		DynamoDB *DynamoDB `json:"dynamodb,omitempty"`
		// Export replaces the Export port, which has no adapter by default:
		// nothing is copied out of the service unless a deployment says where.
		Export *PortsExport `json:"export,omitempty"`
	}

	// DynamoDB is where the `dynamodb` adapter keeps State, the transitional
	// Index and the Trigger: one table. Credentials are the platform's (Pod
	// Identity, IRSA, a Lambda role), never configured.
	DynamoDB struct {
		Table    string `json:"table,omitempty"`
		Region   string `json:"region,omitempty"`
		Endpoint string `json:"endpoint,omitempty"`
		Create   bool   `json:"create,omitempty"`
	}

	// NATS is where the `nats` adapter keeps State, the transitional Index and
	// the Trigger: one JetStream KV bucket. The credential is a file, never a
	// value.
	NATS struct {
		URL       string `json:"url,omitempty"`
		Bucket    string `json:"bucket,omitempty"`
		Replicas  int    `json:"replicas,omitempty"`
		TokenFile string `json:"tokenFile,omitempty"`
		CredsFile string `json:"credsFile,omitempty"`
		CAFile    string `json:"caFile,omitempty"`
		Create    *bool  `json:"create,omitempty"`
	}

	// PortsBlob names the adapter behind the Blob port.
	PortsBlob struct {
		Adapter string       `json:"adapter,omitempty"`
		S3      *PortsBlobS3 `json:"s3,omitempty"`
	}

	// PortsBlobS3 is where the S3 Blob adapter keeps its objects. Credentials
	// are the platform's (Pod Identity, IRSA, a Lambda role), never configured.
	PortsBlobS3 struct {
		Bucket    string `json:"bucket,omitempty"`
		Prefix    string `json:"prefix,omitempty"`
		Region    string `json:"region,omitempty"`
		KMSKey    string `json:"kmsKey,omitempty"`
		Endpoint  string `json:"endpoint,omitempty"`
		PathStyle bool   `json:"pathStyle,omitempty"`
	}

	// PortsSealer names the adapter behind the Sealer port.
	PortsSealer struct {
		Adapter string          `json:"adapter,omitempty"`
		KMS     *PortsSealerKMS `json:"kms,omitempty"`
	}

	// PortsSealerKMS is the key the KMS Sealer wraps data keys under.
	PortsSealerKMS struct {
		KeyID    string `json:"keyId,omitempty"`
		Region   string `json:"region,omitempty"`
		Endpoint string `json:"endpoint,omitempty"`
	}

	// GitHub is what the service knows of GitHub: whose CI it verifies and which
	// Apps it may make.
	GitHub struct {
		Owners        []string `json:"owners,omitempty"`
		RunnerTiers   []string `json:"runnerTiers,omitempty"`
		CatalogueFile string   `json:"catalogueFile,omitempty"`
	}

	// Slack is what the service knows of Slack.
	Slack struct {
		CatalogueFile string `json:"catalogueFile,omitempty"`
	}

	// Audit is the audit installation this process records to.
	Audit struct {
		Writer                  string `json:"writer,omitempty"`
		TokenFile               string `json:"tokenFile,omitempty"`
		QueryURL                string `json:"queryURL,omitempty"`
		Audience                string `json:"audience,omitempty"`
		ForwardedForTrustedHops int    `json:"forwardedForTrustedHops,omitempty"`
	}

	// RosterAudit is the audit installation a controller records to.
	RosterAudit struct {
		Writer    string `json:"writer,omitempty"`
		TokenFile string `json:"tokenFile,omitempty"`
	}
)

// Serve is the configuration of `access-roster serve`: the issuer, the console
// and the directory hub, which run as one process.
type Serve struct {
	IssuerURL     string `json:"issuerURL"`
	Release       string `json:"release,omitempty"`
	Cluster       string `json:"cluster,omitempty"`
	AllowInsecure bool   `json:"allowInsecure,omitempty"`
	Demo          bool   `json:"demo,omitempty"`
	InCluster     bool   `json:"inCluster,omitempty"`

	Listen *Address `json:"listen,omitempty"`
	Probes *Address `json:"probes,omitempty"`
	Log    *Log     `json:"log,omitempty"`

	Store         string `json:"store,omitempty"`
	Ports         *Ports `json:"ports,omitempty"`
	PolicyDir     string `json:"policyDir,omitempty"`
	OverlayFile   string `json:"overlayFile,omitempty"`
	PublicURL     string `json:"publicURL,omitempty"`
	PublicRootURL string `json:"publicRootURL,omitempty"`
	SecureCookies *bool  `json:"secureCookies,omitempty"`
	GroupsScoping string `json:"groupsScoping,omitempty"`

	ClientSecretsDir string `json:"clientSecretsDir,omitempty"`
	AdminPasswordEnv string `json:"adminPasswordEnv,omitempty"`

	Lifetimes   *Lifetimes   `json:"lifetimes,omitempty"`
	Freshness   *Freshness   `json:"freshness,omitempty"`
	Exchange    *Exchange    `json:"exchange,omitempty"`
	Recovery    *Recovery    `json:"recovery,omitempty"`
	API         *API         `json:"api,omitempty"`
	Login       *Login       `json:"login,omitempty"`
	Console     *Console     `json:"console,omitempty"`
	OAuthClient *OAuthClient `json:"oauthClient,omitempty"`
	SigningKey  *SigningKey  `json:"signingKey,omitempty"`
	Valkey      *Valkey      `json:"valkey,omitempty"`
	GitHub      *GitHub      `json:"github,omitempty"`
	Slack       *Slack       `json:"slack,omitempty"`
	Audit       *Audit       `json:"audit,omitempty"`
	// Exports are the copies of secrets this service makes out of itself, into
	// the secret store named by ports.export (docs/decisions/0034).
	Exports []Export `json:"exports,omitempty"`
}

// Roster is what the two controllers share.
type Roster struct {
	Release    string       `json:"release,omitempty"`
	PolicyDir  string       `json:"policyDir"`
	ConsoleURL string       `json:"consoleURL"`
	TokenFile  string       `json:"tokenFile,omitempty"`
	RecordsDir string       `json:"recordsDir,omitempty"`
	Interval   *Duration    `json:"interval,omitempty"`
	Log        *Log         `json:"log,omitempty"`
	Ports      *Ports       `json:"ports,omitempty"`
	Audit      *RosterAudit `json:"audit,omitempty"`
}

// ControllerGitHub is the configuration of `access-roster controller github`.
type ControllerGitHub struct {
	Roster
	AppsDir       string   `json:"appsDir,omitempty"`
	CatalogueFile string   `json:"catalogueFile,omitempty"`
	EnabledOrgs   []string `json:"enabledOrgs,omitempty"`
}

// ControllerSlack is the configuration of `access-roster controller slack`.
type ControllerSlack struct {
	Roster
	CredentialsDir    string   `json:"credentialsDir,omitempty"`
	EnabledWorkspaces []string `json:"enabledWorkspaces,omitempty"`
}
