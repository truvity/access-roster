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

// Issuer is the configuration of access-issuer: the issuer, the console and
// the directory hub, which run as one process.
type Issuer struct {
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
	Audit      *RosterAudit `json:"audit,omitempty"`
}

// GitHubRoster is the configuration of github-roster.
type GitHubRoster struct {
	Roster
	AppsDir       string   `json:"appsDir,omitempty"`
	CatalogueFile string   `json:"catalogueFile,omitempty"`
	EnabledOrgs   []string `json:"enabledOrgs,omitempty"`
}

// SlackRoster is the configuration of slack-roster.
type SlackRoster struct {
	Roster
	CredentialsDir    string   `json:"credentialsDir,omitempty"`
	EnabledWorkspaces []string `json:"enabledWorkspaces,omitempty"`
}
