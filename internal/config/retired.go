package config

import (
	"fmt"
	"slices"
	"strings"
)

// The environment variables the binaries used to be configured with. A retired
// variable that is still set is refused at start, not ignored: a deployment
// that still sets one believes it is configuring something, and an unknown one
// ignored is the silence docs/decisions/0007 and 0032 exist to end.
//
// Each names what replaces it. docs/reference/configuration.md carries the same
// table, and a test holds the two to one another.

// retiredCommon are retired for every binary that read them, with the same
// replacement.
var retiredCommon = map[string]string{
	"POLICY_DIR":       "policyDir",
	"RELEASE_NAME":     "release",
	"LOG_LEVEL":        "log.level",
	"AUDIT_WRITER_URL": "audit.writer",
	"AUDIT_TOKEN_FILE": "audit.tokenFile",
}

var retiredIssuer = map[string]string{
	"ISSUER_URL":                       "issuerURL",
	"PORT":                             "listen.address",
	"HEALTH_PORT":                      "probes.address",
	"API_PORT":                         "nothing: the directory's own listeners are not served by access-issuer",
	"CONSOLE_PORT":                     "nothing: the console is served on the issuer's listener",
	"DEMO":                             "demo",
	"ALLOW_INSECURE":                   "allowInsecure",
	"IN_CLUSTER":                       "inCluster",
	"PUBLIC_URL":                       "publicURL",
	"PUBLIC_ROOT_URL":                  "publicRootURL",
	"SECURE_COOKIES":                   "secureCookies",
	"STORE":                            "store",
	"OVERLAY_FILE":                     "overlayFile",
	"GROUPS_SCOPING":                   "groupsScoping",
	"CLUSTER":                          "cluster",
	"CLIENT_SECRETS_DIR":               "clientSecretsDir",
	"ADMIN_PASSWORD":                   "adminPasswordEnv, which names the variable that holds it",
	"RECOVERY_ENABLED":                 "recovery.enabled",
	"RECOVERY_SERVICE_ACCOUNT":         "recovery.serviceAccount",
	"RECOVERY_AUDIENCE":                "recovery.audience",
	"API_AUDIENCE":                     "api.audience",
	"CONSUMERS_FILE":                   "api.consumersFile",
	"LOGIN_DIRECTORY":                  "login.directory",
	"SIGN_OUT_URL":                     "login.signOutURL",
	"FORWARDED_EMAIL_HEADER":           "login.forwarded.emailHeader",
	"FORWARDED_ISSUER":                 "login.forwarded.issuer",
	"FORWARDED_AUDIENCE":               "login.forwarded.audience",
	"CONSOLE_ORIGIN":                   "console.origin",
	"CONSOLE_CLIENT_ID":                "console.client",
	"OAUTH_CLIENT_ID":                  "oauthClient.id",
	"OAUTH_CLIENT_ID_FILE":             "oauthClient.idFile",
	"OAUTH_CLIENT_SECRET":              "oauthClient.secretEnv, which names the variable that holds it",
	"OAUTH_CLIENT_SECRET_FILE":         "oauthClient.secretFile",
	"OAUTH_CLIENT_SECRET_NAME":         "oauthClient.secretName",
	"OAUTH_CLIENT_ID_KEY":              "oauthClient.idKey",
	"OAUTH_CLIENT_SECRET_KEY":          "oauthClient.secretKey",
	"SIGNING_KEY_FILE":                 "signingKey.file",
	"SIGNING_KEY_FILES":                "signingKey.additionalFiles",
	"SIGNING_KEY_POLL_INTERVAL":        "signingKey.pollInterval",
	"SIGNING_KEY_ACTIVATION_DELAY":     "signingKey.activationDelay",
	"SIGNING_KEY_OVERLAP":              "signingKey.overlap",
	"TOKEN_LIFETIME":                   "lifetimes.token",
	"REFRESH_LIFETIME":                 "lifetimes.refresh",
	"ABSOLUTE_LIFETIME":                "lifetimes.absolute",
	"HOLD_WINDOW":                      "lifetimes.hold",
	"SESSION_LIFETIME":                 "lifetimes.session",
	"REFRESH_INTERVAL":                 "freshness.refreshInterval",
	"FRESHNESS_WINDOW":                 "freshness.freshnessWindow",
	"PROBE_INTERVAL":                   "freshness.probeInterval",
	"EXCHANGE_AUDIENCE":                "exchange.audience",
	"CLUSTERS_FILE":                    "exchange.clustersFile",
	"AWS_FEDERATION_FILE":              "exchange.awsFile",
	"VALKEY_ADDRESS":                   "valkey.address",
	"VALKEY_PASSWORD":                  "valkey.passwordEnv, which names the variable that holds it",
	"VALKEY_TLS":                       "valkey.tls",
	"VALKEY_CLUSTER":                   "valkey.cluster",
	"GITHUB_OWNERS":                    "github.owners",
	"GITHUB_RUNNER_TIERS":              "github.runnerTiers",
	"GITHUB_APPS_CATALOGUE_FILE":       "github.catalogueFile",
	"SLACK_APPS_CATALOGUE_FILE":        "slack.catalogueFile",
	"AUDIT_QUERY_URL":                  "audit.queryURL",
	"AUDIT_AUDIENCE":                   "audit.audience",
	"AUDIT_FORWARDED_FOR_TRUSTED_HOPS": "audit.forwardedForTrustedHops",
	"SECRET_MANAGERS_FILE": "nothing: the console's secret-store view was removed in v1.30.0, " +
		"see docs/decisions/0002-mission-boundary-tokens-and-memberships.md",
}

var retiredGitHubRoster = map[string]string{
	"CONSOLE_URL":                "consoleURL",
	"TOKEN_FILE":                 "tokenFile",
	"APPS_DIR":                   "appsDir",
	"RECORDS_DIR":                "recordsDir",
	"INTERVAL":                   "interval",
	"ENABLED_ORGS":               "enabledOrgs",
	"GITHUB_APPS_CATALOGUE_FILE": "catalogueFile",
}

var retiredSlackRoster = map[string]string{
	"CONSOLE_URL":        "consoleURL",
	"TOKEN_FILE":         "tokenFile",
	"CREDENTIALS_DIR":    "credentialsDir",
	"RECORDS_DIR":        "recordsDir",
	"INTERVAL":           "interval",
	"ENABLED_WORKSPACES": "enabledWorkspaces",
}

// Retired returns, for one binary, every retired variable and what replaces it.
// The documentation's migration table is this, and a test holds them together.
func Retired(binary string) map[string]string {
	out := map[string]string{}
	add := func(from map[string]string) {
		for k, v := range from {
			out[k] = v
		}
	}
	switch binary {
	case "access-issuer":
		add(retiredIssuer)
		// The service's own spelling of what the controllers share.
		out["POLICY_DIR"] = "policyDir"
		out["RELEASE_NAME"] = "release"
		out["LOG_LEVEL"] = "log.level"
		out["AUDIT_WRITER_URL"] = "audit.writer"
		out["AUDIT_TOKEN_FILE"] = "audit.tokenFile"
	case "github-roster":
		add(retiredCommon)
		add(retiredGitHubRoster)
		out["AUDIT_WRITER_URL"] = "audit.writer"
		out["AUDIT_TOKEN_FILE"] = "audit.tokenFile"
	case "slack-roster":
		add(retiredCommon)
		add(retiredSlackRoster)
	}
	return out
}

// RefuseRetired is the start-up check: it fails when the environment still
// holds a variable the binary no longer reads, naming each with what replaces
// it. environ is os.Environ's shape.
func RefuseRetired(binary string, environ []string) error {
	retired := Retired(binary)
	var found []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if _, ok := retired[name]; ok && value != "" {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return nil
	}
	slices.Sort(found)
	var b strings.Builder
	fmt.Fprintf(&b, "%s is configured by one file, --config <file>, and no longer reads these environment "+
		"variables, which are set: ", binary)
	for i, name := range found {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s (now %s)", name, retired[name])
	}
	b.WriteString(". Remove them and put the setting in the file: docs/reference/configuration.md has the mapping")
	return fmt.Errorf("%s", b.String())
}
