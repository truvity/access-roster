// Package schema builds the JSON Schema of each binary's configuration file.
//
// It is a package of its own, apart from the types and the loader, so that the
// generator which writes the committed files does not need them to exist.
//
//nolint:lll // a schema is prose, and a description is one string
package schema

import (
	"bytes"
	"encoding/json"
	"strings"

	storageschemas "github.com/truvity/sluis/storage/schemas"
)

// idBase is where the schemas are named: the identifier is a name, and nothing
// fetches it. The version in it is the document's own, see [ID].
const idBase = "https://truvity.github.io/sluis/schemas/"

// ID is the `$id` of the schema of a document: the version in it is the
// version of the `apiVersion` the document carries, so a v3 document is never
// named as v2 (the service document was, for a release).
func ID(name, apiVersion string) string {
	return idBase + apiVersion[strings.LastIndex(apiVersion, "/")+1:] + "/config/" + name + ".schema.json"
}

// apiVersionOf is the `const` of a properties block's `apiVersion`.
func apiVersionOf(props m) string {
	v, _ := props["apiVersion"].(m)["const"].(string)
	return v
}

// The shared shapes this repository takes from truvity/policy, by the `$id`
// they carry. The loader resolves them from its embedded copies.
const policy = "https://github.com/truvity/policy/schemas/"

// Names are the documents, as the schema files are named:
// schemas/config/<name>.schema.json. The first three are the service documents,
// one per process; `policy` is the one policy document they all name; `installation`
// is what `sluisctl render` writes both from.
var Names = []string{"sluis", "serve", "controller-github", "controller-slack", "sluis-backup", "sluis-google", "sluis-outline", "policy", "installation"}

// Services are the service documents: the ones a process is started with.
// `sluis` is the one document of the one process (v3): the serve settings and,
// under `controllers`, the controllers it runs. The other three are what a
// deployment that still runs the processes apart reads, for one release.
var Services = []string{"sluis", "serve", "controller-github", "controller-slack"}

// Group is the group of the documents' kinds: `apiVersion` is
// `<Group>/<document>/v<N>` (truvity/policy docs/contracts/config.md, rule 7).
const Group = "sluis.truvity.github.io"

// apiVersion is the `apiVersion` every v2 document carries.
func apiVersion(name string) m {
	return m{"const": Group + "/" + name + "/v2", "description": "Which version of which document this is. " + Group + "/" + name + "/v2 is what this build writes; a document with no apiVersion is v1, which the binary converts as it loads it, and a binary reads v2 and v1 (docs/reference/sluis/configuration.md)."}
}

// apiVersionSluis is the `apiVersion` of the one service document, v3. A
// binary reads it, and also the v2 `serve` document (and v1, which has none)
// as a service with no controllers.
func apiVersionSluis() m {
	return m{"const": Group + "/sluis/v3", "description": "Which version of which document this is. " + Group + "/sluis/v3 is the one service document: the process that serves the issuer and the console and, under `controllers`, runs the GitHub and Slack controllers. A binary still reads the v2 `serve` document (and v1, which has no apiVersion) as this document with no controllers (docs/reference/sluis/configuration.md)."}
}

// policyRef is `policy`: the policy document a process decides by.
func policyRef(description string) m {
	return obj(description, m{
		"file": str("The policy document: the one canonical file `sluisctl policy render` writes (schemas/config/policy.schema.json). Read once, at start: a change is a new instance."),
	}, "file")
}

type m = map[string]any

func ref(id string) m { return m{"$ref": id} }

func obj(description string, props m, required ...string) m {
	o := m{
		"type":                 "object",
		"additionalProperties": false,
		"description":          description,
		"properties":           props,
	}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

// exclusive refuses an object that names both a and b.
// exclusiveOf is exclusive for any number of keys: no two of names are set together.
func exclusiveOf(o m, names ...string) m {
	var pairs []any
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			pairs = append(pairs, m{"required": []string{names[i], names[j]}})
		}
	}
	o["not"] = m{"anyOf": pairs}
	return o
}

func str(description string) m {
	return m{"type": "string", "minLength": 1, "description": description}
}

func strDefault(description, def string) m {
	s := str(description)
	s["default"] = def
	return s
}

func enum(description, def string, values ...string) m {
	o := m{"enum": values, "description": description}
	if def != "" {
		o["default"] = def
	}
	return o
}

func integer(description string, least int, def any) m {
	o := m{"type": "integer", "minimum": least, "description": description}
	if def != nil {
		o["default"] = def
	}
	return o
}

func boolean(description string) m {
	return m{"type": "boolean", "description": description}
}

func boolDefault(description string, def bool) m {
	b := boolean(description)
	b["default"] = def
	return b
}

func duration(description string, def string) m {
	o := m{"$ref": "#/$defs/duration", "description": description}
	if def != "" {
		o["default"] = def
	}
	return o
}

func list(description string, item m) m {
	return m{"type": "array", "items": item, "description": description}
}

// url is an address with no credentials in it: a password in a URL is a secret
// in the file.
func url(description string) m {
	return m{"$ref": "#/$defs/url", "description": description}
}

// sharedDefs are the shapes more than one schema uses, written once here and
// carried into each schema that names them, because a schema the loader reads
// has to stand alone.
func sharedDefs() map[string]m {
	return map[string]m{
		"duration": {
			"type":        "string",
			"pattern":     `^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`,
			"description": "A Go duration: 30s, 2m, 168h.",
		},
		// The two checks that a secret might fail are `not`, because a pattern
		// that fails is reported with the value it was given, and an error is
		// logged.
		"url": {
			"type":      "string",
			"minLength": 1,
			"allOf": []any{
				m{"pattern": `^https?://\S+$`},
				m{"not": m{"pattern": `^https?://[^/?#\s]*@`}},
			},
			"description": "An http or https URL with a host and no credentials: a password in a URL is a secret in the file, and a secret is named, never carried.",
		},
		"secretName": {
			"type":        "string",
			"pattern":     `^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`,
			"description": "The NAME of a secret, delivered as `secrets.source` says: `valkey/password`, `issuer/state-secret`. A value is never in the document.",
		},
	}
}

func listen(def string) m {
	return m{"$ref": policy + "fragments/listen.json", "default": m{"address": def}}
}

func probes(def string) m {
	return m{"$ref": policy + "fragments/probes.json", "default": m{"address": def}}
}

func logLevel() m { return ref(policy + "fragments/log.json") }

// document builds one schema: its identity, its properties, and the shapes it
// shares.
func document(name, title, description string, props m, required []string, uses []string, extra m) m {
	shared := sharedDefs()
	defs := m{}
	for _, u := range uses {
		defs[u] = shared[u]
	}
	s := m{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  ID(name, apiVersionOf(props)),
		"title":                title,
		"description":          description,
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	if len(defs) > 0 {
		s["$defs"] = defs
	}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

const secretsNote = " Secrets are never in this file: a field ending in ...Secret holds the NAME of a secret, which `secrets` says how to deliver, and a field ending in ...File holds a path (a credential the platform mounts and rotates). Telemetry is the OTEL_* environment, not configuration."

func secretField(description string) m {
	return m{"$ref": "#/$defs/secretName", "description": description}
}

// secretsSchema is `secrets`: how the names the document gives are delivered.
func secretsSchema() m {
	s := obj("How the secrets this document names are delivered (truvity/policy config.md section 5). Absent is `env`.", m{
		"source":    enum("`env`: the variable SLUIS_SECRET_<NAME> (the name upper-cased, every other character an underscore), for a local run. `file`: the file <root>/<name>, read on every use, so a rotated mount takes effect without a restart. `ssm`: a SecureString in AWS SSM Parameter Store under <root> (/sluis/<instance>), on layout v5 (`layout`): a name the service knows is read at its module's address (`<root>/internal/oidc/state-secret`, ...), any other at `<root>/internal/config/<name>`.", "env", "env", "file", "ssm"),
		"root":      str("`file`: the directory the secrets are mounted under. `ssm`: the installation's root, /sluis/<instance>."),
		"region":    str("`ssm`: the region. Unset follows the AWS SDK's own resolution."),
		"endpoint":  url("`ssm`: overrides the SSM address, for LocalStack."),
		"refresh":   duration("`ssm`: how old a secret's copy may be before it is read again: a rotated secret reaches every instance within it.", "1m"),
		"kmsKeyId":  str("`ssm`: the id, ARN or alias of the customer-managed KMS key the parameters the service itself writes (its credentials) are encrypted with. Unset, the AWS-managed `alias/aws/ssm`. The `ssm` secrets adapter's `kmsKeyId` setting; naming another there is refused."),
		"layout":    enum("`ssm`, required: the storage layout of the installation's secrets, `v5`, the only one: the module first, `<root>/internal/<module>/` and `<root>/external/<module>/` (docs/decisions/0072-storage-layout-v5-module-first.md). Layout `v4` was removed in v1.77.1 (an installation still on it migrates with `sluis migrate v5` of v1.77.0 first), and with it the reading of an absent layout as `v4`.", "", "v5"),
		"readCache": duration("`ssm`: how long a process keeps a document it read; a write drops it. `0s` is off. SLUIS_SECRETS_READ_CACHE_TTL overrides.", "5m"),
		"grace":     duration("`ssm`: how long the previous value of a rotated client secret is still accepted: the document's previous revision, while the current one is younger than this (docs/decisions/0039-the-issuer-generates-confidential-client-secrets.md, the overlap).", "24h"),
	}, "source")
	s["allOf"] = []any{
		m{"if": m{"properties": m{"source": m{"enum": []string{"file", "ssm"}}}}, "then": m{"required": []string{"root"}}},
		m{"if": m{"properties": m{"source": m{"const": "ssm"}}, "required": []string{"source"}}, "then": m{"required": []string{"layout"}}},
		m{"if": m{"properties": m{"source": m{"enum": []string{"env", "file"}}}}, "then": m{"not": m{"anyOf": []any{m{"required": []string{"kmsKeyId"}}, m{"required": []string{"layout"}}, m{"required": []string{"grace"}}, m{"required": []string{"readCache"}}}}}},
	}
	return s
}

func serveSchema() m {
	props := m{
		"apiVersion":    apiVersion("serve"),
		"issuerURL":     m{"$ref": "#/$defs/url", "description": "The issuer: baked into every token and every relying party's trust, so there is no default. No trailing slash is kept."},
		"release":       strDefault("The name this installation's objects carry: the Kubernetes object names (`<release>-github-orgs`, ...) and the prefix of its keys in a shared store. The chart requires it to be the release's full name.", "sluis"),
		"instance":      m{"type": "string", "pattern": `^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`, "description": "The installation's name, bound into the default encryption context of `keys` ({instance, purpose}): stable and not secret, because a ciphertext made under it opens only with it. Unset is `release`."},
		"keys":          keysSchema(),
		"cluster":       str("Names this cluster in a ServiceAccount's subject. A pod cannot discover it; unset keeps the older unqualified subject."),
		"allowInsecure": boolean("Accept a plain-http issuer URL, for a local run. When the issuer URL is also on the loopback interface (`localhost`, `127.0.0.1`, `::1`), the issuer connects to loopback and private addresses when it fetches client documents and posts back-channel logouts; with any other issuer URL those guards stay on."),
		"demo":          boolean("Two tenants held in memory, which need no credential and no network."),
		"inCluster":     boolean("Prove recovery against the cluster the pod runs in. Set by a deployment that turns recovery on."),
		"listen":        listen(":8080"),
		"probes":        probes(":7070"),
		"log":           logLevel(),
		"store": enum("Where what an operator connected is kept: `memory` keeps nothing (a restart is a fresh installation), `kubernetes` keeps it in this namespace.", "memory",
			"memory", "kubernetes"),
		"ports":         portsSchema(),
		"platform":      platformSchema(),
		"preset":        presetSchema(),
		"adapters":      adaptersSchema(),
		"policy":        policyRef("The policy document this service decides by. Unset is the built-in two groups, or the demonstration policy under `demo`."),
		"directory":     directorySchema(),
		"publicURL":     m{"$ref": "#/$defs/url", "description": "Where a browser reaches the console, including its mount. The admin-consent redirect URI and the values the setup steps show are built from it. Default http://localhost:8081."},
		"publicRootURL": m{"$ref": "#/$defs/url", "description": "The host's root, never carrying the console's mount: the bootstrap surface stays there. Unset follows `publicURL`."},
		"secureCookies": boolean("Mark session cookies Secure. Unset follows the scheme the browser will use: https in the URL. `false` is for a plain-http local run: the service refuses it when `issuerURL` or `publicRootURL` is https."),
		"hsts": obj("The Strict-Transport-Security header the issuer and the console send on a response that arrived over https. Never `preload`; never sent over http or to a loopback host.", m{
			"maxAge":            duration("How long a browser keeps the rule, in whole seconds. Zero sends no header.", "8760h"),
			"includeSubDomains": boolDefault("Extend the rule to the host's subdomains. Off by default: an issuer on an apex or parent domain would pin every sibling subdomain to https for `maxAge`. Turn it on only when every subdomain answers https.", false),
		}),
		"groupsScoping": enum("How far this installation has moved toward per-audience `groups` scoping: `off`, `report` or `enforce`.", "report", "off", "report", "enforce"),
		"secrets":       secretsSchema(),
		"lifetimes": obj("How long what the issuer hands out lives.", m{
			"token":    duration("An access token.", "1h"),
			"refresh":  duration("A refresh token.", "12h"),
			"absolute": duration("A session, at most. Positive, and at least `token`: a session has to end SOMETIME after sign-in, and an access token cannot outlive the session that grants it.", "24h"),
			"hold":     duration("How long a removal is held before it takes effect.", "4h"),
			"session":  duration("The console's own session cookie, capped at `absolute`.", "12h"),
			"agent": obj("The refresh chains of clients the policy marks `session: agent`, such as MCP hosts (docs/decisions/0040). Their chains are held to these instead of `refresh` and `absolute`.", m{
				"refresh":  duration("An agent chain's idle limit. Positive, and at most `absolute`.", "336h"),
				"absolute": duration("An agent chain, at most, from `auth_time`. Positive, and at most 2160h (90 days).", "720h"),
				"access":   duration("The longest an agent client's access or ID token lives. Positive, and at most 1h.", "30m"),
			}),
		}),
		"freshness": obj("How the directory's snapshot is kept current.", m{
			"refreshInterval": duration("How often a snapshot is refreshed.", "15m"),
			"freshnessWindow": duration("How old a snapshot may be and still be answered from.", "30m"),
			"probeInterval":   duration("How often the directory is probed.", "5m"),
		}),
		"exchange": obj("How the token exchange verifies workloads. Whom it trusts (the clusters, the AWS accounts, the GitHub owners) is the policy document's `exchange`.", m{
			"audience": str("The audience a workload token must be minted for. Defaults to `release`, so two issuers in one cluster cannot accept each other's proofs."),
		}),
		"recovery": obj("The sign-in that needs no directory: in a cluster, a token for a ServiceAccount proven against the API server; anywhere else, a password. Unset is off for the issuer and, for the hub, on.", m{
			"enabled":        boolean("Turn recovery on. Needs `inCluster`, `serviceAccount` and `audience` to be usable."),
			"serviceAccount": str("The ServiceAccount whose token signs in."),
			"audience":       str("The audience its token must carry."),
			"generation":     str("Names this configuration's decision to have recovery on. An operator may disable recovery from the console (only after signing in through the identity provider); the disable is kept in the State against the generation in force and covers only it. A redeploy of the same document keeps recovery disabled; change this value, to any other string, to turn it back on. Unset is the generation `\"\"`."),
			"verifierSecret": secretField("Outside a cluster: the secret the recovery account's SRP verifier is (`recovery/verifier`): a salt and a verifier, never the password. The sign-in page proves knowledge of the password against it without sending it (docs/decisions/0076). Unset derives one from the password at start."),
			"passwordSecret": secretField("Outside a cluster: the secret the recovery password is (`recovery/password`), read to derive the account's SRP verifier, which is all the hub holds of it, unless `verifierSecret` names one (docs/decisions/0076). Unset generates one and prints it, except on a function, where recovery is then off. `enabled: false` leaves it untouched and refuses the sign-in, so turning it back on needs no new password."),
		}),
		"conformance": obj("The test account of the OpenID conformance harness: a non-privileged subject that signs in with a username and password, only to clients the policy marks `harness`, and only while enabled. Off unless turned on (docs/decisions/0076).", m{
			"enabled":        boolean("Turn the account on. The sign-in page offers it only for a request of a client marked `harness`; a Lambda stack also generates its password and verifier."),
			"verifierSecret": secretField("The secret the account's SRP verifier is (`conformance/verifier`): a salt and a verifier, never the password."),
		}),
		"login": obj("How a person signs in to the console.", m{
			"directory":  boolDefault("Sign in with the corporate directory.", true),
			"signOutURL": str("Where sign-out sends the browser."),
			"forwarded": obj("A sign-in an authenticating proxy has already done.", m{
				"issuer":      str("The proxy's issuer."),
				"audience":    str("The audience its token carries."),
				"emailHeader": str("The header that carries the signed-in address."),
			}),
		}),
		"console": obj("Where the console is published, for the sign-in that starts there.", m{
			"origin":      str("The console's origin, when it is not the issuer's."),
			"client":      str("The client id the console signs in as."),
			"awsAudience": str("The audience an AWS role's web identity token must be minted for to be a bearer at the console (a Lambda controller). Its own, distinct from the AWS federation file's, so a token for token exchange is no proof here and the reverse. Default `<issuerURL>/console`."),
			"backup": obj("Connects the console's Backups page to the backup module and the restore function (docs/decisions/0071). The console only reads from them, as the caller class `console`. Unset has no page.", m{
				"function":        str("The backup module's Lambda function, name or ARN, invoked through its `live-console` alias. Set exactly one of `function` and `url`."),
				"url":             url("The backup module's Kubernetes Service. A call carries the pod's projected ServiceAccount token."),
				"restoreFunction": str("The restore function, name or ARN, invoked through its `live-console` alias. At most one of it and `restoreURL`; without either the page says there is none."),
				"restoreURL":      url("The restore function's Kubernetes Service."),
				"audience":        str("The audience of the projected token. Each module's name when unset."),
				"tokenFile":       str("Where the projected token is mounted. `/var/run/secrets/sluis/backup/token` when unset."),
			}),
		}),
		"oauthClient": obj("The OAuth client registered once with the directory backend: it drives both admin consent and operator sign-in.", m{
			"id":         str("The client id, for a local run. Not a secret."),
			"provider":   m{"type": "string", "pattern": `^[A-Za-z0-9][A-Za-z0-9._-]*$`, "description": "Names the client's secrets: providers/google/<provider>/client-secret, and providers/google/<provider>/client-id unless `id` gives it. One segment of a secret's name."},
			"secretName": str("The Kubernetes Secret the client is declared in, which the console shows and cannot change."),
			"idKey":      str("The key of the id in that Secret."),
			"secretKey":  str("The key of the secret in that Secret."),
		}),
		"signingKey": exclusiveOf(obj("The issuer's signing keys: provisioned, never minted here.", m{
			"file": str("The primary key. Unset generates one for this process, which a local run may do and nothing else should. Exclusive with `kms`."),
			"kms": obj("Sign with AWS KMS keys instead of a file: the private key never leaves KMS. Exclusive with `file`.", m{
				"keys": m{"type": "array", "minItems": 1, "uniqueItems": true, "items": m{"type": "string", "minLength": 1},
					"description": "ECC_NIST_P384 SIGN_VERIFY keys, as ids, ARNs or aliases, oldest first. The LAST signs; the earlier ones stay published until `overlap` after the next one activates. Rotation appends a key. The role needs kms:Sign and kms:GetPublicKey on each."},
				"additional": list("Every OTHER algorithm this installation signs with at once, each on its own rotation track, as `signingKey.additionalFiles` does for files. RS256 is the one that exists: for relying parties that need it (Kargo, EKS's OIDC provider).",
					obj("One algorithm's keys.", m{
						"alg": m{"enum": []string{"RS256"}, "description": "The algorithm."},
						"keys": m{"type": "array", "minItems": 1, "uniqueItems": true, "items": m{"type": "string", "minLength": 1},
							"description": "RSA_2048, RSA_3072 or RSA_4096 SIGN_VERIFY keys, oldest first, the last signing; same rotation rules as `keys`."},
					}, "alg", "keys")),
				"region":      str("The keys' region. Unset follows the AWS SDK's own resolution."),
				"stateSecret": secretField("The secret (`issuer/state-secret`) holding at least 32 random bytes as base64 or hex (`openssl rand -base64 32`), the same in every replica (a replica whose secret differs refuses to start), from which the sign-in state is derived: a KMS key has no private bytes to derive from."),
			}, "keys", "stateSecret"),
			"kmsWrapped": obj("Sign with key pairs AWS KMS generates and wraps under ONE symmetric key (the `kms-wrapped` adapter): a new pair per algorithm every `rotateEvery`, published before it signs and kept after it is replaced. The private key is decrypted into process memory to sign. Exclusive with `file` and `kms`.", m{
				"keyId":       m{"type": "string", "deprecated": true, "description": "DEPRECATED, accepted for one release with a warning: name the symmetric key as `keys.sign` instead. An alias given here is mapped onto `keys.sign`; an ARN or an id is refused."},
				"region":      str("The key's region. Unset follows the AWS SDK's own resolution."),
				"stateSecret": secretField("The secret (`issuer/state-secret`) holding at least 32 random bytes as base64 or hex, the same in every replica, from which the sign-in state is derived: a wrapped key is replaced daily and the state must outlive it."),
				"algorithms": m{"type": "array", "minItems": 1, "uniqueItems": true, "items": m{"enum": []string{"ES384", "RS256"}},
					"description": "The algorithms signed with, the first the installation default. Unset is ES384 and RS256. EdDSA is not supported yet."},
				"rotateEvery": duration("How often a new key pair is generated for each algorithm. Longer than `prepublish`, at most 168h.", "24h"),
				"prepublish":  duration("How long a new key is published before anything signs with it: longer than any verifier caches the key set (Envoy's jwt_authn: 10m; an hour is common), and shorter than `rotateEvery`. Unset is half of `rotateEvery`, and never shorter than `activationDelay`.", "12h"),
				"retain":      duration("How long a replaced key stays published: at least `lifetimes.token` plus a skew margin. Unset is `overlap`.", ""),
			}, "stateSecret"),
			"additionalFiles": list("Every OTHER algorithm this installation signs with at once, one file per algorithm.", str("A key file.")),
			"verifyOnly": list("PUBLIC keys published in the JWKS and never signed with, so tokens an earlier signer issued keep verifying until they expire: the overlap of a cutover from file keys to `kmsWrapped`. Each is dropped from the JWKS at its `until`. A private key stops the start.",
				obj("One public key.", m{
					"file":  str("A PEM public key (`PUBLIC KEY`, `RSA PUBLIC KEY`, or a certificate) or a JWK file: ECDSA on P-384 (ES384) or RSA of 2048 bits or more (RS256). Another curve or a shorter RSA key is refused. Never a private key."),
					"kid":   str("The `kid` the old tokens carry. Unset is the RFC 7638 thumbprint of the key, which is what a file signer derived for it."),
					"alg":   m{"enum": []string{"ES384", "RS256"}, "description": "The key's algorithm. Unset follows the key."},
					"until": m{"type": "string", "format": "date-time", "description": "An RFC 3339 instant after which the key is no longer published: the old tokens' last expiry, plus the verifiers' cache. Required: an overlap has an end."},
				}, "file", "until")),
			"pollInterval":    duration("How often the files are re-read.", "30s"),
			"activationDelay": duration("How long a newly published key waits before a replica signs with it. At least `pollInterval`.", "15m"),
			"overlap":         duration("How long a rotated key stays published. Unset is `lifetimes.token` plus a margin for clock skew.", ""),
		}), "file", "kms", "kmsWrapped"),
		"valkey": obj("Deprecated since v1.74.0 and still read: migrate with `sluis migrate`. The shared store for logins in progress and snapshots. Unset keeps both in memory, correct for one replica.", m{
			"address":        m{"type": "string", "allOf": []any{m{"pattern": `^[^\s/]+:[0-9]{1,5}$`}, m{"not": m{"pattern": "@"}}}, "description": "host:port, with no credentials."},
			"passwordSecret": secretField("The secret the password is (`valkey/password`). Unset connects with none."),
			"tls":            boolean("Speak TLS to the server."),
			"cluster":        boolDefault("Speak the cluster protocol. A plain single server needs it off.", true),
		}),
		"cloudflare": cloudflareSchema(),
		"audit": obj("The audit installation this service records to. Unset keeps the trail in the log only.", m{
			"writer":                  url("The installation's receiver."),
			"tokenFile":               str("This workload's projected service-account token, presented on every call."),
			"queryURL":                url("The query service, for the console's Audit page. Its own setting: it needs no `writer`, so the page works with the `sqs` and `log` sinks. A path prefix (`https://audit.example/sluis`) is kept and the procedure path appended."),
			"audience":                strDefault("The client whose audience the Audit page's tokens carry.", "audit"),
			"forwardedForTrustedHops": integer("How many of the deployment's own proxies append to X-Forwarded-For; zero records the peer.", 0, 0),
		}),
	}
	return document("serve", "sluis serve",
		"The configuration of `sluis serve`: the issuer, the console and the directory hub, one process."+secretsNote,
		props, []string{"apiVersion", "issuerURL"}, []string{"duration", "url", "secretName"},
		m{
			"allOf": []any{
				m{"if": m{"required": []string{"valkey"}}, "then": m{"properties": m{"valkey": m{"required": []string{"address"}}}}},
			},
		})
}

// sluisSchema is the one service document: every key of `serve`, at the top
// level, and `controllers`. A controller shares what the process already says
// (the release, the policy, the storage ports and adapters, the audit
// installation, the log level and the probes), so its section holds only what
// is its own.
func sluisSchema() m {
	s := serveSchema()
	props, _ := s["properties"].(m)
	props["apiVersion"] = apiVersionSluis()
	addRemotes(props)
	props["outline"] = outlineRemoteSchema()
	props["controllers"] = obj("The controllers this process runs beside the issuer and the console, each in its own loop. A controller that is absent is off. Which organisations and workspaces a running controller may CHANGE is the policy document's `controllers.<kind>.enabledOrgs` and `enabledWorkspaces`, as before. A controller reads the console's API as a workload, so the policy's exchange must admit its proof (a ServiceAccount token on Kubernetes, the function role's web identity token on Lambda).", m{
		"github": obj("The GitHub controller: makes each GitHub organisation's teams match the policy's github table.", controllerProps(
			"/var/run/secrets/github-roster/token", "/var/run/github-roster/records",
			"appsDir", "One file per connected organisation: its App's credentials. Read only with `ports.adapter: legacy`; with another adapter they are on the State port.", "/var/run/github-roster/apps")),
		"slack": obj("The Slack controller: makes each Slack workspace's user groups match the policy's slack table.", controllerProps(
			"/var/run/secrets/slack-roster/token", "/var/run/slack-roster/workspaces",
			"credentialsDir", "One file per connected workspace: the app's credentials and its bot token. Read only with `ports.adapter: legacy`; with another adapter they are on the State port.", "/var/run/slack-roster/credentials")),
	})
	s["$id"] = ID("sluis", apiVersionOf(props))
	s["title"] = "sluis"
	s["description"] = "The configuration of `sluis serve`, the one process of sluis: the issuer, the console and the directory hub and, under `controllers`, the GitHub and Slack controllers. On Kubernetes it is one Deployment; on AWS Lambda it is one function." + secretsNote
	return s
}

// controllerProps is what is a controller's own in the one document.
func controllerProps(tokenDefault, recordsDefault, dirKey, dirDescription, dirDefault string) m {
	return m{
		"consoleURL": url("The console's API, which answers who holds a group. Unset is `publicURL`. On Kubernetes it is this release's own Service, which the chart writes."),
		"tokenFile":  strDefault("This pod's projected ServiceAccount token, presented to the console and read afresh on every call.", tokenDefault),
		"console": obj("How the controller proves itself to the console, when the pod's `tokenFile` is not the way.", m{
			"auth": obj("The proof. Absent, `tokenFile`.", m{
				"aws": obj("The function role's AWS outbound web identity token (`sts:GetWebIdentityToken`), re-minted every four minutes. The console's issuer must federate the account, and its policy must declare an `aws` matcher for the role.", m{
					"audience": str("The audience requested from STS. It must equal `console.awsAudience` (default `<issuerURL>/console`), NOT the audience of the issuer's AWS federation file."),
				}, "audience"),
			}),
		}),
		"recordsDir": strDefault("The console's records, mounted. Read only with `ports.adapter: legacy`.", recordsDefault),
		dirKey:       strDefault(dirDescription, dirDefault),
		"interval":   duration("How long between passes. Positive.", "15m"),
	}
}

// portsSchema is the `ports` section both kinds of file share.
func portsSchema() m {
	o := obj("The adapters behind the storage ports (docs/concepts/sluis/ports.md).", m{
		"adapter": enum("`legacy`, the default, is deprecated since v1.74.0 and still ships: migrate with `sluis migrate`. It keeps state where it has always been kept: the namespace's ConfigMaps and Secrets and, when `valkey` is set, Valkey. `memory` keeps all of it in this process, which a restart loses: for a local run and the demonstration, and not with `store: kubernetes` or `valkey`.  `dynamodb` keeps the same in one DynamoDB table (`ports.dynamodb`), with the platform's credentials, and takes its Blob from `legacy` unless `ports.blob` names its own.", "legacy",
			"legacy", "memory", "dynamodb"),
		"blob":     portsBlobSchema(),
		"dynamodb": portsDynamoDBSchema(),
	})
	o["allOf"] = []any{
		m{"if": m{"properties": m{"adapter": m{"const": "dynamodb"}}, "required": []string{"adapter"}}, "then": m{"required": []string{"dynamodb"}}},
	}
	return o
}

// portsDynamoDBSchema is `ports.dynamodb`: the table of the `dynamodb` adapter.
func portsDynamoDBSchema() m {
	tables := m{}
	for _, mod := range []string{"oidc", "github", "slack", "cloudflare", "google", "backup", "outline"} {
		tables[mod] = str("The name of the " + mod + " module's table. The library default is `sluis-<instance>-" + mod + "`.")
	}
	named := obj("Layout v5 (docs/decisions/0072-storage-layout-v5-module-first.md): the table of each module, by module name. A process names its own module's table and the tables of the peers it reads; a module it does not name is not opened. The single table of layout v4 (`table`) was removed in v1.77.1.",
		tables)
	named["minProperties"] = 1
	o := obj("The DynamoDB tables of the `dynamodb` adapter: one table per module (`tables`, layout v5). Each has a string partition key `pk`, a string sort key `sk` and the TTL attribute `expires`. Credentials are the platform's (EKS Pod Identity, IRSA, a Lambda role) and are never configured here; an S3-compatible `endpoint` with no such identity names a credentials document by address (`credentialsRef`), never by value.", m{
		"tables":   named,
		"region":   str("The table's region. Absent, the SDK's own resolution (`AWS_REGION`)."),
		"endpoint": url("Overrides the DynamoDB address: LocalStack or DynamoDB Local."),
		"create":   boolDefault("Create the table (on-demand, TTL on `expires`) at start when it is not there, for a test or a development installation. Off, the table must exist: production uses the one the infrastructure code made, and the role needs `dynamodb:DescribeTable` on it (layout v5: the readiness probe asks, not the start).", false),
	})
	o["required"] = []string{"tables"}
	return o
}

// portsBlobSchema is `ports.blob`: the Blob port's own adapter, which
// replaces the one `ports.adapter` brings and composes with any of them.
func portsBlobSchema() m {
	s := obj("Replaces the Blob port (status reports, directory snapshots) with an adapter of its own, whatever `ports.adapter` is. Absent, the Blob is `ports.adapter`'s.", m{
		"adapter": enum("`s3` keeps the blobs in an S3 bucket.", "", "s3"),
		"s3": obj("Where the S3 adapter keeps its objects. Credentials are the platform's (EKS Pod Identity, IRSA, a Lambda role) and are never configured here.", m{
			"bucket":    str("The bucket. It must exist, with public access blocked."),
			"prefix":    str("A key prefix inside the bucket, for an installation that shares it."),
			"region":    str("The bucket's region. Absent, the SDK's own resolution (`AWS_REGION`)."),
			"kmsKey":    str("A KMS key id, ARN or alias for server-side encryption (SSE-KMS) of every write. Absent, the bucket's default encryption applies."),
			"endpoint":  url("Overrides the S3 address: LocalStack or an S3-compatible store (Cloudflare R2, MinIO)."),
			"pathStyle": boolean("Addresses the bucket in the path and not the host name, which LocalStack and most S3-compatible stores need."),
			"checksum":  enum("The integrity header of every upload: `sha256` (x-amz-checksum-sha256, computed over the whole body and sent precomputed, never as an aws-chunked trailer), `md5` (Content-MD5) or `none`, for a store that refuses SHA-256. AWS refuses a PutObject without one on an Object Lock bucket.", "sha256", "sha256", "md5", "none"),
			"credentialsRef": m{"type": "string", "pattern": "^(internal/[a-z0-9][a-z0-9-]{0,30}/[a-z0-9][a-z0-9._-]{0,62}|external/cloudflare/[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?)$",
				"description": "Where the credentials for `endpoint` are, in the installation's secrets store (the ssm secrets source): the internal address, `internal/<module>/<name>`, of the `s3-credentials/v1` document (`access_key_id`, `secret_access_key`) that holds static credentials, or `external/cloudflare/<preset>`, the `cloudflare/v1` document the Cloudflare module rotates for an R2 preset with `store: external` (the access key is the token's id; it is read again with a third of its time left and after a 403). Read at start and again after an answer of 403, at most once a minute. Needs `endpoint`; `region` defaults to `auto` with it. Any other address is refused. This is the simple way and needs no `cloudflare` section in this document, so it is the one to use when the presets are another module's (`cloudflare.remote`)."},
			"credentials": obj("Instead of a static document, sluis mints its own R2 credentials from a Cloudflare preset: the account's minter credential clones the preset's prototype, the credentials are renewed with a third of their lifetime left and minted again once after a 403. Exclusive with `credentialsRef`. Needs `endpoint`, the ssm secrets source, and the `cloudflare` section.", m{
				"preset": m{"type": "string", "pattern": cloudflareName, "description": "A key of `cloudflare.presets` that has an `endpoint` (an R2 preset)."},
			}, "preset"),
		}, "bucket"),
	}, "adapter")
	s["allOf"] = []any{m{"if": m{"properties": m{"adapter": m{"const": "s3"}}}, "then": m{"required": []string{"s3"}}}}
	s3 := s["properties"].(m)["s3"].(m)
	s3["dependentRequired"] = m{"credentialsRef": []string{"endpoint"}, "credentials": []string{"endpoint"}}
	s3["not"] = m{"required": []string{"credentialsRef", "credentials"}}
	return s
}

func rosterProps(kind, mountDefault, recordsDefault string) m {
	kindName := "controller-" + kind
	props := m{
		"apiVersion": apiVersion(kindName),
		"release":    strDefault("The name the installation's objects carry. It must be the release's full name: the controller reads the report and the records the service writes under it.", "sluis"),
		"policy":     policyRef("The policy document: the bindings are its " + kind + " table, and its `controllers." + kind + "` section is what this controller may change."),
		"consoleURL": url("The console's API, which answers who holds a group."),
		"tokenFile":  strDefault("This pod's projected ServiceAccount token, presented to the console and read afresh on every call.", mountDefault),
		"console": obj("How the controller proves itself to the console, when the pod's `tokenFile` is not the way.", m{
			"auth": obj("The proof. Absent, `tokenFile`.", m{
				"aws": obj("The function role's AWS outbound web identity token (`sts:GetWebIdentityToken`), re-minted every four minutes. The console's issuer must federate the account, and its policy must declare an `aws` matcher for the role.", m{
					"audience": str("The audience requested from STS. It must equal the issuer's `console.awsAudience` (default `<issuerURL>/console`), NOT the audience of its AWS federation file."),
				}, "audience"),
			}),
		}),
		"recordsDir": strDefault("The console's records, mounted.", recordsDefault),
		"interval":   duration("How long between passes. Positive.", "15m"),
		"log":        logLevel(),
		"ports":      portsSchema(),
		"platform":   platformSchema(),
		"preset":     presetSchema(),
		"adapters":   adaptersSchema(),
		"probes":     probes(":7070"),
		"secrets":    secretsSchema(),
		"audit": obj("The audit installation the controller records to, as its own workload. Unset only logs what it did.", m{
			"writer":    url("The installation's receiver."),
			"tokenFile": str("This workload's projected service-account token."),
		}),
	}
	addRemotes(props)
	return props
}

func controllerGitHubSchema() m {
	props := rosterProps("github", "/var/run/secrets/github-roster/token", "/var/run/github-roster/records")
	props["appsDir"] = strDefault("One file per connected organisation: its App's credentials.", "/var/run/github-roster/apps")
	return document("controller-github", "sluis controller github",
		"The configuration of `sluis controller github`: the controller that makes each GitHub organisation's teams match the policy's github table."+secretsNote,
		props, []string{"apiVersion", "consoleURL"}, []string{"duration", "url"}, nil)
}

func controllerSlackSchema() m {
	props := rosterProps("slack", "/var/run/secrets/slack-roster/token", "/var/run/slack-roster/workspaces")
	props["credentialsDir"] = strDefault("One file per connected workspace: the app's credentials and its bot token.", "/var/run/slack-roster/credentials")
	return document("controller-slack", "sluis controller slack",
		"The configuration of `sluis controller slack`: the controller that makes each Slack workspace's user groups match the policy's slack table."+secretsNote,
		props, []string{"apiVersion", "consoleURL"}, []string{"duration", "url"}, nil)
}

// Schema returns one binary's schema, written as the committed file is.
func Schema(name string) ([]byte, bool) {
	var s m
	switch name {
	case "sluis":
		s = sluisSchema()
	case "serve":
		s = serveSchema()
	case "controller-github":
		s = controllerGitHubSchema()
	case "controller-slack":
		s = controllerSlackSchema()
	case "sluis-backup":
		s = sluisBackupSchema()
	case "sluis-google":
		s = sluisGoogleSchema()
	case "sluis-outline":
		s = sluisOutlineSchema()
	case "policy":
		s = policySchema()
	case "installation":
		s = installationSchema()
	default:
		return nil, false
	}
	return encode(s), true
}

func encode(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// platformSchema is `platform`: the answers that pick a preset.
func platformSchema() m {
	return obj("What this installation has to build on. The answers pick a preset (the decision tree in docs/concepts/sluis/ports.md), and start refuses an adapter that needs an answer that is no. Absent, the `ports` keys decide and nothing is checked against the platform.", m{
		"aws":        boolean("AWS is available: its credentials, DynamoDB, S3, SSM, KMS, SQS and EventBridge."),
		"kubernetes": boolean("A Kubernetes cluster is available."),
		"openbao":    boolean("An OpenBao is available."),
		"runtime":    enum("Where sluis itself runs. Absent: `kubernetes` with a cluster, else `lambda` on AWS, else `process`.", "", "kubernetes", "lambda", "process"),
		"replicas":   integer("How many replicas share this installation's state. Above 1 start refuses an adapter that keeps its data in the process (`memory`).", 1, 1),
	})
}

// presetSchema is `preset`.
func presetSchema() m {
	return enum("The adapters of a whole platform, one per concern: `server` (no AWS, no Kubernetes), `k8s-minimal`, `k8s-openbao`, `aws-serverless`, `aws-hybrid` (sluis on Lambda, a cluster for the workloads), `k8s-aws` (sluis as a pod on Kubernetes with AWS storage: DynamoDB, S3, KMS-wrapped signing; SSM secrets, or OpenBao with `adapters.secrets`). `aws-eks` is the deprecated name of `k8s-aws`. Absent, the preset the `platform` answers lead to; with neither, the `ports` keys decide. `adapters` and the `ports` keys override single concerns.", "",
		"server", "k8s-minimal", "k8s-openbao", "aws-serverless", "aws-hybrid", "k8s-aws", "aws-eks")
}

// adaptersSchema is `adapters`: the per-concern overrides.
func adaptersSchema() m {
	choice := func(concern string) m {
		return obj("The adapter for "+concern+", replacing the preset's.", m{
			"adapter":  str("The adapter's name, as the compatibility matrix lists it."),
			"settings": m{"type": "object", "description": "The adapter's own settings (an object; the adapter refuses a key it does not know)."},
		}, "adapter")
	}
	return obj("Names the adapter of single concerns, over the preset and the `ports` keys. The names and what each needs are in the matrix of docs/reference/sluis/adapters.md.", m{
		"state":    choice("state, sessions included"),
		"secrets":  choice("secrets (dynamic secrets)"),
		"blobs":    choice("blobs"),
		"signing":  choice("token signing"),
		"trigger":  choice("the \"run a pass now\" trigger"),
		"schedule": choice("the schedule of passes"),
		"audit":    choice("the audit sink"),
	})
}

// keysSchema is the `keys` block: storage/schemas/keys.schema.json, one
// definition for sluis and audit, with its `#/$defs` references inlined so that
// the block carries no `$id` or `$defs` of its own (the chart's values schema
// rewrites definitions and would lose them).
func keysSchema() m {
	var out m
	if err := json.Unmarshal(storageschemas.Keys, &out); err != nil {
		panic("keys.schema.json is not JSON: " + err.Error())
	}
	defs, _ := out["$defs"].(map[string]any)
	delete(out, "$schema")
	delete(out, "$id")
	delete(out, "$defs")
	inlined := inlineDefs(out, defs).(map[string]any)
	// sluis does not use the archive purpose: the shared schema's description
	// is audit's. Since backup format 2 the backup module ignores the key.
	if props, ok := inlined["properties"].(map[string]any); ok {
		if e, ok := props["archive"].(map[string]any); ok {
			e["description"] = "Deprecated, ignored: the archive key of backup format 1. Accepted so a document that still sets it loads; backups are age-encrypted to `backup.recipients`."
		}
	}
	return inlined
}

func inlineDefs(v any, defs map[string]any) any {
	switch t := v.(type) {
	case map[string]any:
		if r, ok := t["$ref"].(string); ok && strings.HasPrefix(r, "#/$defs/") {
			target, _ := inlineDefs(defs[strings.TrimPrefix(r, "#/$defs/")], defs).(map[string]any)
			merged := map[string]any{}
			for k, x := range target {
				merged[k] = x
			}
			for k, x := range t {
				if k != "$ref" {
					merged[k] = x
				}
			}
			return merged
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = inlineDefs(x, defs)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = inlineDefs(x, defs)
		}
		return out
	}
	return v
}

// sluisBackupSchema is the backup module's document: the keys of `serve` that
// open the storage it reads, the audit trail and the key service, and `backup`.
// The module has no issuer, console or policy, so none of their keys are here.
func sluisBackupSchema() m {
	s := serveSchema()
	all, _ := s["properties"].(m)
	props := m{"apiVersion": m{"const": Group + "/sluis-backup/v1", "description": "Which version of which document this is: the backup module's own document (docs/decisions/0071)."}}
	for _, k := range []string{"instance", "keys", "log", "ports", "platform", "preset", "adapters", "secrets", "audit"} {
		props[k] = all[k]
	}
	props["backup"] = obj("What the backup module writes and where. The module reads every module's table, secrets and blobs through the `ports` and `secrets` above (its role has read access to them), and writes one age-encrypted tar.gz per backup, then its sidecar, to `target` (format 2, docs/reference/sluis/backup.md).", m{
		"recipients": m{"type": "array", "minItems": 1, "uniqueItems": true,
			"items":       m{"type": "string", "pattern": `^age1[02-9ac-hj-np-z]{58}$`},
			"description": "The age X25519 public keys (age1...) every backup is encrypted to; at least one, and required in the backup role. Each holder of a matching identity can decrypt a backup without sluis: `age -d -i key.txt <id>.tar.gz.age | tar xz`. The backup role holds nothing that decrypts. In the restore role they are the recipients a backup's sidecar must list: a backup written to another set (before the recipients changed) is refused whatever else is passed, and an `allowUnverified` restore needs them. This does not detect a forged backup: the recipients are public."},
		"identity": m{"type": "string", "pattern": `^[A-Za-z0-9][A-Za-z0-9._-]*$`, "default": "restore-identity",
			"description": "The restore role's secret holding the age identity (AGE-SECRET-KEY-1...) that decrypts the backups: internal/backup/<identity> in the secret store, as {\"value\":\"<base64>\"}. Only the restore role reads it."},
		"key": func() m {
			e := keysSchema()["properties"].(m)["archive"].(m)
			e["description"] = "Deprecated, ignored: the KMS key of backup format 1. Accepted for one release so a document that still sets it loads; set `recipients`."
			return e
		}(),
		"verify": obj("How the restore role proves a backup is the one the backup function made, before it decrypts a byte (docs/reference/sluis/backup.md). Each completed backup is recorded in the audit trail with the hashes of its object and sidecar and its recipients; the restore asks the audit installation's query service for that record and requires the hashes to match and the hour to be sealed. Unset, the restore refuses every backup unless it is started with `allowUnverified`. Read by the restore role only.", m{
			"query":       url("The audit installation's query service (its address, without the `/audit.v1.QueryService/...` path). https, or http on a loopback address."),
			"tokenFile":   str("A file holding the bearer token the query service accepts, read on every request. The token's grants must let it search and get on `profile`."),
			"profile":     str("The audit profile that keeps the `activity` category, where `roster.backup.completed` is kept. Default `activity`."),
			"observer":    str("The id the audit writer stamps on the backup function's records (the writer's `senders` table). A record of a backup stamped by any other is refused. Required unless `anyObserver` is set: without it, any principal that may send to the audit queue can plant a record that vouches for a forged backup."),
			"anyObserver": boolean("Accept a record stamped by any observer. Weakens the check to whoever may write a record as the `roster` source; a start logs a warning. One of `observer` and `anyObserver` is required."),
		}, "query", "tokenFile"),
		"role":   enum("Which function this document configures: `backup` (the scheduled export, the default) or `restore` (the restore function, which only an administrator or the break-glass role may invoke and whose role may write every module's table). The zip is the same; the document picks the role, and `sluis restore` selects it on the command line.", "backup", "backup", "restore"),
		"region": str("Deprecated, ignored: the region of the KMS key of backup format 1."),
		"target": obj("The S3 bucket of the archive. For an AWS bucket with Object Lock, enable versioning and a default retention no longer than `retention`; credentials are the function role's and are never configured here.", m{
			"bucket":    str("The bucket. It must exist."),
			"prefix":    str("A key prefix inside the bucket, put before `backup/<instance>/`."),
			"region":    str("The bucket's region. Unset follows the SDK's own resolution."),
			"kmsKey":    str("A KMS key id, ARN or alias for server-side encryption of every write. Unset leaves the bucket's own default encryption."),
			"endpoint":  url("Overrides the S3 address: LocalStack or an S3-compatible store."),
			"pathStyle": boolean("Addresses the bucket in the path and not the host name, which LocalStack and most S3-compatible stores need."),
			"checksum":  enum("The integrity header of every upload: `sha256` (x-amz-checksum-sha256, computed over the whole body and sent precomputed, never as an aws-chunked trailer), `md5` (Content-MD5) or `none`, for a store that refuses SHA-256. AWS refuses a PutObject without one on an Object Lock bucket.", "sha256", "sha256", "md5", "none"),
		}, "bucket"),
		"retention": obj("Which completed backups a prune keeps. A backup is deleted when it is beyond the `keep` newest AND older than `maxAge`.", m{
			"keep":   integer("How many of the newest completed backups are always kept.", 1, 7),
			"maxAge": duration("How old a backup beyond `keep` may be before it is deleted. 0s deletes it as soon as it is beyond `keep`.", "720h"),
		}),
	}, "target")
	s["properties"] = props
	s["required"] = []string{"apiVersion", "backup"}
	delete(s, "allOf")
	s["$id"] = ID("sluis-backup", apiVersionOf(props))
	s["title"] = "sluis backup"
	s["description"] = "The configuration of `sluis backup`, the backup module (docs/decisions/0071): a scheduled export of the installation, encrypted with age to `backup.recipients`, into an S3 bucket." + secretsNote
	return s
}

// sluisGoogleSchema is the Google module's document: the keys of `serve` that
// open the storage it reads and writes (its own table, the hub cache in the
// blob store, the workspaces' keys), and `google`. The module has no issuer,
// console, signer or policy, so none of their keys are here; it keeps its own
// audit trail (`audit`).
func sluisGoogleSchema() m {
	s := serveSchema()
	all, _ := s["properties"].(m)
	props := m{"apiVersion": m{"const": Group + "/sluis-google/v1", "description": "Which version of which document this is: the Google module's own document (docs/decisions/0071)."}}
	for _, k := range []string{"instance", "log", "probes", "ports", "platform", "preset", "adapters", "secrets"} {
		props[k] = all[k]
	}
	props["audit"] = obj("The audit installation the module records to, as its own workload: the connections it makes and the changes it makes to them. Unset only logs what it did.", m{
		"writer":    url("The installation's receiver."),
		"tokenFile": str("This workload's projected service-account token."),
	})
	oauth := all["oauthClient"].(m)["properties"].(m)
	dir := directorySchema()["properties"].(m)["workspaces"].(m)
	dir["description"] = "The workspaces this deployment declares: each adopted at start, and its service-account key read when it is first used. One that cannot be adopted stops the module. A workspace the console connects is kept in the module's table, with its credential in the secrets store, and is refreshed the same way."
	props["google"] = obj("What the Google module reads and how often it refreshes. The module is the only writer of the directory snapshots (the hub cache in the blob store); the issuer only reads them.", m{
		"workspaces": dir,
		"oauthClient": obj("The OAuth client registered once with Google: needed to reopen a workspace that was connected by consent (a stored refresh token). Not needed for service-account keys.", m{
			"id":       oauth["id"],
			"provider": oauth["provider"],
			"hostedDomains": m{"type": "array", "uniqueItems": true, "items": m{"type": "string", "minLength": 1},
				"description": "The Google Workspace domains a person may sign in from. A sign-in must carry an `hd` claim that names one of them, so an account of another organisation, or a consumer account, is refused whatever its address says. Unset asks nothing of `hd`. A sign-in must in every case carry a verified address."},
		}),
		"publicURL":       url("Where a browser reaches the issuer, including its mount. The consent and sign-in redirect URIs are built from it, so it is the issuer's own `publicURL`. Needed to start a consent or a sign-in; a module that only refreshes does not read it."),
		"refreshInterval": duration("How often a snapshot is refreshed: the schedule's period. A snapshot younger than three quarters of it is not read again, whatever runner asks.", "15m"),
		"freshnessWindow": duration("How old a snapshot may be and still be answered from. The issuer reads it with the same window.", "30m"),
		"probeInterval":   duration("How often the loop probes each workspace's credential (the loop only: a scheduled function does not probe).", "5m"),
	})
	s["properties"] = props
	s["required"] = []string{"apiVersion", "google"}
	delete(s, "allOf")
	s["$id"] = ID("sluis-google", apiVersionOf(props))
	s["title"] = "sluis google"
	s["description"] = "The configuration of `sluis google`, the Google module (docs/decisions/0071): the refresh of the Google Workspace directory snapshots, and the one holder of the workspaces' keys." + secretsNote
	return s
}
