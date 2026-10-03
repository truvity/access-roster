package config_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	policyconfig "github.com/truvity/policy/config"
	yaml "go.yaml.in/yaml/v3"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/config/schema"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A schema in schemas/config is what schema.Schema writes. The binaries read
// the committed file, and a chart's tests validate against it, so a change to
// the builder that is not followed by `just config-schemas` fails here as well
// as in the drift check.
func TestTheCommittedSchemasAreTheGeneratedOnes(t *testing.T) {
	for _, name := range schema.Names {
		want, ok := schema.Schema(name)
		if !ok {
			t.Fatalf("%s: no schema is built", name)
		}
		got, err := os.ReadFile(filepath.Join("..", "..", "schemas", "config", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is not what `just config-schemas` writes", name)
		}
	}
	got, err := os.ReadFile(filepath.Join("..", "..", "charts", "access-roster", "values.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, schema.Values()) {
		t.Error("the chart's values.schema.json is not what `just config-schemas` writes")
	}
}

// Each type is held to its schema in both directions: a file that sets every
// key must decode into the type with no key left over, and writing the type
// back must give the file again. A key added to the schema and not the type is
// refused by the first; one added to the type and not the schema, by the
// second.
func TestTheTypesAndTheSchemasDescribeTheSameKeys(t *testing.T) {
	for _, c := range []struct {
		name string
		into any
	}{
		{"serve", &config.Serve{}},
		{"controller-github", &config.ControllerGitHub{}},
		{"controller-slack", &config.ControllerSlack{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", c.name+".full.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if err := config.Validate(c.name, doc); err != nil {
				t.Fatalf("the full example does not validate: %v", err)
			}
			asJSON, _ := json.Marshal(doc)
			dec := json.NewDecoder(bytes.NewReader(asJSON))
			dec.DisallowUnknownFields()
			if err := dec.Decode(c.into); err != nil {
				t.Fatalf("the type does not hold a key the example sets: %v", err)
			}
			back, err := json.Marshal(c.into)
			if err != nil {
				t.Fatal(err)
			}
			var want, got any
			_ = json.Unmarshal(asJSON, &want)
			_ = json.Unmarshal(back, &got)
			if !jsonEqual(canonical(want), canonical(got)) {
				t.Errorf("the type does not write back what the example sets:\n want %s\n  got %s", asJSON, back)
			}
			// And the example sets EVERY property the schema has: a key left out
			// of it is one no test holds to the type.
			var s struct {
				Properties map[string]json.RawMessage `json:"properties"`
			}
			body, _ := schema.Schema(c.name)
			if err := json.Unmarshal(body, &s); err != nil {
				t.Fatal(err)
			}
			for key := range s.Properties {
				if _, set := doc.(map[string]any)[key]; !set {
					t.Errorf("the full example does not set %s", key)
				}
			}
		})
	}
}

// canonical writes every duration as the span it is, so that "15m" and
// "15m0s" are the same value.
func canonical(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = canonical(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = canonical(x)
		}
		return out
	case string:
		if d, err := time.ParseDuration(t); err == nil {
			return d.String()
		}
	}
	return v
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

const minimalIssuer = "issuerURL: https://access.example\n"

func TestAValidFileLoads(t *testing.T) {
	f, err := config.LoadServe(write(t, minimalIssuer))
	if err != nil {
		t.Fatal(err)
	}
	if f.IssuerURL != "https://access.example" {
		t.Errorf("not decoded: %+v", f)
	}
	g, err := config.LoadControllerGitHub(write(t, "policyDir: /p\nconsoleURL: http://c:8080/console\ninterval: 5m\nenabledOrgs: [a]\n"))
	if err != nil || g.Interval.D().String() != "5m0s" || g.EnabledOrgs[0] != "a" {
		t.Errorf("controller-github: %v %+v", err, g)
	}
	if _, err := config.LoadControllerSlack(write(t, "policyDir: /p\nconsoleURL: http://c:8080/console\n")); err != nil {
		t.Errorf("controller-slack: %v", err)
	}
}

// What a typo must do: fail, and say which key.
func TestAnUnknownKeyIsRefusedAndNamed(t *testing.T) {
	_, err := config.LoadServe(write(t, minimalIssuer+"valkey2: {}\nlisten: {adr: ':1'}\n"))
	var ce *policyconfig.Error
	if !errors.As(err, &ce) {
		t.Fatalf("want a configuration error, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"'valkey2'", "listen: additional properties 'adr'"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not name %q: %s", want, msg)
		}
	}
}

func TestAMissingRequiredKeyIsRefusedAndNamed(t *testing.T) {
	if _, err := config.LoadServe(write(t, "store: memory\n")); err == nil || !strings.Contains(err.Error(), "issuerURL") {
		t.Fatalf("want a refusal naming issuerURL, got %v", err)
	}
	if _, err := config.LoadControllerGitHub(write(t, "consoleURL: http://c:8080\n")); err == nil || !strings.Contains(err.Error(), "policyDir") {
		t.Fatalf("want a refusal naming policyDir, got %v", err)
	}
	if _, err := config.LoadControllerSlack(write(t, "policyDir: /p\n")); err == nil || !strings.Contains(err.Error(), "consoleURL") {
		t.Fatalf("want a refusal naming consoleURL, got %v", err)
	}
}

// A secret is never in the file: not under a key of its own, which no schema
// has, and not inside a URL or an address, which would have been the easy
// place.
func TestASecretInTheFileIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"a valkey password key":      minimalIssuer + "valkey: {address: 'v:6379', password: hunter2}\n",
		"a valkey address with auth": minimalIssuer + "valkey: {address: ':hunter2@v:6379'}\n",
		"an oauth secret key":        minimalIssuer + "oauthClient: {secret: hunter2}\n",
		"an admin password key":      minimalIssuer + "adminPassword: hunter2\n",
		"a password in the issuer":   "issuerURL: https://u:hunter2@access.example\n",
		"a password in the writer":   minimalIssuer + "audit: {writer: 'http://u:hunter2@audit:8080'}\n",
	} {
		_, err := config.LoadServe(write(t, body))
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the error quotes the secret: %v", name, err)
		}
	}
	// A variable NAME is not a value: a value that is not a name is refused.
	if _, err := config.LoadServe(write(t, minimalIssuer+"valkey: {address: 'v:6379', passwordEnv: 'hunter 2!'}\n")); err == nil {
		t.Error("a password value in a ...Env field was accepted")
	}
}

// The environment supplies exactly the secrets the file names.
func TestADeclaredSecretIsReadFromTheEnvironment(t *testing.T) {
	t.Setenv("ACCESS_TEST_SECRET", "s3cr:et@/x")
	got, err := config.Secret("ACCESS_TEST_SECRET")
	if err != nil || got != "s3cr:et@/x" {
		t.Fatalf("the named variable was not read: %q %v", got, err)
	}
	if _, err := config.Secret("ACCESS_TEST_NOT_SET"); err == nil || !strings.Contains(err.Error(), "ACCESS_TEST_NOT_SET") {
		t.Errorf("an unset variable must be named: %v", err)
	}
}

func TestAnEmptyOrMissingFileIsRefused(t *testing.T) {
	if _, err := config.LoadServe(write(t, "")); err == nil {
		t.Error("an empty file was accepted")
	}
	if _, err := config.LoadServe(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// What the schema alone refuses of the values the binaries used to check in
// code: a duration that is not one, a level that is not one, a tier that is not
// one, an enum, a listener that is not an address.
func TestTheSchemaRefusesWhatTheEnvironmentWasTrustedWith(t *testing.T) {
	for name, extra := range map[string]string{
		"a duration that is not one":           "lifetimes: {token: a while}\n",
		"a zero absolute lifetime":             "lifetimes: {absolute: 0}\n",
		"a log level that is not one":          "log: {level: chatty}\n",
		"a store that is not one":              "store: postgres\n",
		"a scoping mode that is not one":       "groupsScoping: sometimes\n",
		"a runner tier that is not one":        "github: {runnerTiers: ['Not A Tier']}\n",
		"a listener that is not an address":    "listen: {address: '8080'}\n",
		"a negative trusted hop count":         "audit: {writer: 'http://a:1', forwardedForTrustedHops: -1}\n",
		"the query service without the writer": "audit: {queryURL: 'http://q:1'}\n",
		"a signing key list that is a string":  "signingKey: {additionalFiles: /k}\n",
	} {
		if _, err := config.LoadServe(write(t, minimalIssuer+extra)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestACommandLineIsTheFileAndNothingElse(t *testing.T) {
	var out bytes.Buffer
	file, done, err := config.Command("access-roster serve", "serve", []string{"--config", "/etc/c.yaml"}, &out)
	if err != nil || done || file != "/etc/c.yaml" {
		t.Errorf("--config: %q %v %v", file, done, err)
	}
	if _, done, err = config.Command("access-roster serve", "serve", []string{"--version"}, &out); err != nil || !done {
		t.Errorf("--version: %v %v", done, err)
	}
	if _, done, err = config.Command("access-roster serve", "serve", []string{"--help"}, &out); err != nil || !done {
		t.Errorf("--help: %v %v", done, err)
	}
	for name, args := range map[string][]string{
		"no file":       {},
		"an old flag":   {"--config", "/c", "--port", "8080"},
		"an argument":   {"--config", "/c", "extra"},
		"an empty file": {"--config", ""},
	} {
		if _, _, err := config.Command("access-roster serve", "serve", args, &out); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A retired variable that is still set is refused at start, naming what
// replaces it, and only when it holds something.
func TestARetiredVariableIsRefused(t *testing.T) {
	err := config.RefuseRetired("serve", []string{"PATH=/bin", "ISSUER_URL=https://x", "VALKEY_PASSWORD=hunter2", "LOG_LEVEL="})
	if err == nil {
		t.Fatal("retired variables were accepted")
	}
	for _, want := range []string{"ISSUER_URL (now issuerURL)", "VALKEY_PASSWORD (now valkey.passwordEnv"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "LOG_LEVEL") {
		t.Errorf("the refusal quotes a value or names an empty variable: %v", err)
	}
	if err := config.RefuseRetired("serve", []string{"SECRET_MANAGERS_FILE=/x"}); err == nil || !strings.Contains(err.Error(), "v1.30.0") {
		t.Errorf("the removed secret-store view's variable must still be refused, with its reason: %v", err)
	}
	if err := config.RefuseRetired("serve", []string{"PATH=/bin", "OTEL_EXPORTER_OTLP_ENDPOINT=http://c:4318", "NAMESPACE=x"}); err != nil {
		t.Errorf("OpenTelemetry's variables and the pod's own are not retired: %v", err)
	}
	if err := config.RefuseRetired("controller-github", []string{"ENABLED_ORGS=a"}); err == nil || !strings.Contains(err.Error(), "enabledOrgs") {
		t.Errorf("controller-github: %v", err)
	}
	if err := config.RefuseRetired("controller-slack", []string{"ENABLED_WORKSPACES=a"}); err == nil || !strings.Contains(err.Error(), "enabledWorkspaces") {
		t.Errorf("controller-slack: %v", err)
	}
}

// The reference documents every retired variable and what replaces it, and
// nothing it lists is retired twice: a migration table is a table somebody
// follows line by line.
func TestTheReferenceListsEveryRetiredVariable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	cell := regexp.MustCompile("`([A-Z][A-Z0-9_]+)`")
	listed := map[string]bool{}
	for _, m := range cell.FindAllStringSubmatch(doc, -1) {
		listed[m[1]] = true
	}
	for _, binary := range schema.Names {
		for name := range config.Retired(binary) {
			if !listed[name] {
				t.Errorf("%s: the reference's migration table does not list %s", binary, name)
			}
		}
	}
}

// `ports.adapter` is one of the two adapters that exist, and the default is
// the one that keeps state where it has always been kept.
func TestThePortsAdapterIsOneOfTheTwo(t *testing.T) {
	for _, adapter := range []string{"legacy", "memory"} {
		if _, err := config.LoadServe(write(t, minimalIssuer+"ports: {adapter: "+adapter+"}\n")); err != nil {
			t.Errorf("adapter %s was refused: %v", adapter, err)
		}
	}
	if _, err := config.LoadServe(write(t, minimalIssuer+"ports: {adapter: nats}\n")); err == nil {
		t.Error("the nats adapter was accepted with no server named")
	}
	if _, err := config.LoadServe(write(t, minimalIssuer+"ports: {adapter: nats, nats: {bucket: b}}\n")); err == nil {
		t.Error("a nats section with no url was accepted")
	}
	full := "ports:\n  adapter: nats\n  nats: {url: 'nats://n:4222', replicas: 3, tokenFile: /var/run/secrets/nats/token}\n"
	if f, err := config.LoadServe(write(t, minimalIssuer+full)); err != nil {
		t.Errorf("the nats adapter was refused: %v", err)
	} else if f.Ports.NATS == nil || f.Ports.NATS.URL != "nats://n:4222" || f.Ports.NATS.TokenFile == "" {
		t.Errorf("ports.nats = %+v", f.Ports.NATS)
	}
	withPassword := "ports: {adapter: nats, nats: {url: 'nats://n:4222', password: x}}\n"
	if _, err := config.LoadServe(write(t, minimalIssuer+withPassword)); err == nil {
		t.Error("a nats password in the file was accepted")
	}
	if _, err := config.LoadServe(write(t, minimalIssuer+"ports: {adapter: dynamodb}\n")); err == nil {
		t.Error("an adapter that does not exist was accepted")
	}
	if _, err := config.LoadControllerGitHub(write(t, "policyDir: /p\nconsoleURL: http://c:8080\nports: {adapter: dynamodb}\n")); err == nil {
		t.Error("a controller accepted an adapter that does not exist")
	}
	if _, err := config.LoadControllerSlack(write(t, "policyDir: /p\nconsoleURL: http://c:8080\nports: {adapter: memory}\n")); err != nil {
		t.Errorf("a controller refused the memory adapter: %v", err)
	}
}

// `ports.blob` and `ports.sealer` each name one adapter and its settings, and
// compose with any `ports.adapter`.
func TestThePortsBlobAndSealerAreChecked(t *testing.T) {
	good := minimalIssuer + `ports:
  adapter: legacy
  blob: {adapter: s3, s3: {bucket: b, prefix: ar, region: eu-west-1, kmsKey: alias/ar, endpoint: "http://localhost:4566", pathStyle: true}}
  sealer: {adapter: kms, kms: {keyId: alias/ar, region: eu-west-1}}
`
	c, err := config.LoadServe(write(t, good))
	if err != nil {
		t.Fatalf("a Blob and a Sealer over the legacy State were refused: %v", err)
	}
	if c.Ports.Blob.S3.Bucket != "b" || !c.Ports.Blob.S3.PathStyle || c.Ports.Sealer.KMS.KeyID != "alias/ar" {
		t.Errorf("decoded %+v %+v", c.Ports.Blob, c.Ports.Sealer)
	}
	for name, bad := range map[string]string{
		"an unknown blob adapter":   "ports: {blob: {adapter: gcs}}\n",
		"s3 with no settings":       "ports: {blob: {adapter: s3}}\n",
		"s3 with no bucket":         "ports: {blob: {adapter: s3, s3: {prefix: x}}}\n",
		"an unknown s3 key":         "ports: {blob: {adapter: s3, s3: {bucket: b, accessKey: x}}}\n",
		"an unknown sealer adapter": "ports: {sealer: {adapter: vault}}\n",
		"kms with no settings":      "ports: {sealer: {adapter: kms}}\n",
		"kms with no key":           "ports: {sealer: {adapter: kms, kms: {region: eu-west-1}}}\n",
		"a blob with no adapter":    "ports: {blob: {s3: {bucket: b}}}\n",
	} {
		if _, err := config.LoadServe(write(t, minimalIssuer+bad)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := config.LoadControllerGitHub(write(t, "policyDir: /p\nconsoleURL: http://c:8080\nports: {blob: {adapter: s3, s3: {bucket: b}}}\n")); err != nil {
		t.Errorf("a controller refused ports.blob: %v", err)
	}
}
