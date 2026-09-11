package app_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// Variables a deployment is not expected to set. Everything else the
// binary reads, the chart must set — or it is a setting that works on a
// laptop and does something different, or nothing, in production.
var localOnly = []string{
	// A demonstration switch, and the password that only exists where
	// there is no cluster to prove access to.
	"DEMO", "ADMIN_PASSWORD",
	// Insecure transport: a laptop over http, never a deployment.
	"ALLOW_INSECURE",
	// The chart mounts these as FILES and sets the _FILE pair instead,
	// so a secret never becomes an environment variable something can
	// print. The bare names are the laptop's way in.
	"OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET",
	// THE HUB'S OWN DEPLOYMENT SETTINGS, which nothing sets any more
	// because the hub no longer has a deployment. Each was supplied by
	// the hub's chart, and the merged service either answers it in code
	// or has no use for it:
	//
	//   API_PORT, CONSOLE_PORT   two listeners that are now one, on the
	//                            issuer's port
	//   API_AUDIENCE,            the gate on the hub's API for OTHER
	//   CONSUMERS_FILE           consumers; the only consumer is now
	//                            this same process
	//   FORWARDED_*              who the proxy in front of the console
	//                            said you were -- there is no proxy in
	//                            front of the console any more, it reads
	//                            the issuer's own session (INF-701)
	//   SIGN_OUT_URL             where the console's sign-out pointed;
	//                            the issuer serves /logout itself now
	//
	// This list is the merge's remaining debt written down. SIGN_OUT_URL
	// is why it is worth writing down: the merged service had no source
	// for it, the console's button rendered empty, and "sign out does
	// not work" was reported twice before anybody looked. Nothing failed,
	// because an empty string is valid everywhere it lands.
	"API_PORT", "CONSOLE_PORT", "API_AUDIENCE", "CONSUMERS_FILE",
	"FORWARDED_AUDIENCE", "FORWARDED_EMAIL_HEADER", "FORWARDED_ISSUER",
	"SIGN_OUT_URL",

	// SPLIT-DEPLOYMENT LEFTOVERS. The hub was reached over the network
	// at HUB_ADDRESS until INF-691 folded it into this process, and the
	// shipped binary now always supplies the directory in-process — so
	// nothing sets these and nothing should. The code path behind them
	// is dead in the one binary we build, and removing it is the last
	// of that merge rather than part of this change.
	"HUB_ADDRESS", "HUB_TOKEN_FILE",
}

// The chart and the binary agree on the environment between them, and
// nothing else checks it. Five variables were being read here and set
// nowhere, and the worst of them built every OAuth redirect URI from
// `http://localhost:8081` — invisible in every local run and fatal in the
// first deployment.
//
// The lists are read from the source rather than restated, because a
// restated list is one that drifts, which is the failure this exists to
// catch.
func TestTheChartSetsEverythingTheBinaryReads(t *testing.T) {
	// BOTH readers, because one chart now feeds both. The issuer reads
	// its own settings in internal/issuerapp and runs the hub in process
	// from internal/app; a deployment that set only what one of them
	// wanted would leave the other on laptop defaults.
	pattern := regexp.MustCompile(`env(?:String|Bool|Int|Duration|List)\("([A-Z_]+)"`)
	reads := append(
		found(t, "app.go", pattern),
		found(t, filepath.Join("..", "issuerapp", "app.go"), pattern)...,
	)
	// The ISSUER's chart, because the issuer is what deploys this code:
	// INF-691 folded the hub into it and internal/rosterapp runs it in
	// process. The hub's own chart is gone, and this check followed the
	// deployment rather than being deleted with it -- what it catches is
	// a variable read here and set nowhere, which does not care which
	// chart does the setting.
	sets := found(t, filepath.Join("..", "..", "charts", "access-issuer", "templates", "deployment.yaml"),
		regexp.MustCompile(`(?m)^\s+- name: ([A-Z_]+)\s*$`))

	if len(reads) == 0 || len(sets) == 0 {
		t.Fatalf("read %d variables and %d settings; the patterns have stopped matching", len(reads), len(sets))
	}
	for _, name := range reads {
		if slices.Contains(localOnly, name) || slices.Contains(sets, name) {
			continue
		}
		t.Errorf("the binary reads %s and the chart never sets it: a deployment gets the default, "+
			"which is whatever a laptop wanted", name)
	}
	for _, name := range sets {
		// NAMESPACE is read by internal/kube rather than through the
		// helpers here, so it is expected and named rather than matched.
		if name == "NAMESPACE" || slices.Contains(reads, name) {
			continue
		}
		t.Errorf("the chart sets %s and nothing reads it: it is a value an operator can change "+
			"with no effect", name)
	}
}

func found(t *testing.T, path string, pattern *regexp.Regexp) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, match := range pattern.FindAllStringSubmatch(string(body), -1) {
		if !slices.Contains(out, match[1]) {
			out = append(out, match[1])
		}
	}
	slices.Sort(out)
	return out
}
