package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests are the mutations of the live steps. Each step judges what the real CLI printed with a function of its own;
// here the function gets a recording of a good run and of the same run with one thing wrong (a changed exit code, a
// refusal that names no reason, a key set that lists the key), and must accept the first and refuse every other. A step
// that accepted a broken command would pass in `just local-cli-smoke` whatever the command did.

func js(t *testing.T, code int, v map[string]any) ran {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return ran{code: code, stdout: string(b) + "\n"}
}

func obj(command string, code int, outcome string, more map[string]any) map[string]any {
	m := map[string]any{"output": 1, "command": command, "exit_code": code, "outcome": outcome}
	for k, v := range more {
		m[k] = v
	}
	return m
}

// verifies: REQ-TEST-018
func TestVersionStepRefusesWhatIsNotAVersion(t *testing.T) {
	good := ran{stdout: "sluis 0.0.0-dev (go1.27.4)\ncontracts: a/v1 b/v1\n"}
	if rel, err := checkVersionText(good); err != nil || rel != "0.0.0-dev" {
		t.Fatalf("a good run: %q, %v", rel, err)
	}
	for name, r := range map[string]ran{
		"a wrong exit code":    {code: 1, stdout: good.stdout},
		"no contracts line":    {stdout: "sluis 0.0.0-dev (go1.27.4)\n"},
		"another name":         {stdout: "store 0.0.0-dev (go1.27.4)\ncontracts: a\n"},
		"no Go runtime":        {stdout: "sluis 0.0.0-dev\ncontracts: a\n"},
		"nothing on stdout":    {},
		"an extra output line": {stdout: good.stdout + "debug\n"},
	} {
		if _, err := checkVersionText(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	okJSON := js(t, 0, obj("version", 0, "done", map[string]any{"version": "0.0.0-dev"}))
	if err := checkVersionJSON(okJSON, "0.0.0-dev"); err != nil {
		t.Fatalf("a good object: %v", err)
	}
	for name, r := range map[string]ran{
		"another release":      js(t, 0, obj("version", 0, "done", map[string]any{"version": "9.9.9"})),
		"the process exits 1":  js(t, 1, obj("version", 0, "done", map[string]any{"version": "0.0.0-dev"})),
		"the object says fail": js(t, 0, obj("version", 0, "failed", map[string]any{"version": "0.0.0-dev"})),
		"another command":      js(t, 0, obj("doctor", 0, "done", map[string]any{"version": "0.0.0-dev"})),
		"no object":            {stdout: "sluis 0.0.0-dev\n"},
	} {
		if err := checkVersionJSON(r, "0.0.0-dev"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if checkUsage(ran{code: 2}) != nil || checkUsage(ran{code: 0}) == nil || checkUsage(ran{code: 3}) == nil {
		t.Error("checkUsage must accept exit 2 and nothing else")
	}
}

func checks(results ...string) []any {
	names := []string{"bootstrap", "installation", "installation", "installation", "installation", "set"}
	var out []any
	for i, n := range names {
		r := "ok"
		if i < len(results) && results[i] != "" {
			r = results[i]
		}
		out = append(out, map[string]any{"name": n, "result": r, "path": "p"})
	}
	return out
}

// verifies: REQ-TEST-018
func TestConfigStepsRefuseABrokenCheck(t *testing.T) {
	pass := func(c []any) ran { return js(t, 0, obj("config check", 0, "done", map[string]any{"checks": c})) }
	if err := checkConfigPass(pass(checks())); err != nil {
		t.Fatalf("a good run: %v", err)
	}
	for name, r := range map[string]ran{
		"a failed line that exits 0":      pass(checks("", "", "", "", "", "fail")),
		"an installation line not run":    pass(checks("", "not-run")),
		"an installation line that warns": pass(checks("", "", "warn")),
		"a missing set line":              pass(checks()[:5]),
		"the process exits 3":             js(t, 3, obj("config check", 3, "refused", map[string]any{"checks": checks(), "reasons": []string{"set"}})),
		"the wrong command":               js(t, 0, obj("config explain", 0, "done", map[string]any{"checks": checks()})),
	} {
		if checkConfigPass(r) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noRuntime := []any{map[string]any{"name": "bootstrap", "result": "ok"}, map[string]any{"name": "installation", "result": "not-run"}}
	if err := checkConfigNoRuntime(pass(noRuntime)); err != nil {
		t.Fatalf("no runtime, a good run: %v", err)
	}
	if checkConfigNoRuntime(pass(checks())) == nil {
		t.Error("an installation check that ran without --runtime was accepted")
	}

	refused := js(t, 3, obj("config check", 3, "refused", map[string]any{"reasons": []string{"document KeyPlan"}}))
	if err := checkConfigRefused(refused, "config check"); err != nil {
		t.Fatalf("a good refusal: %v", err)
	}
	for name, r := range map[string]ran{
		"exit 0":          js(t, 0, obj("config check", 0, "done", nil)),
		"exit 1":          js(t, 1, obj("config check", 1, "failed", nil)),
		"no reason":       js(t, 3, obj("config check", 3, "refused", nil)),
		"exit 3 but done": js(t, 3, obj("config check", 3, "done", map[string]any{"reasons": []string{"x"}})),
	} {
		if checkConfigRefused(r, "config check") == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	field := func(code int, path, value, class, layer, version string) ran {
		return js(t, code, obj("config explain", code, "done", map[string]any{"fields": []any{
			map[string]any{"path": path, "value": value, "class": class, "layer": layer, "version": version, "source": "s"}}}))
	}
	if err := checkExplainField(field(0, "a.b", "10m", "config", "config", "3"), "a.b", "10m", "config", "config"); err != nil {
		t.Fatalf("a good field: %v", err)
	}
	for name, r := range map[string]ran{
		"another value":                field(0, "a.b", "11m", "config", "config", "3"),
		"another layer":                field(0, "a.b", "10m", "config", "bootstrap", "3"),
		"another path":                 field(0, "a.c", "10m", "config", "config", "3"),
		"a document without a version": field(0, "a.b", "10m", "config", "config", ""),
		"two fields":                   js(t, 0, obj("config explain", 0, "done", map[string]any{"fields": []any{map[string]any{}, map[string]any{}}})),
		"no field":                     js(t, 0, obj("config explain", 0, "done", nil)),
	} {
		if checkExplainField(r, "a.b", "10m", "config", "config") == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// verifies: REQ-TEST-018
func TestTamperChangesThePayloadOfASignedDocument(t *testing.T) {
	doc := []byte("{\n  \"payload\": \"abcdef\",\n  \"signatures\": []\n}\n")
	got, err := tamper(doc)
	if err != nil || string(got) == string(doc) || !strings.Contains(string(got), `"payload": "aZbcdef"`) {
		t.Fatalf("tamper = %q, %v", got, err)
	}
	if _, err := tamper([]byte(`{"signatures": []}`)); err == nil {
		t.Error("a document with no payload was tampered")
	}
	set := t.TempDir()
	for name, body := range map[string]string{"key-plan.jws": string(doc), "boundary.jws": string(doc)} {
		if err := os.WriteFile(filepath.Join(set, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bad, err := tamperedSet(set, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]bool{"key-plan.jws": true, "boundary.jws": false} {
		b, err := os.ReadFile(filepath.Join(bad, name)) //nolint:gosec // a temporary directory of the test
		if err != nil {
			t.Fatal(err)
		}
		if (string(b) != string(doc)) != changed {
			t.Errorf("%s: changed = %v, want %v", name, !changed, changed)
		}
	}
}

// verifies: REQ-TEST-018
func TestNodeStepRefusesAGuessedState(t *testing.T) {
	good := js(t, 1, obj("node status", 1, "failed", map[string]any{"error": "node status: status: the admin socket cannot be reached (is the driver running, and are you root?)"}))
	if err := checkNodeUnreachable(good); err != nil {
		t.Fatalf("a good run: %v", err)
	}
	for name, r := range map[string]ran{
		"unlocked, though nobody answered": js(t, 0, obj("node status", 0, "done", map[string]any{"node": map[string]any{"node": "n1", "locked": false}})),
		"locked, with a failure":           js(t, 1, obj("node status", 1, "failed", map[string]any{"error": "x cannot be reached", "node": map[string]any{"node": "n1", "locked": true}})),
		"refused instead of failed":        js(t, 3, obj("node status", 3, "refused", map[string]any{"error": "cannot be reached"})),
		"no word about reaching":           js(t, 1, obj("node status", 1, "failed", map[string]any{"error": "something"})),
	} {
		if checkNodeUnreachable(r) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func address(name, state string, listed ...string) map[string]any {
	n := 3
	return map[string]any{"name": name, "state": state, "keys": n, "issuer": "https://i", "listed": listed}
}

func confirmation(confirmed bool, addrs ...any) map[string]any {
	return map[string]any{"confirmed": confirmed, "rounds": 2, "kids": []string{"k"}, "addresses": addrs}
}

// verifies: REQ-TEST-018
func TestKeyRevokeStepsRefuseABrokenRevocation(t *testing.T) {
	const kid = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	absent := confirmation(true, address("public", "absent"), address("entry", "absent"))
	delivered := func(code int, outcome string, already bool, audited bool, conf map[string]any) ran {
		return js(t, code, obj("key revoke", code, outcome, map[string]any{"revoke": map[string]any{
			"seq": 7, "audited": audited, "confirmation": conf,
			"keys": []any{map[string]any{"kid": kid, "already": already, "unknown": !already}},
		}}))
	}
	// As root the delivery revokes, audits and reads the public key set, and cannot read entry's (the defect that
	// checkDelivered records): exit 5, entry unknown.
	rootSees := confirmation(false, address("public", "absent"), map[string]any{"name": "entry", "state": "unknown", "reason": "EOF"})
	if err := checkDelivered(delivered(5, "failed", false, true, rootSees), kid, false); err != nil {
		t.Fatalf("a good delivery: %v", err)
	}
	if err := checkDelivered(delivered(5, "failed", true, true, rootSees), kid, true); err != nil {
		t.Fatalf("a good repeat: %v", err)
	}
	listed := confirmation(false, address("public", "listed", kid), address("entry", "absent"))
	unread := confirmation(false, map[string]any{"name": "public", "state": "absent", "issuer": "https://i"}, map[string]any{"name": "entry", "state": "unknown"})
	for name, r := range map[string]ran{
		"exit 0 with the defect gone, unnoticed": delivered(0, "done", false, true, absent),
		"entry's set read as absent":             delivered(5, "failed", false, true, confirmation(false, address("public", "absent"), address("entry", "absent"))),
		"the public key set lists the key":       delivered(5, "failed", false, true, confirmation(false, address("public", "listed", kid), map[string]any{"name": "entry", "state": "unknown"})),
		"the audit fact is not durable":          delivered(5, "failed", false, false, rootSees),
		"a public key set that was not read":     delivered(5, "failed", false, true, unread),
		"one address only":                       delivered(5, "failed", false, true, confirmation(false, address("public", "absent"))),
		"the addresses the wrong way":            delivered(5, "failed", false, true, confirmation(false, map[string]any{"name": "entry", "state": "unknown"}, address("public", "absent"))),
		"no confirmation":                        delivered(5, "failed", false, true, nil),
	} {
		if err := checkDelivered(r, kid, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A first delivery of a key that key@ knows is not the drill this step made.
	known := js(t, 5, obj("key revoke", 5, "failed", map[string]any{"revoke": map[string]any{
		"seq": 7, "audited": true, "confirmation": rootSees, "keys": []any{map[string]any{"kid": kid}}}}))
	if checkDelivered(known, kid, false) == nil {
		t.Error("a first delivery of a key that key@ knew was accepted")
	}
	// The repeat must say already; a first delivery that says already is refused too.
	if checkDelivered(delivered(5, "failed", true, true, rootSees), kid, false) == nil {
		t.Error("a first delivery that says already revoked was accepted")
	}
	if checkDelivered(delivered(5, "failed", false, true, rootSees), kid, true) == nil {
		t.Error("a repeat that says revoked now was accepted")
	}

	look := func(code int, outcome string, conf map[string]any) ran {
		return js(t, code, obj("key revoke", code, outcome, map[string]any{"revoke": map[string]any{"confirmation": conf}}))
	}
	if err := checkCheckedAbsent(look(0, "done", absent)); err != nil {
		t.Fatalf("a good --check: %v", err)
	}
	if checkCheckedAbsent(look(5, "failed", listed)) == nil || checkCheckedAbsent(delivered(5, "failed", false, true, rootSees)) == nil {
		t.Error("a --check that found the key listed, or one that delivered, was accepted")
	}

	both := confirmation(false, address("public", "listed", kid), address("entry", "listed", kid))
	if err := checkStillListed(look(5, "failed", both), kid); err != nil {
		t.Fatalf("a good negative control: %v", err)
	}
	for name, r := range map[string]ran{
		"exit 0":                 look(0, "done", both),
		"exit 1, failed":         look(1, "failed", both),
		"only one set lists it":  look(5, "failed", listed),
		"listed but another kid": look(5, "failed", confirmation(false, address("public", "listed", "other"), address("entry", "listed", "other"))),
		"could not tell, exit 5": look(5, "failed", confirmation(false, map[string]any{"name": "public", "state": "unknown"}, address("entry", "listed", kid))),
		"no confirmation object": js(t, 5, obj("key revoke", 5, "failed", map[string]any{"revoke": map[string]any{}})),
	} {
		if checkStillListed(r, kid) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// verifies: REQ-TEST-018
func TestRevokeWrittenDeclaration(t *testing.T) {
	const kid = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	path := filepath.Join(t.TempDir(), "revoke.yaml")
	text := "# comment\nboundary: dev\nkids:\n  - " + kid + "\nreason: drill\nallow_unknown: true\n"
	ok := js(t, 0, obj("key revoke", 0, "done", map[string]any{"revoke": map[string]any{"written": path}}))
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(text)
	if err := checkRevokeWritten(ok, path, kid); err != nil {
		t.Fatalf("a good declaration: %v", err)
	}
	for name, s := range map[string]string{
		"another boundary":  strings.Replace(text, "boundary: dev", "boundary: prod", 1),
		"another reason":    strings.Replace(text, "drill", "compromise", 1),
		"no allow_unknown":  strings.Replace(text, "allow_unknown: true\n", "", 1),
		"another key":       strings.Replace(text, kid, "x"+kid[1:], 1),
		"a key as a prefix": strings.Replace(text, "  - "+kid, "  - "+kid+"A", 1),
	} {
		write(s)
		if checkRevokeWritten(ok, path, kid) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	write(text)
	if checkRevokeWritten(js(t, 2, obj("key revoke", 2, "usage", nil)), path, kid) == nil {
		t.Error("a usage error was accepted as a written declaration")
	}
}

// verifies: REQ-TEST-018
func TestFirstThumbprintIsTheRFC7638ThumbprintOfTheFirstKey(t *testing.T) {
	// The EC key of RFC 7638's family of examples is not used: any key must give 43 base64url characters, and a set with
	// no key none.
	set := `{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"first"}]}`
	id, err := firstThumbprint([]byte(set))
	if err != nil || !thumbprint.MatchString(id) {
		t.Fatalf("thumbprint = %q, %v", id, err)
	}
	if _, err := firstThumbprint([]byte(`{"keys":[]}`)); err == nil {
		t.Error("an empty key set gave a thumbprint")
	}
	if _, err := firstThumbprint([]byte(`not json`)); err == nil {
		t.Error("garbage gave a thumbprint")
	}
}
