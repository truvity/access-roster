package writerd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

const schemaDir = "../../../../kits/conformance/audit/schema"

// realCatalogue is the AuditCatalogue of a release with the real schemas, as the generator makes the document.
func realCatalogue(t *testing.T, release string) *configv2alpha1.AuditCatalogue {
	t.Helper()
	ents, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatal(err)
	}
	c := &configv2alpha1.AuditCatalogue{Release: release, Policy: audit.PolicyVersion}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(schemaDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		c.Schemas = append(c.Schemas, &configv2alpha1.AuditSchema{Name: e.Name(), Json: string(b)})
		if e.Name() != audit.DefsName {
			c.Actions = append(c.Actions, strings.TrimSuffix(e.Name(), ".schema.json"))
		}
	}
	return c
}

// realChecker is a checker whose AuditCatalogue is the real one: the schemas generated from the action table, as the
// release pipeline publishes them, at the release the local installation names.
func realChecker(t *testing.T) checker {
	t.Helper()
	ents, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatal(err)
	}
	files, actions := map[string]string{}, catalogue{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(schemaDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = string(b)
		if e.Name() != audit.DefsName {
			actions[strings.TrimSuffix(e.Name(), ".schema.json")] = struct{}{}
		}
	}
	if len(actions) < 40 {
		t.Fatalf("%d schemas: the directory lost its files", len(actions))
	}
	s, err := audit.ParseSchemas(files)
	if err != nil {
		t.Fatal(err)
	}
	return checker{boundary: "dev", project: "sluis", release: "v0.0.0", actions: actions, schemas: s}
}

type exampleCase struct {
	Name     string `json:"name"`
	Actor    string `json:"actor"`
	UID      string `json:"uid"`
	Expected string `json:"expected"`
}

func exampleCases(t *testing.T) []exampleCase {
	t.Helper()
	b, err := os.ReadFile("../../../../kits/conformance/audit/action-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []exampleCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

// verifies: REQ-AUDIT-113
//
// The writer accepts the example record of every action of the table against the real catalogue, as the emitter of
// that actor sends it: the schemas the pipeline publishes accept what the emitters make.
func TestTheWriterAcceptsTheExampleOfEveryActionAgainstTheRealCatalogue(t *testing.T) {
	c := realChecker(t)
	for _, ex := range exampleCases(t) {
		t.Run(ex.Name, func(t *testing.T) {
			if _, rej := c.check(ex.UID, ex.Actor+"@dev", []byte(ex.Expected), 0); rej != nil {
				t.Fatalf("refused: %v", rej)
			}
		})
	}
}

// verifies: REQ-AUDIT-113
//
// The negative vectors of unmapped.sluis through the writer: a member the action lacks, a required member missing, a
// value of the wrong type or shape, `lost` of the wrong shape. The refusal names the member and never a value.
func TestTheWriterRefusesAnUnmappedSluisThatDoesNotValidate(t *testing.T) {
	c := realChecker(t)
	var base exampleCase
	for _, ex := range exampleCases(t) {
		if ex.Name == "key.sign" {
			base = ex
		}
	}
	mutate := func(f func(sluis map[string]any)) []byte {
		v, err := parseStrict([]byte(base.Expected))
		if err != nil {
			t.Fatal(err)
		}
		u := v.(map[string]any)["unmapped"].(map[string]any)["sluis"].(map[string]any)
		f(u)
		return canonical(t, v)
	}
	for name, tc := range map[string]struct {
		f    func(map[string]any)
		path string
	}{
		"a member the action lacks": {func(s map[string]any) { s["extra"] = "x" }, "unmapped.sluis"},
		"a required member missing": {func(s map[string]any) { delete(s, "key_id") }, "unmapped.sluis"},
		"an integer for a string":   {func(s map[string]any) { s["purpose"] = int64(7) }, "unmapped.sluis.purpose"},
		"a name with a space":       {func(s map[string]any) { s["caller"] = "a secret value" }, "unmapped.sluis.caller"},
		"lost of the wrong shape":   {func(s map[string]any) { s["lost"] = "3" }, "unmapped.sluis.lost"},
		"lost with a total of zero": {func(s map[string]any) {
			s["lost"] = map[string]any{"process": "0123456789abcdef", "total": int64(0), "since": int64(1)}
		}, "unmapped.sluis.lost.total"},
	} {
		t.Run(name, func(t *testing.T) {
			_, rej := c.check(base.UID, "key@dev", mutate(tc.f), 0)
			if rej == nil || rej.Reason != reasonSchema || rej.Path != tc.path {
				t.Fatalf("rejection = %v, want schema at %s", rej, tc.path)
			}
		})
	}
	// And one that is valid, with lost beside the members: the note of lost facts is part of the record.
	ok := mutate(func(s map[string]any) {
		s["lost"] = map[string]any{"process": "0123456789abcdef", "total": int64(3), "since": int64(1793750400000)}
	})
	if _, rej := c.check(base.UID, "key@dev", ok, 0); rej != nil {
		t.Fatalf("a record with the note of lost facts: %v", rej)
	}
}

// verifies: REQ-AUDIT-146
//
// A record of a release newer than the catalogue's is kept aside, and one that is not a version too; the same release
// and older ones, prereleases included, are taken: the catalogue only grows within a major version (REQ-AUDIT-119).
func TestTheWriterRefusesARecordOfAReleaseNewerThanTheCatalogue(t *testing.T) {
	c := realChecker(t)
	c.release = "v2.3.0"
	var base exampleCase
	for _, ex := range exampleCases(t) {
		if ex.Name == "key.sign" {
			base = ex
		}
	}
	at := func(version string) *rejection {
		v, err := parseStrict([]byte(base.Expected))
		if err != nil {
			t.Fatal(err)
		}
		v.(map[string]any)["metadata"].(map[string]any)["product"].(map[string]any)["version"] = version
		_, rej := c.check(base.UID, "key@dev", canonical(t, v), 0)
		return rej
	}
	for _, v := range []string{"2.3.0", "2.2.9", "2.3.0-rc.1", "1.9.0", "2.3.0+build.5", "0.0.0-dev"} {
		if rej := at(v); rej != nil {
			t.Errorf("release %s: refused: %v", v, rej)
		}
	}
	for _, v := range []string{"2.3.1", "2.4.0", "3.0.0", "2.10.0", "not-a-version", "2.3", "v2.3.0"} {
		if rej := at(v); rej == nil || rej.Reason != reasonRelease || rej.Path != "metadata.product.version" {
			t.Errorf("release %s: rejection = %v, want release", v, rej)
		}
	}
}

// verifies: REQ-AUDIT-113, REQ-AUDIT-149
//
// The writer starts on no catalogue it cannot use: an action without its schema, a release that is no version, schemas
// that do not compile. It does not start and says which document, never a value.
func TestStartRefusesACatalogueItCannotUse(t *testing.T) {
	for name, edit := range map[string]func(*configv2alpha1.AuditCatalogue){
		"an action without its schema": func(c *configv2alpha1.AuditCatalogue) { c.Schemas = c.Schemas[:1] },
		"a release that is no version": func(c *configv2alpha1.AuditCatalogue) { c.Release = "latest" },
		"a short release":              func(c *configv2alpha1.AuditCatalogue) { c.Release = "1.2" },
		"a schema that is not JSON":    func(c *configv2alpha1.AuditCatalogue) { c.Schemas[1].Json = "{" },
		"a schema that does not compile": func(c *configv2alpha1.AuditCatalogue) {
			c.Schemas[1].Json = `{"type":"nonsense"}`
		},
		"no definitions document":            func(c *configv2alpha1.AuditCatalogue) { c.Schemas = c.Schemas[1:] },
		"a policy this writer does not read": func(c *configv2alpha1.AuditCatalogue) { c.Policy = audit.PolicyVersion + 1 },
		"no policy":                          func(c *configv2alpha1.AuditCatalogue) { c.Policy = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			c := openCatalogue("0.0.0", "key.sign", "store.start")
			edit(c)
			e.store.items["audit-catalogue"] = c
			if err := e.writer().Init(context.Background()); err == nil {
				t.Fatal("started on it")
			}
		})
	}
}

// verifies: REQ-AUDIT-146, REQ-AUDIT-149
//
// The releases the writer takes and refuses are the corpus store@ and the generator use: the release of a catalogue is read
// the same way in all three, and x/mod orders only what semver.org writes.
func TestTheWriterReadsReleasesAsTheSharedCorpusDoes(t *testing.T) {
	var f struct {
		Accept []string `json:"accept"`
		Reject []string `json:"reject"`
	}
	b, err := os.ReadFile("../../../../kits/conformance/audit/semver-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.Accept {
		if !releaseCovered("v999.0.0", s) {
			t.Errorf("record release %q refused by a catalogue of 999.0.0", s)
		}
	}
	for _, s := range f.Reject {
		if releaseCovered("v999.0.0", s) {
			t.Errorf("record release %q taken", s)
		}
	}
}

// verifies: REQ-AUDIT-113
//
// The backstop of validation is a retry and not a refusal: a validation that does not finish in time (a stalled clock, a CPU
// that a re-sync keeps busy) makes check answer `retry`, which is not a reason of any refusal; and after four timed-out
// validations still running the writer answers `retry` at once, without starting another.
//
// "At once" is asserted without a clock reading that a loaded runner can stretch: the budget is an hour for the records past
// the limit, so a check that starts a validation or waits for its budget cannot answer before the test gives up, and the
// number of validations started is counted.
func TestAValidationThatDoesNotFinishInTimeIsARetryAndNotARefusal(t *testing.T) {
	c := realChecker(t)
	release := make(chan struct{})
	defer close(release)
	var started atomic.Int32
	c.valid = func(string, []byte) error { started.Add(1); <-release; return nil } // a stalled clock: it never finishes until the test ends
	c.budget = 20 * time.Millisecond
	c.running = new(atomic.Int32)
	var base exampleCase
	for _, ex := range exampleCases(t) {
		if ex.Name == "key.sign" {
			base = ex
		}
	}
	for i := 0; i < maxStuck+3; i++ {
		want := "record"
		if i >= maxStuck {
			want = pathStuck // no validation was started: it is no attempt of the record
			c.budget = time.Hour
		}
		answered := make(chan *rejection, 1)
		go func() {
			_, rej := c.check(base.UID, "key@dev", []byte(base.Expected), 0)
			answered <- rej
		}()
		var rej *rejection
		select {
		case rej = <-answered:
		case <-time.After(10 * time.Second):
			t.Fatalf("record %d: no answer in 10 s, want at once (the stuck validations are at the limit, so none may be started or waited for)", i)
		}
		if rej == nil || rej.Reason != reasonRetry || rej.Path != want {
			t.Fatalf("record %d: rejection = %v, want retry at %s", i, rej, want)
		}
	}
	if n := c.running.Load(); n != maxStuck {
		t.Fatalf("%d validations still running, want %d", n, maxStuck)
	}
	// A validation goroutine may be scheduled late on a loaded machine: wait for the four, then count.
	for deadline := time.Now().Add(10 * time.Second); started.Load() < maxStuck && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if n := started.Load(); n != maxStuck {
		t.Fatalf("%d validations started, want %d (none after the limit)", n, maxStuck)
	}
}
