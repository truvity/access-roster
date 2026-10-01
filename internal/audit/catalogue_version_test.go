package audit_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// An audit installation keeps every catalogue version it was sent and refuses
// a different document under a version it already holds, which stops the
// service at start. So a released version is frozen: testdata/released holds
// the document of each version that shipped, and a catalogue carrying one of
// those versions must equal it. Changing an action means bumping the version
// in roster.yaml AND adding roster-<version>.yaml here.
func TestAReleasedCatalogueVersionIsNeverChanged(t *testing.T) {
	read := func(path string) (string, any) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		version, _ := doc["version"].(string)
		if version == "" {
			t.Fatalf("%s: no version", path)
		}
		return version, doc
	}

	current, currentDoc := read(filepath.Join("catalogue", "roster.yaml"))

	fixtures, err := filepath.Glob(filepath.Join("catalogue", "testdata", "released", "roster-*.yaml"))
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("no released fixtures found (err %v)", err)
	}
	seen := false
	for _, fixture := range fixtures {
		version, doc := read(fixture)
		if want := "roster-" + version + ".yaml"; filepath.Base(fixture) != want {
			t.Errorf("%s declares version %s; it should be named %s", fixture, version, want)
		}
		if version != current {
			continue
		}
		seen = true
		if !reflect.DeepEqual(doc, currentDoc) {
			t.Errorf("catalogue version %s was released as %s and roster.yaml now differs from it: "+
				"bump `version` in roster.yaml and add testdata/released/roster-<new version>.yaml", current, fixture)
		}
	}
	_ = seen // a version with no fixture is new: it is not yet released
	if strings.TrimSpace(current) == "" {
		t.Fatal("empty catalogue version")
	}
}
