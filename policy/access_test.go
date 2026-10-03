package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/access-roster/policy"
)

// canonical writes a policy the way a reader sees it, so that two
// policies that differ only in an empty list versus an absent one (which
// the loader treats alike) compare equal, and nothing else does.
func canonical(t *testing.T, p policy.Policy) any {
	t.Helper()
	raw, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAccessDocumentEqualsTheHandWrittenReshaping is the golden for the
// reshaping this package took over: helm-rendered.yaml is the output of
// the Helm loops an installation used to carry for the same content, and
// the document must produce a policy that reads the same.
func TestAccessDocumentEqualsTheHandWrittenReshaping(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "access", "access.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !policy.IsAccessDocument(data) {
		t.Fatal("the fixture is not recognised as an access document")
	}
	got, err := policy.ParseAccess(data)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "access", "helm-rendered.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["version"] = 1
	raw, err = yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := policy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	gotC, wantC := canonical(t, got), canonical(t, want)
	gotY, _ := yaml.Marshal(gotC)
	wantY, _ := yaml.Marshal(wantC)
	if string(gotY) != string(wantY) {
		t.Errorf("the access document does not produce the hand-written policy.\n--- got\n%s\n--- want\n%s", gotY, wantY)
	}
}

// A directory load reads an access document beside ordinary layers, and
// a group declared by both is refused like any other clash.
func TestLoadDeclaredReadsAnAccessDocument(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "access", "access.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "access.yaml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := policy.LoadDeclared(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Groups) == 0 || len(loaded.Clients) == 0 {
		t.Fatalf("the access document was not read: %d groups, %d clients", len(loaded.Groups), len(loaded.Clients))
	}

	clash := "version: 1\ngroups:\n  \"alpha:k8s:admin\": {}\n"
	if err = os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(clash), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = policy.LoadDeclared(dir); err == nil {
		t.Fatal("a group declared by an access document and by a layer was accepted")
	}
}

func TestAccessDocumentRefusals(t *testing.T) {
	t.Parallel()

	for name, doc := range map[string]string{
		"unknown key":           "access:\n  groop: []\n",
		"group twice":           "access:\n  groups:\n    - name: a:b:c\n    - name: a:b:c\n",
		"overlay client clash":  "access:\n  clients:\n    - {name: x, kind: public}\noverlay:\n  clients:\n    x: {kind: public}\n",
		"person twice":          "access:\n  people:\n    - name: p\n    - name: p\n",
		"unknown matcher field": "access:\n  groups:\n    - name: a:b:c\n      github:\n        - {repo: x}\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := policy.ParseAccess([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// An overlay matcher is appended after what the matrix derived, and a
// group the matrix never produced is created for it.
func TestOverlayAppendsAndCreates(t *testing.T) {
	t.Parallel()

	got, err := policy.ParseAccess([]byte(`
access:
  groups:
    - name: a:b:c
      emails: [x@example.com]
overlay:
  groups:
    a:b:c:
      matchers: [{email_domain: example.com}]
    d:e:f:
      matchers: [{email: y@example.com}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if m := got.Groups["a:b:c"].Matchers; len(m) != 2 || m[0].Email != "x@example.com" || m[1].EmailDomain != "example.com" {
		t.Errorf("a:b:c matchers = %+v", m)
	}
	if m := got.Groups["d:e:f"].Matchers; len(m) != 1 || m[0].Email != "y@example.com" {
		t.Errorf("d:e:f matchers = %+v", m)
	}
}
