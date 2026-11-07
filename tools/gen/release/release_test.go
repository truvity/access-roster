package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const root = "../../.."

func discover(t *testing.T) []Exec {
	t.Helper()
	execs, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	return execs
}

// TestCommittedConfigIsWhatTheGeneratorMakes is the golden test: .goreleaser.yaml is exactly the output, so a new actor or
// driver is in the release or this test fails. `just release-gen` rewrites it.
func TestCommittedConfigIsWhatTheGeneratorMakes(t *testing.T) {
	got, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != Render(discover(t)) {
		t.Error(".goreleaser.yaml differs from the generator's output: run `just release-gen`")
	}
}

type goreleaser struct {
	Builds []struct {
		ID, Builder, Binary string
		Targets             []string
		Goarch              []string
		Env                 []string
		Flags               []string
	}
	Archives []struct {
		ID  string
		IDs []string
	}
}

func parsed(t *testing.T, cfg string) goreleaser {
	t.Helper()
	var g goreleaser
	if err := yaml.Unmarshal([]byte(cfg), &g); err != nil {
		t.Fatal(err)
	}
	return g
}

// TestEveryExecutableOfTheTreeIsBuiltAndArchivedOrIsNative: the sweep is not empty, every executable has a build and an
// archive of its own for both architectures, and the one that needs cgo is named as the native job's, not dropped.
func TestEveryExecutableOfTheTreeIsBuiltAndArchivedOrIsNative(t *testing.T) {
	execs := discover(t)
	if len(execs) < 10 {
		t.Fatalf("found %d executables: the sweep looks empty", len(execs))
	}
	g := parsed(t, Render(execs))
	builds := map[string]bool{}
	for _, b := range g.Builds {
		if builds[b.ID] {
			t.Errorf("build %s twice", b.ID)
		}
		builds[b.ID] = true
		switch b.Builder {
		case "go":
			if len(b.Goarch) != 2 {
				t.Errorf("%s: goarch %v, want amd64 and arm64", b.ID, b.Goarch)
			}
			if !contains(b.Env, "CGO_ENABLED=0") {
				t.Errorf("%s: a Go build of the release has CGO on", b.ID)
			}
		case "rust":
			if len(b.Targets) != 2 {
				t.Errorf("%s: targets %v, want two musl targets", b.ID, b.Targets)
			}
			if !contains(b.Flags, "--locked") {
				t.Errorf("%s: cargo may change Cargo.lock", b.ID)
			}
		default:
			t.Errorf("%s: builder %q", b.ID, b.Builder)
		}
	}
	archives := map[string]bool{}
	for _, a := range g.Archives {
		archives[a.ID] = true
		if len(a.IDs) != 1 || a.IDs[0] != a.ID {
			t.Errorf("archive %s takes %v", a.ID, a.IDs)
		}
	}
	native := 0
	for _, e := range execs {
		if e.Native() {
			native++
			if builds[e.Name()] || archives[e.Name()] {
				t.Errorf("%s needs cgo and is in the cross build", e.Dir)
			}
			continue
		}
		if !builds[e.Name()] || !archives[e.Name()] {
			t.Errorf("%s (%s) has no build or no archive", e.Dir, e.Name())
		}
	}
	if native != 1 {
		t.Errorf("%d native executables, want the card driver alone", native)
	}
	if len(builds) != len(execs)-native || len(archives) != len(builds) {
		t.Errorf("%d executables, %d native, %d builds, %d archives", len(execs), native, len(builds), len(archives))
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestNames(t *testing.T) {
	for _, c := range []struct{ dir, name, archive string }{
		{"actors/store", "actor-store", "sluis-actor-store"},
		{"actors/adapter-upstream-oidc", "actor-adapter-upstream-oidc", "sluis-actor-adapter-upstream-oidc"},
		{"drivers/store/rqlite", "driver-store-rqlite", "sluis-driver-store-rqlite"},
		{"drivers/key/yubikey-piv", "driver-key-yubikey-piv", "sluis-driver-key-yubikey-piv"},
		{"cli/sluis", "sluis", "sluis"},
	} {
		e := Exec{Dir: c.dir}
		if e.Name() != c.name || e.ArchiveName() != c.archive {
			t.Errorf("%s: name %s, archive %s; want %s, %s", c.dir, e.Name(), e.ArchiveName(), c.name, c.archive)
		}
	}
}

func TestParsers(t *testing.T) {
	g, err := parseGoList(modulePath + "/actors/key\n" + modulePath + "/cli/sluis\n\n")
	if err != nil || len(g) != 2 || g[0].Dir != "actors/key" || g[0].Bin != "key" {
		t.Fatalf("parseGoList = %v, %v", g, err)
	}
	for _, bad := range []string{modulePath + "/kits/go/x", "example.com/actors/key", modulePath + "/drivers/key"} {
		if _, err := parseGoList(bad); err == nil {
			t.Errorf("parseGoList accepted %q", bad)
		}
	}
	meta := `{"packages":[
	  {"name":"store","manifest_path":"/r/actors/store/Cargo.toml","targets":[{"name":"store","kind":["bin"]},{"name":"store","kind":["lib"]}]},
	  {"name":"kit","manifest_path":"/r/kits/rust/kit/Cargo.toml","targets":[{"name":"kit","kind":["lib"]},{"name":"tool","kind":["bin"]}]},
	  {"name":"lib-only","manifest_path":"/r/actors/lib/Cargo.toml","targets":[{"name":"lib-only","kind":["lib"]}]}]}`
	r, err := parseCargoMetadata([]byte(meta), "/r")
	if err != nil || len(r) != 1 || r[0].Dir != "actors/store" || r[0].Pkg != "store" || r[0].Bin != "store" {
		t.Fatalf("parseCargoMetadata = %v, %v", r, err)
	}
	two := `{"packages":[{"name":"x","manifest_path":"/r/actors/x/Cargo.toml","targets":[{"name":"a","kind":["bin"]},{"name":"b","kind":["bin"]}]}]}`
	if _, err := parseCargoMetadata([]byte(two), "/r"); err == nil {
		t.Error("two binaries in one directory were accepted")
	}
	n, err := parseNativeList("# c\n\ndrivers/key/yubikey-piv\tsluis_card\n")
	if err != nil || n["drivers/key/yubikey-piv"] != "sluis_card" {
		t.Fatalf("parseNativeList = %v, %v", n, err)
	}
	if _, err := parseNativeList("drivers/key/yubikey-piv sluis_card\n"); err == nil {
		t.Error("a native.list line without a tab was accepted")
	}
}

func TestCombineRefusesWhatWouldShipTheWrongThing(t *testing.T) {
	goE := []Exec{{Dir: "actors/key", Lang: "go", Bin: "key"}}
	rustE := []Exec{{Dir: "actors/store", Lang: "rust", Bin: "store", Pkg: "store"}}
	if _, err := Combine(goE, rustE, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Combine(goE, []Exec{{Dir: "actors/key", Lang: "rust"}}, nil); err == nil {
		t.Error("one directory, two languages, accepted")
	}
	if _, err := Combine(goE, rustE, map[string]string{"actors/gone": "tag"}); err == nil {
		t.Error("a native.list entry that names nothing was accepted: the card driver could vanish from the release unseen")
	}
	if _, err := Combine(goE, rustE, map[string]string{"actors/store": "tag"}); err == nil {
		t.Error("a Rust executable in native.list was accepted")
	}
	if _, err := Combine(nil, nil, nil); err == nil {
		t.Error("an empty release was accepted")
	}
	if !strings.Contains(Render([]Exec{{Dir: "actors/key", Lang: "go", Bin: "key", Tags: "t"}}), "builds:\n\narchives:") {
		t.Error("a native executable is in the cross build")
	}
}
