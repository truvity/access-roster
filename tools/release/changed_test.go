package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

const metaFixture = `{"workspace_root":"/r","packages":[
 {"name":"store","manifest_path":"/r/actors/store/Cargo.toml","targets":[{"kind":["bin"]},{"kind":["lib"]}]},
 {"name":"entry","manifest_path":"/r/actors/entry/Cargo.toml","targets":[{"kind":["bin"]}]},
 {"name":"sluis-driver-indexer-fs","manifest_path":"/r/drivers/indexer/fs/Cargo.toml","targets":[{"kind":["bin"]}]},
 {"name":"sluis-store","manifest_path":"/r/kits/rust/sluis-store/Cargo.toml","targets":[{"kind":["lib"]}]}]}`

func TestChangedRustPackages(t *testing.T) {
	for name, c := range map[string]struct {
		changed []string
		want    []string
	}{
		"one actor":                   {[]string{"actors/store/src/main.rs"}, []string{"store"}},
		"a driver":                    {[]string{"drivers/indexer/fs/src/lib.rs", "docs/a.md"}, []string{"sluis-driver-indexer-fs"}},
		"two":                         {[]string{"actors/entry/Cargo.toml", "actors/store/x.rs"}, []string{"entry", "store"}},
		"a kit":                       {[]string{"kits/rust/sluis-store/src/lib.rs"}, []string{"entry", "sluis-driver-indexer-fs", "store"}},
		"the lock file":               {[]string{"Cargo.lock"}, []string{"entry", "sluis-driver-indexer-fs", "store"}},
		"the toolchain":               {[]string{"rust-toolchain.toml"}, []string{"entry", "sluis-driver-indexer-fs", "store"}},
		"the cargo config":            {[]string{".cargo/config.toml"}, []string{"entry", "sluis-driver-indexer-fs", "store"}},
		"nothing of rust":             {[]string{"docs/a.md", "actors/storex/main.go"}, nil},
		"a prefix is not a directory": {[]string{"actors/store-other/src/main.rs"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ChangedRustPackages([]byte(metaFixture), "/r", c.changed)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
	if _, err := ChangedRustPackages([]byte(`{"packages":[]}`), "/r", []string{"Cargo.lock"}); err == nil {
		t.Error("an empty sweep was accepted")
	}
	if _, err := ChangedRustPackages([]byte(`{`), "/r", nil); err == nil {
		t.Error("broken metadata was accepted")
	}
}

// The release job refuses a build that names another commit than the tag's: the check is in the recipe, so the test reads it.
func TestThePublishRecipeComparesTheBuildsCommitWithTheTags(t *testing.T) {
	raw, err := os.ReadFile("../../Justfile")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, publishHeader)
	if i < 0 {
		t.Fatal("no recipe release-publish")
	}
	rest := s[i:]
	if j := strings.Index(rest, "\n# "); j > 0 && strings.Contains(rest[:j], "check-dist") {
		rest = rest[:j]
	}
	if !strings.Contains(rest, `jq -r .commit "$dist/metadata.json"`) || !strings.Contains(rest, `"$commit" = "${GITHUB_SHA:?`) {
		t.Error("release-publish does not compare the commit of metadata.json with GITHUB_SHA")
	}
	if strings.Index(rest, `"$commit" = "${GITHUB_SHA`) > strings.Index(rest, "publish-images") {
		t.Error("the commit is compared after the images are pushed")
	}
}
