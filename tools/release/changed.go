package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// ChangedRustPackages returns the Cargo packages with a binary that a change can affect: those whose directory holds a changed
// file, and all of them when the change is to something every package shares (the lock file, the root manifest, the toolchain, the
// cargo configuration, or a crate below kits/rust). meta is `cargo metadata --format-version 1 --no-deps`; root is the workspace
// root with no trailing slash; changed are the paths of the change relative to it.
//
// The release builds each executable alone (`cargo zigbuild --package P`), so Cargo resolves the features of P without the
// features that a sibling would add. The jobs that build the whole workspace in one run unify them, and a change that compiles
// only through a sibling's feature would pass those and fail the release. `cargo check --package P` for the packages this
// returns finds it at the cost of one check each.
func ChangedRustPackages(meta []byte, root string, changed []string) ([]string, error) {
	var m cargoMetadata
	if err := json.Unmarshal(meta, &m); err != nil {
		return nil, fmt.Errorf("cargo metadata: %w", err)
	}
	type pkg struct{ name, dir string }
	var bins []pkg
	for _, p := range m.Packages {
		dir, ok := strings.CutPrefix(path.Dir(p.ManifestPath), root+"/")
		if !ok {
			continue
		}
		for _, t := range p.Targets {
			if contains(t.Kind, "bin") {
				bins = append(bins, pkg{p.Name, dir})
				break
			}
		}
	}
	if len(bins) == 0 {
		return nil, fmt.Errorf("cargo metadata lists no package with a binary: an empty sweep is a failure")
	}
	all := false
	for _, f := range changed {
		switch {
		case f == "Cargo.lock", f == "Cargo.toml", f == "rust-toolchain.toml", strings.HasPrefix(f, ".cargo/"), strings.HasPrefix(f, "kits/rust/"):
			all = true
		}
	}
	set := map[string]bool{}
	for _, b := range bins {
		if all {
			set[b.name] = true
			continue
		}
		for _, f := range changed {
			if strings.HasPrefix(f, b.dir+"/") {
				set[b.name] = true
			}
		}
	}
	var out []string
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

type cargoMetadata struct {
	Packages []struct {
		Name         string `json:"name"`
		ManifestPath string `json:"manifest_path"`
		Targets      []struct {
			Kind []string `json:"kind"`
		} `json:"targets"`
	} `json:"packages"`
	WorkspaceRoot string `json:"workspace_root"`
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// RustChanged runs cargo and git in the current directory and returns ChangedRustPackages for the change since base.
func RustChanged(base string) ([]string, error) {
	meta, err := exec.Command("cargo", "metadata", "--format-version", "1", "--no-deps", "--locked").Output()
	if err != nil {
		return nil, fmt.Errorf("cargo metadata: %w", err)
	}
	var m cargoMetadata
	if err := json.Unmarshal(meta, &m); err != nil {
		return nil, err
	}
	diff, err := exec.Command("git", "diff", "--no-renames", "--name-only", "--end-of-options", base, "HEAD").Output() //nolint:gosec // git, with the base of the change
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	var changed []string
	for _, l := range strings.Split(strings.TrimSpace(string(diff)), "\n") {
		if l != "" {
			changed = append(changed, l)
		}
	}
	return ChangedRustPackages(meta, m.WorkspaceRoot, changed)
}
