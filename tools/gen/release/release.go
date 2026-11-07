// Package main generates .goreleaser.yaml from the tree: one build and one archive per executable below actors/,
// drivers/ and cli/, for amd64 and arm64 (ADR 0013, "One version"). The list of executables is found, not written, so a new
// actor or driver joins the release when it merges and a test fails while the committed file differs.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strings"
	"text/template"
)

// modulePath is the main Go module (ADR 0013: the path ends in /v2).
const modulePath = "github.com/truvity/sluis/v2"

// versionVar is the Go variable the release build stamps (kits/go/version).
const versionVar = modulePath + "/kits/go/version.Version"

// Exec is one executable of the release.
type Exec struct {
	Dir  string // below the repository root: actors/store, drivers/store/rqlite, cli/sluis
	Lang string // "go" or "rust"
	Bin  string // the name of the file the build makes (the Cargo bin name, or the last element of Dir)
	Pkg  string // the Cargo package, for a Rust executable
	Tags string // the Go build tags the executable needs, and so a native build (deploy/boards/native.list)
}

// Native is true for an executable that links a C library: a cross-compile with CGO off cannot make it, and a card driver
// built that way could not open a card. It is built in the native job of the release (ADR 0013), not by this file.
func (e Exec) Native() bool { return e.Tags != "" }

// Kind is the kind of the executable in an artifact name: actor, driver or cli.
func (e Exec) Kind() string {
	switch {
	case strings.HasPrefix(e.Dir, "actors/"):
		return "actor"
	case strings.HasPrefix(e.Dir, "drivers/"):
		return "driver"
	default:
		return "cli"
	}
}

// Name is the name of the executable in an artifact: the kind and the registry name, as images are named (actor-store,
// driver-store-rqlite). The command-line tool is the one exception, sluis, because it is no actor or driver.
func (e Exec) Name() string {
	switch e.Kind() {
	case "actor":
		return "actor-" + path.Base(e.Dir)
	case "driver":
		return "driver-" + strings.ReplaceAll(strings.TrimPrefix(e.Dir, "drivers/"), "/", "-")
	default:
		return path.Base(e.Dir)
	}
}

// ArchiveName is the name of the archive of the executable, without the version, the OS and the architecture.
func (e Exec) ArchiveName() string {
	if e.Kind() == "cli" {
		return e.Name()
	}
	return "sluis-" + e.Name()
}

// valid says whether a directory is where an executable may be.
func valid(dir string) bool {
	return strings.HasPrefix(dir, "actors/") || strings.HasPrefix(dir, "cli/") || (strings.HasPrefix(dir, "drivers/") && strings.Count(dir, "/") == 2)
}

// parseGoList reads the output of
//
//	go list -f '{{if eq .Name "main"}}{{.ImportPath}}{{end}}' ./actors/... ./drivers/... ./cli/...
func parseGoList(out string) ([]Exec, error) {
	var res []Exec
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		dir, ok := strings.CutPrefix(l, modulePath+"/")
		if !ok || !valid(dir) {
			return nil, fmt.Errorf("go list: %q is not a package of the main module below actors/, drivers/ or cli/", l)
		}
		res = append(res, Exec{Dir: dir, Lang: "go", Bin: path.Base(dir)})
	}
	return res, nil
}

type cargoMeta struct {
	Packages []struct {
		Name         string `json:"name"`
		ManifestPath string `json:"manifest_path"`
		Targets      []struct {
			Name string   `json:"name"`
			Kind []string `json:"kind"`
		} `json:"targets"`
	} `json:"packages"`
}

// parseCargoMetadata reads the output of `cargo metadata --format-version 1 --no-deps`: every package below actors/,
// drivers/ or cli/ that has a binary target. root is the repository root, with no trailing slash.
func parseCargoMetadata(raw []byte, root string) ([]Exec, error) {
	var m cargoMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("cargo metadata: %w", err)
	}
	var res []Exec
	for _, p := range m.Packages {
		dir, ok := strings.CutPrefix(path.Dir(p.ManifestPath), root+"/")
		if !ok || !valid(dir) {
			continue
		}
		var bins []string
		for _, t := range p.Targets {
			for _, k := range t.Kind {
				if k == "bin" {
					bins = append(bins, t.Name)
				}
			}
		}
		switch len(bins) {
		case 0:
			continue
		case 1:
			res = append(res, Exec{Dir: dir, Lang: "rust", Bin: bins[0], Pkg: p.Name})
		default:
			return nil, fmt.Errorf("%s has %d binaries (%s): one directory is one executable", dir, len(bins), strings.Join(bins, ", "))
		}
	}
	return res, nil
}

// parseNativeList reads deploy/boards/native.list: the package and the Go build tags, separated by a tab.
func parseNativeList(raw string) (map[string]string, error) {
	res := map[string]string{}
	for _, l := range strings.Split(raw, "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 2 || f[0] == "" || f[1] == "" {
			return nil, fmt.Errorf("native.list: %q is not <package><tab><tags>", l)
		}
		res[f[0]] = f[1]
	}
	return res, nil
}

// Combine joins the Go and Rust executables, marks the native ones and sorts them by directory. A directory that holds two
// executables, a native entry that names no executable, and an empty result are errors.
func Combine(goExecs, rustExecs []Exec, native map[string]string) ([]Exec, error) {
	seen := map[string]bool{}
	var all []Exec
	for _, e := range append(append([]Exec{}, goExecs...), rustExecs...) {
		if seen[e.Dir] {
			return nil, fmt.Errorf("%s is both a Go and a Rust executable", e.Dir)
		}
		seen[e.Dir] = true
		if tags, ok := native[e.Dir]; ok {
			if e.Lang != "go" {
				return nil, fmt.Errorf("native.list names %s, which is not a Go executable", e.Dir)
			}
			e.Tags = tags
		}
		all = append(all, e)
	}
	for dir := range native {
		if !seen[dir] {
			return nil, fmt.Errorf("native.list names %s, which is no executable of the tree", dir)
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no executable found below actors/, drivers/ or cli/: an empty release is a failure")
	}
	names := map[string]string{}
	for _, e := range all {
		if other, dup := names[e.Name()]; dup {
			return nil, fmt.Errorf("%s and %s are both named %s", other, e.Dir, e.Name())
		}
		names[e.Name()] = e.Dir
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Dir < all[j].Dir })
	return all, nil
}

// Discover finds the executables of the tree at root by asking the Go and the Cargo tools, which build.sh asks too.
func Discover(root string) ([]Exec, error) {
	run := func(name string, args ...string) ([]byte, error) {
		c := exec.Command(name, args...) //nolint:gosec // go and cargo, with arguments written in this file
		c.Dir = root
		var stderr bytes.Buffer
		c.Stderr = &stderr
		out, err := c.Output()
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
	gl, err := run("go", "list", "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./actors/...", "./drivers/...", "./cli/...")
	if err != nil {
		return nil, err
	}
	goExecs, err := parseGoList(string(gl))
	if err != nil {
		return nil, err
	}
	meta, err := run("cargo", "metadata", "--format-version", "1", "--no-deps", "--locked")
	if err != nil {
		return nil, err
	}
	rustExecs, err := parseCargoMetadata(meta, absRoot(root))
	if err != nil {
		return nil, err
	}
	nl, err := readFile(root, "deploy/boards/native.list")
	if err != nil {
		return nil, err
	}
	native, err := parseNativeList(nl)
	if err != nil {
		return nil, err
	}
	return Combine(goExecs, rustExecs, native)
}

var rustTargets = []string{"x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"}

const header = `# Generated by tools/gen/release from the tree (go list, cargo metadata, deploy/boards/native.list).
# Do not edit: run ` + "`just release-gen`" + `.
#
# One build and one archive per executable of actors/, drivers/ and cli/, for linux on amd64 and arm64 (ADR 0013,
# "One version"): Go with CGO off, Rust through cargo-zigbuild to static musl, both stamped with the release version.
# The executables that link a C library (deploy/boards/native.list) are not here: they are built in the native job.
# A dry run needs no tag and publishes nothing: ` + "`just release-snapshot`" + `.
`

const preamble = `version: 2
project_name: sluis
dist: dist/release
report_sizes: true

# The release notes are the CHANGELOG, written by hand (docs/contributing/workflow.md).
changelog:
  disable: true

# A dry run: the version is the tag-like version of GORELEASER_CURRENT_TAG and the commit.
snapshot:
  version_template: "{{ .Version }}-snapshot.{{ .ShortCommit }}"

# Pre-release for every v2.0.0-alpha.N (ADR 0013); nothing is stable before v2.0.0.
release:
  prerelease: auto
  draft: false
`

// Render writes the configuration for the executables.
func Render(execs []Exec) string {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString(preamble)
	var built []Exec
	for _, e := range execs {
		if !e.Native() {
			built = append(built, e)
		}
	}
	b.WriteString("\nbuilds:\n")
	for _, e := range built {
		if err := buildTmpl.Execute(&b, e); err != nil {
			panic(err)
		}
	}
	b.WriteString("\narchives:\n")
	for _, e := range built {
		if err := archiveTmpl.Execute(&b, e); err != nil {
			panic(err)
		}
	}
	b.WriteString(footer)
	return b.String()
}

func tmpl(name, s string) *template.Template {
	return template.Must(template.New(name).Funcs(template.FuncMap{"targets": func() []string { return rustTargets }}).Parse(s))
}

var buildTmpl = tmpl("build", `  - id: {{ .Name }}
{{- if eq .Lang "go" }}
    builder: go
    main: ./{{ .Dir }}
    binary: {{ .Bin }}
    goos: [linux]
    goarch: [amd64, arm64]
    env: [CGO_ENABLED=0]
    flags: [-trimpath]
    ldflags: ["-s -w -X `+versionVar+`={{"{{ .Version }}"}}"]
    mod_timestamp: "{{"{{ .CommitTimestamp }}"}}"
{{- else }}
    builder: rust
    dir: .
    binary: {{ .Bin }}
    tool: cargo
    command: zigbuild
    flags: [--release, --locked, --package={{ .Pkg }}]
    env: ["SLUIS_VERSION={{"{{ .Version }}"}}"]
    targets: [{{ range $i, $t := targets }}{{ if $i }}, {{ end }}{{ $t }}{{ end }}]
{{- end }}
`)

var archiveTmpl = tmpl("archive", `  - id: {{ .Name }}
    ids: [{{ .Name }}]
    formats: [tar.gz]
    name_template: "{{ .ArchiveName }}_{{"{{ .Version }}"}}_{{"{{ .Os }}"}}_{{"{{ .Arch }}"}}"
    files: [LICENSE]
`)

// footer: the checksums. SHA256SUMS lists every archive; the .sha256 beside each archive is made by the step below, which
// GoReleaser calls a signature only because that is the stage that makes one file per artifact: it signs nothing.
const footer = `
# SHA256SUMS over every archive. A .sha256 beside each archive follows (ADR 0013, "Signing and checksums").
checksum:
  name_template: SHA256SUMS
  algorithm: sha256

signs:
  - id: sha256-each
    artifacts: archive
    cmd: tools/release/sha256-each.sh
    args: ["${artifact}", "${signature}"]
    signature: "${artifact}.sha256"
    output: false
`
