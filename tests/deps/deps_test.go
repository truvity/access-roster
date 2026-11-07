// Package deps holds the dependency checks of the work actors: what an executable links is what it contains (ADR 0002,
// "Work actors"). The Go executables are read with `go list -deps`, the Rust ones with `cargo metadata`, from the
// registry's list of work actors, so a new work actor is swept without an edit here.
package deps

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

const module = "github.com/truvity/sluis/v2"

// root is the repository, from this package's directory.
const root = "../.."

type workActor struct {
	name string
	rust bool
}

// workActors are the work actors of the registry that have code in actors/: a Cargo.toml for Rust, a main.go for Go.
func workActors(t *testing.T) []workActor {
	t.Helper()
	var out []workActor
	for _, a := range registry.Actors() {
		if a.Family != "work" {
			continue
		}
		dir := filepath.Join(root, "actors", a.Name)
		switch {
		case exists(filepath.Join(dir, "Cargo.toml")):
			out = append(out, workActor{a.Name, true})
		case exists(filepath.Join(dir, "main.go")):
			out = append(out, workActor{a.Name, false})
		}
	}
	return out
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// ---- Go

func goDeps(t *testing.T, pattern string) []string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is not on PATH: %v", err)
	}
	cmd := exec.Command(goBin, "list", "-deps", "-f", "{{.ImportPath}}", pattern) // #nosec G204 -- a fixed command; the pattern is from the registry
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pattern, err, stderr.String())
	}
	return strings.Fields(string(out))
}

// The ports of the drivers: the item port (the engines), the blob, index and key store ports, and the source port (the
// config source and the secret source). A work actor has none of them: it reaches data through the store service and keys
// through the key service. The transport port is the audit-emit port that every actor has.
var driverPorts = []string{"item", "blob", "index", "keystore", "source"}

// Libraries that read configuration or secrets from a place, watch a file for it, or speak to an engine or a secret
// store. A work actor reads its configuration as kinds through the store service, so it needs none of them.
var goForbiddenLibs = []string{
	"github.com/spf13/viper", "github.com/knadh/koanf", "github.com/kelseyhightower/envconfig", "github.com/joho/godotenv",
	"github.com/caarlos0/env", "github.com/ilyakaznacheev/cleanenv", "github.com/fsnotify/fsnotify",
	"github.com/hashicorp/vault", "github.com/openbao", "github.com/hashicorp/consul", "go.etcd.io",
	"github.com/aws/aws-sdk-go", "cloud.google.com/go/secretmanager", "github.com/Azure/azure-sdk-for-go",
	"github.com/mattn/go-sqlite3", "modernc.org/sqlite", "github.com/rqlite", "github.com/jackc/pgx", "github.com/lib/pq",
}

// goForbidden says why a work actor may not link the package, or "".
func goForbidden(actor, imp string) string {
	rel, ok := strings.CutPrefix(imp, module+"/")
	if ok {
		switch {
		case strings.HasPrefix(rel, "drivers/"):
			return "a driver"
		case strings.HasPrefix(rel, "actors/") && rel != "actors/"+actor && !strings.HasPrefix(rel, "actors/"+actor+"/"):
			return "another actor's code"
		}
		for _, p := range driverPorts {
			if rel == "gen/go/sluis/port/"+p || strings.HasPrefix(rel, "gen/go/sluis/port/"+p+"/") {
				return "the " + p + " port of the drivers"
			}
		}
		return ""
	}
	for _, lib := range goForbiddenLibs {
		if imp == lib || strings.HasPrefix(imp, lib+"/") {
			return "a configuration, secret or engine library"
		}
	}
	return ""
}

// ---- Rust

type rustPackage struct {
	ID, Name, Source string
	ManifestPath     string `json:"manifest_path"`
}

type rustGraph struct {
	pkgs   map[string]rustPackage // by id
	deps   map[string][]string    // normal dependencies, by id
	byName map[string]string      // id by name, for the workspace's own packages
}

// cargoGraph reads the dependency graph of the workspace, or skips (outside CI) when cargo is not here.
func cargoGraph(t *testing.T) rustGraph {
	t.Helper()
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("cargo is not on PATH in CI: %v", err)
		}
		t.Skip("SKIP: cargo is not on PATH")
	}
	cmd := exec.Command(cargo, "metadata", "--format-version", "1", "--locked", "--offline") // #nosec G204 -- a fixed command
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cargo metadata: %v\n%s", err, stderr.String())
	}
	var m struct {
		Packages []rustPackage `json:"packages"`
		Resolve  struct {
			Nodes []struct {
				ID   string `json:"id"`
				Deps []struct {
					Pkg      string `json:"pkg"`
					DepKinds []struct {
						Kind *string `json:"kind"`
					} `json:"dep_kinds"`
				} `json:"deps"`
			} `json:"nodes"`
		} `json:"resolve"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("cargo metadata: %v", err)
	}
	g := rustGraph{pkgs: map[string]rustPackage{}, deps: map[string][]string{}, byName: map[string]string{}}
	for _, p := range m.Packages {
		g.pkgs[p.ID] = p
		if p.Source == "" {
			g.byName[p.Name] = p.ID
		}
	}
	for _, n := range m.Resolve.Nodes {
		for _, d := range n.Deps {
			for _, k := range d.DepKinds {
				// A normal dependency is linked; a dev-dependency is for the tests and a build one runs at build time.
				if k.Kind == nil {
					g.deps[n.ID] = append(g.deps[n.ID], d.Pkg)
					break
				}
			}
		}
	}
	if len(g.pkgs) < 50 || len(g.byName) < 10 {
		t.Fatalf("cargo metadata found %d packages, %d of the workspace: an empty sweep checks nothing", len(g.pkgs), len(g.byName))
	}
	return g
}

// closure is the package and everything it links, sorted by name.
func (g rustGraph) closure(t *testing.T, name string) []rustPackage {
	t.Helper()
	start, ok := g.byName[name]
	if !ok {
		t.Fatalf("no package %s in the workspace", name)
	}
	seen := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, d := range g.deps[id] {
			if !seen[d] {
				seen[d] = true
				queue = append(queue, d)
			}
		}
	}
	var out []rustPackage
	for id := range seen {
		out = append(out, g.pkgs[id])
	}
	slices.SortFunc(out, func(a, b rustPackage) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// dir is the package's directory below the repository, or "" for a package from a registry.
func (g rustGraph) dir(p rustPackage) string {
	if p.Source != "" {
		return ""
	}
	abs, _ := filepath.Abs(root)
	rel, err := filepath.Rel(abs, filepath.Dir(p.ManifestPath))
	if err != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}

var rustForbiddenLibs = []string{
	"config", "figment", "dotenvy", "dotenv", "envy", "notify", "aws-config", "vaultrs", "keyring",
	"rusqlite", "sqlx", "diesel", "rqlite", "redis", "tokio-postgres",
}

// rustForbidden says why a work actor may not link the package, or "".
func (g rustGraph) rustForbidden(actor string, p rustPackage) string {
	if d := g.dir(p); d != "" {
		switch {
		case strings.HasPrefix(d, "drivers/"):
			return "a driver"
		case strings.HasPrefix(d, "actors/") && d != "actors/"+actor:
			return "another actor's code (the configuration loader is store@'s)"
		case d == "kits/rust/sluis-conformance":
			return "the engines of the port suite"
		}
		return ""
	}
	if slices.Contains(rustForbiddenLibs, p.Name) || strings.HasPrefix(p.Name, "aws-sdk-") || strings.HasPrefix(p.Name, "rusoto") {
		return "a configuration, secret or engine library"
	}
	return ""
}

// rustSources are the .rs files below dir, by path, read through a file system rooted at dir.
func rustSources(dir string) (map[string]string, error) {
	out := map[string]string{}
	fsys := os.DirFS(dir)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".rs") {
			return err
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		out[filepath.Join(dir, path)] = string(b)
		return nil
	})
	return out, err
}

// ---- the checks

// A work actor's executable links no configuration loader, no secret source and no driver: none of the packages it
// links is a driver, another actor's code (store@'s loader is in the store actor), a port of the drivers, or a library
// that loads configuration or secrets or speaks to an engine. What it does read, through the store service, is the signed
// documents that store@ gives it, which `kits/go/signedconfig` verifies: that is a verifier, and the loader that reads a
// source and holds a snapshot is not in the kit.
//
// Each sweep has a control: the same matcher is run over the closure of a driver and of the store actor, and must find
// what it is looking for.
//
// verifies: REQ-ISO-087
func TestWorkActorsLinkNoConfigSourceSecretSourceOrDriver(t *testing.T) {
	actors := workActors(t)
	if len(actors) < 6 {
		t.Fatalf("only %d work actors with code: %v", len(actors), actors)
	}

	t.Run("go", func(t *testing.T) {
		checked := 0
		for _, a := range actors {
			if a.rust {
				continue
			}
			checked++
			deps := goDeps(t, "./actors/"+a.name+"/...")
			if len(deps) < 100 {
				t.Fatalf("%s: go list found %d packages", a.name, len(deps))
			}
			for _, imp := range deps {
				if why := goForbidden(a.name, imp); why != "" {
					t.Errorf("%s links %s: %s", a.name, imp, why)
				}
			}
		}
		if checked < 3 {
			t.Fatalf("only %d Go work actors checked", checked)
		}
		// The control: a driver's closure holds a driver, and the matcher says so.
		var found bool
		for _, imp := range goDeps(t, "./drivers/key/software/...") {
			found = found || goForbidden("session", imp) == "a driver"
		}
		if !found {
			t.Error("the control failed: the matcher did not find a driver in the closure of a driver")
		}
		if goForbidden("session", "github.com/spf13/viper/internal") == "" || goForbidden("session", module+"/actors/key/internal/keyd") == "" ||
			goForbidden("session", module+"/gen/go/sluis/port/item/v2alpha1") == "" {
			t.Error("the control failed: the matcher let a known case through")
		}
		if goForbidden("session", module+"/actors/session/internal/sessiond") != "" || goForbidden("session", module+"/gen/go/sluis/port/transport/v2alpha1") != "" {
			t.Error("the matcher refuses what a work actor has")
		}
	})

	t.Run("rust", func(t *testing.T) {
		g := cargoGraph(t)
		checked := 0
		for _, a := range actors {
			if !a.rust {
				continue
			}
			checked++
			closure := g.closure(t, a.name)
			if len(closure) < 50 {
				t.Fatalf("%s: %d packages in the closure", a.name, len(closure))
			}
			for _, p := range closure {
				if why := g.rustForbidden(a.name, p); why != "" {
					t.Errorf("%s links %s (%s): %s", a.name, p.Name, g.dir(p), why)
				}
			}
		}
		if checked < 3 {
			t.Fatalf("only %d Rust work actors checked", checked)
		}
		// The control: the store actor is the loader, and a work actor that linked it would be flagged.
		var flagged []string
		for _, p := range g.closure(t, "store") {
			if g.rustForbidden("entry", p) != "" {
				flagged = append(flagged, p.Name)
			}
		}
		if !slices.Contains(flagged, "store") {
			t.Errorf("the control failed: the matcher did not flag the store actor (flagged %v)", flagged)
		}
	})
}

// Crates that load code at run time: a dynamic loader, a plugin framework, a script or WebAssembly engine, or a runtime
// that embeds a language.
var rustLoaders = []string{
	"libloading", "dlopen", "dlopen2", "dlopen-derive", "abi_stable", "sharedlib", "plugin", "plugins", "wasmtime", "wasmer",
	"wasmi", "extism", "mlua", "rlua", "rhai", "pyo3", "deno_core", "v8", "neon", "boa_engine", "libc-dlopen",
}

var sourceLoader = regexp.MustCompile(`\b(dlopen|dlsym|dlmopen|LoadLibrary\w*|libloading|LD_PRELOAD|LD_LIBRARY_PATH)\b`)

// The entry actor loads no plugin: nothing it links loads code at run time (no dynamic loader, plugin framework or
// script engine among the packages in its closure), the workspace's own packages that it links name no loader in their
// source, its crate takes the workspace's lint that denies unsafe code (a call into the loader needs it), and it takes no
// option or variable that names a library, a module or a plugin.
//
// verifies: REQ-ISO-093
func TestEntryLoadsNoPlugins(t *testing.T) {
	entryDir := filepath.Join(root, "actors", "entry")

	// Its crate denies unsafe code, as the workspace does, and does not allow it back anywhere.
	manifest, err := os.ReadFile(filepath.Join(entryDir, "Cargo.toml")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\[lints\]\s*\nworkspace = true$`).Match(manifest) {
		t.Error("actors/entry/Cargo.toml does not take the workspace's lints")
	}
	workspace, err := os.ReadFile(filepath.Join(root, "Cargo.toml")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^unsafe_code = "deny"`).Match(workspace) {
		t.Error("the workspace does not deny unsafe code")
	}
	// The sources: no allow of unsafe code, no loader, and no option or variable for one.
	optionName := regexp.MustCompile(`\.(?:long|env)\("([^"]+)"\)|env!?\("([^"]+)"\)`)
	forbiddenOption := regexp.MustCompile(`(?i)plugin|module|library|extension|preload|\.so\b|dso|dylib`)
	srcs, err := rustSources(filepath.Join(entryDir, "src"))
	if err != nil {
		t.Fatal(err)
	}
	sources := len(srcs)
	for path, text := range srcs {
		if strings.Contains(text, "allow(unsafe_code)") || strings.Contains(text, "unsafe {") || strings.Contains(text, "unsafe fn") {
			t.Errorf("%s has unsafe code", path)
		}
		if m := sourceLoader.FindString(text); m != "" {
			t.Errorf("%s names the loader %s", path, m)
		}
		for _, m := range optionName.FindAllStringSubmatch(text, -1) {
			if name := m[1] + m[2]; forbiddenOption.MatchString(name) {
				t.Errorf("%s: the option or variable %q names a library or a plugin", path, name)
			}
		}
	}
	if sources < 5 {
		t.Fatalf("only %d sources of entry read", sources)
	}

	// What it links.
	g := cargoGraph(t)
	closure := g.closure(t, "entry")
	if len(closure) < 50 {
		t.Fatalf("%d packages in the closure of entry", len(closure))
	}
	own := 0
	for _, p := range closure {
		if slices.Contains(rustLoaders, p.Name) {
			t.Errorf("entry links %s, which loads code at run time", p.Name)
		}
		if d := g.dir(p); d != "" && d != "actors/entry" {
			own++
			// A package of the workspace that entry links: no loader in its source either.
			linked, err := rustSources(filepath.Join(root, d, "src"))
			if err != nil {
				t.Errorf("%s: %v", d, err)
			}
			for path, text := range linked {
				if m := sourceLoader.FindString(text); m != "" {
					t.Errorf("%s (linked by entry) names the loader %s", path, m)
				}
			}
		}
	}
	if own < 4 {
		t.Fatalf("only %d workspace packages linked by entry were read", own)
	}

	// The controls: the matchers find what they look for.
	if !slices.Contains(rustLoaders, "libloading") || !sourceLoader.MatchString("let lib = libc::dlopen(path, 0);") ||
		!forbiddenOption.MatchString("plugin-dir") || !forbiddenOption.MatchString("load-library") {
		t.Error("the control failed: a matcher let a known case through")
	}
	if forbiddenOption.MatchString("socket-mode") || forbiddenOption.MatchString("run-dir") || forbiddenOption.MatchString("front") {
		t.Error("the option matcher refuses entry's own options")
	}
}
