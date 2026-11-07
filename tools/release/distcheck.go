package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// arches are the architectures of every release (ADR 0013: every artifact is built for amd64 and arm64).
var arches = map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}

type config struct {
	Builds []struct {
		ID     string `yaml:"id"`
		Binary string `yaml:"binary"`
	} `yaml:"builds"`
	SBOMs []struct {
		ID string `yaml:"id"`
	} `yaml:"sboms"`
	Archives []struct {
		ID           string   `yaml:"id"`
		IDs          []string `yaml:"ids"`
		NameTemplate string   `yaml:"name_template"`
	} `yaml:"archives"`
}

// loadConfig reads the parts of .goreleaser.yaml the checks use.
func loadConfig(p string) (config, error) {
	var c config
	raw, err := os.ReadFile(p) //nolint:gosec // the repository's own configuration
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("%s: %w", p, err)
	}
	return c, nil
}

func yamlUnmarshal(raw []byte, v any) error { return yaml.Unmarshal(raw, v) }

var nameTemplate = regexp.MustCompile(`^([a-z0-9-]+)_\{\{ \.Version \}\}_\{\{ \.Os \}\}_\{\{ \.Arch \}\}$`)

// CheckDist reads what a GoReleaser run left in dist, against the configuration it ran with, and returns every problem.
// It proves, for each archive the configuration names and each architecture: the archive exists, SHA256SUMS and the .sha256
// beside it carry its real hash, it holds the executable and the licence and nothing else, the executable is a static ELF
// of the architecture, and the release version is in it. An archive nobody asked for is a problem too.
func CheckDist(configPath, dist string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	raw, err := os.ReadFile(configPath) //nolint:gosec // the repository's own configuration
	if err != nil {
		return []string{err.Error()}
	}
	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return []string{fmt.Sprintf("%s: %v", configPath, err)}
	}
	if len(cfg.Archives) == 0 {
		return []string{fmt.Sprintf("%s has no archive: an empty release is a failure", configPath)}
	}
	m, err := distMeta(dist)
	if err != nil {
		return []string{err.Error()}
	}
	version := m.Version

	// The executables must not carry the paths of the machine that built them (Go has -trimpath, Rust --remap-path-prefix).
	var forbidden []string
	if root, err := filepath.Abs(filepath.Dir(configPath)); err == nil && len(root) > 4 {
		forbidden = append(forbidden, root)
	}
	if home := os.Getenv("HOME"); len(home) > 5 {
		forbidden = append(forbidden, home)
	}

	binaryOf := map[string]string{}
	for _, b := range cfg.Builds {
		binaryOf[b.ID] = b.Binary
	}

	sums, err := readSums(filepath.Join(dist, "SHA256SUMS"))
	if err != nil {
		bad("%v", err)
	}
	expected := map[string]bool{}
	for _, a := range cfg.Archives {
		m := nameTemplate.FindStringSubmatch(a.NameTemplate)
		if m == nil {
			bad("archive %s: name_template %q is not <name>_{{ .Version }}_{{ .Os }}_{{ .Arch }}", a.ID, a.NameTemplate)
			continue
		}
		bin := binaryOf[a.ID]
		if bin == "" || len(a.IDs) != 1 || a.IDs[0] != a.ID {
			bad("archive %s: it must take the one build of the same id, which must name a binary", a.ID)
			continue
		}
		for arch, machine := range arches {
			name := fmt.Sprintf("%s_%s_linux_%s.tar.gz", m[1], version, arch)
			expected[name] = true
			path := filepath.Join(dist, name)
			body, err := os.ReadFile(path) //nolint:gosec // GoReleaser's own output
			if err != nil {
				bad("%s: the archive is missing (%s, %s)", name, a.ID, arch)
				continue
			}
			sum := sha256.Sum256(body)
			hexSum := hex.EncodeToString(sum[:])
			if got, ok := sums[name]; !ok {
				bad("%s: SHA256SUMS does not list it", name)
			} else if got != hexSum {
				bad("%s: SHA256SUMS says %s, the file is %s", name, got, hexSum)
			}
			each, err := readSums(path + ".sha256")
			switch {
			case err != nil:
				bad("%v", err)
			case len(each) != 1 || each[name] != hexSum:
				bad("%s.sha256 does not hold exactly the hash of the archive", name)
			}
			for _, p := range checkArchive(name, body, bin, machine, version, forbidden) {
				bad("%s", p)
			}
			// With an sboms stage, the SPDX document of the archive is a release file too, and SHA256SUMS covers it.
			if len(cfg.SBOMs) > 0 {
				doc := name + ".sbom.spdx.json"
				expected[doc] = true
				dbody, err := os.ReadFile(filepath.Join(dist, doc)) //nolint:gosec // GoReleaser's own output
				if err != nil {
					bad("%s: the SBOM is missing (%s, %s)", doc, a.ID, arch)
				} else {
					dsum := sha256.Sum256(dbody)
					if got, ok := sums[doc]; !ok || got != hex.EncodeToString(dsum[:]) {
						bad("%s: SHA256SUMS does not list it with its hash", doc)
					}
				}
			}
		}
	}
	for name := range sums {
		// The list of images and the SBOMs of the images are added to SHA256SUMS after the images are pushed (tools/release sums).
		if !expected[name] && name != "release-images.txt" && name != CatalogueFile && (!strings.HasSuffix(name, ".sbom.spdx.json") || strings.Contains(name, ".tar.gz")) {
			bad("SHA256SUMS lists %s, which no archive of the configuration is", name)
		}
	}
	entries, err := os.ReadDir(dist)
	if err != nil {
		bad("%v", err)
	}
	for _, e := range entries {
		n := e.Name()
		if (strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tar.gz.sha256") || strings.HasSuffix(n, ".tar.gz.sbom.spdx.json")) && !expected[strings.TrimSuffix(n, ".sha256")] {
			bad("%s: nobody asked for this file", n)
		}
	}
	sort.Strings(problems)
	return problems
}

// readSums reads a file of `<hash>  <name>` lines.
func readSums(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return nil, err
	}
	res := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || len(f[0]) != 64 {
			return nil, fmt.Errorf("%s: %q is not <sha256>  <name>", filepath.Base(path), l)
		}
		if _, dup := res[f[1]]; dup {
			return nil, fmt.Errorf("%s: %s is listed twice", filepath.Base(path), f[1])
		}
		res[f[1]] = f[0]
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("%s is empty", filepath.Base(path))
	}
	return res, nil
}

// checkArchive reads one .tar.gz: the executable bin and LICENSE, nothing else; the executable is a static ELF of the machine
// that holds the version.
func checkArchive(name string, body []byte, bin string, machine elf.Machine, version string, forbidden []string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, name+": "+fmt.Sprintf(format, a...)) }
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	tr := tar.NewReader(zr)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return append(problems, name+": "+err.Error())
		}
		seen[h.Name] = true
		switch h.Name {
		case "LICENSE":
		case bin:
			if h.Mode&0o111 == 0 {
				bad("%s is not executable (mode %o)", bin, h.Mode)
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				bad("%v", err)
				continue
			}
			for _, p := range checkExecutable(data, machine, version, forbidden) {
				bad("%s: %s", bin, p)
			}
		default:
			bad("holds %s, which is neither %s nor LICENSE", h.Name, bin)
		}
	}
	for _, want := range []string{bin, "LICENSE"} {
		if !seen[want] {
			bad("does not hold %s", want)
		}
	}
	return problems
}

// checkExecutable says what is wrong with an executable of a release: not an ELF of the machine, an interpreter or a shared
// library (it must be static, ADR 0013), or no release version in it (the build did not stamp it).
func checkExecutable(data []byte, machine elf.Machine, version string, forbidden []string) []string {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return []string{"is not an ELF file: " + err.Error()}
	}
	defer func() { _ = f.Close() }()
	var problems []string
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		problems = append(problems, fmt.Sprintf("is %v %v %v, not a 64-bit little-endian Linux ELF", f.Class, f.Data, f.OSABI))
	}
	if f.Machine != machine {
		problems = append(problems, fmt.Sprintf("is for %v, want %v", f.Machine, machine))
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			problems = append(problems, "asks for a dynamic loader (PT_INTERP): it is not static")
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		problems = append(problems, "needs shared libraries "+strings.Join(libs, ", ")+": it is not static")
	}
	for _, path := range forbidden {
		if bytes.Contains(data, []byte(path)) {
			problems = append(problems, "holds the build path "+path+": the build did not remap its paths")
		}
	}
	if !bytes.Contains(data, []byte(version)) {
		problems = append(problems, "does not hold the release version "+version+": the build did not stamp it")
	}
	return problems
}
