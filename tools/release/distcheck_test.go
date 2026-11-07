package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	version = "2.0.0-alpha.0-snapshot.abc"
	commit  = "0123456789abcdef0123456789abcdef01234567"
)

// fakeELF is the smallest ELF file debug/elf reads: a 64-bit little-endian header and, when interp is set, one PT_INTERP header.
func fakeELF(machine elf.Machine, interp bool, tail string) []byte {
	var b bytes.Buffer
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	le := binary.LittleEndian
	le.PutUint16(h[16:], uint16(elf.ET_EXEC))
	le.PutUint16(h[18:], uint16(machine))
	le.PutUint32(h[20:], 1)
	le.PutUint16(h[52:], 64) // e_ehsize
	if interp {
		le.PutUint64(h[32:], 64) // e_phoff
		le.PutUint16(h[54:], 56) // e_phentsize
		le.PutUint16(h[56:], 1)  // e_phnum
	}
	b.Write(h)
	if interp {
		ph := make([]byte, 56)
		le.PutUint32(ph[0:], uint32(elf.PT_INTERP))
		le.PutUint64(ph[8:], 120)
		le.PutUint64(ph[32:], 10)
		b.Write(ph)
		b.WriteString("/ld.so\x00")
	}
	b.WriteString(tail)
	return b.Bytes()
}

func archive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// release writes a dist directory of one executable, "key", for both architectures, and its configuration.
func release(t *testing.T, mutate func(dist string)) (cfg, dist string) {
	t.Helper()
	dir := t.TempDir()
	dist = filepath.Join(dir, "dist")
	if err := os.Mkdir(dist, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg = filepath.Join(dir, ".goreleaser.yaml")
	conf := "builds:\n  - id: actor-key\n    binary: key\narchives:\n  - id: actor-key\n    ids: [actor-key]\n    name_template: \"sluis-actor-key_{{ .Version }}_{{ .Os }}_{{ .Arch }}\"\n"
	write := func(p string, b []byte) {
		if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // a test file
			t.Fatal(err)
		}
	}
	write(cfg, []byte(conf))
	write(filepath.Join(dist, "metadata.json"), []byte(`{"version":"`+version+`","commit":"`+commit+`"}`))
	var sums strings.Builder
	for arch, m := range map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64} {
		name := fmt.Sprintf("sluis-actor-key_%s_linux_%s.tar.gz", version, arch)
		body := archive(t, map[string][]byte{"key": fakeELF(m, false, version), "LICENSE": []byte("MIT")})
		sum := sha256.Sum256(body)
		line := hex.EncodeToString(sum[:]) + "  " + name + "\n"
		sums.WriteString(line)
		write(filepath.Join(dist, name), body)
		write(filepath.Join(dist, name+".sha256"), []byte(line))
	}
	write(filepath.Join(dist, "SHA256SUMS"), []byte(sums.String()))
	if mutate != nil {
		mutate(dist)
	}
	return cfg, dist
}

func TestAGoodDistPasses(t *testing.T) {
	cfg, dist := release(t, nil)
	if p := CheckDist(cfg, dist); len(p) != 0 {
		t.Fatalf("a good dist has problems: %v", p)
	}
}

// Each case breaks one promise of the release and the check must say so: the mutation that shows the check bites.
func TestCheckDistBites(t *testing.T) {
	arm := fmt.Sprintf("sluis-actor-key_%s_linux_arm64.tar.gz", version)
	amd := fmt.Sprintf("sluis-actor-key_%s_linux_amd64.tar.gz", version)
	// rewrite replaces one archive and keeps its .sha256 and its line of SHA256SUMS true, so only the content is wrong.
	rewrite := func(dist, name string, files map[string][]byte) {
		body := archive(t, files)
		sum := sha256.Sum256(body)
		line := hex.EncodeToString(sum[:]) + "  " + name
		sums, err := os.ReadFile(filepath.Join(dist, "SHA256SUMS")) //nolint:gosec // a test file
		if err != nil {
			t.Fatal(err)
		}
		out := []string{line}
		for _, l := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
			if !strings.HasSuffix(l, name) {
				out = append(out, l)
			}
		}
		for p, b := range map[string][]byte{name: body, name + ".sha256": []byte(line + "\n"), "SHA256SUMS": []byte(strings.Join(out, "\n") + "\n")} {
			if err := os.WriteFile(filepath.Join(dist, p), b, 0o644); err != nil { //nolint:gosec // a test file
				t.Fatal(err)
			}
		}
	}
	for name, c := range map[string]struct {
		mutate func(dist string)
		want   string
	}{
		"missing archive": {func(d string) { _ = os.Remove(filepath.Join(d, arm)) }, "the archive is missing"},
		"hash differs in SHA256SUMS": {func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, "SHA256SUMS")) //nolint:gosec // a test file
			flipped := append([]byte{}, b...)
			flipped[0] = map[bool]byte{true: '1', false: '0'}[b[0] == '0']
			_ = os.WriteFile(filepath.Join(d, "SHA256SUMS"), flipped, 0o644) //nolint:gosec // a test file
		}, "SHA256SUMS says"},
		"no .sha256": {func(d string) { _ = os.Remove(filepath.Join(d, amd+".sha256")) }, ".sha256"},
		"extra archive": {func(d string) {
			_ = os.WriteFile(filepath.Join(d, "sluis-other_1_linux_amd64.tar.gz"), []byte("x"), 0o600)
		}, "nobody asked for this file"},
		"wrong machine": {func(d string) {
			rewrite(d, arm, map[string][]byte{"key": fakeELF(elf.EM_X86_64, false, version), "LICENSE": []byte("MIT")})
		}, "is for EM_X86_64, want EM_AARCH64"},
		"dynamic": {func(d string) {
			rewrite(d, amd, map[string][]byte{"key": fakeELF(elf.EM_X86_64, true, version), "LICENSE": []byte("MIT")})
		}, "PT_INTERP"},
		"not stamped": {func(d string) {
			rewrite(d, amd, map[string][]byte{"key": fakeELF(elf.EM_X86_64, false, "0.0.0-dev"), "LICENSE": []byte("MIT")})
		}, "did not stamp it"},
		"a build path": {func(d string) {
			rewrite(d, amd, map[string][]byte{"key": fakeELF(elf.EM_X86_64, false, version+" panicked at "+filepath.Dir(d)+"/src/main.rs"), "LICENSE": []byte("MIT")})
		}, "holds the build path"},
		"not an ELF": {func(d string) {
			rewrite(d, amd, map[string][]byte{"key": []byte("#!/bin/sh"), "LICENSE": []byte("MIT")})
		}, "is not an ELF"},
		"no licence": {func(d string) {
			rewrite(d, amd, map[string][]byte{"key": fakeELF(elf.EM_X86_64, false, version)})
		}, "does not hold LICENSE"},
		"stray file": {func(d string) {
			rewrite(d, amd, map[string][]byte{"key": fakeELF(elf.EM_X86_64, false, version), "LICENSE": []byte("MIT"), "id_rsa": []byte("x")})
		}, "holds id_rsa"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, dist := release(t, c.mutate)
			p := CheckDist(cfg, dist)
			if len(p) == 0 {
				t.Fatal("the check passed a broken dist")
			}
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
}

func TestCheckDistRefusesAnEmptyConfigAndADistWithoutMetadata(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(cfg, []byte("builds: []\n"), 0o644); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	if p := CheckDist(cfg, dir); len(p) == 0 {
		t.Error("a configuration with no archive passed")
	}
	if p := CheckDist(filepath.Join(dir, "none.yaml"), dir); len(p) == 0 {
		t.Error("a missing configuration passed")
	}
}
