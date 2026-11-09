package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goreleaser/nfpm/v2"

	. "github.com/truvity/sluis/v2/tools/release/pkgs" //nolint:revive // the tool and the library are one program in two modules
)

const testVersion = "2.0.0-alpha.1"

// commitTime is what GoReleaser's mod_timestamp gives every file of an archive.
var commitTime = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// fakeELF is the smallest static ELF64 that debug/elf reads: the header, one PT_LOAD and no PT_INTERP, no dynamic section, for the
// machine, with the version text in it as the release build stamps it.
func fakeELF(machine elf.Machine, version string) []byte {
	var b bytes.Buffer
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), byte(elf.ELFOSABI_NONE)})
	le := binary.LittleEndian
	le.PutUint16(h[16:], uint16(elf.ET_EXEC))
	le.PutUint16(h[18:], uint16(machine))
	le.PutUint32(h[20:], 1)
	le.PutUint64(h[32:], 64) // e_phoff
	le.PutUint16(h[52:], 64) // e_ehsize
	le.PutUint16(h[54:], 56) // e_phentsize
	le.PutUint16(h[56:], 1)  // e_phnum
	le.PutUint16(h[58:], 64) // e_shentsize
	b.Write(h)
	ph := make([]byte, 56)
	le.PutUint32(ph[0:], uint32(elf.PT_LOAD))
	le.PutUint32(ph[4:], uint32(elf.PF_R|elf.PF_X))
	body := []byte("sluis test executable " + version + "\n")
	le.PutUint64(ph[32:], uint64(120+len(body)))
	le.PutUint64(ph[40:], uint64(120+len(body)))
	b.Write(ph)
	b.Write(body)
	return b.Bytes()
}

// writeArchive writes an archive as GoReleaser does: the executable and LICENSE, mode 0755 and 0644, the commit's time.
func writeArchive(t *testing.T, p string, bin string, exe []byte) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, f := range []struct {
		n    string
		mode int64
		b    []byte
	}{{"LICENSE", 0o644, []byte("MIT License\n")}, {bin, 0o755, exe}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.n, Mode: f.mode, Size: int64(len(f.b)), ModTime: commitTime, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeDist writes a dist directory for the specs: metadata.json and an archive of a fake static executable for each executable and
// architecture.
func fakeDist(t *testing.T, version string, specs []Spec) string {
	t.Helper()
	dist := t.TempDir()
	if err := os.WriteFile(filepath.Join(dist, "metadata.json"), []byte(fmt.Sprintf(`{"version":%q}`, version)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, s := range specs {
		for _, ex := range s.Execs {
			for arch, m := range Arches {
				writeArchive(t, filepath.Join(dist, fmt.Sprintf("%s_%s_linux_%s.tar.gz", ex.Archive, version, arch)), ex.Bin, fakeELF(m, version))
			}
		}
	}
	return dist
}

// realSpecs is the plan of the tree: the images list of the repository and its actor registry.
func realSpecs(t *testing.T) []Spec {
	t.Helper()
	specs, _ := realPlan(t)
	return specs
}

// realPlan is realSpecs and the actors of the registry. The packages of the older tests hold executables alone: they are the plan
// of the tree with the units, the users and the scripts taken away, so that a test that adds one thing to a package sees only that.
// realPlanWithUnits is the plan a release builds.
func realPlan(t *testing.T) ([]Spec, []Actor) {
	t.Helper()
	specs, actors := realPlanWithUnits(t)
	for i := range specs {
		specs[i].Extra, specs[i].Units, specs[i].Scripts = nil, nil, nil
	}
	return specs, actors
}

func realPlanWithUnits(t *testing.T) ([]Spec, []Actor) {
	t.Helper()
	specs, actors, err := PlanFiles("../../../deploy/release/images.yaml", "../../../docs/architecture/actors.yaml", "../../../deploy/boards/units")
	if err != nil {
		t.Fatal(err)
	}
	return specs, actors
}

// build builds the specs into a new directory and returns the dist and the output.
func build(t *testing.T, specs []Spec, tweak func(Spec, Format, *nfpm.Info)) (dist, out string) {
	t.Helper()
	dist = fakeDist(t, testVersion, specs)
	out = filepath.Join(t.TempDir(), "packages")
	b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: tweak}
	if err := b.Build(); err != nil {
		t.Fatal(err)
	}
	return dist, out
}
