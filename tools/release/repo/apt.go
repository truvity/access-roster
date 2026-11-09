package repo

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tools/release/pkgs"
)

// aptArches are the architectures of the Release file and the directories of dists, in the order apt prints them.
var aptArches = []string{"amd64", "arm64"}

// poolPath is where a package lies below the root of the apt tree: pool/main/<first letter>/<name>/<file>, as Debian lays out its
// pool.
func poolPath(name, file string) string {
	return path.Join("pool", aptComponent, name[:1], name, file)
}

// writeApt writes pool/ and dists/stable/main/binary-<arch>/{Packages,Packages.gz,Release} and dists/stable/Release. The Release
// file lists the hashes of the index files; there is no InRelease and no Release.gpg.
func writeApt(root string, debs []*pkgs.Pkg, date time.Time) error {
	sort.Slice(debs, func(i, j int) bool {
		if debs[i].Name != debs[j].Name {
			return debs[i].Name < debs[j].Name
		}
		if debs[i].Version != debs[j].Version {
			return debs[i].Version < debs[j].Version
		}
		return debs[i].Arch < debs[j].Arch
	})
	stanzas := map[string]*bytes.Buffer{}
	for _, a := range aptArches {
		stanzas[a] = &bytes.Buffer{}
	}
	for _, d := range debs {
		file := filepath.Base(d.File)
		rel := poolPath(d.Name, file)
		if err := copyFile(d.File, filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			return err
		}
		s, err := stanza(d, rel)
		if err != nil {
			return err
		}
		switch d.Arch {
		case "all":
			for _, a := range aptArches {
				_, _ = stanzas[a].WriteString(s)
			}
		default:
			b, ok := stanzas[d.Arch]
			if !ok {
				return fmt.Errorf("%s: the architecture %q is not one of %v", file, d.Arch, aptArches)
			}
			_, _ = b.WriteString(s)
		}
	}
	type indexFile struct {
		rel  string // below dists/stable
		body []byte
	}
	var index []indexFile
	for _, a := range aptArches {
		dir := path.Join(aptComponent, "binary-"+a)
		pk := stanzas[a].Bytes()
		gz, err := gzipBytes(pk)
		if err != nil {
			return err
		}
		archRelease := fmt.Sprintf("Archive: %s\nComponent: %s\nOrigin: sluis-test\nLabel: sluis-test\nArchitecture: %s\n", aptSuite, aptComponent, a)
		index = append(index, indexFile{path.Join(dir, "Packages"), pk}, indexFile{path.Join(dir, "Packages.gz"), gz},
			indexFile{path.Join(dir, "Release"), []byte(archRelease)})
	}
	var rel strings.Builder
	rel.WriteString("Origin: sluis-test\nLabel: sluis-test\n")
	fmt.Fprintf(&rel, "Suite: %s\nCodename: %s\n", aptSuite, aptSuite)
	fmt.Fprintf(&rel, "Date: %s\n", date.Format("Mon, 02 Jan 2006 15:04:05 UTC"))
	fmt.Fprintf(&rel, "Architectures: %s\nComponents: %s\n", strings.Join(aptArches, " "), aptComponent)
	rel.WriteString("Description: UNSIGNED throwaway repository of tools/release/repo, for tests only\n")
	for _, h := range []struct {
		field string
		sum   func([]byte) string
	}{{"SHA256", sha256hex}, {"SHA512", sha512hex}} {
		rel.WriteString(h.field + ":\n")
		for _, f := range index {
			fmt.Fprintf(&rel, " %s %d %s\n", h.sum(f.body), len(f.body), f.rel)
		}
	}
	index = append(index, indexFile{"Release", []byte(rel.String())})
	for _, f := range index {
		p := filepath.Join(root, "dists", aptSuite, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.body, 0o644); err != nil { //nolint:gosec // a file for a loopback server to hand out
			return err
		}
	}
	return nil
}

// stanza is the paragraph of a package in Packages: the control file of the package as it is, then the fields that only the
// index has (Filename, Size and the hashes).
func stanza(d *pkgs.Pkg, filename string) (string, error) {
	if d.Control == "" {
		return "", fmt.Errorf("%s: no control file was read", d.File)
	}
	raw, err := os.ReadFile(d.File)
	if err != nil {
		return "", err
	}
	for _, f := range []string{"Filename:", "Size:", "SHA256:", "SHA512:", "MD5sum:", "SHA1:"} {
		if strings.Contains("\n"+d.Control, "\n"+f) {
			return "", fmt.Errorf("%s: the control file already has a %s field", d.File, strings.TrimSuffix(f, ":"))
		}
	}
	var sb strings.Builder
	sb.WriteString(strings.TrimRight(d.Control, "\n") + "\n")
	fmt.Fprintf(&sb, "Filename: %s\nSize: %d\nSHA256: %s\nSHA512: %s\n\n", filename, len(raw), sha256hex(raw), sha512hex(raw))
	return sb.String(), nil
}

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func sha512hex(b []byte) string { s := sha512.Sum512(b); return hex.EncodeToString(s[:]) }

// gzipBytes compresses b with a header that carries no time and no name, so the same input gives the same bytes.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
