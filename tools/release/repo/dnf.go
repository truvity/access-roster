package repo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tools/release/pkgs"
)

// The tags of an rpm header that the metadata reads (rpm's tag numbers, lib/rpmtag.h).
const (
	tagSummary      = 1004
	tagDescription  = 1005
	tagBuildTime    = 1006
	tagBuildHost    = 1007
	tagSize         = 1009
	tagVendor       = 1011
	tagLicense      = 1014
	tagPackager     = 1015
	tagGroup        = 1016
	tagURL          = 1020
	tagSourceRPM    = 1044
	tagEpoch        = 1003
	tagProvideName  = 1047
	tagProvideFlags = 1112
	tagProvideVer   = 1113
	tagRequireFlags = 1048
	tagRequireName  = 1049
	tagRequireVer   = 1050
	tagConflictFlag = 1053
	tagConflictName = 1054
	tagConflictVer  = 1055
	tagObsoleteName = 1090
	tagObsoleteFlag = 1114
	tagObsoleteVer  = 1115
	tagRecommendN   = 5046
	tagRecommendV   = 5047
	tagRecommendF   = 5048
	tagSuggestN     = 5049
	tagSuggestV     = 5050
	tagSuggestF     = 5051
	tagLongSize     = 5009
)

// The bits of the flags of a dependency (RPMSENSE_*).
const (
	sensLess    = 0x02
	sensGreater = 0x04
	sensEqual   = 0x08
	// sensPre is every flag that asks for the dependency before the scriptlets of the install run (PREREQ and the two scriptlet
	// flags): the `pre="1"` of the metadata.
	sensPre = 0x40 | 0x200 | 0x400
)

// rpmArchDirs are the directories of the dnf tree: $basearch of the client. An architecture-independent package goes in each.
var rpmArchDirs = []string{"x86_64", "aarch64"}

// writeDnf writes dnf/<basearch>/{Packages/<file>, repodata/{repomd.xml, primary, filelists, other}} for each architecture.
func writeDnf(root string, rpms []*pkgs.Pkg, date time.Time) error {
	for _, a := range rpmArchDirs {
		var mine []*pkgs.Pkg
		for _, r := range rpms {
			if r.Arch == a || r.Arch == "noarch" {
				mine = append(mine, r)
			} else if !contains(rpmArchDirs, r.Arch) && r.Arch != "noarch" {
				return fmt.Errorf("%s: the architecture %q is not one of %v", r.File, r.Arch, rpmArchDirs)
			}
		}
		if err := writeDnfTree(filepath.Join(root, a), mine, date); err != nil {
			return fmt.Errorf("%s: %w", a, err)
		}
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// rpmEntry is one package as the three metadata files describe it.
type rpmEntry struct {
	p        *pkgs.Pkg
	m        *pkgs.RPMMeta
	pkgid    string // SHA-256 of the file
	size     int64
	location string
	epoch    string
}

func writeDnfTree(dir string, rpms []*pkgs.Pkg, date time.Time) error {
	sort.Slice(rpms, func(i, j int) bool {
		if rpms[i].Name != rpms[j].Name {
			return rpms[i].Name < rpms[j].Name
		}
		return rpms[i].Version < rpms[j].Version
	})
	var es []rpmEntry
	for _, p := range rpms {
		raw, err := os.ReadFile(p.File)
		if err != nil {
			return err
		}
		m, err := pkgs.ReadRPMMeta(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", p.File, err)
		}
		loc := "Packages/" + filepath.Base(p.File)
		if err := copyFile(p.File, filepath.Join(dir, filepath.FromSlash(loc))); err != nil {
			return err
		}
		epoch := "0"
		if e := m.U32s(tagEpoch); len(e) == 1 {
			epoch = strconv.FormatUint(uint64(e[0]), 10)
		}
		sum := sha256.Sum256(raw)
		es = append(es, rpmEntry{p: p, m: m, pkgid: hex.EncodeToString(sum[:]), size: int64(len(raw)), location: loc, epoch: epoch})
	}
	primary, filelists, other := &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}
	n := len(es)
	fmt.Fprintf(primary, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", n)
	fmt.Fprintf(filelists, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"%d\">\n", n)
	fmt.Fprintf(other, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"%d\">\n", n)
	for _, e := range es {
		e.primary(primary, date)
		e.filelist(filelists)
		e.otherdata(other)
	}
	primary.WriteString("</metadata>\n")
	filelists.WriteString("</filelists>\n")
	other.WriteString("</otherdata>\n")

	var data strings.Builder
	data.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n")
	fmt.Fprintf(&data, "  <revision>%d</revision>\n", date.Unix())
	for _, f := range []struct {
		typ  string
		body []byte
	}{{"primary", primary.Bytes()}, {"filelists", filelists.Bytes()}, {"other", other.Bytes()}} {
		gz, err := gzipBytes(f.body)
		if err != nil {
			return err
		}
		sum := sha256hex(gz)
		href := "repodata/" + sum + "-" + f.typ + ".xml.gz"
		p := filepath.Join(dir, filepath.FromSlash(href))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, gz, 0o644); err != nil { //nolint:gosec // a file for a loopback server to hand out
			return err
		}
		fmt.Fprintf(&data, "  <data type=%q>\n    <checksum type=\"sha256\">%s</checksum>\n    <open-checksum type=\"sha256\">%s</open-checksum>\n", f.typ, sum, sha256hex(f.body))
		fmt.Fprintf(&data, "    <location href=%q/>\n    <timestamp>%d</timestamp>\n    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n", href, date.Unix(), len(gz), len(f.body))
	}
	data.WriteString("</repomd>\n")
	return os.WriteFile(filepath.Join(dir, "repodata", "repomd.xml"), []byte(data.String()), 0o644) //nolint:gosec // a file for a loopback server to hand out
}

// primary writes the <package> of primary.xml.
func (e rpmEntry) primary(w *bytes.Buffer, date time.Time) {
	m := e.m
	fmt.Fprintf(w, "<package type=\"rpm\">\n  <name>%s</name>\n  <arch>%s</arch>\n  <version epoch=%q ver=\"%s\" rel=\"%s\"/>\n", esc(e.p.Name), esc(e.p.Arch), e.epoch, esc(e.p.Version), esc(e.p.Release))
	fmt.Fprintf(w, "  <checksum type=\"sha256\" pkgid=\"YES\">%s</checksum>\n", e.pkgid)
	summary := m.Str(tagSummary)
	if summary == "" {
		summary = e.p.Name
	}
	fmt.Fprintf(w, "  <summary>%s</summary>\n  <description>%s</description>\n  <packager>%s</packager>\n  <url>%s</url>\n",
		esc(summary), esc(m.Str(tagDescription)), esc(m.Str(tagPackager)), esc(m.Str(tagURL)))
	var build uint32
	if b := m.U32s(tagBuildTime); len(b) == 1 {
		build = b[0]
	}
	installed := uint64(0)
	if s := m.U64s(tagLongSize); len(s) == 1 {
		installed = s[0]
	} else if s := m.U32s(tagSize); len(s) == 1 {
		installed = uint64(s[0])
	}
	fmt.Fprintf(w, "  <time file=\"%d\" build=\"%d\"/>\n  <size package=\"%d\" installed=\"%d\" archive=\"%d\"/>\n  <location href=\"%s\"/>\n",
		date.Unix(), build, e.size, installed, m.PayloadSize, esc(e.location))
	fmt.Fprintf(w, "  <format>\n    <rpm:license>%s</rpm:license>\n    <rpm:vendor>%s</rpm:vendor>\n    <rpm:group>%s</rpm:group>\n    <rpm:buildhost>%s</rpm:buildhost>\n    <rpm:sourcerpm>%s</rpm:sourcerpm>\n",
		esc(m.Str(tagLicense)), esc(m.Str(tagVendor)), esc(m.Str(tagGroup)), esc(m.Str(tagBuildHost)), esc(m.Str(tagSourceRPM)))
	fmt.Fprintf(w, "    <rpm:header-range start=\"%d\" end=\"%d\"/>\n", m.HeaderStart, m.HeaderEnd)
	for _, d := range []struct {
		tag               string
		name, ver, flagsT uint32
	}{
		{"provides", tagProvideName, tagProvideVer, tagProvideFlags},
		{"requires", tagRequireName, tagRequireVer, tagRequireFlags},
		{"conflicts", tagConflictName, tagConflictVer, tagConflictFlag},
		{"obsoletes", tagObsoleteName, tagObsoleteVer, tagObsoleteFlag},
		{"recommends", tagRecommendN, tagRecommendV, tagRecommendF},
		{"suggests", tagSuggestN, tagSuggestV, tagSuggestF},
	} {
		writeDeps(w, d.tag, m.Strs(d.name), m.Strs(d.ver), m.U32s(d.flagsT), d.tag == "requires")
	}
	for _, f := range e.p.Files {
		if !inPrimary(f.Path) {
			continue
		}
		if f.Kind == 'd' {
			fmt.Fprintf(w, "    <file type=\"dir\">%s</file>\n", esc(f.Path))
		} else {
			fmt.Fprintf(w, "    <file>%s</file>\n", esc(f.Path))
		}
	}
	w.WriteString("  </format>\n</package>\n")
}

// inPrimary is the rule of createrepo for the files that primary.xml lists, so that a dependency on a file of a binary directory or
// of /etc is met without fetching filelists.xml: the others are in filelists.xml alone.
func inPrimary(p string) bool {
	return strings.Contains(p, "bin/") || strings.HasPrefix(p, "/etc/") || p == "/usr/lib/sendmail"
}

func (e rpmEntry) filelist(w *bytes.Buffer) {
	fmt.Fprintf(w, "<package pkgid=\"%s\" name=\"%s\" arch=\"%s\">\n  <version epoch=%q ver=\"%s\" rel=\"%s\"/>\n", e.pkgid, esc(e.p.Name), esc(e.p.Arch), e.epoch, esc(e.p.Version), esc(e.p.Release))
	for _, f := range e.p.Files {
		if f.Kind == 'd' {
			fmt.Fprintf(w, "  <file type=\"dir\">%s</file>\n", esc(f.Path))
		} else {
			fmt.Fprintf(w, "  <file>%s</file>\n", esc(f.Path))
		}
	}
	w.WriteString("</package>\n")
}

func (e rpmEntry) otherdata(w *bytes.Buffer) {
	fmt.Fprintf(w, "<package pkgid=\"%s\" name=\"%s\" arch=\"%s\">\n  <version epoch=%q ver=\"%s\" rel=\"%s\"/>\n</package>\n", e.pkgid, esc(e.p.Name), esc(e.p.Arch), e.epoch, esc(e.p.Version), esc(e.p.Release))
}

// writeDeps writes <rpm:provides> and its kin: one <rpm:entry> for each distinct dependency. A relation that carries no version
// is written as the bare name.
func writeDeps(w *bytes.Buffer, tag string, names, vers []string, flags []uint32, markPre bool) {
	var lines []string
	seen := map[string]bool{}
	for i, n := range names {
		var v string
		var f uint32
		if i < len(vers) {
			v = vers[i]
		}
		if i < len(flags) {
			f = flags[i]
		}
		var sb strings.Builder
		sb.WriteString("      <rpm:entry name=\"" + esc(n) + "\"")
		if op := flagName(f); op != "" && v != "" {
			epoch, ver, rel := splitEVR(v)
			sb.WriteString(" flags=\"" + op + "\" epoch=\"" + esc(epoch) + "\" ver=\"" + esc(ver) + "\"")
			if rel != "" {
				sb.WriteString(" rel=\"" + esc(rel) + "\"")
			}
		}
		if markPre && f&sensPre != 0 {
			sb.WriteString(" pre=\"1\"")
		}
		sb.WriteString("/>\n")
		if l := sb.String(); !seen[l] {
			seen[l] = true
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return
	}
	w.WriteString("    <rpm:" + tag + ">\n")
	for _, l := range lines {
		w.WriteString(l)
	}
	w.WriteString("    </rpm:" + tag + ">\n")
}

// flagName is the comparison of a dependency as the metadata names it, "" for none.
func flagName(f uint32) string {
	switch {
	case f&sensLess != 0 && f&sensEqual != 0:
		return "LE"
	case f&sensGreater != 0 && f&sensEqual != 0:
		return "GE"
	case f&sensLess != 0:
		return "LT"
	case f&sensGreater != 0:
		return "GT"
	case f&sensEqual != 0:
		return "EQ"
	}
	return ""
}

// splitEVR splits [epoch:]version[-release]. The epoch is "0" when the text has none; a version that has no release has none.
func splitEVR(s string) (epoch, ver, rel string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		epoch, s = e, rest
	}
	if i := strings.LastIndex(s, "-"); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

// esc escapes text for an element or an attribute. xml.EscapeText also turns a character that XML 1.0 cannot carry into U+FFFD, and
// a quote and a line break into character references, so the text is safe in both places.
func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
