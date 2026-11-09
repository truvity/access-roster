package repo

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Check reads the trees below root back and returns every disagreement between the metadata and the files, empty for a good tree.
// It reads by another path than the writer: the Packages and Release files with a parser of their own and the XML with the
// standard library's decoder, and it compares what the metadata says with the files it names (their size, their SHA-256, the
// count of packages). It also holds the tree to what a throwaway repository is: unsigned, and with every dependency on a package
// of the release (a name that starts with "sluis") met inside the tree of its architecture, at the exact version it asks for.
func Check(root string) []string {
	c := &checker{root: root}
	if _, err := os.Stat(filepath.Join(root, noticeName)); err != nil {
		c.add("%s is missing: the tree must say it is not the publication site", noticeName)
	}
	c.apt(filepath.Join(root, AptDir))
	for _, a := range rpmArchDirs {
		c.dnf(filepath.Join(root, DnfDir, a), a)
	}
	return c.problems
}

type checker struct {
	root     string
	problems []string
}

func (c *checker) add(format string, a ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, a...))
}

func (c *checker) rel(p string) string {
	r, err := filepath.Rel(c.root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

// ---- apt

// paragraphs splits a control-format file into paragraphs of fields, keeping each field's continuation lines joined by a newline.
func paragraphs(text string) ([]map[string]string, error) {
	var res []map[string]string
	cur := map[string]string{}
	key := ""
	flush := func() {
		if len(cur) > 0 {
			res = append(res, cur)
		}
		cur, key = map[string]string{}, ""
	}
	for _, l := range strings.Split(text, "\n") {
		switch {
		case l == "":
			flush()
		case l[0] == ' ' || l[0] == '\t':
			if key == "" {
				return nil, fmt.Errorf("a continuation line with no field: %q", l)
			}
			cur[key] += "\n" + strings.TrimSpace(l)
		default:
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				return nil, fmt.Errorf("%q is not a field", l)
			}
			if _, dup := cur[k]; dup {
				return nil, fmt.Errorf("the field %s twice in a paragraph", k)
			}
			key, cur[k] = k, strings.TrimSpace(v)
		}
	}
	flush()
	return res, nil
}

func (c *checker) apt(root string) {
	for _, unsigned := range []string{"InRelease", "Release.gpg"} {
		if _, err := os.Stat(filepath.Join(root, "dists", aptSuite, unsigned)); err == nil {
			c.add("%s: a signature file in a tree that is unsigned by design", c.rel(filepath.Join(root, "dists", aptSuite, unsigned)))
		}
	}
	relPath := filepath.Join(root, "dists", aptSuite, "Release")
	raw, err := os.ReadFile(relPath) //nolint:gosec // the tree being checked
	if err != nil {
		c.add("apt: %v", err)
		return
	}
	ps, err := paragraphs(string(raw))
	if err != nil || len(ps) != 1 {
		c.add("%s: not one paragraph of fields (%v)", c.rel(relPath), err)
		return
	}
	rel := ps[0]
	if rel["Suite"] != aptSuite || rel["Components"] != aptComponent {
		c.add("%s: Suite %q and Components %q, want %q and %q", c.rel(relPath), rel["Suite"], rel["Components"], aptSuite, aptComponent)
	}
	if strings.Fields(rel["Architectures"]) == nil || strings.Join(strings.Fields(rel["Architectures"]), " ") != strings.Join(aptArches, " ") {
		c.add("%s: Architectures %q, want %q", c.rel(relPath), rel["Architectures"], strings.Join(aptArches, " "))
	}
	listed := map[string]bool{}
	for _, field := range []string{"SHA256", "SHA512"} {
		lines := strings.Fields(rel[field])
		if len(lines) == 0 || len(lines)%3 != 0 {
			c.add("%s: the %s list is empty or not hash, size and name", c.rel(relPath), field)
			continue
		}
		for i := 0; i < len(lines); i += 3 {
			name := lines[i+2]
			if field == "SHA256" {
				listed[name] = true
			}
			body, err := os.ReadFile(filepath.Join(root, "dists", aptSuite, filepath.FromSlash(name))) //nolint:gosec // the tree being checked
			if err != nil {
				c.add("%s lists %s: %v", c.rel(relPath), name, err)
				continue
			}
			want := sha256hex(body)
			if field == "SHA512" {
				want = sha512hex(body)
			}
			if lines[i] != want || lines[i+1] != strconv.Itoa(len(body)) {
				c.add("%s: %s has %s and %d bytes in the %s list, the file has %s and %d", c.rel(relPath), name, lines[i], atoiOr(lines[i+1], -1), field, want, len(body))
			}
		}
	}
	type pk struct{ name, version string }
	inPool := map[string]bool{}
	byArch := map[string]map[pk]bool{}
	referenced := map[string]bool{}
	var stanzas []struct {
		arch string
		f    map[string]string
	}
	for _, a := range aptArches {
		dir := path.Join(aptComponent, "binary-"+a)
		for _, n := range []string{"Packages", "Packages.gz", "Release"} {
			if !listed[path.Join(dir, n)] {
				c.add("%s does not list %s", c.rel(relPath), path.Join(dir, n))
			}
		}
		plain, err := os.ReadFile(filepath.Join(root, "dists", aptSuite, filepath.FromSlash(dir), "Packages")) //nolint:gosec // the tree being checked
		if err != nil {
			c.add("apt: %v", err)
			continue
		}
		gzRaw, err := os.ReadFile(filepath.Join(root, "dists", aptSuite, filepath.FromSlash(dir), "Packages.gz")) //nolint:gosec // the tree being checked
		if err == nil {
			zr, zerr := gzip.NewReader(bytes.NewReader(gzRaw))
			var un []byte
			if zerr == nil {
				un, zerr = io.ReadAll(zr)
			}
			if zerr != nil || !bytes.Equal(un, plain) {
				c.add("%s/Packages.gz is not the compressed Packages (%v)", dir, zerr)
			}
		}
		ps, err := paragraphs(string(plain))
		if err != nil {
			c.add("%s/Packages: %v", dir, err)
			continue
		}
		byArch[a] = map[pk]bool{}
		for _, f := range ps {
			stanzas = append(stanzas, struct {
				arch string
				f    map[string]string
			}{a, f})
			k := pk{f["Package"], f["Version"]}
			if k.name == "" || k.version == "" {
				c.add("%s/Packages: a stanza with no Package or Version", dir)
				continue
			}
			if byArch[a][k] {
				c.add("%s/Packages lists %s %s twice", dir, k.name, k.version)
			}
			byArch[a][k] = true
			if f["Architecture"] != a && f["Architecture"] != "all" {
				c.add("%s/Packages: %s is for %q", dir, k.name, f["Architecture"])
			}
			fn := f["Filename"]
			if !strings.HasPrefix(fn, "pool/") || strings.Contains(fn, "..") {
				c.add("%s/Packages: %s has the Filename %q, not a path below pool/", dir, k.name, fn)
				continue
			}
			referenced[fn] = true
			body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fn))) //nolint:gosec // the tree being checked
			if err != nil {
				c.add("%s/Packages: %s: %v", dir, k.name, err)
				continue
			}
			if f["Size"] != strconv.Itoa(len(body)) || f["SHA256"] != sha256hex(body) {
				c.add("%s/Packages: %s: Size %s and SHA256 %s, the file has %d and %s", dir, k.name, f["Size"], f["SHA256"], len(body), sha256hex(body))
			}
		}
	}
	_ = filepath.WalkDir(filepath.Join(root, "pool"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if r, err := filepath.Rel(root, p); err == nil {
				inPool[filepath.ToSlash(r)] = true
			}
		}
		return nil
	})
	for p := range inPool {
		if !referenced[p] {
			c.add("%s is in the pool and in no Packages file", p)
		}
	}
	// A dependency on a package of the release is met in the same architecture, at the version it asks for.
	for _, s := range stanzas {
		for _, field := range []string{"Depends", "Recommends"} {
			for _, item := range strings.Split(s.f[field], ",") {
				item = strings.TrimSpace(item)
				name, rest, hasVer := strings.Cut(item, " (")
				if !strings.HasPrefix(name, "sluis") {
					continue
				}
				if !hasVer || !strings.HasPrefix(rest, "= ") || !strings.HasSuffix(rest, ")") {
					c.add("%s %s: %s %q of the release is not an exact version", s.f["Package"], s.arch, field, item)
					continue
				}
				if !byArch[s.arch][pk{name, strings.TrimSuffix(strings.TrimPrefix(rest, "= "), ")")}] {
					c.add("%s %s: %s %q is not in the %s Packages", s.f["Package"], s.arch, field, item, s.arch)
				}
			}
		}
	}
}

func atoiOr(s string, d int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return n
}

// ---- dnf

type xmlRepomd struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Checksum struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"checksum"`
		OpenChecksum struct {
			Value string `xml:",chardata"`
		} `xml:"open-checksum"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Size     int `xml:"size"`
		OpenSize int `xml:"open-size"`
	} `xml:"data"`
}

type xmlEVR struct {
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

type xmlEntry struct {
	Name  string `xml:"name,attr"`
	Flags string `xml:"flags,attr"`
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

type xmlPrimary struct {
	Count    int `xml:"packages,attr"`
	Packages []struct {
		Name     string `xml:"name"`
		Arch     string `xml:"arch"`
		Version  xmlEVR `xml:"version"`
		Checksum struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"checksum"`
		Size struct {
			Package int `xml:"package,attr"`
		} `xml:"size"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
		Provides   []xmlEntry `xml:"format>provides>entry"`
		Requires   []xmlEntry `xml:"format>requires>entry"`
		Recommends []xmlEntry `xml:"format>recommends>entry"`
	} `xml:"package"`
}

type xmlPkgids struct {
	Count    int `xml:"packages,attr"`
	Packages []struct {
		Pkgid string `xml:"pkgid,attr"`
		Name  string `xml:"name,attr"`
	} `xml:"package"`
}

func (c *checker) dnf(dir, arch string) {
	rel := func(p string) string { return c.rel(filepath.Join(dir, filepath.FromSlash(p))) }
	for _, unsigned := range []string{"repodata/repomd.xml.asc", "repodata/repomd.xml.key"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(unsigned))); err == nil {
			c.add("%s: a signature file in a tree that is unsigned by design", rel(unsigned))
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "repodata", "repomd.xml")) //nolint:gosec // the tree being checked
	if err != nil {
		c.add("dnf %s: %v", arch, err)
		return
	}
	var md xmlRepomd
	if err := xml.Unmarshal(raw, &md); err != nil {
		c.add("%s: %v", rel("repodata/repomd.xml"), err)
		return
	}
	bodies := map[string][]byte{}
	for _, d := range md.Data {
		gz, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(d.Location.Href))) //nolint:gosec // the tree being checked
		if err != nil {
			c.add("%s lists %s: %v", rel("repodata/repomd.xml"), d.Location.Href, err)
			continue
		}
		if d.Checksum.Type != "sha256" || strings.TrimSpace(d.Checksum.Value) != sha256hex(gz) || d.Size != len(gz) {
			c.add("%s: %s has the checksum %q and the size %d, the file has %s and %d", rel("repodata/repomd.xml"), d.Type, d.Checksum.Value, d.Size, sha256hex(gz), len(gz))
		}
		if !strings.Contains(d.Location.Href, sha256hex(gz)) {
			c.add("%s: %s is not named by its checksum", rel("repodata/repomd.xml"), d.Location.Href)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		var un []byte
		if err == nil {
			un, err = io.ReadAll(zr)
		}
		if err != nil {
			c.add("%s: %v", rel(d.Location.Href), err)
			continue
		}
		if strings.TrimSpace(d.OpenChecksum.Value) != sha256hex(un) || d.OpenSize != len(un) {
			c.add("%s: %s has the open-checksum %q and the open-size %d, the data has %s and %d", rel("repodata/repomd.xml"), d.Type, d.OpenChecksum.Value, d.OpenSize, sha256hex(un), len(un))
		}
		bodies[d.Type] = un
	}
	var pri xmlPrimary
	if b, ok := bodies["primary"]; !ok {
		c.add("%s has no primary", rel("repodata/repomd.xml"))
		return
	} else if err := xml.Unmarshal(b, &pri); err != nil {
		c.add("primary.xml of %s: %v", arch, err)
		return
	}
	if pri.Count != len(pri.Packages) {
		c.add("primary.xml of %s says packages=%d and holds %d", arch, pri.Count, len(pri.Packages))
	}
	ids := map[string]string{}
	type nv struct{ name, evr string }
	have, haveVer := map[nv]bool{}, map[nv]bool{}
	located := map[string]bool{}
	for _, p := range pri.Packages {
		if p.Arch != arch && p.Arch != "noarch" {
			c.add("primary.xml of %s lists %s for %s", arch, p.Name, p.Arch)
		}
		ids[strings.TrimSpace(p.Checksum.Value)] = p.Name
		have[nv{p.Name, p.Version.Ver + "-" + p.Version.Rel}] = true
		haveVer[nv{p.Name, p.Version.Ver}] = true
		located[path.Clean(p.Location.Href)] = true
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p.Location.Href))) //nolint:gosec // the tree being checked
		if err != nil {
			c.add("primary.xml of %s: %s: %v", arch, p.Name, err)
			continue
		}
		if p.Checksum.Type != "sha256" || strings.TrimSpace(p.Checksum.Value) != sha256hex(body) || p.Size.Package != len(body) {
			c.add("primary.xml of %s: %s has the checksum %q and %d bytes, the file has %s and %d", arch, p.Name, p.Checksum.Value, p.Size.Package, sha256hex(body), len(body))
		}
	}
	for _, typ := range []string{"filelists", "other"} {
		var l xmlPkgids
		b, ok := bodies[typ]
		if !ok {
			c.add("%s has no %s", rel("repodata/repomd.xml"), typ)
			continue
		}
		if err := xml.Unmarshal(b, &l); err != nil {
			c.add("%s.xml of %s: %v", typ, arch, err)
			continue
		}
		if l.Count != len(l.Packages) || len(l.Packages) != len(pri.Packages) {
			c.add("%s.xml of %s holds %d packages (says %d), primary.xml %d", typ, arch, len(l.Packages), l.Count, len(pri.Packages))
		}
		for _, p := range l.Packages {
			if ids[p.Pkgid] != p.Name {
				c.add("%s.xml of %s: %s has the pkgid %s, which primary.xml does not give it", typ, arch, p.Name, p.Pkgid)
			}
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "Packages"))
	for _, e := range entries {
		if !located["Packages/"+e.Name()] {
			c.add("%s is in Packages/ and in no primary.xml of %s", e.Name(), arch)
		}
	}
	// A dependency on a package of the release is met in the same tree, at the version it asks for.
	for _, p := range pri.Packages {
		for _, group := range [][]xmlEntry{p.Requires, p.Recommends} {
			for _, e := range group {
				if !strings.HasPrefix(e.Name, "sluis") {
					continue
				}
				// A dependency written without a release is met by any release of that version.
				met := haveVer[nv{e.Name, e.Ver}]
				if e.Rel != "" {
					met = have[nv{e.Name, e.Ver + "-" + e.Rel}]
				}
				if e.Flags != "EQ" || !met {
					c.add("%s %s: the dependency %s %s %s-%s is not an exact version of a package in this tree", p.Name, arch, e.Name, e.Flags, e.Ver, e.Rel)
				}
			}
		}
	}
}

// ProblemsText is the problems as one text, sorted, for a message.
func ProblemsText(p []string) string {
	q := append([]string(nil), p...)
	sort.Strings(q)
	return strings.Join(q, "\n")
}
