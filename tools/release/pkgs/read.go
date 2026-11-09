package pkgs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Rel is one dependency as the package states it.
type Rel struct {
	Raw     string // the text of the package, which is what the package manager reads
	Name    string
	Op      string // "", "=", ">=", "<=", "<", ">"
	Version string
}

// PFile is one entry of the file list of a package.
type PFile struct {
	Path   string
	Kind   byte   // 'f' regular, 'd' directory, 'l' symlink, '?' anything else
	Mode   uint32 // permission bits and setuid, setgid, sticky
	Owner  string
	Group  string
	Size   int64
	SHA256 string // regular files
	Link   string // symlinks
	Body   []byte // a .deb only, and only for the files below /usr/lib: the unit files and the sysusers and tmpfiles files
}

// Pkg is what a package file says, read back from the file and not from what built it.
type Pkg struct {
	File       string
	Format     Format
	Name       string
	Version    string // as the metadata states it: the Version of a .deb, the Version (without Release) of an .rpm
	Release    string // .rpm only
	Arch       string // the architecture as the format names it
	Depends    []Rel
	Recommends []Rel
	Suggests   []Rel
	Files      []PFile
	Scripts    map[string]string // preinst, postinst, prerm, postrm: the rpm scriptlets are named after their deb counterparts
	RPMLib     []string          // .rpm: the rpmlib(...) features the package asks of rpm
	Payload    string            // .rpm: the compressor of the payload
	Fields     []string          // .deb: the names of the fields of the control file
	Tags       []uint32          // .rpm: the tags of the header
	Provides   []string          // .rpm: what the package provides, as name or name = version
	Members    []string          // .deb: the members of the ar archive and of the control archive
	DigestAlgo int               // .rpm: the algorithm of the file digests (8 is SHA-256)
	SHA256     string            // of the package file
}

// ReadPackage reads a .deb or an .rpm.
func ReadPackage(p string) (*Pkg, error) {
	raw, err := os.ReadFile(p) //nolint:gosec // a file this tool built, or is asked to check
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	var pk *Pkg
	switch {
	case strings.HasSuffix(p, ".deb"):
		pk, err = readDeb(raw)
	case strings.HasSuffix(p, ".rpm"):
		pk, err = readRPM(raw)
	default:
		return nil, fmt.Errorf("%s is neither a .deb nor an .rpm", p)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	pk.File = p
	pk.SHA256 = hex.EncodeToString(sum[:])
	sort.Slice(pk.Files, func(i, j int) bool { return pk.Files[i].Path < pk.Files[j].Path })
	return pk, nil
}

// ---- deb

// readDeb reads the ar archive of a .deb: debian-binary, control.tar.gz and data.tar.gz. Other compressions are refused here
// because the build asks for gzip alone; a package that uses another is not the one this tool built.
func readDeb(raw []byte) (*Pkg, error) {
	const magic = "!<arch>\n"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, errors.New("not an ar archive")
	}
	members := map[string][]byte{}
	var order []string
	b := raw[len(magic):]
	for len(b) > 0 {
		if len(b) < 60 || string(b[58:60]) != "`\n" {
			return nil, errors.New("a broken ar header")
		}
		name := strings.TrimRight(strings.TrimSpace(string(b[:16])), "/")
		var size int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(b[48:58])), "%d", &size); err != nil || size < 0 || 60+size > len(b) {
			return nil, errors.New("a broken ar size")
		}
		members[name] = b[60 : 60+size]
		order = append(order, name)
		adv := 60 + size
		if adv%2 == 1 && adv < len(b) {
			adv++
		}
		b = b[adv:]
	}
	if len(order) < 3 || order[0] != "debian-binary" || string(members["debian-binary"]) != "2.0\n" {
		return nil, fmt.Errorf("members %v: want debian-binary 2.0 first", order)
	}
	ctl, data := members["control.tar.gz"], members["data.tar.gz"]
	if ctl == nil || data == nil {
		return nil, fmt.Errorf("members %v: want control.tar.gz and data.tar.gz (the build asks for gzip)", order)
	}
	pk := &Pkg{Format: Deb, Scripts: map[string]string{}, Members: order}
	cm, err := readTarGz(ctl)
	if err != nil {
		return nil, fmt.Errorf("control.tar.gz: %w", err)
	}
	for n, body := range cm {
		switch n {
		case "control":
			if err := parseControl(pk, string(body)); err != nil {
				return nil, err
			}
		case "preinst", "postinst", "prerm", "postrm":
			pk.Scripts[n] = string(body)
		case "md5sums":
		default:
			return nil, fmt.Errorf("control.tar.gz holds %s, which the build does not make", n)
		}
	}
	if _, ok := cm["control"]; !ok {
		return nil, errors.New("no control file")
	}
	if err := readDebData(pk, data); err != nil {
		return nil, fmt.Errorf("data.tar.gz: %w", err)
	}
	return pk, nil
}

// What a package may inflate to. The check runs in the job that holds the write tokens, over files its build job made, and a gzip
// of a few kilobytes can inflate to terabytes: every stream is read through a cap and a stream over it is an error that says so.
// They are variables for the tests, which lower them; nothing else sets them.
var (
	maxPayload = int64(1 << 30) // the data archive of a .deb and the cpio of an .rpm: 1 GiB
	maxControl = int64(8 << 20) // the control archive of a .deb: 8 MiB
)

// maxUnitFile is the size up to which the body of a file below /usr/lib is kept (the unit files and the sysusers and tmpfiles files).
const maxUnitFile = 1 << 16

// capReader is a reader that fails, instead of ending, when more than its limit has been read through it.
type capReader struct {
	r     io.Reader
	left  int64
	limit int64
	what  string
}

func newCap(r io.Reader, limit int64, what string) *capReader {
	return &capReader{r: r, left: limit, limit: limit, what: what}
}

func (c *capReader) Read(p []byte) (int, error) {
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1] // one byte more than the limit, to see that there is more
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return max(0, n+int(c.left)), fmt.Errorf("%s inflates to more than %d bytes: refused (a gzip bomb, or a package larger than any release's)", c.what, c.limit)
	}
	return n, err
}

// tarEntryOK refuses the entries that the cap of the inflated stream cannot see. Go's tar reader synthesizes the holes of a sparse
// file (a PAX sparse entry whose GNU.sparse.realsize is 8 GiB reads as 8 GiB of zeros that cost no byte of the stream), so the size
// of the entry in its header is counted against the cap too, and a sparse entry of any kind is refused: a package has none.
func tarEntryOK(h *tar.Header, total *int64, limit int64, what string) error {
	if h.Typeflag == tar.TypeGNUSparse {
		return fmt.Errorf("%s holds the sparse entry %s: a package has none", what, h.Name)
	}
	for k := range h.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return fmt.Errorf("%s holds the entry %s with the sparse record %s: a package has none", what, h.Name, k)
		}
	}
	if h.Size < 0 || h.Size > limit {
		return fmt.Errorf("%s holds the entry %s of %d bytes, over the cap of %d (a gzip bomb, or a package larger than any release's)", what, h.Name, h.Size, limit)
	}
	*total += h.Size
	if *total > limit {
		return fmt.Errorf("%s holds entries that add up to more than %d bytes: refused", what, limit)
	}
	return nil
}

func readTarGz(gz []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(newCap(zr, maxControl, "the control archive"))
	res := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		if err := tarEntryOK(h, &total, maxControl, "the control archive"); err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		res[strings.TrimPrefix(h.Name, "./")] = body
	}
}

func readDebData(pk *Pkg, gz []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	tr := tar.NewReader(newCap(zr, maxPayload, "the data archive"))
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := tarEntryOK(h, &total, maxPayload, "the data archive"); err != nil {
			return err
		}
		f := PFile{Path: "/" + strings.Trim(strings.TrimPrefix(h.Name, "."), "/"), Owner: h.Uname, Group: h.Gname, Size: h.Size}
		if f.Path == "/" {
			continue
		}
		f.Mode = uint32(h.Mode & 0o7777)
		switch h.Typeflag {
		case tar.TypeReg:
			f.Kind = 'f'
			// The file is hashed as it streams; only the head of a file below /usr/lib is held, and kept if the file is that small.
			sum := sha256.New()
			var head []byte
			if strings.HasPrefix(f.Path, "/usr/lib/") {
				if head, err = io.ReadAll(io.LimitReader(tr, maxUnitFile+1)); err != nil {
					return err
				}
				_, _ = sum.Write(head)
			}
			if _, err := io.Copy(sum, tr); err != nil { //nolint:gosec // tr reads through newCap: a stream over maxPayload is an error
				return err
			}
			f.SHA256 = hex.EncodeToString(sum.Sum(nil))
			if len(head) > 0 && len(head) <= maxUnitFile {
				f.Body = head
			}
		case tar.TypeDir:
			f.Kind = 'd'
		case tar.TypeSymlink:
			f.Kind, f.Link = 'l', h.Linkname
		default:
			f.Kind = '?'
		}
		pk.Files = append(pk.Files, f)
	}
}

// parseControl reads the fields of a control file. A field that continues on a line that starts with a space is joined.
func parseControl(pk *Pkg, text string) error {
	fields := map[string]string{}
	var key string
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if l == "" {
			return errors.New("control: an empty line")
		}
		if l[0] == ' ' || l[0] == '\t' {
			if key == "" {
				return errors.New("control: a continuation with no field")
			}
			fields[key] += "\n" + strings.TrimSpace(l)
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return fmt.Errorf("control: %q is not a field", l)
		}
		key = k
		if _, dup := fields[k]; dup {
			return fmt.Errorf("control: %s twice", k)
		}
		fields[k] = strings.TrimSpace(v)
	}
	for k := range fields {
		pk.Fields = append(pk.Fields, k)
	}
	sort.Strings(pk.Fields)
	pk.Name, pk.Version, pk.Arch = fields["Package"], fields["Version"], fields["Architecture"]
	if pk.Name == "" || pk.Version == "" || pk.Arch == "" {
		return errors.New("control: Package, Version or Architecture is empty")
	}
	var err error
	if pk.Depends, err = debRels(fields["Depends"]); err != nil {
		return err
	}
	if pk.Recommends, err = debRels(fields["Recommends"]); err != nil {
		return err
	}
	if pk.Suggests, err = debRels(fields["Suggests"]); err != nil {
		return err
	}
	return nil
}

// debRels splits a Depends-like field. The text is kept as written (Raw), and parsed only as far as the check needs: name, and one
// optional (op version). Anything else, including a template that was not expanded, leaves Op empty and Version set to the
// rest, which the check refuses.
func debRels(v string) ([]Rel, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	var res []Rel
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		r := Rel{Raw: item}
		name, rest, hasVer := strings.Cut(item, " (")
		r.Name = name
		if hasVer {
			if !strings.HasSuffix(rest, ")") {
				return nil, fmt.Errorf("the dependency %q has no closing parenthesis", item)
			}
			op, ver, ok := strings.Cut(strings.TrimSuffix(rest, ")"), " ")
			if !ok {
				return nil, fmt.Errorf("the dependency %q has no version after its operator", item)
			}
			r.Op, r.Version = op, ver
		}
		res = append(res, r)
	}
	return res, nil
}

// ---- rpm

// The tags of an rpm header that the checks read (rpm's tag numbers, lib/rpmtag.h).
const (
	tagName         = 1000
	tagVersion      = 1001
	tagRelease      = 1002
	tagArch         = 1022
	tagPreIn        = 1023
	tagPostIn       = 1024
	tagPreUn        = 1025
	tagPostUn       = 1026
	tagFileModes    = 1030
	tagFileSizes    = 1028
	tagFileDigests  = 1035
	tagFileLinkTos  = 1036
	tagFileFlags    = 1037
	tagFileUser     = 1039
	tagFileGroup    = 1040
	tagRequireFlags = 1048
	tagRequireName  = 1049
	tagRequireVer   = 1050
	tagDirIndexes   = 1116
	tagBasenames    = 1117
	tagDirnames     = 1118
	tagPayloadComp  = 1125
	tagPreTrans     = 1151
	tagPostTrans    = 1152
	tagRecommendN   = 5046
	tagRecommendV   = 5047
	tagRecommendF   = 5048
	tagSuggestN     = 5049
	tagSuggestV     = 5050
	tagSuggestF     = 5051
	tagLongFileSize = 5008
	tagDigestAlgo   = 5011
	tagProvideName  = 1047
	tagProvideFlags = 1112
	tagProvideVer   = 1113
	tagPayloadDig   = 5092
)

const (
	sensLess    = 0x02
	sensGreater = 0x04
	sensEqual   = 0x08
	sensRPMLib  = 1 << 24
)

type rpmEntry struct {
	typ   uint32
	count uint32
	data  []byte // from the offset to the end of the store
}

type rpmHeader map[uint32]rpmEntry

// rpmTypeSize is the size in bytes of one value of the fixed-size types of an rpm header (INT8 and CHAR 1, INT16 2, INT32 4,
// INT64 8); strings have none.
var rpmTypeSize = map[uint32]int{1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}

// fits says whether the count of an entry is possible for the data it points to. The count is read from the file, so it is
// not trusted: a string takes at least its NUL, a number its size, and a count of 0x7fffffff over a few bytes is a header that
// would have made the readers loop and allocate until the memory was gone. Every string of an array must end inside the data.
//
// Entries may point anywhere in the store, so many of them can point at the same long run of bytes, and a walk of each would be
// quadratic (2000 entries over an 8 MiB store took 71 s). All the walks of one header share a budget of twice the size of its store,
// plus a little; a header whose strings overlap each other, which no rpm does, runs it out and is refused.
func (e rpmEntry) fits(tag uint32, budget *int64) error {
	bad := func(why string) error {
		return fmt.Errorf("tag %d has the count %d, which %s the %d bytes of the store left", tag, e.count, why, len(e.data))
	}
	switch e.typ {
	case 6, 9:
		k := bytes.IndexByte(e.data, 0)
		if err := spend(budget, tag, k, len(e.data)); err != nil {
			return err
		}
		if e.count != 1 || k < 0 {
			return bad("is not one string ended by a NUL in")
		}
	case 8:
		if int64(e.count) > int64(len(e.data)) {
			return bad("is more than")
		}
		d := e.data
		for i := uint32(0); i < e.count; i++ {
			k := bytes.IndexByte(d, 0)
			if err := spend(budget, tag, k, len(d)); err != nil {
				return err
			}
			if k < 0 {
				return bad("is more strings than there are NULs in")
			}
			d = d[k+1:]
		}
	default:
		size, ok := rpmTypeSize[e.typ]
		if !ok {
			return fmt.Errorf("tag %d has the type %d, which the reader does not know", tag, e.typ)
		}
		if int64(e.count)*int64(size) > int64(len(e.data)) {
			return bad("takes more than")
		}
	}
	return nil
}

// spend takes the bytes a scan for a NUL looked at (k+1 when it found one at k, all n when it found none) from the budget.
func spend(budget *int64, tag uint32, k, n int) error {
	if k < 0 {
		*budget -= int64(n)
	} else {
		*budget -= int64(k) + 1
	}
	if *budget < 0 {
		return fmt.Errorf("tag %d: the strings of the header overlap or are read over and over (the walk of the header ran out of its budget): refused", tag)
	}
	return nil
}

// maxRPMStore is the largest store of a header the reader takes: 64 MiB, where the store of a real package is at most a few MB
// (MEASURED 2026-11-09, about 2.5 MB for the biggest of 27 packages of Rocky Linux 10 and Amazon Linux 2023).
const maxRPMStore = 64 << 20

// maxStrings and maxFixedBytes bound what the entries of one header may claim whatever its store: the readers build 16 bytes of slice and
// about 100 bytes of Rel for each string, and a package of this release has a handful of files. A real package of a distribution
// has far fewer strings than a quarter of its store (about a twentieth, MEASURED), and none has more than the first.
const (
	maxStrings    = 1 << 18
	maxFixedBytes = 16 << 20
)

func readRPMHeader(b []byte, pad bool) (rpmHeader, []byte, error) {
	if len(b) < 16 || !bytes.Equal(b[:4], []byte{0x8e, 0xad, 0xe8, 0x01}) {
		return nil, nil, errors.New("no header magic")
	}
	n := binary.BigEndian.Uint32(b[8:12])
	sz := binary.BigEndian.Uint32(b[12:16])
	if sz > maxRPMStore {
		return nil, nil, fmt.Errorf("the store of the header is %d bytes, over the %d the reader takes", sz, maxRPMStore)
	}
	if n > 1<<16 || uint64(16)+uint64(n)*16+uint64(sz) > uint64(len(b)) {
		return nil, nil, errors.New("a header larger than the file")
	}
	idx := b[16 : 16+n*16]
	store := b[16+n*16 : 16+n*16+sz]
	// Before anything is read or allocated, the sums of what the entries claim are held to the size of the store: a string takes at
	// least a byte and a real package has at most a twentieth as many strings as bytes (MEASURED), so all the strings of a header are
	// at most a quarter of the store and a little more, and the numbers and bytes of it at most the store and a little more. A header
	// that claims more has entries that overlap, and the readers would build slices of 16 bytes per string for each of them (a crafted
	// package of 64 MiB took 5.9 GB).
	var strs, fixed int64
	for i := uint32(0); i < n; i++ {
		e := idx[i*16 : i*16+16]
		typ, cnt := binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[12:])
		switch typ {
		case 6, 8, 9:
			strs += int64(cnt)
		default:
			fixed += int64(cnt) * int64(rpmTypeSize[typ])
		}
	}
	if strs > min(int64(sz)/4+4096, maxStrings) {
		return nil, nil, fmt.Errorf("the entries of the header claim %d strings in a store of %d bytes: more than a quarter of its size and 4096, or than %d, which no package has", strs, sz, maxStrings)
	}
	if fixed > min(int64(sz)+4096, maxFixedBytes) {
		return nil, nil, fmt.Errorf("the entries of the header claim %d bytes of numbers in a store of %d bytes: more than its size and 4096, or than %d, which no package has", fixed, sz, maxFixedBytes)
	}
	h := rpmHeader{}
	budget := 2*int64(sz) + 4096
	for i := uint32(0); i < n; i++ {
		e := idx[i*16 : i*16+16]
		tag, typ, off, cnt := binary.BigEndian.Uint32(e[0:]), binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[8:]), binary.BigEndian.Uint32(e[12:])
		if off > sz {
			return nil, nil, fmt.Errorf("tag %d points outside the store", tag)
		}
		e2 := rpmEntry{typ: typ, count: cnt, data: store[off:]}
		if err := e2.fits(tag, &budget); err != nil {
			return nil, nil, err
		}
		h[tag] = e2
	}
	rest := b[16+n*16+sz:]
	if pad {
		if p := (16 + int(n)*16 + int(sz)) % 8; p != 0 {
			if len(rest) < 8-p {
				return nil, nil, errors.New("short padding")
			}
			rest = rest[8-p:]
		}
	}
	return h, rest, nil
}

func (h rpmHeader) str(tag uint32) string {
	e, ok := h[tag]
	if !ok || (e.typ != 6 && e.typ != 9) {
		return ""
	}
	s, _, _ := bytes.Cut(e.data, []byte{0})
	return string(s)
}

func (h rpmHeader) strs(tag uint32) []string {
	e, ok := h[tag]
	if !ok || e.typ != 8 {
		return nil
	}
	if int64(e.count) > int64(len(e.data)) {
		return nil
	}
	res := make([]string, 0, e.count) // the count was held to the data and to the sums of the header when it was read
	d := e.data
	for i := uint32(0); i < e.count; i++ {
		s, rest, _ := bytes.Cut(d, []byte{0})
		res = append(res, string(s))
		d = rest
	}
	return res
}

func (h rpmHeader) u32s(tag uint32) []uint32 {
	e, ok := h[tag]
	if !ok || int64(e.count)*int64(rpmTypeSize[e.typ]) > int64(len(e.data)) {
		return nil
	}
	var res []uint32
	for i := uint32(0); i < e.count; i++ {
		switch e.typ {
		case 3:
			if len(e.data) < int(2*i+2) {
				return res
			}
			res = append(res, uint32(binary.BigEndian.Uint16(e.data[2*i:])))
		case 4:
			if len(e.data) < int(4*i+4) {
				return res
			}
			res = append(res, binary.BigEndian.Uint32(e.data[4*i:]))
		}
	}
	return res
}

func (h rpmHeader) u64s(tag uint32) []uint64 {
	e, ok := h[tag]
	if !ok || e.typ != 5 || int64(e.count)*8 > int64(len(e.data)) {
		return nil
	}
	var res []uint64
	for i := uint32(0); i < e.count; i++ {
		if len(e.data) < int(8*i+8) {
			return res
		}
		res = append(res, binary.BigEndian.Uint64(e.data[8*i:]))
	}
	return res
}

func rpmRels(names, vers []string, flags []uint32) ([]Rel, []string) {
	var res []Rel
	var lib []string
	for i, n := range names {
		var v string
		var f uint32
		if i < len(vers) {
			v = vers[i]
		}
		if i < len(flags) {
			f = flags[i]
		}
		if f&sensRPMLib != 0 || strings.HasPrefix(n, "rpmlib(") {
			lib = append(lib, n)
			continue
		}
		r := Rel{Name: n, Version: v}
		switch {
		case f&sensLess != 0 && f&sensEqual != 0:
			r.Op = "<="
		case f&sensGreater != 0 && f&sensEqual != 0:
			r.Op = ">="
		case f&sensLess != 0:
			r.Op = "<"
		case f&sensGreater != 0:
			r.Op = ">"
		case f&sensEqual != 0:
			r.Op = "="
		}
		r.Raw = n
		if r.Op != "" {
			r.Raw = n + " " + r.Op + " " + v
		}
		res = append(res, r)
	}
	return res, lib
}

func readRPM(raw []byte) (*Pkg, error) {
	if len(raw) < 96 || !bytes.Equal(raw[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, errors.New("not an rpm")
	}
	_, rest, err := readRPMHeader(raw[96:], true)
	if err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	h, payload, err := readRPMHeader(rest, false)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	pk := &Pkg{Format: RPM, Scripts: map[string]string{}, Name: h.str(tagName), Version: h.str(tagVersion), Release: h.str(tagRelease),
		Arch: h.str(tagArch), Payload: h.str(tagPayloadComp)}
	if pk.Name == "" || pk.Version == "" || pk.Arch == "" {
		return nil, errors.New("the name, the version or the architecture is empty")
	}
	if a := h.u32s(tagDigestAlgo); len(a) == 1 {
		pk.DigestAlgo = int(a[0])
	}
	for t := range h {
		pk.Tags = append(pk.Tags, t)
	}
	sort.Slice(pk.Tags, func(i, j int) bool { return pk.Tags[i] < pk.Tags[j] })
	provides, _ := rpmRels(h.strs(tagProvideName), h.strs(tagProvideVer), h.u32s(tagProvideFlags))
	for _, p := range provides {
		pk.Provides = append(pk.Provides, p.Raw)
	}
	var lib []string
	pk.Depends, lib = rpmRels(h.strs(tagRequireName), h.strs(tagRequireVer), h.u32s(tagRequireFlags))
	pk.RPMLib = lib
	pk.Recommends, _ = rpmRels(h.strs(tagRecommendN), h.strs(tagRecommendV), h.u32s(tagRecommendF))
	pk.Suggests, _ = rpmRels(h.strs(tagSuggestN), h.strs(tagSuggestV), h.u32s(tagSuggestF))
	for tag, name := range map[uint32]string{tagPreIn: "preinst", tagPostIn: "postinst", tagPreUn: "prerm", tagPostUn: "postrm", tagPreTrans: "pretrans", tagPostTrans: "posttrans"} {
		if s := h.str(tag); s != "" {
			pk.Scripts[name] = s
		}
	}
	bases, dirs, dirIdx := h.strs(tagBasenames), h.strs(tagDirnames), h.u32s(tagDirIndexes)
	modes, users, groups := h.u32s(tagFileModes), h.strs(tagFileUser), h.strs(tagFileGroup)
	digests, links := h.strs(tagFileDigests), h.strs(tagFileLinkTos)
	sizes := h.u64s(tagLongFileSize)
	if sizes == nil {
		for _, s := range h.u32s(tagFileSizes) {
			sizes = append(sizes, uint64(s))
		}
	}
	n := len(bases)
	if len(dirIdx) != n || len(modes) != n || len(users) != n || len(groups) != n || len(digests) != n || len(links) != n || len(sizes) != n {
		return nil, fmt.Errorf("the file tables disagree (%d names, %d dirs, %d modes, %d users, %d groups, %d digests, %d links, %d sizes)",
			n, len(dirIdx), len(modes), len(users), len(groups), len(digests), len(links), len(sizes))
	}
	for i := 0; i < n; i++ {
		if int(dirIdx[i]) >= len(dirs) {
			return nil, errors.New("a directory index outside the table")
		}
		f := PFile{Path: strings.TrimSuffix(dirs[dirIdx[i]], "/") + "/" + bases[i], Owner: users[i], Group: groups[i], Mode: modes[i] & 0o7777,
			Size: int64(sizes[i])} //nolint:gosec // a file size from a package that is being checked
		switch modes[i] & 0o170000 {
		case 0o100000:
			f.Kind, f.SHA256 = 'f', digests[i]
		case 0o040000:
			f.Kind = 'd'
		case 0o120000:
			f.Kind, f.Link = 'l', links[i]
		default:
			f.Kind = '?'
		}
		pk.Files = append(pk.Files, f)
	}
	if err := checkPayload(h, payload, pk.Files); err != nil {
		return nil, err
	}
	return pk, nil
}

// checkPayload reads the payload of an .rpm, which is a gzip of a cpio archive, and holds it to the header: the digest of the
// payload that the header records, and for each regular file the same size and SHA-256 as the header lists. A byte of the payload
// that differs from what the header says is a read error, so the check never trusts a header over the files it describes.
func checkPayload(h rpmHeader, payload []byte, files []PFile) error {
	d := h.strs(tagPayloadDig)
	if len(d) != 1 {
		return errors.New("the header records no payload digest")
	}
	if sum := sha256.Sum256(payload); d[0] != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("the payload has the SHA-256 %x, the header says %s", sum, d[0])
	}
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	cpio, err := io.ReadAll(newCap(zr, maxPayload, "the payload"))
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	want := map[string]PFile{}
	for _, f := range files {
		if f.Kind == 'f' {
			want[f.Path] = f
		}
	}
	for len(cpio) > 0 {
		if len(cpio) < 110 || string(cpio[:6]) != "070701" {
			return errors.New("payload: not a newc cpio archive")
		}
		field := func(i int) (int, error) {
			var v int
			_, err := fmt.Sscanf(string(cpio[6+8*i:14+8*i]), "%x", &v)
			return v, err
		}
		size, err1 := field(6)
		nameLen, err2 := field(11)
		if err1 != nil || err2 != nil || nameLen < 1 || size < 0 {
			return errors.New("payload: a broken cpio header")
		}
		nameEnd := 110 + nameLen
		dataStart := (nameEnd + 3) &^ 3
		dataEnd := dataStart + size
		if nameEnd > len(cpio) || dataEnd > len(cpio) {
			return errors.New("payload: a truncated cpio entry")
		}
		name := string(cpio[110 : nameEnd-1])
		if name == "TRAILER!!!" {
			break
		}
		p := "/" + strings.TrimPrefix(strings.TrimPrefix(name, "."), "/")
		if f, ok := want[p]; ok {
			sum := sha256.Sum256(cpio[dataStart:dataEnd])
			if int64(size) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
				return fmt.Errorf("payload: %s differs from what the header lists", p)
			}
			delete(want, p)
		}
		next := (dataEnd + 3) &^ 3
		if next > len(cpio) {
			next = len(cpio)
		}
		cpio = cpio[next:]
	}
	if len(want) > 0 {
		var miss []string
		for p := range want {
			miss = append(miss, p)
		}
		sort.Strings(miss)
		return fmt.Errorf("payload: lacks %v, which the header lists", miss)
	}
	return nil
}
