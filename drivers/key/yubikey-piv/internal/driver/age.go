package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A PIV card does not store when a key was generated, and key@ needs to know (ADR 0041: a revocation of a purpose
// refuses the keys made at or before its declaration, and not a replacement made after it). So the driver records the
// time itself when it generates a key in a slot, in its own state directory, together with the thumbprint of the key's
// public half. Ensure reports the time only when the record's thumbprint is that of the key the slot holds now: a
// record for a key that was replaced, or none (a key that the owners provisioned in a ceremony, a state directory that
// was lost), means the age is unknown, and key@ treats a key of unknown age as older than any revocation, which fails
// closed.

// agesFile is the file of the records in the state directory: one line per purpose, "<purpose> <unix seconds> <hex
// of the SHA-256 of the key's SubjectPublicKeyInfo>".
const agesFile = "created-at.txt"

// age is when a key was generated, and which key.
type age struct {
	at    time.Time
	thumb string // hex SHA-256 of the SPKI of the key
}

// thumbOf names a key by the SHA-256 of its SubjectPublicKeyInfo, as the record keeps it.
func thumbOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// ages are the records of the state directory. A zero ages has no directory and records nothing.
type ages struct {
	dir string
	m   map[string]age
}

// openAges reads the records of dir. A dir that is empty disables them. A directory that is missing, not the driver's
// or open to others is an error; a file that is damaged is not: it is a lost record, which only makes ages unknown,
// and the driver logs it and goes on.
func openAges(dir string) (*ages, error) {
	a := &ages{dir: dir, m: map[string]age{}}
	if dir == "" {
		return a, nil
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("state directory %s is missing", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int64(st.Uid) != int64(os.Getuid()) {
		return nil, fmt.Errorf("state directory %s is not owned by the driver's user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("state directory %s is open to group or world", dir)
	}
	path := filepath.Join(dir, agesFile)
	li, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil || !li.Mode().IsRegular() || li.Mode().Perm()&0o177 != 0 {
		slog.Warn("the record of key ages is not read: not a regular file with mode 0600; every age is unknown")
		return a, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // the driver's own state directory, checked above
	if err != nil {
		slog.Warn("the record of key ages cannot be read; every age is unknown")
		return a, nil
	}
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		f := strings.Fields(l)
		if len(f) != 3 {
			slog.Warn("the record of key ages is damaged; every age is unknown")
			return &ages{dir: dir, m: map[string]age{}}, nil
		}
		sec, perr := strconv.ParseInt(f[1], 10, 64)
		if perr != nil || sec <= 0 || len(f[2]) != 64 {
			slog.Warn("the record of key ages is damaged; every age is unknown")
			return &ages{dir: dir, m: map[string]age{}}, nil
		}
		a.m[f[0]] = age{at: time.Unix(sec, 0).UTC(), thumb: f[2]}
	}
	return a, nil
}

// of returns when the key with this SPKI was generated, if the record is of this key.
func (a *ages) of(purpose string, spki []byte) (time.Time, bool) {
	r, ok := a.m[purpose]
	if !ok || r.thumb != thumbOf(spki) {
		return time.Time{}, false
	}
	return r.at, true
}

// record writes the age of a key that was just generated: a temporary file, synced, renamed over the file (0600), and the
// directory synced. Without a directory it records nothing.
func (a *ages) record(purpose string, spki []byte, at time.Time) error {
	if a.dir == "" {
		return nil
	}
	next := map[string]age{}
	for k, v := range a.m {
		next[k] = v
	}
	next[purpose] = age{at: at.UTC().Truncate(time.Second), thumb: thumbOf(spki)}
	var b strings.Builder
	for _, e := range slotPlan {
		if r, ok := next[e.purpose]; ok {
			fmt.Fprintf(&b, "%s %d %s\n", e.purpose, r.at.Unix(), r.thumb)
		}
	}
	f, err := os.CreateTemp(a.dir, agesFile+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(a.dir, agesFile)); err != nil {
		return err
	}
	d, err := os.Open(a.dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return err
	}
	a.m = next
	return nil
}
