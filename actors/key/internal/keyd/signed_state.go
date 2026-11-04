package keyd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"google.golang.org/protobuf/proto"
)

// The highest document of each kind that key@ verifies (the KeyPlan, the Boundary) is kept in key@'s own durable
// local state, so that a restart does not forget it and take an older document that store@ serves (ADR 0005, "Freshness at a cold start"; REQ-KEYS-110).
// The state is key@'s alone: a directory that the platform makes for it (--state-dir: the key-store directory of the
// board, the local volume), 0700, and never store@, whose word is what the mark guards against.
//
// What it guarantees: after a restart key@ refuses a document with a lower seq than the highest of its kind it ever
// verified on this node, and a second payload under that seq. What it does not: a node whose state is gone (a new disk, a purged
// volume, a first start) has no mark and takes the newest validly signed document store@ shows. A runtime with no
// durable local state at all (a function on Lambda) has the same residual at every cold start.

// The files of the marks, in the state directory: one for each kind that key@ verifies.
const (
	planMarkFile     = "keyplan.mark"
	boundaryMarkFile = "boundary.mark"
)

// seqMark is the seq and the SHA-384 of the payload of the highest document of a kind that key@ verified.
type seqMark struct {
	seq    uint64
	sha384 [48]byte
}

func (m seqMark) text() string {
	return fmt.Sprintf("seq %d\nsha384 %s\n", m.seq, hex.EncodeToString(m.sha384[:]))
}

// parseMark reads the file strictly. A mark that does not parse is an error: key@ does not start on a damaged file and
// does not guess, because a guessed mark is a mark the thief could have chosen; the operator removes it knowing why.
func parseMark(b []byte) (seqMark, error) {
	var m seqMark
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "seq ") || !strings.HasPrefix(lines[1], "sha384 ") {
		return m, errors.New("not a mark")
	}
	seq, err := strconv.ParseUint(strings.TrimPrefix(lines[0], "seq "), 10, 64)
	if err != nil || seq < 1 || seq >= 1<<53 {
		return m, errors.New("not a mark")
	}
	d, err := hex.DecodeString(strings.TrimPrefix(lines[1], "sha384 "))
	if err != nil || len(d) != len(m.sha384) {
		return m, errors.New("not a mark")
	}
	m.seq = seq
	copy(m.sha384[:], d)
	return m, nil
}

// checkStateDir refuses a state directory that is missing, that is not key@'s own (another owner than key@'s uid), or
// that group or world can reach, as it refuses the run directory. The platform makes it; key@ does not.
func checkStateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("state directory %s is missing", dir)
	}
	if !ownedBy(fi, os.Getuid()) {
		return fmt.Errorf("state directory %s is not owned by key@'s user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory %s is open to group or world", dir)
	}
	return nil
}

// ownedBy reports whether the file belongs to the uid. A file whose owner cannot be read is not owned.
func ownedBy(fi os.FileInfo, uid int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(uid)
}

// restoreMarks reads the marks of the state directory into the sequencers, before any document is fetched. save says
// whether this process will write the marks: the serving process does, the check command only reads them.
func (s *Server) restoreMarks(save bool) error {
	if s.cfg.StateDir == "" {
		return errors.New("keyd: no state directory")
	}
	if err := checkStateDir(s.cfg.StateDir); err != nil {
		return err
	}
	s.saveMark = save
	if err := restoreMark(s, s.plan); err != nil {
		return err
	}
	return restoreMark(s, s.boundary)
}

// restoreMark reads the mark of one kind.
func restoreMark[T proto.Message](s *Server, k *signedKind[T]) error {
	path := filepath.Join(s.cfg.StateDir, k.markFile)
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // a first start: nothing to restore
	}
	if err != nil {
		return fmt.Errorf("the %s mark cannot be read: %w", k.label, err)
	}
	// The mark is key@'s own file: a regular file, key@'s, and 0600. Another owner, wider bits or a link is a file
	// that something else could have written, and a guessed mark is a mark a thief could choose.
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o177 != 0 || !ownedBy(fi, os.Getuid()) {
		return fmt.Errorf("the %s mark %s is not key@'s own regular file with mode 0600: remove it to start without one, knowing that key@ then takes the newest validly signed %s store@ shows", k.label, path, k.label)
	}
	b, err := os.ReadFile(path) //nolint:gosec // key@'s own state directory, checked above
	if err != nil {
		return fmt.Errorf("the %s mark cannot be read: %w", k.label, err)
	}
	m, err := parseMark(b)
	if err != nil {
		return fmt.Errorf("the %s mark in %s is damaged (%w): remove it to start without one, knowing that key@ then takes the newest validly signed %s store@ shows", k.label, path, err, k.label)
	}
	k.seq.Restore(m.seq, m.sha384)
	return nil
}

// writeMark saves a mark durably, before the document it stands for is used: a temporary file, synced, renamed over
// the mark, and the directory synced. A document whose mark cannot be saved is not used.
func (s *Server) writeMark(file string, m seqMark) error {
	dir := s.cfg.StateDir
	f, err := os.CreateTemp(dir, file+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.WriteString(m.text()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
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
	if err := os.Rename(tmp, filepath.Join(dir, file)); err != nil {
		return err
	}
	d, err := os.Open(dir) //nolint:gosec // key@'s own state directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
