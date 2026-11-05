package driver

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// A released PIN that the card refused stops the PIN release on this board until a person unlocks it (ADR 0006,
// "Touch and PIN"). The stop is the driver's, in its state directory, so that a restart of key@ or of the driver does
// not try another released PIN: each try counts against the card's retry limit. While the mark is there,
// FinishPinRelease sends the card no PIN; a successful unlock on the admin socket removes it.

const refusedMarkFile = "pin-release.refused"

// refusedMark is the stop. The caller holds the service's mu.
type refusedMark struct {
	dir string // empty: in memory only (the check command, and tests without state)
	set bool
}

// restore reads the mark at start. Any file under the name is a stop: the mark fails closed, and a person who knows
// why removes it by unlocking the board.
func (m *refusedMark) restore() error {
	if m.dir == "" {
		return nil
	}
	_, err := os.Lstat(filepath.Join(m.dir, refusedMarkFile))
	switch {
	case err == nil:
		m.set = true
		slog.Warn("a released PIN was refused by the card before: no PIN release until the board is unlocked with sluis node unlock")
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("the PIN release stop cannot be read: %w", err)
	}
	return nil
}

// mark sets the stop, durably when the driver has a state directory. A mark that cannot be saved still holds in this
// process.
func (m *refusedMark) mark() {
	m.set = true
	if m.dir == "" {
		return
	}
	if err := writeSynced(m.dir, refusedMarkFile, "a released PIN was refused by the card; unlock the board to clear\n"); err != nil {
		slog.Error("the PIN release stop cannot be saved: a restart may try a released PIN again", "error", err.Error())
	}
}

// clear removes the stop after a person unlocked the board.
func (m *refusedMark) clear() {
	if !m.set {
		return
	}
	m.set = false
	if m.dir == "" {
		return
	}
	if err := os.Remove(filepath.Join(m.dir, refusedMarkFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("the PIN release stop cannot be removed: it holds again after a restart", "error", err.Error())
		return
	}
	if d, err := os.Open(m.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeSynced writes a file durably: a temporary file, synced, renamed, and the directory synced.
func writeSynced(dir, name, text string) error {
	f, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.WriteString(text); err != nil {
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
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir) //nolint:gosec // the driver's own state directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
