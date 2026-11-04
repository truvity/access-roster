//go:build linux

package driver

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
)

// pinMemory holds the PIN in one page of anonymous memory that is locked into RAM (mlock: it is never swapped) and
// kept out of core dumps (MADV_DONTDUMP). The PIN is written nowhere else by the driver.
//
// The PIN has to reach piv-go as a Go string at the moment the card asks for it, and that copy is on the Go heap,
// which cannot be locked or wiped. The page is the resting place; the copy lives for one call.
type pinMemory struct {
	mu   sync.Mutex
	page []byte
	n    int
}

const madvDontDump = 16 // MADV_DONTDUMP, linux/mman-common.h

var errMemory = errors.New("driver: the PIN cannot be held in locked memory")

// set copies the PIN into the locked page. It fails, and holds nothing, when the memory cannot be locked.
func (m *pinMemory) set(pin []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(pin) == 0 || len(pin) > 64 {
		return errMemory
	}
	if m.page == nil {
		page, err := syscall.Mmap(-1, 0, syscall.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			return fmt.Errorf("%w: mmap", errMemory)
		}
		if err := syscall.Mlock(page); err != nil {
			_ = syscall.Munmap(page)
			return fmt.Errorf("%w: mlock", errMemory)
		}
		if err := syscall.Madvise(page, madvDontDump); err != nil {
			_ = syscall.Munlock(page)
			_ = syscall.Munmap(page)
			return fmt.Errorf("%w: madvise", errMemory)
		}
		m.page = page
	}
	clear(m.page)
	m.n = copy(m.page, pin)
	return nil
}

// held reports whether a PIN is held.
func (m *pinMemory) held() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n > 0
}

// get returns a copy of the PIN for one call to the card, or false when none is held.
func (m *pinMemory) get() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n == 0 {
		return "", false
	}
	return string(m.page[:m.n]), true
}

// wipe overwrites the PIN. The page stays locked for the next unlock.
func (m *pinMemory) wipe() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.page != nil {
		clear(m.page)
	}
	m.n = 0
}

// release wipes the PIN and gives the page back.
func (m *pinMemory) release() {
	m.wipe()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.page != nil {
		_ = syscall.Munlock(m.page)
		_ = syscall.Munmap(m.page)
		m.page = nil
	}
}

// hardenProcess makes the process non-dumpable (prctl PR_SET_DUMPABLE 0): no core file, and no ptrace by a process of
// the same uid, so the PIN page cannot be read from outside.
func hardenProcess() error {
	const prSetDumpable = 4
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("driver: prctl(PR_SET_DUMPABLE): %w", errno)
	}
	return nil
}
