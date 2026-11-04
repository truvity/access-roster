//go:build linux

package driver

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// lockedOrSkip sets the PIN, or skips when this environment forbids locking memory (a container with a tiny
// RLIMIT_MEMLOCK). A skip is not a pass: it prints why.
func lockedOrSkip(t *testing.T, m *pinMemory, pin string) {
	t.Helper()
	if err := m.set([]byte(pin)); err != nil {
		if errors.Is(err, errMemory) && strings.Contains(err.Error(), "mlock") {
			t.Skipf("SKIP: mlock is not allowed here: %v", err)
		}
		t.Fatal(err)
	}
}

func TestThePINIsKeptInOneLockedPageAndWipedOnRequest(t *testing.T) {
	var m pinMemory
	defer m.release()
	if m.held() {
		t.Fatal("a new holder holds a PIN")
	}
	lockedOrSkip(t, &m, "123456")
	if got, ok := m.get(); !ok || got != "123456" {
		t.Fatalf("get = %q, %t", got, ok)
	}
	page := m.page
	m.wipe()
	if m.held() {
		t.Fatal("held after wipe")
	}
	if !bytes.Equal(page, make([]byte, len(page))) {
		t.Fatal("the page still holds bytes after wipe")
	}
	if _, ok := m.get(); ok {
		t.Fatal("get after wipe")
	}
}

func TestThePageIsReallyLockedAndOutOfCoreDumps(t *testing.T) {
	var m pinMemory
	defer m.release()
	lockedOrSkip(t, &m, "123456")
	// The kernel says so: the mapping that holds the page is Locked and marked "dd" (do not dump) in smaps.
	b, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		t.Skipf("SKIP: no /proc/self/smaps: %v", err)
	}
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmFlags:") && strings.Contains(line, " lo") && strings.Contains(line, " dd") {
			found = true
		}
	}
	if !found {
		t.Fatal("no mapping of the process is both locked (lo) and out of dumps (dd)")
	}
}

func TestReleasingGivesThePageBack(t *testing.T) {
	var m pinMemory
	lockedOrSkip(t, &m, "123456")
	m.release()
	if m.held() || m.page != nil {
		t.Fatal("release left the PIN or the page")
	}
}

func TestAPINTooLongForThePageIsRefused(t *testing.T) {
	var m pinMemory
	defer m.release()
	if err := m.set(make([]byte, 65)); err == nil {
		t.Fatal("65 octets were accepted")
	}
	if err := m.set(nil); err == nil {
		t.Fatal("an empty PIN was accepted")
	}
}
