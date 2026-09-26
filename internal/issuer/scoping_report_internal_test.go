package issuer

import (
	"testing"
	"time"
)

// A finding logs once, is suppressed for the rest of the window, and logs
// again once the window has passed — the whole of what report mode's
// rate limit promises, so a session that refreshes every few minutes does
// not write the same line for as long as it lives.
func TestGroupsScopingReporterSuppressesWithinTheWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	r := newGroupsScopingReporter()
	r.now = func() time.Time { return now }

	if !r.allow("k") {
		t.Fatal("the first sighting of a key must log")
	}
	if r.allow("k") {
		t.Error("the same key inside the window must be suppressed")
	}

	now = now.Add(groupsScopingReportWindow - time.Second)
	if r.allow("k") {
		t.Error("one second short of the window must still be suppressed")
	}

	now = now.Add(2 * time.Second)
	if !r.allow("k") {
		t.Error("past the window, the same key must log again")
	}
}

// dropped-set is part of the key, so a caller whose held groups CHANGE
// between two mints is a different finding and is never suppressed by
// the other one's window — the change is exactly what report mode exists
// to surface.
func TestGroupsScopingReporterKeysOnTheFullFinding(t *testing.T) {
	t.Parallel()
	r := newGroupsScopingReporter()
	r.now = func() time.Time { return time.Unix(0, 0) }

	if !r.allow("aud\x00sub\x00devel:k8s:admin") {
		t.Fatal("a new finding must log")
	}
	if !r.allow("aud\x00sub\x00devel:k8s:admin,prod:shop:deployer") {
		t.Error("a different dropped set for the same audience and subject is a different finding")
	}
	if !r.allow("aud\x00other-sub\x00devel:k8s:admin") {
		t.Error("a different subject is a different finding")
	}
}
