package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String()
	if !strings.HasPrefix(got, Version) {
		t.Fatalf("String() = %q, want prefix %q", got, Version)
	}
	if !strings.Contains(got, runtime.Version()) {
		t.Fatalf("String() = %q, want the Go runtime %q", got, runtime.Version())
	}
}

func TestDefaultIsDev(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty")
	}
}
