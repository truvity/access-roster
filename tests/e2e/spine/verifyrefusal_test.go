package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The step that refuses a damaged log must accept an intact one and refuse every judgement that is not a refusal naming a
// tile, or it would pass whatever `sluis audit verify` did.
//
// verifies: REQ-TEST-018
func TestAuditVerifyStepJudgesRefusalsAndPasses(t *testing.T) {
	var ok verified
	ok.Outcome, ok.Audit.Size, ok.Audit.Entries = "done", 10, 10
	if err := judgeVerified(0, ok); err != nil {
		t.Fatalf("an intact log: %v", err)
	}
	empty := ok
	empty.Audit.Entries = 0
	failed := ok
	failed.Outcome = "refused"
	for name, c := range map[string]struct {
		code int
		v    verified
	}{"exit 3": {3, ok}, "an empty log": {0, empty}, "a refusal": {0, failed}} {
		if judgeVerified(c.code, c.v) == nil {
			t.Errorf("%s: accepted as a verified log", name)
		}
	}

	refused := verified{Outcome: "refused", Reasons: []string{"tile/entries/000.entry"}}
	if err := judgeRefused(3, refused); err != nil {
		t.Fatalf("a good refusal: %v", err)
	}
	for name, c := range map[string]struct {
		code int
		v    verified
	}{
		"exit 0 on a damaged log": {0, verified{Outcome: "done"}},
		"exit 1":                  {1, verified{Outcome: "failed", Reasons: []string{"tile/entries/000.entry"}}},
		"no reason":               {3, verified{Outcome: "refused"}},
		"a reason without a file": {3, verified{Outcome: "refused", Reasons: []string{"checkpoint.signature"}}},
	} {
		if judgeRefused(c.code, c.v) == nil {
			t.Errorf("%s: accepted as a refusal", name)
		}
	}
}

// verifies: REQ-TEST-018
func TestCopyTamperedChangesEveryEntryBundleAndNothingElse(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	files := map[string]string{"checkpoint": "c", "tile/0/000": "hash", "tile/entries/000": "ab", "tile/entries/001.p/3": "xyz"}
	for rel, body := range files {
		p := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	n, err := copyTampered(src, dst)
	if err != nil || n != 2 {
		t.Fatalf("changed %d, %v, want 2", n, err)
	}
	for rel, body := range files {
		b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel))) //nolint:gosec // a temporary directory of the test
		if err != nil {
			t.Fatal(err)
		}
		bundle := len(rel) > 13 && rel[:13] == "tile/entries/"
		if (string(b) != body) != bundle {
			t.Errorf("%s: changed = %v, want %v", rel, string(b) != body, bundle)
		}
	}
	if _, err := copyTampered(t.TempDir(), t.TempDir()); err == nil {
		t.Error("a log with no entry bundle was reported as tampered")
	}
}
