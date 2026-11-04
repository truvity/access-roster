package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 600 entries make two full tiles, a partial tile of 88 hashes and a partial level-1 tile.
const fixtureEntries = 600

func verifyArgs(l *fixtureLog, extra ...string) []string {
	return append([]string{"audit", "verify", l.dir, "--key", l.key.vkey}, extra...)
}

func TestAuditVerifyOK(t *testing.T) {
	key := newFixtureKey(t)
	l := newFixtureLog(t, key, fixtureEntries, 100, 300)
	ta := newTestApp(t)
	if code := ta.do(verifyArgs(l)...); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	if !strings.HasPrefix(ta.out.String(), "ok: ") || !strings.Contains(ta.out.String(), "600 entries") {
		t.Fatalf("stdout = %q", ta.out.String())
	}
}

func TestAuditVerifyJSON(t *testing.T) {
	key := newFixtureKey(t)
	l := newFixtureLog(t, key, fixtureEntries, 300)
	ta := newTestApp(t)
	if code := ta.do(verifyArgs(l, "--output", "json", "--origin", fixtureOrigin)...); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	o := ta.object(t)
	if o["command"] != "audit verify" || o["outcome"] != "done" || o["exit_code"] != float64(0) || o["output"] != float64(1) {
		t.Fatalf("object = %v", o)
	}
	a := o["audit"].(map[string]any)
	if a["size"] != float64(fixtureEntries) || a["origin"] != fixtureOrigin || a["checkpoints"] != float64(2) {
		t.Fatalf("audit = %v", a)
	}
}

func TestAuditVerifyKeyFileAndEmptyLog(t *testing.T) {
	key := newFixtureKey(t)
	l := newFixtureLog(t, key, 0)
	kf := filepath.Join(t.TempDir(), "log.vkey")
	if err := os.WriteFile(kf, []byte(key.vkey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ta := newTestApp(t)
	if code := ta.do("audit", "verify", l.dir, "--key-file", kf); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
}

func TestAuditVerifyRefusals(t *testing.T) {
	other := newFixtureKey(t)
	cases := []struct {
		name    string
		breakIt func(t *testing.T, l *fixtureLog)
		args    []string
		reason  string
	}{
		{"tampered level-0 tile", func(t *testing.T, l *fixtureLog) { l.flip(t, "tile/0/000", 40) }, nil, "tile.hash"},
		{"tampered partial tile", func(t *testing.T, l *fixtureLog) { l.flip(t, "tile/0/002.p/88", 7) }, nil, "tile.hash"},
		{"tampered level-1 tile", func(t *testing.T, l *fixtureLog) { l.flip(t, "tile/1/000.p/2", 3) }, nil, "tile.hash"},
		{"tampered entry", func(t *testing.T, l *fixtureLog) { l.flip(t, "tile/entries/001", 5) }, nil, "tile/entries/001.entry"},
		{"truncated entry bundle", func(t *testing.T, l *fixtureLog) {
			p := filepath.Join(l.dir, "tile/entries/000")
			b, _ := os.ReadFile(p)                                       //nolint:gosec // test fixture
			if err := os.WriteFile(p, b[:len(b)-3], 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}, nil, "tile/entries/000.format"},
		{"missing tile", func(t *testing.T, l *fixtureLog) {
			if err := os.Remove(filepath.Join(l.dir, "tile/0/001")); err != nil {
				t.Fatal(err)
			}
		}, nil, "tile/0/001.missing"},
		{"tampered checkpoint text", func(t *testing.T, l *fixtureLog) {
			p := filepath.Join(l.dir, "checkpoint")
			b, _ := os.ReadFile(p) //nolint:gosec // test fixture
			b = []byte(strings.Replace(string(b), "\n600\n", "\n599\n", 1))
			if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}, nil, "checkpoint.signature"},
		{"checkpoint signed by another key", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoint", l.checkpoint(t, other, fixtureEntries, l.rootAt(t, fixtureEntries)))
		}, nil, "checkpoint.signature"},
		{"size beyond the tiles", func(t *testing.T, l *fixtureLog) {
			// A validly signed checkpoint that claims 900 entries when the blobs hold 600.
			l.write(t, "checkpoint", l.checkpoint(t, l.key, 900, l.rootAt(t, fixtureEntries)))
		}, nil, ".missing"},
		{"root hash that does not belong to the size", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoint", l.checkpoint(t, l.key, fixtureEntries, l.rootAt(t, 300)))
		}, nil, "tile.hash"},
		{"history checkpoint inconsistent with the head", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/300", l.checkpoint(t, l.key, 300, l.rootAt(t, 299)))
		}, nil, "checkpoints/300.inconsistent"},
		{"history file named for another size", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/301", l.checkpoint(t, l.key, 300, l.rootAt(t, 300)))
		}, nil, "checkpoints/301.size"},
		{"other origin", func(*testing.T, *fixtureLog) {}, []string{"--origin", "example.com/other"}, "checkpoint.origin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := newFixtureKey(t)
			l := newFixtureLog(t, key, fixtureEntries, 300)
			c.breakIt(t, l)
			ta := newTestApp(t)
			args := verifyArgs(l, append([]string{"--output", "json"}, c.args...)...)
			if code := ta.do(args...); code != 3 {
				t.Fatalf("exit = %d, want 3; stdout %q stderr %q", code, ta.out.String(), ta.err.String())
			}
			o := ta.object(t)
			if o["outcome"] != "refused" || o["exit_code"] != float64(3) {
				t.Fatalf("object = %v", o)
			}
			reasons, _ := o["reasons"].([]any)
			found := false
			for _, r := range reasons {
				if strings.Contains(r.(string), c.reason) {
					found = true
				}
			}
			if !found {
				t.Fatalf("reasons = %v, want one with %q", reasons, c.reason)
			}
		})
	}
}

func TestAuditVerifyFailuresAndUsage(t *testing.T) {
	key := newFixtureKey(t)
	empty := t.TempDir()
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no checkpoint file", []string{"audit", "verify", empty, "--key", key.vkey}, 1},
		{"no directory", []string{"audit", "verify", filepath.Join(empty, "nope"), "--key", key.vkey}, 1},
		{"no key", []string{"audit", "verify", empty}, 2},
		{"no directory argument", []string{"audit", "verify", "--key", key.vkey}, 2},
		{"bad key", []string{"audit", "verify", empty, "--key", "name+00000000+AAAA"}, 2},
		{"unknown subcommand", []string{"audit", "frobnicate"}, 2},
		{"unknown flag", []string{"audit", "verify", empty, "--nope"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t)
			if code := ta.do(c.args...); code != c.want {
				t.Fatalf("exit = %d, want %d; stderr %q", code, c.want, ta.err.String())
			}
		})
	}
}

func TestParseVerifierKeyRejects(t *testing.T) {
	key := newFixtureKey(t)
	if _, err := parseVerifierKey(key.vkey); err != nil {
		t.Fatalf("a good key: %v", err)
	}
	if _, err := parseVerifierKey(strings.Replace(key.vkey, "+", "+ff", 1)); err == nil {
		t.Fatal("a key with a wrong ID is accepted")
	}
	// The key ID of an ECDSA key is the hash of the key alone: the Ed25519 rule (name, newline, type, key) is refused.
	parts := strings.SplitN(key.vkey, "+", 3)
	data, _ := base64.StdEncoding.DecodeString(parts[2])
	sum := sha256.Sum256(append([]byte(parts[0]+"\n"), data...))
	if _, err := parseVerifierKey(parts[0] + "+" + hex.EncodeToString(sum[:4]) + "+" + parts[2]); err == nil {
		t.Fatal("a key ID made with the Ed25519 rule is accepted")
	}
	// Type 0x01 is Ed25519.
	if _, err := parseVerifierKey(parts[0] + "+" + parts[1] + "+" + base64.StdEncoding.EncodeToString(append([]byte{1}, data[1:]...))); err == nil {
		t.Fatal("signature type 0x01 is accepted")
	}
}

func TestAuditVerifyRefusesAnotherDigest(t *testing.T) {
	// A checkpoint signed over the SHA-256 digest, as the witness implementation does, is not one of ours.
	key := newFixtureKey(t)
	l := newFixtureLog(t, key, 300)
	key.digest = func(msg []byte) []byte { d := sha256.Sum256(msg); return d[:] }
	l.write(t, "checkpoint", l.checkpoint(t, key, 300, l.rootAt(t, 300)))
	ta := newTestApp(t)
	if code := ta.do(verifyArgs(l)...); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestTilePath(t *testing.T) {
	for _, c := range []struct {
		level int
		n     int64
		w     int
		want  string
	}{
		{0, 0, 256, "tile/0/000"},
		{1, 7, 3, "tile/1/007.p/3"},
		{0, 1234067, 256, "tile/0/x001/x234/067"},
		{-1, 12, 256, "tile/entries/012"},
		{-1, 12, 5, "tile/entries/012.p/5"},
	} {
		if got := filepath.ToSlash(tilePath(c.level, c.n, c.w)); got != c.want {
			t.Errorf("tilePath(%d,%d,%d) = %q, want %q", c.level, c.n, c.w, got, c.want)
		}
	}
}
