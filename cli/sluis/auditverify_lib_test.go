package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	tdlog "github.com/transparency-dev/formats/log"
	tdnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// oldWriterLog is a log written by the writer before it used torchwood and golang.org/x/mod/sumdb/note (commit
// a01e20863): the pointer, two checkpoints in checkpoints/<size>, and the tiles of seven entries.
const oldWriterLog = "../../tests/testdata/audit-log/old-writer"

func oldWriterKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(oldWriterLog, "vkey"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// The log the former writer wrote still verifies, byte for byte as stored.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func TestAuditVerifyReadsALogOfTheFormerWriter(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.do("audit", "verify", filepath.Join(oldWriterLog, "log"), "--key", oldWriterKey(t), "--output", "json"); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	a := ta.object(t)["audit"].(map[string]any)
	if a["size"] != float64(7) || a["checkpoints"] != float64(3) || a["origin"] != "sluis.local.test/dev/sluis/audit/main" {
		t.Fatalf("audit = %v", a)
	}
}

// The oracle: github.com/transparency-dev/formats is the reference the C2SP signed-note standard names for signature
// type 0x02. Every checkpoint of the fixtures opens with it and parses with its checkpoint parser, with nothing of
// the CLI's code or torchwood in between.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func TestCheckpointsOpenWithTheTransparencyDevVerifier(t *testing.T) {
	check := func(t *testing.T, vkey string, files ...string) {
		t.Helper()
		v, err := tdnote.NewECDSAVerifier(vkey)
		if err != nil {
			t.Fatalf("the reference refuses the verifier key: %v", err)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f) //nolint:gosec // a test fixture
			if err != nil {
				t.Fatal(err)
			}
			n, err := note.Open(raw, note.VerifierList(v))
			if err != nil || len(n.Sigs) != 1 {
				t.Fatalf("%s does not open with the reference verifier: %v", f, err)
			}
			var cp tdlog.Checkpoint
			if rest, err := cp.Unmarshal([]byte(n.Text)); err != nil || len(rest) != 0 || len(cp.Hash) != 32 {
				t.Fatalf("%s: the reference parser reads %q: rest %q, %v", f, n.Text, rest, err)
			}
			if base := filepath.Base(f); base != "checkpoint" && base != strconv.FormatUint(cp.Size, 10) {
				t.Fatalf("%s names size %d", f, cp.Size)
			}
		}
	}
	t.Run("former writer", func(t *testing.T) {
		files := []string{filepath.Join(oldWriterLog, "log", "checkpoint")}
		hist, err := filepath.Glob(filepath.Join(oldWriterLog, "log", "checkpoints", "*"))
		if err != nil || len(hist) != 2 {
			t.Fatalf("history: %v %v", hist, err)
		}
		check(t, oldWriterKey(t), append(files, hist...)...)
	})
	t.Run("fixture generator", func(t *testing.T) {
		key := newFixtureKey(t)
		l := newFixtureLog(t, key, 300, 100)
		check(t, key.vkey, filepath.Join(l.dir, "checkpoint"), filepath.Join(l.dir, "checkpoints", "100"))
	})
}

// A verifier key that the reference reads is read by the CLI to the same key, and one the reference refuses is refused.
// verifies: REQ-SEC-018
func TestVerifierKeyAgreesWithTheTransparencyDevVerifier(t *testing.T) {
	key := newFixtureKey(t)
	vkey := key.vkey
	ref, err := tdnote.NewECDSAVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := parseVerifierKey(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if ours.Name() != ref.Name() || ours.KeyHash() != ref.KeyHash() {
		t.Fatalf("name %q/%q, key hash %08x/%08x", ours.Name(), ref.Name(), ours.KeyHash(), ref.KeyHash())
	}
	// A signature made as the standard says (ASN.1 DER ECDSA over the SHA-256 of the message) passes both; another does not.
	msg := []byte("a message\n")
	sig, err := ecdsa.SignASN1(rand.Reader, key.priv, sha256Of(msg))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []note.Verifier{ours, ref} {
		if !v.Verify(msg, sig) || v.Verify([]byte("another\n"), sig) || v.Verify(msg, sig[1:]) {
			t.Fatalf("%T disagrees on the signature", v)
		}
	}
}

// Parsing a checkpoint body: no panic, and what is accepted names an origin, a size and a root.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func FuzzParseCheckpoint(f *testing.F) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, s := range []string{
		fixtureOrigin + "\n7\n" + root + "\n",
		fixtureOrigin + "\n0\n" + root + "\n",
		fixtureOrigin + "\n7\n" + root + "\nextension line\nanother\n",
		"\n\n\n\n", "a\n1\n\n", "a\n9223372036854775807\n" + root + "\n", "a\n-0\n" + root + "\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		cp, err := parseCheckpoint(text)
		if err != nil {
			return
		}
		if cp.Origin == "" || cp.N < 0 {
			t.Fatalf("accepted %q as %+v", text, cp)
		}
		// The body re-parses to the same checkpoint.
		again, err := parseCheckpoint(cp.String())
		if err != nil || again != cp {
			t.Fatalf("%q: %+v, then %+v, %v", text, cp, again, err)
		}
	})
}

func TestParseCheckpointRefusals(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	good := fixtureOrigin + "\n7\n" + root + "\n"
	if cp, err := parseCheckpoint(good + "extension\n"); err != nil || cp.Extension != "extension\n" {
		t.Fatalf("an extension line: %+v, %v", cp, err)
	}
	for name, text := range map[string]string{
		"empty":               "",
		"no trailing newline": strings.TrimSuffix(good, "\n"),
		"empty origin":        "\n7\n" + root + "\n",
		"size with a sign":    fixtureOrigin + "\n+7\n" + root + "\n",
		"size with a zero":    fixtureOrigin + "\n07\n" + root + "\n",
		"negative size":       fixtureOrigin + "\n-1\n" + root + "\n",
		"size beyond int64":   fixtureOrigin + "\n9223372036854775808\n" + root + "\n",
		"short root":          fixtureOrigin + "\n7\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"blank extension":     good + "\n",
		"three lines":         fixtureOrigin + "\n7\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCheckpoint(text); err == nil {
				t.Fatalf("accepted %q", text)
			}
		})
	}
}

// The reader of checkpoints/<size>, the one object family that is sluis's own: every name is a size, every file a
// checkpoint signed by the log key with that size, and a directory beyond the limits is refused, never read.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func TestHistoryReaderRefusals(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []struct {
		name   string
		setup  func(t *testing.T, l *fixtureLog)
		reason string
	}{
		{"leading zero", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/0300", l.checkpoint(t, l.key, 300, l.rootAt(t, 300)))
		}, "checkpoints/0300.name"},
		{"sign", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/+300", l.checkpoint(t, l.key, 300, l.rootAt(t, 300)))
		}, "checkpoints/+300.name"},
		{"not a number", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/latest", l.checkpoint(t, l.key, 300, l.rootAt(t, 300)))
		}, "checkpoints/latest.name"},
		{"name longer than an int64", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/"+strings.Repeat("1", maxHistoryName+1), l.checkpoint(t, l.key, 300, l.rootAt(t, 300)))
		}, ".name"},
		{"beyond int64", func(t *testing.T, l *fixtureLog) { l.write(t, "checkpoints/9223372036854775808", []byte("x")) }, "9223372036854775808.name"},
		{"a directory", func(t *testing.T, l *fixtureLog) {
			if err := os.MkdirAll(filepath.Join(l.dir, "checkpoints", "300"), 0o755); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}, "checkpoints/300.name"},
		{"unsigned", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/300", []byte(fixtureOrigin+"\n300\n"+root+"\n"))
		}, "checkpoints/300.signature"},
		{"empty file", func(t *testing.T, l *fixtureLog) { l.write(t, "checkpoints/300", nil) }, "checkpoints/300.signature"},
		{"over the length limit", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/300", bytes.Repeat([]byte("x"), maxCheckpointFile+1))
		}, "checkpoints/300.length"},
		{"signed but not a checkpoint", func(t *testing.T, l *fixtureLog) {
			l.write(t, "checkpoints/300", l.key.sign(t, "this is a note\n"))
		}, "checkpoints/300.format"},
		{"signed, with an extension line, for another size than its name", func(t *testing.T, l *fixtureLog) {
			r := l.rootAt(t, 299)
			l.write(t, "checkpoints/300", l.key.sign(t, fmt.Sprintf("%s\n299\n%s\nx\n", fixtureOrigin, base64.StdEncoding.EncodeToString(r[:]))))
		}, "checkpoints/300.size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newFixtureLog(t, newFixtureKey(t), 300)
			c.setup(t, l)
			_, err := verifyLog(l.dir, mustKey(t, l.key.vkey), "")
			r, ok := err.(interface{ Reasons() []string })
			if !ok {
				t.Fatalf("err = %v, want a refusal", err)
			}
			found := false
			for _, s := range r.Reasons() {
				found = found || strings.Contains(s, c.reason)
			}
			if !found {
				t.Fatalf("reasons = %v, want one with %q", r.Reasons(), c.reason)
			}
		})
	}

	t.Run("no directory is an empty history", func(t *testing.T) {
		l := newFixtureLog(t, newFixtureKey(t), 10)
		got, err := historySizes(logDir(l.dir))
		if err != nil || len(got) != 0 {
			t.Fatalf("%v, %v", got, err)
		}
	})
}

// A history has no limit on its count: the writer makes one checkpoint for each sealed batch, for the life of the log,
// and a compliance lock forbids pruning. There is no constant to test at; this history is more than two batches of the
// directory reader (historyBatch), so the reader must go on past the first read.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func TestHistoryHasNoLimitOnItsCount(t *testing.T) {
	const n = 2*historyBatch + 500
	sizes := make([]int64, 0, n)
	for s := int64(1); s <= n; s++ {
		sizes = append(sizes, s)
	}
	l := newFixtureLog(t, newFixtureKey(t), n, sizes...)
	got, err := historySizes(logDir(l.dir))
	if err != nil || len(got) != n || !slices.IsSorted(got) {
		t.Fatalf("sizes: %d, sorted %v, %v", len(got), slices.IsSorted(got), err)
	}
	ta := newTestApp(t)
	if code := ta.do(verifyArgs(l, "--output", "json")...); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, ta.err.String())
	}
	if a := ta.object(t)["audit"].(map[string]any); a["checkpoints"] != float64(n+1) || a["size"] != float64(n) {
		t.Fatalf("audit = %v", a)
	}
}

// When several files are wrong the refusal is always the same one: names before files, and files in ascending size
// (the directory order does not decide it). The files lie in different reads of the directory.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func TestHistoryRefusalIsDeterministic(t *testing.T) {
	const n = historyBatch + 300
	sizes := make([]int64, 0, n)
	for s := int64(1); s <= n; s++ {
		sizes = append(sizes, s)
	}
	run := func(t *testing.T, setup func(*fixtureLog)) string {
		t.Helper()
		l := newFixtureLog(t, newFixtureKey(t), n, sizes...)
		setup(l)
		var first string
		for i := range 5 {
			_, err := verifyLog(l.dir, mustKey(t, l.key.vkey), "")
			r, ok := err.(interface{ Reasons() []string })
			if !ok || len(r.Reasons()) != 1 {
				t.Fatalf("err = %v, want one refusal", err)
			}
			if i == 0 {
				first = r.Reasons()[0]
			} else if r.Reasons()[0] != first {
				t.Fatalf("reasons %q, then %q", first, r.Reasons()[0])
			}
		}
		return first
	}
	t.Run("bad signatures", func(t *testing.T) {
		got := run(t, func(l *fixtureLog) {
			for _, s := range []int{1200, 77, 1300, 400} {
				l.write(t, fmt.Sprintf("checkpoints/%d", s), []byte("not a note"))
			}
		})
		if got != "checkpoints/77.signature" {
			t.Fatalf("reason = %q", got)
		}
	})
	t.Run("bad names", func(t *testing.T) {
		got := run(t, func(l *fixtureLog) {
			for _, name := range []string{"zz", "0900", "-5", "latest"} {
				l.write(t, "checkpoints/"+name, []byte("x"))
			}
			l.write(t, "checkpoints/3", []byte("not a note")) // a bad file, which a bad name outranks
		})
		if got != "checkpoints/-5.name" {
			t.Fatalf("reason = %q", got)
		}
	})
}

// golang.org/x/mod v0.42.0 opens a note with the first line of the log's key and drops a repeat of the same name and key
// ID unchecked, so a good line followed by a garbage or bad repeat would open. The Rust verifier refuses it, and two
// verifiers of one log must agree: every line of the key must verify (everyLineVerifies). A repeat of the same good line
// is no harm and is accepted; a bad line anywhere, first or last, refuses the note.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func TestRepeatedSignatureLinesOfTheLogKey(t *testing.T) {
	key := newFixtureKey(t)
	l := newFixtureLog(t, key, 5)
	good := string(l.checkpoint(t, key, 5, l.rootAt(t, 5)))
	goodLine := good[strings.Index(good, "\n\n")+2:] // "— name b64\n"
	text := good[:strings.Index(good, "\n\n")+1]
	// A line of the log's key with a signature over other text: right shape, wrong signature.
	badLine := string(key.sign(t, text+"another line\n"))
	badLine = badLine[strings.Index(badLine, "\n\n")+2:]
	garbage := "\u2014 " + key.name + " " + base64.StdEncoding.EncodeToString(append(slices.Clone(key.id), "garbage"...)) + "\n"
	vk := mustKey(t, key.vkey)
	for name, c := range map[string]struct {
		note string
		ok   bool
	}{
		"one good line":               {text + "\n" + goodLine, true},
		"good, then the same again":   {text + "\n" + goodLine + goodLine, true},
		"good, then a garbage repeat": {text + "\n" + goodLine + garbage, false},
		"good, then a bad repeat":     {text + "\n" + goodLine + badLine, false},
		"bad, good, then good again":  {text + "\n" + badLine + goodLine + goodLine, false},
		"garbage first, then good":    {text + "\n" + garbage + goodLine, false},
		"bad first, then good":        {text + "\n" + badLine + goodLine, false},
		"only a bad line":             {text + "\n" + badLine, false},
	} {
		t.Run(name, func(t *testing.T) {
			l.write(t, "checkpoint", []byte(c.note))
			cp, err := readCheckpoint(logDir(l.dir), "checkpoint", vk)
			if c.ok != (err == nil) {
				t.Fatalf("accepted = %v, err %v", err == nil, err)
			}
			if err == nil && (cp.N != 5 || cp.Origin != fixtureOrigin) {
				t.Fatalf("read %+v", cp.Checkpoint)
			}
		})
	}
}

func mustKey(t *testing.T, vkey string) *logKey {
	t.Helper()
	k, err := parseVerifierKey(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Reading checkpoints/<size> from a directory of any content: no panic, no hang, no read beyond the limits, and a
// checkpoint that is returned is signed by the log key, at the size its file is named for.
// verifies: REQ-SEC-018, REQ-AUDIT-026
func FuzzHistoryReader(f *testing.F) {
	key := newFixtureKey(f)
	l := newFixtureLog(f, key, 5)
	good := l.checkpoint(f, key, 5, l.rootAt(f, 5))
	f.Add("5", good)
	f.Add("5", []byte{})
	f.Add("05", good)
	f.Add("4", good)
	f.Add("-1", good)
	f.Add("9223372036854775807", good)
	f.Add("5", append(bytes.Clone(good), "extra"...))
	f.Add("5", bytes.ReplaceAll(good, []byte("\n\n"), []byte("\n")))
	vk, err := parseVerifierKey(key.vkey)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, name string, content []byte) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "checkpoints"), 0o755); err != nil { //nolint:gosec // a fuzz directory
			t.Fatal(err)
		}
		if strings.ContainsAny(name, "/\x00") || name == "" || name == "." || name == ".." {
			return // not a name a directory can hold
		}
		if err := os.WriteFile(filepath.Join(dir, "checkpoints", name), content, 0o600); err != nil {
			return // the file system refuses the name
		}
		sizes, err := historySizes(logDir(dir))
		if err != nil {
			return
		}
		for _, size := range sizes {
			cp, err := readHistoryFile(logDir(dir), size, fixtureOrigin, vk)
			if err != nil {
				continue
			}
			want, nerr := historySize(name)
			if nerr != nil || cp.N != size || size != want || cp.Origin != fixtureOrigin || len(content) > maxCheckpointFile {
				t.Fatalf("%q read as %+v", name, cp)
			}
			if _, err := parseCheckpoint(cp.String()); err != nil {
				t.Fatalf("%q: %+v does not re-parse", name, cp)
			}
		}
	})
}

// historySize is the one reader of a name.
// verifies: REQ-SEC-018
func FuzzHistorySize(f *testing.F) {
	for _, s := range []string{"0", "1", "300", "9223372036854775807", "9223372036854775808", "-1", "+1", "01", "", " 1", "1 ", "１２"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		size, err := historySize(name)
		if err != nil {
			return
		}
		if size < 0 || strconv.FormatInt(size, 10) != name || len(name) > maxHistoryName {
			t.Fatalf("%q read as %d", name, size)
		}
	})
}
