package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The corpus of the RFC 8785 author (see kits/conformance/audit/jcs-corpus/README.md) and the differential golden
// file are shared with kits/rust/sluis-audit: both suites must pass on them.
const (
	corpusDir       = vectorDir + "jcs-corpus/"
	differentialTSV = vectorDir + "jcs-differential.tsv"
)

// profileRefuses names the corpus inputs that carry a number which is not an integer. The library canonicalises
// them (the corpus proves it, in TestCorpusThroughTheLibrary), and the sluis profile refuses them.
var profileRefuses = map[string]bool{"structures.json": true, "values.json": true}

func corpusFiles(t *testing.T) []string {
	t.Helper()
	names, err := filepath.Glob(corpusDir + "input/*.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("no corpus input: %v", err)
	}
	sort.Strings(names)
	for i, n := range names {
		names[i] = filepath.Base(n)
	}
	return names
}

func readCorpus(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(corpusDir + dir + "/" + name) //nolint:gosec // a fixed directory of the repository
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
func TestCorpusThroughTheLibrary(t *testing.T) {
	for _, name := range corpusFiles(t) {
		t.Run(name, func(t *testing.T) {
			got, err := jcs.Transform(readCorpus(t, "input", name))
			if err != nil {
				t.Fatal(err)
			}
			if want := readCorpus(t, "output", name); !bytes.Equal(got, want) {
				t.Fatalf("got  %q\nwant %q", got, want)
			}
		})
	}
}

// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
func TestCorpusThroughCanonical(t *testing.T) {
	for _, name := range corpusFiles(t) {
		t.Run(name, func(t *testing.T) {
			v := decode(t, readCorpus(t, "input", name))
			got, err := Canonical(v)
			if profileRefuses[name] {
				if err == nil {
					t.Fatalf("a number that is not an integer was accepted: %s", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := readCorpus(t, "output", name); !bytes.Equal(got, want) {
				t.Fatalf("got  %q\nwant %q", got, want)
			}
		})
	}
}

// differentialLines is what both languages must print, byte for byte: for each corpus input the library's output,
// then the output of the sluis profile or "!refused"; for each vector of jcs-vectors.json the same; and for each
// record vector the whole record. A line is "name TAB canonical text"; canonical JSON holds no raw tab or newline.
func differentialLines(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	line := func(name string, out []byte, err error) {
		text := "!refused"
		if err == nil {
			text = string(out)
		}
		if strings.ContainsAny(text, "\t\n") {
			t.Fatalf("%s: a raw tab or newline in canonical text", name)
		}
		sb.WriteString(name + "\t" + text + "\n")
	}
	for _, name := range corpusFiles(t) {
		out, err := jcs.Transform(readCorpus(t, "input", name))
		line("corpus-library/"+name, out, err)
		out, err = Canonical(decode(t, readCorpus(t, "input", name)))
		line("corpus-profile/"+name, out, err)
	}
	var f jcsFile
	readVectors(t, "jcs-vectors.json", &f)
	for _, v := range f.Vectors {
		out, err := Canonical(decode(t, v.Input))
		line("jcs-vectors/"+v.Name, out, err)
	}
	for _, v := range f.Refused {
		out, err := Canonical(decode(t, v.Input))
		line("jcs-vectors-refused/"+v.Name, out, err)
	}
	var r recordFile
	readVectors(t, "record-vectors.json", &r)
	for _, c := range r.Cases {
		out, err := buildRecord(c.input(t))
		line("record/"+c.Name, out, err)
	}
	return sb.String()
}

// TestDifferentialWithRust is the Go half of the differential test: the Rust crate prints the same lines from
// the same inputs and compares them with the same file. Go writes the file (SLUIS_UPDATE_GOLDEN=1); a change of
// one byte of one line is a change of an audit record hash and needs a decision, not a regeneration.
//
// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
func TestDifferentialWithRust(t *testing.T) {
	got := differentialLines(t)
	if os.Getenv("SLUIS_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(differentialTSV, []byte(got), 0o644); err != nil { //nolint:gosec // a repository file
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(differentialTSV)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("line %d differs\ngot  %s\nwant %s", i+1, gl[i], wl[i])
			}
		}
		t.Fatalf("got %d lines, want %d", len(gl), len(wl))
	}
}

// FuzzCanonical feeds JSON text to the canonicaliser through the value it decodes to. Whatever it accepts must be
// valid JSON, must be its own canonical form (the library maps it to itself), and must decode to the value it was
// given; whatever it refuses must be refused with a reason. Go runs the seeds below, the vector files and the
// corpus with every `go test`; `just go-fuzz` runs the fuzzer for a bounded time.
//
// verifies: REQ-SEC-018, REQ-AUDIT-106, REQ-AUDIT-107
func FuzzCanonical(f *testing.F) {
	for _, s := range []string{
		`null`, `[]`, `{}`, `[true,false,null]`, `{"b":1,"a":[2,{"d":"x","c":"y"}]}`, `"\u0000\u001f\"\\\/"`,
		`{"😀":1,"דּ":2,"€":3,"":4}`, `9007199254740991`, `-9007199254740992`, `1.5`, `1e30`, `[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]`,
	} {
		f.Add([]byte(s))
	}
	if names, err := filepath.Glob(corpusDir + "input/*.json"); err == nil {
		for _, n := range names {
			if raw, err := os.ReadFile(n); err == nil { //nolint:gosec // a fixed directory of the repository
				f.Add(raw)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		var v any
		if d.Decode(&v) != nil {
			return
		}
		v = convert(v, false)
		out, err := Canonical(v)
		if err != nil {
			if reason, _ := refusal.Reason(err); reason == "" {
				t.Fatalf("a refusal without a reason: %v", err)
			}
			return
		}
		if !json.Valid(out) {
			t.Fatalf("not JSON: %q", out)
		}
		again, err := jcs.Transform(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not canonical: %q -> %q (%v)", out, again, err)
		}
		d = json.NewDecoder(bytes.NewReader(out))
		d.UseNumber()
		var back any
		if err := d.Decode(&back); err != nil {
			t.Fatal(err)
		}
		if back = convert(back, false); !reflect.DeepEqual(back, v) {
			t.Fatalf("decodes to another value: %q", out)
		}
	})
}
