package main

import (
	"testing"
	"time"
)

// verifies: the log check of a borrower's refusal tells it from its caller's
// The guard logs the registry name of the peer's uid, so entry-audit's refusal and entry's carry the name "entry". Each row
// is held to the lines stamped while its own probe ran: a borrower whose callee logged nothing for it is missing, even when
// its caller's refusal of the same socket is in the log.
func TestRefusalInTellsABorrowerFromItsCaller(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	caller := window{from: t0, to: t0.Add(2 * time.Second)}
	borrower := window{from: t0.Add(3 * time.Second), to: t0.Add(5 * time.Second)}
	out := []byte(t0.Add(time.Second).Format(time.RFC3339Nano) + ` {"level":"INFO","msg":"call refused","reason":"call_graph","actor":"store","caller":"entry","uid":61000}` + "\n" +
		"a line docker did not stamp, call refused caller=entry\n")
	lines := parseLogs(out)
	if len(lines) != 2 {
		t.Fatalf("parsed %d lines, want 2", len(lines))
	}
	if !refusalIn(lines, "entry", caller) {
		t.Error("the caller's refusal, in its own window, was not found")
	}
	if refusalIn(lines, "entry", borrower) {
		t.Error("the caller's refusal was taken for the borrower's")
	}
	// The borrower's own line, in its window, is found.
	lines = append(lines, logLine{at: t0.Add(4 * time.Second), text: `refused: call graph callee="store" caller="entry"`})
	if !refusalIn(lines, "entry", borrower) {
		t.Error("the borrower's refusal, in its own window, was not found")
	}
	// A line that names another caller, whose name holds this one, is not a refusal of this one ("ca" in "ssh-ca").
	if refusalIn([]logLine{{at: t0.Add(time.Second), text: "call refused caller=entry-other"}}, "entry", caller) {
		t.Error("a refusal of another name was taken")
	}
}

func TestRefusalInNamesTheCallerAlone(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	w := window{from: t0, to: t0.Add(time.Second)}
	at := t0.Add(time.Second / 2)
	for _, c := range []struct {
		line string
		want bool
	}{
		{`{"msg":"call refused","caller":"ca"}`, true},
		{`refused: call graph callee="store" caller="ca"`, true},
		{`{"msg":"call refused","caller":"ssh-ca"}`, false},
		{`{"msg":"call refused","caller":"cab"}`, false},
		{`{"msg":"call served","caller":"ca"}`, false},
	} {
		if got := refusalIn([]logLine{{at: at, text: c.line}}, "ca", w); got != c.want {
			t.Errorf("%s: got %v, want %v", c.line, got, c.want)
		}
	}
}
