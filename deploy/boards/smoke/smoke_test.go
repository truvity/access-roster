package main

import (
	"testing"
	"time"
)

func TestActiveAt(t *testing.T) {
	since := "2026-11-04T10:00:00Z"
	want := time.Date(2026, 11, 4, 10, 30, 0, 0, time.UTC)
	// Right after a switch the node's OLD key is still active in the ring and the NEW one is pre-published (the signer keeps
	// the old one until the new one is active). The hint is about the key that key@ holds now, so the old active key of the
	// node must not hide it.
	ring := []string{
		"kidOld ES384 active node=board-b since=2026-11-04T08:00:00Z",
		"kidA ES384 active node=board-a since=2026-11-04T08:00:00Z",
		"kidNew ES384 pre-published node=board-b since=" + since,
	}
	if at, ok := activeAt(ring, "kidNew"); !ok || !at.Equal(want) {
		t.Errorf("activeAt(kidNew) = %v, %t; want %v", at, ok, want)
	}
	// The key that key@ holds is active: no wait.
	if _, ok := activeAt(ring, "kidOld"); ok {
		t.Error("an active key was said to wait")
	}
	// A key that is not in the ring says nothing.
	if _, ok := activeAt(ring, "kidMissing"); ok {
		t.Error("a key that is not in the ring was said to wait")
	}
	// Lines without the fields (an older spine) say nothing.
	if _, ok := activeAt([]string{"kidNew ES384 pre-published"}, "kidNew"); ok {
		t.Error("a line without a since was taken")
	}
	// A retiring key is not waiting either.
	if _, ok := activeAt([]string{"kidR ES384 retiring node=n since=" + since}, "kidR"); ok {
		t.Error("a retiring key was said to wait")
	}
}
