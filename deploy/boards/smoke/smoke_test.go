package main

import (
	"testing"
	"time"
)

func TestActiveAt(t *testing.T) {
	since := "2026-11-04T10:00:00Z"
	ring := []string{
		"kidA ES384 active node=board-a since=2026-11-04T08:00:00Z",
		"kidB ES384 active node=board-b since=2026-11-04T08:00:00Z",
		"kidC ES384 pre-published node=board-b since=" + since,
	}
	// A node with an active key is not waiting.
	if _, ok := activeAt(ring, "board-b"); ok {
		t.Error("a node that has an active key was said to wait")
	}
	// A node with only a pre-published key is: the key is active a lead time after it entered the state.
	only := []string{"kidD ES384 pre-published node=board-c since=" + since, "kidE ES384 active node=board-a since=" + since}
	at, ok := activeAt(only, "board-c")
	want := time.Date(2026, 11, 4, 10, 30, 0, 0, time.UTC)
	if !ok || !at.Equal(want) {
		t.Errorf("activeAt = %v, %t; want %v", at, ok, want)
	}
	// Another node's pre-published key is not this node's.
	if _, ok := activeAt(only, "board-a"); ok {
		t.Error("another node's pre-published key was taken for this node's")
	}
	// Lines without the fields (an older spine) say nothing.
	if _, ok := activeAt([]string{"kidF ES384 pre-published"}, "board-c"); ok {
		t.Error("a line without a node was taken")
	}
	// The earliest of two pre-published keys wins.
	two := []string{"k1 ES384 pre-published node=n since=2026-11-04T10:10:00Z", "k2 ES384 pre-published node=n since=" + since}
	if at, ok := activeAt(two, "n"); !ok || !at.Equal(want) {
		t.Errorf("two pre-published keys: %v, %t; want %v", at, ok, want)
	}
}
