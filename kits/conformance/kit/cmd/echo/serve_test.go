//go:build sluis_test

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// The serve and call commands agree with each other: the same code that a Rust peer talks to.
func TestServeAndCall(t *testing.T) {
	dir, err := os.MkdirTemp("", "e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "e.sock")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cli.Flags{Boundary: "test", Socket: socket}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serve did not return")
		}
	})

	var code int
	for range 100 {
		if code = call([]string{"--socket", socket}); code == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("call exit = %d, want 0", code)
}
