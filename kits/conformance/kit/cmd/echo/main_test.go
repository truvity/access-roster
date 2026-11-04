package main

import (
	"context"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

func TestCallUsage(t *testing.T) {
	if code := call(nil); code != 2 {
		t.Fatalf("call without --socket: exit %d, want 2", code)
	}
}

func TestServeNeedsASocket(t *testing.T) {
	if err := serve(context.Background(), cli.Flags{}); err == nil {
		t.Fatal("serve without a socket succeeded")
	}
}
