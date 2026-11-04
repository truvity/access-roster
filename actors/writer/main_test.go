package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var f flags
	var out, errb bytes.Buffer
	code := cli.Run(context.Background(), "writer", commands(&f), f.add, args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestServeNeedsABoundary(t *testing.T) {
	code, out := run(t, "serve")
	if code != cli.ExitUsage || !strings.Contains(out, "--boundary") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestTheSocketsDefaultToTheLayout(t *testing.T) {
	var f flags
	cfg, err := f.config(cli.Flags{Boundary: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{
		cfg.StoreSocket:     "/run/sluis/store/dev.sock",
		cfg.KeySocket:       "/run/sluis/key/dev/writer/key.sock",
		cfg.PolicySocket:    "/run/sluis/policy/dev.sock",
		cfg.BlobSocket:      "/run/sluis/writer/dev/blob.sock",
		cfg.TransportSocket: "/run/sluis/audit/dev/receive.sock",
	} {
		if got != want {
			t.Fatalf("socket = %s, want %s", got, want)
		}
	}
	if cfg.Instance == "" {
		t.Fatal("no instance name")
	}
}

func TestTheWriterTakesNoSocketGID(t *testing.T) {
	// The writer serves no socket, so there is nothing to open to a group: the flag is not one of its flags.
	code, out := run(t, "check", "--boundary", "dev", "--socket-gid", "61000")
	if code != cli.ExitUsage || !strings.Contains(out, "socket-gid") {
		t.Fatalf("exit %d: %s", code, out)
	}
}
