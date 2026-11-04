package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

func run(t *testing.T, args ...string) int {
	t.Helper()
	var f flags
	var out, errb bytes.Buffer
	return cli.Run(context.Background(), "key", commands(&f), f.add, args, &out, &errb)
}

func TestCommandLine(t *testing.T) {
	dir := t.TempDir()
	flagsOK := []string{
		"--boundary", "dev", "--run-dir", filepath.Join(dir, "run"), "--store-socket", filepath.Join(dir, "s.sock"),
		"--driver-socket", filepath.Join(dir, "d.sock"), "--transport-socket", filepath.Join(dir, "t.sock"), "--node", "node-1",
	}
	if got := run(t, append([]string{"serve", "--boundary", "dev"}, "--node", "node-1")...); got != cli.ExitUsage {
		t.Errorf("serve without its flags exits %d, want %d", got, cli.ExitUsage)
	}
	// A check that cannot reach what it needs is refused: exit 3, never a pass.
	if got := run(t, append([]string{"check"}, flagsOK...)...); got != cli.ExitRefused {
		t.Errorf("check with nothing reachable exits %d, want %d", got, cli.ExitRefused)
	}
	if got := run(t, "version"); got != cli.ExitOK {
		t.Errorf("version exits %d", got)
	}
}
