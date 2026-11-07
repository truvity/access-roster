//go:build sluis_test

package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

func run(args ...string) (code int, out string) {
	var stdout, stderr bytes.Buffer
	var f flags
	code = cli.Run(context.Background(), "ca", commands(&f), f.add, args, &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

func TestVersion(t *testing.T) {
	if code, out := run("version"); code != cli.ExitOK || out == "" {
		t.Fatalf("version exited %d: %q", code, out)
	}
}

func TestServeAndCheckNeedTheBoundary(t *testing.T) {
	for _, args := range [][]string{{"serve"}, {"check"}} {
		if code, _ := run(args...); code != cli.ExitUsage {
			t.Errorf("%v exited %d, want usage (2)", args, code)
		}
	}
}

// The check fails closed when nothing can be reached.
func TestCheckFailsClosedWhenTheSocketsAreAbsent(t *testing.T) {
	code, _ := run("check", "--boundary", "dev", "--store-socket", "/nonexistent/store.sock",
		"--key-socket", "/nonexistent/key.sock")
	if code != cli.ExitRefused {
		t.Fatalf("check exited %d, want refused (3)", code)
	}
}
