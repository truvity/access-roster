package main

import (
	"context"
	"os"
	"testing"
)

// verifies: REQ-DATA-066, REQ-KEYS-044, REQ-ISO-090
// TestDenyMatrix runs the deny matrix (ADR 0002, "Enforcement is tested") against a running local installation: for
// every caller and every socket, a probe as the caller's uid, with its unit's groups, must be refused at the socket or
// by the callee's guard when the registry does not list the call, and must get past the guard when it does. A single
// pair that the registry denies and the installation lets through fails the test.
//
// tests/deny/run.sh (`just local-deny`, and the `deny` job of CI) starts the installation and runs this test with
// SLUIS_DENY_RUN_PROJECT and SLUIS_DENY_RUN_IMAGE set. Without them there is no installation to probe, and the test
// says so and does not run.
func TestDenyMatrix(t *testing.T) {
	project, image := os.Getenv("SLUIS_DENY_RUN_PROJECT"), os.Getenv("SLUIS_DENY_RUN_IMAGE")
	if project == "" || image == "" {
		t.Skip("SKIP: no installation to probe; tests/deny/run.sh (just local-deny) starts one and runs this test")
	}
	boundary := os.Getenv("SLUIS_DENY_RUN_BOUNDARY")
	if boundary == "" {
		boundary = "dev"
	}
	ok, err := run(context.Background(), project, boundary, image, os.Getenv("SLUIS_DENY_REPORT"))
	if err != nil {
		t.Fatalf("the matrix did not run: %v", err)
	}
	if !ok {
		t.Fatal("the deny matrix found violations; the report above names each pair")
	}
}
