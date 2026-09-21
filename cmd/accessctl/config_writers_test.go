package main

import (
	"slices"
	"strings"
	"testing"
)

// TestCredentialArgsCarriesInteractiveMode is the regression test for a
// context that could not authenticate at all.
//
// `accessctl kubeconfig` wrote exec entries declaring
// client.authentication.k8s.io/v1 and omitting interactiveMode. That field
// is optional in v1beta1, which defaults it, and MANDATORY in v1, so
// kubectl refused every context this tool had ever written:
//
//	error: interactiveMode must be specified for accessctl:hive to use
//	exec authentication plugin
//
// It refuses before running the plugin, so no amount of looking at tokens
// or issuers finds it.
func TestCredentialArgsCarriesInteractiveMode(t *testing.T) {
	args := credentialArgs("/usr/local/bin/accessctl", "k8s:hive", "https://access.example.com")

	if !slices.Contains(args, "--exec-interactive-mode=Never") {
		t.Fatalf("interactiveMode is mandatory for %s and is missing; kubectl will refuse the entry.\ngot: %v",
			execAPIVersion, args)
	}
}

// TestCredentialArgsInteractiveModeMatchesTheAPIVersion guards the pairing
// rather than the literal: interactiveMode is only mandatory on v1, so a
// future move back to v1beta1 should make this test say so out loud rather
// than silently keep asserting a field nobody needs.
func TestCredentialArgsInteractiveModeMatchesTheAPIVersion(t *testing.T) {
	if !strings.HasSuffix(execAPIVersion, "/v1") {
		t.Skipf("execAPIVersion is %s; interactiveMode is only mandatory on v1", execAPIVersion)
	}

	args := credentialArgs("accessctl", "k8s:prod", "https://issuer.example.com")
	var mode string
	for _, a := range args {
		if rest, ok := strings.CutPrefix(a, "--exec-interactive-mode="); ok {
			mode = rest
		}
	}

	// Never, not IfAvailable: kube-token loads a cached sign-in and prints
	// a credential. It never prompts, and Never is also what lets kubectl
	// run the plugin where there is no stdin at all -- CI.
	if mode != "Never" {
		t.Fatalf("interactiveMode = %q, want %q: kube-token is not interactive, and Never is what makes the same kubeconfig work in CI", mode, "Never")
	}
}

// TestCredentialArgsCarriesTheExchangeInputs keeps the rest of the tail
// honest, since the whole list is what a context is worth.
func TestCredentialArgsCarriesTheExchangeInputs(t *testing.T) {
	const (
		binary   = "/opt/bin/accessctl"
		audience = "k8s:hive"
		issuer   = "https://access.excavador.xyz"
	)
	args := credentialArgs(binary, audience, issuer)

	for _, want := range []string{
		"--exec-api-version=" + execAPIVersion,
		"--exec-command=" + binary,
		"--exec-arg=kube-token",
		"--exec-arg=--audience=" + audience,
		"--exec-arg=--issuer=" + issuer,
	} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q\ngot: %v", want, args)
		}
	}
}
