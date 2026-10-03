package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The command surface is fixed: these are the commands a deployment is
// written against, and each is refused cleanly when it is wrong.
func TestTheCommandSurface(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}, {"serve", "--help"}, {"serve", "--version"},
		{"controller", "github", "--help"}, {"controller", "slack", "--version"}} {
		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Errorf("%v: %v", args, err)
		}
		if out.Len() == 0 {
			t.Errorf("%v: printed nothing", args)
		}
	}
}

func TestAWrongCommandIsAUsageError(t *testing.T) {
	for name, args := range map[string][]string{
		"none":                  {},
		"unknown":               {"tick"},
		"controller alone":      {"controller"},
		"controller unknown":    {"controller", "gitlab"},
		"a retired binary name": {"access-issuer"},
	} {
		var out bytes.Buffer
		if err := run(args, &out); !errors.Is(err, errUsage) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSubcommandsNeedTheirFile(t *testing.T) {
	for _, args := range [][]string{{"serve"}, {"controller", "github"}, {"controller", "slack"}} {
		var out bytes.Buffer
		err := run(args, &out)
		if err == nil || !strings.Contains(err.Error(), "--config") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestMigrateIsNotYetAvailable(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"migrate"}, &out)
	if !errors.Is(err, errNotAvailable) || !strings.Contains(err.Error(), "not yet available") {
		t.Errorf("migrate: %v", err)
	}
}
