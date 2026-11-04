package refusal_test

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

func TestNewCarriesTheDetail(t *testing.T) {
	err := refusal.New(connect.CodeNotFound, "absent", "id")
	if err.Code() != connect.CodeNotFound {
		t.Fatalf("code = %v", err.Code())
	}
	if r, ok := refusal.Reason(err); !ok || r != "absent" {
		t.Fatalf("Reason = %q, %v", r, ok)
	}
	if p, ok := refusal.FieldPath(err); !ok || p != "id" {
		t.Fatalf("FieldPath = %q, %v", p, ok)
	}
}

func TestReasonSeesThroughWrapping(t *testing.T) {
	err := fmt.Errorf("get: %w", refusal.New(connect.CodeAborted, "version", ""))
	if r, ok := refusal.Reason(err); !ok || r != "version" {
		t.Fatalf("Reason = %q, %v", r, ok)
	}
}

func TestReasonOfPlainErrors(t *testing.T) {
	if _, ok := refusal.Reason(errors.New("boom")); ok {
		t.Fatal("a plain error has no reason")
	}
	if _, ok := refusal.Reason(connect.NewError(connect.CodeInternal, errors.New("x"))); ok {
		t.Fatal("a Connect error without the detail has no reason")
	}
	if _, ok := refusal.Reason(nil); ok {
		t.Fatal("nil has no reason")
	}
}

func TestStripKeepsOnlyTheCode(t *testing.T) {
	err := refusal.New(connect.CodePermissionDenied, "call_graph", "secret.path")
	err.Meta().Set("X-Detail", "v")
	s := refusal.Strip(fmt.Errorf("ctx: %w", err))
	if s.Code() != connect.CodePermissionDenied {
		t.Fatalf("code = %v", s.Code())
	}
	if len(s.Details()) != 0 || len(s.Meta()) != 0 {
		t.Fatalf("detail or metadata survived: %v %v", s.Details(), s.Meta())
	}
	if got := s.Message(); got != "permission denied" {
		t.Fatalf("message = %q", got)
	}
	if _, ok := refusal.Reason(s); ok {
		t.Fatal("reason survived Strip")
	}
	if got := refusal.Strip(errors.New("a secret cause")).Code(); got != connect.CodeInternal {
		t.Fatalf("plain error code = %v", got)
	}
}
