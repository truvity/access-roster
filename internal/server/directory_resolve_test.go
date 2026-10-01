package server

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
)

func resolveGroups(t *testing.T, console *Console, who access.Identity, groups ...string) (*directoryrosterv1.ResolveDirectoryGroupsResponse, error) {
	t.Helper()
	got, err := console.ResolveDirectoryGroups(as(who), connect.NewRequest(&directoryrosterv1.ResolveDirectoryGroupsRequest{Groups: groups}))
	if err != nil {
		return nil, err
	}
	return got.Msg, nil
}

func TestResolveDirectoryGroupsExpandsNestingAndNamesTheDirectory(t *testing.T) {
	h := newConnectHarness(t)
	got, err := resolveGroups(t, h.console, everywhere, "ALL@north.example", "eng@south.example", "nobody@north.example", "loop-a@south.example")
	if err != nil || len(got.Groups) != 4 {
		t.Fatalf("resolve = %+v, %v", got, err)
	}
	if got.PolicyDigest == "" || got.PolicyDigest != h.console.deps.Authorizer.Policy().Digest() {
		t.Errorf("policy digest = %q", got.PolicyDigest)
	}
	all := got.Groups[0]
	var members []string
	for _, m := range all.Members {
		members = append(members, m.Email)
		if !m.Known || !m.Live {
			t.Errorf("%s: known %v live %v", m.Email, m.Known, m.Live)
		}
	}
	if !all.Found || !all.Authoritative || all.WorkspaceId != "C0north" || all.Email != "all@north.example" ||
		!slices.Equal(members, []string{"ann@north.example", "bob@north.example", "dee@north.example"}) ||
		!slices.Equal(all.Nested, []string{"partners@north.example"}) || all.Truncated {
		t.Errorf("all = %+v", all)
	}
	if eng := got.Groups[1]; !eng.Found || eng.WorkspaceId != "C0south" || len(eng.Members) != 1 {
		t.Errorf("eng = %+v", eng)
	}
	if none := got.Groups[2]; none.Found || len(none.Members) != 0 || none.WorkspaceId != "" {
		t.Errorf("a group nobody holds = %+v", none)
	}
	// Groups that name each other end, and are not cut short.
	if loop := got.Groups[3]; !loop.Found || loop.Truncated || !slices.Equal(loop.Nested, []string{"loop-b@south.example"}) {
		t.Errorf("a cycle = %+v", loop)
	}
}

// The answer never reveals a directory the caller may not view.
func TestResolveDirectoryGroupsIsGatedLikeEveryOtherRead(t *testing.T) {
	h := newConnectHarness(t)
	got, err := resolveGroups(t, h.console, northViewer, "partners@north.example", "eng@south.example")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Groups[0].Found || got.Groups[1].Found || len(got.Groups[1].Members) != 0 || got.Groups[1].WorkspaceId != "" {
		t.Errorf("a scoped viewer is told of %+v", got.Groups)
	}
	// A role over some directory is a role: the answer is simply empty.
	got, err = resolveGroups(t, h.console, elsewhereOp, "partners@north.example")
	if err == nil && got.Groups[0].Found {
		t.Error("an operator of an unrelated directory read another directory's group")
	}
	_, err = h.console.ResolveDirectoryGroups(context.Background(), connect.NewRequest(&directoryrosterv1.ResolveDirectoryGroupsRequest{}))
	wantCode(t, "no identity", err, connect.CodeUnauthenticated)
	_, err = resolveGroups(t, h.console, access.Identity{}, "partners@north.example")
	wantCode(t, "no role", err, connect.CodePermissionDenied)
	many := make([]string, resolveMaxGroups+1)
	for i := range many {
		many[i] = "g@north.example"
	}
	_, err = resolveGroups(t, h.console, everywhere, many...)
	wantCode(t, "too many groups", err, connect.CodeInvalidArgument)
}
