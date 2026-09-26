package server

import (
	"testing"

	"github.com/truvity/access-roster/policy"
)

// TestHeldProtoReportsTheChain proves the wire side of the "why do I hold
// this group" chain: a concrete grant's key is its own group and is never
// a wildcard, a mapping wildcard's key differs from the group it granted
// and is reported as one, and an inherited group carries the direct
// parent that implied it and no key at all -- exactly what policy.Held
// already computes ([policy.Held.Key], [policy.Held.Implies]), rendered
// onto [directoryrosterv1.HeldGroup].
func TestHeldProtoReportsTheChain(t *testing.T) {
	t.Parallel()
	// argocd and k8s are two unrelated things on purpose: the concrete
	// membership below must not ALSO be reachable through the wildcard's
	// implies chain, or it would carry two [policy.Held] reasons and the
	// test would be asserting on whichever one happened to sort last.
	p, err := policy.Parse([]byte(`
version: 1
vocabulary:
  scopes:
    devel: {}
  things:
    k8s:
      scopes: [devel]
      roles: { viewer: [], operator: [viewer], admin: [operator] }
    argocd:
      scopes: [devel]
      roles: { viewer: [], deployer: [viewer] }
groups:
  devel:argocd:deployer: { members: [ops@b.example] }
  "*:k8s:admin": { matchers: [{ email_domain: b.example }] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	got := set.Evaluate(policy.Input{
		Email:           "alice@b.example",
		DirectoryGroups: []string{"ops@b.example"},
		Authoritative:   true,
	})

	byGroup := map[string]*policy.Held{}
	for i, h := range got.Held {
		byGroup[h.Group] = &got.Held[i]
	}

	protoByGroup := map[string]*[3]any{}
	for _, out := range heldProto(got.Held) {
		protoByGroup[out.Group] = &[3]any{out.GrantedByKey, out.Wildcard, out.ImpliedBy}
	}

	// A concrete grant: the key is the group's own name, and it is never
	// a wildcard.
	if _, ok := byGroup["devel:argocd:deployer"]; !ok {
		t.Fatalf("held groups = %v, want devel:argocd:deployer (a concrete membership)", got.Groups)
	}
	if fields := protoByGroup["devel:argocd:deployer"]; fields == nil ||
		fields[0] != "devel:argocd:deployer" || fields[1] != false || fields[2] != "" {
		t.Errorf("devel:argocd:deployer proto fields = %+v, want key=devel:argocd:deployer wildcard=false implied_by=\"\"", fields)
	}

	// A wildcard grant: the key is the wildcard itself, which differs
	// from the concrete group it granted.
	if fields := protoByGroup["devel:k8s:admin"]; fields == nil ||
		fields[0] != "*:k8s:admin" || fields[1] != true || fields[2] != "" {
		t.Errorf("devel:k8s:admin proto fields = %+v, want key=*:k8s:admin wildcard=true implied_by=\"\"", fields)
	}

	// An inherited grant: no key of its own, and the direct parent that
	// implied it -- devel:k8s:viewer comes from devel:k8s:admin's role
	// ladder (admin -> operator -> viewer), but the DIRECT parent is
	// operator, not the ultimate root.
	if fields := protoByGroup["devel:k8s:viewer"]; fields == nil ||
		fields[0] != "" || fields[1] != false || fields[2] != "devel:k8s:operator" {
		t.Errorf("devel:k8s:viewer proto fields = %+v, want key=\"\" wildcard=false implied_by=devel:k8s:operator", fields)
	}
}
