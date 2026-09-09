package policy_test

import (
	"testing"

	"github.com/truvity/access-roster/policy"
)

// A ServiceAccount's subject names its cluster, because the same
// namespace and name exist on every cluster in the estate. Without it two
// different machines are one `sub`, and an audit log cannot tell them
// apart — which is the collision `sub` exists to prevent.
func TestAServiceAccountSubjectNamesItsCluster(t *testing.T) {
	t.Parallel()

	named := policy.ServiceAccountRef{Cluster: "kernel", Namespace: "access-issuer", Name: "recovery"}
	if got := named.Subject(); got != "kernel:k8s:access-issuer:recovery" {
		t.Errorf("subject = %q, want the cluster first, like every group name", got)
	}

	// An installation that has not named its cluster keeps the subject it
	// already mints rather than getting an invented cluster.
	plain := policy.ServiceAccountRef{Namespace: "access-issuer", Name: "recovery"}
	if got := plain.Subject(); got != "k8s:access-issuer:recovery" {
		t.Errorf("subject = %q, want the unqualified form", got)
	}
}

// Every spelling this estate has minted is readable, and only the newest
// is written. A reader that knew one of them would refuse a token minted
// by a release either side of its own — on, for recovery, exactly the day
// it is the only way in.
func TestEverySpellingOfAServiceAccountIsRead(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		subject string
		want    policy.ServiceAccountRef
	}{
		{
			// The API server's own, which a recovery sign-in used to
			// complete as.
			subject: "system:serviceaccount:access-issuer:recovery",
			want:    policy.ServiceAccountRef{Namespace: "access-issuer", Name: "recovery"},
		},
		{
			// This issuer's older form, from a token exchange.
			subject: "k8s:access-issuer:recovery",
			want:    policy.ServiceAccountRef{Namespace: "access-issuer", Name: "recovery"},
		},
		{
			subject: "kernel:k8s:access-issuer:recovery",
			want: policy.ServiceAccountRef{
				Cluster: "kernel", Namespace: "access-issuer", Name: "recovery",
			},
		},
	} {
		got, ok := policy.ParseServiceAccountSubject(tc.subject)
		if !ok || got != tc.want {
			t.Errorf("%q → %+v, %v; want %+v", tc.subject, got, ok, tc.want)
		}
	}

	// A person's address is not a ServiceAccount, and neither is a group
	// name that happens to have colons in it.
	for _, notOne := range []string{
		"ada@north.example", "kernel:k8s:admin", "", "k8s::recovery", "system:serviceaccount:",
	} {
		if got, ok := policy.ParseServiceAccountSubject(notOne); ok {
			t.Errorf("%q parsed as a ServiceAccount: %+v", notOne, got)
		}
	}
}

// A rule may narrow to one cluster's account, and a rule that names no
// cluster still means what it meant before clusters were named — which is
// what every rule written so far says.
func TestAMatcherMayNarrowToOneCluster(t *testing.T) {
	t.Parallel()

	set := compile(t, `
version: 1
groups:
  anywhere:
    matchers:
      - service_account: { namespace: authz, name: webhook }
  kernel-only:
    matchers:
      - service_account: { cluster: kernel, namespace: authz, name: webhook }
`)

	onKernel := set.Evaluate(policy.Input{ServiceAccount: &policy.ServiceAccountRef{
		Cluster: "kernel", Namespace: "authz", Name: "webhook",
	}})
	if !onKernel.Has("anywhere") || !onKernel.Has("kernel-only") {
		t.Errorf("on kernel = %v, want both rules", onKernel.Groups)
	}

	// The same account on another cluster is a different machine.
	onDevel := set.Evaluate(policy.Input{ServiceAccount: &policy.ServiceAccountRef{
		Cluster: "devel", Namespace: "authz", Name: "webhook",
	}})
	if !onDevel.Has("anywhere") {
		t.Errorf("on devel = %v, want the unqualified rule to still hold", onDevel.Groups)
	}

	if onDevel.Has("kernel-only") {
		t.Errorf("on devel = %v, want another cluster's account refused by the narrowed rule", onDevel.Groups)
	}
}

func compile(t *testing.T, document string) *policy.Set {
	t.Helper()

	parsed, err := policy.Parse([]byte(document))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	set, err := policy.NewSet(parsed)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	return set
}
