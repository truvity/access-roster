package issuer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// fakeDirectory stands in for the hub. The issuer never reads a directory
// itself, so this is the whole of its dependency on one.
type fakeDirectory struct {
	standing map[string]issuer.Standing
	err      error
	calls    int
}

func (f *fakeDirectory) ResolveUser(_ context.Context, email string) (issuer.Standing, error) {
	f.calls++
	if f.err != nil {
		return issuer.Standing{}, f.err
	}
	return f.standing[email], nil
}

func newIssuer(t *testing.T, dir issuer.Directory) *issuer.Issuer {
	t.Helper()
	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("parse the demonstration policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	return issuer.New(issuer.Config{URL: "https://issuer.example"}, set, dir)
}

func live(groups ...string) issuer.Standing {
	return issuer.Standing{Found: true, Groups: groups, Authoritative: true}
}

// The gate the whole rule-gated audience design rests on: a cloud trust
// policy can see only sub, aud, amr and email, so the decision has to
// ride in aud — which means an audience the proof is not entitled to must
// be refused here, at the exchange, or never.
func TestExchangeGatesTheAudience(t *testing.T) {
	t.Parallel()
	iss := newIssuer(t, &fakeDirectory{})
	ctx := context.Background()

	onMaster := issuer.Proof{GitHub: &policy.GitHubClaims{
		Repository: "example-org/gitops", Owner: "example-org", Ref: "refs/heads/master",
	}}
	grant, err := iss.Exchange(ctx, onMaster, "aws:1111:deployer")
	if err != nil {
		t.Fatalf("master → deployer: %v", err)
	}
	if grant.Audience != "aws:1111:deployer" {
		t.Errorf("audience = %q", grant.Audience)
	}
	if grant.Subject != "github:example-org/gitops" {
		t.Errorf("subject = %q, want the repository and never a person", grant.Subject)
	}
	if !grant.Result.Has("ci-gitops") {
		t.Errorf("groups = %v, want ci-gitops", grant.Result.Groups)
	}
	// ci-gitops says 1h and ci-any-branch 30m; the job matches both, and
	// the shortest wins.
	if got := time.Duration(iss.Lifetime(grant)); got != 30*time.Minute {
		t.Errorf("lifetime = %s, want the shortest across the groups it holds", got)
	}

	// The same repository on a fork branch matches only the owner-wide
	// rule, which opens nothing. This is the case that must fail: it is a
	// pull request from anyone with a fork.
	onFork := issuer.Proof{GitHub: &policy.GitHubClaims{
		Repository: "example-org/gitops", Owner: "example-org", Ref: "refs/heads/patch-1",
	}}
	if _, err := iss.Exchange(ctx, onFork, "aws:1111:deployer"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("fork branch → deployer: %v, want a refusal", err)
	}

	// "There is no such audience" and "you may not have this audience" are
	// different facts, and only the second is about the caller.
	if _, err := iss.Exchange(ctx, onMaster, "aws:9999:nobody"); !errors.Is(err, issuer.ErrUnknownTarget) {
		t.Errorf("unknown audience: %v, want ErrUnknownTarget", err)
	}
	if _, err := iss.Exchange(ctx, onMaster, ""); !errors.Is(err, issuer.ErrNoTarget) {
		t.Errorf("no audience: %v, want ErrNoTarget", err)
	}
}

// A workload's proof is matched on its ServiceAccount and nothing else,
// and it reaches exactly the one client its group opens.
func TestExchangeAdmitsAWorkload(t *testing.T) {
	t.Parallel()
	iss := newIssuer(t, &fakeDirectory{})
	proof := issuer.Proof{ServiceAccount: &policy.ServiceAccountRef{
		Namespace: "identity-system", Name: "authorization-webhook",
	}}

	grant, err := iss.Exchange(context.Background(), proof, "directory-roster")
	if err != nil {
		t.Fatalf("workload → directory-roster: %v", err)
	}
	if grant.Subject != "k8s:identity-system:authorization-webhook" {
		t.Errorf("subject = %q", grant.Subject)
	}
	if _, err := iss.Exchange(context.Background(), proof, "aws:1111:power"); !errors.Is(err, issuer.ErrRefused) {
		t.Errorf("workload → power: %v, want a refusal", err)
	}
}

// A person's claims are the deep merge of every held group's fragment,
// and the client's cap is applied after the groups have had their say.
func TestExchangeMergesClaimsAndCapsLifetime(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": live("directory-admins@north.example", "engineering@north.example"),
	}}
	iss := newIssuer(t, dir)
	ctx := context.Background()
	ada := issuer.Proof{Email: "ada@north.example"}

	grant, err := iss.Exchange(ctx, ada, "aws:1111:power")
	if err != nil {
		t.Fatalf("ada → power: %v", err)
	}
	groups, _ := grant.Claims["groups"].([]any)
	want := map[string]bool{
		"platform": true, "engineering": true, "hub-operators": true,
		"cluster-kernel:admin": true, "cluster-devel:admin": true, "cluster-devel:developer": true,
	}
	for _, g := range groups {
		delete(want, g.(string))
	}
	if len(want) != 0 {
		t.Errorf("groups claim %v is missing %v", groups, want)
	}
	// Two fragments set tailnet.tiers; a list union rather than one
	// winning is the whole reason the merge exists.
	tailnet, ok := grant.Claims["tailnet"].(map[string]any)
	if !ok {
		t.Fatalf("claims carry no tailnet: %v", grant.Claims)
	}
	if tiers, _ := tailnet["tiers"].([]any); len(tiers) != 2 {
		t.Errorf("tailnet.tiers = %v, want vpc and service unioned", tailnet["tiers"])
	}

	// platform says 4h and is the shortest she holds; the exchange client
	// caps nothing, so 4h stands.
	if got := time.Duration(iss.Lifetime(grant)); got != 4*time.Hour {
		t.Errorf("power lifetime = %s, want 4h", got)
	}
	// ArgoCD caps at 2h, which is shorter still.
	capped, err := iss.Exchange(ctx, ada, "argocd")
	if err != nil {
		t.Fatalf("ada → argocd: %v", err)
	}
	if got := time.Duration(iss.Lifetime(capped)); got != 2*time.Hour {
		t.Errorf("argocd lifetime = %s, want the client's 2h cap", got)
	}
}

// The hold window is what keeps an unreachable directory from reading as
// a mass revocation, and what stops it from lasting forever.
func TestHoldWindow(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": live("directory-admins@north.example"),
	}}
	iss := newIssuer(t, dir)
	ctx := context.Background()
	ada := issuer.Proof{Email: "ada@north.example"}

	if _, err := iss.Exchange(ctx, ada, "aws:1111:power"); err != nil {
		t.Fatalf("first, authoritative: %v", err)
	}

	// The hub can no longer vouch for what it says. Ada keeps what she
	// last had, and the grant says so.
	dir.standing["ada@north.example"] = issuer.Standing{Found: true, Groups: nil, Authoritative: false}
	held, err := iss.Exchange(ctx, ada, "aws:1111:power")
	if err != nil {
		t.Fatalf("within the window: %v", err)
	}
	if !held.Held {
		t.Errorf("grant does not say it was held")
	}
	if !held.Result.Has("platform") {
		t.Errorf("held groups = %v, want the last known", held.Result.Groups)
	}

	// Someone never seen before has nothing to hold, so the window grants
	// them nothing rather than guessing.
	brian := issuer.Proof{Email: "brian@north.example"}
	dir.standing["brian@north.example"] = issuer.Standing{Found: true, Authoritative: false}
	var refused *issuer.Refused
	if _, err := iss.Exchange(ctx, brian, "aws:1111:power"); !errors.As(err, &refused) {
		t.Errorf("unseen identity within the window: %v, want a refusal", err)
	}

	// A hub that is down at all is the same situation as one that cannot
	// vouch: act on what was last known, and only that.
	dir.err = errors.New("dial the hub: connection refused")
	if _, err := iss.Exchange(ctx, ada, "aws:1111:power"); err != nil {
		t.Errorf("hub down, within the window: %v, want the last known", err)
	}
	if _, err := iss.Exchange(ctx, brian, "aws:1111:power"); err == nil {
		t.Errorf("hub down, never seen: want an error")
	}
}

// A suspended account gets nothing even though its identity provider
// would still sign it in. That is the point of asking the hub at all.
func TestSuspendedGetsNothing(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"cleo@north.example": {Found: true, Suspended: true, Groups: []string{"everyone@north.example"}, Authoritative: true},
	}}
	iss := newIssuer(t, dir)

	var refused *issuer.Refused
	_, err := iss.Exchange(context.Background(), issuer.Proof{Email: "cleo@north.example"}, "argocd")
	if !errors.As(err, &refused) {
		t.Fatalf("suspended: %v, want a refusal", err)
	}
}

// Revoking must also forget the last-known groups, or an unreachable hub
// would keep a revoked person alive for the length of the hold window.
func TestRevokeForgetsTheHeldAnswer(t *testing.T) {
	t.Parallel()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": live("directory-admins@north.example"),
	}}
	iss := newIssuer(t, dir)
	ctx := context.Background()
	ada := issuer.Proof{Email: "ada@north.example"}

	if _, err := iss.Exchange(ctx, ada, "aws:1111:power"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	iss.Sessions().Record("ada@north.example", "argocd", issuer.HowCode, "token-1")

	if ended := iss.Revoke("ada@north.example"); ended != 1 {
		t.Errorf("revoked %d sessions, want 1", ended)
	}
	dir.standing["ada@north.example"] = issuer.Standing{Found: true, Authoritative: false}
	if _, err := iss.Exchange(ctx, ada, "aws:1111:power"); err == nil {
		t.Errorf("a revoked identity is still held through an unvouched hub")
	}
}

// Sessions are the index that makes "what is open right now" answerable
// and revocable, per identity and per client.
func TestSessions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	sessions := issuer.NewSessions(12 * time.Hour)
	sessions.SetClock(func() time.Time { return now })

	sessions.Record("ada@north.example", "argocd", issuer.HowCode, "t-argocd")
	kubectl := sessions.Record("ada@north.example", "k8s:kernel", issuer.HowDevice, "t-kubectl")
	sessions.Record("eli@south.example", "argocd", issuer.HowCode, "t-eli")

	if got := len(sessions.List(issuer.Query{})); got != 3 {
		t.Errorf("all = %d, want 3", got)
	}
	if got := len(sessions.List(issuer.Query{Identity: "Ada@North.Example"})); got != 2 {
		t.Errorf("ada's = %d, want 2 and an address matched case-insensitively", got)
	}
	if got := len(sessions.List(issuer.Query{ClientID: "argocd"})); got != 2 {
		t.Errorf("argocd's = %d, want 2", got)
	}

	// A refresh spends the old token and carries the session on.
	if _, ok := sessions.Refreshed("t-kubectl", "t-kubectl-2"); !ok {
		t.Fatalf("refresh did not find the session")
	}
	if _, ok := sessions.ByToken("t-kubectl"); ok {
		t.Errorf("the spent token still works")
	}
	if s, ok := sessions.ByToken("t-kubectl-2"); !ok || s.ID != kubectl.ID {
		t.Errorf("the new token does not carry the same session")
	}

	// Ending one client's session must not end the others: an operator
	// dealing with one incident should not cut off unrelated work.
	if ended := sessions.Revoke(issuer.Query{Identity: "ada@north.example", ClientID: "argocd"}); ended != 1 {
		t.Errorf("revoked %d, want 1", ended)
	}
	if got := len(sessions.List(issuer.Query{Identity: "ada@north.example"})); got != 1 {
		t.Errorf("ada keeps %d sessions, want her kubectl one", got)
	}
	if !sessions.RevokeID(kubectl.ID) {
		t.Errorf("revoking by id found nothing")
	}
	if got := len(sessions.List(issuer.Query{Identity: "ada@north.example"})); got != 0 {
		t.Errorf("ada keeps %d sessions, want none", got)
	}

	// Expiry is not revocation: a session that ran out stops being live
	// on its own, and the sweep is what removes it.
	now = now.Add(13 * time.Hour)
	if got := len(sessions.List(issuer.Query{})); got != 0 {
		t.Errorf("expired sessions are still listed: %d", got)
	}
	if swept := sessions.Sweep(); swept != 1 {
		t.Errorf("swept %d, want the one remaining", swept)
	}
}
