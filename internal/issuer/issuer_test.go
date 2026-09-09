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
	return issuer.New(issuer.Config{URL: "https://issuer.example"}, set, dir, issuer.NewMemoryState())
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
	if !grant.Result.Has("all:gitops:deployer") {
		t.Errorf("groups = %v, want all:gitops:deployer", grant.Result.Groups)
	}
	// all:gitops:deployer says 1h and all:gitops:builder 30m; the job matches both, and
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
		"rung:platform": true, "rung:engineering": true, "all:access-roster:operator": true,
		"kernel:k8s:admin": true, "devel:k8s:admin": true, "devel:k8s:viewer": true,
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
	if !held.Result.Has("rung:platform") {
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
	if _, err := iss.Sessions().Record(ctx, issuer.Opened{Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode, Token: "token-1"}); err != nil {
		t.Fatalf("record: %v", err)
	}

	ended, err := iss.Revoke(ctx, "ada@north.example")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if ended != 1 {
		t.Errorf("revoked %d sessions, want 1", ended)
	}
	dir.standing["ada@north.example"] = issuer.Standing{Found: true, Authoritative: false}
	if _, err := iss.Exchange(ctx, ada, "aws:1111:power"); err == nil {
		t.Errorf("a revoked identity is still held through an unvouched hub")
	}
}

// Sessions are the index that makes "what is open right now" answerable
// and revocable, per identity and per client. It lives in the shared
// store, so what one replica records another can list and end.
func TestSessions(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	state := issuer.NewMemoryState()
	state.SetClock(func() time.Time { return now })
	sessions := issuer.NewSessions(state, 12*time.Hour)
	sessions.SetClock(func() time.Time { return now })

	record := func(identity, client string, how issuer.How, token string) issuer.Session {
		t.Helper()

		session, err := sessions.Record(ctx, issuer.Opened{Identity: identity, ClientID: client, How: how, Token: token})
		if err != nil {
			t.Fatalf("record %s at %s: %v", identity, client, err)
		}

		return session
	}

	counted := func(q issuer.Query) int {
		t.Helper()

		listed, err := sessions.List(ctx, q)
		if err != nil {
			t.Fatalf("list %+v: %v", q, err)
		}

		return len(listed)
	}

	record("ada@north.example", "argocd", issuer.HowCode, "t-argocd")
	kubectl := record("ada@north.example", "k8s:kernel", issuer.HowDevice, "t-kubectl")
	record("eli@south.example", "argocd", issuer.HowCode, "t-eli")

	if got := counted(issuer.Query{}); got != 3 {
		t.Errorf("all = %d, want 3", got)
	}

	if got := counted(issuer.Query{Identity: "Ada@North.Example"}); got != 2 {
		t.Errorf("ada's = %d, want 2 and an address matched case-insensitively", got)
	}

	if got := counted(issuer.Query{ClientID: "argocd"}); got != 2 {
		t.Errorf("argocd's = %d, want 2", got)
	}

	// A refresh spends the old token and carries the session on.
	if _, ok, err := sessions.Refreshed(ctx, "t-kubectl", "t-kubectl-2"); err != nil || !ok {
		t.Fatalf("refresh did not find the session: ok=%v err=%v", ok, err)
	}

	if _, ok, _ := sessions.ByToken(ctx, "t-kubectl"); ok {
		t.Errorf("the spent token still works")
	}

	if session, ok, _ := sessions.ByToken(ctx, "t-kubectl-2"); !ok || session.ID != kubectl.ID {
		t.Errorf("the new token does not carry the same session")
	}

	// Ending one client's session must not end the others: an operator
	// dealing with one incident should not cut off unrelated work.
	ended, err := sessions.Revoke(ctx, issuer.Query{Identity: "ada@north.example", ClientID: "argocd"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if ended != 1 {
		t.Errorf("revoked %d, want 1", ended)
	}

	if got := counted(issuer.Query{Identity: "ada@north.example"}); got != 1 {
		t.Errorf("ada keeps %d sessions, want her kubectl one", got)
	}

	if gone, err := sessions.RevokeID(ctx, kubectl.ID); err != nil || !gone {
		t.Errorf("revoking by id found nothing: %v", err)
	}

	if got := counted(issuer.Query{Identity: "ada@north.example"}); got != 0 {
		t.Errorf("ada keeps %d sessions, want none", got)
	}

	// Expiry is not revocation: a session that ran out stops being live
	// on its own, and nothing has to sweep for it to stop counting.
	now = now.Add(13 * time.Hour)

	if got := counted(issuer.Query{}); got != 0 {
		t.Errorf("expired sessions are still listed: %d", got)
	}
}

// The index is shared, so a session one replica records is one another
// can list and end. An index per process would answer with whatever that
// pod happened to see, and revoke only there.
func TestSessionsAreSharedBetweenReplicas(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	shared := issuer.NewMemoryState()
	replicaA := issuer.NewSessions(shared, time.Hour)
	replicaB := issuer.NewSessions(shared, time.Hour)

	recorded, err := replicaA.Record(ctx, issuer.Opened{Identity: "ada@north.example", ClientID: "console", How: issuer.HowCode, Token: "t-1"})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	listed, err := replicaB.List(ctx, issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(listed) != 1 || listed[0].ID != recorded.ID {
		t.Fatalf("the other replica lists %d sessions, want the one just recorded", len(listed))
	}

	if gone, err := replicaB.RevokeToken(ctx, "t-1"); err != nil || !gone {
		t.Fatalf("the other replica could not end it: gone=%v err=%v", gone, err)
	}

	// And the replica that recorded it agrees, which is the half that
	// makes revocation mean anything.
	if _, ok, err := replicaA.ByToken(ctx, "t-1"); err != nil || ok {
		t.Errorf("the recording replica still honours a revoked token")
	}
}

// A token names the person, not only the address: the directory supplies
// given and family names, and the issuer carries them into `userinfo` and
// the ID token so a relying party's UI shows somebody rather than an
// address. None of it is authorization.
func TestATokenNamesThePerson(t *testing.T) {
	t.Parallel()

	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {
			Found: true, Authoritative: true,
			Groups:     []string{"directory-admins@north.example"},
			GivenName:  "Ada",
			FamilyName: "North",
		},
	}}

	resolved, err := issuer.NewResolver(dir, time.Hour).Resolve(context.Background(), "ada@north.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if resolved.GivenName != "Ada" || resolved.FamilyName != "North" {
		t.Errorf("names = %q %q, want Ada North", resolved.GivenName, resolved.FamilyName)
	}
}

// A held answer carries the last known GRANTS and nothing else. A name
// recovered from memory would be a claim the issuer cannot currently
// vouch for, and the hold window exists for authorization, not for
// cosmetics.
func TestAHeldAnswerCarriesNoNames(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {
			Found: true, Authoritative: true,
			Groups:     []string{"directory-admins@north.example"},
			GivenName:  "Ada",
			FamilyName: "North",
		},
	}}
	resolver := issuer.NewResolver(dir, time.Hour)

	if _, err := resolver.Resolve(ctx, "ada@north.example"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The directory can no longer vouch for anything.
	dir.standing["ada@north.example"] = issuer.Standing{Found: true, Authoritative: false}

	held, err := resolver.Resolve(ctx, "ada@north.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !held.Held {
		t.Fatal("the answer was not held")
	}

	if len(held.Groups) == 0 {
		t.Error("a held answer lost the grants, which is the thing it is for")
	}

	if held.GivenName != "" || held.FamilyName != "" {
		t.Errorf("a held answer carried names: %q %q", held.GivenName, held.FamilyName)
	}
}
