package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

type memoryConfirmations struct {
	mu    sync.Mutex
	byOrg map[string]connection.Confirmation
}

func (m *memoryConfirmations) PutConfirmation(_ context.Context, c connection.Confirmation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byOrg[c.Org] = c
	return nil
}

func (m *memoryConfirmations) Confirmations(context.Context) (map[string]connection.Confirmation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.byOrg), nil
}

// Only the removal set the latest report shows can be confirmed, only by
// an operator, and the confirmation is what the status then carries.
func TestConfirmingRemovalsIsForTheSetTheReportShows(t *testing.T) {
	document, err := status.Encode(status.Org{Org: "globex", Breaker: &status.Breaker{Affected: 3, Members: 4, Fingerprint: "abc123"}})
	if err != nil {
		t.Fatal(err)
	}
	console := githubConsole(t, reports{status.Key("globex"): document})
	confirmations := &memoryConfirmations{byOrg: map[string]connection.Confirmation{}}
	console.deps.GitHubConfirmations = confirmations
	confirm := func(ctx context.Context, fingerprint string) error {
		_, err := console.ConfirmGitHubRemovals(ctx, connect.NewRequest(&directoryrosterv1.ConfirmGitHubRemovalsRequest{Org: "globex", Fingerprint: fingerprint}))
		return err
	}

	viewer := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer})
	if err := confirm(viewer, "abc123"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer confirming = %v, want permission denied", err)
	}
	if err := confirm(operator(), "stale"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stale fingerprint = %v, want failed precondition", err)
	}
	if err := confirm(operator(), "abc123"); err != nil {
		t.Fatalf("confirming the shown set: %v", err)
	}
	got, err := githubStatus(t, console, access.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	c := organisation(t, got, "globex").GetRemovalConfirmation()
	if c.GetFingerprint() != "abc123" || c.GetConfirmedBy() != "ada@north.example" {
		t.Errorf("confirmation = %+v", c)
	}
	if b := organisation(t, got, "globex").GetBreaker(); b.GetAffected() != 3 || b.GetFingerprint() != "abc123" {
		t.Errorf("breaker = %+v", b)
	}

	// A day later it no longer holds.
	confirmations.byOrg["globex"] = connection.Confirmation{Org: "globex", Fingerprint: "abc123", By: "x", At: time.Now().Add(-25 * time.Hour)}
	got, _ = githubStatus(t, console, access.RoleViewer)
	if organisation(t, got, "globex").GetRemovalConfirmation() != nil {
		t.Error("a day-old confirmation still holds")
	}
}

// An import adopts a pairing only when it was approved, an address is a
// live account the directory vouches for, and the account is a member of a
// connected organisation — and says why for every one it skips.
func TestImportingLinksAppliesTheThreeChecks(t *testing.T) {
	r := newLinkRig(t, directory{
		"ada@globex.example":  {InDomain: true, Found: true, Authoritative: true},
		"gone@globex.example": {InDomain: true, Found: true, Suspended: true, Authoritative: true},
		"out@globex.example":  {InDomain: true, Found: true, Authoritative: true},
	})
	r.github.AddMember("ada-gh", false)
	r.github.AddMember("gone-gh", false)
	r.github.AddAccount("out-gh")
	credentialFor(t, r, "globex")

	response, err := r.console.ImportGitHubLinks(operator(), connect.NewRequest(&directoryrosterv1.ImportGitHubLinksRequest{
		Origin: "github-roster 0.x",
		Records: []*directoryrosterv1.GitHubLinkRecord{
			{Login: "ada-gh", Emails: []string{"ada@globex.example"}, ApprovedBy: "boss@globex.example"},
			{Login: "gone-gh", Emails: []string{"gone@globex.example"}, ApprovedBy: "boss@globex.example"},
			{Login: "out-gh", Emails: []string{"out@globex.example"}, ApprovedBy: "boss@globex.example"},
			{Login: "ada-gh", Emails: []string{"ada@globex.example"}},
		},
	}))
	if err != nil {
		t.Fatalf("ImportGitHubLinks: %v", err)
	}
	if len(response.Msg.GetImported()) != 1 || response.Msg.GetImported()[0].GetLogin() != "ada-gh" ||
		response.Msg.GetImported()[0].GetSource() != string(link.SourceImported) {
		t.Errorf("imported = %+v, want ada-gh alone, as imported", response.Msg.GetImported())
	}
	reasons := map[string]string{}
	for _, skipped := range response.Msg.GetSkipped() {
		reasons[skipped.GetLogin()] += skipped.GetReason() + ";"
	}
	for login, want := range map[string]string{"gone-gh": "suspended", "out-gh": "not a member", "ada-gh": "nobody approved"} {
		if !strings.Contains(reasons[login], want) {
			t.Errorf("%s skipped for %q, want %q", login, reasons[login], want)
		}
	}
	for _, l := range r.links.byID {
		if l.Login == "ada-gh" && (!l.Active() || l.Checked() || !strings.Contains(l.Note, "approved by boss@globex.example")) {
			t.Errorf("ada's link = %+v", l)
		}
	}
}

// credentialFor connects the rig's fake organisation, so an import can ask
// it who its members are. The fake mints a token for any App key.
func credentialFor(t *testing.T, r *linkRig, org string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryConnections()
	_ = store.Put(context.Background(),
		connection.Record{Org: org, AppID: 42, AppSlug: org + "-access-roster", InstallationID: 7},
		connection.Credential{Org: org, AppID: 42, InstallationID: 7,
			PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))})
	r.console.deps.GitHubOrgs = store
}
