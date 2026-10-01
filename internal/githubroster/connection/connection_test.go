package connection_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/githubroster/connection"
)

// A credential is a private key, so nothing that reads one may put it in
// an error: errors reach logs and, on a callback, a page.
func TestAnUnreadableCredentialNeverRepeatsItself(t *testing.T) {
	t.Parallel()
	secret := `{"version":1,"org":"globex","private_key":"-----BEGIN RSA PRIVATE KEY-----SECRET` // truncated JSON
	_, err := connection.DecodeCredential([]byte(secret))
	if err == nil {
		t.Fatal("a truncated credential decoded")
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("the error repeats the key: %v", err)
	}
}

// What the service writes, the controller reads back whole — and a
// document of another version is refused rather than half-read.
func TestARecordAndACredentialReadBackAsWritten(t *testing.T) {
	t.Parallel()
	raw, err := connection.EncodeCredential(connection.Credential{Org: "globex", AppID: 42, InstallationID: 7, PrivateKey: "key"})
	if err != nil {
		t.Fatalf("EncodeCredential: %v", err)
	}
	credential, err := connection.DecodeCredential(raw)
	if err != nil || credential.AppID != 42 || credential.InstallationID != 7 || credential.PrivateKey != "key" {
		t.Errorf("credential = %+v, %v", credential, err)
	}
	record, err := connection.EncodeRecord(connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster"})
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	if decoded, err := connection.DecodeRecord(record); err != nil || decoded.Installed() {
		t.Errorf("record = %+v, %v; want uninstalled", decoded, err)
	}
	if _, err = connection.DecodeRecord(`{"version":2,"org":"globex"}`); !errors.Is(err, connection.ErrVersion) {
		t.Errorf("version 2 = %v, want ErrVersion", err)
	}
	// A record or credential missing what the controller needs to act is
	// never written.
	if _, err = connection.EncodeCredential(connection.Credential{Org: "globex", AppID: 42}); err == nil {
		t.Error("a credential with no key was encoded")
	}
	if _, err = connection.EncodeRecord(connection.Record{Org: "globex"}); err == nil {
		t.Error("a record with no App was encoded")
	}
}

// A record written before owners were recorded has none, and reads as an
// organisation only the installation-wide roles operate; a record with an
// owner reads it back.
func TestAnOldRecordHasNoOwnerAndANewOneKeepsIt(t *testing.T) {
	t.Parallel()
	old, err := connection.DecodeRecord(
		`{"version":1,"org":"globex","app_id":42,"app_slug":"globex-access-roster","installation_id":7,` +
			`"connected_at":"2026-09-01T09:00:00Z","connected_by":"o@example.com"}`)
	if err != nil || old.Owner != "" || !old.Installed() {
		t.Fatalf("an old record = %+v, %v; want installed, with no owner", old, err)
	}
	raw, err := connection.EncodeRecord(connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster", Owner: "C0north"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := connection.DecodeRecord(raw); err != nil || got.Owner != "C0north" {
		t.Errorf("record = %+v, %v; want owner C0north", got, err)
	}
	raw, err = connection.EncodeRecord(connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "owner") {
		t.Errorf("a record with no owner writes one: %s", raw)
	}
}
