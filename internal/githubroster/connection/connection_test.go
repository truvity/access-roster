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
	secret := `{"version":1,"org":"truvity","private_key":"-----BEGIN RSA PRIVATE KEY-----SECRET` // truncated JSON
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
	raw, err := connection.EncodeCredential(connection.Credential{Org: "truvity", AppID: 42, InstallationID: 7, PrivateKey: "key"})
	if err != nil {
		t.Fatalf("EncodeCredential: %v", err)
	}
	credential, err := connection.DecodeCredential(raw)
	if err != nil || credential.AppID != 42 || credential.InstallationID != 7 || credential.PrivateKey != "key" {
		t.Errorf("credential = %+v, %v", credential, err)
	}
	record, err := connection.EncodeRecord(connection.Record{Org: "truvity", AppID: 42, AppSlug: "truvity-access-roster"})
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	if decoded, err := connection.DecodeRecord(record); err != nil || decoded.Installed() {
		t.Errorf("record = %+v, %v; want uninstalled", decoded, err)
	}
	if _, err = connection.DecodeRecord(`{"version":2,"org":"truvity"}`); !errors.Is(err, connection.ErrVersion) {
		t.Errorf("version 2 = %v, want ErrVersion", err)
	}
	// A record or credential missing what the controller needs to act is
	// never written.
	if _, err = connection.EncodeCredential(connection.Credential{Org: "truvity", AppID: 42}); err == nil {
		t.Error("a credential with no key was encoded")
	}
	if _, err = connection.EncodeRecord(connection.Record{Org: "truvity"}); err == nil {
		t.Error("a record with no App was encoded")
	}
}
