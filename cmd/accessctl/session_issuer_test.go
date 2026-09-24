package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A laptop belongs to more than one estate, and until sessions moved per
// issuer it could only hold one login at a time: signing in at the second
// replaced the first one's refresh token, and `--issuer` then selected
// the right endpoint and handed it the WRONG token. The issuer refuses
// that with `subject_token is invalid` -- a message that reads as expiry
// and is not, which sends people to re-run a login that already worked.
func TestTwoIssuersDoNotClobberEachOther(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	const (
		north = "https://access.north.example"
		south = "https://access.south.example"
	)

	if err := saveSession(north, Session{RefreshToken: "north-refresh", Email: "a@north"}); err != nil {
		t.Fatalf("save north: %v", err)
	}

	if err := saveSession(south, Session{RefreshToken: "south-refresh", Email: "a@south"}); err != nil {
		t.Fatalf("save south: %v", err)
	}

	// The second login must not have cost the first one.
	first, err := loadSession(north)
	if err != nil {
		t.Fatalf("load north after signing in elsewhere: %v", err)
	}

	if first.RefreshToken != "north-refresh" {
		t.Errorf("north holds %q; the second sign-in overwrote the first", first.RefreshToken)
	}

	second, err := loadSession(south)
	if err != nil {
		t.Fatalf("load south: %v", err)
	}

	if second.RefreshToken != "south-refresh" {
		t.Errorf("south holds %q", second.RefreshToken)
	}
}

// A trailing slash is the same installation. Two files would mean a
// second browser round trip for a difference nobody intended.
func TestTheIssuerIsNormalisedBeforeItNamesAFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := saveSession("https://access.north.example/", Session{RefreshToken: "a-refresh"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := loadSession("https://access.north.example")
	if err != nil {
		t.Fatalf("load without the slash: %v", err)
	}

	if got.RefreshToken != "a-refresh" {
		t.Errorf("refresh token %q", got.RefreshToken)
	}
}

// An issuer never signed in at is NOT signed in -- it must not fall back
// to whatever else is cached. Serving another estate's token here is the
// original defect, and it fails at the far end where the message names
// the token rather than the mistake.
func TestAnUnknownIssuerIsNotSignedIn(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if err := saveSession("https://access.north.example", Session{RefreshToken: "a-refresh"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	if _, err := loadSession("https://access.elsewhere.example"); err == nil {
		t.Fatal("an issuer with no session read as signed in, using another estate's token")
	}
}

// The file says which installation it belongs to, and THAT is what
// decides -- not the name it was found under. So a file whose name
// collides, or one moved by hand, fails closed rather than opening a
// session at the wrong estate.
func TestAFileClaimingAnotherIssuerIsRefused(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	const asked = "https://access.north.example"

	path, err := sessionPath(asked)
	if err != nil {
		t.Fatalf("sessionPath: %v", err)
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	body, err := json.Marshal(Session{RefreshToken: "someone-elses", Issuer: "https://access.south.example"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err = os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err = loadSession(asked); err == nil {
		t.Fatal("a session stamped with another issuer was served")
	}
}

// An upgrade must not cost a login. The single-issuer cache carries no
// issuer of its own -- that is the defect being repaired -- so it is
// adopted by whoever asks first. A wrong guess costs exactly what today
// costs: the issuer refuses it, and one login replaces it.
func TestTheOldSingleIssuerCacheIsAdopted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	legacy, err := legacySessionPath()
	if err != nil {
		t.Fatalf("legacySessionPath: %v", err)
	}

	if err = os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	body, err := json.Marshal(Session{RefreshToken: "from-before", Email: "ada@north.example"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err = os.WriteFile(legacy, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := loadSession("https://access.north.example")
	if err != nil {
		t.Fatalf("the old cache was not adopted: %v", err)
	}

	if got.RefreshToken != "from-before" || got.Email != "ada@north.example" {
		t.Errorf("adopted %+v", got)
	}

	// A per-issuer file wins over the legacy one, so the first login
	// after the upgrade ends the guessing.
	if err = saveSession("https://access.north.example", Session{RefreshToken: "fresh"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err = loadSession("https://access.north.example")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if got.RefreshToken != "fresh" {
		t.Errorf("the legacy file still won after a real sign-in: %q", got.RefreshToken)
	}
}

// Two installations differing only in something the readable part of the
// name flattens -- a scheme, a port, a path -- must not share a file.
func TestIssuersThatFlattenToTheSameNameStillDiffer(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	a, err := sessionPath("https://access.north.example/one")
	if err != nil {
		t.Fatalf("a: %v", err)
	}

	b, err := sessionPath("https://access.north.example/two")
	if err != nil {
		t.Fatalf("b: %v", err)
	}

	if a == b {
		t.Fatalf("both issuers map to %s", a)
	}

	if c, _ := sessionPath("http://access.north.xyz/one"); c == a {
		t.Errorf("http and https map to the same file %s", a)
	}
}
