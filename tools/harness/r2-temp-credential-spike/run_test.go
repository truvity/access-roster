package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAccount = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	testBucket  = "spike-test-bucket"
	testParent  = "parent-token-for-the-test"
	testCreator = "creator-token-for-the-test"
)

// fakeCloud stands in for the Cloudflare API and for the bucket's S3 endpoint. It issues credentials, refuses
// each one as behave says (by the credential's number and the number of the request it made), and keeps the
// objects.
type fakeCloud struct {
	t      *testing.T
	behave func(cred, req int) int // the status to answer; 0 to serve the request normally

	mu      sync.Mutex
	issued  int
	creds   map[string]*fakeCred // by access key id
	objects map[string]string
	mints   []map[string]any
	tokens  map[string]bool // token ids that are alive
}

type fakeCred struct {
	num, reqs int
	session   string
}

func newFakeCloud(t *testing.T, behave func(cred, req int) int) (*fakeCloud, config) {
	t.Helper()
	f := &fakeCloud{t: t, behave: behave, creds: map[string]*fakeCred{}, objects: map[string]string{}, tokens: map[string]bool{}}
	api := httptest.NewServer(http.HandlerFunc(f.api))
	s3 := httptest.NewServer(http.HandlerFunc(f.s3))
	t.Cleanup(api.Close)
	t.Cleanup(s3.Close)
	u, _ := url.Parse(s3.URL)
	cfg := config{
		account: testAccount, parent: testParent, creator: testCreator, bucket: testBucket, prefix: "sluis-spike/",
		n: 4, spacing: 0, ttl: 5 * time.Minute, interval: 5 * time.Millisecond, deadline: 2 * time.Second, soak: 60 * time.Millisecond,
		arms: []string{"temp"}, group: "Workers R2 Storage Bucket Item Write", outDir: filepath.Join(t.TempDir(), "out"),
		apiBase: api.URL, endpoint: u,
	}
	return f, cfg
}

func (f *fakeCloud) issue(secret string) (id, session string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued++
	id = fmt.Sprintf("key-id-%d-for-the-test", f.issued)
	session = fmt.Sprintf("session-%d-for-the-test", f.issued)
	f.creds[id] = &fakeCred{num: f.issued, session: session}
	_ = secret
	return id, session
}

func reply(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": status/100 == 2, "errors": []any{}, "result": result})
}

func (f *fakeCloud) api(w http.ResponseWriter, r *http.Request) {
	bearer := r.Header.Get("Authorization")
	acct := "/accounts/" + testAccount
	switch {
	case r.Method == http.MethodGet && r.URL.Path == acct+"/tokens/verify" && bearer == "Bearer "+testParent:
		reply(w, 200, map[string]string{"id": "parent-key-id-for-the-test"})
	case r.Method == http.MethodPost && r.URL.Path == acct+"/r2/temp-access-credentials" && bearer == "Bearer "+testParent:
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.mints = append(f.mints, in)
		f.mu.Unlock()
		id, session := f.issue("")
		reply(w, 200, map[string]string{"accessKeyId": id, "secretAccessKey": "secret-for-the-test-" + id, "sessionToken": session})
	case r.Method == http.MethodGet && r.URL.Path == acct+"/tokens/permission_groups" && bearer == "Bearer "+testCreator:
		reply(w, 200, []map[string]string{{"id": "g1", "name": "Other"}, {"id": "g2", "name": "Workers R2 Storage Bucket Item Write"}})
	case r.Method == http.MethodPost && r.URL.Path == acct+"/tokens" && bearer == "Bearer "+testCreator:
		id, _ := f.issue("")
		value := "token-value-for-the-test-" + id
		sum := sha256.Sum256([]byte(value))
		f.mu.Lock()
		f.creds[id].session = "" // an API-token credential has no session token
		f.creds[id].reqs = 0
		f.tokens[id] = true
		f.mu.Unlock()
		_ = hex.EncodeToString(sum[:])
		reply(w, 200, map[string]string{"id": id, "value": value})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, acct+"/tokens/") && bearer == "Bearer "+testCreator:
		f.mu.Lock()
		delete(f.tokens, strings.TrimPrefix(r.URL.Path, acct+"/tokens/"))
		f.mu.Unlock()
		reply(w, 200, map[string]string{})
	default:
		reply(w, http.StatusForbidden, nil)
	}
}

var credentialField = regexp.MustCompile(`Credential=([^/]+)/`)

func (f *fakeCloud) s3(w http.ResponseWriter, r *http.Request) {
	m := credentialField.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil || r.Header.Get("X-Amz-Content-Sha256") == "" || r.Header.Get("X-Amz-Date") == "" {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.creds[m[1]]
	if c == nil || r.Header.Get("X-Amz-Security-Token") != c.session {
		http.Error(w, `<Error><Code>InvalidAccessKeyId</Code><Message>do not echo</Message></Error>`, http.StatusUnauthorized)
		return
	}
	c.reqs++
	if status := f.behave(c.num, c.reqs); status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`<Error><Code>SignatureDoesNotMatch</Code></Error>`))
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/"+testBucket+"/")
	switch r.Method {
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.objects[key] = string(b)
	case http.MethodGet:
		v, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(v))
	case http.MethodHead:
		if _, ok := f.objects[key]; !ok {
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func readOut(t *testing.T, cfg config) (creds, attempts, summary string) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(cfg.outDir, name)) //nolint:gosec // a path in the test's temporary directory
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return read("credentials.csv"), read("attempts.csv"), read("summary.txt")
}

func noSecrets(t *testing.T, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		for _, leak := range []string{"for-the-test", testAccount, testBucket} {
			if strings.Contains(out, leak) {
				t.Errorf("an output holds %q:\n%s", leak, out)
			}
		}
	}
}

func TestARunRecordsTheRefusalsBeforeAndAfterAnAcceptAndCleansUp(t *testing.T) {
	// credential 1 is refused with 401 on its first two requests, credential 2 with 403 on its fourth (after
	// its put, get and head were accepted), the others never.
	f, cfg := newFakeCloud(t, func(cred, req int) int {
		switch {
		case cred == 1 && req <= 2:
			return http.StatusUnauthorized
		case cred == 2 && req == 4:
			return http.StatusForbidden
		}
		return 0
	})
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), cfg, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr.String())
	}
	creds, attempts, summary := readOut(t, cfg)
	noSecrets(t, creds, attempts, summary, stdout.String(), stderr.String())

	if len(f.objects) != 0 {
		t.Errorf("objects left behind: %v", f.objects)
	}
	if len(f.mints) != 4 {
		t.Fatalf("%d credentials minted, want 4", len(f.mints))
	}
	m := f.mints[0]
	if m["bucket"] != testBucket || m["parentAccessKeyId"] != "parent-key-id-for-the-test" || m["permission"] != "object-read-write" ||
		m["ttlSeconds"] != float64(300) || fmt.Sprint(m["prefixes"]) != "[sluis-spike/]" {
		t.Errorf("the mint request = %v", m)
	}
	lines := strings.Split(strings.TrimSpace(creds), "\n")
	if len(lines) != 5 {
		t.Fatalf("credentials.csv has %d lines:\n%s", len(lines), creds)
	}
	// arm,credential,minted,mint_ms,accepted,first_accept_ms,attempts_to_first_accept,first_attempt_refused,before,after,...
	if c := strings.Split(lines[1], ","); c[4] != "true" || c[6] != "3" || c[7] != "true" || c[8] != "2" || c[9] != "0" {
		t.Errorf("credential 1 (two 401 then accepted): %v", c)
	}
	if c := strings.Split(lines[2], ","); c[6] != "1" || c[8] != "0" || c[9] != "1" || c[12] != "1" {
		t.Errorf("credential 2 (a 403 after an accept): %v", c)
	}
	if !strings.Contains(attempts, ",401,InvalidAccessKeyId,") && !strings.Contains(attempts, ",401,SignatureDoesNotMatch,") {
		t.Errorf("no 401 with a code in attempts.csv:\n%s", attempts)
	}
	for _, want := range []string{"credentials refused after an accept 1", "NO VERDICT: N is 4"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
}

func TestAStoppedRunStillDeletesItsObjectsWithAFreshCredential(t *testing.T) {
	f, cfg := newFakeCloud(t, func(int, int) int { return 0 })
	cfg.n, cfg.soak = 1, 5*time.Second // the soak is where the run is stopped
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			f.mu.Lock()
			n := len(f.objects)
			f.mu.Unlock()
			if n > 0 {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	var stdout, stderr bytes.Buffer
	if err := run(ctx, cfg, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr.String())
	}
	if len(f.objects) != 0 {
		t.Errorf("objects left behind: %v", f.objects)
	}
	if f.issued != 2 {
		t.Errorf("%d credentials issued, want the probe's and the cleanup's", f.issued)
	}
	_, _, summary := readOut(t, cfg)
	if !strings.Contains(summary, "objects left behind after cleanup: 0") {
		t.Errorf("summary:\n%s", summary)
	}
}

func TestTheTokenArmCreatesProbesAndDeletesTokens(t *testing.T) {
	f, cfg := newFakeCloud(t, func(_, req int) int {
		if req == 1 {
			return http.StatusUnauthorized
		}
		return 0
	})
	cfg.arms, cfg.n = []string{"temp", "token"}, 2
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), cfg, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr.String())
	}
	creds, attempts, summary := readOut(t, cfg)
	noSecrets(t, creds, attempts, summary, stdout.String(), stderr.String())
	if len(f.tokens) != 0 || len(f.objects) != 0 {
		t.Errorf("tokens alive %v, objects %v", f.tokens, f.objects)
	}
	if got := strings.Count(creds, "\ntoken,") + strings.Count(creds, "\ntemp,"); got != 4 {
		t.Errorf("%d credential rows, want 4:\n%s", got, creds)
	}
	if !strings.Contains(summary, "arm: temp") || !strings.Contains(summary, "arm: token") {
		t.Errorf("summary:\n%s", summary)
	}
}

func TestAFirstMintThatFailsStopsTheRunWithoutALeak(t *testing.T) {
	_, cfg := newFakeCloud(t, func(int, int) int { return 0 })
	cfg.parent = "another-token-for-the-test"
	err := run(context.Background(), cfg, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("a refused parent token must stop the run")
	}
	noSecrets(t, err.Error())
}

func TestNewConfigNamesTheMissingVariablesNotTheirValues(t *testing.T) {
	env := map[string]string{envAccount: testAccount}
	_, err := newConfig(func(k string) string { return env[k] }, 30, time.Second, 15*time.Minute, 500*time.Millisecond, 120*time.Second, 40*time.Second, "temp", "g", "")
	if err == nil || !strings.Contains(err.Error(), envParentToken) || !strings.Contains(err.Error(), envBucket) || strings.Contains(err.Error(), testAccount) {
		t.Errorf("error = %v", err)
	}
	env[envParentToken], env[envBucket] = testParent, testBucket
	if _, err := newConfig(func(k string) string { return env[k] }, 30, time.Second, 5*time.Minute, 500*time.Millisecond, 120*time.Second, 40*time.Second, "temp", "g", ""); err == nil || !strings.Contains(err.Error(), "-ttl") {
		t.Errorf("a ttl shorter than a probe: %v", err)
	}
	if _, err := newConfig(func(k string) string { return env[k] }, 30, time.Second, 15*time.Minute, 500*time.Millisecond, 120*time.Second, 40*time.Second, "token", "g", ""); err == nil || !strings.Contains(err.Error(), envCreator) {
		t.Errorf("the token arm without its creator token: %v", err)
	}
}
