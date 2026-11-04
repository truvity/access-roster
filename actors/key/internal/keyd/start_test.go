//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"encoding/base64"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// syncBuffer is a log sink that tests read while servers may still write.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

func TestFloorSoftwareDriverInProduction(t *testing.T) {
	e := newTestEnv(t, "production")
	n := e.newNode(nodeOpts{})
	err := n.srv.Init(context.Background())
	if err == nil || err.Error() != "software key driver refused in production" {
		t.Fatalf("Init = %v, want the refusal of the floor", err)
	}
	if len(n.driver.keys) != 0 {
		t.Fatal("the driver made keys before the floor was checked")
	}
	if e.store.items["|key-certificate|wrapping/"+n.srv.recipient] != nil {
		t.Fatal("a certificate was published")
	}
	if err := n.srv.Check(context.Background()); err == nil {
		t.Fatal("check passed in production with the software driver")
	}
}

func TestFloorStagingWarnsAndProductionAllowsACard(t *testing.T) {
	log := captureLog(t)
	e := newTestEnv(t, "staging")
	e.startedNode(nodeOpts{})
	if !strings.Contains(log.String(), "level=WARN") || !strings.Contains(log.String(), "software key driver in staging") {
		t.Fatalf("no warning line in staging:\n%s", log.String())
	}

	p := newTestEnv(t, "production")
	p.startedNode(nodeOpts{driver: newFakeDriver("yubikey-piv")}) // a card is what production is for
}

func TestConfigAndRunDirMustBeThere(t *testing.T) {
	ctx := context.Background()
	t.Run("no Boundary", func(t *testing.T) {
		e := newTestEnv(t, "development")
		delete(e.store.items, "|boundary|default")
		if err := e.newNode(nodeOpts{}).srv.Init(ctx); err == nil {
			t.Fatal("started without Boundary")
		}
	})
	t.Run("no KeyPlan", func(t *testing.T) {
		e := newTestEnv(t, "development")
		delete(e.store.items, "|key-plan|default")
		if err := e.newNode(nodeOpts{}).srv.Init(ctx); err == nil {
			t.Fatal("started without KeyPlan")
		}
	})
	t.Run("unknown environment", func(t *testing.T) {
		e := newTestEnv(t, "")
		if err := e.newNode(nodeOpts{}).srv.Init(ctx); err == nil {
			t.Fatal("started without an environment")
		}
	})
	t.Run("no wrapping purpose", func(t *testing.T) {
		e := newTestEnv(t, "development")
		plan := defaultPlan()
		plan.Purposes = plan.Purposes[1:]
		e.store.put("key-plan", "", "default", plan)
		if err := e.newNode(nodeOpts{}).srv.Init(ctx); err == nil {
			t.Fatal("started without a wrapping key")
		}
	})
	for name, ttl := range map[string]time.Duration{"above the maximum": 2 * time.Hour, "negative": -time.Second} {
		t.Run("cache_ttl "+name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			plan := defaultPlan()
			plan.CacheTtl = durationpb.New(ttl)
			e.store.put("key-plan", "", "default", plan)
			n := e.newNode(nodeOpts{})
			if err := n.srv.Init(ctx); err == nil {
				t.Fatal("started with a cache_ttl outside the range")
			}
			if len(n.driver.keys) != 0 {
				t.Fatal("the driver made keys for a refused KeyPlan")
			}
		})
	}
	t.Run("caller directory missing", func(t *testing.T) {
		e := newTestEnv(t, "development")
		n := e.newNode(nodeOpts{})
		callers := registry.CallersOf("key")
		if err := os.Remove(filepath.Join(n.runDir, callers[0])); err != nil {
			t.Fatal(err)
		}
		if err := n.srv.Init(ctx); err == nil {
			t.Fatal("started with a caller directory missing")
		}
	})
	for name, mode := range map[string]fs.FileMode{"group-writable": 0o770, "world-writable": 0o757} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.newNode(nodeOpts{})
			dir := filepath.Join(n.runDir, registry.CallersOf("key")[0])
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if err := n.srv.Init(ctx); err == nil {
				t.Fatal("started with a " + name + " caller directory")
			}
		})
	}
}

func TestInitPublishesTheWrappingCertificate(t *testing.T) {
	e := newTestEnv(t, "development")
	rec := &recorder{}
	n := e.startedNode(nodeOpts{name: "node-1", audit: rec})
	if !regexp.MustCompile(`^node-1-[a-z2-7]{16}$`).MatchString(n.srv.recipient) {
		t.Fatalf("recipient = %q", n.srv.recipient)
	}
	if want := recipientLabel("node-1", n.srv.keys[wrappingPurpose].spki); n.srv.recipient != want {
		t.Fatalf("recipient = %q, want %q", n.srv.recipient, want)
	}
	it := e.store.items["|key-certificate|wrapping/"+n.srv.recipient]
	if it == nil {
		t.Fatal("no KeyCertificate wrapping/<recipient>")
	}
	if rec.count(ActionStart) != 1 {
		t.Fatalf("key.start events = %d, want 1", rec.count(ActionStart))
	}
	// Tonight there is no chain and no authority key is a recipient: the plan's three keys exist, no more.
	if len(n.driver.keys) != 3 {
		t.Fatalf("driver keys = %d, want 3 (wrapping, token-signing, audit-log)", len(n.driver.keys))
	}
}

// One socket per caller, in the caller's own directory, each served to that caller only.
func TestSocketsAreOnePerCaller(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	for _, c := range registry.CallersOf("key") {
		fi, err := os.Stat(filepath.Join(n.runDir, c, socketName))
		if err != nil {
			t.Fatalf("no socket for %s: %v", c, err)
		}
		if fi.Mode()&fs.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
			t.Errorf("socket of %s: mode %v, want a socket 0660", c, fi.Mode())
		}
	}
	// A peer named exchange on the session socket is refused by the call graph, before any rule.
	_, err := seal1(n.as("exchange", "session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "call_graph")
	// The right peer on its own socket gets through.
	if _, err := seal1(n.as("session", "session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatalf("session on its own socket: %v", err)
	}
	// A caller that may use key@ but is not the one of this socket is refused too.
	_, err = seal1(n.as("policy", "session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "call_graph")
}

func TestAuditFailureNeverChangesAnOutcome(t *testing.T) {
	e := newTestEnv(t, "development")
	rec := &recorder{failing: true}
	n := e.startedNode(nodeOpts{audit: rec})
	env, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	if err != nil {
		t.Fatalf("Seal with a failing audit transport: %v", err)
	}
	if _, err := open1(n.client("session"), "cookie", "cookie", "", "s1", env, nil); err != nil {
		t.Fatalf("Open with a failing audit transport: %v", err)
	}
	// A refusal stays a refusal.
	_, err = seal1(n.client("signer"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	if rec.count(ActionRefuse) != 1 {
		t.Fatalf("key.refuse events = %d, want 1", rec.count(ActionRefuse))
	}
}

// No audit fact holds a value: not the plaintext, not the key, not the envelope.
func TestAuditFactsCarryNoValues(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	secret := []byte("super-secret-plaintext")
	env, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = open1(n.client("signer"), "cookie", "cookie", "", "s1", env, nil) // refused: no rule
	hdr, _ := envelope.ParseHeader(env)
	if hdr.Generation != 1 {
		t.Fatal("generation")
	}
	for _, ev := range n.audit.all() {
		s := ev.Action + ev.Reason + ev.Tenant
		for k, v := range ev.Fields {
			s += k + "=" + strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(fmtAny(v), "\n", " "), "\t", " ")) + ";"
		}
		if strings.Contains(s, string(secret)) || strings.Contains(s, string(env)) {
			t.Fatalf("audit fact %s holds a value", ev.Action)
		}
	}
	if n.audit.count(ActionDataKeyMake) != 1 || n.audit.count(ActionWrapWrite) != 1 || n.audit.count(ActionRefuse) != 1 {
		t.Fatalf("events: %d keys, %d wraps, %d refusals; want 1, 1, 1",
			n.audit.count(ActionDataKeyMake), n.audit.count(ActionWrapWrite), n.audit.count(ActionRefuse))
	}
}

func TestStartLogsTheRewrapLimit(t *testing.T) {
	log := captureLog(t)
	e := newTestEnv(t, "development")
	e.startedNode(nodeOpts{})
	if !strings.Contains(log.String(), "rewrap visits only the default tenant and the tenants used since start") {
		t.Fatalf("the rewrap limit was not logged:\n%s", log.String())
	}
}

// A signature is an audit fact that is durable before the signature is returned: the fact is emitted blocking,
// and when it cannot be made durable the signature is withheld. Seals, opens and macs never wait for audit; an
// audit-log signature is not a fact at all.
func TestSignatureWaitsForItsAuditFact(t *testing.T) {
	e := newTestEnv(t, "development")
	rec := &recorder{}
	n := e.startedNode(nodeOpts{audit: rec})
	_, kid := publicKey(t, n, "signer", "token-signing")
	in := tokenInput(kid, "", "")
	if _, err := n.client("signer").Sign(context.Background(), signReq("token-signing", in)); err != nil {
		t.Fatal(err)
	}
	var signs []Event
	for _, ev := range rec.all() {
		if ev.Action == ActionSign {
			signs = append(signs, ev)
		}
	}
	if len(signs) != 1 || !signs[0].Blocking {
		t.Fatalf("key.sign events = %+v, want one, blocking", signs)
	}

	rec.mu.Lock()
	rec.failing = true
	rec.mu.Unlock()
	res, err := n.client("signer").Sign(context.Background(), signReq("token-signing", in))
	wantRefusal(t, err, connect.CodeUnavailable, "audit")
	if res != nil {
		t.Fatal("a signature was returned without its audit fact")
	}
	// The checkpoint of the log is its own evidence: it signs with the transport down.
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := n.client("writer").Sign(context.Background(), signReq("audit-log", []byte("example.com/log\n1\n"+root+"\n"))); err != nil {
		t.Fatalf("audit-log signature with the transport down: %v", err)
	}
}

// lockProbe is an Auditor that records whether loadMu was free while the fact was being emitted.
type lockProbe struct {
	srv  *Server
	held atomic.Int64
	seen atomic.Int64
}

func (p *lockProbe) Emit(context.Context, Event) error {
	p.seen.Add(1)
	if p.srv.loadMu.TryLock() {
		p.srv.loadMu.Unlock()
	} else {
		p.held.Add(1)
	}
	return nil
}

// A new key emits 1+N facts, each with its own timeout; none of them holds the lock that every key load needs.
func TestFactsOfANewKeyAreEmittedOutsideLoadMu(t *testing.T) {
	e := newTestEnv(t, "development")
	probe := &lockProbe{}
	n := e.newNode(nodeOpts{audit: probe})
	probe.srv = n.srv
	n.start()
	probe.seen.Store(0)
	if _, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if probe.seen.Load() < 2 {
		t.Fatalf("facts emitted = %d, want a key and a wrap at least", probe.seen.Load())
	}
	if probe.held.Load() != 0 {
		t.Fatalf("%d facts were emitted while loadMu was held", probe.held.Load())
	}
}

func TestCheckReachesTheTransport(t *testing.T) {
	e := newTestEnv(t, "development")
	sock := filepath.Join(shortDir(t), "emit.sock")
	n := e.newNode(nodeOpts{transport: sock})
	if err := n.srv.Check(context.Background()); err == nil {
		t.Fatal("check passed with no transport listening")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := n.srv.Check(context.Background()); err != nil {
		t.Fatalf("check with the transport listening: %v", err)
	}
}
