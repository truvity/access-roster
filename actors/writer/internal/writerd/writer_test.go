//go:build sluis_test

package writerd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

func TestMain(m *testing.M) {
	// The writer logs what it refuses and what it adopts; the tests read the blob, not the log.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// ---- helpers

// emitterOf makes the records the way an actor does: with the emitter library. Nothing is sent; the test pushes the
// message to the fake transport, which names the emitter key@dev.
func emitterOf(t *testing.T, _ *env) *audit.Emitter {
	t.Helper()
	// Record builds a message without a transport; the library requires one to be configured, so give it the fake's.
	em, err := audit.New(audit.Config{Actor: "key", Boundary: testBoundary, Release: "0.0.0-dev", Transport: dummyTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	return em
}

type message struct {
	uid string
	rec []byte
}

// newMessage builds the message of a key.sign event of the tenant ("" for none).
func newMessage(t *testing.T, em *audit.Emitter, action, tenant string) message {
	t.Helper()
	rec, uid, err := em.Record(context.Background(), audit.Event{
		Action: audit.Action{Name: action, ClassUID: 6003, ActivityID: 99, ActivityName: "Sign"},
		Status: audit.StatusSuccess, Tenant: tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return message{uid, rec}
}

func (e *env) push(m message) {
	e.tr.push(&transportv2alpha1.AuditMessage{Uid: m.uid, Record: m.rec})
}

// logEntries reads every entry of the audit log from its files, in order.
func logEntries(t *testing.T, dir string) []map[string]any {
	t.Helper()
	cp, err := os.ReadFile(filepath.Join(dir, "checkpoint")) //nolint:gosec // a test directory
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(cp), "\n")
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for n := int64(0); n*tileWidth < size; n++ {
		w := int(min(tileWidth, size-n*tileWidth))
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tilePath(-1, n, w)))) //nolint:gosec // a test directory
		if err != nil {
			t.Fatal(err)
		}
		es, err := parseBundle(b)
		if err != nil || len(es) != w {
			t.Fatalf("bundle %d: %v (%d entries, want %d)", n, err, len(es), w)
		}
		for _, e := range es {
			var m map[string]any
			if err := json.Unmarshal(e, &m); err != nil {
				t.Fatal(err)
			}
			out = append(out, m)
		}
	}
	if int64(len(out)) != size {
		t.Fatalf("read %d entries, the checkpoint says %d", len(out), size)
	}
	return out
}

func recordEntries(es []map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range es {
		if e["entry"] == entryRecord {
			out = append(out, e)
		}
	}
	return out
}

// openEntry opens the sealed record of a record entry and returns the plaintext.
func openEntry(t *testing.T, e *env, entry map[string]any) []byte {
	t.Helper()
	md := entry["metadata"].(map[string]any)
	sealed, err := base64.StdEncoding.DecodeString(entry["sealed"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := e.key.open(sealed, md["tenant_uid"].(string), SealKind, SealID("sluis", "audit", "main", md["uid"].(string)))
	if err != nil {
		t.Fatalf("the record does not open at its address: %v", err)
	}
	return pt
}

var (
	cliOnce sync.Once
	cliPath string
	cliErr  error
)

// verifyWithCLI runs the merged `sluis audit verify` on the log directory and returns its output and exit code.
func verifyWithCLI(t *testing.T, dir, key string) (string, int) {
	t.Helper()
	cliOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			cliErr = errors.New("no go tool on the path")
			return
		}
		root, err := exec.Command(goBin, "env", "GOMOD").Output() //nolint:gosec // the go tool of the path
		if err != nil {
			cliErr = err
			return
		}
		tmp, err := os.MkdirTemp("", "sluis-cli")
		if err != nil {
			cliErr = err
			return
		}
		cliPath = filepath.Join(tmp, "sluis")
		cmd := exec.Command(goBin, "build", "-o", cliPath, "./cli/sluis") //nolint:gosec // the go tool of the path builds the CLI of this module
		cmd.Dir = filepath.Dir(strings.TrimSpace(string(root)))
		if out, err := cmd.CombinedOutput(); err != nil {
			cliErr = fmt.Errorf("build the CLI: %w: %s", err, out)
		}
	})
	if cliErr != nil {
		t.Fatalf("the CLI is not built: %v", cliErr)
	}
	cmd := exec.Command(cliPath, "audit", "verify", "--key", key, dir) //nolint:gosec // the CLI this test built
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func (e *env) mustVerify(t *testing.T) string {
	t.Helper()
	out, code := verifyWithCLI(t, e.logDir(), e.verifier())
	if code != 0 {
		t.Fatalf("sluis audit verify exited %d: %s", code, out)
	}
	return out
}

// ---- tests

func TestWriterWritesALogTheCLIVerifies(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	r := e.start()

	want := []message{
		newMessage(t, em, "key.sign", "acme"),
		newMessage(t, em, "key.sign", "globex"),
		newMessage(t, em, "store.start", ""), // no tenant: the operator's own
		newMessage(t, em, "key.sign", "acme"),
	}
	for _, m := range want {
		e.push(m)
	}
	wait(t, "the first messages to be acknowledged", func() bool { return e.tr.ackedCount() == len(want) })

	// A second life of the writer carries on the same log, from its state.
	_ = r.stop(t)
	more := []message{newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "globex")}
	e.start()
	for _, m := range more {
		e.push(m)
	}
	want = append(want, more...)
	wait(t, "the later messages to be acknowledged", func() bool { return e.tr.ackedCount() == len(want) })

	out := e.mustVerify(t)
	if !strings.Contains(out, "ok: "+testOrigin) {
		t.Fatalf("output = %q", out)
	}

	es := logEntries(t, e.logDir())
	recs := recordEntries(es)
	if len(recs) != len(want) {
		t.Fatalf("%d record entries, want %d", len(recs), len(want))
	}
	for i, m := range want {
		entry := recs[i]
		if got := openEntry(t, e, entry); !bytes.Equal(got, m.rec) {
			t.Fatalf("record %d: the opened bytes are not the bytes the emitter made", i)
		}
		md := entry["metadata"].(map[string]any)
		if md["uid"] != m.uid {
			t.Fatalf("record %d: envelope uid %v, want %s", i, md["uid"], m.uid)
		}
		if _, leaked := entry["unmapped"]; leaked {
			t.Fatal("the envelope holds a field of the record's body")
		}
		w := entry["writer"].(map[string]any)
		if w["instance"] != "node-1" || w["recorded_at"].(float64) <= 0 {
			t.Fatalf("writer stamps = %v", w)
		}
	}
	// A record with no tenant is routed to the operator's own tenant (REQ-AUDIT-020).
	if got := recs[2]["metadata"].(map[string]any)["tenant_uid"]; got != testDefault {
		t.Fatalf("tenant of a tenantless record = %v, want %s", got, testDefault)
	}
	if got := recs[0]["metadata"].(map[string]any)["tenant_uid"]; got != "acme" {
		t.Fatalf("tenant = %v", got)
	}
	// Every batch ends with a seal entry in clear.
	var seals int
	for _, en := range es {
		if en["entry"] == entrySeal {
			seals++
			if en["clock"].(map[string]any)["observed"] != true {
				t.Fatalf("the seal entry holds no clock observation: %v", en)
			}
		}
	}
	if seals < 2 || int64(len(es)) != int64(len(want)+seals) {
		t.Fatalf("%d seal entries among %d entries for %d records", seals, len(es), len(want))
	}
	// A record sealed for one tenant does not open as another's (0029: bound to the tenant).
	sealed, _ := base64.StdEncoding.DecodeString(recs[0]["sealed"].(string))
	if _, err := e.key.open(sealed, "globex", SealKind, SealID("sluis", "audit", "main", want[0].uid)); err == nil {
		t.Fatal("a record opened under another tenant")
	}

	// The writer asked policy for audit.seal as itself, once per tenant per batch.
	for _, q := range e.pol.requests() {
		if q.GetAction() != "audit.seal" || q.GetPrincipal().GetType() != "Actor" || q.GetPrincipal().GetId() != "writer" ||
			q.GetResource().GetType() != "Boundary" || q.GetResource().GetId() != testBoundary ||
			len(q.GetGrantKeyOps()) != 1 || q.GetGrantKeyOps()[0] != "seal" {
			t.Fatalf("policy was asked %v", q)
		}
	}
}

func TestBatchClosesAt256Messages(t *testing.T) {
	e := newEnv(t)
	e.cfg.BatchWindow = time.Hour // only the count can close the batch
	em := emitterOf(t, e)
	e.start()
	for range 300 {
		e.push(newMessage(t, em, "key.sign", "acme"))
	}
	wait(t, "the first 256 to be acknowledged", func() bool { return e.tr.ackedCount() == 256 })
	time.Sleep(200 * time.Millisecond)
	if n := e.tr.ackedCount(); n != 256 {
		t.Fatalf("%d acknowledged, want 256: the rest waits for its window", n)
	}
	es := logEntries(t, e.logDir())
	if len(es) != 257 || es[256]["entry"] != entrySeal || es[256]["records"].(float64) != 256 {
		t.Fatalf("the first batch is %d entries, want 256 records and a seal entry", len(es))
	}
	e.mustVerify(t)
}

func TestBatchClosesAfterTheWindow(t *testing.T) {
	e := newEnv(t)
	e.cfg.BatchWindow = 300 * time.Millisecond
	em := emitterOf(t, e)
	e.start()
	start := time.Now()
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "the message to be acknowledged", func() bool { return e.tr.ackedCount() == 1 })
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("the batch closed after %v, before its window", d)
	}
	e.mustVerify(t)
}

func TestManyBatchesCrossBundleAndTileBoundaries(t *testing.T) {
	e := newEnv(t)
	e.cfg.BatchMax = 100
	em := emitterOf(t, e)
	e.start()
	const n = 700
	for range n {
		e.push(newMessage(t, em, "key.sign", "acme"))
	}
	wait(t, "all messages", func() bool { return e.tr.ackedCount() == n })
	out := e.mustVerify(t)
	if !strings.Contains(out, "root") {
		t.Fatalf("output = %q", out)
	}
	if got := len(recordEntries(logEntries(t, e.logDir()))); got != n {
		t.Fatalf("%d record entries, want %d", got, n)
	}
}

func TestDuplicatesAreDropped(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	a := newMessage(t, em, "key.sign", "acme")
	b := newMessage(t, em, "key.sign", "acme")
	e.push(a)
	e.push(a) // twice in one batch
	e.push(b)
	wait(t, "the first three", func() bool { return e.tr.ackedCount() == 3 })
	e.push(a) // again, after it is sealed
	wait(t, "the repeat", func() bool { return e.tr.ackedCount() == 4 })

	recs := recordEntries(logEntries(t, e.logDir()))
	if len(recs) != 2 {
		t.Fatalf("%d record entries, want 2", len(recs))
	}
	e.mustVerify(t)
}

func TestWriteOrderAndAckAfterDurability(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	for range 3 {
		e.push(newMessage(t, em, "key.sign", "acme"))
	}
	wait(t, "the batch", func() bool { return e.tr.ackedCount() == 3 })

	lastTile := -1
	for i, s := range e.ev.all() {
		if strings.HasPrefix(s, "blob.create:audit/main/tile/") {
			lastTile = i
		}
	}
	cp := e.ev.index("blob.create:audit/main/checkpoints/", 0)
	st := e.ev.index("blob.put:state/writer-state", 0)
	sign := e.ev.index("key.sign", 0)
	ptr := e.ev.index("blob.put:audit/main/checkpoint", 0)
	ack := e.ev.index("transport.ack", 0)
	if lastTile < 0 || cp < 0 || st < 0 || ptr < 0 || ack < 0 || sign < 0 {
		t.Fatalf("events missing: %v", e.ev.all())
	}
	// The state is put before key@ is asked to sign, so a writer that loses the put never signs.
	if lastTile >= st || st >= sign || sign >= cp || cp >= ptr || ptr >= ack {
		t.Fatalf("order is not tiles, state, signature, checkpoint, pointer, ack: %v", e.ev.all())
	}
	// Bundles come before hash tiles (an object that holds a hash always has its entries behind it).
	firstHash := -1
	lastBundle := -1
	for i, s := range e.ev.all() {
		if strings.HasPrefix(s, "blob.create:audit/main/tile/entries/") {
			lastBundle = i
		} else if strings.HasPrefix(s, "blob.create:audit/main/tile/") && firstHash < 0 {
			firstHash = i
		}
	}
	if lastBundle > firstHash {
		t.Fatalf("a hash tile was written before the last bundle: %v", e.ev.all())
	}
}

func TestNothingIsAcknowledgedWhenTheCheckpointFails(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.key.failSign = connect.NewError(connect.CodeUnavailable, errors.New("key@ is down"))
	r := e.start()
	e.push(newMessage(t, em, "key.sign", "acme"))
	// The writer stops: it began a write, so its next start recovers.
	if err := r.result(t); !errors.As(err, new(*fatalError)) {
		t.Fatalf("Run returned %v, want a fatal error", err)
	}
	if n := e.tr.ackedCount(); n != 0 {
		t.Fatalf("%d acknowledged without a checkpoint", n)
	}
	if e.tr.pendingCount() != 1 {
		t.Fatal("the message is no longer pending")
	}
}

// openQuarantine opens the sealed message of a quarantine object.
func openQuarantine(t *testing.T, e *env, path string) (map[string]any, *transportv2alpha1.AuditMessage) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // a test path under a temporary directory
	if err != nil {
		t.Fatal(err)
	}
	var rep map[string]any
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	env, err := base64.StdEncoding.DecodeString(rep["sealed"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := e.key.open(env, rep["tenant"].(string), quarantineKind, SealID("sluis", "quarantine", "main", rep["sha384"].(string)))
	if err != nil {
		t.Fatalf("the quarantined message does not open at its address: %v", err)
	}
	var m transportv2alpha1.AuditMessage
	if err := proto.Unmarshal(pt, &m); err != nil {
		t.Fatal(err)
	}
	return rep, &m
}

func TestAnUnknownActionIsQuarantinedSealedAndReported(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()

	bad := newMessage(t, em, "key.nothing", "acme") // not in the catalogue
	e.push(bad)
	wait(t, "the refusal to be acknowledged", func() bool { return e.tr.ackedCount() == 1 })

	reports, err := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports = %v (%v)", reports, err)
	}
	b, err := os.ReadFile(reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("key.nothing")) || bytes.Contains(b, []byte(bad.uid+bad.uid)) {
		t.Fatalf("the object repeats the record in clear: %s", b)
	}
	rep, m := openQuarantine(t, e, reports[0])
	if rep["reason"] != reasonAction || rep["path"] != "metadata.event_code" || rep["uid"] != bad.uid ||
		rep["emitter"] != "key@dev" || rep["tenant"] != "acme" {
		t.Fatalf("report = %s", b)
	}
	// Not lost: an operator who may open the tenant's evidence gets the bytes the emitter made.
	if !bytes.Equal(m.GetRecord(), bad.rec) || m.GetUid() != bad.uid {
		t.Fatal("the quarantined message is not the message that was delivered")
	}
	// The seal was made under a grant from policy for that tenant.
	var granted bool
	for _, q := range e.pol.requests() {
		granted = granted || (q.GetAction() == "audit.seal" && q.GetTenant() == "acme")
	}
	if !granted {
		t.Fatal("no grant was asked for the tenant of the quarantined record")
	}
	if _, err := os.Stat(filepath.Join(e.logDir(), "checkpoint")); err == nil {
		t.Fatal("a log of refused messages only was sealed")
	}

	// A good record after it is sealed, and the log verifies.
	good := newMessage(t, em, "key.sign", "acme")
	e.push(good)
	wait(t, "the good record", func() bool { return e.tr.ackedCount() == 2 })
	recs := recordEntries(logEntries(t, e.logDir()))
	if len(recs) != 1 || recs[0]["metadata"].(map[string]any)["uid"] != good.uid {
		t.Fatalf("entries = %v", recs)
	}
	e.mustVerify(t)
}

func TestAMessageWithAUsagePartIsQuarantinedWithIt(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	m := newMessage(t, em, "key.sign", "globex")
	usage := []byte(`{"id":"x/0"}`)
	e.tr.push(&transportv2alpha1.AuditMessage{Uid: m.uid, Record: m.rec, Usage: [][]byte{usage}})
	wait(t, "the message to be acknowledged", func() bool { return e.tr.ackedCount() == 1 })
	reports, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
	if len(reports) != 1 {
		t.Fatalf("reports = %v", reports)
	}
	rep, got := openQuarantine(t, e, reports[0])
	if rep["reason"] != reasonUsage || rep["tenant"] != "globex" || len(got.GetUsage()) != 1 || !bytes.Equal(got.GetUsage()[0], usage) {
		t.Fatalf("report = %v, message = %v", rep, got)
	}
	if e.key.sealCount() != 1 {
		t.Fatal("the record was sealed into the log as well")
	}
}

func TestAMessageWithoutAReadableTenantIsQuarantinedUnderTheOperators(t *testing.T) {
	e := newEnv(t)
	e.start()
	e.tr.push(&transportv2alpha1.AuditMessage{Uid: "u1", Record: []byte("not json")})
	wait(t, "the message to be acknowledged", func() bool { return e.tr.ackedCount() == 1 })
	reports, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
	if len(reports) != 1 {
		t.Fatalf("reports = %v", reports)
	}
	rep, got := openQuarantine(t, e, reports[0])
	if rep["tenant"] != testDefault || rep["reason"] != reasonCanonical || string(got.GetRecord()) != "not json" {
		t.Fatalf("report = %v", rep)
	}
}

func TestNothingIsAcknowledgedWhenAQuarantineCannotBeSealed(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.pol.mode = "deny"
	e.start()
	e.push(newMessage(t, em, "key.nothing", "acme"))
	wait(t, "policy to be asked", func() bool { return len(e.pol.requests()) > 0 })
	time.Sleep(200 * time.Millisecond)
	if e.tr.ackedCount() != 0 {
		t.Fatal("a refused message was acknowledged without being kept")
	}
	if g, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*")); len(g) != 0 {
		t.Fatal("a quarantine object was written without a seal")
	}
}

func TestAnIdleLogSignsNothing(t *testing.T) {
	e := newEnv(t)
	e.start()
	time.Sleep(500 * time.Millisecond) // several windows
	if i := e.ev.index("key.sign", 0); i >= 0 {
		t.Fatalf("an idle writer asked for a signature: %v", e.ev.all())
	}
	if _, err := os.Stat(filepath.Join(e.logDir(), "checkpoint")); err == nil {
		t.Fatal("an idle writer made a checkpoint")
	}
}

func TestWithoutAGrantNothingIsSealedOrAcknowledged(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.pol.mode = "deny"
	e.start()
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "policy to be asked", func() bool { return len(e.pol.requests()) > 0 })
	time.Sleep(200 * time.Millisecond)
	if e.key.sealCount() != 0 || e.tr.ackedCount() != 0 {
		t.Fatalf("sealed %d, acknowledged %d, without a grant", e.key.sealCount(), e.tr.ackedCount())
	}
	if _, err := os.Stat(filepath.Join(e.root, "audit")); err == nil {
		t.Fatal("the log was written without a grant")
	}
	// Policy comes back: the stream is opened again, the message is delivered again and sealed.
	e.pol.mu.Lock()
	e.pol.mode = ""
	e.pol.mu.Unlock()
	wait(t, "the message to be sealed after the retry", func() bool { return e.tr.ackedCount() == 1 })
	e.mustVerify(t)
}

func TestASecondWriterCannotFork(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "the first batch", func() bool { return e.tr.ackedCount() == 1 })

	// B starts from the same state as the running writer A.
	b := e.writer()
	if err := b.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.recover(ctx); err != nil {
		t.Fatal(err)
	}

	// A seals another batch. B, which still holds the old state, then tries a batch of the same width: the same
	// bundle path with other bytes, and create-if-absent refuses it.
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "the second batch", func() bool { return e.tr.ackedCount() == 2 })
	before := e.mustVerify(t)

	m := newMessage(t, em, "key.sign", "acme")
	err := b.processBatch(ctx, []*transportv2alpha1.Delivery{{DeliveryId: 99, Emitter: "key@dev",
		Message: &transportv2alpha1.AuditMessage{Uid: m.uid, Record: m.rec}}})
	var fatal *fatalError
	if !errors.As(err, &fatal) || !errors.Is(err, ErrFence) {
		t.Fatalf("B's batch = %v, want a fatal refusal of the fence", err)
	}
	if after := e.mustVerify(t); after != before {
		t.Fatalf("the log changed: %q then %q", before, after)
	}

	// A batch of another width gets past the bundles; the conditional put of the state then loses.
	c := e.writer()
	if err := c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.recover(ctx); err != nil {
		t.Fatal(err)
	}
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "the third batch", func() bool { return e.tr.ackedCount() == 3 })
	stateBefore, _ := os.ReadFile(filepath.Join(e.root, "state", "writer-state"))
	var ds []*transportv2alpha1.Delivery
	for i := range 3 {
		m := newMessage(t, em, "key.sign", "acme")
		ds = append(ds, &transportv2alpha1.Delivery{DeliveryId: uint64(100 + i), Emitter: "key@dev",
			Message: &transportv2alpha1.AuditMessage{Uid: m.uid, Record: m.rec}})
	}
	err = c.processBatch(ctx, ds)
	if !errors.Is(err, ErrFence) {
		t.Fatalf("C's batch = %v, want a refusal of the fence", err)
	}
	if stateAfter, _ := os.ReadFile(filepath.Join(e.root, "state", "writer-state")); !bytes.Equal(stateBefore, stateAfter) {
		t.Fatal("a stale writer changed the state")
	}
	if n := e.tr.ackedCount(); n != 3 {
		t.Fatalf("%d acknowledged; the stale writers acknowledged nothing", n)
	}
	// The writer that lost the put never signed: no checkpoint of a fork is in the log.
	e.mustVerify(t)
	if n := len(e.ev.all()); n == 0 {
		t.Fatal("no events")
	}
	signs := 0
	for _, s := range e.ev.all() {
		if s == "key.sign" {
			signs++
		}
	}
	if cps, _ := filepath.Glob(filepath.Join(e.logDir(), "checkpoints", "*")); len(cps) != signs {
		t.Fatalf("%d checkpoints for %d signatures", len(cps), signs)
	}
}

// crashOnce makes the first operation that matches fail, as if the blob went away, and returns the hook.
func crashOnce(match func(op, p string) bool) func(op, p string) error {
	var once sync.Once
	return func(op, p string) error {
		var err error
		if match(op, p) {
			once.Do(func() { err = connect.NewError(connect.CodeUnavailable, errors.New("the blob went away")) })
		}
		return err
	}
}

func TestACrashBetweenTheBundlesAndTheStateIsAdopted(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.blob.before = crashOnce(func(op, p string) bool { return op == "put" && strings.HasSuffix(p, "writer-state") })
	r := e.start()
	msgs := []message{newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "globex")}
	for _, m := range msgs {
		e.push(m)
	}
	if err := r.result(t); !errors.As(err, new(*fatalError)) {
		t.Fatalf("Run returned %v, want a fatal error", err)
	}
	if e.tr.ackedCount() != 0 {
		t.Fatal("something was acknowledged before its checkpoint")
	}
	if e.ev.index("key.sign", 0) >= 0 {
		t.Fatal("key@ signed before the state was put")
	}

	// The next start finds the bundles and no state. The same entries cannot be created again with other
	// contents, so they are adopted; the transport delivers the messages again and they are dropped as repeats.
	e.start()
	wait(t, "the messages to be acknowledged after the restart", func() bool { return e.tr.ackedCount() == len(msgs) })
	e.mustVerify(t)
	recs := recordEntries(logEntries(t, e.logDir()))
	if len(recs) != len(msgs) {
		t.Fatalf("%d record entries, want %d, each once", len(recs), len(msgs))
	}
	for i, m := range msgs {
		if recs[i]["metadata"].(map[string]any)["uid"] != m.uid {
			t.Fatalf("entry %d is not message %d", i, i)
		}
	}
}

func TestACrashBetweenTheStateAndTheCheckpointIsFinished(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.blob.before = crashOnce(func(op, p string) bool { return op == "create" && strings.Contains(p, "checkpoints/") })
	r := e.start()
	m := newMessage(t, em, "key.sign", "acme")
	e.push(m)
	if err := r.result(t); !errors.As(err, new(*fatalError)) {
		t.Fatalf("Run returned %v, want a fatal error", err)
	}
	if _, err := os.Stat(filepath.Join(e.root, "state", "writer-state")); err != nil {
		t.Fatalf("the state was not committed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.logDir(), "checkpoints")); err == nil {
		t.Fatal("a checkpoint exists")
	}
	if e.tr.ackedCount() != 0 {
		t.Fatal("acknowledged without a checkpoint")
	}
	// The state is the commit: the next start signs the checkpoint that is missing instead of refusing.
	e.start()
	wait(t, "the message to be acknowledged", func() bool { return e.tr.ackedCount() == 1 })
	e.mustVerify(t)
	if recs := recordEntries(logEntries(t, e.logDir())); len(recs) != 1 {
		t.Fatalf("%d record entries, want 1", len(recs))
	}
}

func TestStartRefusesWithoutItsDocuments(t *testing.T) {
	for _, kind := range []string{"audit-log", "audit-catalogue", "boundary"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			delete(e.store.items, kind)
			if err := e.writer().Init(context.Background()); err == nil {
				t.Fatal("started without " + kind)
			}
		})
	}
}

func TestACheckpointOfAnotherKeyIsRefusedAtStart(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "the batch", func() bool { return e.tr.ackedCount() == 1 })

	// A writer whose key is another cannot take the log over: the committed checkpoint does not verify.
	other := newEnv(t)
	other.root = e.root
	other.blob.root = e.root
	other.cfg.BlobSocket = e.cfg.BlobSocket
	s := other.writer()
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.recover(context.Background()); !errors.Is(err, ErrFence) {
		t.Fatalf("recover = %v, want a refusal of the fence", err)
	}
}

func TestAMovedPointerStopsTheWriter(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	r := e.start()
	e.push(newMessage(t, em, "key.sign", "acme"))
	wait(t, "the first batch", func() bool { return e.tr.ackedCount() == 1 })

	// Another writer moves the pointer.
	b := e.writer()
	ptr := "audit/main/checkpoint"
	have, etag, err := b.blob.get(context.Background(), ptr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.blob.put(context.Background(), ptr, append(have, 'x'), etag); err != nil {
		t.Fatal(err)
	}

	e.push(newMessage(t, em, "key.sign", "acme"))
	if err := r.result(t); !errors.Is(err, ErrFence) {
		t.Fatalf("Run returned %v, want a refusal of the fence", err)
	}
	if e.tr.ackedCount() != 1 {
		t.Fatal("a batch was acknowledged after the pointer was lost")
	}
}
