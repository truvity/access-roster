package lambdaext_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRuntime is the Lambda Extensions API: register, then event/next
// answering whatever the test queues.
type fakeRuntime struct {
	*httptest.Server
	events     chan string
	mu         sync.Mutex
	registered []string // the Lambda-Extension-Name of each registration
	regBody    string
	nexts      int
	subscribe  []string // bodies of PUT /2022-07-01/telemetry
	subStatus  int      // 0 is 200
}

func newFakeRuntime(t *testing.T) *fakeRuntime {
	t.Helper()
	f := &fakeRuntime{events: make(chan string, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /2020-01-01/extension/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.registered = append(f.registered, r.Header.Get("Lambda-Extension-Name"))
		f.regBody = string(body)
		f.mu.Unlock()
		w.Header().Set("Lambda-Extension-Identifier", "ext-1")
		_, _ = w.Write([]byte(`{"functionName":"f"}`))
	})
	mux.HandleFunc("PUT /2022-07-01/telemetry", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Lambda-Extension-Identifier") != "ext-1" {
			http.Error(w, "unregistered", http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.subscribe = append(f.subscribe, string(body))
		status := f.subStatus
		f.mu.Unlock()
		if status != 0 {
			http.Error(w, `{"errorMessage":"refused"}`, status)
			return
		}
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("GET /2020-01-01/extension/event/next", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Lambda-Extension-Identifier") != "ext-1" {
			http.Error(w, "unregistered", http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.nexts++
		f.mu.Unlock()
		select {
		case ev := <-f.events:
			_, _ = w.Write([]byte(ev))
		case <-r.Context().Done():
		}
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeRuntime) invoke() { f.events <- `{"eventType":"INVOKE","deadlineMs":0,"requestId":"r"}` }
func (f *fakeRuntime) shutdown() {
	f.events <- fmt.Sprintf(`{"eventType":"SHUTDOWN","deadlineMs":%d,"shutdownReason":"spindown"}`,
		time.Now().Add(2*time.Second).UnixMilli())
}
func (f *fakeRuntime) state() (names []string, body string, nexts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.registered...), f.regBody, f.nexts
}

// subscription returns the Telemetry API subscription bodies seen so far.
func (f *fakeRuntime) subscriptions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.subscribe...)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// extensionBinary builds the real command once, named as it is in the layer.
func extensionBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "lambdaext-bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "access-roster-otlp")
		out, err := exec.Command("go", "build", "-o", binPath, "../../cmd/access-roster-lambda").CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("%v: %s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

type running struct {
	cmd    *exec.Cmd
	logs   *syncBuffer
	exited chan error
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func startExtension(t *testing.T, env []string) *running {
	t.Helper()
	cmd := exec.Command(extensionBinary(t))
	cmd.Env = append([]string{"HOME=" + t.TempDir()}, env...)
	logs := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := &running{cmd: cmd, logs: logs, exited: make(chan error, 1)}
	go func() { r.exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return r
}

// export is what a function's OTel SDK does: one POST to the loopback address.
func export(t *testing.T, addr string) int {
	t.Helper()
	var status int
	eventually(t, "the proxy to accept a connection", func() bool {
		resp, err := http.Post("http://"+addr+"/v1/traces", "application/x-protobuf", strings.NewReader("spans"))
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		status = resp.StatusCode
		return true
	})
	return status
}

func baseEnv(rt *fakeRuntime, sts *fakeSTS, issuer *fakeIssuer, up *fakeUpstream, addr string) []string {
	return []string{
		"AWS_LAMBDA_RUNTIME_API=" + strings.TrimPrefix(rt.URL, "http://"),
		"AWS_REGION=eu-west-1", "AWS_ACCESS_KEY_ID=AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY=secret",
		"AWS_SESSION_TOKEN=session", "AWS_ENDPOINT_URL_STS=" + sts.URL, "AWS_EC2_METADATA_DISABLED=true",
		"ACCESS_ROSTER_ISSUER=" + issuer.URL, "ACCESS_ROSTER_AUDIENCE=" + issuer.URL,
		"ACCESS_ROSTER_OTLP_ENDPOINT=" + up.URL, "ACCESS_ROSTER_LISTEN=" + addr,
		"ACCESS_ROSTER_PLATFORM_LOGS=false", // the Telemetry API tests opt in
	}
}

func TestExtensionEndToEnd(t *testing.T) {
	rt, sts, up := newFakeRuntime(t), newFakeSTS(t), newFakeUpstream(t)
	issuer := newFakeIssuer(t, 6) // refresh window opens after 4 seconds
	addr := freeAddr(t)
	tokenFile := filepath.Join(t.TempDir(), "sub", "token")
	ext := startExtension(t, append(baseEnv(rt, sts, issuer, up, addr), "ACCESS_ROSTER_TOKEN_FILE="+tokenFile))

	// Registered under the executable's own name, for both events.
	eventually(t, "registration", func() bool { n, _, _ := rt.state(); return len(n) == 1 })
	names, body, _ := rt.state()
	if names[0] != "access-roster-otlp" || body != `{"events":["INVOKE","SHUTDOWN"]}` {
		t.Fatalf("registered %v %s", names, body)
	}
	eventually(t, "the first next", func() bool { _, _, n := rt.state(); return n >= 1 })
	rt.invoke()

	// The function's export reaches the upstream with the exchanged token.
	if s := export(t, addr); s != 200 {
		t.Fatalf("export: %d", s)
	}
	call := up.seen()[0]
	if call.Auth != "Bearer access-1" || call.Path != "/v1/traces" || string(call.Body) != "spans" {
		t.Fatalf("upstream saw %+v", call)
	}
	// The STS identity token, not anything from the function, went to the issuer.
	if issuer.exchanges[0].Get("subject_token") != "sts-jwt-1" || issuer.exchanges[0].Get("audience") != "otlp" {
		t.Fatalf("exchange %v", issuer.exchanges[0])
	}
	if sts.calls()[0].Get("Audience.member.1") != issuer.URL || sts.calls()[0].Get("SigningAlgorithm") != "ES384" {
		t.Fatalf("sts %v", sts.calls()[0])
	}

	// The optional token file: the same token, 0600.
	eventually(t, "the token file", func() bool { _, err := os.Stat(tokenFile); return err == nil })
	if b, _ := os.ReadFile(tokenFile); string(b) != "access-1" {
		t.Fatalf("token file %q", b)
	}
	if st, _ := os.Stat(tokenFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", st.Mode())
	}

	// Cached: a second export does not touch STS or the issuer.
	export(t, addr)
	if issuer.count() != 1 || len(sts.calls()) != 1 {
		t.Fatalf("expected one exchange, got %d / %d sts", issuer.count(), len(sts.calls()))
	}

	// "Frozen" past the refresh window with no INVOKE: refreshed on demand.
	time.Sleep(4500 * time.Millisecond)
	export(t, addr)
	if got := up.seen()[2].Auth; got != "Bearer access-2" {
		t.Fatalf("after expiry the upstream saw %q", got)
	}
	if b, _ := os.ReadFile(tokenFile); string(b) != "access-2" {
		t.Fatalf("token file after refresh %q", b)
	}

	// SHUTDOWN: a clean exit inside the deadline.
	start := time.Now()
	rt.shutdown()
	select {
	case err := <-ext.exited:
		if err != nil || time.Since(start) > 2*time.Second {
			t.Fatalf("exit %v after %v", err, time.Since(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the extension did not exit on SHUTDOWN")
	}
	// Tokens are never logged.
	for _, secret := range []string{"access-1", "access-2", "sts-jwt", "secret", "session"} {
		if strings.Contains(ext.logs.String(), secret) {
			t.Fatalf("log leaks %q:\n%s", secret, ext.logs.String())
		}
	}
}

func TestExtensionFailsOpenWhenNoTokenCanBeHad(t *testing.T) {
	rt, sts, up := newFakeRuntime(t), newFakeSTS(t), newFakeUpstream(t)
	issuer := newFakeIssuer(t, 900)
	issuer.refuse = true
	addr := freeAddr(t)
	ext := startExtension(t, baseEnv(rt, sts, issuer, up, addr))
	eventually(t, "registration", func() bool { n, _, _ := rt.state(); return len(n) == 1 })
	rt.invoke()

	for range 3 {
		if s := export(t, addr); s != http.StatusServiceUnavailable {
			t.Fatalf("want 503 so the exporter retries, got %d", s)
		}
	}
	if len(up.seen()) != 0 {
		t.Fatal("nothing may be forwarded without a token")
	}
	// The extension is still answering the platform, and logged once.
	eventually(t, "a log line", func() bool { return strings.Contains(ext.logs.String(), "exports will be refused") })
	if n := strings.Count(ext.logs.String(), "exports will be refused"); n != 1 {
		t.Fatalf("one line per failure window, got %d:\n%s", n, ext.logs.String())
	}
	select {
	case err := <-ext.exited:
		t.Fatalf("a failing token must never end the extension: %v", err)
	default:
	}

	// The issuer recovers; the next export, after the backoff, succeeds.
	issuer.mu.Lock()
	issuer.refuse = false
	issuer.mu.Unlock()
	time.Sleep(5200 * time.Millisecond)
	if s := export(t, addr); s != 200 {
		t.Fatalf("after recovery: %d", s)
	}
	rt.shutdown()
	if err := <-ext.exited; err != nil {
		t.Fatal(err)
	}
}

func TestExtensionWithoutConfigurationStillAnswersThePlatform(t *testing.T) {
	rt := newFakeRuntime(t)
	ext := startExtension(t, []string{"AWS_LAMBDA_RUNTIME_API=" + strings.TrimPrefix(rt.URL, "http://")})
	eventually(t, "the first next", func() bool { _, _, n := rt.state(); return n >= 1 })
	rt.invoke()
	eventually(t, "the second next", func() bool { _, _, n := rt.state(); return n >= 2 })
	rt.shutdown()
	if err := <-ext.exited; err != nil {
		t.Fatalf("%v\n%s", err, ext.logs.String())
	}
	if !strings.Contains(ext.logs.String(), "ACCESS_ROSTER_ISSUER is not set") {
		t.Fatalf("the misconfiguration must be named once:\n%s", ext.logs.String())
	}
}

func TestShutdownDrainsAnInFlightForward(t *testing.T) {
	rt, sts, issuer := newFakeRuntime(t), newFakeSTS(t), newFakeIssuer(t, 900)
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte("late"))
	}))
	defer slow.Close()
	up := &fakeUpstream{Server: slow}
	addr := freeAddr(t)
	ext := startExtension(t, baseEnv(rt, sts, issuer, up, addr))
	eventually(t, "the first next", func() bool { _, _, n := rt.state(); return n >= 1 })

	done := make(chan int, 1)
	go func() {
		eventually(t, "the proxy", func() bool {
			c, err := net.Dial("tcp", addr)
			if err == nil {
				_ = c.Close()
			}
			return err == nil
		})
		resp, err := http.Post("http://"+addr+"/v1/traces", "application/json", strings.NewReader("{}"))
		if err != nil {
			done <- -1
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	eventually(t, "the exchange", func() bool { return issuer.count() == 1 })
	time.Sleep(200 * time.Millisecond) // the forward is now blocked upstream
	rt.shutdown()
	time.Sleep(300 * time.Millisecond)
	select {
	case <-ext.exited:
		t.Fatal("exited with a forward in flight")
	default:
	}
	close(release)
	if s := <-done; s != 200 {
		t.Fatalf("the in-flight export got %d", s)
	}
	if err := <-ext.exited; err != nil {
		t.Fatal(err)
	}
}
