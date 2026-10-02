//nolint:lll // the AWS fixtures are single-line JSON
package lambdaext_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/lambdaext"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

var fixedNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// Fixtures follow the AWS Telemetry API reference (schema 2022-12-13).
const (
	traceValue = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"

	fxStart = `{"time":"2022-10-12T00:03:50.000Z","type":"platform.start","record":{"requestId":"6d68ca91-49c9-448d-89b8-7ca3e6dc66aa","version":"$LATEST",` +
		`"tracing":{"spanId":"54565fb41ac79632","type":"X-Amzn-Trace-Id","value":"` + traceValue + `"}}}`
	fxRuntimeDone = `{"time":"2022-10-12T00:03:50.000Z","type":"platform.runtimeDone","record":{"requestId":"6d68ca91-49c9-448d-89b8-7ca3e6dc66aa","status":"success",` +
		`"metrics":{"durationMs":140.0,"producedBytes":16},"spans":[{"name":"responseLatency","start":"2022-10-12T00:03:50.000Z","durationMs":0.5}]}}`
	fxReport = `{"time":"2022-10-12T00:03:50.000Z","type":"platform.report","record":{"requestId":"6d68ca91-49c9-448d-89b8-7ca3e6dc66aa","status":"success",` +
		`"metrics":{"durationMs":1.62,"billedDurationMs":2,"memorySizeMB":128,"maxMemoryUsedMB":47,"initDurationMs":201.5}}}`
	fxTimeoutReport = `{"time":"2022-10-12T00:04:50.000Z","type":"platform.report","record":{"requestId":"b1","status":"timeout","errorType":"Task.Timedout",` +
		`"metrics":{"durationMs":3000.0,"billedDurationMs":3000,"memorySizeMB":128,"maxMemoryUsedMB":60}}}`
	fxTimeoutDone = `{"time":"2022-10-12T00:04:50.000Z","type":"platform.runtimeDone","record":{"requestId":"b1","status":"timeout","metrics":{"durationMs":3000.0}}}`
	fxOOMReport   = `{"time":"2022-10-12T00:05:50.000Z","type":"platform.report","record":{"requestId":"c2","status":"error","errorType":"Runtime.OutOfMemory",` +
		`"metrics":{"durationMs":800.1,"billedDurationMs":801,"memorySizeMB":128,"maxMemoryUsedMB":128}}}`
	fxInitStart = `{"time":"2022-10-12T00:00:15.000Z","type":"platform.initStart","record":{"initializationType":"on-demand","phase":"init",` +
		`"runtimeVersion":"python:3.13.v10","runtimeVersionArn":"runtime-arn","functionName":"billing","functionVersion":"$LATEST","instanceId":"i-1","instanceMaxMemory":134217728}}`
	fxInitRuntimeDone = `{"time":"2022-10-12T00:00:16.000Z","type":"platform.initRuntimeDone","record":{"initializationType":"on-demand","phase":"init","status":"success"}}`
	fxInitError       = `{"time":"2022-10-12T00:00:16.000Z","type":"platform.initRuntimeDone","record":{"initializationType":"on-demand","phase":"init","status":"error","errorType":"Runtime.ImportModuleError"}}`
	fxInitReport      = `{"time":"2022-10-12T00:00:16.000Z","type":"platform.initReport","record":{"initializationType":"on-demand","phase":"init","status":"success","metrics":{"durationMs":500.8}}}`
	fxRestoreStart    = `{"time":"2022-10-12T00:00:15.000Z","type":"platform.restoreStart","record":{"runtimeVersion":"java17","runtimeVersionArn":"runtime-arn"}}`
	fxRestoreReport   = `{"time":"2022-10-12T00:00:16.000Z","type":"platform.restoreReport","record":{"status":"success","metrics":{"durationMs":120.5}}}`
	fxLogsDropped     = `{"time":"2022-10-12T00:00:17.000Z","type":"platform.logsDropped","record":{"droppedBytes":12000,"droppedRecords":40,"reason":"Consumer seems to have fallen behind as it has not acknowledged receipt of logs."}}`
	fxFunction        = `{"time":"2022-10-12T00:03:50.000Z","type":"function","record":"hello from the function\n"}`
	fxFunctionJSON    = `{"time":"2022-10-12T00:03:50.000Z","type":"function","record":{"timestamp":"2022-10-12T00:03:50.000Z","level":"ERROR","requestId":"r9","message":"boom"}}`
	fxExtension       = `{"time":"2022-10-12T00:03:50.000Z","type":"extension","record":"an extension line"}`
)

func attrs(rec *lambdaext.LogRecord) map[string]any { return attrMap(rec.Attrs) }

func attrMap(in []lambdaext.Attr) map[string]any {
	m := map[string]any{}
	for _, a := range in {
		switch a.Kind {
		case lambdaext.KindString:
			m[a.Key] = a.Str
		case lambdaext.KindInt:
			m[a.Key] = a.Int
		case lambdaext.KindFloat:
			m[a.Key] = a.Float
		}
	}
	return m
}

// wireAttrs reads attributes back from what went over the wire, decoded by
// the generated OTLP packages, which the binary itself does not link.
func wireAttrs(in []*commonpb.KeyValue) map[string]any {
	m := map[string]any{}
	for _, kv := range in {
		switch v := kv.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			m[kv.Key] = v.StringValue
		case *commonpb.AnyValue_DoubleValue:
			m[kv.Key] = v.DoubleValue
		case *commonpb.AnyValue_IntValue:
			m[kv.Key] = v.IntValue
		}
	}
	return m
}

func mapOne(t *testing.T, fixture string) *lambdaext.LogRecord {
	t.Helper()
	var ev lambdaext.TelemetryEvent
	if err := json.Unmarshal([]byte(fixture), &ev); err != nil {
		t.Fatal(err)
	}
	rec, ok := lambdaext.MapEvent(ev, fixedNow)
	if !ok {
		t.Fatalf("not mapped: %s", fixture)
	}
	return rec
}

func TestMapEvent(t *testing.T) {
	cases := []struct {
		name, fixture string
		sev           int32
		body          string
		attrs         map[string]any
	}{
		{"start", fxStart, lambdaext.SeverityInfo,
			"START RequestId: 6d68ca91-49c9-448d-89b8-7ca3e6dc66aa Version: $LATEST",
			map[string]any{"event.name": "platform.start", "requestId": "6d68ca91-49c9-448d-89b8-7ca3e6dc66aa"}},
		{"runtimeDone", fxRuntimeDone, lambdaext.SeverityInfo,
			"RUNTIME_DONE RequestId: 6d68ca91-49c9-448d-89b8-7ca3e6dc66aa Status: success",
			map[string]any{"status": "success", "durationMs": 140.0, "producedBytes": 16.0}},
		{"report", fxReport, lambdaext.SeverityInfo,
			"REPORT RequestId: 6d68ca91-49c9-448d-89b8-7ca3e6dc66aa Duration: 1.62 ms Billed Duration: 2 ms Memory Size: 128 MB Max Memory Used: 47 MB Init Duration: 201.5 ms Status: success",
			map[string]any{"durationMs": 1.62, "billedDurationMs": 2.0, "memorySizeMB": 128.0, "maxMemoryUsedMB": 47.0, "initDurationMs": 201.5}},
		{"timeout report", fxTimeoutReport, lambdaext.SeverityError,
			"REPORT RequestId: b1 Duration: 3000 ms Billed Duration: 3000 ms Memory Size: 128 MB Max Memory Used: 60 MB Status: timeout ErrorType: Task.Timedout",
			map[string]any{"status": "timeout", "errorType": "Task.Timedout", "billedDurationMs": 3000.0}},
		{"timeout runtimeDone", fxTimeoutDone, lambdaext.SeverityError,
			"RUNTIME_DONE RequestId: b1 Status: timeout", map[string]any{"status": "timeout"}},
		{"out of memory report", fxOOMReport, lambdaext.SeverityError,
			"REPORT RequestId: c2 Duration: 800.1 ms Billed Duration: 801 ms Memory Size: 128 MB Max Memory Used: 128 MB Status: error ErrorType: Runtime.OutOfMemory",
			map[string]any{"status": "error", "errorType": "Runtime.OutOfMemory", "maxMemoryUsedMB": 128.0, "memorySizeMB": 128.0}},
		{"initStart", fxInitStart, lambdaext.SeverityInfo,
			"INIT_START Runtime Version: python:3.13.v10 Phase: init",
			map[string]any{"initializationType": "on-demand", "phase": "init"}},
		{"initRuntimeDone", fxInitRuntimeDone, lambdaext.SeverityInfo,
			"INIT_RUNTIME_DONE Phase: init Status: success", map[string]any{"status": "success"}},
		{"init error", fxInitError, lambdaext.SeverityError,
			"INIT_RUNTIME_DONE Phase: init Status: error ErrorType: Runtime.ImportModuleError",
			map[string]any{"errorType": "Runtime.ImportModuleError"}},
		{"initReport", fxInitReport, lambdaext.SeverityInfo,
			"INIT_REPORT Phase: init Status: success Duration: 500.8 ms", map[string]any{"durationMs": 500.8}},
		{"restoreStart", fxRestoreStart, lambdaext.SeverityInfo,
			"RESTORE_START Runtime Version: java17", map[string]any{"event.name": "platform.restoreStart"}},
		{"restoreReport", fxRestoreReport, lambdaext.SeverityInfo,
			"RESTORE_REPORT Status: success Duration: 120.5 ms", map[string]any{"durationMs": 120.5}},
		{"logsDropped", fxLogsDropped, lambdaext.SeverityWarn,
			"LOGS_DROPPED Reason: Consumer seems to have fallen behind as it has not acknowledged receipt of logs. Dropped Records: 40",
			map[string]any{"droppedRecords": 40.0, "droppedBytes": 12000.0}},
		{"function string", fxFunction, lambdaext.SeverityInfo,
			"hello from the function", map[string]any{"event.name": "function"}},
		{"function json", fxFunctionJSON, lambdaext.SeverityError,
			"boom", map[string]any{"requestId": "r9"}},
		{"extension", fxExtension, lambdaext.SeverityInfo,
			"an extension line", map[string]any{"event.name": "extension"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := mapOne(t, c.fixture)
			if rec.Severity != c.sev {
				t.Errorf("severity %v, want %v", rec.Severity, c.sev)
			}
			if got := rec.Body; got != c.body {
				t.Errorf("body %q\nwant %q", got, c.body)
			}
			got := attrs(rec)
			for k, v := range c.attrs {
				if got[k] != v {
					t.Errorf("attribute %s = %v, want %v (all: %v)", k, got[k], v, got)
				}
			}
			if rec.TimeUnixNano == 0 {
				t.Error("no timestamp")
			}
		})
	}
	// The time comes from the event, not from the clock.
	if got := mapOne(t, fxStart).TimeUnixNano; got != uint64(time.Date(2022, 10, 12, 0, 3, 50, 0, time.UTC).UnixNano()) {
		t.Errorf("time %d", got)
	}
}

func TestMapEventTraceCorrelation(t *testing.T) {
	rec := mapOne(t, fxStart)
	if hex.EncodeToString(rec.TraceID) != "5759e988bd862e3fe1be46a994272793" ||
		hex.EncodeToString(rec.SpanID) != "54565fb41ac79632" || rec.Flags != 1 {
		t.Fatalf("trace %x span %x flags %d", rec.TraceID, rec.SpanID, rec.Flags)
	}
	// Without spanId the Parent of the header is the span.
	noSpan := strings.Replace(fxStart, `"spanId":"54565fb41ac79632",`, "", 1)
	if got := hex.EncodeToString(mapOne(t, noSpan).SpanID); got != "53995c3f42cd8ad8" {
		t.Errorf("span %s", got)
	}
	// No tracing, or a value that does not parse: no correlation, still a record.
	for _, fx := range []string{fxReport, strings.Replace(fxStart, traceValue, "Root=garbage", 1)} {
		if rec := mapOne(t, fx); rec.TraceID != nil || rec.SpanID != nil {
			t.Errorf("unexpected correlation %x %x", rec.TraceID, rec.SpanID)
		}
	}
}

func TestMapEventDropsWhatItDoesNotKnow(t *testing.T) {
	for _, fx := range []string{
		`{"time":"2022-10-12T00:00:00Z","type":"something.else","record":{}}`,
		`{"time":"2022-10-12T00:00:00Z","type":"platform.start","record":"not an object"}`,
	} {
		var ev lambdaext.TelemetryEvent
		_ = json.Unmarshal([]byte(fx), &ev)
		if _, ok := lambdaext.MapEvent(ev, fixedNow); ok {
			t.Errorf("mapped %s", fx)
		}
	}
	// A bad timestamp falls back to the clock.
	var ev lambdaext.TelemetryEvent
	_ = json.Unmarshal([]byte(`{"time":"yesterday","type":"function","record":"x"}`), &ev)
	if rec, ok := lambdaext.MapEvent(ev, fixedNow); !ok || rec.TimeUnixNano != uint64(fixedNow.UnixNano()) {
		t.Errorf("fallback time: %v %v", rec, ok)
	}
}

func TestResource(t *testing.T) {
	env := map[string]string{
		"AWS_LAMBDA_FUNCTION_NAME": "billing", "AWS_LAMBDA_FUNCTION_VERSION": "7", "AWS_LAMBDA_LOG_STREAM_NAME": "2026/10/02/[7]abc",
		"AWS_REGION": "eu-west-1", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "128",
	}
	get := func(k string) string { return env[k] }
	got := attrMap(lambdaext.Resource(get))
	want := map[string]any{
		"service.name": "billing", "faas.name": "billing", "faas.version": "7", "faas.instance": "2026/10/02/[7]abc",
		"cloud.provider": "aws", "cloud.platform": "aws_lambda", "cloud.region": "eu-west-1", "faas.max_memory": int64(128 << 20),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	env["OTEL_SERVICE_NAME"] = "billing-api"
	if attrMap(lambdaext.Resource(get))["service.name"] != "billing-api" {
		t.Error("OTEL_SERVICE_NAME must win")
	}
}

func TestLoadTelemetryConfig(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	c, err := lambdaext.LoadTelemetryConfig(get)
	if err != nil || !c.Platform || c.Function || c.Extension || c.Listen != "sandbox.localdomain:4243" ||
		c.MaxItems != 1000 || c.MaxBytes != 262144 || c.TimeoutMs != 1000 || c.QueueItems != 5000 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	env[lambdaext.EnvPlatformLogs] = "false"
	env[lambdaext.EnvFunctionLogs] = "true"
	env[lambdaext.EnvBufferTimeoutMs] = "250"
	if c, err = lambdaext.LoadTelemetryConfig(get); err != nil || c.Platform || !c.Function || c.TimeoutMs != 250 || !c.Enabled() {
		t.Fatalf("set: %+v %v", c, err)
	}
	env[lambdaext.EnvFunctionLogs] = "false"
	if c, _ = lambdaext.LoadTelemetryConfig(get); c.Enabled() {
		t.Fatal("nothing subscribed must be disabled")
	}
	env[lambdaext.EnvBufferMaxItems] = "5"
	env[lambdaext.EnvBufferMaxBytes] = "x"
	env[lambdaext.EnvExtensionLogs] = "maybe"
	_, err = lambdaext.LoadTelemetryConfig(get)
	for _, name := range []string{lambdaext.EnvBufferMaxItems, lambdaext.EnvBufferMaxBytes, lambdaext.EnvExtensionLogs} {
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("error must name %s: %v", name, err)
		}
	}
}

// staticTokens is a Tokens whose token and failure the test sets.
type staticTokens struct {
	mu          sync.Mutex
	token       string
	err         error
	invalidated []string
}

func (s *staticTokens) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, s.err
}

func (s *staticTokens) Invalidate(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated = append(s.invalidated, tok)
	s.token = "fresh"
}

func records(n int) []*lambdaext.LogRecord {
	out := make([]*lambdaext.LogRecord, n)
	for i := range out {
		out[i] = &lambdaext.LogRecord{Severity: lambdaext.SeverityInfo, Body: fmt.Sprint("r", i)}
	}
	return out
}

func decodeLogs(t *testing.T, c upstreamCall) (*collogs.ExportLogsServiceRequest, []*logspb.LogRecord) {
	t.Helper()
	var req collogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(c.Body, &req); err != nil {
		t.Fatal(err)
	}
	var recs []*logspb.LogRecord
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			recs = append(recs, sl.LogRecords...)
		}
	}
	return &req, recs
}

func TestTelemetryQueueDropsOldestAndSaysSo(t *testing.T) {
	up := newFakeUpstream(t)
	tele := &lambdaext.Telemetry{Upstream: up.URL, Tokens: &staticTokens{token: "tok"}, QueueItems: 3,
		Resource: lambdaext.Resource(func(string) string { return "" }), Now: func() time.Time { return fixedNow }}
	tele.Enqueue(records(5))
	if tele.Dropped() != 2 {
		t.Fatalf("dropped %d", tele.Dropped())
	}
	if err := tele.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := up.seen()
	if len(seen) != 1 || seen[0].Path != "/v1/logs" || seen[0].Auth != "Bearer tok" || seen[0].ContentType != "application/x-protobuf" {
		t.Fatalf("upstream saw %+v", seen)
	}
	_, recs := decodeLogs(t, seen[0])
	// A warning about the drop first, then the newest three (r2..r4).
	if len(recs) != 4 || !strings.Contains(recs[0].Body.GetStringValue(), "dropped 2 Lambda telemetry records") ||
		recs[1].Body.GetStringValue() != "r2" || recs[3].Body.GetStringValue() != "r4" {
		t.Fatalf("records %v", recs)
	}
	if tele.Dropped() != 0 {
		t.Fatal("the drop counter must reset once reported")
	}
}

func TestTelemetryFlushBatches(t *testing.T) {
	up := newFakeUpstream(t)
	tele := &lambdaext.Telemetry{Upstream: up.URL, Tokens: &staticTokens{token: "tok"}, QueueItems: 2000}
	tele.Enqueue(records(1100))
	if err := tele.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := up.seen()
	if len(seen) != 3 {
		t.Fatalf("1100 records in batches of 500: %d exports", len(seen))
	}
}

func TestTelemetryFailsOpenAndLogsOncePerWindow(t *testing.T) {
	up := newFakeUpstream(t)
	up.setStatus(http.StatusBadGateway)
	var mu sync.Mutex
	var lines []string
	tele := &lambdaext.Telemetry{Upstream: up.URL, Tokens: &staticTokens{token: "tok"}, QueueItems: 100,
		Logf: func(f string, a ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, a...)); mu.Unlock() }}
	for range 3 {
		tele.Enqueue(records(2))
		if err := tele.Flush(context.Background()); err != nil {
			t.Fatalf("a failed export must not be an error to the caller: %v", err)
		}
	}
	mu.Lock()
	if len(lines) != 1 || strings.Contains(lines[0], "tok") {
		t.Fatalf("one line per failure window, no secrets: %v", lines)
	}
	mu.Unlock()
	up.setStatus(http.StatusOK)
	tele.Enqueue(records(1))
	_ = tele.Flush(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 || !strings.Contains(lines[1], "again") {
		t.Fatalf("recovery line: %v", lines)
	}
}

func TestTelemetryNoTokenDropsWithoutCallingUpstream(t *testing.T) {
	up := newFakeUpstream(t)
	tele := &lambdaext.Telemetry{Upstream: up.URL, Tokens: &staticTokens{err: errors.New("no token")}}
	tele.Enqueue(records(2))
	if err := tele.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(up.seen()) != 0 {
		t.Fatal("nothing may be sent without a token")
	}
}

func TestTelemetryRetriesOnceAfter401(t *testing.T) {
	var mu sync.Mutex
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer stale" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	tokens := &staticTokens{token: "stale"}
	tele := &lambdaext.Telemetry{Upstream: srv.URL, Tokens: tokens}
	tele.Enqueue(records(1))
	_ = tele.Flush(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(auths) != 2 || auths[1] != "Bearer fresh" || len(tokens.invalidated) != 1 {
		t.Fatalf("auths %v invalidated %v", auths, tokens.invalidated)
	}
}

func TestTelemetryHandlerAnswersAtOnce(t *testing.T) {
	up := newFakeUpstream(t)
	tele := &lambdaext.Telemetry{Upstream: up.URL, Tokens: &staticTokens{token: "tok"}}
	h := httptest.NewServer(tele)
	defer h.Close()
	body := "[" + fxReport + "," + fxTimeoutReport + `,{"type":"unknown","record":{}}]`
	resp, err := http.Post(h.URL, "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	_ = resp.Body.Close()
	eventually(t, "the export", func() bool { return len(up.seen()) == 1 })
	_, recs := decodeLogs(t, up.seen()[0])
	if len(recs) != 2 {
		t.Fatalf("the unknown event is dropped: %d records", len(recs))
	}
	if r, _ := http.Post(h.URL, "application/json", strings.NewReader("{")); r.StatusCode != 400 {
		t.Fatalf("bad body: %d", r.StatusCode)
	}
}

// postBatch is the Telemetry API: it POSTs a batch to the destination the
// extension subscribed.
func postBatch(t *testing.T, uri string, events ...string) {
	t.Helper()
	resp, err := http.Post(uri, "application/json", strings.NewReader("["+strings.Join(events, ",")+"]"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("the listener answered %d", resp.StatusCode)
	}
}

func telemetryEnv(t *testing.T, rt *fakeRuntime, sts *fakeSTS, issuer *fakeIssuer, up *fakeUpstream, listen string, extra ...string) []string {
	env := append(baseEnv(rt, sts, issuer, up, freeAddr(t)),
		"AWS_LAMBDA_FUNCTION_NAME=billing", "AWS_LAMBDA_FUNCTION_VERSION=$LATEST",
		"AWS_LAMBDA_LOG_STREAM_NAME=2026/10/02/[$LATEST]abc", "AWS_REGION=eu-west-1",
		"ACCESS_ROSTER_PLATFORM_LOGS=true", "ACCESS_ROSTER_TELEMETRY_LISTEN="+listen)
	return append(env, extra...)
}

func TestExtensionForwardsPlatformLogs(t *testing.T) {
	rt, sts, up := newFakeRuntime(t), newFakeSTS(t), newFakeUpstream(t)
	issuer := newFakeIssuer(t, 900)
	listen := freeAddr(t)
	ext := startExtension(t, telemetryEnv(t, rt, sts, issuer, up, listen,
		"ACCESS_ROSTER_FUNCTION_LOGS=true", "ACCESS_ROSTER_TELEMETRY_BUFFER_TIMEOUT_MS=250"))

	eventually(t, "the subscription", func() bool { return len(rt.subscriptions()) == 1 })
	var sub struct {
		SchemaVersion string
		Types         []string
		Buffering     map[string]int
		Destination   struct{ Protocol, URI string }
	}
	if err := json.Unmarshal([]byte(rt.subscriptions()[0]), &sub); err != nil {
		t.Fatal(err)
	}
	if sub.SchemaVersion != "2022-12-13" || strings.Join(sub.Types, ",") != "platform,function" ||
		sub.Buffering["timeoutMs"] != 250 || sub.Buffering["maxBytes"] != 262144 || sub.Buffering["maxItems"] != 1000 ||
		sub.Destination.Protocol != "HTTP" || sub.Destination.URI != "http://"+listen {
		t.Fatalf("subscription %+v", sub)
	}

	rt.invoke()
	postBatch(t, sub.Destination.URI, fxStart, fxFunction, fxTimeoutReport)
	eventually(t, "the logs to reach the upstream", func() bool {
		for _, c := range up.seen() {
			if c.Path == "/v1/logs" {
				return true
			}
		}
		return false
	})
	var call upstreamCall
	for _, c := range up.seen() {
		if c.Path == "/v1/logs" {
			call = c
		}
	}
	if call.Auth != "Bearer access-1" || call.ContentType != "application/x-protobuf" {
		t.Fatalf("upstream saw %+v", call)
	}
	req, recs := decodeLogs(t, call)
	res := wireAttrs(req.ResourceLogs[0].Resource.Attributes)
	if res["service.name"] != "billing" || res["faas.name"] != "billing" || res["cloud.platform"] != "aws_lambda" ||
		res["cloud.region"] != "eu-west-1" || res["faas.instance"] != "2026/10/02/[$LATEST]abc" {
		t.Fatalf("resource %v", res)
	}
	if len(recs) != 3 || int32(recs[2].SeverityNumber) != lambdaext.SeverityError ||
		wireAttrs(recs[2].Attributes)["errorType"] != "Task.Timedout" || recs[0].TraceId == nil {
		t.Fatalf("records %v", recs)
	}

	// SHUTDOWN: a batch that arrives with it is still exported before exit.
	before := len(up.seen())
	postBatch(t, sub.Destination.URI, fxOOMReport)
	rt.shutdown()
	if err := <-ext.exited; err != nil {
		t.Fatalf("%v\n%s", err, ext.logs.String())
	}
	if len(up.seen()) <= before {
		t.Fatal("the last batch was not flushed on SHUTDOWN")
	}
	_, last := decodeLogs(t, up.seen()[len(up.seen())-1])
	if wireAttrs(last[0].Attributes)["errorType"] != "Runtime.OutOfMemory" {
		t.Fatalf("last export %v", last)
	}
	for _, secret := range []string{"access-1", "sts-jwt", "secret", "session"} {
		if strings.Contains(ext.logs.String(), secret) {
			t.Fatalf("log leaks %q:\n%s", secret, ext.logs.String())
		}
	}
}

func TestExtensionSubscribesToPlatformOnlyByDefaultAndCanBeOff(t *testing.T) {
	rt, sts, up := newFakeRuntime(t), newFakeSTS(t), newFakeUpstream(t)
	issuer := newFakeIssuer(t, 900)
	startExtension(t, telemetryEnv(t, rt, sts, issuer, up, freeAddr(t)))
	eventually(t, "the subscription", func() bool { return len(rt.subscriptions()) == 1 })
	if !strings.Contains(rt.subscriptions()[0], `"types":["platform"]`) {
		t.Fatalf("default types: %s", rt.subscriptions()[0])
	}

	rt2 := newFakeRuntime(t)
	ext := startExtension(t, telemetryEnv(t, rt2, sts, issuer, up, freeAddr(t), "ACCESS_ROSTER_PLATFORM_LOGS=false"))
	eventually(t, "the first next", func() bool { _, _, n := rt2.state(); return n >= 1 })
	time.Sleep(300 * time.Millisecond)
	if len(rt2.subscriptions()) != 0 {
		t.Fatalf("subscribed with every type off: %v", rt2.subscriptions())
	}
	rt2.shutdown()
	if err := <-ext.exited; err != nil {
		t.Fatal(err)
	}
}

func TestExtensionKeepsRunningWhenTheSubscriptionIsRefused(t *testing.T) {
	rt, sts, up := newFakeRuntime(t), newFakeSTS(t), newFakeUpstream(t)
	issuer := newFakeIssuer(t, 900)
	rt.mu.Lock()
	rt.subStatus = http.StatusForbidden
	rt.mu.Unlock()
	addr := freeAddr(t)
	env := telemetryEnv(t, rt, sts, issuer, up, freeAddr(t), "ACCESS_ROSTER_LISTEN="+addr)
	ext := startExtension(t, env)
	eventually(t, "a log line", func() bool { return strings.Contains(ext.logs.String(), "Lambda telemetry logs are off") })
	// The OTLP proxy is unaffected.
	if s := export(t, addr); s != 200 {
		t.Fatalf("export: %d", s)
	}
	rt.invoke()
	rt.shutdown()
	if err := <-ext.exited; err != nil {
		t.Fatalf("%v\n%s", err, ext.logs.String())
	}
}

// The hand-written encoder must agree with the generated OTLP schema.
func TestEncodeLogsRoundTripsThroughTheGeneratedSchema(t *testing.T) {
	rec := mapOne(t, fxStart)
	rec2 := mapOne(t, fxOOMReport)
	rec2.Attrs = append(rec2.Attrs, lambdaext.Attr{Key: "n", Kind: lambdaext.KindInt, Int: -7})
	payload := lambdaext.EncodeLogs(lambdaext.Resource(func(k string) string {
		return map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "billing", "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": "128"}[k]
	}), []*lambdaext.LogRecord{rec, rec2})
	var req collogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		t.Fatal(err)
	}
	rl := req.ResourceLogs[0]
	if wireAttrs(rl.Resource.Attributes)["faas.name"] != "billing" || wireAttrs(rl.Resource.Attributes)["faas.max_memory"] != int64(128<<20) {
		t.Fatalf("resource %v", rl.Resource.Attributes)
	}
	got := rl.ScopeLogs[0].LogRecords
	if len(got) != 2 {
		t.Fatalf("records %d", len(got))
	}
	g := got[0]
	if g.TimeUnixNano != rec.TimeUnixNano || g.ObservedTimeUnixNano != rec.ObservedTimeUnixNano ||
		g.SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_INFO || g.SeverityText != "INFO" ||
		g.Body.GetStringValue() != rec.Body || g.Flags != 1 ||
		hex.EncodeToString(g.TraceId) != "5759e988bd862e3fe1be46a994272793" || hex.EncodeToString(g.SpanId) != "54565fb41ac79632" {
		t.Fatalf("record %v", g)
	}
	if g := got[1]; g.SeverityText != "ERROR" || wireAttrs(g.Attributes)["n"] != int64(-7) ||
		wireAttrs(g.Attributes)["maxMemoryUsedMB"] != 128.0 || g.TraceId != nil {
		t.Fatalf("record %v", g)
	}
}
