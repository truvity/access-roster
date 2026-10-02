package lambdaext

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Telemetry API settings and their AWS-documented bounds.
const (
	EnvPlatformLogs     = "ACCESS_ROSTER_PLATFORM_LOGS"
	EnvFunctionLogs     = "ACCESS_ROSTER_FUNCTION_LOGS"
	EnvExtensionLogs    = "ACCESS_ROSTER_EXTENSION_LOGS"
	EnvTelemetryListen  = "ACCESS_ROSTER_TELEMETRY_LISTEN"
	EnvBufferMaxItems   = "ACCESS_ROSTER_TELEMETRY_BUFFER_MAX_ITEMS"
	EnvBufferMaxBytes   = "ACCESS_ROSTER_TELEMETRY_BUFFER_MAX_BYTES"
	EnvBufferTimeoutMs  = "ACCESS_ROSTER_TELEMETRY_BUFFER_TIMEOUT_MS"
	EnvBufferQueueItems = "ACCESS_ROSTER_TELEMETRY_BUFFER_QUEUE_ITEMS"

	telemetryAPIPath    = "/2022-07-01/telemetry"
	telemetrySchema     = "2022-12-13"
	defaultTelemetryAdr = "sandbox.localdomain:4243"
	// maxTelemetryBody bounds one POST from the platform; AWS batches are at
	// most 1 MiB.
	maxTelemetryBody = 4 << 20
	// exportBatch is the most records one OTLP export carries.
	exportBatch = 500
)

// TelemetryConfig is the Telemetry API part of the settings.
type TelemetryConfig struct {
	// Platform, Function and Extension select the log types subscribed to.
	Platform, Function, Extension bool
	// Listen is where the platform POSTs batches; the Destination URI is
	// derived from it.
	Listen string
	// MaxItems, MaxBytes and TimeoutMs are the platform's buffering
	// (AWS bounds: 1000..10000, 262144..1048576, 25..30000).
	MaxItems, MaxBytes, TimeoutMs int
	// QueueItems bounds the records held here waiting for an export; beyond
	// it the oldest are dropped and counted.
	QueueItems int
}

// Enabled reports whether any log type is subscribed to.
func (c TelemetryConfig) Enabled() bool { return c.Platform || c.Function || c.Extension }

// bindAddr is where the listener binds. In Lambda sandbox.localdomain is the
// name the platform delivers to; it does not resolve anywhere else (and
// binding the name instead of the wildcard would fail there), so it binds
// every interface of the single-tenant sandbox on that port.
func (c TelemetryConfig) bindAddr() string {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || host != "sandbox.localdomain" {
		return c.Listen
	}
	return net.JoinHostPort("0.0.0.0", port)
}

func (c TelemetryConfig) types() []string {
	var t []string
	if c.Platform {
		t = append(t, "platform")
	}
	if c.Function {
		t = append(t, "function")
	}
	if c.Extension {
		t = append(t, "extension")
	}
	return t
}

// LoadTelemetryConfig reads the Telemetry API settings; the error names
// every invalid one.
func LoadTelemetryConfig(getenv func(string) string) (TelemetryConfig, error) {
	c := TelemetryConfig{
		Platform: true, Listen: defaultTelemetryAdr,
		MaxItems: 1000, MaxBytes: 262144, TimeoutMs: 1000, QueueItems: 5000,
	}
	var problems []error
	flag := func(name string, dst *bool) {
		if raw := getenv(name); raw != "" {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				problems = append(problems, fmt.Errorf("%s must be true or false, got %q", name, raw))
				return
			}
			*dst = v
		}
	}
	number := func(name string, dst *int, lo, hi int) {
		if raw := getenv(name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < lo || n > hi {
				problems = append(problems, fmt.Errorf("%s must be %d..%d, got %q", name, lo, hi, raw))
				return
			}
			*dst = n
		}
	}
	flag(EnvPlatformLogs, &c.Platform)
	flag(EnvFunctionLogs, &c.Function)
	flag(EnvExtensionLogs, &c.Extension)
	if v := getenv(EnvTelemetryListen); v != "" {
		c.Listen = v
	}
	number(EnvBufferMaxItems, &c.MaxItems, 1000, 10000)
	number(EnvBufferMaxBytes, &c.MaxBytes, 262144, 1048576)
	number(EnvBufferTimeoutMs, &c.TimeoutMs, 25, 30000)
	number(EnvBufferQueueItems, &c.QueueItems, 100, 1000000)
	return c, errors.Join(problems...)
}

// Subscribe asks the Telemetry API to POST batches to cfg.Listen. The
// listener must already be accepting.
func (c *Client) Subscribe(ctx context.Context, cfg TelemetryConfig) error {
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": telemetrySchema,
		"types":         cfg.types(),
		"buffering":     map[string]int{"timeoutMs": cfg.TimeoutMs, "maxBytes": cfg.MaxBytes, "maxItems": cfg.MaxItems},
		"destination":   map[string]string{"protocol": "HTTP", "URI": "http://" + cfg.Listen},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, c.Base+telemetryAPIPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Lambda-Extension-Identifier", c.id)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry subscribe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telemetry subscribe: %s %s", resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

// Telemetry receives the platform's batches, keeps them in a bounded queue
// and exports them as OTLP logs to the same upstream as the proxy, with the
// same token source. It is fail-open: a record that cannot be exported is
// dropped, never retried into the next invocation's way.
type Telemetry struct {
	// Upstream is the OTLP base URL; Tokens the shared token source.
	Upstream string
	Tokens   Tokens
	Resource []Attr
	Client   *http.Client
	Logf     func(format string, args ...any)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// QueueItems bounds the queue; zero is 5000.
	QueueItems int
	// TokenTimeout bounds waiting for a token; zero is 5 seconds.
	TokenTimeout time.Duration

	mu      sync.Mutex
	queue   []*LogRecord
	dropped int
	failing bool
	sem     chan struct{}
}

func (t *Telemetry) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Telemetry) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	}
}

func (t *Telemetry) init() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sem == nil {
		t.sem = make(chan struct{}, 1)
	}
}

// Enqueue adds records, dropping the oldest beyond QueueItems.
func (t *Telemetry) Enqueue(recs []*LogRecord) {
	limit := t.QueueItems
	if limit <= 0 {
		limit = 5000
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.queue = append(t.queue, recs...)
	if over := len(t.queue) - limit; over > 0 {
		t.dropped += over
		t.queue = append([]*LogRecord(nil), t.queue[over:]...)
	}
}

// Dropped is how many records the bound has discarded and no export has
// reported yet.
func (t *Telemetry) Dropped() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dropped
}

// ServeHTTP is the Telemetry API destination.
func (t *Telemetry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTelemetryBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var events []TelemetryEvent
	if err = json.Unmarshal(body, &events); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := t.now()
	recs := make([]*LogRecord, 0, len(events))
	for _, ev := range events {
		if rec, ok := MapEvent(ev, now); ok {
			recs = append(recs, rec)
		}
	}
	t.Enqueue(recs)
	w.WriteHeader(http.StatusOK)
	// Export in the background so the platform's POST is answered at once;
	// the extension's own loop flushes before it lets the environment freeze.
	go func() { _ = t.Flush(context.Background()) }()
}

// Flush exports everything queued, in batches, until the queue is empty or
// ctx ends. Only one flush runs at a time; a second waits for it.
func (t *Telemetry) Flush(ctx context.Context) error {
	t.init()
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		batch, dropped := t.take()
		if len(batch) == 0 {
			return nil
		}
		if dropped > 0 {
			batch = append([]*LogRecord{t.droppedRecord(dropped)}, batch...)
		}
		if err := t.send(ctx, batch); err != nil {
			t.mu.Lock()
			first := !t.failing
			t.failing = true
			t.mu.Unlock()
			if first {
				t.logf("access-roster-otlp: dropping Lambda telemetry logs, the export failed: %v", err)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue // the batch is gone; carry on with what is queued
		}
		t.mu.Lock()
		recovered := t.failing
		t.failing = false
		t.mu.Unlock()
		if recovered {
			t.logf("access-roster-otlp: exporting Lambda telemetry logs again")
		}
	}
}

func (t *Telemetry) take() ([]*LogRecord, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := min(len(t.queue), exportBatch)
	batch := append([]*LogRecord(nil), t.queue[:n]...)
	t.queue = t.queue[n:]
	dropped := t.dropped
	t.dropped = 0
	return batch, dropped
}

func (t *Telemetry) droppedRecord(n int) *LogRecord {
	now := uint64(t.now().UnixNano()) //nolint:gosec // a post-1970 time
	rec := &LogRecord{
		TimeUnixNano: now, ObservedTimeUnixNano: now, Severity: SeverityWarn,
		Body:  fmt.Sprintf("access-roster-otlp dropped %d Lambda telemetry records: the queue was full", n),
		Attrs: []Attr{strAttr("event.name", "access_roster.telemetry.dropped"), intAttr("droppedRecords", int64(n))},
	}
	return rec
}

func (t *Telemetry) send(ctx context.Context, recs []*LogRecord) error {
	payload := EncodeLogs(t.Resource, recs)
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	timeout := t.TokenTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	for attempt := range 2 {
		tctx, cancel := context.WithTimeout(ctx, timeout)
		token, err := t.Tokens.Token(tctx)
		cancel()
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Upstream+"/v1/logs", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode/100 == 2:
			return nil
		case resp.StatusCode == http.StatusUnauthorized && attempt == 0:
			t.Tokens.Invalidate(token)
		default:
			return fmt.Errorf("upstream answered %s", resp.Status)
		}
	}
	return errors.New("upstream refused the token")
}
