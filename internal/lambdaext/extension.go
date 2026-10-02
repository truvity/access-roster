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
	"os"
	"path/filepath"
	"time"
)

// Client speaks the Lambda Extensions API.
type Client struct {
	// Base is http://${AWS_LAMBDA_RUNTIME_API}.
	Base string
	HTTP *http.Client
	id   string
}

// Event is what /event/next returns.
type Event struct {
	EventType  string `json:"eventType"`
	DeadlineMs int64  `json:"deadlineMs"`
}

// Register announces the extension. name must be the executable's file name.
func (c *Client) Register(ctx context.Context, name string) error {
	body := []byte(`{"events":["INVOKE","SHUTDOWN"]}`)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/2020-01-01/extension/register", bytes.NewReader(body))
	req.Header.Set("Lambda-Extension-Name", name)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: %s", resp.Status)
	}
	c.id = resp.Header.Get("Lambda-Extension-Identifier")
	if c.id == "" {
		return errors.New("register: no Lambda-Extension-Identifier")
	}
	return nil
}

// Next blocks until the next event; the platform imposes no timeout.
func (c *Client) Next(ctx context.Context) (Event, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/2020-01-01/extension/event/next", nil)
	req.Header.Set("Lambda-Extension-Identifier", c.id)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Event{}, fmt.Errorf("next: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Event{}, fmt.Errorf("next: %s", resp.Status)
	}
	var ev Event
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ev); err != nil {
		return Event{}, fmt.Errorf("next: %w", err)
	}
	return ev, nil
}

// Options are what Run needs from outside, so a test can drive the same
// code the binary runs.
type Options struct {
	Getenv func(string) string
	Logf   func(format string, args ...any)
	// Name is the registered extension name.
	Name string
}

// Run is the extension: register, serve the proxy, and loop on events until
// SHUTDOWN. It never fails the function: a misconfiguration or a failed bind
// is logged and the extension keeps answering the platform, because an
// extension that exits is reported by Lambda as a crash of the invocation.
func Run(ctx context.Context, opt Options) error {
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	logf := opt.Logf
	api := opt.Getenv("AWS_LAMBDA_RUNTIME_API")
	if api == "" {
		return errors.New("AWS_LAMBDA_RUNTIME_API is not set: not running inside Lambda")
	}
	client := &Client{Base: "http://" + api, HTTP: &http.Client{}}
	if err := client.Register(ctx, opt.Name); err != nil {
		return err
	}

	source, srv, cfg, err := start(ctx, opt)
	if err != nil {
		logf("access-roster-otlp: running without telemetry forwarding: %v", err)
	}
	var tele *teleServer
	if source != nil {
		tele = startTelemetry(ctx, client, opt, cfg, source)
	}
	return loop(ctx, client, source, srv, tele)
}

// start configures the token source and binds the proxy. When it fails the
// extension still runs (see Run) and the function's exports find nothing
// listening, which an OTLP exporter treats as a retryable failure.
func start(ctx context.Context, opt Options) (*Source, *http.Server, Config, error) {
	cfg, err := LoadConfig(opt.Getenv)
	if err != nil {
		return nil, nil, cfg, err
	}
	stsAPI, err := NewSTS(ctx)
	if err != nil {
		return nil, nil, cfg, err
	}
	source := &Source{
		Subject:  SubjectFunc(stsAPI, cfg),
		Exchange: ExchangeFunc(cfg, nil),
		Logf:     opt.Logf,
	}
	if cfg.TokenFile != "" {
		source.OnToken = func(token string) {
			if err := writeTokenFile(cfg.TokenFile, token); err != nil {
				opt.Logf("access-roster-otlp: write the token file: %v", err)
			}
		}
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, nil, cfg, fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	srv := &http.Server{
		Handler:           &Proxy{Upstream: cfg.Endpoint, Tokens: source, Logf: opt.Logf},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	// Warm the token while the runtime initialises; the first export waits
	// on the same single flight if it arrives first.
	go source.Warm(ctx)
	return source, srv, cfg, nil
}

// writeTokenFile replaces path atomically with mode 0600, for users who run
// their own collector with a bearer-token-from-file extension.
func writeTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.WriteString(token); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func loop(ctx context.Context, client *Client, source *Source, srv *http.Server, tele *teleServer) error {
	for {
		// The environment may freeze as soon as this extension asks for the
		// next event, so what the platform has delivered goes out first.
		tele.flush(ctx, flushBudget)
		ev, err := client.Next(ctx)
		if err != nil {
			shutdown(srv, 0)
			tele.close(0)
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch ev.EventType {
		case "INVOKE":
			if source != nil {
				go source.Warm(ctx)
			}
		case "SHUTDOWN":
			wait := time.Until(time.UnixMilli(ev.DeadlineMs)) - 200*time.Millisecond
			tele.flush(ctx, max(wait/2, 0))
			shutdown(srv, wait)
			tele.close(wait)
			return nil
		}
	}
}

func shutdown(srv *http.Server, wait time.Duration) {
	if srv == nil {
		return
	}
	wait = max(wait, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if srv.Shutdown(ctx) != nil {
		_ = srv.Close()
	}
}

// flushBudget bounds the pre-freeze export of queued telemetry logs.
const flushBudget = 2 * time.Second

// teleServer is the Telemetry API listener and its exporter; a nil
// *teleServer is "not subscribed" and every method is a no-op.
type teleServer struct {
	tele *Telemetry
	srv  *http.Server
}

// startTelemetry subscribes to the Telemetry API. Every failure is logged
// and leaves the extension running without it.
func startTelemetry(ctx context.Context, client *Client, opt Options, cfg Config, tokens Tokens) *teleServer {
	tc, err := LoadTelemetryConfig(opt.Getenv)
	if err != nil {
		opt.Logf("access-roster-otlp: Lambda telemetry logs are off: %v", err)
		return nil
	}
	if !tc.Enabled() {
		return nil
	}
	tele := &Telemetry{
		Upstream: cfg.Endpoint, Tokens: tokens, Resource: Resource(opt.Getenv),
		Logf: opt.Logf, QueueItems: tc.QueueItems,
	}
	ln, err := net.Listen("tcp", tc.bindAddr())
	if err != nil {
		opt.Logf("access-roster-otlp: Lambda telemetry logs are off: listen on %s: %v", tc.Listen, err)
		return nil
	}
	srv := &http.Server{Handler: tele, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	if err = client.Subscribe(ctx, tc); err != nil {
		opt.Logf("access-roster-otlp: Lambda telemetry logs are off: %v", err)
		_ = srv.Close()
		return nil
	}
	return &teleServer{tele: tele, srv: srv}
}

func (s *teleServer) flush(ctx context.Context, budget time.Duration) {
	if s == nil || budget <= 0 {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	_ = s.tele.Flush(fctx)
}

// close stops the listener, then exports what its last batches brought.
func (s *teleServer) close(wait time.Duration) {
	if s == nil {
		return
	}
	shutdown(s.srv, wait/2)
	if wait > 0 {
		fctx, cancel := context.WithTimeout(context.Background(), wait/2)
		defer cancel()
		_ = s.tele.Flush(fctx)
	}
}
