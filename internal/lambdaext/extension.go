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

	source, srv, err := start(ctx, opt)
	if err != nil {
		logf("access-roster-otlp: running without telemetry forwarding: %v", err)
	}
	return loop(ctx, client, source, srv)
}

// start configures the token source and binds the proxy. When it fails the
// extension still runs (see Run) and the function's exports find nothing
// listening, which an OTLP exporter treats as a retryable failure.
func start(ctx context.Context, opt Options) (*Source, *http.Server, error) {
	cfg, err := LoadConfig(opt.Getenv)
	if err != nil {
		return nil, nil, err
	}
	stsAPI, err := NewSTS(ctx)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	srv := &http.Server{
		Handler:           &Proxy{Upstream: cfg.Endpoint, Tokens: source, Logf: opt.Logf},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	// Warm the token while the runtime initialises; the first export waits
	// on the same single flight if it arrives first.
	go source.Warm(ctx)
	return source, srv, nil
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

func loop(ctx context.Context, client *Client, source *Source, srv *http.Server) error {
	for {
		ev, err := client.Next(ctx)
		if err != nil {
			shutdown(srv, 0)
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
			shutdown(srv, wait)
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
