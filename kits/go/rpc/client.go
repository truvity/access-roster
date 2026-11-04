package rpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// baseURL is the URL base of a client over a Unix socket; the host is not used.
const baseURL = "http://unix"

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// Dial returns an HTTP client for the Unix socket, speaking h2c, and the base URL to give the generated
// New<Service>Client. Use it with ClientOptions():
//
//	hc, url := rpc.Dial(socket)
//	c := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
func Dial(socket string) (connect.HTTPClient, string) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		Protocols:       clientProtocols(),
		IdleConnTimeout: 90 * time.Second,
	}
	return &http.Client{Transport: tr}, baseURL
}

// ClientSetting adjusts ClientOptions.
type ClientSetting func(*clientSettings)

type clientSettings struct{ readMax int }

// WithReadMax sets the largest response message the client reads, in place of the default (4 MiB, the largest
// message of the contracts is far below). It is for a caller of a contract that returns large records and knows its
// bound; there are no caps per method.
func WithReadMax(n int) ClientSetting { return func(c *clientSettings) { c.readMax = n } }

// ClientOptions returns the options of every generated New<Service>Client: the correlation id of the context goes
// out in the header of the call, a unary call without a deadline gets the default one, and a response over the read
// limit is refused (the peer may be the adversary: key@ reads a signed document from store@, and no reader buffers
// without bound). The deadline of a context is sent by Connect itself (Connect-Timeout-Ms), so a callee sees what is
// left of its caller's.
func ClientOptions(settings ...ClientSetting) []connect.ClientOption {
	c := clientSettings{readMax: readMaxBytes}
	for _, f := range settings {
		f(&c)
	}
	return []connect.ClientOption{
		connect.WithInterceptors(clientInterceptor{}, DefaultDeadline(DefaultDeadlineValue)),
		connect.WithReadMaxBytes(c.readMax),
	}
}

// oversize reports the error that Connect makes when a response is over the read limit. It has no Refusal detail, which
// every refusal of a sluis peer carries, so it cannot be a peer's own resource_exhausted.
func oversize(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeResourceExhausted || len(ce.Details()) != 0 {
		return false
	}
	return strings.Contains(ce.Message(), "larger than configured max")
}

type clientInterceptor struct{}

func (clientInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if id := CorrelationID(ctx); id != "" {
			req.Header().Set(HeaderCorrelation, id)
		}
		res, err := next(ctx, req)
		if oversize(err) {
			// resource_exhausted is a quota or a rate limit with Retry-After (contracts.md, "Errors"); a response that
			// is too large to read is no such thing and must not be retried or mapped to RATE_LIMITED. It is the
			// peer's fault: internal.
			return nil, refusal.New(connect.CodeInternal, "schema", "response")
		}
		return res, err
	}
}

func (clientInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		if id := CorrelationID(ctx); id != "" {
			conn.RequestHeader().Set(HeaderCorrelation, id)
		}
		return conn
	}
}

func (clientInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
