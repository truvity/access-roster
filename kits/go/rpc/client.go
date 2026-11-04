package rpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"

	"connectrpc.com/connect"
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

// ClientOptions returns the options of every generated New<Service>Client: the correlation id of the context goes
// out in the header of the call, and a unary call without a deadline gets the default one. The deadline of a
// context is sent by Connect itself (Connect-Timeout-Ms), so a callee sees what is left of its caller's.
func ClientOptions() []connect.ClientOption {
	return []connect.ClientOption{
		connect.WithInterceptors(clientInterceptor{}, DefaultDeadline(DefaultDeadlineValue)),
	}
}

type clientInterceptor struct{}

func (clientInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if id := CorrelationID(ctx); id != "" {
			req.Header().Set(HeaderCorrelation, id)
		}
		return next(ctx, req)
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
