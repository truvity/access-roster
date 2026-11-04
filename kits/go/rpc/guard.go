package rpc

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The reasons of the two refusals the guard makes (docs/reference/contracts.md, "Errors").
const (
	reasonCaller    = "caller"     // no peer, or a uid the registry does not know, or another boundary's uid block
	reasonCallGraph = "call_graph" // a known caller that the call graph does not allow
)

// guard is the default-deny check of one server: who is the caller, and may it make this call.
type guard struct {
	actor string
	block uint32
	allow func(Peer, string) bool
}

func newGuard(cfg ServerConfig) guard {
	g := guard{actor: cfg.Actor, block: cfg.UIDBlock, allow: cfg.Allow}
	if g.allow == nil {
		g.allow = func(p Peer, _ string) bool { return registry.MayCall(p.Name, cfg.Actor) }
	}
	return g
}

// check returns nil when the caller of ctx may call procedure, and the refusal otherwise. It looks at the
// transport only: ctx carries the credentials the server read from the socket.
func (g guard) check(ctx context.Context, procedure string) *connect.Error {
	cp, _ := ctx.Value(peerKey{}).(connPeer)
	if !cp.known || cp.UIDBlock != g.block {
		g.logRefused(reasonCaller, cp, procedure)
		return refusal.New(connect.CodePermissionDenied, reasonCaller, "")
	}
	if !g.allow(cp.Peer, procedure) {
		g.logRefused(reasonCallGraph, cp, procedure)
		return refusal.New(connect.CodePermissionDenied, reasonCallGraph, "")
	}
	return nil
}

// logRefused logs the refusal at Info with the caller and the procedure, never the payload.
func (g guard) logRefused(reason string, cp connPeer, procedure string) {
	slog.Info("call refused",
		"reason", reason, "actor", g.actor, "procedure", procedure,
		"caller", cp.Name, "uid", cp.UID, "pid", cp.PID)
}

// interceptor is the Connect interceptor of every procedure: the same check as the guard's, the correlation id
// from the request header, and the default deadline. The server runs the check before the message is decoded
// (see denyHandlers); this one is the second lock for a handler that is mounted another way.
type interceptor struct {
	guard    guard
	deadline DeadlineDefault
}

func (i interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.guard.check(ctx, req.Spec().Procedure); err != nil {
			return nil, err
		}
		ctx = WithCorrelationID(ctx, correlationFrom(req.Header()))
		ctx, cancel := i.deadline.apply(ctx)
		defer cancel()
		res, err := next(ctx, req)
		if res != nil {
			if id := CorrelationID(ctx); id != "" {
				res.Header().Set(HeaderCorrelation, id)
			}
		}
		return res, err
	}
}

func (i interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.guard.check(ctx, conn.Spec().Procedure); err != nil {
			return err
		}
		ctx = WithCorrelationID(ctx, correlationFrom(conn.RequestHeader()))
		if id := CorrelationID(ctx); id != "" {
			conn.ResponseHeader().Set(HeaderCorrelation, id)
		}
		ctx, cancel := i.deadline.apply(ctx)
		defer cancel()
		return next(ctx, conn)
	}
}

// denyHandlers answer a refused call without decoding it. A Connect handler decodes a unary message before any
// interceptor runs, so the server checks the caller first, at the HTTP layer, and hands a refused call to a
// handler whose codec decodes nothing and whose body is empty, so that the answer has the right shape for the
// protocol (Connect unary, Connect stream, gRPC) and no byte of the request is parsed.
type denyHandlers struct {
	unary, stream http.Handler
}

type denyKey struct{}

// discardCodec decodes nothing and encodes nothing.
type discardCodec struct{ name string }

func (c discardCodec) Name() string              { return c.name }
func (discardCodec) Marshal(any) ([]byte, error) { return nil, nil }
func (discardCodec) Unmarshal([]byte, any) error { return nil }

func newDenyHandlers() denyHandlers {
	failure := func(ctx context.Context) error {
		err, _ := ctx.Value(denyKey{}).(*connect.Error)
		if err == nil {
			err = refusal.New(connect.CodePermissionDenied, reasonCaller, "")
		}
		return err
	}
	opts := []connect.HandlerOption{
		connect.WithCodec(discardCodec{"proto"}),
		connect.WithCodec(discardCodec{"json"}),
	}
	unary := connect.NewUnaryHandler("/deny", func(ctx context.Context, _ *connect.Request[struct{}]) (*connect.Response[struct{}], error) {
		return nil, failure(ctx)
	}, opts...)
	stream := connect.NewBidiStreamHandler("/deny", func(ctx context.Context, _ *connect.BidiStream[struct{}, struct{}]) error {
		return failure(ctx)
	}, opts...)
	return denyHandlers{unary: unary, stream: stream}
}

// serve answers r with the refusal err. A Connect unary request is the only shape that needs the unary handler;
// the streaming and gRPC shapes are answered by the stream handler, which never reads the body.
func (d denyHandlers) serve(w http.ResponseWriter, r *http.Request, err *connect.Error) {
	r = r.WithContext(context.WithValue(r.Context(), denyKey{}, err))
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "application/connect+") || strings.HasPrefix(ct, "application/grpc") {
		d.stream.ServeHTTP(w, r)
		return
	}
	r.Body = http.NoBody
	d.unary.ServeHTTP(w, r)
}

// middleware refuses a call before its handler, and so before its message, is reached.
func (g guard) middleware(d denyHandlers, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := g.check(r.Context(), r.URL.Path); err != nil {
			d.serve(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}
