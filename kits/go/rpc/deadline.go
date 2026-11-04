package rpc

import (
	"context"
	"time"

	"connectrpc.com/connect"
)

// DefaultDeadlineValue is the deadline a call gets when it carries none and the server or client names no other
// (contracts.md, "Every call": every call carries a deadline).
const DefaultDeadlineValue = 30 * time.Second

// DeadlineDefault gives a call without a deadline one. A zero value gives nothing.
type DeadlineDefault struct{ d time.Duration }

func (dd DeadlineDefault) apply(ctx context.Context) (context.Context, context.CancelFunc) {
	if dd.d <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, dd.d)
}

// DefaultDeadline returns an interceptor that gives a call without a deadline d. A call that has one keeps it:
// a callee never extends its caller's deadline (contracts.md, "Every call"). On a handler it covers unary and
// streaming methods; on a client it covers unary calls, because the lifetime of a stream is the caller's.
func DefaultDeadline(d time.Duration) connect.Interceptor {
	return deadlineInterceptor{DeadlineDefault{d}}
}

type deadlineInterceptor struct{ dd DeadlineDefault }

func (i deadlineInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, cancel := i.dd.apply(ctx)
		defer cancel()
		return next(ctx, req)
	}
}

func (i deadlineInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i deadlineInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, cancel := i.dd.apply(ctx)
		defer cancel()
		return next(ctx, conn)
	}
}
