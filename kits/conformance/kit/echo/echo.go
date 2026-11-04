// Package echo is the Go side of the cross-language conformance test of the kits (rule R9 of ADR 0012): an
// EchoService server, and a client that checks a server of either language. It is test-only and no product
// binary links it.
//
// The Rust kit has the same service. The test is: the Go client against the Rust server, and the Rust client
// against the Go server, over a Unix socket, with one unary call, one server stream of 50 messages in order, and
// a refusal whose Refusal detail survives the hop.
package echo

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	conformancev2alpha1 "github.com/truvity/sluis/v2/kits/conformance/kit/gen/go/sluis/conformance/v2alpha1"
	"github.com/truvity/sluis/v2/kits/conformance/kit/gen/go/sluis/conformance/v2alpha1/conformancev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// MaxCount is the largest n a Count call accepts.
const MaxCount = 1000

// Server implements EchoService.
type Server struct {
	conformancev2alpha1connect.UnimplementedEchoServiceHandler
}

// Handler returns the handler of the service for rpc.Serve, with the kit's options.
func Handler(cfg rpc.ServerConfig) rpc.Handler {
	path, h := conformancev2alpha1connect.NewEchoServiceHandler(Server{}, rpc.HandlerOptions(cfg)...)
	return rpc.Handler{Path: path, H: h}
}

// Echo returns the message with what the server saw of the call.
func (Server) Echo(ctx context.Context, req *connect.Request[conformancev2alpha1.EchoRequest]) (*connect.Response[conformancev2alpha1.EchoResponse], error) {
	res := &conformancev2alpha1.EchoResponse{
		Message:       req.Msg.GetMessage(),
		CorrelationId: rpc.CorrelationID(ctx),
	}
	if p, ok := rpc.PeerFromContext(ctx); ok {
		res.Caller = p.Name
	}
	if dl, ok := ctx.Deadline(); ok {
		res.TimeoutMs = max(time.Until(dl).Milliseconds(), 1)
	}
	return connect.NewResponse(res), nil
}

// Count streams n numbered messages.
func (Server) Count(_ context.Context, req *connect.Request[conformancev2alpha1.CountRequest], stream *connect.ServerStream[conformancev2alpha1.CountResponse]) error {
	n := req.Msg.GetN()
	if n < 0 || n > MaxCount {
		return refusal.New(connect.CodeInvalidArgument, "count", "n")
	}
	for i := int32(1); i <= n; i++ {
		if err := stream.Send(&conformancev2alpha1.CountResponse{Seq: i}); err != nil {
			return err
		}
	}
	return nil
}

// Refuse fails with the refusal it is asked for.
func (Server) Refuse(_ context.Context, req *connect.Request[conformancev2alpha1.RefuseRequest]) (*connect.Response[conformancev2alpha1.RefuseResponse], error) {
	var code connect.Code
	if err := code.UnmarshalText([]byte(req.Msg.GetCode())); err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "code", "code")
	}
	return nil, refusal.New(code, req.Msg.GetReason(), req.Msg.GetFieldPath())
}

// Call checks the server on socket, whatever language it is written in, and returns the first difference.
func Call(ctx context.Context, socket string) error {
	hc, url := rpc.Dial(socket)
	c := conformancev2alpha1connect.NewEchoServiceClient(hc, url, rpc.ClientOptions()...)

	// Unary: the message, the correlation id and the deadline cross the hop.
	const id = "conformance-0001"
	cctx, cancel := context.WithTimeout(rpc.WithCorrelationID(ctx, id), 10*time.Second)
	defer cancel()
	res, err := c.Echo(cctx, connect.NewRequest(&conformancev2alpha1.EchoRequest{Message: "hello"}))
	if err != nil {
		return fmt.Errorf("echo: %w", err)
	}
	if res.Msg.GetMessage() != "hello" {
		return fmt.Errorf("echo: message %q", res.Msg.GetMessage())
	}
	if res.Msg.GetCorrelationId() != id {
		return fmt.Errorf("echo: correlation id %q, want %q", res.Msg.GetCorrelationId(), id)
	}
	if ms := res.Msg.GetTimeoutMs(); ms <= 0 || ms > 10_000 {
		return fmt.Errorf("echo: deadline %d ms, want within (0, 10000]", ms)
	}

	// Server stream: 50 messages, in order.
	stream, err := c.Count(ctx, connect.NewRequest(&conformancev2alpha1.CountRequest{N: 50}))
	if err != nil {
		return fmt.Errorf("count: %w", err)
	}
	var next int32 = 1
	for stream.Receive() {
		if got := stream.Msg().GetSeq(); got != next {
			return fmt.Errorf("count: message %d came as %d", next, got)
		}
		next++
	}
	if err := stream.Err(); err != nil {
		return fmt.Errorf("count: %w", err)
	}
	if next != 51 {
		return fmt.Errorf("count: %d messages, want 50", next-1)
	}

	// Refusal: the code and the Refusal detail survive.
	_, err = c.Refuse(ctx, connect.NewRequest(&conformancev2alpha1.RefuseRequest{
		Code: "failed_precondition", Reason: "bound", FieldPath: "a.b",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		return fmt.Errorf("refuse: code %v, want failed_precondition", connect.CodeOf(err))
	}
	if r, ok := refusal.Reason(err); !ok || r != "bound" {
		return fmt.Errorf("refuse: reason %q (%v), want bound", r, ok)
	}
	if p, ok := refusal.FieldPath(err); !ok || p != "a.b" {
		return fmt.Errorf("refuse: field path %q (%v), want a.b", p, ok)
	}
	return nil
}
