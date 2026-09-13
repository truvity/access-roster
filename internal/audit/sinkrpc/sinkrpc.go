// Package sinkrpc joins what records audit events to what writes them
// down, in the same process.
//
// The contract between the two is the generated AuditSinkService: a writer
// implements its handler and everything that records holds its client.
// Across processes the generated client over HTTP is the join, and needs
// nothing from here. Within one process there is no reason to pay for a
// network or an encoding, and this is the join instead: a client that
// calls a handler directly.
//
// It behaves as the network would in the one way that matters to a
// caller: the handler receives its own copy of the request and the caller
// its own copy of the answer, so neither can change what the other holds
// afterwards. A writer that queued a request's events and a producer that
// reused the message would otherwise share them.
package sinkrpc

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
)

// InProcess is a client of a writer in this process.
func InProcess(handler directoryrosterv1connect.AuditSinkServiceHandler) directoryrosterv1connect.AuditSinkServiceClient {
	return inProcess{handler: handler}
}

type inProcess struct {
	handler directoryrosterv1connect.AuditSinkServiceHandler
}

// WriteAuditEvents implements the AuditSinkService client.
func (p inProcess) WriteAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.WriteAuditEventsRequest],
) (*connect.Response[directoryrosterv1.WriteAuditEventsResponse], error) {
	return call(ctx, req, p.handler.WriteAuditEvents)
}

// ListStoredAuditEvents implements the AuditSinkService client.
func (p inProcess) ListStoredAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListStoredAuditEventsRequest],
) (*connect.Response[directoryrosterv1.ListStoredAuditEventsResponse], error) {
	return call(ctx, req, p.handler.ListStoredAuditEvents)
}

// call hands a copy of the request to the handler and a copy of its answer
// back.
func call[Req, Res any, ReqMsg interface {
	*Req
	proto.Message
}, ResMsg interface {
	*Res
	proto.Message
}](
	ctx context.Context,
	req *connect.Request[Req],
	handle func(context.Context, *connect.Request[Req]) (*connect.Response[Res], error),
) (*connect.Response[Res], error) {
	copied := connect.NewRequest(proto.Clone(ReqMsg(req.Msg)).(ReqMsg))
	for name, values := range req.Header() {
		copied.Header()[name] = append([]string(nil), values...)
	}
	res, err := handle(ctx, copied)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(proto.Clone(ResMsg(res.Msg)).(ResMsg)), nil
}
