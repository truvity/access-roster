// Command probe is the test code of the deny matrix (WP-29). It runs in a container as the uid and the groups of one
// caller, with every socket directory of the installation mounted read-only, and makes one call to each target it is
// given. It says for each where the call ended: refused at the socket, refused by the guard, or past the guard.
//
// It is test code and never part of a product binary. The call is a unary Connect call of a read-only procedure with an
// empty request, through the kit's own dialer, so the callee sees what it sees from a real caller: the peer uid.
//
//	probe '<json array of spec.Target>'   writes a JSON array of spec.Result
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/tests/deny/internal/spec"
)

const callTimeout = 8 * time.Second

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "probe: one argument, the targets as JSON")
		os.Exit(2)
	}
	var targets []spec.Target
	if err := json.Unmarshal([]byte(os.Args[1]), &targets); err != nil {
		fmt.Fprintln(os.Stderr, "probe: the targets:", err)
		os.Exit(2)
	}
	out := make([]spec.Result, 0, len(targets))
	for _, t := range targets {
		out = append(out, probe(t))
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func probe(t spec.Target) spec.Result {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var err error
	switch t.Kind {
	case spec.Connect:
		err = callConnect(ctx, t)
	case spec.HTTP:
		return probeHTTP(ctx, t)
	default:
		return spec.Result{ID: t.ID, Outcome: spec.Broken, Detail: "unknown kind " + string(t.Kind)}
	}
	return classify(t.ID, err)
}

func callConnect(ctx context.Context, t spec.Target) error {
	hc, base := rpc.Dial(t.Socket)
	c := connect.NewClient[emptypb.Empty, emptypb.Empty](hc, base+t.Procedure, rpc.ClientOptions()...)
	_, err := c.CallUnary(ctx, connect.NewRequest(&emptypb.Empty{}))
	return err
}

// classify turns the error of a call into an outcome. A refusal is read from its Refusal detail, never from a message.
func classify(id string, err error) spec.Result {
	r := spec.Result{ID: id}
	switch {
	case err == nil:
		r.Outcome, r.Detail = spec.Reached, "ok"
	case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
		r.Outcome, r.Detail = spec.Socket, "EACCES"
	case errors.Is(err, syscall.ENOENT):
		r.Outcome, r.Detail = spec.Broken, "ENOENT: no such socket"
	case errors.Is(err, syscall.ECONNREFUSED):
		r.Outcome, r.Detail = spec.Broken, "ECONNREFUSED: nobody listens"
	default:
		code := connect.CodeOf(err)
		reason, _ := refusal.Reason(err)
		switch {
		case code == connect.CodePermissionDenied && (reason == "call_graph" || reason == "caller"):
			r.Outcome, r.Detail = spec.Guard, reason
		case code == connect.CodeUnavailable:
			r.Outcome, r.Detail = spec.Broken, "unavailable: "+reasonOrCode(reason, code)
		case code == connect.CodeUnknown:
			r.Outcome, r.Detail = spec.Broken, "not a Connect answer"
		default:
			r.Outcome, r.Detail = spec.Reached, reasonOrCode(reason, code)
		}
	}
	return r
}

func reasonOrCode(reason string, code connect.Code) string {
	if reason != "" {
		return code.String() + "/" + reason
	}
	return code.String()
}

// probeHTTP asks entry's listener for the discovery document. Entry serves the forwarder's uid only and drops any other
// peer after accept, so a refusal is a connection that ends with no answer.
func probeHTTP(ctx context.Context, t spec.Target) spec.Result {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", t.Socket)
		},
		DisableKeepAlives: true,
	}
	hc := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		return spec.Result{ID: t.ID, Outcome: spec.Broken, Detail: err.Error()}
	}
	res, err := hc.Do(req)
	if err == nil {
		defer func() { _ = res.Body.Close() }()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return spec.Result{ID: t.ID, Outcome: spec.Reached, Detail: fmt.Sprintf("HTTP %d", res.StatusCode)}
	}
	switch {
	case errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
		return spec.Result{ID: t.ID, Outcome: spec.Socket, Detail: "EACCES"}
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		return spec.Result{ID: t.ID, Outcome: spec.Broken, Detail: "no listener: " + err.Error()}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return spec.Result{ID: t.ID, Outcome: spec.Guard, Detail: "dropped"}
	}
	return spec.Result{ID: t.ID, Outcome: spec.Broken, Detail: err.Error()}
}
