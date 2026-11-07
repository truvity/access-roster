//go:build sluis_test

package sessiond_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

var tags = regexp.MustCompile(`<[^>]*>`)

// pageText is what a person reads in the body of a page: the text between the tags, one space between the pieces.
func pageText(r *typev2alpha1.HttpReply) string {
	_, body, _ := strings.Cut(string(r.GetBody()), "<body>")
	return strings.Join(strings.Fields(tags.ReplaceAllString(body, " ")), " ")
}

// A refusal that is shown to a person, because it cannot be sent to the client, shows a generic message and the request
// identifier and nothing else: the same words whatever the cause, no value of the request, and the identifier that entry
// made for this request (so the person can quote it and the audit record of the refusal is found by it). An identifier
// that is not a plain token is not shown.
//
// verifies: REQ-UX-001
func TestARefusalPageShowsAGenericMessageAndTheRequestIdentifier(t *testing.T) {
	const reference = "Sign-in could not continue The request was not valid. Go back to the application and start again. If you ask for help, give this reference: "
	canaries := []string{"nobody-CANARY", "STATE-CANARY", "evil.example.test", "NONCE-CANARY"}
	causes := map[string]func(e *env, ctx context.Context) *typev2alpha1.HttpReply{
		"an unknown client": func(e *env, ctx context.Context) *typev2alpha1.HttpReply {
			p := newAuthorize()
			p.req.ClientId, p.req.State, p.req.Nonce = "nobody-CANARY", "STATE-CANARY", "NONCE-CANARY"
			return call(ctx, t, e.client.Authorize, p.req)
		},
		"a redirect_uri that is not registered": func(e *env, ctx context.Context) *typev2alpha1.HttpReply {
			p := newAuthorize()
			p.req.RedirectUri, p.req.State = "https://evil.example.test/cb", "STATE-CANARY"
			return call(ctx, t, e.client.Authorize, p.req)
		},
		"a callback with no cookie": func(e *env, ctx context.Context) *typev2alpha1.HttpReply {
			return call(ctx, t, e.client.Callback, &sessionv2alpha1.CallbackRequest{Code: "c", State: "STATE-CANARY"})
		},
		"a callback with a state that is not ours": func(e *env, ctx context.Context) *typev2alpha1.HttpReply {
			cb, _ := e.started()
			cb.State = "STATE-CANARY"
			return call(ctx, t, e.client.Callback, cb)
		},
	}
	for name, run := range causes {
		for _, id := range []string{"0192f3a4-7c1e-4b8a-9d2e-5a6b7c8d9e0f", "b1946ac9-2b3c-4d5e-8f60-71829304a5b6"} {
			t.Run(name+"/"+id, func(t *testing.T) {
				e := newEnv(t, nil)
				r := run(e, rpc.WithCorrelationID(context.Background(), id))
				if r.GetStatus() != 400 || !strings.HasPrefix(headerOf(r, "Content-Type")[0], "text/html") {
					t.Fatalf("status %d, content type %v", r.GetStatus(), headerOf(r, "Content-Type"))
				}
				if got := pageText(r); got != reference+id {
					t.Errorf("the page reads %q", got)
				}
				for _, c := range canaries {
					if strings.Contains(string(r.GetBody()), c) {
						t.Errorf("the page repeats %q", c)
					}
				}
			})
		}
	}
	t.Run("an identifier that is not a token is not shown", func(t *testing.T) {
		e := newEnv(t, nil)
		r := causes["an unknown client"](e, rpc.WithCorrelationID(context.Background(), `"><script>x</script>`))
		if got := pageText(r); got != strings.TrimSuffix(reference, " If you ask for help, give this reference: ") || strings.Contains(string(r.GetBody()), "script") {
			t.Errorf("the page reads %q", got)
		}
	})
}

// call sends the request with ctx and returns the reply, which must not be an error.
func call[Req any](ctx context.Context, t *testing.T, f func(context.Context, *connect.Request[Req]) (*connect.Response[typev2alpha1.HttpReply], error), req *Req) *typev2alpha1.HttpReply {
	t.Helper()
	res, err := f(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}
