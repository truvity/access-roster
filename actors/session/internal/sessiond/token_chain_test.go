//go:build sluis_test

package sessiond_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// An access token and an ID token of a person end no later than the session chain they name. The chain here lasts
// five minutes and the tokens ten, so the chain is what limits them: at the sign-in, at a refresh in the middle of the
// session, and at a refresh in its last minute. The chain's end is read from the stored chain, not computed in the
// test. When the chain is over, whether the session's absolute limit passed before the code was redeemed or before a
// refresh, no token is made at all, so a redemption never yields a token with no session behind it.
//
// This proves the limit a token carries (its exp). A token is a signed document that is checked by its signature
// and exp alone, so ending a chain early (a replayed refresh token) stops new tokens but does not recall one already
// issued; the second sentence of the row's verification asks for that and is not built.
//
// verifies: REQ-SESS-054
func TestATokenNeverOutlivesTheChainItNames(t *testing.T) {
	const chainLife = 5 * time.Minute
	newShortEnv := func() *env {
		return newEnv(t, func(o *options) {
			o.lifetime.HumanSessionAbsolute = durationpb.New(chainLife)
			o.lifetime.RefreshIdle = durationpb.New(chainLife)
		})
	}
	chainEnd := func(e *env, sid string) time.Time {
		t.Helper()
		raw, _, ok := e.store.raw("session-chain", testTenant, sid)
		if !ok {
			t.Fatalf("no chain %q", sid)
		}
		return protoOf(t, raw, &sessionv2alpha1.SessionChain{}).GetEndsAt().AsTime()
	}
	// exp of both tokens of an answer, and the lifetime the answer states.
	assertEnds := func(t *testing.T, e *env, b map[string]any, end time.Time, at string) {
		t.Helper()
		for _, tok := range []string{"id_token", "access_token"} {
			_, c := tokenClaims(t, b[tok].(string))
			if exp := time.Unix(num(c, "exp"), 0); exp.After(end) {
				t.Errorf("%s: %s exp %s is after the end of the chain %s", at, tok, exp, end)
			}
			if exp := time.Unix(num(c, "exp"), 0); !exp.Equal(end) {
				t.Errorf("%s: %s exp %s, want the end of the chain %s (the tokens live ten minutes, the chain five)", at, tok, exp, end)
			}
		}
		if got, want := num(b, "expires_in"), int64(end.Sub(e.clk.now())/time.Second); got != want {
			t.Errorf("%s: expires_in = %d, want %d", at, got, want)
		}
	}

	e := newShortEnv()
	b, _ := e.redeemed()
	rt := b["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt, ".")
	end := chainEnd(e, sid)
	if lim := e.clk.now().Add(chainLife); end.After(lim) {
		t.Fatalf("chain ends at %s, more than %s after now", end, chainLife)
	}
	assertEnds(t, e, b, end, "sign-in")

	// A refresh does not move the end of the chain, and the tokens still stop there.
	e.clk.advance(2 * time.Minute)
	r := e.token(refreshRequest(rt))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh at 2m: %d %s", r.GetStatus(), r.GetBody())
	}
	b = body(t, r)
	rt = b["refresh_token"].(string)
	if got := chainEnd(e, sid); !got.Equal(end) {
		t.Errorf("the refresh moved the end of the chain from %s to %s", end, got)
	}
	assertEnds(t, e, b, end, "refresh at 2m")

	// In the last minute the token is as short as what is left.
	e.clk.advance(2*time.Minute + 30*time.Second)
	r = e.token(refreshRequest(rt))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh at 4m30: %d %s", r.GetStatus(), r.GetBody())
	}
	b = body(t, r)
	rt = b["refresh_token"].(string)
	assertEnds(t, e, b, end, "refresh at 4m30")
	if got := num(b, "expires_in"); got != 30 {
		t.Errorf("expires_in = %d, want the 30 seconds left", got)
	}

	// At the end of the chain a refresh makes no token, and the chain is gone.
	e.clk.advance(30 * time.Second)
	signed := len(e.signer.requests())
	assertOAuth(t, e.token(refreshRequest(rt)), http.StatusBadRequest, "invalid_grant")
	if n := len(e.signer.requests()); n != signed {
		t.Errorf("%d tokens signed for a chain that is over", n-signed)
	}
	if _, _, ok := e.store.raw("session-chain", testTenant, sid); ok {
		t.Error("the chain of an over session is still stored")
	}

	// A code redeemed after the session's absolute limit passed makes no chain and no token. The authentication
	// counts from the sign-in, so a short limit can pass inside the life of the code.
	e = newEnv(t, func(o *options) { o.lifetime.HumanSessionAbsolute = durationpb.New(10 * time.Second) })
	code, p := e.signIn()
	e.clk.advance(11 * time.Second)
	signed = len(e.signer.requests())
	assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "invalid_grant")
	if n := len(e.signer.requests()); n != signed {
		t.Errorf("%d tokens signed after the session's absolute limit", n-signed)
	}
	if n := e.store.count("session-chain", testTenant); n != 0 {
		t.Errorf("%d chains for a session that was over at the redemption", n)
	}
}
