package sessiond

import (
	"net/http"
	"net/url"
	"strconv"

	"connectrpc.com/connect"

	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// SigninCookie is the name of the sign-in cookie. entry reads this name and hands the value to Callback
// (CallbackRequest.cookie); the __Host- prefix makes the browser refuse it unless it is Secure, has Path=/ and no
// Domain (RFC 6265bis section 4.1.3.2).
const SigninCookie = "__Host-sluis_signin"

// cookieMaxAge is how long the browser keeps the sign-in cookie: as long as a pending sign-in lives.
const cookieMaxAge = 10 * 60

// header builds one header of an HttpReply. entry relays only Location, Set-Cookie, Content-Type, Cache-Control,
// Pragma and WWW-Authenticate.
func header(name, value string) *typev2alpha1.Header {
	return &typev2alpha1.Header{Name: name, Value: value}
}

// noStore is the pair of headers that keep a response with a code, a token or a redirect out of every cache
// (RFC 6749 section 5.1).
func noStore() []*typev2alpha1.Header {
	return []*typev2alpha1.Header{header("Cache-Control", "no-store"), header("Pragma", "no-cache")}
}

func reply(status int, body []byte, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	return connect.NewResponse(&typev2alpha1.HttpReply{Status: int32(status), Headers: h, Body: body}) //nolint:gosec // an HTTP status
}

// setCookie is the Set-Cookie of the sign-in cookie: Secure, HttpOnly, SameSite=Lax (the callback is a top-level
// GET navigation from the upstream, which Lax sends and Strict does not), Path=/ and no Domain, as __Host- needs.
func setCookie(value string, maxAge int) *typev2alpha1.Header {
	return header("Set-Cookie", SigninCookie+"="+value+"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="+strconv.Itoa(maxAge))
}

// clearCookie ends the sign-in cookie.
func clearCookie() *typev2alpha1.Header { return setCookie("", 0) }

// redirect is a 302 to location with the headers.
func redirect(location string, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	hs := append([]*typev2alpha1.Header{header("Location", location)}, noStore()...)
	return reply(http.StatusFound, nil, append(hs, h...)...)
}

// errorPage is the answer to an authorize or callback request that cannot be redirected to a client (an unknown
// client, a redirect_uri that is not registered, a callback that is not ours): a fixed page. It holds no value of
// the request, so there is nothing to escape; the request must never be reflected (RFC 6749 section 10.15).
func errorPage(h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	hs := append([]*typev2alpha1.Header{header("Content-Type", "text/html; charset=utf-8")}, noStore()...)
	return reply(http.StatusBadRequest, []byte(errorPageHTML), append(hs, h...)...)
}

const errorPageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in could not continue</title></head>
<body><h1>Sign-in could not continue</h1>
<p>The request was not valid. Go back to the application and start again.</p></body></html>
`

// clientRedirect answers a client's redirect_uri with the parameters of RFC 6749 section 4.1.2 (and 4.1.2.1 for an
// error), in the query (the only response mode: session builds no form_post page). Every redirect carries the issuer
// as iss (RFC 9207 section 2), and the client's state when it sent one. params are added after the parsed
// redirect_uri's own query, never in place of it.
func clientRedirect(redirectURI, state, issuer string, params url.Values, h ...*typev2alpha1.Header) (*connect.Response[typev2alpha1.HttpReply], error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return redirect(u.String(), h...), nil
}
