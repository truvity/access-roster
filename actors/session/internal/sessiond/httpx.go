package sessiond

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// SigninCookie is the name of the sign-in cookie. entry reads this name and hands the value to Callback
// (CallbackRequest.cookie); the __Host- prefix makes the browser refuse it unless it is Secure, has Path=/ and no
// Domain (RFC 6265bis section 4.1.3.2).
const SigninCookie = "__Host-sluis_signin"

// CeremonyCookie is the name of the cookie that holds the sealed ceremony of a passkey registration between the registration page
// and its answer. It is not the sign-in cookie, so the ceremony does not replace a pending sign-in and the answer of the finish does
// not clear one; the cookie is SameSite=Strict, because the only request that needs it is the page's own post to this origin. entry
// reads this name for /passkeys/register and no other route; /callback reads the sign-in cookie. The request that starts a
// registration does set the sign-in cookie, as every sign-in does, and the callback spends it: a registration and a sign-in begun
// at the same moment in two tabs of one browser share that one cookie, which is a limit of every sign-in.
const CeremonyCookie = "__Host-sluis_ceremony"

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

// setCeremonyCookie is the Set-Cookie of the ceremony cookie: Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain. Strict is
// enough because the cookie is set in the answer to the callback (a response to a top-level navigation may set it) and is read by
// the page's own post, which is same-site; no navigation from another site carries it.
func setCeremonyCookie(value string, maxAge int) *typev2alpha1.Header {
	return header("Set-Cookie", CeremonyCookie+"="+value+"; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="+strconv.Itoa(maxAge))
}

// clearCeremonyCookie ends the ceremony cookie.
func clearCeremonyCookie() *typev2alpha1.Header { return setCeremonyCookie("", 0) }

// clearCookie ends the sign-in cookie.
func clearCookie() *typev2alpha1.Header { return setCookie("", 0) }

// redirect is a 302 to location with the headers.
func redirect(location string, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	hs := append([]*typev2alpha1.Header{header("Location", location)}, noStore()...)
	return reply(http.StatusFound, nil, append(hs, h...)...)
}

// errorPage is the answer to an authorize or callback request that cannot be redirected to a client (an unknown
// client, a redirect_uri that is not registered, a callback that is not ours): a fixed page. It holds no value of
// the request, so there is nothing to escape; the request must never be reflected (RFC 6749 section 10.15). The one
// thing that varies is the request identifier, the correlation id that entry made for this request: the person gives it
// when asking for help, and the audit record of the refusal carries it (REQ-UX-001, REQ-UX-006).
func errorPage(ctx context.Context, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	hs := append([]*typev2alpha1.Header{header("Content-Type", "text/html; charset=utf-8")}, noStore()...)
	return reply(http.StatusBadRequest, []byte(errorPageHTML(rpc.CorrelationID(ctx))), append(hs, h...)...)
}

// errorPageHTML is the page. The identifier is a token of letters, digits, "-" and "_" (the kit drops any other), and is
// escaped all the same; with none, as when the page is made outside a request, the page has no reference line.
func errorPageHTML(requestID string) string {
	ref := ""
	if requestID != "" {
		ref = "\n<p>If you ask for help, give this reference: <code>" + html.EscapeString(requestID) + "</code></p>"
	}
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in could not continue</title></head>
<body><h1>Sign-in could not continue</h1>
<p>The request was not valid. Go back to the application and start again.</p>` + ref + `
</body></html>
`
}

// responseModeFormPost is the response_mode that asks for the answer as an auto-submitting form (OAuth 2.0 Form Post
// Response Mode). The query is the other served mode, and the default.
const responseModeFormPost = "form_post"

// answerMode is the response mode to answer a request in: form_post when it asked for exactly that, and the query for
// everything else, a mode that is refused included, because the refusal must reach the client some way.
func answerMode(requested string) string {
	if requested == responseModeFormPost {
		return responseModeFormPost
	}
	return ""
}

// clientRedirect answers a client's redirect_uri with the parameters of RFC 6749 section 4.1.2 (and 4.1.2.1 for an
// error), in the query, or in an auto-submitting form when mode is form_post. Every answer carries the issuer
// as iss (RFC 9207 section 2), and the client's state when it sent one. In the query, params are added after the parsed
// redirect_uri's own query, never in place of it.
func clientRedirect(mode, redirectURI, state, issuer string, params url.Values, h ...*typev2alpha1.Header) (*connect.Response[typev2alpha1.HttpReply], error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	if mode == responseModeFormPost {
		return formPostPage(u, state, issuer, params, h...)
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

// formPostScript is the one inline script of the form_post page, byte for byte. The Content-Security-Policy that entry
// sends with the page allows exactly this text by its SHA-256 hash (actors/entry/src/headers.rs, FORM_POST_SCRIPT), and a
// test of this package compares the hash of what the page serves with the hash in that file.
const formPostScript = "document.forms[0].submit();"

// formPostPage answers the redirect_uri u as an HTML page that posts the parameters to it, and submits itself (OAuth 2.0
// Form Post Response Mode, section 2): a code never stands in the URL, the history or a Referer. The page holds nothing
// of the request but the redirect_uri that is registered, as the form's action, and the parameters, as hidden fields;
// every name and value is escaped. HttpReply.form_post_origin names the web origin of the redirect_uri, which entry
// makes the form-action of the page's Content-Security-Policy (REQ-AUTHN-079): a browser then refuses to post the code to
// any other address.
func formPostPage(u *url.URL, state, issuer string, params url.Values, h ...*typev2alpha1.Header) (*connect.Response[typev2alpha1.HttpReply], error) {
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("a redirect_uri with no web origin")
	}
	fields := url.Values{}
	for k, vs := range params {
		fields[k] = vs
	}
	if state != "" {
		fields.Set("state", state)
	}
	fields.Set("iss", issuer)
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Continue</title></head>
<body><form method="post" action="` + html.EscapeString(u.String()) + `">
`)
	for _, k := range names {
		for _, v := range fields[k] {
			b.WriteString(`<input type="hidden" name="` + html.EscapeString(k) + `" value="` + html.EscapeString(v) + `">` + "\n")
		}
	}
	b.WriteString(`<noscript><p>Your browser does not run scripts. Press the button to go back to the application.</p><button type="submit">Continue</button></noscript>
</form>
<script>` + formPostScript + `</script>
</body></html>
`)
	hs := append([]*typev2alpha1.Header{header("Content-Type", "text/html; charset=utf-8")}, noStore()...)
	out := reply(http.StatusOK, []byte(b.String()), append(hs, h...)...)
	out.Msg.FormPostOrigin = strings.ToLower(u.Scheme) + "://" + u.Host
	return out, nil
}
