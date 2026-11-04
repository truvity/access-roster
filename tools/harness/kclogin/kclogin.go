// Package kclogin drives the browser sign-in of the test identity provider (Keycloak, docs/runtimes/local.md,
// "Sign-in") without a browser: it follows the redirects of an authorization request by hand, fills in the user name
// and password form and the one-time-password form, and computes the code from the user's secret (RFC 6238). It is a
// test harness, never part of a product binary, and it holds no secret of its own: the caller passes them in.
//
// It stops at the first redirect whose target the caller owns (`Stop`), usually the loopback redirect of the command-line
// tool, and returns that request's URL, so the caller can hand it to the tool exactly as a browser would.
package kclogin

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 sets HMAC-SHA1 as the default of TOTP, and the identity provider's authenticators use it
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Credentials are what the identity provider asks of a user.
type Credentials struct {
	Username, Password string
	// TOTPSecret is the key of the authenticator, in base32 as an authenticator app takes it (RFC 4648 section 6).
	TOTPSecret string
}

// Driver signs a user in at the identity provider.
type Driver struct {
	// Client sends the requests. Its jar is replaced by the driver's; its CheckRedirect is replaced too.
	Client *http.Client
	// Stop says whether a redirect target is the end of the sign-in: the request is not sent, and its URL is returned.
	Stop func(*url.URL) bool
	// Trace, if set, is told each hop as "METHOD host/path status [names of the query parameters]": no value, no body,
	// no cookie.
	Trace func(string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Sleep waits; nil means time.Sleep honouring ctx. Tests replace it.
	Sleep func(context.Context, time.Duration) error

	jar *jar

	mu       sync.Mutex
	lastStep int64 // the step of the last code this driver made
}

// maxHops bounds the redirects and forms of one sign-in.
const maxHops = 20

var (
	formRE   = regexp.MustCompile(`(?is)<form\b[^>]*\baction="([^"]+)"`)
	hiddenRE = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRE   = regexp.MustCompile(`(?is)\b(type|name|value)\s*=\s*"([^"]*)"`)
	errRE    = regexp.MustCompile(`(?is)kc-feedback-text[^>]*>([^<]*)`)
)

// Authorize follows authURL until a redirect reaches Stop, signing in with c where the identity provider asks. It
// returns the URL of the redirect that Stop accepted. A cookie jar lives as long as the Driver, so a second call is a
// second visit of the same browser: the identity provider's own session answers it without a form.
func (d *Driver) Authorize(ctx context.Context, authURL string, c Credentials) (*url.URL, error) {
	if d.Client == nil || d.Stop == nil {
		return nil, errors.New("kclogin: a Client and a Stop are required")
	}
	if d.jar == nil {
		d.jar = &jar{m: map[string]map[string]string{}}
	}
	hc := *d.Client
	hc.Jar = d.jar
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	next, method, form := authURL, http.MethodGet, url.Values(nil)
	for range maxHops {
		u, err := url.Parse(next)
		if err != nil {
			return nil, fmt.Errorf("kclogin: a redirect that is not a URL")
		}
		if d.Stop(u) {
			return u, nil
		}
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, next, body)
		if err != nil {
			return nil, err
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("kclogin: %s %s: %w", method, u.Host, err)
		}
		page, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		if d.Trace != nil {
			names := make([]string, 0, len(u.Query()))
			for n := range u.Query() {
				names = append(names, n)
			}
			sort.Strings(names)
			d.Trace(fmt.Sprintf("%s %s%s %d %v", method, u.Host, u.Path, res.StatusCode, names))
		}

		if loc := res.Header.Get("Location"); res.StatusCode >= 300 && res.StatusCode < 400 && loc != "" {
			t, err := u.Parse(loc)
			if err != nil {
				return nil, errors.New("kclogin: a Location that is not a URL")
			}
			next, method, form = t.String(), http.MethodGet, nil
			continue
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("kclogin: %s answered %d%s", u.Host, res.StatusCode, feedback(page))
		}
		// A form of the identity provider: the user name and password, or the one-time password.
		action := formRE.FindSubmatch(page)
		if action == nil {
			return nil, fmt.Errorf("kclogin: %s answered a page that is not a form%s", u.Host, feedback(page))
		}
		target, err := u.Parse(html.UnescapeString(string(action[1])))
		if err != nil {
			return nil, errors.New("kclogin: a form action that is not a URL")
		}
		fields := hidden(page)
		switch {
		case hasInput(page, "username"):
			fields.Set("username", c.Username)
			fields.Set("password", c.Password)
		case hasInput(page, "otp"):
			code, err := d.code(ctx, c.TOTPSecret, feedback(page) != "")
			if err != nil {
				return nil, err
			}
			fields.Set("otp", code)
			fields.Set("login", "Sign In")
		default:
			return nil, fmt.Errorf("kclogin: a form that asks for something this driver cannot give%s", feedback(page))
		}
		next, method, form = target.String(), http.MethodPost, fields
	}
	return nil, errors.New("kclogin: too many redirects and forms")
}

// code is the one-time password for now. The identity provider refuses a code twice in one 30 second step, so a
// second code in the same step, or a retry after a refusal, waits for the next step (RFC 6238 section 5.2).
func (d *Driver) code(ctx context.Context, secret string, retry bool) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "=")))
	if err != nil || len(key) == 0 {
		return "", errors.New("kclogin: the TOTP secret is not base32")
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t := now()
	if step := t.Unix() / Period; retry || step == d.lastStep {
		wait := time.Duration(Period-t.Unix()%Period) * time.Second
		sleep := d.Sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, wait); err != nil {
			return "", err
		}
		t = t.Add(wait)
	}
	d.lastStep = t.Unix() / Period
	return TOTP(key, t), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Period is the step of a TOTP in seconds (RFC 6238 section 4.1).
const Period = 30

// TOTP is the six-digit time-based one-time password of RFC 6238 with HMAC-SHA1 (the default of section 1.2), from the
// dynamic truncation of RFC 4226 section 5.3.
func TOTP(key []byte, t time.Time) string {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(t.Unix()/Period)) //nolint:gosec // a time after 1970
	m := hmac.New(sha1.New, key)
	m.Write(c[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// hasInput says whether the page has an input of that name.
func hasInput(page []byte, name string) bool {
	for _, in := range hiddenRE.FindAll(page, -1) {
		if attrs(in)["name"] == name {
			return true
		}
	}
	return false
}

// hidden returns the hidden inputs of the page's form: what a browser would send besides what the user typed.
func hidden(page []byte) url.Values {
	v := url.Values{}
	for _, in := range hiddenRE.FindAll(page, -1) {
		a := attrs(in)
		if strings.EqualFold(a["type"], "hidden") && a["name"] != "" {
			v.Set(a["name"], html.UnescapeString(a["value"]))
		}
	}
	return v
}

func attrs(tag []byte) map[string]string {
	out := map[string]string{}
	for _, m := range attrRE.FindAllSubmatch(tag, -1) {
		out[strings.ToLower(string(m[1]))] = string(m[2])
	}
	return out
}

// feedback is the identity provider's own message on a page, as " (message)", or "" when it has none. It is text the
// provider wrote about the form, never a value the user typed.
func feedback(page []byte) string {
	m := errRE.FindSubmatch(page)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(html.UnescapeString(string(m[1])))
	if t == "" {
		return ""
	}
	return " (" + t + ")"
}

// jar is the cookie jar of a browser that trusts the loopback: the identity provider's cookies are Secure, and the
// test reaches it over plain HTTP on 127.0.0.1, which a browser treats as a secure context and net/http's jar does not.
// It keys cookies by host, name and value only; path and expiry are not modelled, which a sign-in does not need.
type jar struct {
	mu sync.Mutex
	m  map[string]map[string]string
}

func (j *jar) SetCookies(u *url.URL, cs []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	h := u.Hostname()
	if j.m[h] == nil {
		j.m[h] = map[string]string{}
	}
	for _, c := range cs {
		if c.MaxAge < 0 || c.Value == "" {
			delete(j.m[h], c.Name)
			continue
		}
		j.m[h][c.Name] = c.Value
	}
}

func (j *jar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []*http.Cookie
	for n, v := range j.m[u.Hostname()] {
		out = append(out, &http.Cookie{Name: n, Value: v, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	return out
}
