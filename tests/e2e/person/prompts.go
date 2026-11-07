package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tools/harness/kclogin"
)

// prompts is what a client asks of the person's authentication, against the real identity provider (OpenID Connect Core
// section 3.1.2.1; REQ-AUTHN-007, 008, 031, 032). sluis keeps no sign-in session of a returning browser, so prompt=none is a
// silent request to the identity provider and prompt=login is a request to it to ask again. Each case is a browser that
// follows the redirects by hand (the harness driver), counting the forms it had to submit.
//
//	signed in, prompt=none        a code, with no form shown
//	not signed in, prompt=none    login_required at the client's redirect, no code, no form
//	signed in, max_age=3600       a code, with no form shown, and the ID token carries auth_time
//	signed in, prompt=login       the form is shown again, and the ID token's auth_time is from this request
//	prompt=none with login        invalid_request; consent: consent_required (sluis shows neither)
//
// The case that makes the identity provider ask again needs a second one-time password, which it takes once in a 30 second
// step, so it is the last and the one that can wait.
func (s *session) prompts(ctx context.Context) error {
	fmt.Println("\n== 2c. prompt and max_age (OpenID Connect Core 3.1.2.1), against the identity provider")
	posts := 0
	trace := func(l string) {
		if strings.HasPrefix(l, "POST ") {
			posts++
		}
	}
	signedIn := s.driver
	stranger := &kclogin.Driver{Client: s.hc, Stop: s.driver.Stop, Trace: trace}
	was := signedIn.Trace
	signedIn.Trace = func(l string) {
		trace(l)
		if was != nil {
			was(l)
		}
	}
	defer func() { signedIn.Trace = was }()

	// run makes a request with extra parameters in a browser and returns what came back to the client's redirect, and how many
	// forms the browser submitted on the way.
	run := func(b *kclogin.Driver, extra url.Values) (*authRequest, url.Values, int, error) {
		a, err := s.newAuthRequest(ctx, extra)
		if err != nil {
			return nil, nil, 0, err
		}
		posts = 0
		back, err := b.Authorize(ctx, a.url, s.creds)
		if err != nil {
			return nil, nil, 0, err
		}
		q := back.Query()
		if q.Get("state") != a.state || q.Get("iss") != issuer {
			return nil, nil, 0, fmt.Errorf("the redirect carries state %q and iss %q, want this request's state and %s", q.Get("state"), q.Get("iss"), issuer)
		}
		return a, q, posts, nil
	}
	wantCode := func(name string, b *kclogin.Driver, extra url.Values, forms func(int) bool) (map[string]any, error) {
		a, q, n, err := run(b, extra)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if q.Get("code") == "" || q.Get("error") != "" {
			return nil, fmt.Errorf("%s: the client got error %q and no code", name, q.Get("error"))
		}
		if !forms(n) {
			return nil, fmt.Errorf("%s: the browser submitted %d forms", name, n)
		}
		_, claims, err := s.redeem(a, q.Get("code"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return claims, nil
	}
	wantError := func(name string, b *kclogin.Driver, extra url.Values, code string) error {
		_, q, n, err := run(b, extra)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if q.Get("error") != code || q.Get("code") != "" || n != 0 {
			return fmt.Errorf("%s: the client got error %q, code %q after %d forms; want error %s, no code, no form", name, q.Get("error"), q.Get("code"), n, code)
		}
		fmt.Printf("%-34s error=%s at the client's redirect, no code, no form\n", name+":", code)
		return nil
	}
	none := func(f int) bool { return f == 0 }

	if claims, err := wantCode("prompt=none, signed in", signedIn, url.Values{"prompt": {"none"}}, none); err != nil {
		return err
	} else if claims["auth_time"] == nil {
		return errors.New("prompt=none, signed in: the ID token carries no auth_time")
	}
	fmt.Printf("%-34s a code with no form shown\n", "prompt=none, signed in:")
	if err := wantError("prompt=none, not signed in", stranger, url.Values{"prompt": {"none"}}, "login_required"); err != nil {
		return err
	}
	if claims, err := wantCode("max_age=3600, signed in", signedIn, url.Values{"max_age": {"3600"}}, none); err != nil {
		return err
	} else if claims["auth_time"] == nil {
		return errors.New("max_age=3600: the ID token carries no auth_time")
	}
	fmt.Printf("%-34s a code with no form shown, and auth_time in the ID token\n", "max_age=3600, signed in:")
	if err := wantError("prompt=none login", signedIn, url.Values{"prompt": {"none login"}}, "invalid_request"); err != nil {
		return err
	}
	if err := wantError("prompt=consent", signedIn, url.Values{"prompt": {"consent"}}, "consent_required"); err != nil {
		return err
	}

	before := time.Now()
	claims, err := wantCode("prompt=login, signed in", signedIn, url.Values{"prompt": {"login"}}, func(f int) bool { return f > 0 })
	if err != nil {
		return err
	}
	at, _ := claims["auth_time"].(float64)
	if at == 0 || time.Unix(int64(at), 0).Before(before.Add(-10*time.Second)) {
		return fmt.Errorf("prompt=login: the ID token's auth_time %v is from before the request (%s)", claims["auth_time"], before.UTC().Format(time.RFC3339))
	}
	fmt.Printf("%-34s the form was shown again, and auth_time is from this request\n", "prompt=login, signed in:")
	return nil
}
