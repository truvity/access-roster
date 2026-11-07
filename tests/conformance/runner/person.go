package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tools/harness/kclogin"
)

// The names the runner knows, none of them a real host: the installation's issuer, which the harness reaches through the
// forwarder's loopback port, and the suite's own address, which is the redirect of every client of the plans.
const (
	issuerHost = "sluis.dev.local.test"
	suiteHost  = "localhost.emobix.co.uk"
)

// person is the one who signs in when a module asks for a visit: the harness's driver of the identity provider's forms (alice,
// with her password and her one-time code), in a browser that keeps its cookies for as long as the runner says. A module
// that must meet an installation that has never seen the browser asks for a stranger (forget); the others share one browser,
// as one person does who runs a plan, so the identity provider's own session answers the forms again.
type person struct {
	hc    *http.Client // the browser's own client: the issuer by way of the forwarder, the suite by way of its port
	plain *http.Client // the same without cookies, for what the browser delivers to the suite
	drv   *kclogin.Driver
	creds kclogin.Credentials
	trace func(string)
}

// newPerson reads alice's secrets from the file the identity provider's start script made, inside this process; they go
// into the Credentials and nowhere else, and nothing the person does prints them.
func newPerson(caFile, secrets, forwarder, suiteAddr string, trace func(string)) (*person, error) {
	pem, err := os.ReadFile(caFile) //nolint:gosec // the harness CA, named by the caller
	if err != nil {
		return nil, fmt.Errorf("the harness CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the harness CA file holds no certificate")
	}
	sec, err := readSecrets(secrets, "ALICE_PASSWORD", "ALICE_TOTP_BASE32")
	if err != nil {
		return nil, err
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		if h, _, err := net.SplitHostPort(addr); err == nil {
			switch h {
			case issuerHost:
				addr = forwarder
			case suiteHost:
				addr = suiteAddr
			}
		}
		return d.DialContext(ctx, network, addr)
	}
	tr := &http.Transport{
		DialContext: dial,
		// The issuer is checked against the harness CA and its name. The suite's address is a container of this run behind a
		// certificate that its image made for itself, which no one could check against anything; it is the only name that is
		// not checked, and only a redirect lands there.
		DialTLSContext:  nil,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.ServerName == suiteHost {
			return nil
		}
		opts := x509.VerifyOptions{DNSName: cs.ServerName, Roots: pool, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	// VerifyConnection runs after the standard check, which would fail the suite's certificate: so the standard check is
	// switched off, and VerifyConnection does both jobs.
	tr.TLSClientConfig.InsecureSkipVerify = true
	hc := &http.Client{Timeout: 60 * time.Second, Transport: tr}
	p := &person{hc: hc, plain: hc, trace: trace,
		creds: kclogin.Credentials{Username: "alice", Password: sec["ALICE_PASSWORD"], TOTPSecret: sec["ALICE_TOTP_BASE32"]}}
	p.drv = &kclogin.Driver{Client: hc, Stop: func(u *url.URL) bool { return u.Hostname() == suiteHost }, Trace: trace}
	return p, nil
}

// forget makes the browser a stranger to the installation: no cookie of the identity provider's remains.
func (p *person) forget() { p.drv.ForgetCookies("127.0.0.1") }

// visit follows an address the suite asked a person to visit, signing in where the forms ask, and delivers the answer
// to the suite as the browser would: a request to the redirect, or the post of the form when the response mode is form_post.
// It returns what the person saw if it was not the redirect.
func (p *person) visit(ctx context.Context, target string) (seen string, err error) {
	back, err := p.drv.Authorize(ctx, target, p.creds)
	if err != nil {
		if pg := p.drv.Last; pg != nil && pg.Host != "" && pg.Status >= 400 {
			return fmt.Sprintf("%s answered %d: %s", pg.Host, pg.Status, title(pg.Body)), err
		}
		return "", err
	}
	var res *http.Response
	if posted := p.drv.Posted; posted != nil {
		res, err = p.plain.PostForm(back.String(), posted)
	} else {
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, back.String(), http.NoBody); err != nil {
			return "", err
		}
		res, err = p.plain.Do(req)
	}
	if err != nil {
		return "", fmt.Errorf("the redirect to the suite: %w", err)
	}
	page, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	// The suite answers its redirect with a page whose script posts the URL fragment (the hash, "#" and what follows, or
	// nothing) to an address of its own, because a server never sees a fragment; the test goes on when that arrives. A browser
	// runs the script; the person does what it does.
	m := submitRE.FindSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("the suite's answer to the redirect (status %d) names no address to post the fragment to", res.StatusCode)
	}
	hash := ""
	if back.Fragment != "" {
		hash = "#" + back.Fragment
	}
	var submit string
	if err := json.Unmarshal(m[1], &submit); err != nil || !strings.HasPrefix(submit, "https://"+suiteHost+":") {
		return "", errors.New("the address that the suite's page posts the fragment to is not one of the suite's own")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, submit, strings.NewReader(hash))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/plain")
	res, err = p.plain.Do(req)
	if err != nil {
		return "", fmt.Errorf("the fragment to the suite: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()
	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("the suite did not accept the fragment: status %d", res.StatusCode)
	}
	return "", nil
}

// submitRE finds the address that the suite's page posts the fragment to: xhr.open('POST', "<address>", true), with the
// address as a JavaScript string literal, in which the page escapes the slashes.
var submitRE = regexp.MustCompile(`xhr\.open\('POST',\s*("(?:[^"\\]|\\.)*")`)

// title is the heading of a page, for a note: the first line of text between the first pair of h1 tags, else the title tag.
func title(page []byte) string {
	s := string(page)
	for _, tag := range []string{"h1", "title"} {
		if i := strings.Index(s, "<"+tag+">"); i >= 0 {
			if j := strings.Index(s[i:], "</"+tag+">"); j > 0 {
				return strings.TrimSpace(s[i+len(tag)+2 : i+j])
			}
		}
	}
	return "(no heading)"
}

// readSecrets reads the named variables from the secrets file inside this process. A missing name is reported by name only.
func readSecrets(path string, names ...string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // the harness's secrets file, named by the caller
	if err != nil {
		return nil, fmt.Errorf("the secrets file: %w", err)
	}
	defer func() { _ = f.Close() }()
	all := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			all[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	out := map[string]string{}
	for _, n := range names {
		v, ok := all[n]
		if !ok || v == "" {
			return nil, fmt.Errorf("the secrets file has no %s", n)
		}
		out[n] = v
	}
	return out, nil
}
