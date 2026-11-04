package oidc

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// blockedError marks a refusal of the egress policy.
type blockedError struct{ why string }

func (e *blockedError) Error() string { return "egress refused: " + e.why }

// CheckURL accepts an https URL, or, in a development boundary only, an http URL on a loopback IP literal, 127.0.0.1
// or [::1] (decision D-11; RFC 8252 section 7.3 names the literals and section 8.3 advises against the name
// localhost). It is the floor in code: a development difference is configuration, checked here against the
// boundary's environment, and no flag turns it off. The trust roots are the system's.
func CheckURL(raw string, development bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return nil, errors.New("not an absolute URL without credentials or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !development {
			return nil, errors.New("an http URL is accepted only in a development boundary")
		}
		if ip, err := netip.ParseAddr(u.Hostname()); err != nil || !ip.IsLoopback() {
			return nil, errors.New("an http URL is accepted only on a loopback IP literal")
		}
	default:
		return nil, errors.New("not an https URL")
	}
	return u, nil
}

// Authority is the host and port of a URL, with the default port of its scheme made explicit, in lower case. An
// Upstream declares one authority (its issuer's), and every call of the adapter for it must go there.
func Authority(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

// cgnat is 100.64.0.0/10 (RFC 6598), which IsPrivate does not cover.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// benchmark is 198.18.0.0/15 (RFC 2544).
var benchmark = netip.MustParsePrefix("198.18.0.0/15")

// blockedAddress says whether a resolved address is outside what the adapter may reach. Loopback is refused outside a
// development boundary; private, link-local (the metadata address among them), unspecified, multicast and shared
// address space are refused everywhere (REQ-FED-008).
func blockedAddress(ip netip.Addr, development bool) bool {
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return !development
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified():
		return true
	}
	return cgnat.Contains(ip) || benchmark.Contains(ip)
}

// newHTTPClient returns a client whose dialer checks the address after the name is resolved, on every connection
// attempt, and that does not follow a redirect (it would carry a body, or a code, elsewhere) and does not read the
// proxy variables of the environment.
func newHTTPClient(development bool) *http.Client {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return &blockedError{"address"}
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || blockedAddress(ip, development) {
				return &blockedError{"address"}
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           d.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       60 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
