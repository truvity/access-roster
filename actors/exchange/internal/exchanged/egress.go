package exchanged

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxBody bounds a key set read from an issuer.
const maxBody = 1 << 20

// errBlocked marks a refusal of the egress policy.
var errBlocked = errors.New("egress refused")

// CheckURL accepts an https URL, or, in a development boundary only, an http URL on a loopback IP literal, 127.0.0.1
// or [::1] (decision D-11; RFC 8252 section 7.3). It is the floor in code: a development difference is configuration,
// checked against the boundary's environment, and no flag turns it off. The trust roots are the system's.
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

// cgnat is 100.64.0.0/10 (RFC 6598), which IsPrivate does not cover.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// benchmark is 198.18.0.0/15 (RFC 2544).
var benchmark = netip.MustParsePrefix("198.18.0.0/15")

// blockedAddress says whether a resolved address is outside what exchange may reach. Loopback is refused outside a
// development boundary; private, link-local (the metadata address among them), unspecified, multicast and shared
// address space are refused everywhere.
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
// attempt, and that follows no redirect and reads no proxy variable.
func newHTTPClient(development bool) *http.Client {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errBlocked
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || blockedAddress(ip, development) {
				return errBlocked
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

// fetched is an answer of an issuer's key endpoint.
type fetched struct {
	body []byte
	// ttl is how long HTTP caching lets the answer be kept: zero when the issuer says not to keep it, and the
	// default when it says nothing.
	ttl time.Duration
}

// maxKeyTTL is the longest a fetched key set is kept (the maximum of the kind VerifierKeyCache).
const maxKeyTTL = 24 * time.Hour

// defaultKeyTTL is how long a key set is kept when the issuer's answer carries no caching directive. RFC 9111
// section 4.2.2 allows a heuristic; a short one keeps a rotation visible within minutes.
const defaultKeyTTL = 5 * time.Minute

// get makes a GET to the issuer's key endpoint and reads at most maxBody bytes of a 200 answer.
func get(ctx context.Context, hc *http.Client, raw string, development bool) (fetched, error) {
	u, err := CheckURL(raw, development)
	if err != nil {
		return fetched{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fetched{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fetched{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fetched{}, errors.New("the key endpoint did not answer 200")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return fetched{}, errors.New("the key set could not be read")
	}
	return fetched{body: body, ttl: cacheTTL(resp.Header.Values("Cache-Control"))}, nil
}

// cacheTTL reads the freshness of a response from Cache-Control (RFC 9111 section 5.2.2): no-store and no-cache keep
// nothing, max-age gives the time, and the rest is the default. The result never passes maxKeyTTL.
func cacheTTL(values []string) time.Duration {
	ttl := defaultKeyTTL
	for _, v := range values {
		for _, d := range strings.Split(v, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			switch {
			case d == "no-store", d == "no-cache", strings.HasPrefix(d, "no-cache="):
				return 0
			case strings.HasPrefix(d, "max-age="):
				s, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64)
				if err != nil || s < 0 {
					return 0
				}
				ttl = time.Duration(min(s, int64(maxKeyTTL/time.Second))) * time.Second
			}
		}
	}
	return min(ttl, maxKeyTTL)
}
