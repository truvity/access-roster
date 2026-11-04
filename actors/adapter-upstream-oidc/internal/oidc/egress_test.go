package oidc

import (
	"net/netip"
	"testing"
)

func TestCheckURL(t *testing.T) {
	cases := []struct {
		raw  string
		dev  bool
		want bool
	}{
		{"https://idp.example.com/realms/x", false, true},
		{"https://idp.example.com/realms/x", true, true},
		{"http://127.0.0.1:8180/realms/x", true, true},
		{"http://[::1]:8180/realms/x", true, true},
		{"http://127.0.0.1:8180/realms/x", false, false}, // http is for development only (D-11)
		{"http://localhost:8180/realms/x", true, false},  // the name can be made to resolve elsewhere (RFC 8252 section 8.3)
		{"http://idp.example.com/realms/x", true, false}, // http off loopback, even in development
		{"http://192.0.2.7/realms/x", true, false},
		{"ftp://idp.example.com/", true, false},
		{"https://user:pw@idp.example.com/", false, false},
		{"https://idp.example.com/#frag", false, false},
		{"/relative", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		_, err := CheckURL(c.raw, c.dev)
		if (err == nil) != c.want {
			t.Errorf("CheckURL(%q, dev=%v) error = %v, want ok=%v", c.raw, c.dev, err, c.want)
		}
	}
}

func TestBlockedAddress(t *testing.T) {
	cases := []struct {
		ip       string
		dev, bad bool
	}{
		{"127.0.0.1", false, true}, {"127.0.0.1", true, false}, {"::1", false, true}, {"::1", true, false},
		{"::ffff:127.0.0.1", false, true}, // an IPv4-mapped loopback is loopback
		{"10.0.0.5", true, true}, {"172.16.3.4", true, true}, {"192.168.1.9", true, true}, {"fd00::1", true, true},
		{"169.254.169.254", true, true}, {"fe80::1", true, true}, // the cloud metadata address and link-local
		{"100.64.0.1", true, true}, {"198.18.0.1", true, true},
		{"0.0.0.0", true, true}, {"::", true, true}, {"224.0.0.1", true, true}, {"ff02::1", true, true},
		{"93.184.216.34", false, false}, {"2606:2800:220:1:248:1893:25c8:1946", false, false},
	}
	for _, c := range cases {
		if got := blockedAddress(netip.MustParseAddr(c.ip), c.dev); got != c.bad {
			t.Errorf("blockedAddress(%s, dev=%v) = %v, want %v", c.ip, c.dev, got, c.bad)
		}
	}
}
