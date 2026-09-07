package emailaddr

import "testing"

func TestDomain(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		domain string
		ok     bool
	}{
		{"alice@Example.COM", "example.com", true},
		{"  bob@example.org ", "example.org", true},
		{"odd@quoted@example.net", "example.net", true},
		{"nobody", "", false},
		{"@example.com", "", false},
		{"trailing@", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		domain, ok := Domain(c.in)
		if domain != c.domain || ok != c.ok {
			t.Errorf("Domain(%q) = %q, %v; want %q, %v", c.in, domain, ok, c.domain, c.ok)
		}
	}
}
