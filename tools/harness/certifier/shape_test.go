package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
)

// Requests made by hand, with extensions of any content, for the cases no honest `sluis key request` makes: what the certifier
// does with each is a refusal by policy, never an error that stops the batch.

type gname struct {
	tag   int
	bytes []byte
}

func nameConstraints(permitted, excluded []gname) pkix.Extension {
	type subtree struct{ Base asn1.RawValue }
	wrap := func(l []gname) []subtree {
		var out []subtree
		for _, g := range l {
			out = append(out, subtree{asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: g.tag, Bytes: g.bytes}})
		}
		return out
	}
	v, err := asn1.Marshal(struct {
		Permitted []subtree `asn1:"tag:0,optional"`
		Excluded  []subtree `asn1:"tag:1,optional"`
	}{wrap(permitted), wrap(excluded)})
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 30}, Critical: true, Value: v}
}

func basicConstraints(pathLen int) pkix.Extension {
	v, _ := asn1.Marshal(struct {
		CA         bool
		MaxPathLen int
	}{true, pathLen})
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: v}
}

func keyUsage(b byte, bits int) pkix.Extension {
	v, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{b}, BitLength: bits})
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: v}
}

// eku is an extended key usage extension: serverAuth and clientAuth, in that order, not critical, unless others say otherwise.
func eku(critical bool, purposes ...asn1.ObjectIdentifier) pkix.Extension {
	if len(purposes) == 0 {
		purposes = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 5, 5, 7, 3, 2}}
	}
	v, err := asn1.Marshal(purposes)
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: critical, Value: v}
}

var (
	serverAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	clientAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	codeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	anyEKU      = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

var (
	allIPv4 = gname{7, make([]byte, 8)}
	allIPv6 = gname{7, make([]byte, 32)}
	dnsName = func(s string) gname { return gname{2, []byte(s)} }
	both    = []gname{allIPv4, allIPv6}
)

// handMade writes a software request whose extensions are exts, signed by its own key.
func handMade(t *testing.T, dir, stem string, exts []pkix.Extension) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	handMadeFor(t, dir, stem, k, pkix.Name{CommonName: "x"}, exts)
}

// handMadeFor writes a software request for the key and subject given, signed by that key.
func handMadeFor(t *testing.T, dir, stem string, k *ecdsa.PrivateKey, subject pkix.Name, exts []pkix.Extension) {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, SignatureAlgorithm: x509.ECDSAWithSHA384, ExtraExtensions: exts}, k)
	if err != nil {
		t.Fatal(err)
	}
	pj, _ := (&handoff.Proof{RequestSHA256: handoff.RequestDigest(der), Store: handoff.StoreSoftware}).Marshal()
	mustWrite(t, filepath.Join(dir, stem+".csr.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	mustWrite(t, filepath.Join(dir, stem+".proof.json"), pj)
}

func std(permitted, excluded []gname) []pkix.Extension {
	return []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), nameConstraints(permitted, excluded), eku(false)}
}

// refusedOrIssued certifies a hand-made request under a root for boards.test and says what came of it. An error of the
// batch is a failure of the test: a request, whatever it holds, is the request's refusal.
func refusedOrIssued(t *testing.T, r *Root, base string, i int, exts []pkix.Extension, pol Policy) string {
	t.Helper()
	reqs, ans := filepath.Join(base, fmt.Sprint("r", i)), filepath.Join(base, fmt.Sprint("a", i))
	handMade(t, reqs, "x", exts)
	outs, err := r.Certify(reqs, ans, time.Now(), pol)
	if err != nil {
		t.Fatalf("the batch stopped: %v", err)
	}
	if outs[0].Issued {
		return "issued"
	}
	if _, err := os.Stat(filepath.Join(ans, "x.cert.pem")); err == nil {
		t.Fatal("a certificate beside a refusal")
	}
	return outs[0].Reasons[0]
}

// The strict shape is key@'s: the names that pass are host names inside the zones with every address excluded, and the
// rest is a refusal.
func TestStrictShape(t *testing.T) {
	base := t.TempDir()
	r, _, err := Init(filepath.Join(base, "root"), time.Now(), []string{"boards.test"})
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		name string
		exts []pkix.Extension
		want string
	}{
		{"the baseline", std([]gname{dnsName("dev.boards.test")}, both), "issued"},
		{"a trailing dot", std([]gname{dnsName("dev.boards.test.")}, both), "policy"},
		{"two dots at the start", std([]gname{dnsName("..boards.test")}, both), "policy"},
		{"two dots inside", std([]gname{dnsName("a..boards.test")}, both), "policy"},
		{"a space", std([]gname{dnsName("a b.boards.test")}, both), "policy"},
		{"a non-ASCII name", std([]gname{dnsName("bücher.boards.test")}, both), "policy"},
		{"a wildcard", std([]gname{dnsName("*.boards.test")}, both), "policy"},
		{"an empty name", std([]gname{dnsName("")}, both), "policy"},
		{"upper case", std([]gname{dnsName("Dev.Boards.Test")}, both), "policy"},
		{"outside the zone", std([]gname{dnsName("example.com")}, both), "policy"},
		{"a suffix of the zone", std([]gname{dnsName("evilboards.test")}, both), "policy"},
		{"only a directory name", std([]gname{{4, []byte{0x30, 0x00}}}, both), "policy"},
		{"only an other name", std([]gname{{0, []byte{6, 1, 0x2a, 0xa0, 0}}}, both), "policy"},
		{"a name and a directory name", std([]gname{dnsName("dev.boards.test"), {4, []byte{0x30, 0x00}}}, both), "policy"},
		{"no IP exclusion", std([]gname{dnsName("dev.boards.test")}, nil), "policy"},
		{"only IPv4 excluded", std([]gname{dnsName("dev.boards.test")}, []gname{allIPv4}), "policy"},
		{"a permitted address range", std([]gname{dnsName("dev.boards.test"), {7, []byte{10, 0, 0, 0, 255, 0, 0, 0}}}, nil), "policy"},
		{"key usage with digital signature", []pkix.Extension{basicConstraints(0), keyUsage(0x86, 8), nameConstraints([]gname{dnsName("dev.boards.test")}, both), eku(false)}, "policy"},
		{"key usage of certificate signing alone", []pkix.Extension{basicConstraints(0), keyUsage(0x04, 6), nameConstraints([]gname{dnsName("dev.boards.test")}, both), eku(false)}, "policy"},
		{"a path length of 1", []pkix.Extension{basicConstraints(1), keyUsage(0x06, 7), nameConstraints([]gname{dnsName("dev.boards.test")}, both), eku(false)}, "policy"},
		{"no extensions", nil, "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusedOrIssued(t, r, base, i, tc.exts, Policy{}); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// The contract's reference shape, for the vectors, is held rule by rule, and a name that is not a name is a refusal too.
func TestContractShape(t *testing.T) {
	base := t.TempDir()
	r, _, err := Init(filepath.Join(base, "root"), time.Now(), []string{"boards.test"})
	if err != nil {
		t.Fatal(err)
	}
	crit := func(e pkix.Extension, critical bool) pkix.Extension { e.Critical = critical; return e }
	good := func() []pkix.Extension { return std([]gname{dnsName("dev.boards.test")}, nil) }
	extra := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: []byte{0x30, 0x00}}
	for i, tc := range []struct {
		name string
		exts []pkix.Extension
		want string
	}{
		{"the baseline, with no IP exclusion", good(), "issued"},
		{"a DNS name with a period at its start", std([]gname{dnsName(".dev.boards.test")}, nil), "policy"},
		{"a URI constraint with a period at its start", std([]gname{{6, []byte(".dev.boards.test")}}, nil), "issued"},
		{"a URI host", std([]gname{{6, []byte("dev.boards.test")}}, nil), "issued"},
		{"a name of the zone itself", std([]gname{dnsName("boards.test")}, nil), "issued"},
		{"a mail domain inside", std([]gname{{1, []byte("dev.boards.test")}}, nil), "policy"},
		{"a mail domain outside", std([]gname{dnsName("dev.boards.test"), {1, []byte("example.org")}}, nil), "policy"},
		{"a URI host outside", std([]gname{{6, []byte("example.org")}}, nil), "policy"},
		{"a DNS name outside", std([]gname{dnsName("dev.boards.test"), dnsName("example.org")}, nil), "policy"},
		{"a permitted address range", std([]gname{dnsName("dev.boards.test"), {7, []byte{10, 0, 0, 0, 255, 0, 0, 0}}}, nil), "policy"},
		{"every IP address excluded", std([]gname{dnsName("dev.boards.test")}, both), "issued"},
		{"every IP address excluded, in the other order", std([]gname{dnsName("dev.boards.test")}, []gname{allIPv6, allIPv4}), "issued"},
		{"only IPv4 excluded", std([]gname{dnsName("dev.boards.test")}, []gname{allIPv4}), "policy"},
		{"only IPv6 excluded", std([]gname{dnsName("dev.boards.test")}, []gname{allIPv6}), "policy"},
		{"every IP address excluded twice", std([]gname{dnsName("dev.boards.test")}, []gname{allIPv4, allIPv4, allIPv6}), "policy"},
		{"every IP address and a DNS name excluded", std([]gname{dnsName("dev.boards.test")}, append(append([]gname{}, both...), dnsName("other.boards.test"))), "policy"},
		{"a DNS name excluded", std([]gname{dnsName("dev.boards.test")}, []gname{dnsName("other.boards.test")}), "policy"},
		{"/0 with a non-zero IPv4 address", std([]gname{dnsName("dev.boards.test")}, []gname{{7, []byte{10, 0, 0, 0, 0, 0, 0, 0}}, allIPv6}), "policy"},
		{"a zero IPv4 address with a non-zero mask", std([]gname{dnsName("dev.boards.test")}, []gname{{7, []byte{0, 0, 0, 0, 255, 0, 0, 0}}, allIPv6}), "policy"},
		{"a 4-octet IP subtree", std([]gname{dnsName("dev.boards.test")}, []gname{{7, make([]byte, 4)}, allIPv6}), "policy"},
		{"a 16-octet IP subtree", std([]gname{dnsName("dev.boards.test")}, []gname{allIPv4, {7, make([]byte, 16)}}), "policy"},
		{"a narrower IP range excluded", std([]gname{dnsName("dev.boards.test")}, []gname{{7, []byte{10, 0, 0, 0, 255, 0, 0, 0}}, allIPv6}), "policy"},
		{"a trailing dot", std([]gname{dnsName("dev.boards.test.")}, nil), "policy"},
		{"a non-ASCII name", std([]gname{dnsName("bücher.boards.test")}, nil), "policy"},
		{"a space in a name", std([]gname{dnsName("a b.boards.test")}, nil), "policy"},
		{"two dots", std([]gname{dnsName("..boards.test")}, nil), "policy"},
		{"basic constraints not critical", []pkix.Extension{crit(basicConstraints(0), false), keyUsage(0x06, 7), good()[2], eku(false)}, "policy"},
		{"key usage not critical", []pkix.Extension{basicConstraints(0), crit(keyUsage(0x06, 7), false), good()[2], eku(false)}, "policy"},
		{"name constraints not critical", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), crit(good()[2], false), eku(false)}, "policy"},
		{"a repeated extension", []pkix.Extension{basicConstraints(0), basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false)}, "policy"},
		{"extended key usage twice", append(good(), eku(false)), "policy"},
		{"no extended key usage", good()[:3], "policy"},
		{"extended key usage critical", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(true)}, "policy"},
		{"extended key usage of clientAuth alone", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, clientAuth)}, "issued"},
		{"extended key usage of serverAuth alone", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, serverAuth)}, "issued"},
		{"extended key usage in the other order", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, clientAuth, serverAuth)}, "issued"},
		{"extended key usage of any purpose", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, anyEKU)}, "policy"},
		{"extended key usage of code signing", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, codeSigning)}, "policy"},
		{"an allowed purpose beside one that is not", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, serverAuth, codeSigning)}, "policy"},
		{"a purpose twice", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], eku(false, serverAuth, serverAuth)}, "policy"},
		{"no purpose", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), good()[2], {Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0x00}}}, "policy"},
		{"a fifth extension", append(good(), extra), "policy"},
		{"key usage missing", []pkix.Extension{basicConstraints(0), good()[2], eku(false)}, "policy"},
		{"a path length of 1", []pkix.Extension{basicConstraints(1), keyUsage(0x06, 7), good()[2], eku(false)}, "policy"},
		{"no certificate signing", []pkix.Extension{basicConstraints(0), keyUsage(0x80, 1), good()[2], eku(false)}, "policy"},
		{"no permitted subtree", std(nil, both), "policy"},
		{"an extension of another kind", []pkix.Extension{basicConstraints(0), keyUsage(0x06, 7), extra, eku(false)}, "policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusedOrIssued(t, r, base, i, tc.exts, Policy{ContractShape: true}); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// A request for the name or the key of the root that would certify it, or of a root of the bundle that the policy names, is refused
// with `policy`: the name as OpenSSL compares names (case and runs of spaces do not matter), and the key whatever the name.
func TestARequestForARootsNameOrKeyIsRefused(t *testing.T) {
	base := t.TempDir()
	r, _, err := Init(filepath.Join(base, "root"), time.Now(), []string{"boards.test"})
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := Init(filepath.Join(base, "other"), time.Now(), []string{"boards.test"})
	if err != nil {
		t.Fatal(err)
	}
	exts := std([]gname{dnsName("dev.boards.test")}, nil)
	certify := func(i int, pol Policy, k *ecdsa.PrivateKey, subject pkix.Name) string {
		reqs, ans := filepath.Join(base, fmt.Sprint("r", i)), filepath.Join(base, fmt.Sprint("a", i))
		handMadeFor(t, reqs, "x", k, subject, exts)
		outs, err := r.Certify(reqs, ans, time.Now(), pol)
		if err != nil {
			t.Fatal(err)
		}
		if outs[0].Issued {
			return "issued"
		}
		return outs[0].Reasons[0]
	}
	fresh := func() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader); return k }
	rootName := pkix.Name{CommonName: r.cert.Subject.CommonName, Organization: r.cert.Subject.Organization}
	pol := Policy{ContractShape: true}
	for i, tc := range []struct {
		name    string
		pol     Policy
		key     *ecdsa.PrivateKey
		subject pkix.Name
		want    string
	}{
		{"a name of its own", pol, fresh(), pkix.Name{CommonName: "dev intermediate"}, "issued"},
		{"the name of the root", pol, fresh(), rootName, "policy"},
		{"the name of the root in capitals", pol, fresh(), pkix.Name{CommonName: strings.ToUpper(rootName.CommonName), Organization: rootName.Organization}, "policy"},
		{"the key of the root", pol, r.key, pkix.Name{CommonName: "dev intermediate"}, "policy"},
		{"the name of another root of the bundle", Policy{ContractShape: true, Roots: []*x509.Certificate{other.cert}}, fresh(), pkix.Name{CommonName: other.cert.Subject.CommonName, Organization: other.cert.Subject.Organization}, "policy"},
		{"the key of another root of the bundle", Policy{ContractShape: true, Roots: []*x509.Certificate{other.cert}}, other.key, pkix.Name{CommonName: "dev intermediate"}, "policy"},
		{"the name of a root the policy does not name", pol, fresh(), pkix.Name{CommonName: other.cert.Subject.CommonName, Organization: other.cert.Subject.Organization}, "issued"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := certify(i, tc.pol, tc.key, tc.subject); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// With a list of entries, a permitted name is inside only when it equals one: a name below an entry, or the entry with a period in front,
// is another entry; without one, the zone and everything below it is inside.
func TestNamesAreComparedWithTheListedEntries(t *testing.T) {
	base := t.TempDir()
	r, _, err := initRoot(filepath.Join(base, "root"), time.Now(), []string{"example.org"})
	if err != nil {
		t.Fatal(err)
	}
	listed := &ListedNames{URIHosts: []string{"example.org", ".example.net"}, DNSNames: []string{"example.org"}}
	uri := func(s string) gname { return gname{6, []byte(s)} }
	for i, tc := range []struct {
		name   string
		listed *ListedNames
		names  []gname
		want   string
	}{
		{"a listed DNS name", listed, []gname{dnsName("example.org")}, "issued"},
		{"a listed URI host", listed, []gname{uri("example.org")}, "issued"},
		{"a listed period and a domain", listed, []gname{uri(".example.net")}, "issued"}, // outside the zone of this root, and listed
		{"a name below a listed DNS name", listed, []gname{dnsName("a.example.org")}, "policy"},
		{"a name below a listed URI host", listed, []gname{uri("a.example.org")}, "policy"},
		{"a listed host with a period in front", listed, []gname{uri(".example.org")}, "policy"},
		{"a DNS name listed only as a URI host", &ListedNames{URIHosts: []string{"example.org"}}, []gname{dnsName("example.org")}, "policy"},
		{"a name that merely ends like an entry", listed, []gname{dnsName("badexample.org")}, "policy"},
		{"the zone and below it with no list", nil, []gname{dnsName("a.example.org"), uri(".example.org")}, "issued"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqs, ans := filepath.Join(base, fmt.Sprint("r", i)), filepath.Join(base, fmt.Sprint("a", i))
			handMade(t, reqs, "x", std(tc.names, nil))
			outs, err := r.Certify(reqs, ans, time.Now(), Policy{ContractShape: true, Listed: tc.listed})
			if err != nil {
				t.Fatal(err)
			}
			got := "issued"
			if !outs[0].Issued {
				got = outs[0].Reasons[0]
			}
			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
