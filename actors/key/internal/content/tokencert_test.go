package content_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/actors/key/internal/content"
	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/tokencert"
)

// A throwaway intermediate and token key, and the rules key@ would hold for them. The boundary and the dates are random,
// so that a rule that only holds for one value shows.
type fixture struct {
	t        *testing.T
	interKey *ecdsa.PrivateKey
	inter    *x509.Certificate
	tokenKey *ecdsa.PrivateKey
	spki     []byte
	rules    content.TokenCertificateRules
	now      time.Time
}

func randomBoundary(t *testing.T) string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789-"
	out := []byte("b")
	for _, c := range b {
		out = append(out, alpha[int(c)%len(alpha)])
	}
	return string(out)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(1, 1, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ik.PublicKey, ik)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(der)
	spki, _ := x509.MarshalPKIXPublicKey(&tk.PublicKey)
	return &fixture{t: t, interKey: ik, inter: inter, tokenKey: tk, spki: spki, now: now, rules: content.TokenCertificateRules{
		Issuer: inter.RawSubject, IssuerKeyID: inter.SubjectKeyId, SPKI: spki, Boundary: randomBoundary(t),
		IssuerNotBefore: inter.NotBefore, IssuerNotAfter: inter.NotAfter, Now: now,
	}}
}

func (f *fixture) params() tokencert.Params {
	serial, err := tokencert.NewSerial(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return tokencert.Params{
		Serial: serial, Issuer: f.rules.Issuer, IssuerKeyID: f.rules.IssuerKeyID, SPKI: f.spki, Boundary: f.rules.Boundary,
		NotBefore: f.now.Add(-time.Minute), NotAfter: f.inter.NotAfter,
	}
}

func (f *fixture) tbs(p tokencert.Params) []byte {
	f.t.Helper()
	b, err := tokencert.TBS(p)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) sign(tbs []byte) []byte {
	d := sha512.Sum384(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, f.interKey, d[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return tokencert.Assemble(tbs, sig)
}

// verifies: REQ-ISO-006
// The certificate the builder makes passes, and the standard library reads it as a certificate that is not a CA, allows
// digital signatures only, has no name and verifies under the intermediate.
func TestTokenCertificateAcceptsTheBuildersAndTheStandardLibraryReadsItAsNonCA(t *testing.T) {
	for range 40 {
		f := newFixture(t)
		p := f.params()
		tbs := f.tbs(p)
		if err := content.TokenCertificate(tbs, f.rules); err != nil {
			t.Fatalf("the builder's TBSCertificate was refused: %v", err)
		}
		c, err := content.CheckTokenCertificate(f.sign(tbs), f.rules, f.inter)
		if err != nil {
			t.Fatalf("the finished certificate was refused: %v", err)
		}
		if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 0 ||
			c.Subject.CommonName != "token-signing" || len(c.Subject.OrganizationalUnit) != 1 || c.Subject.OrganizationalUnit[0] != "signer@"+f.rules.Boundary ||
			c.Version != 3 || c.SignatureAlgorithm != x509.ECDSAWithSHA384 || c.SerialNumber.BitLen() < 121 || c.SerialNumber.BitLen() > 128 {
			t.Fatalf("the certificate is not the profile: %+v", c)
		}
		if err := c.CheckSignatureFrom(f.inter); err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(f.inter)
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: f.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			// The intermediate is not a root, but it is an anchor of this pool: the path of two links verifies.
			t.Fatalf("the path does not verify: %v", err)
		}
	}
}

// An intermediate with no subject key identifier gets a certificate with no authority key identifier, and it passes.
func TestTokenCertificateWithoutAnIssuerKeyIdentifier(t *testing.T) {
	f := newFixture(t)
	f.rules.IssuerKeyID = nil
	p := f.params()
	p.IssuerKeyID = nil
	if err := content.TokenCertificate(f.tbs(p), f.rules); err != nil {
		t.Fatal(err)
	}
	// And a certificate that carries one the rules do not name is not the one key@ signs.
	p.IssuerKeyID = []byte{9, 9, 9}
	if err := content.TokenCertificate(f.tbs(p), f.rules); err == nil {
		t.Fatal("an authority key identifier the intermediate does not have was accepted")
	}
}

// verifies: REQ-ISO-006
// What key@ is asked to sign and refuses: a certificate of another shape, whatever the signing key would make of it.
func TestTokenCertificateRefusesEveryOtherShape(t *testing.T) {
	f := newFixture(t)
	good := f.params()
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	std := func(mod func(*x509.Certificate)) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: new(big.Int).Lsh(big.NewInt(1), 126), Subject: pkix.Name{CommonName: "token-signing", OrganizationalUnit: []string{"signer@" + f.rules.Boundary}},
			NotBefore: good.NotBefore, NotAfter: good.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, AuthorityKeyId: f.inter.SubjectKeyId,
		}
		mod(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.inter, &f.tokenKey.PublicKey, f.interKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c.RawTBSCertificate
	}
	withP := func(mod func(*tokencert.Params)) []byte {
		p := good
		mod(&p)
		b, err := tokencert.TBS(p)
		if err != nil {
			return nil
		}
		return b
	}
	cri, _ := handoff.CertificationRequestInfo(f.spki, handoff.RequestSpec{
		Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"}, Constraints: handoff.Constraints{URIHosts: []string{"dev.example.org"}, DNS: []string{"dev.example.org"}},
	})
	u, _ := url.Parse("spiffe://dev.example.org/ns/x")
	cases := map[string][]byte{
		// the profile
		"a CA":                     std(func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }),
		"a CA with the usage":      std(func(c *x509.Certificate) { c.IsCA = true }),
		"cert sign usage":          std(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }),
		"two usages":               std(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment }),
		"a server EKU":             std(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }),
		"a DNS name":               std(func(c *x509.Certificate) { c.DNSNames = []string{"a.example.org"} }),
		"an IP address":            std(func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }),
		"a URI name":               std(func(c *x509.Certificate) { c.URIs = []*url.URL{u} }),
		"a subject key identifier": std(func(c *x509.Certificate) { c.SubjectKeyId = []byte{1, 2, 3} }),
		"a name constraint": std(func(c *x509.Certificate) {
			c.PermittedDNSDomains = []string{"example.org"}
			c.PermittedDNSDomainsCritical = true
		}),
		"another subject":           std(func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "other"} }),
		"a second OU":               std(func(c *x509.Certificate) { c.Subject.OrganizationalUnit = append(c.Subject.OrganizationalUnit, "x") }),
		"the standard encoding too": std(func(*x509.Certificate) {}), // Go writes the names and the extensions in its own order: not the one key@ rebuilds
		// what the caller chooses
		"another key":                     withP(func(p *tokencert.Params) { p.SPKI = otherSPKI }),
		"another issuer":                  withP(func(p *tokencert.Params) { p.Issuer = []byte{0x30, 0x00} }),
		"another boundary":                withP(func(p *tokencert.Params) { p.Boundary = f.rules.Boundary + "x" }),
		"serial 1":                        withP(func(p *tokencert.Params) { p.Serial = []byte{1} }),
		"serial 64 bits":                  withP(func(p *tokencert.Params) { p.Serial = []byte{0x7f, 1, 2, 3, 4, 5, 6, 7} }),
		"serial 120 bits":                 withP(func(p *tokencert.Params) { p.Serial = append([]byte{0, 0x80}, make([]byte, 14)...) }),
		"serial 129 bits":                 withP(func(p *tokencert.Params) { p.Serial = append([]byte{1}, make([]byte, 16)...) }),
		"serial negative":                 withP(func(p *tokencert.Params) { p.Serial = append([]byte{0x80}, make([]byte, 15)...) }),
		"serial padded":                   withP(func(p *tokencert.Params) { p.Serial = append([]byte{0, 0x40}, make([]byte, 15)...) }),
		"serial zero":                     withP(func(p *tokencert.Params) { p.Serial = []byte{0} }),
		"ends after issuer":               withP(func(p *tokencert.Params) { p.NotAfter = f.inter.NotAfter.Add(time.Second) }),
		"ends before issuer":              withP(func(p *tokencert.Params) { p.NotAfter = f.inter.NotAfter.Add(-time.Second) }),
		"ends in a day":                   withP(func(p *tokencert.Params) { p.NotAfter = f.now.Add(24 * time.Hour) }),
		"backdated 11 min":                withP(func(p *tokencert.Params) { p.NotBefore = f.now.Add(-11 * time.Minute) }),
		"backdated to the issuer's start": withP(func(p *tokencert.Params) { p.NotBefore = f.inter.NotBefore }),
		"starts before it":                withP(func(p *tokencert.Params) { p.NotBefore = f.inter.NotBefore.Add(-time.Second) }),
		"starts in 10 min":                withP(func(p *tokencert.Params) { p.NotBefore = f.now.Add(10 * time.Minute) }),
		"already ended":                   withP(func(p *tokencert.Params) { p.NotBefore = f.inter.NotBefore; p.NotAfter = f.now.Add(-time.Second) }),
		// other things key@ signs, or could be asked to
		"a CertificationRequestInfo": cri,
		"a JWS signing input":        []byte("eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJ4In0"),
		"empty":                      nil,
		"a lone byte":                {0x30},
		"an empty sequence":          {0x30, 0x00},
		"a long zero run":            make([]byte, 600),
	}
	for name, in := range cases {
		if in == nil && name != "empty" {
			continue // the builder itself refused it: it could not be asked
		}
		if err := content.TokenCertificate(in, f.rules); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A certificate with under an hour to run is not made, and neither is one under an intermediate that ends in 2050 or
	// later, which UTCTime cannot write (the builder refuses it too).
	short := *f
	short.rules.IssuerNotAfter = f.now.Add(30 * time.Minute)
	sp := f.params()
	sp.NotAfter = short.rules.IssuerNotAfter
	if err := content.TokenCertificate(f.tbs(sp), short.rules); err == nil {
		t.Error("a certificate that lives half an hour was accepted")
	}
	long := *f
	long.rules.IssuerNotAfter = time.Date(2050, 6, 1, 0, 0, 0, 0, time.UTC)
	lp := f.params()
	lp.NotAfter = time.Date(2049, 12, 31, 0, 0, 0, 0, time.UTC)
	if err := content.TokenCertificate(f.tbs(lp), long.rules); err == nil {
		t.Error("a certificate under an intermediate that ends in 2050 was accepted")
	}
	// trailing bytes, truncation and a second structure
	if err := content.TokenCertificate(append(f.tbs(good), 0), f.rules); err == nil {
		t.Error("a trailing byte was accepted")
	}
	tbs := f.tbs(good)
	for n := range len(tbs) {
		if err := content.TokenCertificate(tbs[:n], f.rules); err == nil {
			t.Errorf("a truncation to %d bytes was accepted", n)
		}
	}
	// The reason for a CertificationRequestInfo is its own.
	err := content.TokenCertificate(cri, f.rules)
	var ce *content.ErrContent
	if !errors.As(err, &ce) || ce.Path != "content.kind" {
		t.Errorf("a CertificationRequestInfo: %v", err)
	}
}

// verifies: REQ-ISO-006
// The reason it matters: the same key signs a CertificationRequestInfo (SignRequest) and a TBSCertificate (Sign). No
// byte string passes both checks, and each refuses the other's valid input and the mutations of it.
func TestTheRequestInfoCheckAndTheCertificateCheckNeverBothAccept(t *testing.T) {
	f := newFixture(t)
	spec := handoff.RequestSpec{
		Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"}, Constraints: handoff.Constraints{URIHosts: []string{"dev.example.org"}, DNS: []string{"dev.example.org"}},
	}
	// The info is for the intermediate's own key; the certificate is for the token key. Both checks take their key from
	// key@, so the keys differ and the structures are tried against both.
	cri, err := handoff.CertificationRequestInfo(f.spki, spec)
	if err != nil {
		t.Fatal(err)
	}
	tbs := f.tbs(f.params())
	both := func(in []byte) (bool, bool) {
		return handoff.CheckInfo(in, f.spki) == nil, content.TokenCertificate(in, f.rules) == nil
	}
	if a, b := both(cri); !a || b {
		t.Fatalf("the info: CheckInfo %v, TokenCertificate %v", a, b)
	}
	if a, b := both(tbs); a || !b {
		t.Fatalf("the TBSCertificate: CheckInfo %v, TokenCertificate %v", a, b)
	}
	// Mutations of both, byte by byte and at random positions, with real random values.
	for _, base := range [][]byte{cri, tbs} {
		for i := range base {
			for _, x := range []byte{0x01, 0x80, 0xff} {
				m := append([]byte(nil), base...)
				m[i] ^= x
				if a, b := both(m); a && b {
					t.Fatalf("a mutation at %d passes both checks", i)
				}
			}
		}
		for range 2000 {
			var r [16]byte
			_, _ = rand.Read(r[:])
			m := append([]byte(nil), base...)
			for k := range 1 + int(r[0])%4 {
				m[int(binary.BigEndian.Uint16(r[2+2*k:]))%len(m)] = r[10+k]
			}
			if a, b := both(m); a && b {
				t.Fatal("a random mutation passes both checks")
			}
		}
	}
}

// verifies: REQ-ISO-006
// Whatever bytes are accepted, the standard library reads them as the profile: a mutation of the valid TBSCertificate is
// either refused or differs only in what the caller may choose (the serial and the dates), and is never a CA, never wider.
func TestTokenCertificateMutationsAreRefusedOrStillTheProfile(t *testing.T) {
	f := newFixture(t)
	tbs := f.tbs(f.params())
	accepted := 0
	check := func(m []byte) {
		if content.TokenCertificate(m, f.rules) != nil {
			return
		}
		accepted++
		c, err := content.CheckTokenCertificate(f.sign(m), f.rules, f.inter)
		if err != nil {
			t.Fatalf("accepted TBS whose certificate fails: %v", err)
		}
		if c.IsCA || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 0 {
			t.Fatal("an accepted mutation is not the profile")
		}
	}
	for i := range tbs {
		for _, x := range []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff} {
			m := append([]byte(nil), tbs...)
			m[i] ^= x
			check(m)
		}
	}
	for range 5000 {
		m := append([]byte(nil), tbs...)
		var r [3]byte
		_, _ = rand.Read(r[:])
		m[int(r[0])*len(m)/256] = r[1]
		m[int(r[2])*len(m)/256] ^= r[1] | 1
		check(m)
	}
	if accepted == 0 {
		t.Fatal("no mutation of the serial or of the dates was accepted: the test does not reach the fields the caller chooses")
	}
	// Real random garbage of the size of a certificate is refused.
	for range 2000 {
		g := make([]byte, 300+int(time.Now().UnixNano()%200))
		_, _ = rand.Read(g)
		if content.TokenCertificate(g, f.rules) == nil {
			t.Fatal("random bytes were accepted")
		}
	}
}

// verifies: REQ-ISO-006
// A certificate never starts before the intermediate does, even where ten minutes of backdating would reach back that far
// (an intermediate made a minute ago), and never starts in the future: a certificate that has not begun would make key@
// withdraw the chain it gives, and a signature must not be a way to cause that.
func TestTokenCertificateStartsNeitherBeforeTheIntermediateNorInTheFuture(t *testing.T) {
	f := newFixture(t)
	f.rules.IssuerNotBefore = f.now.Add(-2 * time.Minute)
	p := f.params()
	p.NotBefore = f.now.Add(-5 * time.Minute)
	if err := content.TokenCertificate(f.tbs(p), f.rules); err == nil {
		t.Error("a certificate that starts before its intermediate was accepted")
	}
	p.NotBefore = f.now.Add(-2 * time.Minute)
	if err := content.TokenCertificate(f.tbs(p), f.rules); err != nil {
		t.Errorf("a certificate that starts with its intermediate was refused: %v", err)
	}
	for _, ahead := range []time.Duration{time.Second, 4 * time.Minute, 5 * time.Minute, time.Hour} {
		p.NotBefore = f.now.Add(ahead)
		if err := content.TokenCertificate(f.tbs(p), f.rules); err == nil {
			t.Errorf("a certificate that starts %v ahead was accepted", ahead)
		}
	}
}
