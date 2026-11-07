package cad

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// fakeStore keeps KeyCertificate items. A Get of an item counts: ca never asks for one.
type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu    sync.Mutex
	items map[string]*keyv2alpha1.KeyCertificate
	gets  int
	lists int
	fail  bool
}

func (f *fakeStore) Get(context.Context, *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	return nil, connect.NewError(connect.CodeNotFound, errors.New("absent"))
}

func (f *fakeStore) List(_ context.Context, req *connect.Request[storev2alpha1.ListRequest]) (*connect.Response[storev2alpha1.ListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	if f.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}
	var out []*storev2alpha1.Item
	for id, v := range f.items {
		b, _ := proto.Marshal(v)
		out = append(out, &storev2alpha1.Item{Address: &typev2alpha1.Address{Kind: req.Msg.GetKind(), Id: id}, Version: 1, Value: b})
	}
	return connect.NewResponse(&storev2alpha1.ListResponse{Items: out}), nil
}

// fakeKeys is key@ as ca sees it: real keys and real signatures, and the same chain rule as key@'s PublicKey. It checks
// the certificate it is handed as a verifier would, with the standard library, and stores it as key@ does.
type fakeKeys struct {
	keyv2alpha1connect.KeyServiceClient
	t         *testing.T
	st        *fakeStore
	inter     *ecdsa.PrivateKey
	token     *ecdsa.PrivateKey
	boundary  string
	now       func() time.Time
	signs     []([]byte)
	puts      int
	signErr   error
	wrongKey  bool
	noPlan    bool // the KeyPlan has no intermediate
	noToken   bool // the KeyPlan has no token-signing key
	refuseAll bool
}

func spkiOf(k *ecdsa.PrivateKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return b
}

// TokenKey gives the chain by the rule of key@'s PublicKey: the stored certificate fits this key, is valid and ends in the
// installed intermediate.
func (k *fakeKeys) TokenKey(context.Context, *connect.Request[keyv2alpha1.TokenKeyRequest]) (*connect.Response[keyv2alpha1.TokenKeyResponse], error) {
	if k.noToken {
		return connect.NewResponse(&keyv2alpha1.TokenKeyResponse{}), nil
	}
	out := &keyv2alpha1.TokenKeyResponse{SpkiDer: spkiOf(k.token)}
	if !k.noPlan {
		out.IntermediateSpkiDer = spkiOf(k.inter)
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	tok, inter := k.st.items["token"], k.st.items["inter"]
	if tok != nil && inter != nil {
		ic, e1 := x509.ParseCertificate(inter.Chain[0])
		c, e2 := x509.ParseCertificate(tok.Chain[0])
		if e1 == nil && e2 == nil && c.CheckSignatureFrom(ic) == nil && !k.now().Before(c.NotBefore) && k.now().Before(c.NotAfter) {
			out.Chain = append([][]byte{tok.Chain[0]}, inter.Chain...)
		}
	}
	return connect.NewResponse(out), nil
}

func (k *fakeKeys) Sign(_ context.Context, req *connect.Request[keyv2alpha1.SignRequest]) (*connect.Response[keyv2alpha1.SignResponse], error) {
	if k.signErr != nil {
		return nil, k.signErr
	}
	if req.Msg.GetPurpose() != "x509-intermediate" || req.Msg.GetAlgorithm() != "ES384" {
		k.t.Errorf("Sign(%q, %q)", req.Msg.GetPurpose(), req.Msg.GetAlgorithm())
	}
	// What a verifier makes of the TBS: wrap it in a certificate with a dummy signature and read it with the standard library.
	tbs := req.Msg.GetContent()
	k.signs = append(k.signs, tbs)
	d := sha512.Sum384(tbs)
	signer := k.inter
	if k.wrongKey {
		signer = k.token
	}
	sig, _ := ecdsa.SignASN1(rand.Reader, signer, d[:])
	return connect.NewResponse(&keyv2alpha1.SignResponse{SignatureDer: sig}), nil
}

func (k *fakeKeys) PutCertificate(_ context.Context, req *connect.Request[keyv2alpha1.PutCertificateRequest]) (*connect.Response[keyv2alpha1.PutCertificateResponse], error) {
	if k.refuseAll {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("content"))
	}
	k.puts++
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	inter := k.st.items["inter"]
	k.st.items["token"] = &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: spkiOf(k.token), Chain: append([][]byte{req.Msg.GetCertificate()}, inter.Chain...)}
	return connect.NewResponse(&keyv2alpha1.PutCertificateResponse{}), nil
}

type fixture struct {
	t     *testing.T
	st    *fakeStore
	keys  *fakeKeys
	w     *Worker
	clock time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	f := &fixture{t: t, st: &fakeStore{items: map[string]*keyv2alpha1.KeyCertificate{}}, clock: time.Now().UTC().Truncate(time.Second)}
	f.keys = &fakeKeys{t: t, st: f.st, inter: ik, token: tk, boundary: "dev", now: func() time.Time { return f.clock }}
	sc, surl := storeClient(f.st)
	w, err := New(Options{Boundary: "dev", Store: sc, Keys: f.keys, Now: func() time.Time { return f.clock }})
	_ = surl
	if err != nil {
		t.Fatal(err)
	}
	f.w = w
	return f
}

// install puts an intermediate chain, valid around the clock for the given months, as `key install` does.
func (f *fixture) install(months int) *x509.Certificate {
	f.t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root (TEST ONLY)"}, NotBefore: f.clock.AddDate(-5, 0, 0), NotAfter: f.clock.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rder)
	it := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"}, NotBefore: f.clock.Add(-time.Hour), NotAfter: f.clock.AddDate(0, months, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, it, root, &f.keys.inter.PublicKey, rk)
	if err != nil {
		f.t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	f.st.mu.Lock()
	f.st.items["inter"] = &keyv2alpha1.KeyCertificate{Purpose: "x509-intermediate", SpkiDer: spkiOf(f.keys.inter), Chain: [][]byte{der}}
	f.st.mu.Unlock()
	return c
}

// verifies: REQ-PKI-002, REQ-PKI-036
// With no intermediate installed ca waits and asks key@ to sign nothing; once there is one it makes the token certificate
// once: not a CA, digital signature only, no name, 121 to 128 bit serial from the random source, verifying under the
// intermediate, for the token key, ending with the intermediate. It then settles and asks for nothing more. It never asks store@ for an item by id.
func TestWaitsThenMakesTheTokenCertificateOnceAndSettles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for range 3 {
		st, err := f.w.Once(ctx)
		if err != nil || st != StateWaiting || len(f.keys.signs) != 0 {
			t.Fatalf("with no intermediate: state %v, err %v, %d signatures", st, err, len(f.keys.signs))
		}
	}
	inter := f.install(13)
	st, err := f.w.Once(ctx)
	if err != nil || st != StateIssued || len(f.keys.signs) != 1 || f.keys.puts != 1 {
		t.Fatalf("with an intermediate: state %v, err %v, %d signatures, %d puts", st, err, len(f.keys.signs), f.keys.puts)
	}
	tokenItem := f.st.items["token"]
	c, err := x509.ParseCertificate(tokenItem.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSignatureFrom(inter); err != nil {
		t.Fatal(err)
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 0 ||
		len(c.DNSNames)+len(c.URIs)+len(c.IPAddresses)+len(c.EmailAddresses) != 0 || c.Version != 3 || c.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Fatalf("not the profile: %+v", c)
	}
	if !bytes.Equal(c.RawSubjectPublicKeyInfo, spkiOf(f.keys.token)) || !c.NotAfter.Equal(inter.NotAfter) || c.NotBefore.Before(inter.NotBefore) || c.NotBefore.After(f.clock) {
		t.Fatalf("key or validity: %v to %v", c.NotBefore, c.NotAfter)
	}
	if c.Subject.CommonName != "token-signing" || len(c.Subject.OrganizationalUnit) != 1 || c.Subject.OrganizationalUnit[0] != "signer@dev" {
		t.Fatalf("subject %v", c.Subject)
	}
	if n := c.SerialNumber.BitLen(); n < 121 || n > 128 {
		t.Fatalf("serial of %d bits", n)
	}
	// Settled: key@ gives the chain, and nothing more is signed or listed for it.
	lists := f.st.lists
	for range 5 {
		st, err := f.w.Once(ctx)
		if err != nil || st != StateSettled {
			t.Fatalf("after: state %v, err %v", st, err)
		}
	}
	if len(f.keys.signs) != 1 || f.st.lists != lists {
		t.Fatalf("a settled ca did more: %d signatures, %d lists", len(f.keys.signs), f.st.lists-lists)
	}
	if f.st.gets != 0 {
		t.Fatalf("%d Gets of an item by id", f.st.gets)
	}
}

// A renewal of the intermediate (installed over the same key, a later end) makes the certificate older than the intermediate. key@
// still gives it, so that the key set has no gap, but it ends before the intermediate does, and ca makes the certificate again
// over the same key, ending with the new intermediate; key@ allows it because it ends later.
func TestMakesTheCertificateAgainWhenTheIntermediateIsRenewed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.install(13)
	if st, err := f.w.Once(ctx); err != nil || st != StateIssued {
		t.Fatal(st, err)
	}
	renewed := f.install(14)
	st, err := f.w.Once(ctx)
	if err != nil || st != StateIssued || len(f.keys.signs) != 2 {
		t.Fatalf("after renewal: %v %v, %d signatures", st, err, len(f.keys.signs))
	}
	c, _ := x509.ParseCertificate(f.st.items["token"].Chain[0])
	if !c.NotAfter.Equal(renewed.NotAfter) {
		t.Fatal("the new certificate does not end with the new intermediate")
	}
	if st, err := f.w.Once(ctx); err != nil || st != StateSettled {
		t.Fatalf("then: %v %v", st, err)
	}
}

// A stored certificate that fits, which key@ did not give (its read of the store failed a moment ago), is not made twice.
func TestDoesNotMakeASecondCertificateWhenOneIsStoredAndFits(t *testing.T) {
	f := newFixture(t)
	f.install(13)
	ctx := context.Background()
	if _, err := f.w.Once(ctx); err != nil {
		t.Fatal(err)
	}
	// key@ gives no chain, though the item is there.
	hide := &hidingKeys{fakeKeys: f.keys}
	f.w.o.Keys = hide
	st, err := f.w.Once(ctx)
	if err != nil || st != StateSettled || len(f.keys.signs) != 1 {
		t.Fatalf("%v %v, %d signatures", st, err, len(f.keys.signs))
	}
}

type hidingKeys struct{ *fakeKeys }

func (h *hidingKeys) TokenKey(ctx context.Context, req *connect.Request[keyv2alpha1.TokenKeyRequest]) (*connect.Response[keyv2alpha1.TokenKeyResponse], error) {
	r, err := h.fakeKeys.TokenKey(ctx, req)
	if err == nil {
		r.Msg.Chain = nil
	}
	return r, err
}

// Failures are errors for the loop to back off from, nothing is audited and nothing is stored; an intermediate that has
// ended is waited for, not signed under.
func TestFailuresMakeNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.install(13)
	f.keys.signErr = connect.NewError(connect.CodeInvalidArgument, errors.New("content"))
	if st, err := f.w.Once(ctx); err == nil || st == StateIssued || f.st.items["token"] != nil {
		t.Fatalf("a refused signature: %v %v", st, err)
	}
	f.keys.signErr = nil
	f.keys.wrongKey = true // a signature that does not make a certificate of the intermediate is not handed on
	if _, err := f.w.Once(ctx); err == nil || f.keys.puts != 0 {
		t.Fatalf("a wrong signature: %v, %d puts", err, f.keys.puts)
	}
	f.keys.wrongKey = false
	f.keys.refuseAll = true
	if _, err := f.w.Once(ctx); err == nil {
		t.Fatalf("a refused write: %v", err)
	}
	f.keys.refuseAll = false
	f.st.fail = true
	if _, err := f.w.Once(ctx); err == nil {
		t.Fatal("a store that is down is not an error")
	}
	f.st.fail = false
	f.clock = f.clock.AddDate(2, 0, 0) // the intermediate has ended
	signs := len(f.keys.signs)
	if st, err := f.w.Once(ctx); err != nil || st != StateWaiting || len(f.keys.signs) != signs {
		t.Fatalf("an ended intermediate: %v %v", st, err)
	}
}

// The wait after a failure doubles up to a quarter of an hour, so that a refusal that repeats is at most a few records an
// hour; after a success it is short while waiting for an intermediate and long once the chain is in place.
func TestTheWaitBacksOffAndIsBounded(t *testing.T) {
	bad := errors.New("x")
	w := Waiting
	var seen []time.Duration
	for range 12 {
		w = nextWait(w, StateWaiting, bad)
		seen = append(seen, w)
	}
	if seen[0] != 2*Waiting || seen[1] != 4*Waiting || seen[len(seen)-1] != MaxBackoff {
		t.Fatalf("waits %v", seen)
	}
	var total time.Duration
	var n int
	for total = 0; total < time.Hour; n++ {
		total += seen[min(n, len(seen)-1)]
	}
	// From a cold start the failures come to at most 12 an hour; each one is at most one refusal record of key@ (a few
	// in the first minutes and then 4 an hour at the cap), against the 60 an hour of an idle board.
	if n > 12 {
		t.Fatalf("%d attempts in the first hour of failures", n)
	}
	if got := nextWait(MaxBackoff, StateWaiting, nil); got != Waiting {
		t.Fatalf("after a success while waiting: %v", got)
	}
	if got := nextWait(Waiting, StateSettled, nil); got != Settled {
		t.Fatalf("settled: %v", got)
	}
	if got := nextWait(Waiting, StateIssued, nil); got != Settled {
		t.Fatalf("issued: %v", got)
	}
}

// Check names the sockets that cannot be reached, and calls nothing on those that can: a health check is not a request.
func TestCheckDialsAndCallsNothing(t *testing.T) {
	dir, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var accepted atomic.Int32
	listen := func(name string) string {
		p := filepath.Join(dir, name)
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				buf := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if n, _ := c.Read(buf); n > 0 {
					t.Error("the check sent bytes")
				}
				_ = c.Close()
			}
		}()
		return p
	}
	good := map[string]string{"store": listen("s"), "key": listen("k"), "transport": listen("t")}
	if bad := Check(context.Background(), good); len(bad) != 0 {
		t.Fatalf("%v", bad)
	}
	good["key"] = filepath.Join(dir, "none")
	if bad := Check(context.Background(), good); len(bad) != 1 || bad[0] != "key" {
		t.Fatalf("%v", bad)
	}
}

// A plan without a token-signing key is waited under, with no refusal: key@ answers empty and ca asks for nothing more.
func TestAPlanWithoutATokenKeyIsWaitedUnder(t *testing.T) {
	f := newFixture(t)
	f.keys.noToken = true
	f.install(13)
	if st, err := f.w.Once(context.Background()); err != nil || st != StateWaiting || len(f.keys.signs) != 0 {
		t.Fatalf("%v %v, %d signatures", st, err, len(f.keys.signs))
	}
}

// An intermediate with less than an hour left is waited under: nothing is signed for a certificate that would be of no use.
func TestAnIntermediateAboutToEndGetsNoCertificate(t *testing.T) {
	f := newFixture(t)
	f.install(13)
	f.clock = f.clock.AddDate(0, 13, 0).Add(-30 * time.Minute)
	if st, err := f.w.Once(context.Background()); err != nil || st != StateWaiting || len(f.keys.signs) != 0 {
		t.Fatalf("%v %v, %d signatures", st, err, len(f.keys.signs))
	}
}

// With no intermediate in the KeyPlan, ca waits and asks key@ for nothing but TokenKey: it makes no call that key@ would refuse.
func TestAPlanWithoutAnIntermediateIsWaitedUnder(t *testing.T) {
	f := newFixture(t)
	f.keys.noPlan = true
	f.install(13)
	for range 3 {
		if st, err := f.w.Once(context.Background()); err != nil || st != StateWaiting || len(f.keys.signs) != 0 {
			t.Fatalf("%v %v, %d signatures", st, err, len(f.keys.signs))
		}
	}
}
