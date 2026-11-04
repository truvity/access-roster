//go:build sluis_test

package exchanged_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/sluis/v2/actors/exchange/internal/exchanged"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// tenantStore is a store@ that keeps items under their tenant, as the kinds of session are.
type tenantStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu    sync.Mutex
	items map[string][]byte
	fail  bool
}

func (s *tenantStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	a := req.Msg.GetAddress()
	v, ok := s.items[addr(a)]
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "not_found", "")
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: &storev2alpha1.Item{Address: a, Version: 1, Value: v}}), nil
}

// openKey is a key@ whose Open returns the plaintext it was set up with for one envelope, and refuses the rest as key@
// does: permission_denied, reason open.
type openKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	mu    sync.Mutex
	opens []*keyv2alpha1.OpenItem
	good  []byte
	plain []byte
}

func (k *openKey) Open(_ context.Context, req *connect.Request[keyv2alpha1.OpenRequest]) (*connect.Response[keyv2alpha1.OpenResponse], error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	it := req.Msg.GetItems()[0]
	k.opens = append(k.opens, it)
	if string(it.GetEnvelope()) != string(k.good) {
		return nil, refusal.New(connect.CodePermissionDenied, "open", "")
	}
	return connect.NewResponse(&keyv2alpha1.OpenResponse{Plaintexts: [][]byte{k.plain}}), nil
}

type dirEnv struct {
	dir   *exchanged.StoreDirectory
	store *tenantStore
	key   *openKey
}

func newDirEnv(t *testing.T) *dirEnv {
	t.Helper()
	d := shortDir(t)
	st := &tenantStore{items: map[string][]byte{}}
	facts, err := proto.Marshal(&sessionv2alpha1.SignInFacts{Accounts: []string{"workforce/alice"}})
	if err != nil {
		t.Fatal(err)
	}
	ky := &openKey{good: []byte("envelope"), plain: facts}
	path, h := storev2alpha1connect.NewStoreServiceHandler(st)
	serve(t, filepath.Join(d, "store.sock"), "exchange", fakeCfg("store"), rpc.Handler{Path: path, H: h})
	path, h = keyv2alpha1connect.NewKeyServiceHandler(ky)
	serve(t, filepath.Join(d, "key.sock"), "exchange", fakeCfg("key"), rpc.Handler{Path: path, H: h})
	sh, surl := rpc.Dial(filepath.Join(d, "store.sock"))
	sc := storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...)
	kh, kurl := rpc.Dial(filepath.Join(d, "key.sock"))
	kc := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)
	cfg, err := exchanged.NewConfig(sc)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := exchanged.NewStoreDirectory(cfg, sc, kc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return &dirEnv{dir: dir, store: st, key: ky}
}

const (
	dirSID     = "sidsidsidsidsidsidsidsid26"
	dirSubject = "personpersonpersonperson26"
)

func (e *dirEnv) put(kind, id string, m proto.Message) {
	var b []byte
	if m != nil {
		var err error
		if b, err = proto.Marshal(m); err != nil {
			panic(err)
		}
	}
	e.store.items[kind+"/"+testTenant+"/"+id] = b
}

// session is the state session leaves after a sign-in: the person, a live chain with its facts.
func (e *dirEnv) session(ends time.Time) {
	e.put("person", dirSubject, nil)
	e.put("session-chain", dirSID, &sessionv2alpha1.SessionChain{
		Subject: dirSubject, ClientId: "sluis-cli", EndsAt: timestamppb.New(ends), SealedFacts: []byte("envelope"),
	})
}

func claimsOf2(over func(*exchanged.Subject)) *exchanged.Subject {
	s := &exchanged.Subject{Kind: exchanged.KindOwn, SID: dirSID, ClientID: "sluis-cli"}
	if over != nil {
		over(s)
	}
	return s
}

func TestStoreDirectoryFindsThePersonOfALiveChain(t *testing.T) {
	e := newDirEnv(t)
	e.session(t0.Add(time.Hour))
	p, err := e.dir.Person(context.Background(), testTenant, claimsOf2(nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != dirSubject || p.State != "live" || p.Org != testTenant || len(p.Accounts) != 1 || p.Accounts[0] != "workforce/alice" {
		t.Errorf("person = %+v", p)
	}
	// The facts are opened under the boundary's data key: purpose data, no tenant, at the chain's address.
	if len(e.key.opens) != 1 {
		t.Fatalf("%d opens", len(e.key.opens))
	}
	it := e.key.opens[0]
	if it.GetPurpose() != "data" || it.GetAddress().GetTenant() != "" || it.GetAddress().GetKind() != "session-chain" || it.GetAddress().GetId() != dirSID {
		t.Errorf("open = %v", it)
	}
}

func TestStoreDirectoryReportsAHeldPerson(t *testing.T) {
	e := newDirEnv(t)
	e.session(t0.Add(time.Hour))
	e.put("person-hold", dirSubject, nil)
	p, err := e.dir.Person(context.Background(), testTenant, claimsOf2(nil))
	if err != nil || p.State != "held" {
		t.Fatalf("person = %+v, %v", p, err)
	}
}

func TestStoreDirectoryRefusals(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*dirEnv)
		subj  func(*exchanged.Subject)
		want  error
	}{
		{"no chain", func(*dirEnv) {}, nil, exchanged.ErrSessionEnded},
		{"the chain is past its end", func(e *dirEnv) { e.session(t0.Add(-time.Second)) }, nil, exchanged.ErrSessionEnded},
		{"the token has no sid", func(e *dirEnv) { e.session(t0.Add(time.Hour)) }, func(s *exchanged.Subject) { s.SID = "" }, exchanged.ErrUnknownPerson},
		{"the chain is another client's", func(e *dirEnv) { e.session(t0.Add(time.Hour)) }, func(s *exchanged.Subject) { s.ClientID = "other" }, exchanged.ErrUnknownPerson},
		{"no person", func(e *dirEnv) {
			e.session(t0.Add(time.Hour))
			delete(e.store.items, "person/"+testTenant+"/"+dirSubject)
		}, nil, exchanged.ErrUnknownPerson},
		{"facts that do not open", func(e *dirEnv) { e.session(t0.Add(time.Hour)); e.key.good = []byte("other") }, nil, exchanged.ErrSessionEnded},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newDirEnv(t)
			c.setup(e)
			_, err := e.dir.Person(context.Background(), testTenant, claimsOf2(c.subj))
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestStoreDirectoryOutageIsNotAnAnswer(t *testing.T) {
	e := newDirEnv(t)
	e.session(t0.Add(time.Hour))
	e.store.fail = true
	_, err := e.dir.Person(context.Background(), testTenant, claimsOf2(nil))
	if err == nil || errors.Is(err, exchanged.ErrSessionEnded) || errors.Is(err, exchanged.ErrUnknownPerson) {
		t.Fatalf("err = %v, want an outage", err)
	}
}

func TestStoreDirectoryCheck(t *testing.T) {
	e := newDirEnv(t)
	e.store.items["boundary//default"] = mustMarshal(t, &configv2alpha1.Boundary{Name: testBoundary, DefaultTenant: testTenant})
	if err := e.dir.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.store.fail = true
	if err := e.dir.Check(context.Background()); err == nil {
		t.Fatal("a directory that cannot read store@ is bound")
	}
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
