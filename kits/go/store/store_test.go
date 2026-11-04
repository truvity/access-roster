//go:build sluis_test

package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// fake is an in-memory StoreServiceHandler. It checks nothing but the verbs' conditions; the rules of store@ are
// its own tests'.
type fake struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu    sync.Mutex
	items map[string]*storev2alpha1.Item
	seen  []*storev2alpha1.WriteRequest
	reads []*storev2alpha1.GetRequest
	lists []*storev2alpha1.ListRequest
}

func key(a *typev2alpha1.Address) string { return a.GetTenant() + "/" + a.GetKind() + "/" + a.GetId() }

func (f *fake) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, req.Msg)
	it, ok := f.items[key(req.Msg.GetAddress())]
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "")
	}
	if n := req.Msg.GetIfNoneMatch(); n != 0 && n == it.GetVersion() {
		return connect.NewResponse(&storev2alpha1.GetResponse{Unchanged: true}), nil
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: it}), nil
}

func (f *fake) List(_ context.Context, req *connect.Request[storev2alpha1.ListRequest]) (*connect.Response[storev2alpha1.ListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists = append(f.lists, req.Msg)
	var all []*storev2alpha1.Item
	for _, it := range f.items {
		a := it.GetAddress()
		if a.GetKind() == req.Msg.GetKind() && a.GetTenant() == req.Msg.GetTenant() {
			all = append(all, it)
		}
	}
	// Order by id: a stable listing to page through.
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[j].GetAddress().GetId() < all[i].GetAddress().GetId() {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	start := 0
	if t := req.Msg.GetPageToken(); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil {
			return nil, refusal.New(connect.CodeInvalidArgument, "address", "page_token")
		}
		start = n
	}
	size := int(req.Msg.GetPageSize())
	if size == 0 {
		size = 100
	}
	end := min(start+size, len(all))
	res := &storev2alpha1.ListResponse{Items: all[start:end]}
	if end < len(all) {
		res.NextPageToken = strconv.Itoa(end)
	}
	return connect.NewResponse(res), nil
}

func (f *fake) Write(_ context.Context, req *connect.Request[storev2alpha1.WriteRequest]) (*connect.Response[storev2alpha1.WriteResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, req.Msg)
	var out []*storev2alpha1.Item
	for _, op := range req.Msg.GetOperations() {
		k := key(op.GetAddress())
		cur, exists := f.items[k]
		switch op.GetVerb() {
		case storev2alpha1.Verb_CREATE:
			if exists {
				return nil, refusal.New(connect.CodeAlreadyExists, "taken", "")
			}
		case storev2alpha1.Verb_UPDATE:
			if !exists || cur.GetVersion() != op.GetIfVersion() {
				return nil, refusal.New(connect.CodeAborted, "version", "")
			}
		case storev2alpha1.Verb_DELETE:
			if !exists {
				return nil, refusal.New(connect.CodeNotFound, "absent", "")
			}
			if op.GetIfVersion() != 0 && cur.GetVersion() != op.GetIfVersion() {
				return nil, refusal.New(connect.CodeAborted, "version", "")
			}
			delete(f.items, k)
			continue
		case storev2alpha1.Verb_APPLY:
		default:
			return nil, refusal.New(connect.CodeInvalidArgument, "batch", "operations")
		}
		it := &storev2alpha1.Item{Address: op.GetAddress(), Version: cur.GetVersion() + 1, Value: op.GetValue(), Indexes: op.GetIndexes()}
		if op.GetTtl() != nil {
			it.ExpiresAt = timestamppb.New(time.Unix(2_000_000_000, 0))
		}
		f.items[k] = it
		out = append(out, it)
	}
	return connect.NewResponse(&storev2alpha1.WriteResponse{Items: out}), nil
}

func setup(t *testing.T, kind string, opts ...store.Option) (*store.Client[*typev2alpha1.Header], *fake) {
	t.Helper()
	f := &fake{items: map[string]*storev2alpha1.Item{}}
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	cfg := rpc.WithNameResolver(rpc.ServerConfig{
		Actor: "store", Socket: filepath.Join(dir, "s.sock"),
	}, func(uid uint32) (string, uint32, bool) { return "key", 0, uid == self })
	path, h := storev2alpha1connect.NewStoreServiceHandler(f, rpc.HandlerOptions(cfg)...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	hc, url := rpc.Dial(cfg.Socket)
	c := storev2alpha1connect.NewStoreServiceClient(hc, url, rpc.ClientOptions()...)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := c.Get(context.Background(), connect.NewRequest(&storev2alpha1.GetRequest{}))
		if connect.CodeOf(err) != connect.CodeUnavailable || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mu.Lock()
	f.reads = nil
	f.mu.Unlock()
	cl, err := store.New(c, kind, newHeader, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return cl, f
}

func hdr(name, value string) *typev2alpha1.Header {
	return &typev2alpha1.Header{Name: name, Value: value}
}

func TestCreateGetAndErrExists(t *testing.T) {
	c, f := setup(t, "DataKeyWrap")
	ctx := context.Background()

	it, err := c.Create(ctx, "acme", "data/1/board-a", hdr("a", "1"), store.WithGrant([]byte("sealed")), store.WithTTL(time.Hour), store.WithIndex("by-x", []byte("v")))
	if err != nil {
		t.Fatal(err)
	}
	if it.Version != 1 || it.Tenant != "acme" || it.ID != "data/1/board-a" || it.Value.GetName() != "a" || it.ExpiresAt.IsZero() {
		t.Fatalf("created = %+v", it)
	}
	w := f.seen[0]
	op := w.GetOperations()[0]
	if string(w.GetGrant()) != "sealed" || op.GetTtl().AsDuration() != time.Hour || len(op.GetIndexes()) != 1 || op.GetIndexes()[0].GetName() != "by-x" {
		t.Fatalf("write request = %v", w)
	}
	if a := op.GetAddress(); a.GetKind() != "data-key-wrap" || a.GetTenant() != "acme" || a.GetId() != "data/1/board-a" {
		t.Fatalf("address = %v", a)
	}

	got, err := c.Get(ctx, "acme", "data/1/board-a")
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got.Value, hdr("a", "1")) || got.Version != 1 {
		t.Fatalf("got = %+v", got)
	}

	_, err = c.Create(ctx, "acme", "data/1/board-a", hdr("b", "2"))
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create: %v, want ErrExists", err)
	}
	if r, _ := refusal.Reason(err); r != "taken" {
		t.Fatalf("reason = %q, want taken", r)
	}
}

func TestGetOptionsAndErrors(t *testing.T) {
	c, f := setup(t, "DataKeyWrap")
	ctx := context.Background()
	if _, err := c.Get(ctx, "acme", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v, want ErrNotFound", err)
	}
	if _, err := c.Create(ctx, "acme", "x", hdr("a", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "acme", "x", store.IfNoneMatch(1)); !errors.Is(err, store.ErrUnchanged) {
		t.Fatalf("if-none-match at the held version: %v, want ErrUnchanged", err)
	}
	if _, err := c.Get(ctx, "acme", "x", store.IfNoneMatch(7), store.Follower()); err != nil {
		t.Fatalf("if-none-match at another version: %v", err)
	}
	last := f.reads[len(f.reads)-1]
	if last.GetConsistency() != storev2alpha1.Consistency_FOLLOWER || last.GetIfNoneMatch() != 7 {
		t.Fatalf("request = %v", last)
	}
}

func TestUpdateAndErrVersion(t *testing.T) {
	c, _ := setup(t, "DataKeyWrap")
	ctx := context.Background()
	if _, err := c.Create(ctx, "acme", "x", hdr("a", "1")); err != nil {
		t.Fatal(err)
	}
	it, err := c.Update(ctx, "acme", "x", hdr("a", "2"), 1)
	if err != nil || it.Version != 2 {
		t.Fatalf("update at the current version: %+v, %v", it, err)
	}
	if _, err := c.Update(ctx, "acme", "x", hdr("a", "3"), 1); !errors.Is(err, store.ErrVersion) {
		t.Fatalf("update at an old version: %v, want ErrVersion", err)
	}
	if err := c.Delete(ctx, "acme", "x", 1); !errors.Is(err, store.ErrVersion) {
		t.Fatalf("delete at an old version: %v, want ErrVersion", err)
	}
	if err := c.Delete(ctx, "acme", "x", 2); err != nil {
		t.Fatalf("delete at the current version: %v", err)
	}
	if _, err := c.Get(ctx, "acme", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestApplyReplays(t *testing.T) {
	c, _ := setup(t, "DataKeyWrap")
	ctx := context.Background()
	for i, want := range []uint64{1, 2} {
		it, err := c.Apply(ctx, "acme", "x", hdr("a", "same"))
		if err != nil || it.Version != want {
			t.Fatalf("apply %d: %+v, %v", i, it, err)
		}
	}
}

func TestListPages(t *testing.T) {
	c, f := setup(t, "DataKeyWrap")
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if _, err := c.Create(ctx, "acme", id, hdr(id, "")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Create(ctx, "globex", "other", hdr("o", "")); err != nil {
		t.Fatal(err)
	}
	var ids []string
	token := ""
	pages := 0
	for {
		items, next, err := c.List(ctx, "acme", store.PageSize(2), store.PageToken(token))
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, it := range items {
			ids = append(ids, it.ID)
		}
		if next == "" {
			break
		}
		token = next
	}
	if pages != 3 || strings.Join(ids, ",") != "a,b,c,d,e" {
		t.Fatalf("pages %d ids %v", pages, ids)
	}
	if _, _, err := c.List(ctx, "acme", store.ByIndex("by-x", []byte("v"))); err != nil {
		t.Fatal(err)
	}
	last := f.lists[len(f.lists)-1]
	if last.GetKind() != "data-key-wrap" || last.GetTenant() != "acme" || last.GetIndex() != "by-x" || string(last.GetIndexValue()) != "v" {
		t.Fatalf("list request = %v", last)
	}
}

func TestTenantIsEmptyOnTheWire(t *testing.T) {
	c, f := setup(t, "Lease") // a kind with no tenant
	ctx := context.Background()
	it, err := c.Create(ctx, "", "adapter-github/sync", hdr("a", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.seen[0].GetOperations()[0].GetAddress().GetTenant(); got != "" {
		t.Fatalf("the wire tenant = %q, want empty: only the text address carries -", got)
	}
	if it.Tenant != "" {
		t.Fatalf("the item's tenant = %q, want empty", it.Tenant)
	}
	if _, err := c.Get(ctx, "", "adapter-github/sync"); err != nil {
		t.Fatal(err)
	}
	if got := f.reads[len(f.reads)-1].GetAddress().GetTenant(); got != "" {
		t.Fatalf("the wire tenant of a Get = %q, want empty", got)
	}
	items, _, err := c.List(ctx, "")
	if err != nil || len(items) != 1 || items[0].Tenant != "" {
		t.Fatalf("list = %+v, %v", items, err)
	}
	if got := f.lists[0].GetTenant(); got != "" {
		t.Fatalf("the wire tenant of a List = %q, want empty", got)
	}
}

func TestScopeIsCheckedBeforeTheCall(t *testing.T) {
	ctx := context.Background()
	tenanted, f1 := setup(t, "DataKeyWrap")
	plain, f2 := setup(t, "Lease")
	for name, err := range map[string]error{
		"no tenant for a tenant kind":  second(tenanted.Get(ctx, "", "x")),
		"tenant - for a tenant kind":   second(tenanted.Get(ctx, "-", "x")),
		"a tenant for a boundary kind": second(plain.Get(ctx, "acme", "x")),
		"upper-case tenant":            second(tenanted.Get(ctx, "Acme", "x")),
		"empty id":                     second(tenanted.Get(ctx, "acme", "")),
		"bad id":                       second(tenanted.Create(ctx, "acme", "a/../b", hdr("a", ""))),
		"list: no tenant":              list(tenanted.List(ctx, "")),
		"delete: bad id":               tenanted.Delete(ctx, "acme", "A", 0),
	} {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want invalid_argument", name, err)
		}
		if r, _ := refusal.Reason(err); r != "address" {
			t.Errorf("%s: reason %q, want address", name, r)
		}
	}
	if len(f1.reads)+len(f1.seen)+len(f1.lists)+len(f2.reads) != 0 {
		t.Fatal("a call with a bad address reached the store")
	}
}

func second[T any](_ T, err error) error { return err }

func list[T any](_ T, _ string, err error) error { return err }

// DataKeyWrap is tenant-scoped, but its boundary purposes have no tenant: with OptionalTenant the client addresses
// them with the tenant "", which is empty on the wire. Tenant "-" is still refused, and without the option so is "".
func TestOptionalTenantAddressesTheBoundary(t *testing.T) {
	c, f := setup(t, "DataKeyWrap", store.OptionalTenant())
	ctx := context.Background()
	if _, err := c.Create(ctx, "", "cookie/1/node-a", hdr("a", "1")); err != nil {
		t.Fatal(err)
	}
	if got := f.seen[0].GetOperations()[0].GetAddress().GetTenant(); got != "" {
		t.Fatalf("the wire tenant = %q, want empty", got)
	}
	it, err := c.Get(ctx, "", "cookie/1/node-a")
	if err != nil || it.Tenant != "" {
		t.Fatalf("get = %+v, %v", it, err)
	}
	if _, _, err := c.List(ctx, "", store.ByIndex("by_purpose", []byte("cookie"))); err != nil {
		t.Fatal(err)
	}
	if got := f.lists[0].GetTenant(); got != "" {
		t.Fatalf("the wire tenant of a List = %q, want empty", got)
	}
	// A tenant still works, and "-" is still never a tenant.
	if _, err := c.Create(ctx, "acme", "data/1/node-a", hdr("b", "2")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "-", "x"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("tenant -: %v, want invalid_argument", err)
	}
}

func TestCreateAllIsOneWriteWithItsOwnIndexes(t *testing.T) {
	c, f := setup(t, "DataKeyWrap", store.OptionalTenant())
	ctx := context.Background()
	items := []store.NewItem[*typev2alpha1.Header]{
		{Tenant: "", ID: "grant/1/node-a", Value: hdr("a", "1"), Indexes: []store.Index{{Name: "by_purpose", Value: []byte("grant")}, {Name: "by_recipient", Value: []byte("node-a")}}},
		{Tenant: "", ID: "grant/1/node-b", Value: hdr("b", "1"), Indexes: []store.Index{{Name: "by_purpose", Value: []byte("grant")}}},
	}
	got, err := c.CreateAll(ctx, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "grant/1/node-a" || got[1].Version != 1 || got[1].Value.GetName() != "b" {
		t.Fatalf("created = %+v", got)
	}
	if len(f.seen) != 1 || len(f.seen[0].GetOperations()) != 2 || len(f.seen[0].GetGrant()) != 0 {
		t.Fatalf("writes = %d, want one with two operations and no grant", len(f.seen))
	}
	ops := f.seen[0].GetOperations()
	if ops[0].GetVerb().String() != "CREATE" || len(ops[0].GetIndexes()) != 2 || len(ops[1].GetIndexes()) != 1 {
		t.Fatalf("operations = %v", ops)
	}
	// A taken address is ErrExists.
	if _, err := c.CreateAll(ctx, items[:1]); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second CreateAll: %v, want ErrExists", err)
	}
}

func TestCreateAllChecksBeforeTheCall(t *testing.T) {
	c, f := setup(t, "DataKeyWrap")
	ctx := context.Background()
	mk := func(n int) []store.NewItem[*typev2alpha1.Header] {
		out := make([]store.NewItem[*typev2alpha1.Header], n)
		for i := range out {
			out[i] = store.NewItem[*typev2alpha1.Header]{Tenant: "acme", ID: "data/1/n" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Value: hdr("a", "1")}
		}
		return out
	}
	_, err := c.CreateAll(ctx, nil)
	if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodeInvalidArgument || r != "batch" {
		t.Fatalf("empty batch: %v", err)
	}
	_, err = c.CreateAll(ctx, mk(store.MaxBatch+1))
	if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodeInvalidArgument || r != "batch" {
		t.Fatalf("65 items: %v", err)
	}
	bad := mk(2)
	bad[1].ID = "A"
	_, err = c.CreateAll(ctx, bad)
	if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodeInvalidArgument || r != "address" {
		t.Fatalf("bad id in the second item: %v", err)
	}
	if len(f.seen) != 0 {
		t.Fatal("a refused batch reached the store")
	}
	if got, err := c.CreateAll(ctx, mk(store.MaxBatch)); err != nil || len(got) != store.MaxBatch {
		t.Fatalf("64 items: %d, %v", len(got), err)
	}
}
