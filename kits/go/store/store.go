// Package store is the typed client of store@ (ADR 0005, "Typed clients"; docs/reference/store-api.md): one
// Client[T] for each kind, bound to the kind by its registry name. It builds the address, validates it before the
// call, encodes the value as the kind's Protobuf message, and turns the refusals of the store into errors a caller
// can test with errors.Is.
//
// The caller is learned by store@ from the transport, so a call names no actor, and the boundary is the store@ the
// client is connected to, so it names no boundary.
//
// The client does not seal. A sealed kind is refused by New until the helper that seals at key@ exists.
//
// planned: sealed helper, with session (#1221)
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The errors of a call, set by the Connect code of the store's refusal (store-api.md, "Refusals"). The error a
// call returns also wraps the Connect error, so refusal.Reason finds the reason.
var (
	ErrNotFound  = errors.New("store: not found")                   // not_found: no such item, or an expired one
	ErrExists    = errors.New("store: already exists")              // already_exists: a Create found the address taken
	ErrVersion   = errors.New("store: version has moved")           // aborted: an Update or Delete named an old version
	ErrUnchanged = errors.New("store: unchanged since the version") // a Get with IfNoneMatch found the same version
)

// Item is an item of kind T as the store returns it.
type Item[T proto.Message] struct {
	Tenant, ID string // Tenant is "" for a kind that has none
	Version    uint64
	Value      T
	ExpiresAt  time.Time // zero when the kind has no TTL
}

// Client is the client of one kind.
type Client[T proto.Message] struct {
	c            storev2alpha1connect.StoreServiceClient
	kind         registry.Kind
	newT         func() T
	tenantScoped bool // the kind is tenant-scoped
	// optionalTenant lets a tenant-scoped kind be addressed with no tenant: the boundary's own items.
	optionalTenant bool
}

// Option modifies a client.
type Option func(*clientOpts)

type clientOpts struct{ optionalTenant bool }

// OptionalTenant lets a client of a tenant-scoped kind also address the boundary's own items, with the tenant "".
// It is for DataKeyWrap, whose boundary purposes (grant, cookie, mac and the boundary's data key) have no tenant
// and live at tenant "-" in the text form of the address (kinds.yaml, DataKeyWrap; store-api.md, "Address
// encoding"). On the wire the tenant is empty, as it is for a kind with none.
func OptionalTenant() Option { return func(o *clientOpts) { o.optionalTenant = true } }

// New binds a client to one kind by its registry name ("DataKeyWrap"); the address segment comes from the
// registry. newT returns an empty message to decode into. A kind that does not exist, or that is sealed, is an
// error.
func New[T proto.Message](c storev2alpha1connect.StoreServiceClient, kind string, newT func() T, opts ...Option) (*Client[T], error) {
	k, ok := registry.KindByName(kind)
	if !ok {
		return nil, fmt.Errorf("store: unknown kind %q", kind)
	}
	if k.Treatment == "sealed" {
		return nil, fmt.Errorf("store: kind %q is sealed and the client does not seal yet", kind)
	}
	if newT == nil {
		return nil, errors.New("store: newT is nil")
	}
	var o clientOpts
	for _, f := range opts {
		f(&o)
	}
	return &Client[T]{c: c, kind: k, newT: newT, tenantScoped: k.Scope == "boundary+tenant", optionalTenant: o.optionalTenant}, nil
}

// address validates the call's address and builds it. The tenant must fit the kind's scope.
func (c *Client[T]) address(tenant, id string) (*typev2alpha1.Address, error) {
	if err := c.checkTenant(tenant); err != nil {
		return nil, err
	}
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	wt, err := wireTenant(tenant)
	if err != nil {
		return nil, err
	}
	return &typev2alpha1.Address{Kind: c.kind.Segment, Tenant: wt, Id: id}, nil
}

func (c *Client[T]) checkTenant(tenant string) error {
	if c.tenantScoped && tenant == "" && c.optionalTenant {
		return nil
	}
	if c.tenantScoped != (tenant != "") {
		return badAddress("tenant")
	}
	return nil
}

func (c *Client[T]) decode(it *storev2alpha1.Item) (Item[T], error) {
	v := c.newT()
	if err := proto.Unmarshal(it.GetValue(), v); err != nil {
		return Item[T]{}, describe("decode", refusal.New(connect.CodeInternal, "schema", "value"))
	}
	out := Item[T]{
		Tenant:  it.GetAddress().GetTenant(),
		ID:      it.GetAddress().GetId(),
		Version: it.GetVersion(),
		Value:   v,
	}
	if it.GetExpiresAt() != nil {
		out.ExpiresAt = it.GetExpiresAt().AsTime()
	}
	return out, nil
}

// mapErr wraps a Connect error with the sentinel its code names.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var sentinel error
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		sentinel = ErrNotFound
	case connect.CodeAlreadyExists:
		sentinel = ErrExists
	case connect.CodeAborted:
		sentinel = ErrVersion
	}
	if sentinel != nil {
		return fmt.Errorf("store %s: %w: %w", op, sentinel, err)
	}
	return describe(op, err)
}

// GetOption modifies a Get.
type GetOption func(*getOpts)

type getOpts struct {
	follower    bool
	ifNoneMatch uint64
}

// Follower asks for a read that tolerates lag; the default is linearizable.
func Follower() GetOption { return func(o *getOpts) { o.follower = true } }

// IfNoneMatch tells the store the version the caller holds. If the item is still at that version, Get returns
// ErrUnchanged.
func IfNoneMatch(version uint64) GetOption { return func(o *getOpts) { o.ifNoneMatch = version } }

// Get reads one item. A missing or expired item is ErrNotFound.
func (c *Client[T]) Get(ctx context.Context, tenant, id string, opts ...GetOption) (Item[T], error) {
	addr, err := c.address(tenant, id)
	if err != nil {
		return Item[T]{}, describe("get", err)
	}
	var o getOpts
	for _, f := range opts {
		f(&o)
	}
	req := &storev2alpha1.GetRequest{Address: addr, IfNoneMatch: o.ifNoneMatch}
	if o.follower {
		req.Consistency = storev2alpha1.Consistency_FOLLOWER
	}
	res, err := c.c.Get(ctx, connect.NewRequest(req))
	if err != nil {
		return Item[T]{}, mapErr("get", err)
	}
	if res.Msg.GetUnchanged() {
		return Item[T]{}, fmt.Errorf("store get: %w", ErrUnchanged)
	}
	if res.Msg.GetItem() == nil {
		return Item[T]{}, describe("get", refusal.New(connect.CodeInternal, "schema", "item"))
	}
	return c.decode(res.Msg.GetItem())
}

// ListOption modifies a List.
type ListOption func(*listOpts)

type listOpts struct {
	index      string
	indexValue []byte
	pageSize   int32
	pageToken  string
}

// ByIndex lists the items that a declared index of the kind maps to value, in place of the tenant's items.
func ByIndex(name string, value []byte) ListOption {
	return func(o *listOpts) { o.index, o.indexValue = name, value }
}

// PageSize sets the size of a page; the store refuses one above the maximum its contract declares.
func PageSize(n int32) ListOption { return func(o *listOpts) { o.pageSize = n } }

// PageToken continues a listing from the token of the previous page.
func PageToken(t string) ListOption { return func(o *listOpts) { o.pageToken = t } }

// List returns one page of the items of the kind in the tenant, and the token of the next page, empty on the last.
func (c *Client[T]) List(ctx context.Context, tenant string, opts ...ListOption) ([]Item[T], string, error) {
	if err := c.checkTenant(tenant); err != nil {
		return nil, "", describe("list", err)
	}
	wt, err := wireTenant(tenant)
	if err != nil {
		return nil, "", describe("list", err)
	}
	var o listOpts
	for _, f := range opts {
		f(&o)
	}
	res, err := c.c.List(ctx, connect.NewRequest(&storev2alpha1.ListRequest{
		Kind: c.kind.Segment, Tenant: wt,
		Index: o.index, IndexValue: o.indexValue,
		PageSize: o.pageSize, PageToken: o.pageToken,
	}))
	if err != nil {
		return nil, "", mapErr("list", err)
	}
	items := make([]Item[T], 0, len(res.Msg.GetItems()))
	for _, it := range res.Msg.GetItems() {
		d, err := c.decode(it)
		if err != nil {
			return nil, "", err
		}
		items = append(items, d)
	}
	return items, res.Msg.GetNextPageToken(), nil
}

// WriteOption modifies a write.
type WriteOption func(*writeOpts)

type writeOpts struct {
	grant   []byte
	ttl     time.Duration
	indexes []*typev2alpha1.IndexEntry
}

// WithGrant attaches the sealed grant of policy that a write to a tenant-scoped address needs
// (store-api.md, "Write"). The client passes the bytes as they are.
func WithGrant(sealed []byte) WriteOption { return func(o *writeOpts) { o.grant = sealed } }

// WithTTL sets a lifetime shorter than the kind's maximum; without it the kind's default applies.
func WithTTL(d time.Duration) WriteOption { return func(o *writeOpts) { o.ttl = d } }

// WithIndex adds an entry of a declared index of the kind; the writer computes its value.
func WithIndex(name string, value []byte) WriteOption {
	return func(o *writeOpts) {
		o.indexes = append(o.indexes, &typev2alpha1.IndexEntry{Name: name, Value: value})
	}
}

// operation builds one operation of a write.
func (c *Client[T]) operation(op string, verb storev2alpha1.Verb, tenant, id string, v T, hasValue bool, ifVersion uint64, o *writeOpts, indexes []*typev2alpha1.IndexEntry) (*storev2alpha1.Operation, error) {
	addr, err := c.address(tenant, id)
	if err != nil {
		return nil, describe(op, err)
	}
	operation := &storev2alpha1.Operation{Verb: verb, Address: addr, IfVersion: ifVersion, Indexes: indexes}
	if hasValue {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(v)
		if err != nil {
			return nil, describe(op, refusal.New(connect.CodeInvalidArgument, "schema", "value"))
		}
		operation.Value = b
	}
	if o.ttl != 0 {
		if o.ttl < 0 {
			return nil, describe(op, refusal.New(connect.CodeInvalidArgument, "ttl", "ttl"))
		}
		operation.Ttl = durationpb.New(o.ttl)
	}
	return operation, nil
}

func applyWriteOptions(opts []WriteOption) *writeOpts {
	var o writeOpts
	for _, f := range opts {
		f(&o)
	}
	return &o
}

func (c *Client[T]) write(ctx context.Context, op string, verb storev2alpha1.Verb, tenant, id string, v T, hasValue bool, ifVersion uint64, opts []WriteOption) (Item[T], error) {
	o := applyWriteOptions(opts)
	operation, err := c.operation(op, verb, tenant, id, v, hasValue, ifVersion, o, o.indexes)
	if err != nil {
		return Item[T]{}, err
	}
	res, err := c.c.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{
		Operations: []*storev2alpha1.Operation{operation},
		Grant:      o.grant,
	}))
	if err != nil {
		return Item[T]{}, mapErr(op, err)
	}
	if verb == storev2alpha1.Verb_DELETE {
		return Item[T]{}, nil
	}
	if len(res.Msg.GetItems()) != 1 {
		return Item[T]{}, describe(op, refusal.New(connect.CodeInternal, "schema", "items"))
	}
	return c.decode(res.Msg.GetItems()[0])
}

// MaxBatch is the most operations a write carries (store-api.md, "Write").
const MaxBatch = 64

// NewItem is one item of CreateAll.
type NewItem[T proto.Message] struct {
	Tenant, ID string
	Value      T
	// Indexes are the entries of the declared indexes of this item; the writer computes their values.
	Indexes []Index
}

// Index is an entry of a declared index.
type Index struct {
	Name  string
	Value []byte
}

// CreateAll creates the items in one write: all or none. If any address is taken, nothing is written and the
// error is ErrExists. The options (WithGrant, WithTTL) apply to every item; WithIndex is for Create, an item of
// CreateAll names its own Indexes. It returns the items as written, in order.
func (c *Client[T]) CreateAll(ctx context.Context, items []NewItem[T], opts ...WriteOption) ([]Item[T], error) {
	if len(items) == 0 || len(items) > MaxBatch {
		return nil, describe("create", refusal.New(connect.CodeInvalidArgument, "batch", "operations"))
	}
	o := applyWriteOptions(opts)
	ops := make([]*storev2alpha1.Operation, 0, len(items))
	for _, it := range items {
		idx := make([]*typev2alpha1.IndexEntry, 0, len(it.Indexes))
		for _, e := range it.Indexes {
			idx = append(idx, &typev2alpha1.IndexEntry{Name: e.Name, Value: e.Value})
		}
		op, err := c.operation("create", storev2alpha1.Verb_CREATE, it.Tenant, it.ID, it.Value, true, 0, o, idx)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	res, err := c.c.Write(ctx, connect.NewRequest(&storev2alpha1.WriteRequest{Operations: ops, Grant: o.grant}))
	if err != nil {
		return nil, mapErr("create", err)
	}
	if len(res.Msg.GetItems()) != len(items) {
		return nil, describe("create", refusal.New(connect.CodeInternal, "schema", "items"))
	}
	out := make([]Item[T], 0, len(items))
	for _, it := range res.Msg.GetItems() {
		d, err := c.decode(it)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// Create writes a new item, only if the address is free; a taken address is ErrExists.
func (c *Client[T]) Create(ctx context.Context, tenant, id string, v T, opts ...WriteOption) (Item[T], error) {
	return c.write(ctx, "create", storev2alpha1.Verb_CREATE, tenant, id, v, true, 0, opts)
}

// Update writes the item only at ifVersion, the version the caller read; a moved version is ErrVersion.
func (c *Client[T]) Update(ctx context.Context, tenant, id string, v T, ifVersion uint64, opts ...WriteOption) (Item[T], error) {
	return c.write(ctx, "update", storev2alpha1.Verb_UPDATE, tenant, id, v, true, ifVersion, opts)
}

// Apply creates the item or sets it to the value, for a writer that owns the whole item and replays idempotently.
func (c *Client[T]) Apply(ctx context.Context, tenant, id string, v T, opts ...WriteOption) (Item[T], error) {
	return c.write(ctx, "apply", storev2alpha1.Verb_APPLY, tenant, id, v, true, 0, opts)
}

// Delete removes the item, at ifVersion when it is not 0; a moved version is ErrVersion.
func (c *Client[T]) Delete(ctx context.Context, tenant, id string, ifVersion uint64, opts ...WriteOption) error {
	var zero T
	_, err := c.write(ctx, "delete", storev2alpha1.Verb_DELETE, tenant, id, zero, false, ifVersion, opts)
	return err
}
