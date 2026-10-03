// Package dynamodb is the DynamoDB adapter of the State, Index and Trigger
// ports (docs/design/ports.md, ADR 0027): one table, shared by every replica
// and every process, so a lease is exclusive across pods and a notification
// crosses processes. It is the State of the AWS platform, and what a
// Kubernetes deployment on AWS can use instead of NATS.
//
// # Table
//
// One table with a string partition key `pk` and a string sort key `sk`, and
// the table's TTL attribute `expires` (epoch seconds). Credentials are the
// platform's (Pod Identity, IRSA, a Lambda role): none is configured. With
// Config.Create the adapter makes the table (on-demand billing, TTL on
// `expires`) for a test or a development installation; production binds to
// the table the infrastructure code made.
//
// # Mapping
//
// A key is split at its first dot: pk is the first segment (`ses`, `lease`,
// `rt`), sk is the whole key. A prefix that ends at or after a dot is then a
// Query on ONE partition with begins_with on sk, which returns the keys in
// key order and pages by LastEvaluatedKey. A prefix with no dot (`ses`, “ or a
// legacy `issuer:code:`) names no partition and is a Scan, sorted in memory:
// an operator's listing, and what `access-roster migrate` does through the
// exporters. The partition is the key family on purpose: ADR 0027's IAM
// condition dynamodb:LeadingKeys then grants a role the families it writes. A
// hot partition is not a concern at this scale, and the one-item-per-key
// layout leaves a split to the engine.
//
// The Index is per set: the partition is `idx#<set>`, the sort key the member,
// and an item marked `k` = `i` so that no State listing returns it.
//
//	attribute  type  meaning
//	pk         S     partition: the first segment of the key; `idx#<set>` for an Index member
//	sk         S     the whole key; the member for an Index member
//	v          B     the value (State only)
//	rev        N     the revision: a random 64-bit number drawn on every write
//	expires    N     epoch seconds the item is dead from; absent for a permanent record
//	k          S     `i` for an Index member, absent for a State record
//
// # Operations
//
//   - Get is GetItem with ConsistentRead: an eventually consistent read could be
//     behind a write the caller was acknowledged for, and a revoked session
//     must read as revoked.
//   - Put is an unconditional PutItem. Create is a PutItem conditioned on the
//     key being absent or expired. Update and DeleteIfRevision are conditioned
//     on `rev` being the caller's and the item being live. A failed condition
//     returns the old item (ReturnValuesOnConditionCheckFailure), which tells
//     ErrConflict from ErrNotFound and ErrExists without a second call.
//   - A revision is a random 64-bit number and not a counter. A counter that a
//     delete resets would hand a record that went A, delete, A the revision it
//     had the first time, and a stale Update would succeed; a fresh random
//     number changes on every write, identical bytes included.
//   - Expiry is judged by the adapter's clock on every read and condition, to
//     the second: DynamoDB removes an expired item lazily, up to days later, and
//     is not relied on. A lifetime is rounded up to the second, so a record
//     lives up to a second longer than asked and never shorter.
//   - List is a Query (or a Scan) filtered on expiry, paged by a token that names
//     the last key (port.PageToken), so a record written during a listing may or
//     may not appear and none appears twice.
//
// # Watch, Trigger
//
// DynamoDB has no cheap change feed (Streams need a consumer and a second
// IAM surface), so Watch polls: it lists the prefix every poll interval (one
// second by default, [WithPollInterval]) and reports what differs from the
// last list, a key whose revision moved as a put and a key that is gone (deleted
// or expired) as a delete. Two changes to one key between two polls are one
// event, and a record written and removed between them is none: that is within
// the port's at-least-once, no-completeness contract, and a watcher reconciles
// by listing. A Watch costs one Query per interval on its prefix.
//
// The Trigger is the same as on NATS: Notify writes `notify.<target>` for a
// minute and Subscribe watches that prefix, so a notification reaches the
// subscribers of every process. It is polling, so delivery takes up to one
// poll interval; the asynchronous lambda:Invoke of ADR 0029 is another
// adapter, for the Lambda platform, and is not this one.
//
// # IAM
//
// dynamodb:GetItem, PutItem, DeleteItem and Query on the table, Scan for
// `access-roster migrate` and a listing by a dotless prefix, and
// dynamodb:DescribeTable (the start-up check that the table is there and the
// readiness probe). dynamodb:LeadingKeys may be restricted to the families a
// role writes; `notify` and `lease` belong to every role that runs a tick.
package dynamodb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/truvity/access-roster/internal/port"
)

var (
	_ port.State   = (*Store)(nil)
	_ port.Index   = (*Store)(nil)
	_ port.Trigger = (*Store)(nil)

	_ port.StateExporter = (*Store)(nil)
	_ port.IndexExporter = (*Store)(nil)
)

// DefaultPollInterval is how often a Watch lists its prefix.
const DefaultPollInterval = time.Second

const (
	// opTimeout bounds a call whose context has no deadline.
	opTimeout = 15 * time.Second
	// tableWait bounds how long a newly created table may take to be active.
	tableWait = 90 * time.Second
	// maxKey is DynamoDB's limit on a sort key, in bytes.
	maxKey = 1024
)

// The attribute names.
const (
	attrPK      = "pk"
	attrSK      = "sk"
	attrValue   = "v"
	attrRev     = "rev"
	attrExpires = "expires"
	attrKind    = "k"

	kindIndex = "i"
	idxPrefix = "idx#"
)

// The expressions. They are constants, and the fake of the unit tests
// evaluates exactly these.
const (
	condCreate = "attribute_not_exists(pk) OR (attribute_exists(expires) AND expires <= :now)"
	condLive   = "rev = :rev AND (attribute_not_exists(expires) OR expires > :now)"
	keyCond    = "pk = :pk"
	keyCondSK  = "pk = :pk AND begins_with(sk, :p)"
	filterAll  = "attribute_not_exists(k)"
	filterIdx  = "k = :i"
	scanState  = "attribute_not_exists(k) AND begins_with(sk, :p)"
	scanIndex  = "k = :i AND begins_with(pk, :p)"
)

// API is the part of the DynamoDB client the adapter uses, so a test can put a
// fake behind it.
type API interface {
	GetItem(ctx context.Context, in *ddb.GetItemInput, opts ...func(*ddb.Options)) (*ddb.GetItemOutput, error)
	PutItem(ctx context.Context, in *ddb.PutItemInput, opts ...func(*ddb.Options)) (*ddb.PutItemOutput, error)
	DeleteItem(ctx context.Context, in *ddb.DeleteItemInput, opts ...func(*ddb.Options)) (*ddb.DeleteItemOutput, error)
	Query(ctx context.Context, in *ddb.QueryInput, opts ...func(*ddb.Options)) (*ddb.QueryOutput, error)
	Scan(ctx context.Context, in *ddb.ScanInput, opts ...func(*ddb.Options)) (*ddb.ScanOutput, error)
	CreateTable(ctx context.Context, in *ddb.CreateTableInput, opts ...func(*ddb.Options)) (*ddb.CreateTableOutput, error)
	DescribeTable(ctx context.Context, in *ddb.DescribeTableInput, opts ...func(*ddb.Options)) (*ddb.DescribeTableOutput, error)
	UpdateTimeToLive(ctx context.Context, in *ddb.UpdateTimeToLiveInput, opts ...func(*ddb.Options)) (*ddb.UpdateTimeToLiveOutput, error)
}

// Config is how a table is reached and made.
type Config struct {
	// Table is the table's name. Required.
	Table string
	// Region is the table's region; empty is the SDK's own resolution
	// (AWS_REGION).
	Region string
	// Endpoint overrides the DynamoDB address: LocalStack, DynamoDB Local.
	Endpoint string
	// Create makes the table (and its TTL attribute) at start when it is not
	// there. Off, the table must exist: production uses the one the
	// infrastructure code made.
	Create bool
}

// Option configures [New] and [Open].
type Option func(*Store)

// WithClock replaces the clock expiry is judged by.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// WithPollInterval sets how often a Watch lists its prefix.
func WithPollInterval(d time.Duration) Option { return func(s *Store) { s.poll = d } }

// Store is the State, Index and Trigger over one table.
type Store struct {
	api   API
	table string

	now    func() time.Time
	offset atomic.Int64
	poll   time.Duration
}

// Open connects with the platform's credentials and binds the table, creating
// it when the configuration says so.
func Open(ctx context.Context, cfg Config, opts ...Option) (*Store, error) {
	if cfg.Table == "" {
		return nil, errors.New("dynamodb: no table")
	}
	var loaders []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loaders = append(loaders, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loaders...)
	if err != nil {
		return nil, unavailable(err)
	}
	client := ddb.NewFromConfig(awsCfg, func(o *ddb.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
	})
	return New(ctx, client, cfg, opts...)
}

// New binds the table over a client the caller made.
func New(ctx context.Context, api API, cfg Config, opts ...Option) (*Store, error) {
	if cfg.Table == "" {
		return nil, errors.New("dynamodb: no table")
	}
	s := &Store{api: api, table: cfg.Table, now: time.Now, poll: DefaultPollInterval}
	for _, opt := range opts {
		opt(s)
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if cfg.Create {
		if err := s.createTable(ctx); err != nil {
			return nil, unavailable(fmt.Errorf("table %q: %w", cfg.Table, err))
		}
	}
	if err := s.Ping(ctx); err != nil {
		return nil, fmt.Errorf("table %q: %w (set ports.dynamodb.create to make it, or make it with the infrastructure code)", cfg.Table, err)
	}
	return s, nil
}

func (s *Store) createTable(ctx context.Context) error {
	_, err := s.api.CreateTable(ctx, &ddb.CreateTableInput{
		TableName:   &s.table,
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
	})
	var inUse *types.ResourceInUseException
	if err != nil && !errors.As(err, &inUse) {
		return err
	}
	deadline := time.Now().Add(tableWait)
	for {
		out, err := s.api.DescribeTable(ctx, &ddb.DescribeTableInput{TableName: &s.table})
		if err == nil && out.Table != nil && out.Table.TableStatus == types.TableStatusActive {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("the table did not become active")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	_, err = s.api.UpdateTimeToLive(ctx, &ddb.UpdateTimeToLiveInput{
		TableName:               &s.table,
		TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String(attrExpires), Enabled: aws.Bool(true)},
	})
	// A second start finds TTL on already, which the API reports as an error.
	if err != nil && !strings.Contains(err.Error(), "already enabled") {
		return err
	}
	return nil
}

// Ping asks for the table: it is reachable, it is there and the credentials
// may describe it.
func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if _, err := s.api.DescribeTable(ctx, &ddb.DescribeTableInput{TableName: &s.table}); err != nil {
		return unavailable(err)
	}
	return nil
}

// Close is a no-op: the client holds no connection of its own to release.
func (s *Store) Close() {}

// Set returns the ports this adapter implements.
func (s *Store) Set() port.Set { return port.Set{State: s, Index: s, Trigger: s} }

// Advance moves the adapter's clock forward, so a test can cross a lifetime
// without sleeping. DynamoDB's own TTL runs on real time and is not relied on.
func (s *Store) Advance(d time.Duration) { s.offset.Add(int64(d)) }

func (s *Store) clock() time.Time { return s.now().Add(time.Duration(s.offset.Load())) }

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, opTimeout)
}

func unavailable(err error) error {
	if errors.Is(err, port.ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", port.ErrUnavailable, err)
}

// --- keys, revisions, lifetimes ---

// partition is the key's partition: its first segment.
func partition(key string) (string, error) {
	pk, _, _ := strings.Cut(key, ".")
	if pk == "" {
		return "", fmt.Errorf("%w: a key starts with a segment (%q)", port.ErrUnsupported, key)
	}
	if len(key) > maxKey {
		return "", fmt.Errorf("%w: a key of %d bytes is over DynamoDB's sort key limit of %d", port.ErrUnsupported, len(key), maxKey)
	}
	return pk, nil
}

// prefixPartition is the one partition a prefix lies in: known only when the
// prefix holds a dot.
func prefixPartition(prefix string) (string, bool) {
	pk, _, found := strings.Cut(prefix, ".")
	return pk, found && pk != ""
}

func newRev() string {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err) // no entropy: nothing safe to do
		}
		if n := binary.BigEndian.Uint64(b[:]); n != 0 {
			return strconv.FormatUint(n, 10)
		}
	}
}

// expiresAt is the stored expiry of a lifetime: whole seconds, rounded up.
func (s *Store) expiresAt(ttl time.Duration) (int64, bool) {
	if ttl <= 0 {
		return 0, false
	}
	t := s.clock().Add(ttl)
	sec := t.Unix()
	if t.Nanosecond() > 0 {
		sec++
	}
	return sec, true
}

func (s *Store) nowSec() int64 { return s.clock().Unix() }

func numAttr(n int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}
func strAttr(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

type item struct {
	pk, key string
	value   []byte
	rev     port.Revision
	expires int64 // 0 is none
	index   bool
}

func parseItem(m map[string]types.AttributeValue) (item, bool) {
	var it item
	if v, ok := m[attrPK].(*types.AttributeValueMemberS); ok {
		it.pk = v.Value
	} else {
		return it, false
	}
	if v, ok := m[attrSK].(*types.AttributeValueMemberS); ok {
		it.key = v.Value
	} else {
		return it, false
	}
	if v, ok := m[attrValue].(*types.AttributeValueMemberB); ok {
		it.value = v.Value
	}
	if v, ok := m[attrRev].(*types.AttributeValueMemberN); ok {
		it.rev = port.Revision(v.Value)
	}
	if v, ok := m[attrExpires].(*types.AttributeValueMemberN); ok {
		it.expires, _ = strconv.ParseInt(v.Value, 10, 64)
	}
	if v, ok := m[attrKind].(*types.AttributeValueMemberS); ok && v.Value == kindIndex {
		it.index = true
	}
	return it, true
}

func (s *Store) dead(it item) bool { return it.expires != 0 && it.expires <= s.nowSec() }

// remaining is what is left of an item's lifetime; 0 is none.
func (s *Store) remaining(it item) time.Duration {
	if it.expires == 0 {
		return 0
	}
	if d := time.Unix(it.expires, 0).Sub(s.clock()); d > 0 {
		return d
	}
	return time.Millisecond
}

func (s *Store) build(pk, sk string, value []byte, ttl time.Duration, index bool) (map[string]types.AttributeValue, string) {
	rev := newRev()
	m := map[string]types.AttributeValue{
		attrPK:  strAttr(pk),
		attrSK:  strAttr(sk),
		attrRev: &types.AttributeValueMemberN{Value: rev},
	}
	if index {
		m[attrKind] = strAttr(kindIndex)
	} else {
		m[attrValue] = &types.AttributeValueMemberB{Value: value}
	}
	if exp, ok := s.expiresAt(ttl); ok {
		m[attrExpires] = numAttr(exp)
	}
	return m, rev
}

func keyOf(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: strAttr(pk), attrSK: strAttr(sk)}
}

// --- State ---

// live reads the item, absent or expired being [port.ErrNotFound].
func (s *Store) live(ctx context.Context, pk, sk string) (item, error) {
	out, err := s.api.GetItem(ctx, &ddb.GetItemInput{TableName: &s.table, Key: keyOf(pk, sk), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return item{}, unavailable(err)
	}
	it, ok := parseItem(out.Item)
	if !ok || s.dead(it) {
		return item{}, port.ErrNotFound
	}
	return it, nil
}

// Get implements [port.State].
func (s *Store) Get(ctx context.Context, key string) (port.Record, error) {
	pk, err := partition(key)
	if err != nil {
		return port.Record{}, port.ErrNotFound
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	it, err := s.live(ctx, pk, key)
	if err != nil {
		return port.Record{}, err
	}
	if it.index {
		return port.Record{}, port.ErrNotFound
	}
	return port.Record{Key: key, Value: it.value, Revision: it.rev}, nil
}

// Put implements [port.State].
func (s *Store) Put(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	pk, err := s.checkWrite(key, value, ttl)
	if err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	m, rev := s.build(pk, key, value, ttl, false)
	if _, err = s.api.PutItem(ctx, &ddb.PutItemInput{TableName: &s.table, Item: m}); err != nil {
		return "", unavailable(err)
	}
	return port.Revision(rev), nil
}

func (s *Store) checkWrite(key string, value []byte, ttl time.Duration) (string, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	return partition(key)
}

// Create implements [port.State]: the write is conditioned on the key being
// absent or expired, so exactly one of several takers of an expired lease wins.
func (s *Store) Create(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	pk, err := s.checkWrite(key, value, ttl)
	if err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	m, rev := s.build(pk, key, value, ttl, false)
	_, err = s.api.PutItem(ctx, &ddb.PutItemInput{
		TableName: &s.table, Item: m,
		ConditionExpression:       aws.String(condCreate),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": numAttr(s.nowSec())},
	})
	switch {
	case err == nil:
		return port.Revision(rev), nil
	case isConditionFailed(err):
		return "", port.ErrExists
	}
	return "", unavailable(err)
}

func isConditionFailed(err error) bool {
	var c *types.ConditionalCheckFailedException
	return errors.As(err, &c)
}

// failedWith says why a condition on a live revision failed: the old item
// (which the failure carries, or a read finds) is gone or expired, or has
// another revision.
func (s *Store) failedWith(ctx context.Context, err error, pk, sk string) error {
	var c *types.ConditionalCheckFailedException
	if errors.As(err, &c) && len(c.Item) > 0 {
		if it, ok := parseItem(c.Item); !ok || s.dead(it) {
			return port.ErrNotFound
		}
		return port.ErrConflict
	}
	if _, err = s.live(ctx, pk, sk); err != nil {
		return err // ErrNotFound, or the store being down
	}
	return port.ErrConflict
}

func validRev(rev port.Revision) bool {
	n, err := strconv.ParseUint(string(rev), 10, 64)
	return err == nil && n != 0
}

// Update implements [port.State].
func (s *Store) Update(ctx context.Context, key string, value []byte, ttl time.Duration, rev port.Revision) (port.Revision, error) {
	pk, err := s.checkWrite(key, value, ttl)
	if err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if !validRev(rev) {
		if _, err = s.live(ctx, pk, key); err != nil {
			return "", err
		}
		return "", port.ErrConflict
	}
	m, next := s.build(pk, key, value, ttl, false)
	_, err = s.api.PutItem(ctx, &ddb.PutItemInput{
		TableName: &s.table, Item: m,
		ConditionExpression: aws.String(condLive),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":rev": &types.AttributeValueMemberN{Value: string(rev)}, ":now": numAttr(s.nowSec()),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	switch {
	case err == nil:
		return port.Revision(next), nil
	case isConditionFailed(err):
		return "", s.failedWith(ctx, err, pk, key)
	}
	return "", unavailable(err)
}

// Delete implements [port.State].
func (s *Store) Delete(ctx context.Context, key string) error {
	pk, err := partition(key)
	if err != nil {
		return nil // such a key was never written
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if _, err = s.api.DeleteItem(ctx, &ddb.DeleteItemInput{TableName: &s.table, Key: keyOf(pk, key)}); err != nil {
		return unavailable(err)
	}
	return nil
}

// DeleteIfRevision implements [port.State].
func (s *Store) DeleteIfRevision(ctx context.Context, key string, rev port.Revision) error {
	pk, err := partition(key)
	if err != nil {
		return port.ErrNotFound
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if !validRev(rev) {
		if _, err = s.live(ctx, pk, key); err != nil {
			return err
		}
		return port.ErrConflict
	}
	_, err = s.api.DeleteItem(ctx, &ddb.DeleteItemInput{
		TableName: &s.table, Key: keyOf(pk, key),
		ConditionExpression: aws.String(condLive),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":rev": &types.AttributeValueMemberN{Value: string(rev)}, ":now": numAttr(s.nowSec()),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	switch {
	case err == nil:
		return nil
	case isConditionFailed(err):
		return s.failedWith(ctx, err, pk, key)
	}
	return unavailable(err)
}

// Table is the table's name.
func (s *Store) Table() string { return s.table }
