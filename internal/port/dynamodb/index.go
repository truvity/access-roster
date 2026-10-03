package dynamodb

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/truvity/access-roster/internal/port"
)

// The Index is the transitional set of the port. A set is a partition,
// `idx#<set>`, and a member is an item in it with the member as its sort key
// and the lifetime of the Add that wrote it, so the lifetime is the member's
// and an Add does not extend the others'. `k` = `i` keeps a member out of every
// State listing.

func indexPK(set string) string { return idxPrefix + set }

func (s *Store) indexKeys(set, member string) (string, error) {
	if set == "" || member == "" {
		return "", fmt.Errorf("%w: an index set and member are not empty", port.ErrUnsupported)
	}
	if len(member) > maxKey {
		return "", fmt.Errorf("%w: a member of %d bytes is over DynamoDB's sort key limit", port.ErrUnsupported, len(member))
	}
	return indexPK(set), nil
}

// Add implements [port.Index].
func (s *Store) Add(ctx context.Context, key, member string, ttl time.Duration) error {
	pk, err := s.indexKeys(key, member)
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	m, _ := s.build(pk, member, nil, ttl, true)
	if _, err = s.api.PutItem(ctx, &ddb.PutItemInput{TableName: &s.table, Item: m}); err != nil {
		return unavailable(err)
	}
	return nil
}

// Remove implements [port.Index].
func (s *Store) Remove(ctx context.Context, key, member string) error {
	pk, err := s.indexKeys(key, member)
	if err != nil {
		return nil // never written
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if _, err = s.api.DeleteItem(ctx, &ddb.DeleteItemInput{TableName: &s.table, Key: keyOf(pk, member)}); err != nil {
		return unavailable(err)
	}
	return nil
}

func (s *Store) members(ctx context.Context, set string) ([]item, error) {
	in := &ddb.QueryInput{
		TableName:                 &s.table,
		ConsistentRead:            aws.Bool(true),
		KeyConditionExpression:    aws.String(keyCond),
		FilterExpression:          aws.String(filterIdx),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": strAttr(indexPK(set)), ":i": strAttr(kindIndex)},
	}
	var out []item
	err := s.queryPages(ctx, in, func(it item) bool {
		out = append(out, it)
		return true
	})
	return out, err
}

// Members implements [port.Index]: one Query on the set's partition.
func (s *Store) Members(ctx context.Context, key string) ([]string, error) {
	if key == "" {
		return nil, nil
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	items, err := s.members(ctx, key)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, it := range items {
		out = append(out, it.key)
	}
	return out, nil
}

// ExportIndex implements [port.IndexExporter]: every live set whose name has the
// prefix, with the lifetime of its longest-lived member (a member with none
// makes the set permanent). Sets are found by a Scan: there is no partition to
// ask for.
func (s *Store) ExportIndex(ctx context.Context, prefix string, fn func(port.Exported) error) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	in := &ddb.ScanInput{
		ConsistentRead:   aws.Bool(true),
		FilterExpression: aws.String(scanIndex),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":i": strAttr(kindIndex), ":p": strAttr(idxPrefix + prefix),
		},
	}
	sets := map[string]*port.Exported{}
	forever := map[string]bool{}
	var order []string
	err := s.scan(ctx, in, func(it item) bool {
		if !it.index || s.dead(it) {
			return true
		}
		set := it.pk[len(idxPrefix):]
		x, ok := sets[set]
		if !ok {
			x = &port.Exported{Key: set}
			sets[set] = x
			order = append(order, set)
		}
		x.Members = append(x.Members, it.key)
		if ttl := s.remaining(it); ttl == 0 {
			forever[set] = true
		} else if ttl > x.TTL {
			x.TTL = ttl
		}
		return true
	})
	if err != nil {
		return err
	}
	for set := range forever {
		sets[set].TTL = 0
	}
	slices.Sort(order)
	for _, set := range order {
		slices.Sort(sets[set].Members)
		if err = fn(*sets[set]); err != nil {
			return err
		}
	}
	return nil
}
