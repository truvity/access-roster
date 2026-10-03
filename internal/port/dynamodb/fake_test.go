package dynamodb

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// fakeAPI is an in-memory DynamoDB that understands exactly the expressions this
// package sends (the constants of dynamodb.go) and refuses any other: a change of
// an expression without a change here fails loudly. It models conditions,
// ReturnValuesOnConditionCheckFailure, key-ordered Query with ExclusiveStartKey
// and Limit, and Scan. The real engine is the LocalStack run.
type fakeAPI struct {
	mu     sync.Mutex
	tables map[string]map[string]map[string]map[string]types.AttributeValue // table, pk, sk
	// calls counts the operations, for a test that asserts on what was sent.
	calls map[string]int
}

func newFake() *fakeAPI {
	return &fakeAPI{tables: map[string]map[string]map[string]map[string]types.AttributeValue{}, calls: map[string]int{}}
}

func str(m map[string]types.AttributeValue, k string) (string, bool) {
	v, ok := m[k].(*types.AttributeValueMemberS)
	if !ok {
		return "", false
	}
	return v.Value, true
}

func num(m map[string]types.AttributeValue, k string) (int64, bool) {
	v, ok := m[k].(*types.AttributeValueMemberN)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		// A revision is a 64-bit unsigned: compare as text where it overflows.
		return 0, false
	}
	return n, true
}

func (f *fakeAPI) table(name string) (map[string]map[string]map[string]types.AttributeValue, error) {
	t, ok := f.tables[name]
	if !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("no table " + name)}
	}
	return t, nil
}

func (f *fakeAPI) CreateTable(_ context.Context, in *ddb.CreateTableInput, _ ...func(*ddb.Options)) (*ddb.CreateTableOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["CreateTable"]++
	if _, ok := f.tables[*in.TableName]; ok {
		return nil, &types.ResourceInUseException{Message: aws.String("exists")}
	}
	f.tables[*in.TableName] = map[string]map[string]map[string]types.AttributeValue{}
	return &ddb.CreateTableOutput{}, nil
}

func (f *fakeAPI) DescribeTable(_ context.Context, in *ddb.DescribeTableInput, _ ...func(*ddb.Options)) (*ddb.DescribeTableOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["DescribeTable"]++
	if _, err := f.table(*in.TableName); err != nil {
		return nil, err
	}
	return &ddb.DescribeTableOutput{Table: &types.TableDescription{TableStatus: types.TableStatusActive}}, nil
}

func (f *fakeAPI) UpdateTimeToLive(_ context.Context, in *ddb.UpdateTimeToLiveInput, _ ...func(*ddb.Options)) (*ddb.UpdateTimeToLiveOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["UpdateTimeToLive"]++
	if *in.TimeToLiveSpecification.AttributeName != attrExpires {
		return nil, fmt.Errorf("the TTL attribute is %q, want %q", *in.TimeToLiveSpecification.AttributeName, attrExpires)
	}
	return &ddb.UpdateTimeToLiveOutput{}, nil
}

func (f *fakeAPI) GetItem(_ context.Context, in *ddb.GetItemInput, _ ...func(*ddb.Options)) (*ddb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["GetItem"]++
	t, err := f.table(*in.TableName)
	if err != nil {
		return nil, err
	}
	if in.ConsistentRead == nil || !*in.ConsistentRead {
		return nil, fmt.Errorf("GetItem must be a consistent read")
	}
	pk, _ := str(in.Key, attrPK)
	sk, _ := str(in.Key, attrSK)
	return &ddb.GetItemOutput{Item: maps.Clone(t[pk][sk])}, nil
}

// check evaluates one of the two conditions.
func check(cond *string, old map[string]types.AttributeValue, vals map[string]types.AttributeValue) (bool, error) {
	if cond == nil {
		return true, nil
	}
	now, _ := num(vals, ":now")
	exists := old != nil
	exp, hasExp := num(old, attrExpires)
	switch *cond {
	case condCreate:
		return !exists || (hasExp && exp <= now), nil
	case condLive:
		want := vals[":rev"].(*types.AttributeValueMemberN).Value
		have, ok := old[attrRev].(*types.AttributeValueMemberN)
		return exists && ok && have.Value == want && (!hasExp || exp > now), nil
	}
	return false, fmt.Errorf("the fake does not know the condition %q", *cond)
}

func (f *fakeAPI) PutItem(_ context.Context, in *ddb.PutItemInput, _ ...func(*ddb.Options)) (*ddb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["PutItem"]++
	t, err := f.table(*in.TableName)
	if err != nil {
		return nil, err
	}
	pk, _ := str(in.Item, attrPK)
	sk, _ := str(in.Item, attrSK)
	old := t[pk][sk]
	ok, err := check(in.ConditionExpression, old, in.ExpressionAttributeValues)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, conditionFailed(in.ReturnValuesOnConditionCheckFailure, old)
	}
	if t[pk] == nil {
		t[pk] = map[string]map[string]types.AttributeValue{}
	}
	t[pk][sk] = maps.Clone(in.Item)
	return &ddb.PutItemOutput{}, nil
}

func conditionFailed(rv types.ReturnValuesOnConditionCheckFailure, old map[string]types.AttributeValue) error {
	e := &types.ConditionalCheckFailedException{Message: aws.String("the conditional request failed")}
	if rv == types.ReturnValuesOnConditionCheckFailureAllOld {
		e.Item = maps.Clone(old)
	}
	return e
}

func (f *fakeAPI) DeleteItem(_ context.Context, in *ddb.DeleteItemInput, _ ...func(*ddb.Options)) (*ddb.DeleteItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["DeleteItem"]++
	t, err := f.table(*in.TableName)
	if err != nil {
		return nil, err
	}
	pk, _ := str(in.Key, attrPK)
	sk, _ := str(in.Key, attrSK)
	old := t[pk][sk]
	ok, err := check(in.ConditionExpression, old, in.ExpressionAttributeValues)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, conditionFailed(in.ReturnValuesOnConditionCheckFailure, old)
	}
	delete(t[pk], sk)
	return &ddb.DeleteItemOutput{}, nil
}

func hasKind(it map[string]types.AttributeValue) bool { _, ok := str(it, attrKind); return ok }

func (f *fakeAPI) Query(_ context.Context, in *ddb.QueryInput, _ ...func(*ddb.Options)) (*ddb.QueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["Query"]++
	t, err := f.table(*in.TableName)
	if err != nil {
		return nil, err
	}
	if in.ConsistentRead == nil || !*in.ConsistentRead {
		return nil, fmt.Errorf("Query must be a consistent read")
	}
	vals := in.ExpressionAttributeValues
	pk, _ := str(vals, ":pk")
	prefix, hasPrefix := str(vals, ":p")
	switch *in.KeyConditionExpression {
	case keyCond:
		if hasPrefix {
			return nil, fmt.Errorf("keyCond takes no prefix")
		}
	case keyCondSK:
	default:
		return nil, fmt.Errorf("the fake does not know the key condition %q", *in.KeyConditionExpression)
	}
	var keep func(map[string]types.AttributeValue) bool
	switch *in.FilterExpression {
	case filterAll:
		keep = func(it map[string]types.AttributeValue) bool { return !hasKind(it) }
	case filterIdx:
		keep = func(it map[string]types.AttributeValue) bool { k, _ := str(it, attrKind); return k == kindIndex }
	default:
		return nil, fmt.Errorf("the fake does not know the filter %q", *in.FilterExpression)
	}
	sks := make([]string, 0, len(t[pk]))
	for sk := range t[pk] {
		sks = append(sks, sk)
	}
	sort.Strings(sks)
	start, _ := str(in.ExclusiveStartKey, attrSK)
	out := &ddb.QueryOutput{}
	read := 0
	for _, sk := range sks {
		if in.ExclusiveStartKey != nil && sk <= start {
			continue
		}
		if hasPrefix && !strings.HasPrefix(sk, prefix) {
			continue
		}
		if in.Limit != nil && read == int(*in.Limit) {
			break
		}
		read++
		it := t[pk][sk]
		if keep(it) {
			out.Items = append(out.Items, maps.Clone(it))
		}
		out.LastEvaluatedKey = keyOf(pk, sk)
	}
	if in.Limit == nil || read < int(*in.Limit) {
		out.LastEvaluatedKey = nil
	}
	return out, nil
}

func (f *fakeAPI) Scan(_ context.Context, in *ddb.ScanInput, _ ...func(*ddb.Options)) (*ddb.ScanOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["Scan"]++
	t, err := f.table(*in.TableName)
	if err != nil {
		return nil, err
	}
	vals := in.ExpressionAttributeValues
	prefix, _ := str(vals, ":p")
	var keep func(map[string]types.AttributeValue) bool
	switch *in.FilterExpression {
	case filterAll:
		keep = func(it map[string]types.AttributeValue) bool { return !hasKind(it) }
	case scanState:
		keep = func(it map[string]types.AttributeValue) bool {
			sk, _ := str(it, attrSK)
			return !hasKind(it) && strings.HasPrefix(sk, prefix)
		}
	case scanIndex:
		keep = func(it map[string]types.AttributeValue) bool {
			pk, _ := str(it, attrPK)
			k, _ := str(it, attrKind)
			return k == kindIndex && strings.HasPrefix(pk, prefix)
		}
	default:
		return nil, fmt.Errorf("the fake does not know the scan filter %q", *in.FilterExpression)
	}
	out := &ddb.ScanOutput{}
	for _, part := range t {
		for _, it := range part {
			if keep(it) {
				out.Items = append(out.Items, maps.Clone(it))
			}
		}
	}
	return out, nil // one page, in no order, like the engine
}
