package s3audit_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/s3audit"
)

// bucket is S3 as the store sees it: put, list by prefix, get. It refuses
// to overwrite a key, as a bucket under Object Lock effectively does for
// the record, and can be told to refuse puts.
type bucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	refuse  bool
	puts    int
	gets    int
}

func newBucket() *bucket { return &bucket{objects: map[string][]byte{}} }

func (b *bucket) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refuse {
		return nil, errors.New("s3 is down")
	}
	if in.ChecksumAlgorithm != types.ChecksumAlgorithmCrc32 {
		return nil, errors.New("a bucket under Object Lock wants a checksum")
	}
	key := aws.ToString(in.Key)
	if _, exists := b.objects[key]; exists {
		return nil, errors.New("overwrote " + key)
	}
	body, _ := io.ReadAll(in.Body)
	b.objects[key] = body
	b.puts++
	return &s3.PutObjectOutput{}, nil
}

func (b *bucket) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := &s3.ListObjectsV2Output{IsTruncated: aws.Bool(false)}
	var keys []string
	for key := range b.objects {
		if strings.HasPrefix(key, aws.ToString(in.Prefix)) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys) // S3 lists in key order
	if limit := int(aws.ToInt32(in.MaxKeys)); limit > 0 && len(keys) > limit {
		keys, out.IsTruncated = keys[:limit], aws.Bool(true)
	}
	for _, key := range keys {
		out.Contents = append(out.Contents, types.Object{Key: aws.String(key)})
	}
	return out, nil
}

func (b *bucket) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	body, ok := b.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, errors.New("no such key")
	}
	b.gets++
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (b *bucket) keys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for key := range b.objects {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

// clock is a time the test moves.
type clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = t
}

func newStore(t *testing.T, b *bucket, c *clock) *s3audit.Store {
	t.Helper()
	// A long interval: the tests decide when a batch is written, by
	// closing the store or by filling a batch.
	s := s3audit.New(b, s3audit.Config{Bucket: "audit", FlushInterval: time.Hour, BatchSize: 1000, Writer: "pod/a"}, nil, c.now)
	return s
}

func record(t *testing.T, s *s3audit.Store, at time.Time, kind, subject string) string {
	t.Helper()
	id, err := s.Append(context.Background(), audit.Event{At: at, Source: "issuer", Kind: kind, Subject: subject, Outcome: audit.OutcomeOK})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return id
}

func kinds(events []audit.Event) []string {
	var out []string
	for i := range events {
		out = append(out, events[i].Kind)
	}
	return out
}

// Written on close, one object per hour, each named for its hour, and read
// back newest first by another replica that holds nothing in memory.
func TestTheTrailIsWrittenByHourAndReadBackNewestFirst(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 16, 58, 0, 0, time.UTC)
	c.set(base)
	s := newStore(t, b, c)
	record(t, s, base, "sign-in", "a@x.example")
	record(t, s, base.Add(time.Minute), "token.exchanged", "a@x.example")
	record(t, s, base.Add(3*time.Minute), "github.member.add", "b@x.example") // 17:01, the next hour
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	keys := b.keys()
	if len(keys) != 2 || !strings.HasPrefix(keys[0], "events/2026/09/13/16/") || !strings.HasPrefix(keys[1], "events/2026/09/13/17/") {
		t.Fatalf("keys = %v, want one object in hour 16 and one in hour 17", keys)
	}
	if !strings.Contains(keys[0], "-pod_a-") {
		t.Errorf("key %q does not name its writer safely", keys[0])
	}

	c.set(base.Add(time.Hour))
	reader := newStore(t, b, c)
	got, cursor, err := reader.List(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if want := []string{"github.member.add", "token.exchanged", "sign-in"}; !slices.Equal(kinds(got), want) || cursor != "" {
		t.Errorf("List = %v (cursor %q), want %v and no cursor", kinds(got), cursor, want)
	}
}

// A page ends with a cursor, and the next page continues below it, across
// hours, without repeating or skipping anything.
func TestAListingPagesWithACursor(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	c.set(base)
	s := newStore(t, b, c)
	var want []string
	for i := range 7 {
		at := base.Add(time.Duration(i) * 20 * time.Minute)
		record(t, s, at, "k"+string(rune('a'+i)), "x@x.example")
		want = append([]string{"k" + string(rune('a'+i))}, want...)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	c.set(base.Add(3 * time.Hour))
	reader := newStore(t, b, c)
	var got []string
	cursor := ""
	for page := 0; ; page++ {
		events, next, err := reader.List(context.Background(), audit.Query{Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		got = append(got, kinds(events)...)
		if next == "" {
			break
		}
		if page > 5 {
			t.Fatal("the listing never ended")
		}
		cursor = next
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged = %v, want %v", got, want)
	}
}

// What this replica has not written yet is in its listings already, once.
func TestUnwrittenEventsAreListed(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.set(base)
	s := newStore(t, b, c)
	record(t, s, base, "sign-in", "a@x.example")

	got, _, err := s.List(context.Background(), audit.Query{})
	if err != nil || !slices.Equal(kinds(got), []string{"sign-in"}) {
		t.Fatalf("before the write: List = %v, %v; want the event", kinds(got), err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _, err = s.List(context.Background(), audit.Query{})
	if err != nil || len(got) != 1 {
		t.Errorf("after the write: List = %v, %v; want the event once", kinds(got), err)
	}
}

// S3 refusing a batch loses nothing: it is written, in order, once S3
// answers again, and recording never waited for it.
func TestARefusedBatchIsWrittenLater(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.set(base)
	b.refuse = true
	s := newStore(t, b, c)
	record(t, s, base, "first", "a@x.example")
	record(t, s, base.Add(time.Second), "second", "a@x.example")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Close(ctx); err == nil {
		t.Fatal("Close reported success while S3 refused every write")
	}
	if len(b.keys()) != 0 {
		t.Fatalf("something was written while S3 refused: %v", b.keys())
	}

	// Still listed from memory, and written once S3 is back.
	got, _, _ := s.List(context.Background(), audit.Query{})
	if !slices.Equal(kinds(got), []string{"second", "first"}) {
		t.Errorf("List while refused = %v, want both, newest first", kinds(got))
	}
	b.mu.Lock()
	b.refuse = false
	b.mu.Unlock()
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close once S3 answered: %v", err)
	}
	keys := b.keys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v, want the one batch written once S3 answered", keys)
	}
	reader := newStore(t, b, c)
	got, _, err := reader.List(context.Background(), audit.Query{})
	if err != nil || !slices.Equal(kinds(got), []string{"second", "first"}) {
		t.Errorf("read back = %v, %v; want both, newest first", kinds(got), err)
	}
}

// Filters apply, Since stops the reading, and a narrow filter over a long
// quiet stretch answers with a cursor instead of reading forever.
func TestFiltersSinceAndTheReadingBudget(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	old := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	c.set(old)
	s := newStore(t, b, c)
	record(t, s, old, "sign-in", "old@x.example")
	recent := time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)
	record(t, s, recent, "sign-in", "new@x.example")
	record(t, s, recent.Add(time.Minute), "token.exchanged", "new@x.example")
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	c.set(recent.Add(2 * time.Hour))
	reader := newStore(t, b, c)

	got, _, err := reader.List(context.Background(), audit.Query{Kind: "sign-in", Since: recent.Add(-time.Hour)})
	if err != nil || len(got) != 1 || got[0].Subject != "new@x.example" {
		t.Errorf("filtered since = %+v, %v; want only new@'s sign-in", got, err)
	}

	// Eleven days back is past one listing's reading budget: the first
	// page ends with a cursor, and following it finds the old event.
	var found []string
	cursor := ""
	for page := 0; page < 10; page++ {
		events, next, err := reader.List(context.Background(), audit.Query{Subject: "old@x.example", Cursor: cursor})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for i := range events {
			found = append(found, events[i].Subject)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if !slices.Equal(found, []string{"old@x.example"}) {
		t.Errorf("following the cursor found %v, want the old event", found)
	}
}
