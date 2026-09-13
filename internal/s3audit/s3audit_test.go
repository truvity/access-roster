package s3audit_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
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

// write hands the store events through its AuditSinkService handler, as
// the service does.
func write(t *testing.T, s *s3audit.Store, durable bool, events ...audit.Event) error {
	t.Helper()
	_, err := s.WriteAuditEvents(context.Background(), connect.NewRequest(&directoryrosterv1.WriteAuditEventsRequest{
		Events: audit.EventsToProto(events), Durable: durable,
	}))
	return err
}

func record(t *testing.T, s *s3audit.Store, at time.Time, kind, subject string) {
	t.Helper()
	if err := write(t, s, false, audit.Event{At: at, Source: "issuer", Kind: kind, Subject: subject, Outcome: audit.OutcomeOK}); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// list reads a page back through the handler.
func list(s *s3audit.Store, q audit.Query) ([]audit.Event, string, error) {
	response, err := s.ListStoredAuditEvents(context.Background(), connect.NewRequest(&directoryrosterv1.ListStoredAuditEventsRequest{Query: q.Proto()}))
	if err != nil {
		return nil, "", err
	}
	return audit.EventsFromProto(response.Msg.GetEvents()), response.Msg.GetCursor(), nil
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
	got, cursor, err := list(reader, audit.Query{})
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
		events, next, err := list(reader, audit.Query{Limit: 3, Cursor: cursor})
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

	got, _, err := list(s, audit.Query{})
	if err != nil || !slices.Equal(kinds(got), []string{"sign-in"}) {
		t.Fatalf("before the write: List = %v, %v; want the event", kinds(got), err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _, err = list(s, audit.Query{})
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
	got, _, _ := list(s, audit.Query{})
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
	got, _, err := list(reader, audit.Query{})
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

	got, _, err := list(reader, audit.Query{Kind: "sign-in", Since: recent.Add(-time.Hour)})
	if err != nil || len(got) != 1 || got[0].Subject != "new@x.example" {
		t.Errorf("filtered since = %+v, %v; want only new@'s sign-in", got, err)
	}

	// Eleven days back is past one listing's reading budget: the first
	// page ends with a cursor, and following it finds the old event.
	var found []string
	cursor := ""
	for page := 0; page < 10; page++ {
		events, next, err := list(reader, audit.Query{Subject: "old@x.example", Cursor: cursor})
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

// A durable write is in the bucket when it returns, in an object of its
// own and ahead of anything queued; refused, it leaves nothing behind to
// be written later.
func TestADurableWriteIsPutBeforeItReturns(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.set(base)
	s := newStore(t, b, c)
	record(t, s, base, "sign-in", "a@x.example") // queued, not yet written

	recovered := audit.Event{At: base.Add(time.Second), Source: "console", Kind: "recovery.sign-in", Subject: "k8s:ops:recovery", Outcome: audit.OutcomeOK}
	if err := write(t, s, true, recovered); err != nil {
		t.Fatalf("durable write: %v", err)
	}
	keys := b.keys()
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "events/2026/09/13/12/") {
		t.Fatalf("keys after a durable write = %v, want its own object and nothing queued written", keys)
	}
	// Another replica reads it at once.
	got, _, err := list(newStore(t, b, c), audit.Query{})
	if err != nil || !slices.Equal(kinds(got), []string{"recovery.sign-in"}) {
		t.Errorf("another replica reads %v, %v; want the durable event only", kinds(got), err)
	}

	b.mu.Lock()
	b.refuse = true
	b.mu.Unlock()
	refused := recovered
	refused.At, refused.Subject = base.Add(2*time.Second), "k8s:ops:second"
	if err = write(t, s, true, refused); err == nil {
		t.Fatal("a durable write S3 refused reported success")
	}
	b.mu.Lock()
	b.refuse = false
	b.mu.Unlock()
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	all, _, _ := list(newStore(t, b, c), audit.Query{})
	for i := range all {
		if all[i].Subject == "k8s:ops:second" {
			t.Errorf("the refused durable event was written later: %+v", all[i])
		}
	}
	if len(all) != 2 {
		t.Errorf("read back %v, want the durable event and the queued sign-in", kinds(all))
	}
}

// The id an event arrives with is the id it is kept under — queued or
// durable — because the log line written before it names that id. Only an
// event with none is given one.
func TestAWriterKeepsTheIDItIsGiven(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.set(base)
	s := newStore(t, b, c)
	queued := audit.Event{ID: audit.NewID(base, "logger"), At: base, Source: "issuer", Kind: "sign-in", Outcome: audit.OutcomeOK}
	durable := audit.Event{
		ID: audit.NewID(base.Add(time.Second), "logger"), At: base.Add(time.Second),
		Source: "console", Kind: "recovery.sign-in", Outcome: audit.OutcomeOK,
	}
	if err := write(t, s, false, queued); err != nil {
		t.Fatal(err)
	}
	if err := write(t, s, true, durable); err != nil {
		t.Fatal(err)
	}
	if err := write(t, s, false, audit.Event{At: base.Add(2 * time.Second), Source: "issuer", Kind: "anonymous"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _, err := list(newStore(t, b, c), audit.Query{})
	if err != nil || len(got) != 3 {
		t.Fatalf("read back %v, %v", kinds(got), err)
	}
	ids := map[string]string{}
	for i := range got {
		ids[got[i].Kind] = got[i].ID
	}
	if ids["sign-in"] != queued.ID || ids["recovery.sign-in"] != durable.ID {
		t.Errorf("ids = %v, want %s and %s kept", ids, queued.ID, durable.ID)
	}
	if !strings.Contains(ids["anonymous"], "-pod_a-") {
		t.Errorf("an event with no id was given %q, want one naming this writer", ids["anonymous"])
	}
}

// The bucket holds objects of 1.6.2's own event lines for as long as their
// lock, beside ECS records in the same hour, and a listing reads both as
// one trail, newest first.
func TestAnHourOfBothFormatsReadsAsOneTrail(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)
	c.set(base.Add(30 * time.Minute))
	// What 1.6.2 wrote, byte for byte in its shape.
	native := `{"id":"` + fmt.Sprintf("%019d", base.Add(time.Minute).UnixNano()) + `-old-pod-1","at":"2026-09-13T15:01:00Z","source":"issuer",` +
		`"kind":"sign-in","actor":"ada@north.example","subject":"ada@north.example","target":"argocd","outcome":"ok","attributes":{"how":"google"}}` + "\n"
	b.objects[fmt.Sprintf("events/2026/09/13/15/%019d-old-pod-1.jsonl", base.Add(time.Minute).UnixNano())] = []byte(native)

	s := newStore(t, b, c)
	record(t, s, base.Add(2*time.Minute), "token.exchanged", "ada@north.example")
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var ecsObject string
	for _, key := range b.keys() {
		if strings.Contains(key, "-pod_a-") {
			ecsObject = string(b.objects[key])
		}
	}
	if !strings.Contains(ecsObject, `"event":{`) || !strings.Contains(ecsObject, `"dataset":"access_roster.audit"`) {
		t.Errorf("this release wrote %q, want an ECS document", ecsObject)
	}

	got, _, err := list(newStore(t, b, c), audit.Query{})
	if err != nil || !slices.Equal(kinds(got), []string{"token.exchanged", "sign-in"}) {
		t.Fatalf("read back %v, %v; want both formats, newest first", kinds(got), err)
	}
	old := got[1]
	if old.Actor != "ada@north.example" || old.Target != "argocd" || old.Attributes["how"] != "google" || !old.At.Equal(base.Add(time.Minute)) {
		t.Errorf("the 1.6.2 event read back as %+v", old)
	}
}

// Whether the trail is being written is visible without reading it: puts
// by outcome and kind, drops, and the queue.
func TestTheWriterPublishesItsMetrics(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	b, c := newBucket(), &clock{}
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.set(base)
	s := s3audit.New(b, s3audit.Config{Bucket: "audit", FlushInterval: time.Hour, BatchSize: 1000, Writer: "pod", Meter: provider}, nil, c.now)
	record(t, s, base, "a", "x@x.example")
	record(t, s, base, "b", "x@x.example")

	collected := collect(t, reader)
	if got := collected["access_roster.audit.queue"]; got != 2 {
		t.Errorf("queue = %d, want the two unwritten events", got)
	}
	if err := write(t, s, true, audit.Event{At: base, Source: "console", Kind: "recovery.sign-in"}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.refuse = true
	b.mu.Unlock()
	_ = write(t, s, true, audit.Event{At: base, Source: "console", Kind: "recovery.sign-in"})

	collected = collect(t, reader)
	if collected["access_roster.audit.writes{durable=true,outcome=ok}"] != 1 ||
		collected["access_roster.audit.writes{durable=true,outcome=failed}"] != 1 {
		t.Errorf("writes = %v, want one durable put and one refused", collected)
	}
}

// collect reads every int64 data point, named with its attributes.
func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("collect: %v", err)
	}
	out := map[string]int64{}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			var points []metricdata.DataPoint[int64]
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				points = d.DataPoints
			case metricdata.Gauge[int64]:
				points = d.DataPoints
			}
			for _, point := range points {
				name := m.Name
				if point.Attributes.Len() > 0 {
					var parts []string
					for _, kv := range point.Attributes.ToSlice() {
						parts = append(parts, string(kv.Key)+"="+kv.Value.String())
					}
					name += "{" + strings.Join(parts, ",") + "}"
				}
				out[name] = point.Value
			}
		}
	}
	return out
}
