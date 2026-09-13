package s3audit_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/audit/sinkrpc"
	"github.com/truvity/access-roster/internal/s3audit"
)

// The writer is reached through its contract, so where it runs is a
// deployment's choice: in this process through sinkrpc, or in another
// behind the generated client. Both writers, both ways, record and read
// back the same trail — and a durable write that fails fails the same way
// across a network as it does in process.
func TestAWriterWorksTheSameInProcessAndOverTheNetwork(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)

	type writer struct {
		handler directoryrosterv1connect.AuditSinkServiceHandler
		// refuseDurable makes durable writes fail, the writer's own way.
		refuseDurable func(bool)
	}
	writers := map[string]func(t *testing.T) writer{
		"memory": func(*testing.T) writer {
			m := audit.NewMemoryWriter(100)
			return writer{m, func(on bool) {
				if on {
					m.FailDurableWrites(errors.New("refused"))
				} else {
					m.FailDurableWrites(nil)
				}
			}}
		},
		"s3": func(t *testing.T) writer {
			b, c := newBucket(), &clock{}
			c.set(base.Add(time.Minute))
			s := newStore(t, b, c)
			t.Cleanup(func() { _ = s.Close(context.Background()) })
			return writer{s, func(on bool) { b.mu.Lock(); b.refuse = on; b.mu.Unlock() }}
		},
	}
	joins := map[string]func(t *testing.T, h directoryrosterv1connect.AuditSinkServiceHandler) directoryrosterv1connect.AuditSinkServiceClient{
		"in process": func(_ *testing.T, h directoryrosterv1connect.AuditSinkServiceHandler) directoryrosterv1connect.AuditSinkServiceClient {
			return sinkrpc.InProcess(h)
		},
		"over http": func(t *testing.T, h directoryrosterv1connect.AuditSinkServiceHandler) directoryrosterv1connect.AuditSinkServiceClient {
			mux := http.NewServeMux()
			mux.Handle(directoryrosterv1connect.NewAuditSinkServiceHandler(h))
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			return directoryrosterv1connect.NewAuditSinkServiceClient(server.Client(), server.URL)
		},
	}

	var reference []audit.Event
	for _, writerName := range []string{"memory", "s3"} {
		for _, joinName := range []string{"in process", "over http"} {
			t.Run(writerName+" "+joinName, func(t *testing.T) {
				w := writers[writerName](t)
				client := joins[joinName](t, w.handler)
				log := audit.NewLog(slog.New(slog.DiscardHandler), client, "pod")
				ctx := context.Background()

				log.Record(ctx, audit.Event{
					At: base, Source: audit.SourceIssuer, Kind: "sign-in", Actor: "ada@north.example", Subject: "ada@north.example",
					Target: "argocd", Attributes: map[string]string{"how": "google"},
					ClientAddress: "203.0.113.7", UserAgent: "Mozilla/5.0", RequestID: "req-1",
				})
				if err := log.RecordDurable(ctx, audit.Event{
					At: base.Add(time.Second), Source: audit.SourceConsole, Kind: "recovery.sign-in",
					Actor: "k8s:ops:recovery", Subject: "k8s:ops:recovery", Target: "console",
				}); err != nil {
					t.Fatalf("RecordDurable: %v", err)
				}
				w.refuseDurable(true)
				err := log.RecordDurable(ctx, audit.Event{At: base.Add(2 * time.Second), Source: audit.SourceConsole, Kind: "recovery.sign-in", Subject: "refused"})
				if err == nil {
					t.Fatal("a refused durable write reported success")
				}
				if joinName == "over http" && connect.CodeOf(errors.Unwrap(err)) != connect.CodeUnavailable {
					t.Errorf("over the network the refusal is %v, want unavailable", err)
				}
				w.refuseDurable(false)

				response, err := client.ListStoredAuditEvents(ctx, connect.NewRequest(&directoryrosterv1.ListStoredAuditEventsRequest{
					Query: audit.Query{}.Proto(),
				}))
				if err != nil {
					t.Fatalf("ListStoredAuditEvents: %v", err)
				}
				got := audit.EventsFromProto(response.Msg.GetEvents())
				for i := range got {
					got[i].ID = "" // assigned per run
				}
				if len(got) != 2 || got[0].Kind != "recovery.sign-in" || got[1].ClientAddress != "203.0.113.7" {
					t.Fatalf("read back %+v, want the durable recovery then the sign-in with its request", got)
				}
				if reference == nil {
					reference = got
					return
				}
				if !reflect.DeepEqual(got, reference) {
					t.Errorf("read back\n%+v\nwhere the in-memory writer in process read back\n%+v", got, reference)
				}
			})
		}
	}
}

// The durable write reaches S3 before the call over the network returns.
func TestADurableWriteOverTheNetworkIsInTheBucketWhenItAnswers(t *testing.T) {
	t.Parallel()
	b, c := newBucket(), &clock{}
	c.set(time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC))
	store := s3audit.New(b, s3audit.Config{Bucket: "audit", FlushInterval: time.Hour, Writer: "writer"}, nil, c.now)
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	mux := http.NewServeMux()
	mux.Handle(directoryrosterv1connect.NewAuditSinkServiceHandler(store))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	log := audit.NewLog(slog.New(slog.DiscardHandler), directoryrosterv1connect.NewAuditSinkServiceClient(server.Client(), server.URL), "service")

	if err := log.RecordDurable(context.Background(), audit.Event{Source: audit.SourceConsole, Kind: "recovery.sign-in"}); err != nil {
		t.Fatal(err)
	}
	if keys := b.keys(); len(keys) != 1 {
		t.Errorf("keys when the durable call answered = %v, want its object", keys)
	}
}
